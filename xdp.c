#define KBUILD_MODNAME "xdp_prog"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* =============================
 *   SELF-DECLARED STRUCTS
 * ============================= */

/* Minimal Ethernet header (14 bytes) */
struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
};

/* IPv4 header */
struct iphdr {
#if defined(__BIG_ENDIAN_BITFIELD)
	__u8 version : 4, ihl : 4;
#else
	__u8 ihl : 4, version : 4;
#endif
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
};

/* TCP header with basic flags */
struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
#if defined(__BIG_ENDIAN_BITFIELD)
	__u16 doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;
#else
	__u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
#endif
	__be16 window;
	__be16 check;
	__be16 urg_ptr;
};

/* UDP header (8 bytes) */
struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
};

/* ICMP header (8 bytes min) */
struct icmphdr {
	__u8 type;
	__u8 code;
	__be16 checksum;
	/*
     * We won't parse deeper fields.
     */
};

/* Protocol constants */
#define ETH_P_IP 0x0800
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Byte-order helpers */
#define ntohs(x) bpf_ntohs(x)
#define htons(x) bpf_htons(x)
#define ntohl(x) bpf_ntohl(x)
#define htonl(x) bpf_htonl(x)

/* =============================
 *   CONFIG & MAP DEFINITIONS
 * ============================= */

/* Per-CPU counters: index=0 => pass, index=1 => drop */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

/* Rate map structures for:
 *   - SYN (TCP)
 *   - UDP
 *   - ICMP
 * Each is keyed by the source IP.
 */
struct rate_data {
	__u64 packet_count;
	__u64 last_seen_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, __u32); /* src IP */
	__type(value, struct rate_data);
} syn_rate_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, __u32); /* src IP */
	__type(value, struct rate_data);
} udp_rate_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, __u32); /* src IP */
	__type(value, struct rate_data);
} icmp_rate_map SEC(".maps");

/* Blacklist map for IP -> timestamp blacklisted */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} blacklist_map SEC(".maps");

/*
 * For a heavier DDoS environment:
 *  - 1-second decay interval
 *  - 60-second blacklist
 *  - Higher thresholds for more traffic
 */
#define DECAY_INTERVAL_NS 1000000000ULL /* 1s decay window */
#define BLACKLIST_DURATION 60ULL /* 60s blacklist */

#define SYN_RATE_THRESHOLD 100000ULL /* Up to 100k SYNs per second per IP */
#define UDP_RATE_THRESHOLD 120000ULL /* Up to 120k UDP pkts/s per IP */
#define ICMP_RATE_THRESHOLD 60000ULL /* Up to 60k ICMP pkts/s per IP */

/* =============================
 *   PORT-SCAN DETECTION
 * ============================= */

/*
 * We'll track distinct ports for an IP in a short time window to catch scans.
 * If IP hits more than SCAN_PORTS_THRESHOLD distinct ports within SCAN_DECAY_NS,
 * we blacklist for 60s.
 */
#define SCAN_PORTS_THRESHOLD 20ULL /* e.g., 20 distinct ports in time window */
#define SCAN_DECAY_NS 2000000000ULL /* 2s decay window for port scan */

/* Key= (src IP, dst port), Value= last timestamp. We'll store these in LRU to avoid bloat. */
struct scan_key {
	__u32 src_ip;
	__u16 dst_port;
};

struct scan_val {
	__u64 last_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct scan_key);
	__type(value, struct scan_val);
} portscan_map SEC(".maps");

/* We'll also store how many distinct ports an IP has hammered recently. */
struct scan_count {
	__u64 distinct_count;
	__u64 last_decay_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048);
	__type(key, __u32); /* src IP */
	__type(value, struct scan_count);
} portscan_count_map SEC(".maps");

/* =============================
 *   HELPER FUNCTIONS
 * ============================= */

/* Increase pass/drop counters. */
static __always_inline void increment_stat(__u32 idx)
{
	__u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
	if (val)
		__sync_fetch_and_add(val, 1);
}

/* Skip Ethernet header (no VLAN here). */
static __always_inline void *skip_ethhdr(void *data, void *end, __be16 *proto)
{
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return NULL;

	*proto = eth->h_proto;
	return eth + 1;
}

/* Check blacklist. Remove IP if blacklist expired, else drop. */
static __always_inline int check_blacklist(__u32 sip, __u64 now_ns)
{
	__u64 *ts = bpf_map_lookup_elem(&blacklist_map, &sip);
	if (!ts)
		return XDP_PASS;

	__u64 elapsed_s = (now_ns - *ts) / 1000000000ULL;
	if (elapsed_s < BLACKLIST_DURATION) {
		return XDP_DROP;
	}

	/* remove expired */
	bpf_map_delete_elem(&blacklist_map, &sip);
	return XDP_PASS;
}

/* Generic rate-limiting: if threshold is exceeded within DECAY_INTERVAL_NS => blacklist. */
static __always_inline int handle_rate_limit(__u32 sip, __u64 now_ns, void *map_ptr, __u64 threshold)
{
	struct rate_data *rd = bpf_map_lookup_elem(map_ptr, &sip);
	if (!rd) {
		/* first time from this IP => initialize */
		struct rate_data newrd = { .packet_count = 1, .last_seen_ns = now_ns };
		bpf_map_update_elem(map_ptr, &sip, &newrd, BPF_ANY);
		return XDP_PASS;
	}

	if ((now_ns - rd->last_seen_ns) > DECAY_INTERVAL_NS) {
		/* reset counters after 1 second */
		rd->packet_count = 0;
		rd->last_seen_ns = now_ns;
	}

	rd->packet_count++;
	if (rd->packet_count > threshold) {
		/* exceed threshold => blacklist IP */
		bpf_map_update_elem(&blacklist_map, &sip, &now_ns, BPF_ANY);
		bpf_map_delete_elem(map_ptr, &sip);
		return XDP_DROP;
	}

	rd->last_seen_ns = now_ns;
	return XDP_PASS;
}

/* Basic port-scan detection: track distinct (IP, port) combos in LRU. */
static __always_inline int handle_portscan(__u32 sip, __u16 dport, __u64 now_ns)
{
	struct scan_key sk = { .src_ip = sip, .dst_port = dport };
	struct scan_val *sv = bpf_map_lookup_elem(&portscan_map, &sk);
	if (!sv) {
		/* new port => increment distinct port count */
		struct scan_val newsv = { .last_ns = now_ns };
		bpf_map_update_elem(&portscan_map, &sk, &newsv, BPF_ANY);

		struct scan_count *sc = bpf_map_lookup_elem(&portscan_count_map, &sip);
		if (!sc) {
			/* first time seeing this IP => create entry */
			struct scan_count newcount = { .distinct_count = 1, .last_decay_ns = now_ns };
			bpf_map_update_elem(&portscan_count_map, &sip, &newcount, BPF_ANY);
		} else {
			/* decay if older than SCAN_DECAY_NS (2s) */
			if ((now_ns - sc->last_decay_ns) > SCAN_DECAY_NS) {
				sc->distinct_count = 0;
				sc->last_decay_ns = now_ns;
			}

			sc->distinct_count++;
			if (sc->distinct_count > SCAN_PORTS_THRESHOLD) {
				/* too many distinct ports => blacklist IP */
				bpf_map_update_elem(&blacklist_map, &sip, &now_ns, BPF_ANY);
				bpf_map_delete_elem(&portscan_count_map, &sip);
				return XDP_DROP;
			}
		}
	} else {
		/* already saw this port => refresh timestamp */
		sv->last_ns = now_ns;
	}

	return XDP_PASS;
}

/* =============================
 *   MAIN XDP
 * ============================= */

SEC("xdp")
int xdp_ddos_portscan_mitigation(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	__u64 now_ns = bpf_ktime_get_ns();
	__be16 proto;

	/* 1) Skip Ethernet */
	void *cursor = skip_ethhdr(data, end, &proto);
	if (!cursor)
		goto pass; /* insufficient data for Ethernet header */

	/* 2) Only handle IPv4 */
	if (proto != htons(ETH_P_IP))
		goto pass;

	struct iphdr *iph = cursor;
	if ((void *)(iph + 1) > end)
		goto pass;

	__u8 ip_len = iph->ihl * 4;
	if ((void *)iph + ip_len > end)
		goto pass;

	/* 3) Check blacklist */
	__u32 sip = iph->saddr;
	if (check_blacklist(sip, now_ns) == XDP_DROP)
		goto drop;

	/* 4) L4 parse */
	void *l4 = (void *)iph + ip_len;
	if (l4 > end)
		goto pass;

	switch (iph->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > end)
			goto pass;

		/* For new inbound SYN, do rate-limit & port-scan detection. */
		if (tcp->syn && !tcp->ack) {
			if (handle_rate_limit(sip, now_ns, &syn_rate_map, SYN_RATE_THRESHOLD) == XDP_DROP)
				goto drop;
			if (handle_portscan(sip, ntohs(tcp->dest), now_ns) == XDP_DROP)
				goto drop;
		}
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > end)
			goto pass;

		/* Rate-limit UDP traffic. */
		if (handle_rate_limit(sip, now_ns, &udp_rate_map, UDP_RATE_THRESHOLD) == XDP_DROP)
			goto drop;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *ic = l4;
		if ((void *)(ic + 1) > end)
			goto pass;

		/* Rate-limit ICMP. */
		if (handle_rate_limit(sip, now_ns, &icmp_rate_map, ICMP_RATE_THRESHOLD) == XDP_DROP)
			goto drop;
		break;
	}
	default:
		/* pass everything else */
		break;
	}

pass:
	increment_stat(0);
	return XDP_PASS;

drop:
	increment_stat(1);
	return XDP_DROP;
}

/* eBPF license needed for helper usage. */
char _license[] SEC("license") = "GPL";
