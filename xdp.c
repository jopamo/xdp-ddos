#define KBUILD_MODNAME "xdp_prog"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* =============================
 *   SELF-DECLARED STRUCTS & MACROS
 * ============================= */

/* Ethernet header (standard 14 bytes) */
struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
};

/* VLAN header (4 bytes).
 * Used if you want to handle VLAN or QinQ.
 */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* IP header (20 bytes minimum, up to 60 with options).
 * We only define the fields we need here.
 */
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

/* TCP header (20 bytes minimum, up to 60 with options).
 * We define flags in a bitfield for convenience.
 */
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

/* UDP header (8 bytes). */
struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
};

/* ICMP header (8 bytes for Echo, but can be bigger with other messages). */
struct icmphdr {
	__u8 type;
	__u8 code;
	__be16 checksum;
	union {
		struct {
			__be16 id;
			__be16 sequence;
		} echo;
		__be32 gateway;
		struct {
			__be16 __unused;
			__be16 mtu;
		} frag;
	} un;
};

/* Common Ethernet protocol values (if you need them) */
#define ETH_P_IP 0x0800 /* IPv4 */
#define ETH_P_8021Q 0x8100 /* VLAN 802.1Q */
#define ETH_P_8021AD 0x88A8 /* VLAN 802.1ad */

/* IP Protocol numbers */
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Some helper macros if needed */
#define ntohs(x) bpf_ntohs(x)
#define htons(x) bpf_htons(x)
#define ntohl(x) bpf_ntohl(x)
#define htonl(x) bpf_htonl(x)

/* =============================
 *   YOUR DDoS/PORTSCAN LOGIC
 * ============================= */

/* Example config */
#define DECAY_INTERVAL_NS 1000000000ULL /* 1s */
#define BLACKLIST_DURATION 60ULL /* 60s in seconds */
#define SYN_RATE_THRESHOLD 10000ULL
#define UDP_RATE_THRESHOLD 15000ULL
#define ICMP_RATE_THRESHOLD 4000ULL
#define DNS_RATE_THRESHOLD 2000ULL
#define HTTP_RATE_THRESHOLD 2000ULL
#define PORT_DNS 53
#define PORT_HTTP 80
#define VLAN_MAX_DEPTH 2

enum scan_type { SCAN_NULL, SCAN_FIN, SCAN_XMAS, SCAN_ACK, SCAN_SYN, SCAN_OTHER, SCAN_MAX };
#define SCAN_SUSPICIOUS_THRESHOLD 10

/* Per-CPU array stats map: index 0 -> pass, 1 -> drop */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

/* Rate-limiting structs & maps */
struct rate_data {
	__u64 packet_count;
	__u64 last_seen_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); /* src IP */
	__type(value, struct rate_data);
	__uint(max_entries, 1024);
} syn_rate_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct rate_data);
	__uint(max_entries, 1024);
} udp_rate_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct rate_data);
	__uint(max_entries, 1024);
} icmp_rate_map SEC(".maps");

/* Blacklist map */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); /* src IP */
	__type(value, __u64); /* timestamp blacklisted */
	__uint(max_entries, 4096);
} blacklist_map SEC(".maps");

/* Port scan detection map */
struct scan_key {
	__u32 src_ip;
	__u16 dst_port;
	__u8 scan_type;
	__u8 pad;
};

struct scan_val {
	__u64 last_seen_ns;
	__u32 counter;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct scan_key);
	__type(value, struct scan_val);
	__uint(max_entries, 16384);
} port_scan_map SEC(".maps");

/* =============================
 *   Helper & Core Functions
 * ============================= */

static __always_inline void increment_stat(__u32 idx)
{
	__u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
	if (val) {
		__sync_fetch_and_add(val, 1);
	}
}

/* Example "bogon" IP check logic */
static __always_inline int is_bogon_ip(__u32 ip_be)
{
	__u32 ip = bpf_ntohl(ip_be);
	/* 127.x.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 169.254.x.x, 100.64-127.x.x */
	if ((ip & 0xFF000000) == 0x7F000000 || (ip & 0xFF000000) == 0x0A000000 || (ip & 0xFFF00000) == 0xAC100000 ||
	    (ip & 0xFFFF0000) == 0xC0A80000 || (ip & 0xFFFF0000) == 0xA9FE0000 || (ip & 0xFFC00000) == 0x64400000) {
		return 1;
	}
	return 0;
}

/* Check IP in blacklist and duration. If blacklisted, drop. */
static __always_inline int check_blacklist(__u32 ip, __u64 now_ns)
{
	__u64 *ts = bpf_map_lookup_elem(&blacklist_map, &ip);
	if (!ts) {
		return XDP_PASS;
	}
	if ((now_ns - *ts) / 1000000000ULL < BLACKLIST_DURATION) {
		return XDP_DROP;
	}
	/* Expired -> remove */
	bpf_map_delete_elem(&blacklist_map, &ip);
	return XDP_PASS;
}

/* Generic rate limit: if threshold is exceeded, blacklist IP */
static __always_inline int handle_rate_limit(__u32 ip, __u64 now_ns, void *map_ptr, __u64 threshold)
{
	struct rate_data *rd = bpf_map_lookup_elem(map_ptr, &ip);
	if (!rd) {
		struct rate_data new_rd = { 1, now_ns };
		bpf_map_update_elem(map_ptr, &ip, &new_rd, BPF_ANY);
		return XDP_PASS;
	}
	if ((now_ns - rd->last_seen_ns) > DECAY_INTERVAL_NS) {
		rd->packet_count = 0;
		rd->last_seen_ns = now_ns;
	}
	rd->packet_count++;
	if (rd->packet_count > threshold) {
		bpf_map_update_elem(&blacklist_map, &ip, &now_ns, BPF_ANY);
		bpf_map_delete_elem(map_ptr, &ip);
		return XDP_DROP;
	}
	rd->last_seen_ns = now_ns;
	return XDP_PASS;
}

/* Classify TCP scans via flags */
static __always_inline enum scan_type classify_tcp_scan(__u8 flags)
{
	__u8 fin = flags & 0x01;
	__u8 syn = flags & 0x02;
	__u8 rst = flags & 0x04;
	__u8 psh = flags & 0x08;
	__u8 ack = flags & 0x10;
	__u8 urg = flags & 0x20;

	if (!fin && !syn && !rst && !psh && !ack && !urg) {
		return SCAN_NULL;
	} else if (fin && !syn && !rst && !psh && !ack && !urg) {
		return SCAN_FIN;
	} else if (fin && psh && urg && !syn && !ack && !rst) {
		return SCAN_XMAS;
	} else if (!fin && !syn && !rst && !psh && ack && !urg) {
		return SCAN_ACK;
	} else if (syn && !ack && !fin && !psh && !rst && !urg) {
		return SCAN_SYN;
	}
	return SCAN_OTHER;
}

/* Track suspicious TCP flag combos as potential scans */
static __always_inline int handle_tcp_scan(__u32 ip, __u16 port, enum scan_type st, __u64 now_ns)
{
	if (st == SCAN_OTHER) {
		return XDP_PASS;
	}
	struct scan_key sk = { .src_ip = ip, .dst_port = port, .scan_type = (__u8)st, .pad = 0 };
	struct scan_val *sv = bpf_map_lookup_elem(&port_scan_map, &sk);
	if (!sv) {
		struct scan_val nv = { now_ns, 1 };
		bpf_map_update_elem(&port_scan_map, &sk, &nv, BPF_ANY);
		return XDP_PASS;
	}
	/* Decay logic */
	if ((now_ns - sv->last_seen_ns) > DECAY_INTERVAL_NS) {
		sv->counter = 0;
		sv->last_seen_ns = now_ns;
	}
	sv->counter++;
	sv->last_seen_ns = now_ns;

	if (sv->counter > SCAN_SUSPICIOUS_THRESHOLD) {
		bpf_map_update_elem(&blacklist_map, &ip, &now_ns, BPF_ANY);
		bpf_map_delete_elem(&port_scan_map, &sk);
		return XDP_DROP;
	}
	return XDP_PASS;
}

static __always_inline void *skip_vlan(void *data, void *end, __be16 *proto)
{
#pragma unroll
	for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (*proto == bpf_htons(ETH_P_8021Q) || *proto == bpf_htons(ETH_P_8021AD)) {
			struct vlan_hdr *vh = data;

			/* bounds check for the next VLAN header */
			if ((void *)(vh + 1) > end)
				return NULL;

			*proto = vh->h_vlan_encapsulated_proto;
			data = vh + 1;
		} else {
			/* not a VLAN protocol; break immediately */
			break;
		}
	}

	return data;
}

/* Skip Ethernet header (and VLAN if present). */
static __always_inline void *skip_ethhdr(void *data, void *end, __be16 *proto)
{
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return NULL;

	*proto = eth->h_proto;
	data = eth + 1;

	/* If you do not have VLAN traffic, you can remove skip_vlan(). */
	data = skip_vlan(data, end, proto);
	return data;
}

/* =============================
 *   MAIN XDP HOOK
 * ============================= */

SEC("xdp")
int xdp_ddos_portscan_mitigation(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	__u64 now_ns = bpf_ktime_get_ns();
	__be16 proto;

	/* Skip L2 + (optionally) VLAN */
	void *cursor = skip_ethhdr(data, end, &proto);
	if (!cursor)
		goto pass;

	/* Only handle IPv4 in this example */
	if (proto != bpf_htons(ETH_P_IP))
		goto pass;

	struct iphdr *ip = cursor;
	if ((void *)(ip + 1) > end)
		goto pass;

	__u8 ip_len = ip->ihl * 4;
	if ((void *)ip + ip_len > end)
		goto pass;

	__u32 sip = ip->saddr;
	/* Basic sanity checks */
	if (ip->ttl < 10)
		goto drop;

	if (ip->frag_off & bpf_htons(0x1FFF))
		goto drop;

	if (is_bogon_ip(sip))
		goto drop;

	if (check_blacklist(sip, now_ns) == XDP_DROP)
		goto drop;

	/* L4 header starts here */
	void *l4 = (void *)ip + ip_len;
	if (l4 > end)
		goto pass;

	switch (ip->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > end)
			goto pass;

		/* Rate-limit SYN (no ACK) */
		if (tcp->syn && !tcp->ack) {
			if (handle_rate_limit(sip, now_ns, &syn_rate_map, SYN_RATE_THRESHOLD) == XDP_DROP)
				goto drop;
		}

		/* Detect suspicious flag combos */
		__u8 flags = 0;
		flags |= (tcp->fin ? 0x01 : 0);
		flags |= (tcp->syn ? 0x02 : 0);
		flags |= (tcp->rst ? 0x04 : 0);
		flags |= (tcp->psh ? 0x08 : 0);
		flags |= (tcp->ack ? 0x10 : 0);
		flags |= (tcp->urg ? 0x20 : 0);

		enum scan_type st = classify_tcp_scan(flags);
		if (handle_tcp_scan(sip, bpf_ntohs(tcp->dest), st, now_ns) == XDP_DROP)
			goto drop;

		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > end)
			goto pass;

		__u16 dport = bpf_ntohs(udp->dest);
		if (dport == PORT_DNS) {
			if (handle_rate_limit(sip, now_ns, &udp_rate_map, DNS_RATE_THRESHOLD) == XDP_DROP)
				goto drop;
		} else if (dport == PORT_HTTP) {
			if (handle_rate_limit(sip, now_ns, &udp_rate_map, HTTP_RATE_THRESHOLD) == XDP_DROP)
				goto drop;
		} else {
			if (handle_rate_limit(sip, now_ns, &udp_rate_map, UDP_RATE_THRESHOLD) == XDP_DROP)
				goto drop;
		}
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *ic = l4;
		if ((void *)(ic + 1) > end)
			goto pass;

		/* Rate-limit ICMP */
		if (handle_rate_limit(sip, now_ns, &icmp_rate_map, ICMP_RATE_THRESHOLD) == XDP_DROP)
			goto drop;
		break;
	}
	default:
		/* Not handling other protocols here */
		break;
	}

pass:
	increment_stat(0);
	return XDP_PASS;

drop:
	increment_stat(1);
	return XDP_DROP;
}

/* eBPF programs must have a license. Use "GPL" for helper restrictions. */
char _license[] SEC("license") = "GPL";
