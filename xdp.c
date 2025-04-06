#define KBUILD_MODNAME "xdp_prog"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* =============================
 *   BASIC STRUCTS & CONSTANTS
 * ============================= */

/* Ethernet header */
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

/* TCP header */
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

/* UDP header */
struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
};

/* ICMP header */
struct icmphdr {
	__u8 type;
	__u8 code;
	__be16 checksum;
};

/* Protocols */
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

/* Byte-order helpers (short macros for clarity) */
#define ntohs(x) bpf_ntohs(x)
#define htons(x) bpf_htons(x)

/* =============================
 *   PERFORMANCE CONSTANTS
 * ============================= */
/*
 * Single configuration block with everything needed for blacklisting,
 * decay intervals, thresholds, etc.
 */
#define DECAY_INTERVAL_NS 1000000000ULL /* 1 second */
#define BLACKLIST_DURATION_S 60ULL /* 60-second blacklist */

/* Rate-limit thresholds (packets/sec approximate) */
#define SYN_THRESHOLD 100000ULL
#define UDP_THRESHOLD 120000ULL
#define ICMP_THRESHOLD 60000ULL

/* Port-scan thresholds */
#define SCAN_PORTS_THRESHOLD 20ULL
#define SCAN_DECAY_NS 2000000000ULL /* 2 seconds */

/* =============================
 *   MAPS
 * ============================= */

/* Per-CPU counters: index=0 => pass, 1 => drop */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

/*
 * Unified per-IP data structure:
 *   - blacklist_time: If >0, time (in ns) we blacklisted.
 *   - syn, udp, icmp: each with (packet_count, last_seen_ns)
 *   - scan_distinct, scan_last_decay: port-scan counters
 */
struct ip_data {
	__u64 blacklist_time;

	struct {
		__u64 packet_count;
		__u64 last_ns;
	} syn, udp, icmp;

	__u64 scan_distinct;
	__u64 scan_last_decay;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct ip_data);
} ip_data_map SEC(".maps");

/* Port-scan LRU map: key = (src IP, dst port), value = last time seen. */
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

/* =============================
 *   FAST INLINED HELPERS
 * ============================= */

static __always_inline void increment_stat(__u32 idx)
{
	/* Per-CPU map update for pass/drop counters */
	__u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
	if (val) {
		/* Atomic add on per-CPU variable is relatively cheap */
		__sync_fetch_and_add(val, 1);
	}
}

static __always_inline void *parse_ethhdr(void *data, void *data_end, __be16 *eth_type)
{
	struct ethhdr *eth = data;
	if ((void *)eth + sizeof(*eth) > data_end)
		return NULL;

	*eth_type = eth->h_proto;
	return eth + 1;
}

/* =============================
 *   MAIN XDP PROGRAM
 * ============================= */

SEC("xdp")
int xdp_ddos_portscan_mitigation(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__be16 eth_proto;
	__u64 now_ns = bpf_ktime_get_ns();

	/* Step 1: Parse Ethernet */
	void *cursor = parse_ethhdr(data, data_end, &eth_proto);
	if (!cursor)
		goto pass;

	/* Step 2: Only handle IPv4 */
	if (eth_proto != htons(ETH_P_IP))
		goto pass;

	/* Safely read IP header */
	struct iphdr *iph = cursor;
	if ((void *)iph + sizeof(*iph) > data_end)
		goto pass;
	__u8 ihl_bytes = iph->ihl * 4;
	if ((void *)iph + ihl_bytes > data_end)
		goto pass;

	__u32 saddr = iph->saddr;
	__u8 proto = iph->protocol;

	/* Single map lookup: get or create ip_data struct */
	struct ip_data *data_ip = bpf_map_lookup_elem(&ip_data_map, &saddr);
	if (!data_ip) {
		/* Not found: create a fresh entry with everything zeroed */
		struct ip_data new_entry = {};
		bpf_map_update_elem(&ip_data_map, &saddr, &new_entry, BPF_NOEXIST);

		/* Look it up again */
		data_ip = bpf_map_lookup_elem(&ip_data_map, &saddr);
		if (!data_ip)
			goto pass; /* Should not normally happen, but fail safe */
	}

	/* Step 3: Check if IP is currently blacklisted */
	if (data_ip->blacklist_time) {
		__u64 blacklist_age_s = (now_ns - data_ip->blacklist_time) / 1000000000ULL;
		if (blacklist_age_s < BLACKLIST_DURATION_S) {
			/* Still blacklisted => drop immediately */
			goto drop;
		}
		/* Expired => reset the blacklist_time */
		data_ip->blacklist_time = 0;
	}

	/* Step 4: L4 parsing */
	void *l4 = (void *)iph + ihl_bytes;
	if (l4 > data_end)
		goto pass;

	/*
	 * We'll do protocol-specific checks:
	 *   - TCP SYN => rate-limit & port-scan
	 *   - UDP    => rate-limit
	 *   - ICMP   => rate-limit
	 */
	switch (proto) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4;
		if ((void *)tcp + sizeof(*tcp) > data_end)
			goto pass;

		/* If this is a SYN (and not an ACK), apply rate-limit + port-scan checks */
		if (tcp->syn && !tcp->ack) {
			/* 1) Rate-limit: decay if needed */
			if ((now_ns - data_ip->syn.last_ns) > DECAY_INTERVAL_NS) {
				data_ip->syn.packet_count = 0;
			}
			data_ip->syn.packet_count++;
			data_ip->syn.last_ns = now_ns;

			if (data_ip->syn.packet_count > SYN_THRESHOLD) {
				/* Blacklist immediately */
				data_ip->blacklist_time = now_ns;
				goto drop;
			}

			/* 2) Port-scan detection */
			{
				/* Decay the distinct_count if older than SCAN_DECAY_NS */
				if ((now_ns - data_ip->scan_last_decay) > SCAN_DECAY_NS) {
					data_ip->scan_distinct = 0;
					data_ip->scan_last_decay = now_ns;
				}

				/* Check if we've seen this (IP,port) combo in LRU map */
				struct scan_key sk = {
					.src_ip = saddr,
					.dst_port = ntohs(tcp->dest),
				};
				struct scan_val *sv = bpf_map_lookup_elem(&portscan_map, &sk);
				if (!sv) {
					/* New port => increment distinct port count */
					struct scan_val new_sv = { .last_ns = now_ns };
					bpf_map_update_elem(&portscan_map, &sk, &new_sv, BPF_ANY);

					data_ip->scan_distinct++;
					if (data_ip->scan_distinct > SCAN_PORTS_THRESHOLD) {
						/* Blacklist for scanning */
						data_ip->blacklist_time = now_ns;
						goto drop;
					}
				} else {
					/* Already saw this port => just refresh timestamp */
					sv->last_ns = now_ns;
				}
			}
		}
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = l4;
		if ((void *)udp + sizeof(*udp) > data_end)
			goto pass;

		/* Rate-limit UDP */
		if ((now_ns - data_ip->udp.last_ns) > DECAY_INTERVAL_NS) {
			data_ip->udp.packet_count = 0;
		}
		data_ip->udp.packet_count++;
		data_ip->udp.last_ns = now_ns;

		if (data_ip->udp.packet_count > UDP_THRESHOLD) {
			data_ip->blacklist_time = now_ns;
			goto drop;
		}
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *ic = l4;
		if ((void *)ic + sizeof(*ic) > data_end)
			goto pass;

		/* Rate-limit ICMP */
		if ((now_ns - data_ip->icmp.last_ns) > DECAY_INTERVAL_NS) {
			data_ip->icmp.packet_count = 0;
		}
		data_ip->icmp.packet_count++;
		data_ip->icmp.last_ns = now_ns;

		if (data_ip->icmp.packet_count > ICMP_THRESHOLD) {
			data_ip->blacklist_time = now_ns;
			goto drop;
		}
		break;
	}
	default:
		/* Pass all other protocols with no extra checks */
		break;
	}

pass:
	increment_stat(0); /* PASS counter */
	return XDP_PASS;

drop:
	increment_stat(1); /* DROP counter */
	return XDP_DROP;
}

/* Required license */
char _license[] SEC("license") = "GPL";
