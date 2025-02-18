#define KBUILD_MODNAME "xdp_prog"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_DNS 53
#define IPPROTO_HTTP 80

struct ethhdr {
	__u8 h_dest[6]; // Destination MAC address
	__u8 h_source[6]; // Source MAC address
	__be16 h_proto; // Ethernet protocol type (e.g., ETH_P_IP for IP)
};

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
	__be32 saddr; // Source address (in network byte order)
	__be32 daddr; // Destination address (in network byte order)
};

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

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
};

struct icmphdr {
	__u8 type;
	__u8 code;
	__be16 checksum;
	union {
		struct {
			__be16 id, sequence;
		} echo;
		__be32 gateway;
		struct {
			__be16 __unused, mtu;
		} frag;
	} un;
};

// Configuration constants and data structures for rate-limiting & blacklisting
#define SYN_RATE_THRESHOLD 10000
#define UDP_RATE_THRESHOLD 15000
#define ICMP_RATE_THRESHOLD 4000
#define DNS_RATE_THRESHOLD 1000
#define HTTP_RATE_THRESHOLD 2000
#define BLACKLIST_DURATION 60
#define DECAY_INTERVAL 1000000000ULL
#define STATS_KEY_PASS 0
#define STATS_KEY_DROP 1

struct rate_data {
	__u64 packet_count, last_seen;
};

// BPF maps for protocol-based rate limiting and blacklist
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct rate_data);
	__uint(max_entries, 1024);
} syn_count_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct rate_data);
	__uint(max_entries, 1024);
} udp_count_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct rate_data);
	__uint(max_entries, 1024);
} icmp_count_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
} blacklist_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

// Helper functions to increment counters and check blacklists
static __always_inline void increment_stat(__u32 stat_key)
{
	__u64 *val = bpf_map_lookup_elem(&stats_map, &stat_key);
	if (val)
		__sync_fetch_and_add(val, 1);
}

static __always_inline int is_bogon_ip(__u32 ip_be)
{
	__u32 ip = bpf_ntohl(ip_be);

	if ((ip & 0xFF000000) == 0x7F000000 || (ip & 0xFF000000) == 0x0A000000 || (ip & 0xFFF00000) == 0xAC100000 ||
	    (ip & 0xFFFF0000) == 0xC0A80000 || (ip & 0xFFFF0000) == 0xA9FE0000 || (ip & 0xFFC00000) == 0x64400000)
		return 1;

	return 0;
}

static __always_inline int check_blacklist(__u32 src_ip, __u64 now)
{
	__u64 *ts = bpf_map_lookup_elem(&blacklist_map, &src_ip);
	if (ts) {
		if ((now - *ts) / 1000000000ULL < BLACKLIST_DURATION)
			return XDP_DROP;
		bpf_map_delete_elem(&blacklist_map, &src_ip);
	}
	return XDP_PASS;
}

static __always_inline int handle_rate_limit(__u32 src_ip, __u64 now, void *map_ptr, __u64 threshold)
{
	struct rate_data *rd = bpf_map_lookup_elem(map_ptr, &src_ip);
	if (!rd) {
		struct rate_data new_data = { .packet_count = 1, .last_seen = now };
		bpf_map_update_elem(map_ptr, &src_ip, &new_data, BPF_ANY);
		return XDP_PASS;
	}

	if ((now - rd->last_seen) > DECAY_INTERVAL) {
		rd->packet_count = 0;
		rd->last_seen = now;
	}

	rd->packet_count++;
	if (rd->packet_count > threshold) {
		bpf_map_update_elem(&blacklist_map, &src_ip, &now, BPF_ANY);
		bpf_map_delete_elem(map_ptr, &src_ip);
		return XDP_DROP;
	}
	rd->last_seen = now;
	return XDP_PASS;
}

// Ethernet header skipping
static __always_inline void *skip_ethhdr(void *data, void *data_end, __be16 *proto)
{
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return NULL;

	*proto = eth->h_proto;
	return eth + 1;
}

SEC("xdp")
int xdp_ddos_mitigation(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 now = bpf_ktime_get_ns();
	__be16 proto;
	void *cursor = skip_ethhdr(data, data_end, &proto);

	if (!cursor)
		goto pass;

	if (proto != bpf_htons(ETH_P_IP))
		goto pass;

	struct iphdr *ip = cursor;
	if ((void *)(ip + 1) > data_end)
		goto pass;

	__u8 ip_hdr_len = ip->ihl * 4;
	if (ip_hdr_len < sizeof(*ip) || (void *)ip + ip_hdr_len > data_end)
		goto pass;

	__u32 src_ip = ip->saddr;

	if (ip->frag_off & bpf_htons(0x1FFF) || ip->ttl < 10)
		goto drop;

	if (is_bogon_ip(src_ip))
		goto drop;

	if (check_blacklist(src_ip, now) == XDP_DROP)
		goto drop;

	void *l4hdr = (void *)ip + ip_hdr_len;
	if (l4hdr > data_end)
		goto pass;

	switch (ip->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4hdr;
		if ((void *)(tcp + 1) > data_end)
			goto pass;

		if (tcp->syn && !tcp->ack) {
			if (handle_rate_limit(src_ip, now, &syn_count_map, SYN_RATE_THRESHOLD) == XDP_DROP)
				goto drop;
		}
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = l4hdr;
		if ((void *)(udp + 1) > data_end)
			goto pass;
		if (handle_rate_limit(src_ip, now, &udp_count_map, UDP_RATE_THRESHOLD) == XDP_DROP)
			goto drop;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *icmp = l4hdr;
		if ((void *)(icmp + 1) > data_end)
			goto pass;
		if (handle_rate_limit(src_ip, now, &icmp_count_map, ICMP_RATE_THRESHOLD) == XDP_DROP)
			goto drop;
		break;
	}
	case IPPROTO_DNS: {
		if (handle_rate_limit(src_ip, now, &udp_count_map, DNS_RATE_THRESHOLD) == XDP_DROP)
			goto drop;
		break;
	}
	case IPPROTO_HTTP: {
		if (handle_rate_limit(src_ip, now, &udp_count_map, HTTP_RATE_THRESHOLD) == XDP_DROP)
			goto drop;
		break;
	}
	default:
		break;
	}

pass:
	increment_stat(STATS_KEY_PASS);
	return XDP_PASS;

drop:
	increment_stat(STATS_KEY_DROP);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
