#define KBUILD_MODNAME "xdp_prog"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* —— Protocol IDs —— */
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

/* Byte‑order wrappers */
#define ntohs(x) bpf_ntohs(x)
#define htons(x) bpf_htons(x)
#define ntohl(x) bpf_ntohl(x)
#define htonl(x) bpf_htonl(x)

/* —— Tunables —— */
/* High thresholds to minimize false positives on routers handling legitimate high-volume traffic. */
/* SYN rate: Allow up to 100k SYN/s per IP with burst of 10k—adjust higher if needed for no FP. */
#define SYN_RATE_PPS 100000U
#define SYN_BURST 10000U

/* UDP rate: For small payloads to non-allowed ports; 200k PPS/burst 20k. */
#define UDP_RATE_PPS 200000U
#define UDP_BURST 20000U

/* ICMP rate: For small payloads; 100k PPS/burst 10k. */
#define ICMP_RATE_PPS 100000U
#define ICMP_BURST 10000U

/* Small payload threshold to target flood attacks without affecting legit larger packets. */
#define SMALL_PAYLOAD_BYTES 128

/* —— Headers —— */
struct ethhdr {
	__u8 dst[6], src[6];
	__be16 proto;
};
struct iphdr {
#if defined(__BIG_ENDIAN_BITFIELD)
	__u8 version : 4, ihl : 4;
#else
	__u8 ihl : 4, version : 4;
#endif
	__u8 tos;
	__be16 tot_len;
	__be16 id, frag_off;
	__u8 ttl, protocol;
	__be16 check;
	__be32 saddr, daddr;
};
struct tcphdr {
	__be16 source, dest;
	__be32 seq, ack_seq;
#if defined(__BIG_ENDIAN_BITFIELD)
	__u16 doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;
#else
	__u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
#endif
	__be16 window, check, urg_ptr;
};
struct udphdr {
	__be16 source, dest, len, check;
};
struct icmphdr {
	__u8 type, code;
	__be16 checksum;
};

/* —— Maps —— */
/* Stats map: Track passed (0) and dropped (1) packets for monitoring—low overhead percpu array. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

/* Allowed UDP ports: Small hash map to bypass rate limiting for known good ports (e.g., DNS=53)—populate from userspace to avoid FP. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32);
	__type(key, __u16);
	__type(value, __u8);
} allow_ports SEC(".maps");

/* Per-IP data: Token buckets for SYN, UDP, ICMP—hash map with limited entries for low memory/CPU. No blacklisting to prevent FP; just drop excess. */
struct ip_data {
	struct {
		__u64 tokens, last_ns;
	} syn, udp, icmp;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096); /* Small size to evict inactive; low overhead. */
	__type(key, __u32); /* Source IP. */
	__type(value, struct ip_data);
} ip_data_map SEC(".maps");

/* —— Helpers —— */
static __always_inline void increment_stat(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats_map, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline void *parse_ethhdr(void *data, void *end, __be16 *ptype)
{
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return NULL;
	*ptype = eth->proto;
	return eth + 1;
}

static __always_inline struct ip_data *get_ip_data(__u32 src)
{
	struct ip_data *st = bpf_map_lookup_elem(&ip_data_map, &src);
	if (!st) {
		struct ip_data zero = {};
		if (bpf_map_update_elem(&ip_data_map, &src, &zero, BPF_NOEXIST) == 0)
			st = bpf_map_lookup_elem(&ip_data_map, &src);
	}
	return st;
}

static __always_inline __u8 token_bucket_ok(__u64 *tokens, __u64 *last_ns, const __u32 rate, const __u32 burst)
{
	__u64 now = bpf_ktime_get_ns(), delta = now - *last_ns;
	if (delta) {
		__u64 ref = (rate * delta) / 1000000000ULL;
		if (ref) {
			*tokens = (*tokens + ref > burst) ? burst : *tokens + ref;
			*last_ns = now;
		}
	}
	if (*tokens) {
		(*tokens)--;
		return 1;
	}
	return 0;
}

/* —— XDP Program —— */
SEC("xdp")
int xdp_ddos(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	__be16 eth_proto;

	void *ptr = parse_ethhdr(data, end, &eth_proto);
	if (!ptr || eth_proto != htons(ETH_P_IP))
		goto PASS;

	struct iphdr *iph = ptr;
	if ((void *)(iph + 1) > end)
		goto PASS;
	__u8 ihl = iph->ihl * 4;
	if ((void *)iph + ihl > end)
		goto PASS;

	__u32 src = iph->saddr; /* Network order for map key. */

	void *l4 = (void *)iph + ihl;
	if (l4 > end)
		goto PASS;
	__u16 total = ntohs(iph->tot_len);
	__u16 payload = (total > ihl) ? total - ihl : 0;

	struct ip_data *st = get_ip_data(src);
	if (!st)
		goto PASS; /* Fail-safe: Pass if map issue. */

	switch (iph->protocol) {
	case IPPROTO_UDP: {
		struct udphdr *u = l4;
		if ((void *)(u + 1) > end)
			goto PASS;
		__u16 dport = ntohs(u->dest);
		if (payload > SMALL_PAYLOAD_BYTES || bpf_map_lookup_elem(&allow_ports, &dport))
			goto PASS; /* Bypass for large or allowed. */

		if (!token_bucket_ok(&st->udp.tokens, &st->udp.last_ns, UDP_RATE_PPS, UDP_BURST))
			goto DROP;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *ic = l4;
		if ((void *)(ic + 1) > end)
			goto PASS;
		if (payload > SMALL_PAYLOAD_BYTES)
			goto PASS;

		if (!token_bucket_ok(&st->icmp.tokens, &st->icmp.last_ns, ICMP_RATE_PPS, ICMP_BURST))
			goto DROP;
		break;
	}
	case IPPROTO_TCP: {
		struct tcphdr *t = l4;
		if ((void *)(t + 1) > end)
			goto PASS;
		if (t->syn && !t->ack) {
			if (!token_bucket_ok(&st->syn.tokens, &st->syn.last_ns, SYN_RATE_PPS, SYN_BURST))
				goto DROP;
		}
		break;
	}
	default:
		goto PASS;
	}

PASS:
	increment_stat(0);
	return XDP_PASS;
DROP:
	increment_stat(1);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
