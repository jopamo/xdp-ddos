/* XDP program for permanent IP blocking using LPM_TRIE.

 */

#define KBUILD_MODNAME "xdp_prog"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* —— Protocol IDs —— */
#define ETH_P_IP 0x0800

/* Byte‑order wrappers */
#define ntohs(x) bpf_ntohs(x)
#define htons(x) bpf_htons(x)
#define ntohl(x) bpf_ntohl(x)
#define htonl(x) bpf_htonl(x)

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

/* —— Maps —— */
/* Stats map for tracking passed (idx=0) and dropped (idx=1) packets—useful for monitoring and debugging. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

/* LPM trie map for blocked IP addresses and ranges.
 * Key: prefixlen (up to 32) + IP data in network byte order (__be32 equivalent).
 * Use prefixlen=32 for individual IPs, lower for CIDR ranges (e.g., /24).
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536); /* Increased for production scale; efficient trie handles it. */
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(
		key, struct {
			__u32 prefixlen;
			__u32 data; /* IP address in network byte order. */
		});
	__type(value, __u8); /* Dummy value; presence indicates block. */
} blocked_ips SEC(".maps");

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

/* —— XDP Program —— */
SEC("xdp")
int xdp_block_ips(struct xdp_md *ctx)
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

	/* Prepare LPM key for source IP lookup: full /32 prefix for LPM matching. */
	struct {
		__u32 prefixlen;
		__u32 data;
	} key = { .prefixlen = 32, .data = iph->saddr }; /* saddr already in network order. */

	/* Lookup: If any matching prefix (longest first), drop the packet. */
	__u8 *val = bpf_map_lookup_elem(&blocked_ips, &key);
	if (val)
		goto DROP;

PASS:
	increment_stat(0);
	return XDP_PASS;
DROP:
	increment_stat(1);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
