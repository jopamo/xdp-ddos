/* XDP program for permanent IP blocking using LPM_TRIE.
 * Build: clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c drop-ng.c -o drop-ng.o
 */
#define KBUILD_MODNAME "xdp_prog"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ----- Protocol IDs ----- */
#define ETH_P_IP 0x0800

/* ----- Byte‑order wrappers (readability only) ----- */
#define ntohs(x) bpf_ntohs(x)
#define htons(x) bpf_htons(x)

/* ----- Header layouts (no #includes keeps BTF small) ----- */
struct ethhdr {
	__u8 dst[6];
	__u8 src[6];
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
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
};

/* ----- Maps ----- */
/* 0 = passed, 1 = dropped */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

/* LPM‑Trie of blocked prefixes */
struct lpm_key {
	__u32 prefixlen; /* up to 32 */
	__u32 data; /* __be32 IPv4 */
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u8); /* dummy */
} blocked_ips SEC(".maps");

/* ----- Helpers ----- */
static __always_inline void inc_stat(__u32 idx)
{
	volatile __u64 *v = bpf_map_lookup_elem(&stats_map, &idx);
	if (v)
		__sync_fetch_and_add(v, 1); /* verifier‑friendly */
}

static __always_inline void *parse_eth(void *data, void *end, __be16 *proto)
{
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return NULL;
	*proto = eth->proto;
	return eth + 1;
}

/* ----- XDP entry ----- */
SEC("xdp")
int xdp_block_ips(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	__be16 eth_proto;

	void *pos = parse_eth(data, end, &eth_proto);
	if (!pos || eth_proto != htons(ETH_P_IP))
		goto pass;

	struct iphdr *iph = pos;
	if ((void *)(iph + 1) > end)
		goto pass;

	/* Longest‑prefix lookup; we probe with /32 key */
	struct lpm_key key = {
		.prefixlen = 32, .data = iph->saddr /* already network order */
	};

	if (bpf_map_lookup_elem(&blocked_ips, &key))
		goto drop;

pass:
	inc_stat(0);
	return XDP_PASS;
drop:
	inc_stat(1);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
