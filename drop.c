#define KBUILD_MODNAME "xdp_prog"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

#define ntohs(x) bpf_ntohs(x)
#define htons(x) bpf_htons(x)
#define ntohl(x) bpf_ntohl(x)
#define htonl(x) bpf_htonl(x)

#define SYN_RATE_PPS 100000U
#define SYN_BURST 10000U

#define UDP_RATE_PPS 200000U
#define UDP_BURST 20000U

#define ICMP_RATE_PPS 100000U
#define ICMP_BURST 10000U

#define SMALL_PAYLOAD_BYTES 128

struct range {
	__u32 start;
	__u32 end;
};

static const struct range blocked_ranges[] = {
	{ 0x12200000U, 0x12FFFFFFU }, /* 18.32.0.0 - 18.255.255.255 */
	{ 0x23C00000U, 0x23CFFFFFU }, /* 35.192.0.0 - 35.207.255.255 */
	{ 0x4F7C3E00U, 0x4F7C3EFFU }, /* 79.124.62.0 - 79.124.62.255 (CLOUDVPS-NET, EU) */
	{ 0x505E5F00U, 0x505E5FFFU }, /* 80.94.95.0 - 80.94.95.255 (UNMANAGED-LTD, GB) */
	{ 0x53DEBE00U, 0x53DEBFFFU }, /* 83.222.190.0 - 83.222.191.255 (Net_4Media, BG) */
	{ 0x59F8A300U, 0x59F8A5FFU }, /* 89.248.163.0 - 89.248.165.255 */
	{ 0x5C762700U, 0x5C7627FFU }, /* 92.118.39.0 - 92.118.39.255 (DMZHOST, Netherlands) */
	{ 0x67D2F400U, 0x67D2F5FFU }, /* 103.210.244.0 - 103.210.245.255 */
	{ 0x68EA0000U, 0x68EAFFFFU }, /* 104.234.0.0 - 104.234.255.255 (Velcom, CA) */
	{ 0x73E74E00U, 0x73E74E7FU }, /* 115.231.78.0 - 115.231.78.127 (Hangzhou Duchuang Keji Co.,Ltd, China) */
	{ 0x771C0000U, 0x771DFFFFU }, /* 119.28.0.0 - 119.29.255.255 (IRT-TencentCloud-CN)*/
	{ 0x95320000U, 0x9532FFFFU }, /* 149.50.0.0 - 149.50.255.255 (COGENT-149-50-16, PSI-1) */
	{ 0xA2D89400U, 0xA2D897FFU }, /* 162.216.148.0 - 162.216.151.255 (Google Cloud) */
	{ 0xA75E8A00U, 0xA75E8AFFU }, /* 167.94.138.0 - 167.94.138.255 (Censys, Inc.)*/
	{ 0xB0419400U, 0xB04194FFU }, /* 176.65.148.0 - 176.65.148.255 (Pfcloud UG DE)*/
	{ 0xB95B7F00U, 0xB95B7F7FU }, /* 185.91.127.0 - 185.91.127.127 (TUBE-VPS, DE) */
	{ 0xB9DA5400U, 0xB9DA54FFU }, /* 185.218.84.0 - 185.218.84.255 (UK-NETIFACE-20250320, GB) */
	{ 0xC12EFF00U, 0xC12EFFFFU }, /* 193.46.255.0 - 193.46.255.255 (UNMANAGED-LTD, GB) */
	{ 0xC1A37D00U, 0xC1A37D7FU }, /* 193.163.125.0 - 193.163.125.127 (DRIFTNET-IPV4-A, GB) */
	{ 0xC2B43000U, 0xC2B430FFU }, /* 194.180.48.0 - 194.180.48.255 (Dedicated Servers IP Range, DE) */
	{ 0xC2B43100U, 0xC2B431FFU }, /* 194.180.49.0 - 194.180.49.255 (Dedicated Servers IP Range, DE) */
	{ 0xC4FB4600U, 0xC4FB46FFU }, /* 196.251.70.0 - 196.251.70.255 (internet-security-cheapyhost, Seychelles) */
	{ 0xC4FB5800U, 0xC4FB58FFU }, /* 196.251.88.0 - 196.251.88.255 (internet-security-cheapyhost, SC) */
	{ 0xCC4CCB00U, 0xCC4CCBFFU }, /* 204.76.203.0 - 204.76.203.255 (INTEL-NET1-25, NL) */
	{ 0x00000000U, 0x00FFFFFFU }, /* bogon: 0.0.0.0/8 */
	{ 0x0A000000U, 0x0AFFFFFFU }, /* bogon: 10.0.0.0/8 (private) */
	{ 0x64400000U, 0x6443FFFFU }, /* bogon: 100.64.0.0/10 (CGNAT) */
	{ 0x7F000000U, 0x7FFFFFFFU }, /* bogon: 127.0.0.0/8 (loopback) */
	{ 0xA9FE0000U, 0xA9FEFFFFU }, /* bogon: 169.254.0.0/16 (link-local) */
	{ 0xAC100000U, 0xAC1FFFFFU }, /* bogon: 172.16.0.0/12 (private) */
	{ 0xC0000000U, 0xC00000FFU }, /* bogon: 192.0.0.0/24 (reserved) */
	{ 0xC0000200U, 0xC00002FFU }, /* bogon: 192.0.2.0/24 (TEST-NET-1) */
	{ 0xC0A80000U, 0xC0A8FFFFU }, /* bogon: 192.168.0.0/16 (private) */
	{ 0xC6120000U, 0xC613FFFFU }, /* bogon: 198.18.0.0/15 (benchmarking) */
	{ 0xC6336400U, 0xC63364FFU }, /* bogon: 198.51.100.0/24 (TEST-NET-2) */
	{ 0xCB007100U, 0xCB0071FFU }, /* bogon: 203.0.113.0/24 (TEST-NET-3) */
	{ 0xE0000000U, 0xEFFFFFFFU }, /* bogon: 224.0.0.0/4 (multicast) */
	{ 0xF0000000U, 0xFFFFFFFFU }, /* bogon: 240.0.0.0/4 (reserved, including 255.255.255.255/32 broadcast) */
};

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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32);
	__type(key, __u16);
	__type(value, __u8);
} allow_ports SEC(".maps");

struct ip_data {
	struct {
		__u64 tokens, last_ns;
	} syn, udp, icmp;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct ip_data);
} ip_data_map SEC(".maps");

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

	__u32 src = iph->saddr;
	__u32 src_host = ntohl(src);

	for (int i = 0; i < sizeof(blocked_ranges) / sizeof(blocked_ranges[0]); i++) {
		if (src_host >= blocked_ranges[i].start && src_host <= blocked_ranges[i].end)
			goto DROP;
	}

	void *l4 = (void *)iph + ihl;
	if (l4 > end)
		goto PASS;
	__u16 total = ntohs(iph->tot_len);
	__u16 payload = (total > ihl) ? total - ihl : 0;

	struct ip_data *st = get_ip_data(src);
	if (!st)
		goto PASS;

	switch (iph->protocol) {
	case IPPROTO_UDP: {
		struct udphdr *u = l4;
		if ((void *)(u + 1) > end)
			goto PASS;
		__u16 dport = ntohs(u->dest);
		if (payload > SMALL_PAYLOAD_BYTES || bpf_map_lookup_elem(&allow_ports, &dport))
			goto PASS;

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
