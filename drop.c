/* SPDX-License-Identifier: GPL-2.0 */
#define KBUILD_MODNAME "xdp_block_ips_fast"

#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* ---- static IPv4 ranges (network-order) --------------------------- */
struct range_be {
	__be32 start, end;
};

static const volatile struct range_be blocked[] = {
	{ 0x2D8EC100, 0x2D8EC1FF }, /* 45.142.193.0/24   */
	{ 0x2DC24200, 0x2DC242FF }, /* 45.194.66.0/24    */
	{ 0x2F4A0000, 0x2F57FFFF }, /* 47.74.0.0-47.87   */
	{ 0x2F580000, 0x2F5BFFFF }, /* 47.88.0.0-47.91   */
	{ 0x4E807100, 0x4E8071FF }, /* 78.128.113/24     */
	{ 0x4F7C0000, 0x4F7CFFFF }, /* 79.124/16         */
	{ 0x4F7C3E00, 0x4F7C3EFF }, /* 79.124.62/24      */
	{ 0x505E5C00, 0x505E5CFF }, /* 80.94.92/24       */
	{ 0x505E5F00, 0x505E5FFF }, /* 80.94.95/24       */
	{ 0x53DEBE00, 0x53DEBFFF }, /* 83.222.190/23     */
	{ 0x59F8A300, 0x59F8A5FF }, /* 89.248.163/23     */
	{ 0x5BBFD180, 0x5BBFD1FF }, /* 91.191.209.128/25 */
	{ 0x5C3FC500, 0x5C3FC5FF }, /* 92.63.197/24      */
	{ 0x5C762700, 0x5C7627FF }, /* 92.118.39/24      */
	{ 0x5DAE5F00, 0x5DAE5FFF }, /* 93.174.95/24      */
	{ 0x5FD63400, 0x5FD637FF }, /* 95.214.52/22      */
	{ 0x6766E600, 0x6766E6FF }, /* 103.102.230/24    */
	{ 0x67D2F400, 0x67D2F5FF }, /* 103.210.244/23    */
	{ 0x71880000, 0x718FFFFF }, /* 113.136/13        */
	{ 0x72D80000, 0x72DFFFFF }, /* 114.216/13        */
	{ 0x73E74E00, 0x73E74E7F }, /* 115.231.78/25     */
	{ 0x75500000, 0x755FFFFF }, /* 117.80/12         */
	{ 0x76780000, 0x767BFFFF }, /* 118.120/14        */
	{ 0x771C0000, 0x771DFFFF }, /* 119.28/15         */
	{ 0x7BBC0000, 0x7BBFFFFF }, /* 123.188/14        */
	{ 0x8D620B00, 0x8D620BFF }, /* 141.98.11/24      */
	{ 0xB0419400, 0xB04194FF }, /* 176.65.148/24     */
	{ 0xB7E08000, 0xB7E3FFFF }, /* 183/14            */
	{ 0xB95B7F00, 0xB95B7F7F }, /* 185.91.127/25     */
	{ 0xB99C4900, 0xB99C49FF }, /* 185.156.73/24     */
	{ 0xB9E08000, 0xB9E080FF }, /* 185.224.128/24    */
	{ 0xC2B43000, 0xC2B430FF }, /* 194.180.48/24     */
	{ 0xC2B43100, 0xC2B431FF }, /* 194.180.49/24     */
	{ 0xC6120000, 0xC613FFFF }, /* 198.18/15         */
	{ 0xC6336400, 0xC63364FF }, /* 198.51.100/24     */
	{ 0xCB007100, 0xCB0071FF }, /* 203.0.113/24      */
	{ 0xCC4CCB00, 0xCC4CCBFF }, /* 204.76.203/24     */
	{ 0xDDE00000, 0xDDE7FFFF }, /* 221.224/13        */
};

#define RANGES (sizeof(blocked) / sizeof(blocked[0]))

static __always_inline bool ip_blocked(__be32 addr_be)
{
	/* kernel ≥5.3 supports bounded loops – no need for unrolling */ /* :contentReference[oaicite:6]{index=6} */
	for (int i = 0; i < RANGES; i++)
		if (addr_be >= blocked[i].start && addr_be <= blocked[i].end)
			return true;
	return false;
}

/* ---- XDP program --------------------------------------------------- */
SEC("xdp")
int xdp_block_ips(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (eth + 1 > (struct ethhdr *)end || eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if (ip + 1 > (struct iphdr *)end)
		return XDP_PASS;

	return ip_blocked(ip->saddr) ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
