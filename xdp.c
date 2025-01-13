#define KBUILD_MODNAME "xdp_prog"
#include <linux/bpf.h>            // For struct xdp_md, XDP_* return codes
#include <bpf/bpf_helpers.h>      // For SEC(), bpf_map_* APIs, etc.
#include <bpf/bpf_endian.h>       // For bpf_htons, bpf_ntohs, etc.

//Minimal local definitions for protocol headers (Ethernet, IPv4, TCP, UDP, ICMP)
#define ETH_P_IP       0x0800  // Internet Protocol v4

#define IPPROTO_ICMP   1
#define IPPROTO_TCP    6
#define IPPROTO_UDP    17

// Ethernet header
struct ethhdr {
    __u8    h_dest[6];
    __u8    h_source[6];
    __be16  h_proto;
};

// Basic IPv4 header with bitfields for version and IHL
struct iphdr {
#if defined(__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
            ihl:4;
#else
    __u8    ihl:4,
            version:4;
#endif
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __be16  check;
    __be32  saddr;
    __be32  daddr;
};

// Minimal TCP header
struct tcphdr {
    __be16  source;
    __be16  dest;
    __be32  seq;
    __be32  ack_seq;
#if defined(__BIG_ENDIAN_BITFIELD)
    __u16   doff:4,
            res1:4,
            cwr:1,
            ece:1,
            urg:1,
            ack:1,
            psh:1,
            rst:1,
            syn:1,
            fin:1;
#else
    __u16   res1:4,
            doff:4,
            fin:1,
            syn:1,
            rst:1,
            psh:1,
            ack:1,
            urg:1,
            ece:1,
            cwr:1;
#endif
    __be16  window;
    __be16  check;
    __be16  urg_ptr;
};

// Minimal UDP header
struct udphdr {
    __be16  source;
    __be16  dest;
    __be16  len;
    __be16  check;
};

// Minimal ICMP header
struct icmphdr {
    __u8    type;
    __u8    code;
    __be16  checksum;
    union {
        struct {
            __be16  id;
            __be16  sequence;
        } echo;
        __be32  gateway;
        struct {
            __be16  __unused;
            __be16  mtu;
        } frag;
    } un;
};

//Configuration constants and data structures for rate-limiting & blacklisting
#define SYN_RATE_THRESHOLD   10000   // Max SYN packets/sec
#define UDP_RATE_THRESHOLD   15000   // Max UDP packets/sec
#define ICMP_RATE_THRESHOLD  4000   // Max ICMP packets/sec

#define BLACKLIST_DURATION   60     // in seconds
#define DECAY_INTERVAL       1000000000ULL  // 1 second (in nanoseconds)

#define STATS_KEY_PASS       0
#define STATS_KEY_DROP       1

struct rate_data {
    __u64 packet_count;
    __u64 last_seen;   // nanosec timestamp of last packet
};

/* -----------------------------------------------------------------------
 * eBPF Maps:
 *  - per-protocol counters
 *  - blacklist
 *  - per-CPU stats
 * -----------------------------------------------------------------------
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // src IP
    __type(value, struct rate_data);
    __uint(max_entries, 1024);
} syn_count_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // src IP
    __type(value, struct rate_data);
    __uint(max_entries, 1024);
} udp_count_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // src IP
    __type(value, struct rate_data);
    __uint(max_entries, 1024);
} icmp_count_map SEC(".maps");

/* Blacklist map: IP -> timestamp blacklisted */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // src IP
    __type(value, __u64); // time in ns
    __uint(max_entries, 1024);
} blacklist_map SEC(".maps");

/* Per-CPU stats: pass/drop counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

//Helper to increment per-CPU pass/drop counters
static __always_inline void increment_stat(__u32 stat_key)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &stat_key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/* -----------------------------------------------------------------------
 * Basic TCP scan detection:
 *  - X-mas scan: FIN+PSH+URG all set
 *  - Null scan: no flags set
 * -----------------------------------------------------------------------
 */
static __always_inline int is_xmas_scan(struct tcphdr *tcp)
{
    return (tcp->fin && tcp->psh && tcp->urg);
}
static __always_inline int is_null_scan(struct tcphdr *tcp)
{
    return (!tcp->fin && !tcp->syn && !tcp->rst &&
            !tcp->psh && !tcp->ack && !tcp->urg);
}

/* -----------------------------------------------------------------------
 * Drop typical "bogon"/private IP addresses on WAN interface
 * Adjust as needed if your use case differs
 * -----------------------------------------------------------------------
 */
static __always_inline int is_bogon_ip(__u32 ip_be)
{
    __u32 ip = bpf_ntohl(ip_be);

    /* 127.0.0.0/8 (loopback) */
    if ((ip & 0xFF000000) == 0x7F000000)
        return 1;
    /* 10.0.0.0/8 */
    if ((ip & 0xFF000000) == 0x0A000000)
        return 1;
    /* 172.16.0.0/12 */
    if ((ip & 0xFFF00000) == 0xAC100000)
        return 1;
    /* 192.168.0.0/16 */
    if ((ip & 0xFFFF0000) == 0xC0A80000)
        return 1;
    /* Link-local 169.254.0.0/16 */
    if ((ip & 0xFFFF0000) == 0xA9FE0000)
        return 1;
    /* 100.64.0.0/10 */
    if ((ip & 0xFFC00000) == 0x64400000)
        return 1;

    return 0;
}

//Check blacklist: drop if still valid, remove if expired
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

/* -----------------------------------------------------------------------
 * Rate-limit function for SYN, UDP, and ICMP:
 *  - Resets if DECAY_INTERVAL passed
 *  - Blacklists if threshold exceeded
 * -----------------------------------------------------------------------
 */
static __always_inline int handle_rate_limit(__u32 src_ip, __u64 now,
                                             void *map_ptr, __u64 threshold)
{
    struct rate_data *rd = bpf_map_lookup_elem(map_ptr, &src_ip);
    if (!rd) {
        struct rate_data new_data = {
            .packet_count = 1,
            .last_seen    = now
        };
        bpf_map_update_elem(map_ptr, &src_ip, &new_data, BPF_ANY);
        return XDP_PASS;
    }

    if ((now - rd->last_seen) > DECAY_INTERVAL) {
        rd->packet_count = 0;
        rd->last_seen    = now;
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

//Skip only the Ethernet header (no VLAN support)
static __always_inline void *skip_ethhdr(void *data, void *data_end, __be16 *proto)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return NULL;

    *proto = eth->h_proto;
    return eth + 1;
}

/* -----------------------------------------------------------------------
 * Main XDP Hook:
 * 1. Skip Ethernet
 * 2. Validate IPv4
 * 3. Check IP header
 * 4. Block fragments & suspicious TTL
 * 5. Block private/bogon IPs
 * 6. Check blacklist
 * 7. Rate-limit TCP SYN, UDP, ICMP
 * 8. TCP scan detection
 * -----------------------------------------------------------------------
 */
SEC("xdp")
int xdp_ddos_mitigation(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now      = bpf_ktime_get_ns();

    // 1) Ethernet (no VLAN)
    __be16 proto;
    void *cursor = skip_ethhdr(data, data_end, &proto);
    if (!cursor)
        goto pass;

    // 2) IPv4 only
    if (proto != bpf_htons(ETH_P_IP))
        goto pass;

    // 3) Check IP
    struct iphdr *ip = cursor;
    if ((void *)(ip + 1) > data_end)
        goto pass;

    __u8 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip))
        goto pass;
    if ((void *)ip + ip_hdr_len > data_end)
        goto pass;

    __u32 src_ip = ip->saddr;

    // 4) Fragments & suspicious TTL
    if (ip->frag_off & bpf_htons(0x1FFF))
        goto drop;
    if (ip->ttl < 10)
        goto drop;

    // 5) Bogon IP check
    if (is_bogon_ip(src_ip))
        goto drop;

    // 6) Blacklist
    if (check_blacklist(src_ip, now) == XDP_DROP)
        goto drop;

    // 7) L4 rate-limiting & 8) TCP scan detection
    void *l4hdr = (void *)ip + ip_hdr_len;
    if (l4hdr > data_end)
        goto pass;

    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = l4hdr;
        if ((void *)(tcp + 1) > data_end)
            goto pass;

        // Basic scans
        if (is_xmas_scan(tcp))
            goto drop;
        if (is_null_scan(tcp))
            goto drop;

        // SYN flood: if SYN and not ACK
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
    default:
        // Other protocols allowed through
        break;
    }

pass:
    increment_stat(STATS_KEY_PASS);
    return XDP_PASS;

drop:
    increment_stat(STATS_KEY_DROP);
    return XDP_DROP;
}

//BPF requires a license to load; "GPL" is the canonical choice
char _license[] SEC("license") = "GPL";
