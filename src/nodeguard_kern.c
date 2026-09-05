// SPDX-License-Identifier: GPL-2.0
// nodeguard: XDP blocklist firewall fed by a passive Suricata IDS.
//
// SAFETY: every failure path returns XDP_PASS (see design.md section 2).
// The ONLY drop is an unexpired blocklist hit on a source address that did
// not match the allowlist, the WireGuard port pass, or the kill switch.
//
// INVARIANT: map parameters here are the single source of truth. Dependents:
// nodeguard-maps.spec (generated from this object at build time) and
// nodeguard-maps.service (creates or verifies pins only from that spec).

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/xdp_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define NG_DISPATCHER_PRIORITY 10

// 13-bit IPv4 fragment offset (UAPI linux/ip.h does not define IP_OFFSET).
#define NG_IPV4_FRAG_OFFSET_MASK bpf_htons(0x1FFF)

struct lpm_v4_key {
	__u32 prefixlen;
	__u8 addr[4];
};

struct lpm_v6_key {
	__u32 prefixlen;
	__u8 addr[16];
};

struct block_val {
	__u64 expiry_ns; // INVARIANT: CLOCK_MONOTONIC ns; 0 = permanent (manual entries only)
	__u64 hits;
};

// config slots (u64 values, host byte order)
enum {
	CFG_WG_PORT = 0,   // tailscaled's live WireGuard UDP listen port
	CFG_KILL_SWITCH,   // nonzero = pass everything
	CFG_REARM_COUNT,   // watchdog auto re-arms this boot
	CFG_RESERVED,
	CFG_MAX,
};

// stats slots
enum {
	ST_PASS = 0,
	ST_DROP_V4,
	ST_DROP_V6,
	ST_PASS_EXPIRED,
	ST_PASS_ALLOW,
	ST_PASS_WGPORT,
	ST_PASS_NONIP,
	ST_PASS_PARSEFAIL,
	ST_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v4_key);
	__type(value, __u8);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} allow4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v6_key);
	__type(value, __u8);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} allow6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v4_key);
	__type(value, struct block_val);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} block4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v6_key);
	__type(value, struct block_val);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} block6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, CFG_MAX);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, ST_MAX);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

static __always_inline void count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		(*v)++;
}

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

// The attach points carry untagged traffic today; one 802.1Q header is
// parsed and skipped so a tagged frame is judged on its real payload
// rather than passing as non-IP.
static __always_inline int handle_v4(void *nh, void *data_end, __u64 wg_port)
{
	struct iphdr *ip = nh;
	struct lpm_v4_key key = { .prefixlen = 32 };
	struct block_val *bv;

	if ((void *)(ip + 1) > data_end) {
		count(ST_PASS_PARSEFAIL);
		return XDP_PASS;
	}

	// SAFETY: the port read is attempted only at fragment offset zero;
	// non-first fragments carry payload where the UDP header would be.
	// RESIDUAL: a truncated UDP header or a non-first fragment cannot
	// match the WireGuard port and falls through to the block/allow
	// lookups instead of the WG-port pass (it is not a parse failure of
	// the packet as a whole); a blocked source's non-first WireGuard
	// fragments are dropped by this path rather than passed.
	if (ip->protocol == IPPROTO_UDP && wg_port &&
	    (ip->frag_off & NG_IPV4_FRAG_OFFSET_MASK) == 0) {
		__u32 ihl = ip->ihl * 4;

		if (ihl >= sizeof(*ip)) {
			struct udphdr *udp = nh + ihl;

			// INVARIANT: wg_port is validated to 1-65535 at the
			// write boundary (ngmap.py set-config); the cast
			// documents the width, it does not sanitize.
			if ((void *)(udp + 1) <= data_end &&
			    bpf_ntohs(udp->dest) == (__u16)wg_port) {
				count(ST_PASS_WGPORT);
				return XDP_PASS;
			}
		}
	}

	__builtin_memcpy(key.addr, &ip->saddr, 4);

	if (bpf_map_lookup_elem(&allow4, &key)) {
		count(ST_PASS_ALLOW);
		return XDP_PASS;
	}

	bv = bpf_map_lookup_elem(&block4, &key);
	if (!bv) {
		count(ST_PASS);
		return XDP_PASS;
	}
	if (bv->expiry_ns && bpf_ktime_get_ns() >= bv->expiry_ns) {
		count(ST_PASS_EXPIRED);
		return XDP_PASS;
	}
	__sync_fetch_and_add(&bv->hits, 1);
	count(ST_DROP_V4);
	return XDP_DROP;
}

static __always_inline int handle_v6(void *nh, void *data_end, __u64 wg_port)
{
	struct ipv6hdr *ip6 = nh;
	struct lpm_v6_key key = { .prefixlen = 128 };
	struct block_val *bv;

	if ((void *)(ip6 + 1) > data_end) {
		count(ST_PASS_PARSEFAIL);
		return XDP_PASS;
	}

	// No extension-header walk: only a directly following UDP header can
	// match the WireGuard pass; anything else proceeds to the lookups.
	if (ip6->nexthdr == IPPROTO_UDP && wg_port) {
		struct udphdr *udp = (void *)(ip6 + 1);

		if ((void *)(udp + 1) <= data_end &&
		    bpf_ntohs(udp->dest) == (__u16)wg_port) {
			count(ST_PASS_WGPORT);
			return XDP_PASS;
		}
	}

	__builtin_memcpy(key.addr, &ip6->saddr, 16);

	if (bpf_map_lookup_elem(&allow6, &key)) {
		count(ST_PASS_ALLOW);
		return XDP_PASS;
	}

	bv = bpf_map_lookup_elem(&block6, &key);
	if (!bv) {
		count(ST_PASS);
		return XDP_PASS;
	}
	if (bv->expiry_ns && bpf_ktime_get_ns() >= bv->expiry_ns) {
		count(ST_PASS_EXPIRED);
		return XDP_PASS;
	}
	__sync_fetch_and_add(&bv->hits, 1);
	count(ST_DROP_V6);
	return XDP_DROP;
}

struct {
	__uint(priority, NG_DISPATCHER_PRIORITY);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(nodeguard);

SEC("xdp")
int nodeguard(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	void *nh;
	__u16 proto;
	__u32 cfg_key;
	__u64 *val;
	__u64 wg_port = 0;

	if ((void *)(eth + 1) > data_end) {
		count(ST_PASS_PARSEFAIL);
		return XDP_PASS;
	}
	proto = eth->h_proto;
	nh = eth + 1;

	if (proto == bpf_htons(ETH_P_8021Q) ||
	    proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vh = nh;

		if ((void *)(vh + 1) > data_end) {
			count(ST_PASS_PARSEFAIL);
			return XDP_PASS;
		}
		proto = vh->h_vlan_encapsulated_proto;
		nh = vh + 1;
	}

	if (proto != bpf_htons(ETH_P_IP) && proto != bpf_htons(ETH_P_IPV6)) {
		count(ST_PASS_NONIP);
		return XDP_PASS;
	}

	cfg_key = CFG_KILL_SWITCH;
	val = bpf_map_lookup_elem(&config, &cfg_key);
	if (val && *val) {
		count(ST_PASS);
		return XDP_PASS;
	}

	cfg_key = CFG_WG_PORT;
	val = bpf_map_lookup_elem(&config, &cfg_key);
	if (val)
		wg_port = *val;

	if (proto == bpf_htons(ETH_P_IP))
		return handle_v4(nh, data_end, wg_port);
	return handle_v6(nh, data_end, wg_port);
}
