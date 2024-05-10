// SPDX-License-Identifier: GPL-2.0-only
#ifndef HIJACK_EBPF_SKB_H
#define HIJACK_EBPF_SKB_H

#include "hijack-ebpf/log.h"
#include "hijack-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
	return BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header);
}

static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_network_header(skb);
}

static int trace_ipv4_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
	struct iphdr *iph = (struct iphdr *)skb_network_header(ctx->skbaddr);
	u8 protocol = BPF_CORE_READ(iph, protocol);

	if (protocol != IPPROTO_ICMP && protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
		return 0;

	u32 saddr = BPF_CORE_READ(iph, saddr);
	u32 daddr = BPF_CORE_READ(iph, daddr);

	LOG("kfree_skb: reason=%u protocol=%u saddr=%pI4 daddr=%pI4", ctx->reason, protocol, &saddr, &daddr);
	return 0;
}

static int trace_ipv6_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
	struct ipv6hdr *iph = (struct ipv6hdr *)skb_network_header(ctx->skbaddr);
	u8 protocol = BPF_CORE_READ(iph, nexthdr);

	if (protocol != IPPROTO_ICMP && protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
		return 0;

	struct in6_addr saddr = BPF_CORE_READ(iph, saddr);
	struct in6_addr daddr = BPF_CORE_READ(iph, daddr);

	LOG("kfree_skb: reason=%u protocol=%u saddr=%pI6 daddr=%pI6", ctx->reason, protocol, &saddr, &daddr);
	return 0;
}

static int trace_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->kfree_skb_enabled)
		return 0;

	struct iphdr *iph = ip_hdr(ctx->skbaddr);
	u8 version = BPF_CORE_READ_BITFIELD_PROBED(iph, version);

	switch (version) {
	case 4:
		trace_ipv4_kfree_skb(ctx);
		break;
	case 6:
		trace_ipv6_kfree_skb(ctx);
		break;
	default:
		break;
	}
	return 0;
}

#endif
