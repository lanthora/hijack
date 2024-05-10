// SPDX-License-Identifier: GPL-2.0-only
#ifndef HIJACK_EBPF_SOCKOPS_H
#define HIJACK_EBPF_SOCKOPS_H

#include "hijack-ebpf/maps.h"
#include "hijack-ebpf/types.h"
#include "hijack-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static void sockops_set_hdr_cb_flags(struct bpf_sock_ops *skops)
{
	bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
}

static void sockops_clear_hdr_cb_flags(struct bpf_sock_ops *skops)
{
	bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags & ~(BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG));
}

static u64 sockops_current_pid_tgid()
{
	int zero = 0;
	u64 *pid_tgid = bpf_map_lookup_elem(&percpu_syscall_proc_map, &zero);
	return pid_tgid ? *pid_tgid : 0;
}

static bool skops_can_add_cafe(struct bpf_sock_ops *skops)
{
	if (!(skops->skb_tcp_flags & TCPHDR_PSH))
		return false;

	// 用缓存的 MSS 判断本次添加 TCP Option 后是否会超过 MTU.
	if (skops->skb_len + TCP_OPTIONS_EXP_CAFE_LEN > skops->mss_cache)
		return false;

	return true;
}

static inline void sockops_tcp_reserve_hdr_cafe(struct bpf_sock_ops *skops)
{
	if (!skops_can_add_cafe(skops))
		return;

	bpf_reserve_hdr_opt(skops, TCP_OPTIONS_EXP_CAFE_LEN, 0);
}

static inline void sockops_tcp_store_hdr_cafe(struct bpf_sock_ops *skops)
{
	struct tcp_options_header header;

	if (!skops_can_add_cafe(skops))
		return;

	header.kind = TCP_OPTIONS_EXP;
	header.length = TCP_OPTIONS_EXP_CAFE_LEN;
	header.exid = bpf_htons(TCP_OPTIONS_EXP_CAFE);
	header.tgid = bpf_htonl(sockops_current_pid_tgid() >> 32);
	bpf_store_hdr_opt(skops, &header, TCP_OPTIONS_EXP_CAFE_LEN, 0);
}

static inline int sockops_write_tcp_options(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		sockops_set_hdr_cb_flags(skops);
		break;
	case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
		sockops_tcp_reserve_hdr_cafe(skops);
		break;
	case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
		sockops_tcp_store_hdr_cafe(skops);
		break;
	}

	return 0;
}

#endif
