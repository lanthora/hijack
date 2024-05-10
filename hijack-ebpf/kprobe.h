// SPDX-License-Identifier: GPL-2.0-only
#ifndef HIJACK_EBPF_KPROBE_H
#define HIJACK_EBPF_KPROBE_H

#include "hijack-ebpf/callstack.h"
#include "hijack-ebpf/log.h"
#include "hijack-ebpf/skb.h"
#include "hijack-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static int trace_nf_hook_slow_enter(struct sk_buff *skb)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->nf_hook_slow_enabled)
		return 0;

	struct hook_ctx_key key = { .func = FUNC_KP_NF_HOOK_SLOW };
	struct hook_ctx_value value = { .skb = skb };

	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);

	return 0;
}

static int trace_nf_hook_slow_exit(int ret)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->nf_hook_slow_enabled)
		return 0;

	struct hook_ctx_key key = { .func = FUNC_KP_NF_HOOK_SLOW };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	static const int EPERM = 1;

	if (value && value->skb && ret == -EPERM) {
		struct iphdr *iph = ip_hdr(value->skb);
		u8 protocol = BPF_CORE_READ(iph, protocol);

		if (protocol != IPPROTO_ICMP && protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
			return 0;

		u32 saddr = BPF_CORE_READ(iph, saddr);
		u32 daddr = BPF_CORE_READ(iph, daddr);

		LOG("nf_hook_slow: protocol=%u saddr=%pI4 daddr=%pI4", protocol, &saddr, &daddr);
	}

	bpf_map_delete_elem(&hook_ctx_map, &key);

	return 0;
}

static int trace_handle_mm_fault_exit(struct pt_regs *ctx, vm_fault_t ret)
{
	if (ret == VM_FAULT_SIGSEGV)
		return 0;

	if (ret & VM_FAULT_MAJOR)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->handle_mm_fault_enabled)
		return 0;

	trace_user_call_stack(ctx, "handle_mm_fault");
	return 0;
}

static int trace_tcp_set_state_enter(struct pt_regs *ctx, struct sock *sk, int state)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->socket_to_pid_enabled)
		return 0;

	bool last_ack = (state == TCP_LAST_ACK) && (BPF_CORE_READ(sk, sk_state) == TCP_CLOSE_WAIT);
	bool fin_wait_1 = (state == TCP_FIN_WAIT1) && (BPF_CORE_READ(sk, sk_state) == TCP_ESTABLISHED);
	if (!last_ack && !fin_wait_1)
		return 0;

	if (BPF_CORE_READ(sk, sk_family) != AF_INET)
		return 0;

	u32 local_addr = BPF_CORE_READ(sk, sk_rcv_saddr);
	u32 remote_addr = BPF_CORE_READ(sk, sk_daddr);
	u16 local_port = BPF_CORE_READ(sk, sk_num);
	u16 remote_port = BPF_CORE_READ(sk, sk_dport);
	remote_port = bpf_ntohs(remote_port);

	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	if (last_ack) {
		LOG("tcp last_ack: local=%pI4:%u remote=%pI4:%u tgid=%d comm=%s", &local_addr, local_port, &remote_addr, remote_port, tgid, comm);
	} else {
		LOG("tcp fin_wait_1: local=%pI4:%u remote=%pI4:%u tgid=%d comm=%s", &local_addr, local_port, &remote_addr, remote_port, tgid, comm);
	}

	return 0;
}

static int trace_tcp_connect_enter(struct pt_regs *ctx, struct sock *sk)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->socket_to_pid_enabled)
		return 0;

	if (BPF_CORE_READ(sk, sk_family) != AF_INET)
		return 0;

	u32 local_addr = BPF_CORE_READ(sk, sk_rcv_saddr);
	u32 remote_addr = BPF_CORE_READ(sk, sk_daddr);
	u16 local_port = BPF_CORE_READ(sk, sk_num);
	u16 remote_port = BPF_CORE_READ(sk, sk_dport);
	remote_port = bpf_ntohs(remote_port);

	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	LOG("tcp connect: local=%pI4:%u remote=%pI4:%u tgid=%d comm=%s", &local_addr, local_port, &remote_addr, remote_port, tgid, comm);
	return 0;
}

static int trace_inet_csk_accept_exit(struct pt_regs *ctx, struct sock *accepted_sk)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->socket_to_pid_enabled)
		return 0;

	if (BPF_CORE_READ(accepted_sk, sk_family) != AF_INET)
		return 0;

	u32 local_addr = BPF_CORE_READ(accepted_sk, sk_rcv_saddr);
	u32 remote_addr = BPF_CORE_READ(accepted_sk, sk_daddr);
	u16 local_port = BPF_CORE_READ(accepted_sk, sk_num);
	u16 remote_port = BPF_CORE_READ(accepted_sk, sk_dport);
	remote_port = bpf_ntohs(remote_port);

	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	LOG("tcp accept: local=%pI4:%u remote=%pI4:%u tgid=%d comm=%s", &local_addr, local_port, &remote_addr, remote_port, tgid, comm);
	return 0;
}

#endif
