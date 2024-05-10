// SPDX-License-Identifier: GPL-2.0-only
#ifndef HIJACK_EBPF_FENTRY_H
#define HIJACK_EBPF_FENTRY_H

#include "hijack-ebpf/log.h"
#include "hijack-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static int trace_udp_lib_get_port_exit(struct sock *sk, unsigned short snum, unsigned int hash2_nulladdr, int ret)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->socket_to_pid_enabled)
		return 0;

	if (ret != 0)
		return 0;

	if (BPF_CORE_READ(sk, sk_family) != AF_INET)
		return 0;

	// FIXME: local_addr 没有取到值
	u32 local_addr = BPF_CORE_READ(sk, sk_rcv_saddr);
	u16 local_port = BPF_CORE_READ(sk, sk_num);

	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	LOG("udp get port: local=%pI4:%u tgid=%d comm=%s", &local_addr, local_port, tgid, comm);

	return 0;
}

static int trace_udp_lib_unhash_enter(struct sock *sk)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (!cfg || !cfg->socket_to_pid_enabled)
		return 0;

	if (BPF_CORE_READ(sk, sk_family) != AF_INET)
		return 0;

	u32 local_addr = BPF_CORE_READ(sk, sk_rcv_saddr);
	u16 local_port = BPF_CORE_READ(sk, sk_num);

	if (local_port == 0)
		return 0;

	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	LOG("udp put port: local=%pI4:%u tgid=%d comm=%s", &local_addr, local_port, tgid, comm);
	return 0;
}

#endif
