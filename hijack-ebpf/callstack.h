// SPDX-License-Identifier: GPL-2.0-only
#ifndef HIJACK_EBPF_CALLSTACK_H
#define HIJACK_EBPF_CALLSTACK_H

#include "hijack-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static int trace_user_call_stack(void *ctx, char *name)
{
	struct event_user_call_stack *e = (struct event_user_call_stack *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct event_user_call_stack), 0);
	if (e) {
		e->stackid = bpf_get_stackid(ctx, &stack_trace_map, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);
		if (e->stackid < 0) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}
		e->type = RB_EVENT_USER_CALL_STACK;
		e->nsec = bpf_ktime_get_boot_ns();
		e->tgid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(e->comm, sizeof(e->comm));
		bpf_probe_read_kernel_str(e->name, sizeof(e->name), name);
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

static int trace_offcpu_call_stack(struct trace_event_raw_sched_switch *ctx, int tgid, int pid, unsigned long long duration, long stackid)
{
	struct event_offcpu_call_stack *e = (struct event_offcpu_call_stack *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct event_offcpu_call_stack), 0);
	if (e) {
		e->type = RB_EVENT_OFFCPU_CALL_STACK;
		e->nsec = bpf_ktime_get_boot_ns();
		e->tgid = tgid;
		e->pid = pid;
		e->duration = duration;
		e->stackid = stackid;
		bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), ctx->next_comm);
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

#endif
