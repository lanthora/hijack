// SPDX-License-Identifier: GPL-2.0-only
#ifndef HIJACK_EBPF_SCHED_H
#define HIJACK_EBPF_SCHED_H

#include "hijack-ebpf/callstack.h"
#include "hijack-ebpf/log.h"
#include "hijack-ebpf/maps.h"

static int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (cfg && cfg->sched_disabled)
		return 0;

	// 有些主进程会临时创建工作进程处理任务,这种情况下根据进程号设置的配置将无效.
	// 复制父进程的配置,有可能创建的只是一个新的线程,会冗余一部分信息,但不影响正确性
	pid_t parent_pid = ctx->parent_pid;
	pid_t child_pid = ctx->child_pid;
	struct pproc_cfg *pproc_cfg = bpf_map_lookup_elem(&pproc_cfg_map, &parent_pid);
	if (pproc_cfg) {
		pid_t child_pid = ctx->child_pid;
		bpf_map_update_elem(&pproc_cfg_map, &child_pid, pproc_cfg, BPF_ANY);
	}

	struct event_sched *e = (struct event_sched *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct event_sched), 0);
	if (e) {
		e->type = RB_EVENT_SCHED;
		e->op = 0;
		e->pid = ctx->child_pid;
		e->ppid = ctx->parent_pid;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

static int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (cfg && cfg->sched_disabled)
		return 0;

	struct event_sched *e = (struct event_sched *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct event_sched), 0);
	if (e) {
		e->type = RB_EVENT_SCHED;
		e->op = 1;
		e->pid = ctx->pid;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

static int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	int zero = 0;
	struct global_cfg *cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
	if (cfg && cfg->sched_disabled)
		return 0;

	int pid = ctx->pid;

	bpf_map_delete_elem(&pproc_cfg_map, &pid);
	bpf_map_delete_elem(&sched_switch_event_map, &pid);

	struct event_sched *e = (struct event_sched *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct event_sched), 0);
	if (e) {
		e->type = RB_EVENT_SCHED;
		e->op = 2;
		e->pid = ctx->pid;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

static int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	int pid = 0;
	unsigned long long duration = 0;
	struct sched_switch_event *event = NULL;

	// offcpu
	pid = ctx->prev_pid;
	event = bpf_map_lookup_elem(&sched_switch_event_map, &pid);
	if (event) {
		event->tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
		event->offcpu_timestamp = bpf_ktime_get_boot_ns();
		event->stackid = bpf_get_stackid(ctx, &stack_trace_map, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);
		event->prev_state = ctx->prev_state;
	}

	// oncpu
	pid = ctx->next_pid;
	event = bpf_map_lookup_elem(&sched_switch_event_map, &pid);
	if (event) {
		if (event->offcpu_timestamp) {
			duration = bpf_ktime_get_boot_ns() - event->offcpu_timestamp;
		}
		if (event->stackid > 0 && event->prev_state != 0) {
			trace_offcpu_call_stack(ctx, event->tgid, pid, duration, event->stackid);
		}
		event->offcpu_timestamp = 0;
	}

	return 0;
}

#endif
