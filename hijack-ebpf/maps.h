// SPDX-License-Identifier: GPL-2.0-only
#ifndef HIJACK_EBPF_MAPS_H
#define HIJACK_EBPF_MAPS_H

#include "hijack-common/config.h"
#include "hijack-common/types.h"
#include "hijack-ebpf/types.h"
#include "hijack-ebpf/vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, CONFIG_RINGBUF_SIZE_MAX);
} ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CONFIG_PROCESS_NUMBER_MAX);
	__type(key, int);
	__type(value, struct pproc_cfg);
} pproc_cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct global_cfg);
} global_cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CONFIG_CONCURRENT_THREAD_MAX);
	__type(key, struct hook_ctx_key);
	__type(value, struct hook_ctx_value);
} hook_ctx_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CONFIG_SOCK_NUM_MAX);
	__type(key, struct tcp_probe_key);
	__type(value, struct tcp_probe_value);
} tcp_probe_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, CONFIG_CONCURRENT_THREAD_MAX);
	__uint(key_size, sizeof(u32));
	__uint(value_size, CONFIG_MAX_STACK_DEPTH * sizeof(u64));
} stack_trace_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, u64);
} percpu_syscall_proc_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CONFIG_CONCURRENT_THREAD_MAX);
	__type(key, struct trace_object_key);
	__type(value, struct trace_object_value);
} trace_object_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CONFIG_CONCURRENT_THREAD_MAX);
	__type(key, struct trace_object_key);
	__type(value, unsigned long long);
} go_ancerstor_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CONFIG_CONCURRENT_THREAD_MAX);
	__type(key, struct trace_object_key);
	__type(value, unsigned long long);
} socket_op_last_time_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CONFIG_CONCURRENT_THREAD_MAX);
	__type(key, int);
	__type(value, struct sched_switch_event);
} sched_switch_event_map SEC(".maps");

#endif
