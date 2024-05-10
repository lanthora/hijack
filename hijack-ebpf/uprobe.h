// SPDX-License-Identifier: GPL-2.0-only
#ifndef HIJACK_EBPF_UPROBE_H
#define HIJACK_EBPF_UPROBE_H

#include "hijack-ebpf/callstack.h"
#include "hijack-ebpf/log.h"
#include "hijack-ebpf/skb.h"
#include "hijack-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static u64 get_goid_from_g(void *g)
{
	u64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g + 152);
	return goid;
}

static u64 get_current_go_routine(void)
{
	void *g;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	void *fsbase = (void *)BPF_CORE_READ(task, thread.fsbase);
	bpf_probe_read_user(&g, sizeof(g), fsbase - 8);
	return get_goid_from_g(g);
}

static bool is_final_go_ancestor(struct trace_object_key *trace_object_key, u64 now)
{
	u64 *last = bpf_map_lookup_elem(&socket_op_last_time_map, trace_object_key);
	if (last && now < *last + 3 * NS_PER_SEC) {
		*last = now;
		return true;
	}

	return false;
}

static u64 get_parent_go_routine(struct trace_object_key *trace_object_key)
{
	u64 *parent = bpf_map_lookup_elem(&go_ancerstor_map, trace_object_key);
	return (parent) ? (*parent) : (0);
}

static u64 get_ancestor_go_routine(void)
{
	const u64 current = get_current_go_routine();
	if (current == 0)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	struct trace_object_key trace_object_key = { .tgid = tgid };

	u64 ancestor = current;
	u64 now = bpf_ktime_get_boot_ns();

	for (int idx = 0; idx < 16; ++idx) {
		trace_object_key.coid = ancestor;
		if (is_final_go_ancestor(&trace_object_key, now))
			return ancestor;

		ancestor = get_parent_go_routine(&trace_object_key);
		if (ancestor == 0)
			break;
	}

	trace_object_key.coid = current;
	bpf_map_update_elem(&socket_op_last_time_map, &trace_object_key, &now, BPF_ANY);

	return current;
}

static int trace_runtime_newproc1_enter(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	void *g = (void *)ctx->bx;
	u64 parent = get_goid_from_g(g);
	if (parent == 0)
		return 0;

	struct hook_ctx_key key = { .func = FUNC_GO_RUNTIME_PROC1, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .goid = parent, .nsec = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);
	return 0;
}

static int trace_runtime_newproc1_exit(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;
	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	void *g = (void *)ctx->ax;
	u64 child = get_goid_from_g(g);
	if (child == 0)
		return 0;

	struct hook_ctx_key hook_ctx_key = { .func = FUNC_GO_RUNTIME_PROC1, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *hook_ctx_value = bpf_map_lookup_elem(&hook_ctx_map, &hook_ctx_key);
	if (!hook_ctx_value)
		return 0;

	u64 parent = hook_ctx_value->goid;
	struct trace_object_key trace_object_key = { .tgid = tgid, .coid = child };
	bpf_map_update_elem(&go_ancerstor_map, &trace_object_key, &parent, BPF_ANY);

	bpf_map_delete_elem(&hook_ctx_map, &hook_ctx_key);
	return 0;
}

static void go_rtype_string(int idx, struct go_string *string)
{
	char str[32] = { 0 };
	bpf_probe_read_user(&str, string->len < sizeof(str) ? string->len : sizeof(str) - 1, (void *)string->addr);
	LOG("%d: type=String value=%s", idx, str);
}

static void go_format_string(struct go_string *string)
{
	char str[32] = { 0 };
	bpf_probe_read_user(&str, string->len < sizeof(str) ? string->len : sizeof(str) - 1, (void *)string->addr);
	LOG("format: %s", str);
}

static int trace_go_interface(struct go_interface *raw, int idx)
{
	struct go_interface interface;
	bpf_probe_read_user(&interface, sizeof(interface), raw + idx);

	struct go_rtype rtype;
	bpf_probe_read_user(&rtype, sizeof(rtype), (struct go_rtype *)interface.type);

	u8 value[16] = { 0 };
	if (rtype.size <= sizeof(value)) {
		bpf_probe_read_user(&value, rtype.size, (void *)interface.addr);
	}

	switch (rtype.kind) {
	case Bool:
		LOG("%d: type=Bool value=%d ", idx, *(u8 *)(value));
		break;
	case Int:
		LOG("%d: type=Int value=%lld", idx, *(s64 *)(value));
		break;
	case Int8:
		LOG("%d: type=Int8 value=%d", idx, *(s8 *)(value));
		break;
	case Int16:
		LOG("%d: type=Int16 value=%d", idx, *(s16 *)(value));
		break;
	case Int32:
		LOG("%d: type=Int32 value=%d", idx, *(s32 *)(value));
		break;
	case Int64:
		LOG("%d: type=Int64 value=%lld", idx, *(s64 *)(value));
		break;
	case Uint:
		LOG("%d: type=Uint value=%lld", idx, *(u64 *)(value));
		break;
	case Uint8:
		LOG("%d: type=Uint8 value=%d", idx, *(u8 *)(value));
		break;
	case Uint16:
		LOG("%d: type=Uint16 value=%d", idx, *(u16 *)(value));
		break;
	case Uint32:
		LOG("%d: type=Uint32 value=%d", idx, *(s32 *)(value));
		break;
	case Uint64:
		LOG("%d: type=Uint64 value=%lld", idx, *(u64 *)(value));
		break;
	case Uintptr:
		LOG("%d: type=Uintptr value=%llx", idx, *(u64 *)(value));
		break;
	case Float32:
		LOG("%d: type=Float32 value=%08x", idx, *(u32 *)(value));
		break;
	case Float64:
		LOG("%d: type=Float64 value=%016llx", idx, *(u64 *)(value));
		break;
	case String:
		go_rtype_string(idx, (struct go_string *)(value));
		break;
	default:
		LOG("%d: kind=%d size=%d", idx, rtype.kind, rtype.size);
		break;
	}

	return 0;
}

static int trace_any_slice_enter(struct pt_regs *ctx, const char *func)
{
	LOG("================= %s ===============", func);
	struct go_slice slice = { .addr = ctx->ax, .size = ctx->bx, .cap = ctx->cx };
	LOG("slice: size=%d cap=%d", slice.size, slice.cap);
	for (int idx = 0; idx < 16 && idx < slice.size; ++idx) {
		trace_go_interface((struct go_interface *)slice.addr, idx);
	}

	return 0;
}

static int trace_format_any_slice_enter(struct pt_regs *ctx, const char *func)
{
	LOG("================= %s ===============", func);
	struct go_string string = { .addr = ctx->ax, .len = ctx->bx };
	go_format_string(&string);

	struct go_slice slice = { .addr = ctx->cx, .size = ctx->di, .cap = ctx->si };
	LOG("slice: size=%d cap=%d", slice.size, slice.cap);
	for (int idx = 0; idx < 16 && idx < slice.size; ++idx) {
		trace_go_interface((struct go_interface *)slice.addr, idx);
	}

	return 0;
}

static int trace_level_format_pointer_any_slice_enter(struct pt_regs *ctx, const char *func)
{
	LOG("================= %s ===============", func);
	s64 level = (s64)(ctx->bx);
	LOG("level: %d", level);

	struct go_string string;
	bpf_probe_read_user(&string, sizeof(string), (void *)ctx->cx);
	go_format_string(&string);

	struct go_slice slice = { .addr = ctx->di, .size = ctx->si, .cap = ctx->r8 };
	LOG("slice: size=%d cap=%d", slice.size, slice.cap);
	for (int idx = 0; idx < 16 && idx < slice.size; ++idx) {
		trace_go_interface((struct go_interface *)slice.addr, idx);
	}

	return 0;
}

// func (fr *http2Framer) checkFrameOrder(f http2Frame) error
static int trace_net_http_http2Framer_checkFrameOrder(struct pt_regs *ctx)
{
	void *Framer = (void *)ctx->ax;

	struct go_interface Frame = { .type = ctx->bx, .addr = ctx->cx };

	// DataFrame Type offset：1
	u8 Type;
	bpf_probe_read_user(&Type, sizeof(Type), (void *)Frame.addr + 1);
	if (Type != 0) {
		return 0;
	}

	// DataFrame StreamID offset：8
	u32 StreamID;
	bpf_probe_read_user(&StreamID, sizeof(StreamID), (void *)Frame.addr + 8);

	// DataFrame data offset: 16
	struct go_slice data;
	bpf_probe_read_user(&data, sizeof(data), (void *)Frame.addr + 16);

	LOG("http2 dataframe read: Framer=%llx StreamID=%d size=%d", Framer, StreamID, data.size);
	return 0;
}

// func (f *http2Framer) WriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error
static int trace_net_http_http2Framer_WriteDataPadded(struct pt_regs *ctx)
{
	void *Framer = (void *)ctx->ax;
	u32 streamID = (u32)ctx->bx;
	bool endStream = (bool)ctx->cx;
	struct go_slice data = { .addr = ctx->di, .size = ctx->si, .cap = ctx->r8 };
	struct go_slice pad = { .addr = ctx->r9, .size = ctx->r10, .cap = ctx->r11 };

	LOG("http2 dataframe write: Framer=%llx streamID=%d size=%d", Framer, streamID, data.size);
	return 0;
}

// func (fr *Framer) checkFrameOrder(f Frame) error
static int trace_golang_org_x_net_http2_Framer_checkFrameOrder(struct pt_regs *ctx)
{
	void *Framer = (void *)ctx->ax;

	struct go_interface Frame = { .type = ctx->bx, .addr = ctx->cx };

	// DataFrame Type offset：1
	u8 Type;
	bpf_probe_read_user(&Type, sizeof(Type), (void *)Frame.addr + 1);
	if (Type != 0) {
		return 0;
	}

	// DataFrame StreamID offset：8
	u32 StreamID;
	bpf_probe_read_user(&StreamID, sizeof(StreamID), (void *)Frame.addr + 8);

	// DataFrame data offset: 16
	struct go_slice data;
	bpf_probe_read_user(&data, sizeof(data), (void *)Frame.addr + 16);

	LOG("grpc dataframe read: Framer=%llx StreamID=%d size=%d", Framer, StreamID, data.size);

	return 0;
}

// func (f *Framer) WriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error
static int trace_golang_org_x_net_http2_Framer_WriteDataPadded(struct pt_regs *ctx)
{
	void *Framer = (void *)ctx->ax;
	u32 streamID = (u32)ctx->bx;
	bool endStream = (bool)ctx->cx;
	struct go_slice data = { .addr = ctx->di, .size = ctx->si, .cap = ctx->r8 };
	struct go_slice pad = { .addr = ctx->r9, .size = ctx->r10, .cap = ctx->r11 };

	LOG("grpc dataframe write: Framer=%llx streamID=%d size=%d", Framer, streamID, data.size);
	return 0;
}

#endif
