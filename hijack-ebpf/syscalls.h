// SPDX-License-Identifier: GPL-2.0-only
#ifndef HIJACK_EBPF_SYSCALLS_H
#define HIJACK_EBPF_SYSCALLS_H

#include "hijack-ebpf/log.h"
#include "hijack-ebpf/maps.h"
#include "hijack-ebpf/types.h"
#include "hijack-ebpf/uprobe.h"
#include "hijack-ebpf/vmlinux.h"
#include <asm/unistd.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

static struct file *fd_to_file(unsigned int idx)
{
	struct file *file = NULL;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);

	unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
	if (idx > max_fds)
		return NULL;

	struct file **fd = BPF_CORE_READ(fdt, fd);
	bpf_probe_read_kernel(&file, sizeof(file), fd + idx);
	return file;
}

static umode_t file_to_i_mode(struct file *file)
{
	return BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT;
}

static struct socket *file_to_private_data(struct file *file)
{
	return (struct socket *)BPF_CORE_READ(file, private_data);
}

static inline struct qstr file_to_d_name(struct file *file)
{
	return BPF_CORE_READ(file, f_path.dentry, d_name);
}

static umode_t fd_to_i_mode(unsigned int idx)
{
	struct file *file = fd_to_file(idx);
	return file_to_i_mode(file);
}

static struct socket *fd_to_socket(unsigned int idx)
{
	struct file *file = fd_to_file(idx);
	return file_to_private_data(file);
}

static inline struct qstr fd_to_d_name(unsigned int idx)
{
	struct file *file = fd_to_file(idx);
	return file_to_d_name(file);
}

static bool is_read_syscall_func(enum FUNC func)
{
	if (func == FUNC_SYSCALL_READ)
		return true;
	if (func == FUNC_SYSCALL_READV)
		return true;
	if (func == FUNC_SYSCALL_RECVFROM)
		return true;
	if (func == FUNC_SYSCALL_RECVMSG)
		return true;
	if (func == FUNC_SYSCALL_RECVMMSG)
		return true;

	return false;
}

static u64 fetch_trace_id(struct hook_ctx_key *key, struct pproc_cfg *cfg, u16 local_port)
{
	struct trace_object_key trace_object_key = { .tgid = key->tgid };

	if (!cfg->listen_port)
		return 0;

	if (trace_object_key.coid == 0)
		trace_object_key.coid = get_ancestor_go_routine();

	if (trace_object_key.coid == 0)
		trace_object_key.pid = key->pid;

	struct trace_object_value *trace_object_value;
	trace_object_value = bpf_map_lookup_elem(&trace_object_map, &trace_object_key);
	if (!trace_object_value && cfg->listen_port == local_port) {
		u64 trace_id = 0;
		trace_id |= ((u64)trace_object_key.tgid & 0xFFFF) << 48;
		trace_id |= ((u64)(trace_object_key.pid + trace_object_key.coid) & 0xFFFF) << 32;
		trace_id |= ((u64)bpf_get_smp_processor_id() & 0x00FF) << 24;
		trace_id |= ((u64)bpf_ktime_get_boot_ns() & 0xFFFF);
		struct trace_object_value value = { .trace_id = trace_id };
		bpf_map_update_elem(&trace_object_map, &trace_object_key, &value, BPF_ANY);
		trace_object_value = bpf_map_lookup_elem(&trace_object_map, &trace_object_key);
	}

	if (!trace_object_value)
		return 0;

	s32 is_last_write = (trace_object_value->last_socket_operation_is_read == 0);
	s32 is_current_read = is_read_syscall_func(key->func);
	if (is_last_write && is_current_read && cfg->listen_port == local_port) {
		++trace_object_value->trace_id;
	}

	trace_object_value->last_socket_operation_is_read = is_current_read;

	return trace_object_value->trace_id;
}

static void trace_io_event_common(char *label, struct pproc_cfg *cfg, struct hook_ctx_key *key, struct hook_ctx_value *value, int ret)
{
	if (!cfg || !key || !value)
		return;

	unsigned int tgid = key->tgid;
	unsigned int pid = key->pid;
	unsigned int fd = value->fd;
	size_t count = value->count;
	unsigned long long latency = bpf_ktime_get_boot_ns() - value->nsec;

	umode_t i_mode = fd_to_i_mode(fd);

	if (i_mode == S_IFSOCK && !cfg->io_event_socket_disabled) {
		if (ret <= 0)
			return;

		struct socket *socket = fd_to_socket(fd);
		struct sock *sk = BPF_CORE_READ(socket, sk);
		int family = BPF_CORE_READ(socket, ops, family);

		if (family == AF_INET) {
			u32 local_addr = BPF_CORE_READ(sk, sk_rcv_saddr);
			u32 remote_addr = BPF_CORE_READ(sk, sk_daddr);
			u16 local_port = BPF_CORE_READ(sk, sk_num);
			u16 remote_port = BPF_CORE_READ(sk, sk_dport);
			remote_port = bpf_ntohs(remote_port);
			u64 coid = get_ancestor_go_routine();
			LOG("%s: tgid=%d fd=%d local=%pI4:%u remote=%pI4:%u size=%d", label, tgid, fd, &local_addr, local_port, &remote_addr, remote_port, count);
		}

		if (family == AF_INET6) {
			// TODO: 处理 IPv6
		}

		if (family == AF_UNIX) {
			// TODO: socket 文件的地址
			LOG("%s: tgid=%d pid=%d fd=%d ret=%d latency=%u family=%u", label, tgid, pid, fd, ret, latency, family);
		}
		return;
	}

	if (i_mode == S_IFREG && !cfg->io_event_regular_disabled) {
		struct qstr d_name = fd_to_d_name(fd);
		char name[CONFIG_FILE_NAME_LEN_MAX] = { 0 };
		bpf_probe_read_kernel(name, sizeof(name) - 1, d_name.name);
		LOG("%s: tgid=%d pid=%d fd=%d ret=%d latency=%u file=%s", label, tgid, pid, fd, ret, latency, name);
		return;
	}

	if (cfg->io_event_others_enabled) {
		LOG("%s: tgid=%d pid=%d fd=%d ret=%d latency=%u i_mode=%d", label, tgid, pid, fd, ret, latency, i_mode);
		return;
	}
}

static int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	unsigned int fd = (unsigned int)ctx->args[0];
	char *buf = (char *)ctx->args[1];
	size_t count = (size_t)ctx->args[2];

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_READ, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .buf = buf, .count = count, .nsec = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);
	return 0;
}

static int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int ret = (int)ctx->ret;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_READ, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	trace_io_event_common("read", cfg, &key, value, ret);

	bpf_map_delete_elem(&hook_ctx_map, &key);
	return 0;
}

static int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	unsigned int fd = (unsigned int)ctx->args[0];
	char *buf = (char *)ctx->args[1];
	size_t count = (size_t)ctx->args[2];

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_WRITE, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .buf = buf, .count = count, .nsec = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);
	return 0;
}

static int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int ret = (int)ctx->ret;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_WRITE, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	trace_io_event_common("write", cfg, &key, value, ret);

	bpf_map_delete_elem(&hook_ctx_map, &key);
	return 0;
}

static int trace_sys_enter_futex(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->lock_event_enabled)
		return 0;

	int futex_op = ctx->args[1] & FUTEX_CMD_MASK;

	if (futex_op != FUTEX_WAIT && futex_op != FUTEX_WAIT_BITSET && futex_op != FUTEX_WAIT_REQUEUE_PI && futex_op != FUTEX_LOCK_PI &&
	    futex_op != FUTEX_LOCK_PI2)
		return 0;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_FUTEX, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .nsec = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);

	LOG("futex enter: tgid=%d pid=%d", tgid, pid);
	return 0;
}

static int trace_sys_exit_futex(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->lock_event_enabled)
		return 0;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_FUTEX, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	if (!value)
		return 0;

	LOG("futex exit: tgid=%d pid=%d", tgid, pid);

	bpf_map_delete_elem(&hook_ctx_map, &key);
	return 0;
}

static int trace_sys_enter_futex_waitv(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->lock_event_enabled)
		return 0;

	LOG("futex_waitv enter: tgid=%d pid=%d", tgid, pid);
	return 0;
}

static int trace_sys_exit_futex_waitv(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->lock_event_enabled)
		return 0;

	LOG("futex_waitv exit: tgid=%d pid=%d", tgid, pid);
	return 0;
}

static int trace_sys_enter_readv(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	unsigned int fd = (unsigned int)ctx->args[0];
	struct iovec *iov = (struct iovec *)ctx->args[1];
	int iovcnt = (int)ctx->args[2];

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_READV, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .iov = iov, .iovcnt = iovcnt, .nsec = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);
	return 0;
}

static int trace_sys_exit_readv(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int ret = (int)ctx->ret;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_READV, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	trace_io_event_common("readv", cfg, &key, value, ret);

	bpf_map_delete_elem(&hook_ctx_map, &key);
	return 0;
}

static int trace_sys_enter_writev(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	unsigned int fd = (unsigned int)ctx->args[0];
	struct iovec *iov = (struct iovec *)ctx->args[1];
	int iovcnt = (int)ctx->args[2];

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_WRITEV, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .iov = iov, .iovcnt = iovcnt, .nsec = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);

	return 0;
}

static int trace_sys_exit_writev(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int ret = (int)ctx->ret;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_WRITEV, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	trace_io_event_common("writev", cfg, &key, value, ret);

	bpf_map_delete_elem(&hook_ctx_map, &key);
	return 0;
}

static int trace_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	unsigned int fd = (unsigned int)ctx->args[0];
	char *buf = (char *)ctx->args[1];
	size_t count = (size_t)ctx->args[2];

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_RECVFROM, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .buf = buf, .count = count, .nsec = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);
	return 0;
}

static int trace_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int ret = (int)ctx->ret;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_RECVFROM, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	trace_io_event_common("recvfrom", cfg, &key, value, ret);

	bpf_map_delete_elem(&hook_ctx_map, &key);
	return 0;
}

static int trace_sys_enter_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	unsigned int fd = (unsigned int)ctx->args[0];
	struct msghdr *message = (struct msghdr *)ctx->args[1];
	int flags = (int)ctx->args[2];

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_RECVMSG, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .message = message, .flags = flags, .nsec = bpf_ktime_get_boot_ns() };
	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);
	return 0;
}

static int trace_sys_exit_recvmsg(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int ret = (int)ctx->ret;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_RECVMSG, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	trace_io_event_common("recvmsg", cfg, &key, value, ret);

	bpf_map_delete_elem(&hook_ctx_map, &key);
	return 0;
}

static int trace_sys_enter_recvmmsg(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->io_event_others_enabled)
		return 0;

	LOG("trace_sys_enter_recvmmsg");
	return 0;
}

static int trace_sys_exit_recvmmsg(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->io_event_others_enabled)
		return 0;

	LOG("trace_sys_exit_recvmmsg");
	return 0;
}

static int trace_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->io_event_others_enabled)
		return 0;

	LOG("trace_sys_enter_sendto");
	return 0;
}

static int trace_sys_exit_sendto(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->io_event_others_enabled)
		return 0;

	LOG("trace_sys_exit_sendto");
	return 0;
}

static int trace_sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->io_event_others_enabled)
		return 0;

	LOG("trace_sys_enter_sendmsg");
	return 0;
}

static int trace_sys_exit_sendmsg(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->io_event_others_enabled)
		return 0;

	LOG("trace_sys_exit_sendmsg");
	return 0;
}

static int trace_sys_enter_sendmmsg(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->io_event_others_enabled)
		return 0;

	LOG("trace_sys_enter_sendmmsg");
	return 0;
}

static int trace_sys_exit_sendmmsg(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled || !cfg->io_event_others_enabled)
		return 0;

	LOG("trace_sys_exit_sendmmsg");
	return 0;
}

static int trace_sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	unsigned int fd = (unsigned int)ctx->args[0];

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_CLOSE, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = fd, .nsec = bpf_ktime_get_boot_ns() };

	// close 系统调用结束后 fd 相关的信息无法获取,需要在进入函数时处理
	trace_io_event_common("close", cfg, &key, &value, 0);
	return 0;
}

static int trace_sys_enter_sendfile(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	unsigned int in_fd = (unsigned int)ctx->args[1];

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_SENDFILE, .tgid = tgid, .pid = pid };
	struct hook_ctx_value value = { .fd = in_fd, .nsec = bpf_ktime_get_boot_ns() };

	bpf_map_update_elem(&hook_ctx_map, &key, &value, BPF_ANY);

	return 0;
}

static int trace_sys_exit_sendfile(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int ret = (int)ctx->ret;

	struct hook_ctx_key key = { .func = FUNC_SYSCALL_SENDFILE, .tgid = tgid, .pid = pid };
	struct hook_ctx_value *value = bpf_map_lookup_elem(&hook_ctx_map, &key);

	trace_io_event_common("sendfile", cfg, &key, value, ret);

	bpf_map_delete_elem(&hook_ctx_map, &key);
	return 0;
}

#if defined(DEBUG)
static int trace_sys_enter_default(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 pid = (u32)pid_tgid;

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	LOG("trace_sys_enter_default: id=%d args=(%d, %d, %d, %d, %d, %d)", ctx->id, ctx->args[0], ctx->args[1], ctx->args[2], ctx->args[3],
	    ctx->args[4], ctx->args[5]);
	return 0;
}

static int trace_sys_exit_default(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = (u32)(pid_tgid >> 32);

	struct pproc_cfg *cfg = bpf_map_lookup_elem(&pproc_cfg_map, &tgid);
	if (!cfg || !cfg->enabled)
		return 0;

	int ret = (int)ctx->ret;
	LOG("trace_sys_exit_default: ret=%d", ret);
	return 0;
}
#else
static int trace_sys_enter_default(struct trace_event_raw_sys_enter *ctx)
{
	return 0;
}

static int trace_sys_exit_default(struct trace_event_raw_sys_exit *ctx)
{
	return 0;
}
#endif

static int syscall_pid_tgid_map_update(struct trace_event_raw_sys_enter *ctx)
{
	int key = 0;
	u64 value = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&percpu_syscall_proc_map, &key, &value, BPF_ANY);
	return 0;
}

static int syscall_pid_tgid_map_clear(struct trace_event_raw_sys_exit *ctx)
{
	int key = 0;
	u64 value = 0;
	bpf_map_update_elem(&percpu_syscall_proc_map, &key, &value, BPF_ANY);
	return 0;
}

static int trace_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	syscall_pid_tgid_map_update(ctx);

	switch (ctx->id) {
	case __NR_read:
		trace_sys_enter_read(ctx);
		break;
	case __NR_write:
		trace_sys_enter_write(ctx);
		break;
	case __NR_futex:
		trace_sys_enter_futex(ctx);
		break;
	case __NR_futex_waitv:
		trace_sys_enter_futex_waitv(ctx);
		break;
	case __NR_readv:
		trace_sys_enter_readv(ctx);
		break;
	case __NR_writev:
		trace_sys_enter_writev(ctx);
		break;
	case __NR_recvfrom:
		trace_sys_enter_recvfrom(ctx);
		break;
	case __NR_recvmsg:
		trace_sys_enter_recvmsg(ctx);
		break;
	case __NR_recvmmsg:
		trace_sys_enter_recvmmsg(ctx);
		break;
	case __NR_sendto:
		trace_sys_enter_sendto(ctx);
		break;
	case __NR_sendmsg:
		trace_sys_enter_sendmsg(ctx);
		break;
	case __NR_sendmmsg:
		trace_sys_enter_sendmmsg(ctx);
		break;
	case __NR_sendfile:
		trace_sys_enter_sendfile(ctx);
		break;
	case __NR_close:
		trace_sys_enter_close(ctx);
		break;
	default:
		trace_sys_enter_default(ctx);
		break;
	}
	return 0;
}

static int trace_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	switch (ctx->id) {
	case __NR_read:
		trace_sys_exit_read(ctx);
		break;
	case __NR_write:
		trace_sys_exit_write(ctx);
		break;
	case __NR_futex:
		trace_sys_exit_futex(ctx);
		break;
	case __NR_futex_waitv:
		trace_sys_exit_futex_waitv(ctx);
		break;
	case __NR_recvfrom:
		trace_sys_exit_recvfrom(ctx);
		break;
	case __NR_readv:
		trace_sys_exit_readv(ctx);
		break;
	case __NR_writev:
		trace_sys_exit_writev(ctx);
		break;
	case __NR_recvmsg:
		trace_sys_exit_recvmsg(ctx);
		break;
	case __NR_recvmmsg:
		trace_sys_exit_recvmmsg(ctx);
		break;
	case __NR_sendto:
		trace_sys_exit_sendto(ctx);
		break;
	case __NR_sendmsg:
		trace_sys_exit_sendmsg(ctx);
		break;
	case __NR_sendmmsg:
		trace_sys_exit_sendmmsg(ctx);
		break;
	case __NR_sendfile:
		trace_sys_exit_sendfile(ctx);
		break;
	default:
		trace_sys_exit_default(ctx);
		break;
	}

	syscall_pid_tgid_map_clear(ctx);
	return 0;
}

#endif
