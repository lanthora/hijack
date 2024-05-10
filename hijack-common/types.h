// SPDX-License-Identifier: Apache-2.0
#ifndef HIJACK_COMMON_TYPES_H
#define HIJACK_COMMON_TYPES_H

#include "hijack-common/config.h"
#include <linux/limits.h>

// 内核通过 Ringbuf 上报的事件
enum {
	RB_EVENT_UNSPEC,
	RB_EVENT_LOG,
	RB_EVENT_USER_CALL_STACK,
	RB_EVENT_SCHED,
	RB_EVENT_TCP_PROBE,
	RB_EVENT_OFFCPU_CALL_STACK,
};

struct event_log {
	unsigned int type /* = RB_EVENT_LOG */;
	unsigned long long nsec;
	char msg[CONFIG_LOG_LEN_MAX];
} __attribute__((__packed__));

struct event_user_call_stack {
	unsigned int type /* = RB_EVENT_USER_CALL_STACK */;
	unsigned long long nsec;
	long stackid;
	int tgid;
	char comm[16];
	char name[32];
} __attribute__((__packed__));

struct event_sched {
	unsigned int type /* = RB_EVENT_SCHED */;
	int op; // 0:fork 1:execve 2:exit
	int pid;
	int ppid;
} __attribute__((__packed__));

struct event_tcp_probe {
	unsigned int type /* = RB_EVENT_TCP_PROBE */;
	unsigned long long nsec;
	int op; // 0:probe 1:retransmit_skb 2:retransmit_synack 3:send_reset 4:receive_reset 5:destroy_sock
	unsigned char saddr[4], daddr[4], saddr_v6[16], daddr_v6[16];
	unsigned short sport, dport;
	unsigned short family;
	unsigned long long srtt_min, srtt_avg, srtt_max;
} __attribute__((__packed__));

struct event_offcpu_call_stack {
	unsigned int type /* = RB_EVENT_OFFCPU_CALL_STACK */;
	unsigned long long nsec;
	int tgid;
	int pid;
	long stackid;
	unsigned long long duration;
	char comm[16];
} __attribute__((__packed__));

struct sched_switch_event {
	long stackid;
	unsigned long long offcpu_timestamp;
	int tgid;
	long int prev_state;
} __attribute__((__packed__));

// 与单个进程相关的配置,至少一个功能与默认行为不一致时才会初始化,初始化时字段默认为 0,
// io_event_socket_disabled, 默认表示不禁用 socket 的 io 事件上报
// io_event_others_enabled, 默认表示不启用其他类型 io 事件上报
struct pproc_cfg {
	int enabled;
	int io_event_socket_disabled;
	int io_event_regular_disabled;
	int io_event_others_enabled;
	int lock_event_enabled;
	int handle_mm_fault_enabled;
	int sched_switch_enabled;

	// 保存当前进程监听的 TCP/UDP 端口号,用于判断是否是作为服务端收到了请求报文,
	// 大多数情况下进程只会监听一个端口,这里不处理监听多个端口的情况,也不分协议处理.
	unsigned short listen_port;
} __attribute__((__packed__));

// 全局配置,成员表示方式与 pproc_cfg 一致
struct global_cfg {
	int log_enabled;
	int kfree_skb_enabled;
	int nf_hook_slow_enabled;
	int sched_disabled;
	int tcp_probe_enabled;
	int socket_to_pid_enabled;
} __attribute__((__packed__));

enum {
	CTL_EVENT_UNSPEC = 0,
	CTL_EVENT_IO_EVENT_OTHERS_ENABLED = 1,
	CTL_EVENT_LOG_ENABLED = 2,
	CTL_EVENT_IO_EVENT_SOCKET_DISABLED = 3,
	CTL_EVENT_PPROC_ENABLED = 4,
	CTL_EVENT_KFREE_SKB_ENABLED = 5,
	CTL_EVENT_NF_HOOK_SLOW_ENABLED = 6,
	CTL_EVENT_SCHED_ENABLED = 7,
	CTL_EVENT_TCP_PROBE_ENABLED = 8,
	CTL_EVENT_CALL_STACK_TRACE = 9,
	CTL_EVENT_IO_EVENT_REGULAR_DISABLED = 10,
	CTL_EVENT_SET_LISTEN_PORT = 11,
	CTL_EVENT_HANDLE_MM_FAULT_ENABLED = 12,
	CTL_EVENT_SCHED_SWITCH_EVENT_ENABLED = 13,
};

struct ctl_io_event_others_enabled {
	unsigned int type /* = CTL_EVENT_IO_EVENT_OTHERS_ENABLED */;
	int tgid;
	int io_event_others_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_log_enabled {
	unsigned int type /* = CTL_EVENT_LOG_ENABLED */;
	int log_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_kfree_skb_enabled {
	unsigned int type /* = CTL_EVENT_KFREE_SKB_ENABLED */;
	int kfree_skb_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_nf_hook_slow_enabled {
	unsigned int type /* = CTL_EVENT_NF_HOOK_SLOW_ENABLED */;
	int nf_hook_slow_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_sched_enabled {
	unsigned int type /* = CTL_EVENT_SCHED_ENABLED */;
	int sched_disabled;
	int ret;
} __attribute__((__packed__));

struct ctl_tcp_probe_enabled {
	unsigned int type /* = CTL_EVENT_TCP_PROBE_ENABLED */;
	int tcp_probe_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_io_event_socket_disabled {
	unsigned int type /* = CTL_EVENT_IO_EVENT_SOCKET_DISABLED */;
	int tgid;
	int io_event_socket_disabled;
	int ret;
} __attribute__((__packed__));

struct ctl_io_event_regular_disabled {
	unsigned int type /* = CTL_EVENT_IO_EVENT_REGULAR_DISABLED */;
	int tgid;
	int io_event_regular_disabled;
	int ret;
} __attribute__((__packed__));

struct ctl_pproc_enabled {
	unsigned int type /* = CTL_EVENT_PPROC_ENABLED */;
	int tgid;
	int enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_call_stack_trace {
	unsigned int type /* = CTL_EVENT_CALL_STACK_TRACE */;
	int retprobe;
	int pid;
	unsigned long long func_offset;
	char binary_path[PATH_MAX];
	int ret;
} __attribute__((__packed__));

struct ctl_set_listen_port {
	unsigned int type /* = CTL_EVENT_SET_LISTEN_PORT */;
	int tgid;
	unsigned short port;
	int ret;
} __attribute__((__packed__));

struct ctl_handle_mm_fault_enabled {
	unsigned int type /* = CTL_EVENT_HANDLE_MM_FAULT_ENABLED */;
	int tgid;
	int handle_mm_fault_enabled;
	int ret;
} __attribute__((__packed__));

struct ctl_sched_switch_event_enabled {
	unsigned int type /* = CTL_EVENT_SCHED_SWITCH_EVENT_ENABLED */;
	int pid;
	int sched_switch_event_enabled;
	int ret;
} __attribute__((__packed__));

#endif
