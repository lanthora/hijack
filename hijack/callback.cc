// SPDX-License-Identifier: Apache-2.0
#include "hijack/callback.h"
#include "hijack-common/types.h"
#include "hijack/binary.h"
#include "hijack/process.h"
#include "hijack/hijack.skel.h"
#include <bpf/bpf.h>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
#include <sys/socket.h>
#include <sys/un.h>

extern struct hijack *skel;
extern class process_collector process_collector;

static const long NS_PER_SEC = 1000000000L;

// 计算系统启动的时间点
static struct timespec boot_timespec()
{
	struct timespec real; // 此刻系统时间点
	struct timespec boot; // 系统启动到此刻的时间段

	clock_gettime(CLOCK_REALTIME, &real);
	clock_gettime(CLOCK_BOOTTIME, &boot);

	real.tv_nsec -= boot.tv_nsec;
	real.tv_sec -= boot.tv_sec;

	if (real.tv_nsec < 0) {
		real.tv_nsec += NS_PER_SEC;
		real.tv_sec -= 1L;
	}

	return real;
}

// 根据系统启动时间和内核记录的纳秒时间戳计算事件产生的时间
static int clock_get_event_time(unsigned long long nsec, struct timespec *now)
{
	static const struct timespec boot = boot_timespec();

	nsec += boot.tv_nsec;
	now->tv_nsec = nsec % NS_PER_SEC;
	now->tv_sec = boot.tv_sec + (nsec / NS_PER_SEC);
	return 0;
}

static int handle_log_event(void *ctx, void *data, size_t len)
{
	struct event_log *e = (struct event_log *)data;

	struct timespec now;
	clock_get_event_time(e->nsec, &now);

	struct tm t;
	char date_time[32];
	strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localtime_r(&now.tv_sec, &t));
	printf("[%s.%09lu] %s\n", date_time, now.tv_nsec, e->msg);
	return 0;
}

static void stack_trace_callback(bfd_vma pc, const char *functionname, const char *filename, int line, void *data)
{
	int idx = *(int *)data;
	printf("#%d %p at %s in %s:%d\n", idx, (void *)pc, functionname, filename, line);
}

static int handle_user_call_stack_event(void *ctx, void *data, size_t len)
{
	struct stack_value {
		uintptr_t ip[CONFIG_MAX_STACK_DEPTH];
		uint32_t tgid;
		uint64_t cnt;
	} tmp = {};

	static std::map<uint64_t, class stack_value> stack_map;

	struct event_user_call_stack *e = (struct event_user_call_stack *)data;
	uint64_t stackid = e->stackid;

	int ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stack_trace_map), &stackid, &tmp.ip);
	if (ret) {
		printf("stack_trace_map lookup failed, stackid=%d\n", stackid);
		return 0;
	}

	struct timespec now;
	clock_get_event_time(e->nsec, &now);

	struct tm t;
	char date_time[32];
	strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localtime_r(&now.tv_sec, &t));

	auto it = stack_map.find(stackid);
	if (it != stack_map.end() && it->second.tgid == e->tgid && memcmp(it->second.ip, tmp.ip, sizeof(tmp.ip)) == 0) {
		printf("[%s.%09lu] %s: stackid=%d tgid=%d comm=%s cnt=%llu\n", date_time, now.tv_nsec, e->name, stackid, e->tgid, e->comm, ++it->second.cnt);
		return 0;
	} else {
		tmp.tgid = e->tgid;
		tmp.cnt = 1;
		stack_map[stackid] = tmp;
		printf("[%s.%09lu] %s: stackid=%d tgid=%d comm=%s cnt=1\n", date_time, now.tv_nsec, e->name, stackid, e->tgid, e->comm);
	}

	struct binary *binary_ctx = process_collector.fetch_binnary_ctx(e->tgid);
	if (!binary_ctx) {
		printf("fetch_binnary_ctx failed\n");
		return 0;
	}

	for (int idx = 0; idx < CONFIG_MAX_STACK_DEPTH; ++idx) {
		if (!tmp.ip[idx])
			break;
		binary_addr_to_line(binary_ctx, tmp.ip[idx], stack_trace_callback, &idx);
	}
	printf("\n");

	return 0;
}

static int handle_offcpu_call_stack_event(void *ctx, void *data, size_t len)
{
	struct stack_value {
		uintptr_t ip[CONFIG_MAX_STACK_DEPTH];
		uint32_t tgid;
		uint64_t cnt;
		uint64_t duration;
	} tmp = {};

	static std::map<uint64_t, class stack_value> stack_map;

	struct event_offcpu_call_stack *e = (struct event_offcpu_call_stack *)data;
	uint64_t stackid = e->stackid;

	int ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stack_trace_map), &stackid, &tmp.ip);
	if (ret) {
		printf("stack_trace_map lookup failed, stackid=%d\n", stackid);
		return 0;
	}

	struct timespec now;
	clock_get_event_time(e->nsec, &now);

	struct tm t;
	char date_time[32];
	strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localtime_r(&now.tv_sec, &t));

	auto it = stack_map.find(stackid);
	if (it != stack_map.end() && it->second.tgid == e->tgid && memcmp(it->second.ip, tmp.ip, sizeof(tmp.ip)) == 0) {
		it->second.cnt += 1;
		it->second.duration += e->duration;
		printf("[%s.%09lu] offcpu: tgid=%d pid=%d stackid=%d comm=%s duration=%llu(%llu) cnt=%llu\n", date_time, now.tv_nsec, e->tgid, e->pid, stackid, e->comm,
		       e->duration, it->second.duration, it->second.cnt);
		return 0;
	} else {
		tmp.tgid = e->tgid;
		tmp.cnt = 1;
		tmp.duration += e->duration;
		stack_map[stackid] = tmp;
		printf("[%s.%09lu] offcpu: tgid=%d pid=%d stackid=%d comm=%s duration=%llu(%llu) cnt=1\n", date_time, now.tv_nsec, e->tgid, e->pid, stackid, e->comm, e->duration,
		       tmp.duration);
	}

	struct binary *binary_ctx = process_collector.fetch_binnary_ctx(e->tgid);
	if (!binary_ctx) {
		printf("fetch_binnary_ctx failed\n");
		return 0;
	}

	for (int idx = 0; idx < CONFIG_MAX_STACK_DEPTH; ++idx) {
		if (!tmp.ip[idx])
			break;
		binary_addr_to_line(binary_ctx, tmp.ip[idx], stack_trace_callback, &idx);
	}
	printf("\n");

	return 0;
}

static int handle_sched_event(void *ctx, void *data, size_t len)
{
	struct event_sched *e = (struct event_sched *)data;
	switch (e->op) {
	case 0: // fork
		process_collector.copy_process_item(e->pid, e->ppid);
		break;
	case 1: // execve
		process_collector.update_process_item(e->pid);
		break;
	case 2: // exit
		process_collector.delete_process_item(e->pid);
		break;
	}
	return 0;
}

static int handle_tcp_probe_event(void *ctx, void *data, size_t len)
{
	struct event_tcp_probe *e = (struct event_tcp_probe *)data;

	struct timespec now;
	clock_get_event_time(e->nsec, &now);

	struct tm t;
	char date_time[32];
	strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localtime_r(&now.tv_sec, &t));
	printf("[%s.%09lu] ", date_time, now.tv_nsec);

	// TODO: 这个实现过于粗糙.需要简化这里的实现.
	switch (e->op) {
	case 0:
		printf("probe: saddr=%d.%d.%d.%d:%u daddr=%d.%d.%d.%d:%u srtt=(%llu,%llu,%llu)", e->saddr[0], e->saddr[1], e->saddr[2], e->saddr[3], e->sport, e->daddr[0],
		       e->daddr[1], e->daddr[2], e->daddr[3], e->dport, e->srtt_min, e->srtt_avg, e->srtt_max);
		break;
	case 1:
		printf("retransmit_skb: saddr=%d.%d.%d.%d:%u daddr=%d.%d.%d.%d:%u", e->saddr[0], e->saddr[1], e->saddr[2], e->saddr[3], e->sport, e->daddr[0], e->daddr[1],
		       e->daddr[2], e->daddr[3], e->dport);
		break;
	case 2:
		printf("retransmit_synack: saddr=%d.%d.%d.%d:%u daddr=%d.%d.%d.%d:%u", e->saddr[0], e->saddr[1], e->saddr[2], e->saddr[3], e->sport, e->daddr[0], e->daddr[1],
		       e->daddr[2], e->daddr[3], e->dport);
		break;
	case 3:
		printf("send_reset: saddr=%d.%d.%d.%d:%u daddr=%d.%d.%d.%d:%u", e->saddr[0], e->saddr[1], e->saddr[2], e->saddr[3], e->sport, e->daddr[0], e->daddr[1], e->daddr[2],
		       e->daddr[3], e->dport);
		break;
	case 4:
		printf("receive_reset: saddr=%d.%d.%d.%d:%u daddr=%d.%d.%d.%d:%u", e->saddr[0], e->saddr[1], e->saddr[2], e->saddr[3], e->sport, e->daddr[0], e->daddr[1],
		       e->daddr[2], e->daddr[3], e->dport);
		break;
	case 5:
		printf("destroy_sock: saddr=%d.%d.%d.%d:%u daddr=%d.%d.%d.%d:%u srtt=(%llu,%llu,%llu)", e->saddr[0], e->saddr[1], e->saddr[2], e->saddr[3], e->sport, e->daddr[0],
		       e->daddr[1], e->daddr[2], e->daddr[3], e->dport, e->srtt_min, e->srtt_avg, e->srtt_max);
		break;
	}
	printf("\n");

	return 0;
}

int ring_buffer_callback(void *ctx, void *data, size_t len)
{
	assert(len >= sizeof(unsigned int));
	unsigned int type = *(unsigned int *)data;

	switch (type) {
	case RB_EVENT_UNSPEC:
		break;
	case RB_EVENT_LOG:
		handle_log_event(ctx, data, len);
		break;
	case RB_EVENT_USER_CALL_STACK:
		handle_user_call_stack_event(ctx, data, len);
		break;
	case RB_EVENT_OFFCPU_CALL_STACK:
		handle_offcpu_call_stack_event(ctx, data, len);
		break;
	case RB_EVENT_SCHED:
		handle_sched_event(ctx, data, len);
		break;
	case RB_EVENT_TCP_PROBE:
		handle_tcp_probe_event(ctx, data, len);
		break;
	default:
		break;
	}
	return 0;
}
