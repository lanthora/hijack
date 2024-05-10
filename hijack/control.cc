// SPDX-License-Identifier: Apache-2.0
#include "hijack/control.h"
#include "hijack-common/types.h"
#include "hijack/process.h"
#include "hijack/hijack.skel.h"
#include <bpf/bpf.h>
#include <cassert>
#include <errno.h>
#if CONFIG_USDT
#include <sys/sdt.h>
#endif
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

extern struct hijack *skel;
extern class process_collector process_collector;

int control::handle_pproc_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_pproc_enabled));

	struct ctl_pproc_enabled *event = (struct ctl_pproc_enabled *)buffer;
	struct pproc_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg);

	// 强转成 bool 类型的 0 或 1,方便后面的比较
	cfg.enabled = (bool)cfg.enabled;
	event->enabled = (bool)event->enabled;

	if (cfg.enabled == event->enabled) {
		event->ret = 0;
		return 0;
	}

	if (event->enabled) {
		process_collector.hook_default_probe(event->tgid, skel);
	} else {
		process_collector.unhook_default_probe(event->tgid, skel);
	}

	cfg.enabled = event->enabled;
	bpf_map_update_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int control::handle_io_event_others_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_io_event_others_enabled));

	struct ctl_io_event_others_enabled *event = (struct ctl_io_event_others_enabled *)buffer;
	struct pproc_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg);

	cfg.io_event_others_enabled = event->io_event_others_enabled;
	bpf_map_update_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int control::handle_io_event_socket_disabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_io_event_socket_disabled));

	struct ctl_io_event_socket_disabled *event = (struct ctl_io_event_socket_disabled *)buffer;
	struct pproc_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg);

	cfg.io_event_socket_disabled = event->io_event_socket_disabled;
	bpf_map_update_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int control::handle_io_event_regular_disabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_io_event_regular_disabled));

	struct ctl_io_event_regular_disabled *event = (struct ctl_io_event_regular_disabled *)buffer;
	struct pproc_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg);

	cfg.io_event_regular_disabled = event->io_event_regular_disabled;
	bpf_map_update_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int control::handle_log_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_log_enabled));

	struct ctl_log_enabled *event = (struct ctl_log_enabled *)buffer;

	int zero = 0;
	struct global_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel->maps.global_cfg_map), &zero, &cfg);

	cfg.log_enabled = event->log_enabled;
	bpf_map_update_elem(bpf_map__fd(skel->maps.global_cfg_map), &zero, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int control::handle_kfree_skb_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_kfree_skb_enabled));

	struct ctl_kfree_skb_enabled *event = (struct ctl_kfree_skb_enabled *)buffer;

	int zero = 0;
	struct global_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel->maps.global_cfg_map), &zero, &cfg);

	cfg.kfree_skb_enabled = event->kfree_skb_enabled;
	bpf_map_update_elem(bpf_map__fd(skel->maps.global_cfg_map), &zero, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int control::handle_nf_hook_slow_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_nf_hook_slow_enabled));

	struct ctl_nf_hook_slow_enabled *event = (struct ctl_nf_hook_slow_enabled *)buffer;

	int zero = 0;
	struct global_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel->maps.global_cfg_map), &zero, &cfg);

	cfg.nf_hook_slow_enabled = event->nf_hook_slow_enabled;
	bpf_map_update_elem(bpf_map__fd(skel->maps.global_cfg_map), &zero, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int control::handle_sched_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_sched_enabled));

	struct ctl_sched_enabled *event = (struct ctl_sched_enabled *)buffer;

	int zero = 0;
	struct global_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel->maps.global_cfg_map), &zero, &cfg);

	cfg.sched_disabled = event->sched_disabled;
	bpf_map_update_elem(bpf_map__fd(skel->maps.global_cfg_map), &zero, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int control::handle_tcp_probe_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_tcp_probe_enabled));

	struct ctl_tcp_probe_enabled *event = (struct ctl_tcp_probe_enabled *)buffer;

	int zero = 0;
	struct global_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel->maps.global_cfg_map), &zero, &cfg);

	cfg.tcp_probe_enabled = event->tcp_probe_enabled;
	bpf_map_update_elem(bpf_map__fd(skel->maps.global_cfg_map), &zero, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int control::handle_call_stack_trace(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_call_stack_trace));
	struct ctl_call_stack_trace *event = (struct ctl_call_stack_trace *)buffer;

	struct bpf_link *link = bpf_program__attach_uprobe(skel->progs.call_stack, event->retprobe, event->pid, event->binary_path, event->func_offset);

	if (link) {
		std::string name = std::string("call_stack");
		name += "/r:" + std::to_string((int)event->retprobe);
		name += "/o:" + std::to_string((unsigned long long)event->func_offset);
		process_collector.add_probe_link(event->pid, name, link);
		event->ret = 0;
	} else {
		event->ret = -1;
	}

	return 0;
}

int control::handle_set_listen_port(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_set_listen_port));

	struct ctl_set_listen_port *event = (struct ctl_set_listen_port *)buffer;
	struct pproc_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg);

	cfg.listen_port = event->port;
	bpf_map_update_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int control::handle_handle_mm_fault_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_handle_mm_fault_enabled));

	struct ctl_handle_mm_fault_enabled *event = (struct ctl_handle_mm_fault_enabled *)buffer;
	struct pproc_cfg cfg = {};
	bpf_map_lookup_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg);

	cfg.handle_mm_fault_enabled = event->handle_mm_fault_enabled;
	bpf_map_update_elem(bpf_map__fd(skel->maps.pproc_cfg_map), &event->tgid, &cfg, BPF_ANY);

	event->ret = 0;
	return 0;
}

int control::handle_sched_switch_event_enabled(void *buffer, int len)
{
	assert(len == sizeof(struct ctl_sched_switch_event_enabled));
	struct ctl_sched_switch_event_enabled *event = (struct ctl_sched_switch_event_enabled *)buffer;
	if (event->sched_switch_event_enabled) {
		struct sched_switch_event empty = {};
		bpf_map_update_elem(bpf_map__fd(skel->maps.sched_switch_event_map), &event->pid, &empty, BPF_ANY);
	} else {
		bpf_map_delete_elem(bpf_map__fd(skel->maps.sched_switch_event_map), &event->pid);
	}

	event->ret = 0;
	return 0;
}

int control::init_socket_fd()
{
	socket_fd_ = socket(AF_UNIX, SOCK_DGRAM, 0);
	assert(socket_fd_ != 0);

	server_.sun_family = AF_UNIX;
	strcpy(server_.sun_path, CONFIG_CTL_SOCKET_PATH);

	assert(!unlink(CONFIG_CTL_SOCKET_PATH) || errno != EPERM);
	assert(bind(socket_fd_, (struct sockaddr *)&server_, sizeof(server_)) != -1);

	return 0;
}

int control::serve()
{
	static const int CTL_TYPE_LEN = 4;
	char buffer[CONFIG_CTL_BUFFER_SIZE_MAX + 1];
	socklen_t len;
	struct sockaddr_un peer;
	int size;
	unsigned int type;

	while (true) {
		len = sizeof(peer);
		size = recvfrom(socket_fd_, buffer, CONFIG_CTL_BUFFER_SIZE_MAX, 0, (struct sockaddr *)&peer, &len);
		assert(size >= CTL_TYPE_LEN);

		type = CTL_EVENT_UNSPEC;
		memcpy(&type, buffer, CTL_TYPE_LEN);
		switch (type) {
		case CTL_EVENT_LOG_ENABLED:
			handle_log_enabled(buffer, size);
			break;
		case CTL_EVENT_PPROC_ENABLED:
			handle_pproc_enabled(buffer, size);
			break;
		case CTL_EVENT_SET_LISTEN_PORT:
			handle_set_listen_port(buffer, size);
			break;
		case CTL_EVENT_IO_EVENT_OTHERS_ENABLED:
			handle_io_event_others_enabled(buffer, size);
			break;
		case CTL_EVENT_IO_EVENT_SOCKET_DISABLED:
			handle_io_event_socket_disabled(buffer, size);
			break;
		case CTL_EVENT_IO_EVENT_REGULAR_DISABLED:
			handle_io_event_regular_disabled(buffer, size);
			break;
		case CTL_EVENT_KFREE_SKB_ENABLED:
			handle_kfree_skb_enabled(buffer, size);
			break;
		case CTL_EVENT_NF_HOOK_SLOW_ENABLED:
			handle_nf_hook_slow_enabled(buffer, size);
			break;
		case CTL_EVENT_SCHED_ENABLED:
			handle_sched_enabled(buffer, size);
			break;
		case CTL_EVENT_TCP_PROBE_ENABLED:
			handle_tcp_probe_enabled(buffer, size);
			break;
		case CTL_EVENT_CALL_STACK_TRACE:
			handle_call_stack_trace(buffer, size);
			break;
		case CTL_EVENT_HANDLE_MM_FAULT_ENABLED:
			handle_handle_mm_fault_enabled(buffer, size);
			break;
		case CTL_EVENT_SCHED_SWITCH_EVENT_ENABLED:
			handle_sched_switch_event_enabled(buffer, size);
			break;
		}
#if CONFIG_USDT
		DTRACE_PROBE2(hijack, control, buffer, size);
#endif
		sendto(socket_fd_, buffer, size, 0, (struct sockaddr *)&peer, len);
	}
	close(socket_fd_);
	return size;
}

int control::start()
{
	int ret = init_socket_fd();
	if (ret)
		return ret;

	std::thread serve_thread([&]() { serve(); });
	serve_thread.detach();
	return 0;
}
