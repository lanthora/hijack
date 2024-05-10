// SPDX-License-Identifier: Apache-2.0
#ifndef HIJACK_CONTROL_H
#define HIJACK_CONTROL_H

#include <sys/un.h>

class control {
    public:
	int start();

    private:
	int handle_log_enabled(void *buffer, int len);
	int handle_pproc_enabled(void *buffer, int len);
	int handle_io_event_others_enabled(void *buffer, int len);
	int handle_io_event_socket_disabled(void *buffer, int len);
	int handle_io_event_regular_disabled(void *buffer, int len);
	int handle_kfree_skb_enabled(void *buffer, int len);
	int handle_nf_hook_slow_enabled(void *buffer, int len);
	int handle_sched_enabled(void *buffer, int len);
	int handle_tcp_probe_enabled(void *buffer, int len);
	int handle_call_stack_trace(void *buffer, int len);
	int handle_set_listen_port(void *buffer, int len);
	int handle_handle_mm_fault_enabled(void *buffer, int len);
	int handle_sched_switch_event_enabled(void *buffer, int len);

    private:
	int init_socket_fd();
	int serve();
	int socket_fd_;
	struct sockaddr_un server_;
};

#endif
