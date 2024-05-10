// SPDX-License-Identifier: Apache-2.0
#include "hijack-common/config.h"
#include "hijack/process.h"
#include "hijack/utils.h"
#include "hijack/callback.h"
#include "hijack/control.h"
#include "hijack/hijack.skel.h"
#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <iostream>

struct hijack *skel = NULL;
class process_collector process_collector;
class control control;
struct ring_buffer *rb = NULL;

static void handle_signal(int sig)
{
	std::cout << strsignal(sig) << std::endl;
}

static void attach_cgroup_sockops()
{
	int cgroup_fd;
	std::string cgroup_mount_path = current_cgroup_mount_path();

	cgroup_fd = open(cgroup_mount_path.data(), O_RDONLY);
	assert(cgroup_fd);
	skel->links.sockops_handler = bpf_program__attach_cgroup(skel->progs.sockops_handler, cgroup_fd);
	assert(skel->links.sockops_handler);
	close(cgroup_fd);
}

static void detach_cgroup_sockops()
{
	bpf_link__detach(skel->links.sockops_handler);
}

static void open_and_load()
{
	skel = hijack__open_and_load();
	assert(skel);
}

static void attach_probes()
{
	int error;

	error = hijack__attach(skel);
	assert(!error);
}

static void detach_probes()
{
	hijack__detach(skel);
}

static void consume()
{
	int error;
	int consumed;

	error = control.start();
	assert(!error);
	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), ring_buffer_callback, NULL, NULL);
	assert(rb);
	process_collector.scan_procfs();

	do {
		consumed = ring_buffer__poll(rb, 100);
	} while (consumed >= 0);

	ring_buffer__free(rb);
}

static void destroy()
{
	hijack__destroy(skel);
}

int main()
{
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	open_and_load();
	attach_probes();
	attach_cgroup_sockops();
	consume();
	detach_cgroup_sockops();
	detach_probes();
	destroy();

	std::cout << "Exit" << std::endl;
	return 0;
}
