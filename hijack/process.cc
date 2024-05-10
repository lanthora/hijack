// SPDX-License-Identifier: Apache-2.0
#include "hijack/process.h"
#include "hijack/binary.h"
#include <bpf/libbpf.h>
#include <cstdio>
#include <dirent.h>
#include <filesystem>
#include <set>

extern class process_collector process_collector;

void process_collector::scan_procfs()
{
	std::set<int> pids;

	DIR *dir = opendir("/proc");
	if (!dir) {
		return;
	}

	struct dirent *entry;
	while ((entry = readdir(dir))) {
		if (entry->d_type != DT_DIR) {
			continue;
		}
		int pid = atol(entry->d_name);
		if (!pid) {
			continue;
		}
		pids.insert(pid);
	}
	closedir(dir);

	for (int pid : pids) {
		update_process_item(pid);
	}

	return;
}

int process_collector::copy_process_item(int new_pid, int old_pid)
{
	if (new_pid == old_pid) {
		return 0;
	}

	if (!process_map.contains(old_pid) || process_map.contains(new_pid)) {
		return 0;
	}

	process_map[new_pid] = process_map[old_pid];
	process_map[new_pid].pid = new_pid;
	process_map[new_pid].bpf_links.clear();

	return 0;
}

int process_collector::update_process_item(int pid)
{
	struct process_item item;

	item.pid = pid;
	item.binary_ctx = std::shared_ptr<struct binary>(binary_init(pid), [](struct binary *ctx) { binary_free(ctx); });

	process_map[pid] = item;
	return 0;
}

int process_collector::delete_process_item(int pid)
{
	for (auto const &[name, link] : process_map[pid].bpf_links) {
		if (link) {
			bpf_link__detach(link);
		}
	}
	process_map.erase(pid);
	return 0;
}

struct binary *process_collector::fetch_binnary_ctx(int pid)
{
	std::map<pid_t, struct process_item>::iterator it = process_map.find(pid);
	if (it == process_map.end()) {
		return NULL;
	}
	return (*it).second.binary_ctx.get();
}

void process_collector::show_all_items()
{
	for (auto item : process_map) {
		printf("================================================================================\n");
		printf("pid:%d\n", item.second.pid);
		printf("binary ctx:%p\n", item.second.binary_ctx.get());
		printf("================================================================================\n\n");
	}
}

int process_collector::add_probe_link(pid_t pid, std::string name, struct bpf_link *link)
{
	process_map[pid].bpf_links[name] = link;
	return 0;
}

int process_collector::del_probe_link(pid_t pid, std::string name)
{
	struct bpf_link *link;
	auto &process = process_map[pid];
	link = process.bpf_links[name];
	if (link) {
		bpf_link__destroy(link);
	}
	return 0;
}

int process_collector::hook_default_probe(pid_t pid, struct hijack *skel)
{
	auto &process = process_map[pid];
	process.hook_golang_runtime_function(skel);
	process.hook_golang_fmt_function(skel);
	process.hook_golang_log_function(skel);
	process.hook_golang_http2_grpc_function(skel);

#if CONFIG_USDT
	process.hook_hijack_control(skel);
#endif
	return 0;
}

int process_collector::unhook_default_probe(pid_t pid, struct hijack *skel)
{
	auto &process = process_map[pid];
	process.unhook_golang_runtime_function(skel);
	process.unhook_golang_fmt_function(skel);
	process.unhook_golang_log_function(skel);
	process.unhook_golang_http2_grpc_function(skel);

#if CONFIG_USDT
	process.unhook_hijack_control(skel);
#endif
	return 0;
}

int process_item::hook_golang_runtime_function(struct hijack *skel)
{
	if (!binary_ctx) {
		return 0;
	}

	const pid_t pid = this->pid;
	const char *binary_path = binary_ctx->abfd->filename;
	struct bpf_link *link;
	unsigned long long func_offset = 0;

	func_offset = binary_sym_to_addr(binary_ctx.get(), "runtime.newproc1");
	if (func_offset) {
		link = bpf_program__attach_uprobe(skel->progs.runtime_newproc1_enter, false, pid, binary_path, func_offset);
		this->bpf_links["runtime_newproc1_enter"] = link;

		// FIXME: runtime.newproc1 uretprobe 存在导致上层应用崩溃的风险.
		// runtime.newproc1 执行过程中可能调用 runtime.morestack_noctxt.abi0 扩展栈,扩展方式是申请一块更大的内存并将当前栈空间的数据复制到新内存.
		// 当使用 uretprobe 时,会在进入函数后记录函数返回地址,此时返回地址指向的是原来栈的地址,紧接着就有可能发生栈扩展,扩展后原本的地址失效,而函数执行完成后依旧会跳转到这个失效的地址.
		// 访问到无效的地址最终导致进程崩溃.
		link = bpf_program__attach_uprobe(skel->progs.runtime_newproc1_exit, true, pid, binary_path, func_offset);
		this->bpf_links["runtime_newproc1_exit"] = link;
	}

	return 0;
}

int process_item::unhook_golang_runtime_function(struct hijack *skel)
{
	struct bpf_link *link;

	link = this->bpf_links["runtime_newproc1_enter"];
	if (link) {
		bpf_link__destroy(link);
	}

	link = this->bpf_links["runtime_newproc1_exit"];
	if (link) {
		bpf_link__destroy(link);
	}

	return 0;
}

int process_item::hook_golang_fmt_function(struct hijack *skel)
{
	if (!binary_ctx) {
		return 0;
	}

	const pid_t pid = this->pid;
	const char *binary_path = binary_ctx->abfd->filename;
	struct bpf_link *link;
	unsigned long long func_offset = 0;

	func_offset = binary_sym_to_addr(binary_ctx.get(), "fmt.Print");
	if (func_offset) {
		link = bpf_program__attach_uprobe(skel->progs.fmt_print_enter, false, pid, binary_path, func_offset);
		this->bpf_links["fmt_print_enter"] = link;
	}

	func_offset = binary_sym_to_addr(binary_ctx.get(), "fmt.Printf");
	if (func_offset) {
		link = bpf_program__attach_uprobe(skel->progs.fmt_printf_enter, false, pid, binary_path, func_offset);
		this->bpf_links["fmt_printf_enter"] = link;
	}

	return 0;
}

int process_item::unhook_golang_fmt_function(struct hijack *skel)
{
	struct bpf_link *link;

	link = this->bpf_links["fmt_print_enter"];
	if (link) {
		bpf_link__destroy(link);
	}

	link = this->bpf_links["fmt_printf_enter"];
	if (link) {
		bpf_link__destroy(link);
	}

	return 0;
}

int process_item::hook_golang_log_function(struct hijack *skel)
{
	if (!binary_ctx) {
		return 0;
	}

	const pid_t pid = this->pid;
	const char *binary_path = binary_ctx->abfd->filename;
	struct bpf_link *link;
	unsigned long long func_offset = 0;

	func_offset = binary_sym_to_addr(binary_ctx.get(), "log.Println");
	if (func_offset) {
		link = bpf_program__attach_uprobe(skel->progs.log_println_enter, false, pid, binary_path, func_offset);
		this->bpf_links["log_println_enter"] = link;
	}

	func_offset = binary_sym_to_addr(binary_ctx.get(), "github.com/op/go-logging.(*Logger).log");
	if (func_offset) {
		link = bpf_program__attach_uprobe(skel->progs.go_logging_logger_log_enter, false, pid, binary_path, func_offset);
		this->bpf_links["go_logging_logger_log_enter"] = link;
	}

	return 0;
}

int process_item::unhook_golang_log_function(struct hijack *skel)
{
	struct bpf_link *link;

	link = this->bpf_links["log_println_enter"];
	if (link) {
		bpf_link__destroy(link);
	}

	link = this->bpf_links["go_logging_logger_log_enter"];
	if (link) {
		bpf_link__destroy(link);
	}

	return 0;
}

int process_item::hook_golang_http2_grpc_function(struct hijack *skel)
{
	if (!binary_ctx) {
		return 0;
	}

	const pid_t pid = this->pid;
	const char *binary_path = binary_ctx->abfd->filename;
	struct bpf_link *link;
	unsigned long long func_offset = 0;

	// http2
	func_offset = binary_sym_to_addr(binary_ctx.get(), "net/http.(*http2Framer).checkFrameOrder");
	if (func_offset) {
		link = bpf_program__attach_uprobe(skel->progs.net_http_http2Framer_checkFrameOrder, false, pid, binary_path, func_offset);
		this->bpf_links["net_http_http2Framer_checkFrameOrder"] = link;
	}

	func_offset = binary_sym_to_addr(binary_ctx.get(), "net/http.(*http2Framer).WriteDataPadded");
	if (func_offset) {
		link = bpf_program__attach_uprobe(skel->progs.net_http_http2Framer_WriteDataPadded, false, pid, binary_path, func_offset);
		this->bpf_links["net_http_http2Framer_WriteDataPadded"] = link;
	}

	// grpc
	func_offset = binary_sym_to_addr(binary_ctx.get(), "golang.org/x/net/http2.(*Framer).checkFrameOrder");
	if (func_offset) {
		link = bpf_program__attach_uprobe(skel->progs.golang_org_x_net_http2_Framer_checkFrameOrder, false, pid, binary_path, func_offset);
		this->bpf_links["golang_org_x_net_http2_Framer_checkFrameOrder"] = link;
	}

	func_offset = binary_sym_to_addr(binary_ctx.get(), "golang.org/x/net/http2.(*Framer).WriteDataPadded");
	if (func_offset) {
		link = bpf_program__attach_uprobe(skel->progs.golang_org_x_net_http2_Framer_WriteDataPadded, false, pid, binary_path, func_offset);
		this->bpf_links["golang_org_x_net_http2_Framer_WriteDataPadded"] = link;
	}

	return 0;
}

int process_item::unhook_golang_http2_grpc_function(struct hijack *skel)
{
	struct bpf_link *link;

	link = this->bpf_links["net_http_http2Framer_checkFrameOrder"];
	if (link) {
		bpf_link__destroy(link);
	}

	link = this->bpf_links["net_http_http2Framer_WriteDataPadded"];
	if (link) {
		bpf_link__destroy(link);
	}

	link = this->bpf_links["golang_org_x_net_http2_Framer_checkFrameOrder"];
	if (link) {
		bpf_link__destroy(link);
	}

	link = this->bpf_links["golang_org_x_net_http2_Framer_WriteDataPadded"];
	if (link) {
		bpf_link__destroy(link);
	}

	return 0;
}

#if CONFIG_USDT
int process_item::hook_hijack_control(struct hijack *skel)
{
	if (!binary_ctx) {
		return 0;
	}

	const pid_t pid = this->pid;
	const char *binary_path = binary_ctx->abfd->filename;
	struct bpf_link *link;

	if (std::filesystem::path(binary_path).filename() == "hijack") {
		link = bpf_program__attach_usdt(skel->progs.hijack_control, pid, binary_path, "hijack", "control", NULL);
		this->bpf_links["hijack_control"] = link;
	}

	return 0;
}
int process_item::unhook_hijack_control(struct hijack *skel)
{
	struct bpf_link *link;

	link = this->bpf_links["hijack_control"];
	if (link) {
		bpf_link__destroy(link);
	}
	return 0;
}
#endif
