// SPDX-License-Identifier: Apache-2.0
#ifndef HIJACK_PROCESS_H
#define HIJACK_PROCESS_H

#include "hijack/binary.h"
#include "hijack/hijack.skel.h"
#include <map>
#include <memory>
#include <string>

// 用户态维护的与进程相关的数据结构.在 update_process_item 中更新.
// 未来可以用来保存当前进程挂载的 uprobe 的 hook 状态和偏移等信息.
struct process_item {
	pid_t pid;
	std::shared_ptr<struct binary> binary_ctx;
	std::map<std::string, struct bpf_link *> bpf_links;

	// Go 运行时探针
	int hook_golang_runtime_function(struct hijack *skel);
	int unhook_golang_runtime_function(struct hijack *skel);
	// Go 格式化探针
	int hook_golang_fmt_function(struct hijack *skel);
	int unhook_golang_fmt_function(struct hijack *skel);
	// Go 日志探针
	int hook_golang_log_function(struct hijack *skel);
	int unhook_golang_log_function(struct hijack *skel);

	// Go Grpc 探针
	int hook_golang_http2_grpc_function(struct hijack *skel);
	int unhook_golang_http2_grpc_function(struct hijack *skel);

	// 当前进程的 USDT
	int hook_hijack_control(struct hijack *skel);
	int unhook_hijack_control(struct hijack *skel);
};

class process_collector {
    public:
	// 扫描 /proc 目录, 尽可能填充 process_collector
	void scan_procfs();

	// 新进程创建时调用,用父进程信息填充子进程,适用于仅 fork 但不 execve 的进程,例如 nginx 的工作进程
	int copy_process_item(int new_pid, int old_pid);

	// execve 系统调用刷新内存,进程信息已经变更,无法直接使用 fork 后的信息,需要重新获取
	int update_process_item(int pid);

	// 进程退出时调用,清理进程信息
	int delete_process_item(int pid);

	// 根据进程号那 binary 上下文
	struct binary *fetch_binnary_ctx(int pid);

	// 打印收集的信息,用于调试
	void show_all_items();

	// 保存手动添加的探针(uprobe/usdt),目前仅在函数调用栈功能中使用
	int add_probe_link(pid_t pid, std::string name, struct bpf_link *link);
	int del_probe_link(pid_t pid, std::string name);

	// 程序运行过程中自动添加的探针(uprobe/usdt)
	int hook_default_probe(pid_t pid, struct hijack *skel);
	int unhook_default_probe(pid_t pid, struct hijack *skel);

    private:
	// 保存系统中的所有进程
	std::map<pid_t, struct process_item> process_map;
};

#endif
