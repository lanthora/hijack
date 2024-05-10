// SPDX-License-Identifier: GPL-2.0-only
#include "hijack-ebpf/fentry.h"
#include "hijack-ebpf/kprobe.h"
#include "hijack-ebpf/sched.h"
#include "hijack-ebpf/skb.h"
#include "hijack-ebpf/sockops.h"
#include "hijack-ebpf/syscalls.h"
#include "hijack-ebpf/tc.h"
#include "hijack-ebpf/tcp.h"
#include "hijack-ebpf/uprobe.h"
#include "hijack-ebpf/usdt.h"
#include "hijack-ebpf/vmlinux.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tp/sched/sched_process_fork")
int sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	return trace_sched_process_fork(ctx);
}

SEC("tp/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	return trace_sched_process_exec(ctx);
}

SEC("tp/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	return trace_sched_process_exit(ctx);
}

SEC("tp/sched/sched_switch")
int sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	return trace_sched_switch(ctx);
}

SEC("tp/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	return trace_sys_enter(ctx);
}

SEC("tp/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	return trace_sys_exit(ctx);
}

SEC("tp/skb/kfree_skb")
int kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
	return trace_kfree_skb(ctx);
}

SEC("tp/tcp/tcp_probe")
int tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	return trace_tcp_probe(ctx);
}

SEC("tp/tcp/tcp_retransmit_skb")
int tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	return trace_tcp_retransmit_skb(ctx);
}

SEC("tp/tcp/tcp_retransmit_synack")
int tcp_retransmit_synack(struct trace_event_raw_tcp_retransmit_synack *ctx)
{
	return trace_tcp_retransmit_synack(ctx);
}

SEC("tp/tcp/tcp_send_reset")
int tcp_send_reset(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	return trace_tcp_send_reset(ctx);
}

SEC("tp/tcp/tcp_receive_reset")
int tcp_receive_reset(struct trace_event_raw_tcp_event_sk *ctx)
{
	return trace_tcp_receive_reset(ctx);
}

SEC("tp/tcp/tcp_destroy_sock")
int tcp_destroy_sock(struct trace_event_raw_tcp_event_sk *ctx)
{
	return trace_tcp_destroy_sock(ctx);
}

SEC("kprobe/nf_hook_slow")
int BPF_KPROBE(nf_hook_slow_enter, struct sk_buff *skb, struct nf_hook_state *state, const struct nf_hook_entries *e, unsigned int i)
{
	return trace_nf_hook_slow_enter(skb);
}

SEC("kretprobe/nf_hook_slow")
int BPF_KRETPROBE(nf_hook_slow_exit, int ret)
{
	return trace_nf_hook_slow_exit(ret);
}

SEC("kretprobe/handle_mm_fault")
int BPF_KRETPROBE(handle_mm_fault_exit, vm_fault_t ret)
{
	return trace_handle_mm_fault_exit(ctx, ret);
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state_enter, struct sock *sk, int state)
{
	return trace_tcp_set_state_enter(ctx, sk, state);
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect_enter, struct sock *sk)
{
	return trace_tcp_connect_enter(ctx, sk);
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_exit, struct sock *accepted_sk)
{
	return trace_inet_csk_accept_exit(ctx, accepted_sk);
}

SEC("fexit/udp_lib_get_port")
int BPF_PROG(fexit_udp_lib_get_port, struct sock *sk, unsigned short snum, unsigned int hash2_nulladdr, int ret)
{
	return trace_udp_lib_get_port_exit(sk, snum, hash2_nulladdr, ret);
}

SEC("fentry/udp_lib_unhash")
int BPF_PROG(fentry_udp_lib_unhash, struct sock *sk)
{
	return trace_udp_lib_unhash_enter(sk);
}
// udp_lib_unhash

SEC("uprobe")
int BPF_KPROBE(call_stack)
{
	return trace_user_call_stack(ctx, "customize");
}

SEC("uprobe")
int BPF_KPROBE(runtime_newproc1_enter)
{
	return trace_runtime_newproc1_enter(ctx);
}

SEC("uretprobe")
int BPF_KRETPROBE(runtime_newproc1_exit)
{
	return trace_runtime_newproc1_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(fmt_print_enter)
{
	return trace_any_slice_enter(ctx, "fmt.Print");
}

SEC("uprobe")
int BPF_KPROBE(fmt_printf_enter)
{
	return trace_format_any_slice_enter(ctx, "fmt.Printf");
}

SEC("uprobe")
int BPF_KPROBE(log_println_enter)
{
	return trace_any_slice_enter(ctx, "log.Println");
}

SEC("uprobe")
int BPF_KPROBE(go_logging_logger_log_enter)
{
	return trace_level_format_pointer_any_slice_enter(ctx, "github.com/op/go-logging.(*Logger).log");
}

SEC("uprobe")
int BPF_KPROBE(net_http_http2Framer_checkFrameOrder)
{
	return trace_net_http_http2Framer_checkFrameOrder(ctx);
}

SEC("uprobe")
int BPF_KPROBE(net_http_http2Framer_WriteDataPadded)
{
	return trace_net_http_http2Framer_WriteDataPadded(ctx);
}

SEC("uprobe")
int BPF_KPROBE(golang_org_x_net_http2_Framer_checkFrameOrder)
{
	return trace_golang_org_x_net_http2_Framer_checkFrameOrder(ctx);
}

SEC("uprobe")
int BPF_KPROBE(golang_org_x_net_http2_Framer_WriteDataPadded)
{
	return trace_golang_org_x_net_http2_Framer_WriteDataPadded(ctx);
}

SEC("sockops") int sockops_handler(struct bpf_sock_ops *skops)
{
	sockops_write_tcp_options(skops);
	return 1;
}

SEC("tc")
int tc_handler(struct __sk_buff *skb)
{
	tc_do_nothing(skb);
	return 0;
}

#if CONFIG_USDT
SEC("usdt")
int BPF_USDT(hijack_control, char *buffer, int size)
{
	return trace_hijack_control(buffer, size);
}
#endif
