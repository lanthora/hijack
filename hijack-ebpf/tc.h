// SPDX-License-Identifier: GPL-2.0-only
#ifndef HIJACK_EBPF_TC_H
#define HIJACK_EBPF_TC_H

// TODO: 自动挂载,避免手动输入一下命令
//
// tc qdisc add dev eth0 clsact
// tc filter add dev eth0 egress bpf da obj target/hijack.o sec tc
// bpftool prog show
// tc filter del dev eth0 egress
// tc qdisc del dev eth0 clsact
int tc_do_nothing(struct __sk_buff *skb)
{
	return 0;
}

#endif
