// SPDX-License-Identifier: GPL-2.0-only
#ifndef HIJACK_EBPF_USDT_H
#define HIJACK_EBPF_USDT_H

#if CONFIG_USDT
#include "hijack-ebpf/log.h"
#include <bpf/usdt.bpf.h>

int trace_hijack_control(char *buffer, int size)
{
	u32 type;
	bpf_probe_read_user(&type, sizeof(type), buffer);
	LOG("usdt hijack control: type=%d, size=%d", type, size);
	return 0;
}
#endif

#endif
