// SPDX-License-Identifier: GPL-2.0-only
#ifndef HIJACK_EBPF_LOG_H
#define HIJACK_EBPF_LOG_H

#include "hijack-common/types.h"
#include "hijack-ebpf/maps.h"
#include "hijack-ebpf/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define ___LOG(__fmt, __args...)                                                                                                                                                   \
	{                                                                                                                                                                          \
		struct event_log *__e = (struct event_log *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct event_log), 0);                                                            \
		if (__e) {                                                                                                                                                         \
			__e->type = RB_EVENT_LOG;                                                                                                                                  \
			__e->nsec = bpf_ktime_get_boot_ns();                                                                                                                       \
			int __len = BPF_SNPRINTF(__e->msg, CONFIG_LOG_LEN_MAX, __fmt, __args);                                                                                     \
			if (__len > 0) {                                                                                                                                           \
				bpf_ringbuf_submit(__e, 0);                                                                                                                        \
			} else {                                                                                                                                                   \
				bpf_ringbuf_discard(__e, 0);                                                                                                                       \
			}                                                                                                                                                          \
		}                                                                                                                                                                  \
	}

#define __LOG(__fmt, __args...)                                                                                                                                                    \
	{                                                                                                                                                                          \
		int __zero = 0;                                                                                                                                                    \
		struct global_cfg *__cfg = bpf_map_lookup_elem(&global_cfg_map, &__zero);                                                                                          \
		if (__cfg && __cfg->log_enabled) {                                                                                                                                 \
			___LOG(__fmt, __args);                                                                                                                                     \
		}                                                                                                                                                                  \
	}

#define LOG __LOG

#endif
