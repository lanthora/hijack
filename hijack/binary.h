// SPDX-License-Identifier: Apache-2.0
#ifndef HIJACK_BINARY_H
#define HIJACK_BINARY_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PACKAGE "binary"
#define PACKAGE_VERSION "0.0.0"
#include <bfd.h>

struct binary {
	bfd *abfd;
	bfd_vma addr_start;
	asymbol **syms;
	long nsym;

	// 以下为内部使用的临时变量
	asection *section;
	bfd_vma pc;
	bfd_boolean found;
	const char *filename;
	const char *functionname;
	unsigned int line;
};

typedef void (*binary_addr2line_callback_t)(bfd_vma pc, const char *functionname, const char *filename, int line, void *data);

struct binary *binary_init(int pid);
void binary_free(struct binary *ctx);

bool binary_addr_to_line(struct binary *ctx, bfd_vma pc, binary_addr2line_callback_t callback, void *data);
long binary_sym_to_addr(struct binary *ctx, const char *symbol);

#endif
