// SPDX-License-Identifier: Apache-2.0
#include "hijack/binary.h"
#include <string>
#include <unistd.h>

static std::string read_symbol_link(std::string filename)
{
	char buffer[1024];
	ssize_t len = 0;
	len = readlink(filename.data(), buffer, sizeof(buffer));
	buffer[len] = '\0';
	return std::string(buffer);
}

static bfd_vma addr_start(int pid)
{
	bfd_vma retval = 0;
	FILE *maps = NULL;
	char buffer[1024];

	sprintf(buffer, "/proc/%d/exe", pid);
	std::string path = read_symbol_link(buffer);

	sprintf(buffer, "/proc/%d/maps", pid);
	maps = fopen(buffer, "rb");
	if (!maps) {
		return 0;
	}

	while (fgets(buffer, sizeof(buffer), maps)) {
		if (buffer[strlen(buffer) - 1] == '\n') {
			buffer[strlen(buffer) - 1] = '\0';
		}

		if (!std::string(buffer).ends_with(path)) {
			continue;
		}
		char *pos = strstr(buffer, "-");
		if (pos) {
			*pos = '\0';
			retval = (bfd_vma)strtoll(buffer, NULL, 16);
		}
		break;
	}

	fclose(maps);

	return retval;
}

// FIXME: 未启动 PIE 的情况下调整为 0, 需要有更好的方法判断是否启用 PIE
static bool binary_no_pie(struct binary *ctx)
{
	return ctx->addr_start == 0x400000;
}

struct binary *binary_init(int pid)
{
	char filename[4096];
	sprintf(filename, "/proc/%d/exe", pid);
	bfd *abfd = bfd_openr(filename, NULL);
	if (!abfd)
		return NULL;

	abfd->flags |= BFD_DECOMPRESS;
	if (!bfd_check_format(abfd, bfd_object)) {
		bfd_close(abfd);
		return NULL;
	}

	if (!(bfd_get_file_flags(abfd) & HAS_SYMS)) {
		bfd_close(abfd);
		return NULL;
	}

	long storage = bfd_get_symtab_upper_bound(abfd);
	if (storage <= 0) {
		bfd_close(abfd);
		return NULL;
	}

	asymbol **syms = (asymbol **)malloc(storage);
	if (!syms) {
		bfd_close(abfd);
		return NULL;
	}

	long nsym = bfd_canonicalize_symtab(abfd, syms);
	if (nsym <= 0) {
		free(syms);
		bfd_close(abfd);
		return NULL;
	}

	struct binary *ctx = (struct binary *)malloc(sizeof(struct binary));
	if (!ctx) {
		free(syms);
		bfd_close(abfd);
		return NULL;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->syms = syms;
	ctx->abfd = abfd;
	ctx->addr_start = addr_start(pid);
	ctx->nsym = nsym;

	ctx->section = bfd_get_section_by_name(ctx->abfd, ".text");

	if ((bfd_section_flags(ctx->section) & SEC_ALLOC) == 0) {
		free(syms);
		bfd_close(abfd);
		free(ctx);
		return NULL;
	}

	return ctx;
}

void binary_free(struct binary *ctx)
{
	if (!ctx)
		return;

	free(ctx->syms);
	bfd_close(ctx->abfd);
	free(ctx);
}

static void find_address_in_section(bfd *abfd, asection *section, void *data)
{
	struct binary *ctx = (struct binary *)data;
	if (ctx->found)
		return;
	if ((bfd_section_flags(section) & SEC_ALLOC) == 0)
		return;
	bfd_vma vma = bfd_section_vma(section);
	if (ctx->pc < vma)
		return;
	bfd_size_type size = bfd_section_size(section);
	if (ctx->pc >= vma + size)
		return;
	ctx->found = bfd_find_nearest_line(abfd, section, ctx->syms, ctx->pc - vma, &ctx->filename, &ctx->functionname, &ctx->line);
}

bool binary_addr_to_line(struct binary *ctx, bfd_vma pc, binary_addr2line_callback_t callback, void *data)
{
	if (!ctx)
		return FALSE;

	ctx->filename = NULL;
	ctx->functionname = NULL;
	ctx->line = 0;
	ctx->found = FALSE;
	ctx->pc = binary_no_pie(ctx) ? pc : pc - ctx->addr_start;
	bfd_map_over_sections(ctx->abfd, find_address_in_section, ctx);
	if (callback) {
		callback(pc, ctx->functionname, ctx->filename, ctx->line, data);
	}

	return ctx->found;
}

long binary_sym_to_addr(struct binary *ctx, const char *symbol)
{
	if (!ctx)
		return 0;

	for (long idx = 0; idx < ctx->nsym; ++idx) {
		if (strcmp(symbol, bfd_asymbol_name(ctx->syms[idx]))) {
			continue;
		}

		bfd_vma addr = bfd_asymbol_value(ctx->syms[idx]);
		if (binary_no_pie(ctx)) {
			addr -= ctx->addr_start;
		}
		return addr;
	}

	return 0;
}
