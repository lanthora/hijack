// SPDX-License-Identifier: Apache-2.0
#include "hijack/process.h"

extern "C" {
static void stack_trace_callback(bfd_vma pc, const char *functionname, const char *filename, int line, void *data)
{
	int idx = *(int *)data;
	printf("%p at %s in %s:%d\n", (void *)pc, functionname, filename, line);
}
}

int main()
{
	struct binary *ctx;
	class process_collector collector;
	collector.scan_procfs();

	ctx = collector.fetch_binnary_ctx(getpid());

	bfd_vma pc = (bfd_vma)stack_trace_callback;
	assert(binary_addr_to_line(ctx, pc, stack_trace_callback, NULL));
	assert(binary_sym_to_addr(ctx, "stack_trace_callback") + ctx->addr_start == (long)stack_trace_callback);

	return 0;
}
