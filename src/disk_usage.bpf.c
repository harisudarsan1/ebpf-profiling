#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
/* #include "core_fixes.bpf.h" */

char LICENSE[] SEC("license") = "GPL";

/**
 * commit d5869fdc189f ("block: introduce block_rq_error tracepoint")
 * adds a new tracepoint block_rq_error and it shares the same arguments
 * with tracepoint block_rq_complete. As a result, the kernel BTF now has
 * a `struct trace_event_raw_block_rq_completion` instead of
 * `struct trace_event_raw_block_rq_complete`.
 * see:
 *     https://github.com/torvalds/linux/commit/d5869fdc189f
 */
struct trace_event_raw_block_rq_complete___x {
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	int errors;
	char rwbs[8];
} __attribute__((preserve_access_index));

struct trace_event_raw_block_rq_completion___x {
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	int errors;
	char rwbs[8];
} __attribute__((preserve_access_index));

static __always_inline bool has_block_rq_completion()
{
	if (bpf_core_type_exists(struct trace_event_raw_block_rq_completion___x))
		return true;
	return false;
}

SEC("tracepoint/block/block_rq_complete")
int handle__block_rq_complete(void *args)
{
	sector_t sector;
	unsigned int nr_sector;
	dev_t dev;
	char rwbs[8];
	char *op;

	if (has_block_rq_completion()) {
		struct trace_event_raw_block_rq_completion___x *ctx = args;
		sector = BPF_CORE_READ(ctx, sector);
		nr_sector = BPF_CORE_READ(ctx, nr_sector);
		dev = BPF_CORE_READ(ctx, dev);

		bpf_core_read_str(rwbs, sizeof(rwbs), &ctx->rwbs);
	} else {
		struct trace_event_raw_block_rq_complete___x *ctx = args;
		sector = BPF_CORE_READ(ctx, sector);
		nr_sector = BPF_CORE_READ(ctx, nr_sector);
		dev = BPF_CORE_READ(ctx, dev);

		bpf_core_read_str(rwbs, sizeof(rwbs), &ctx->rwbs);
	}
	if (rwbs[0] == 'W') {
		op = "write";
	}

	if (rwbs[0] == 'R') {
		op = "read";
	}

	u32 major = (dev >> 20) & 0xfff; // Major number (12 bits)
	u32 minor = dev & 0xfffff; // Minor number (20 bits)
	bpf_printk("dev-id: %s,operation:%s,bytes=%d,major:%d,minor:%d", dev, op, nr_sector * 512,
		   major, minor);

	return 0;
}
