
#include "vmlinux.h"
/* #include <bpf/bpf_helpers.h> */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
/* #include <linux/bpf.h> */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} cpu_info_map SEC(".maps");

#define ARRAY_SIZE 10
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
} cpu_counters SEC(".maps");

SEC("tracepoint/power/cpu_frequency")
int handle_cpu_freq(struct trace_event_raw_cpu *ctx)
{
	int freq = ctx->state;
	int cpu = ctx->cpu_id;
	bpf_printk("hello");
	bpf_printk("cpu-id: %d,freq: %d", cpu, freq);
	return 0;
}

#define nsec_per_sec 1000000000ull
#define user_hz	     100ull // check via `getconf clk_tck` (usually 100)
extern struct kernel_cpustat kernel_cpustat __ksym;
/* we need to attach to perf event because we need our program to 
 * constantly monitor at repeated intervals */
SEC("perf_event")
int get_cpu_info(struct bpf_perf_event_data *ctx)
{
	//  get the current cpu
	u32 cpu = bpf_get_smp_processor_id();
	struct kernel_cpustat *stat;

	// access per-cpu kernel_cpustat which has btf type information as well
	stat = (struct kernel_cpustat *)bpf_this_cpu_ptr(&kernel_cpustat);
	if (!stat)
		return 0;

	/* __u64 user_time = BPF_CORE_READ(stat, cpustat[CPUTIME_USER]); */
	/* #pragma unroll */
	/* 	for (int i = 0; i < 10; i++) { */
	/* 		__u64 value = BPF_CORE_READ(stat, cpustat[i]); */
	/* 		u32 k = i; */
	/* 		bpf_map_update_elem(&cpu_counters, &k, &value, BPF_ANY); */
	/**/
	/* 		value /= (nsec_per_sec / user_hz); // convert ns → jiffies */
	/* 		bpf_printk("cpu:%d,user %llu", cpu, value); */
	/* 	} */

	/* convert the nanoseconds value to jiffles */
	u32 k = 0;
	u64 *val = bpf_map_lookup_elem(&cpu_counters, &k);
	/* u64 value = *val; */
	if (val) {
		bpf_printk("cpu:%d,user %llu", cpu, *val);
	}

	return 0;
}
