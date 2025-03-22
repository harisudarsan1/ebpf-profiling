#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cpu_info.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
			    unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

int main(int argc, char **argv)
{
	int freq = 1, sw_event = 1, pid = -1, cpu;
	struct cpu_info_bpf *skel = NULL;
	struct perf_event_attr attr;
	struct bpf_link **links = NULL;
	/* struct ring_buffer *ring_buf = NULL; */
	int num_cpus, num_online_cpus;
	int *pefds = NULL, pefd;
	int argp, i, err = 0;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		fprintf(stderr, "Fail to get the number of processors\n");
		err = -1;
		goto cleanup;
	}
	skel = cpu_info_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Fail to open and load BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	pefds = malloc(num_cpus * sizeof(int));
	for (int i = 0; i < num_cpus; i++) {
		pefds[i] = -1;
	}

	links = calloc(num_cpus, sizeof(struct bpf_link *));
	/* Setting perf event Attributes */
	memset(&attr, 0, sizeof(attr));

	attr.type = sw_event ? PERF_TYPE_SOFTWARE : PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = sw_event ? PERF_COUNT_SW_CPU_CLOCK : PERF_COUNT_HW_CPU_CYCLES;
	attr.sample_freq = freq;
	attr.freq = 1;

	for (cpu = 0; cpu < num_cpus; cpu++) {
		pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);

		if (pefd < 0) {
			if (!sw_event && errno == ENOENT) {
				fprintf(stderr,
					"Fail to set up performance monitor on a CPU/Core.\n"
					"Try running the profile example with the `--sw-event` option.\n");
			} else {
				fprintf(stderr,
					"Fail to set up performance monitor on a CPU/Core.\n");
			}
			err = -1;
			goto cleanup;
		}

		pefds[cpu] = pefd;

		/* Attach a BPF program on a CPU */
		links[cpu] = bpf_program__attach_perf_event(skel->progs.get_cpu_info, pefd);
		if (!links[cpu]) {
			err = -1;
			goto cleanup;
		}
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:

	if (links) {
		for (cpu = 0; cpu < num_cpus; cpu++)
			bpf_link__destroy(links[cpu]);
		free(links);
	}
	if (pefds) {
		for (i = 0; i < num_cpus; i++) {
			if (pefds[i] >= 0)
				close(pefds[i]);
		}
		free(pefds);
	}
	cpu_info_bpf__destroy(skel);
	return -err;
}
