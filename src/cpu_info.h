
#ifndef __CPU_INFO_H
#define __CPU_INFO_H

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127

struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	bool exit_event;
};

#endif /* __BOOTSTRAP_H */
