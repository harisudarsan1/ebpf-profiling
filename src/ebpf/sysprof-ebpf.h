#ifndef __SYSPROFEBPF_H
#define __SYSPROFEBPF_H

struct network_event {
	char ifname[16];
	unsigned int bytes;
};

#endif /* __SYSPROFEBPF_H */
