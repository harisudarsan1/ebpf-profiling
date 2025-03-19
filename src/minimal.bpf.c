// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
/* #include <bpf/bpf_helpers.h> */
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
/* #include <linux/bpf.h> */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

/* SEC("tp/syscalls/sys_enter_write") */
/* int handle_tp(void *ctx) */
/* { */
/* 	int pid = bpf_get_current_pid_tgid() >> 32; */
/**/
/* 	if (pid != my_pid) */
/* 		return 0; */
/**/
/* 	bpf_printk("BPF triggered from PID %d.\n", pid); */
/**/
/* 	return 0; */
/* } */

SEC("tracepoint/net/netif_receive_skb")
int trace_rx(struct trace_event_raw_net_dev_template *ctx)
{
	/* sk_buff ss; */
	/* ss = ctx->skbaddr; */
	__u32 if_index;
	char ifname[14];
	struct sk_buff *sk_buffer = (struct sk_buff *)ctx->skbaddr;

	if_index = BPF_CORE_READ(sk_buffer, dev, ifindex);
	int err = BPF_CORE_READ_STR_INTO(&ifname, sk_buffer, dev, name);
	unsigned int len = BPF_CORE_READ(sk_buffer, len);
	/* if_index = BPF_CORE_READ(dev, ifindex); */

	/* struct net_data *data; */
	bpf_printk("got ifindex : %s with len: %d", ifname, len);
	/* data = bpf_map_lookup_elem(&net_map, &ifindex); */
	/* if (!data) { */
	/* struct net_data init = {}; */
	/* bpf_map_update_elem(&net_map, &ifindex, &init, BPF_ANY); */
	/* data = bpf_map_lookup_elem(&net_map, &ifindex); */
	/* if (!data) */
	/* 	return 0; */
	/* } */
	/* data->rx_bytes += ctx->len; */
	return 0;
}
