#include "sysprof-ebpf.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* struct trace_event_raw_net_dev_template { */
/* 	struct trace_entry ent; */
/* 	void *skbaddr; */
/* 	unsigned int len; */
/* 	u32 __data_loc_name; */
/* 	char __data[0]; */
/* } __attribute__((preserve_access_index)); */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} network_map SEC(".maps");
/* Tracepoint to update rx bytes.
   Note: The actual tracepoint structure (here assumed to be "struct
   trace_event_raw_net_dev_template") must match your kernel's definition. */
SEC("tracepoint/net/netif_receive_skb")
int trace_rx(struct trace_event_raw_net_dev_template *ctx)
{
	__u32 if_index;
	char ifname[14];
	struct network_event *net_event;
	struct sk_buff *sk_buffer = (struct sk_buff *)ctx->skbaddr;

	/* if_index = BPF_CORE_READ(sk_buffer, dev, ifindex); */

	/* reserve sample from BPF ringbuf */
	net_event = bpf_ringbuf_reserve(&network_map, sizeof(*net_event), 0);
	if (!net_event)
		return 0;

	int err = BPF_CORE_READ_STR_INTO(&net_event->ifname, sk_buffer, dev, name);
	net_event->bytes = BPF_CORE_READ(sk_buffer, len);
	net_event->is_tx = 0;

	bpf_printk("got ifindex : %s with len: %d for rx", net_event->ifname, net_event->bytes);
	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(net_event, 0);
	return 0;
}

/* Tracepoint to update tx bytes */
/* SEC("tracepoint/net/net_dev_xmit") */
/* int trace_tx(struct trace_event_raw_net_dev_template *ctx) */
/* { */
/* 	__u32 if_index; */
/* 	char ifname[14]; */
/* 	struct sk_buff *sk_buffer = (struct sk_buff *)ctx->skbaddr; */
/**/
/* 	if_index = BPF_CORE_READ(sk_buffer, dev, ifindex); */
/* 	int err = BPF_CORE_READ_STR_INTO(&ifname, sk_buffer, dev, name); */
/* 	unsigned int len = BPF_CORE_READ(sk_buffer, len); */
/* 	bpf_printk("got ifindex : %s with len: %d for tx", ifname, len); */
/* 	return 0; */
/* } */
