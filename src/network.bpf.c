#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
/* Tracepoint to update rx bytes.
   Note: The actual tracepoint structure (here assumed to be "struct trace_event_raw_net_dev_template")
   must match your kernel's definition. */
SEC("tracepoint/net/netif_receive_skb")
int trace_rx(struct trace_event_raw_net_dev_template *ctx)
{
	__u32 if_index;
	char ifname[14];
	struct sk_buff *sk_buffer = (struct sk_buff *)ctx->skbaddr;

	if_index = BPF_CORE_READ(sk_buffer, dev, ifindex);
	int err = BPF_CORE_READ_STR_INTO(&ifname, sk_buffer, dev, name);
	unsigned int len = BPF_CORE_READ(sk_buffer, len);
	bpf_printk("got ifindex : %s with len: %d for rx", ifname, len);
	return 0;
}

/* Tracepoint to update tx bytes */
SEC("tracepoint/net/net_dev_xmit")
int trace_tx(struct trace_event_raw_net_dev_template *ctx)
{
	__u32 if_index;
	char ifname[14];
	struct sk_buff *sk_buffer = (struct sk_buff *)ctx->skbaddr;

	if_index = BPF_CORE_READ(sk_buffer, dev, ifindex);
	int err = BPF_CORE_READ_STR_INTO(&ifname, sk_buffer, dev, name);
	unsigned int len = BPF_CORE_READ(sk_buffer, len);
	bpf_printk("got ifindex : %s with len: %d for tx", ifname, len);
	return 0;
}
