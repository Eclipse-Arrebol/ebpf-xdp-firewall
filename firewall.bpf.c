// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#define __BPF_SIDE__
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "firewall.h"
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define ETH_P_IP 0x0800
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);	  // key: IP地址
	__type(value, __u32); // value: 随便，1就行
} blacklist SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16);	  // key: IP地址
	__type(value, __u32); // value: 随便，1就行
} port_blacklist SEC(".maps");

struct pkt_stats
{
	__u64 packets; // 包数量
	__u64 bytes;   // 字节数
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);				 // key: IP地址
	__type(value, struct pkt_stats); // value: 统计数据
} stats SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;

	struct ethhdr *eth = data;

	if (BPF_CORE_READ(eth, h_proto) != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
	{
		return XDP_PASS;
	}

	__u32 ipaddr = BPF_CORE_READ(ip, saddr);
	if (bpf_map_lookup_elem(&blacklist, &ipaddr))
	{
		firewall_event *e = bpf_ringbuf_reserve(&events, sizeof(firewall_event), 0);
		if (!e)
			return XDP_DROP;
		e->type = EVENT_BLOCK_IP_IN;
		e->s_ip = ipaddr;
		e->protocol = ip->protocol;
		bpf_ringbuf_submit(e, 0);
		bpf_printk("block ip : %pI4", &ip->daddr);
		return XDP_DROP;
	}

	struct pkt_stats *value = bpf_map_lookup_elem(&stats, &ipaddr);
	if (value)
	{
		__sync_fetch_and_add(&value->bytes, bpf_ntohs(ip->tot_len));
		__sync_fetch_and_add(&value->packets, 1);
	}
	else
	{
		struct pkt_stats init = {
			.packets = 1,
			.bytes = bpf_ntohs(ip->tot_len),
		};

		bpf_map_update_elem(&stats, &ipaddr, &init, BPF_ANY);
	}

	if (BPF_CORE_READ(ip, protocol) == 17)
	{

		struct udphdr *udp = (void *)(ip + 1);
		if ((void *)(udp + 1) > data_end)
		{
			return XDP_PASS;
		}
		__u16 ipport = BPF_CORE_READ(udp, dest);

		//

		if (bpf_map_lookup_elem(&port_blacklist, &ipport))
		{
			firewall_event *e = bpf_ringbuf_reserve(&events, sizeof(firewall_event), 0);
			if (!e)
				return XDP_DROP;
			e->type = EVENT_BLOCK_PORT_IN;
			e->s_ip = ipaddr;
			e->protocol = BPF_CORE_READ(ip, protocol);
			e->s_port = ipport;
			bpf_ringbuf_submit(e, 0);
			bpf_printk("src ip: %u ,port:%u,is block\n", ipaddr, ipport);
			return XDP_DROP;
		}
	}

	if (BPF_CORE_READ(ip, protocol) == 6)
	{
		struct tcphdr *tcp = (void *)(ip + 1);
		if ((void *)(tcp + 1) > data_end)
		{
			return XDP_PASS;
		}
		__u16 ipport = BPF_CORE_READ(tcp, dest);
		if (bpf_map_lookup_elem(&port_blacklist, &ipport))
		{
			firewall_event *e = bpf_ringbuf_reserve(&events, sizeof(firewall_event), 0);
			if (!e)
				return XDP_DROP;
			e->type = EVENT_BLOCK_PORT_IN;
			e->s_ip = ipaddr;
			e->protocol = BPF_CORE_READ(ip, protocol);
			e->s_port = ipport;
			bpf_ringbuf_submit(e, 0);
			bpf_printk("src ip: %u ,port:%u,is block\n", ipaddr, ipport);
			return XDP_DROP;
		}
	}

	// bpf_printk("src ip: %u\n", bpf_ntohl(ip->saddr));

	return XDP_PASS;
}

SEC("tc")
int tc_egress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;

	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_OK;

	struct ethhdr *eth = data;

	if (BPF_CORE_READ(eth, h_proto) != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	__u32 ipaddr = BPF_CORE_READ(ip, daddr);
	if (bpf_map_lookup_elem(&blacklist, &ipaddr))
	{
		firewall_event *e = bpf_ringbuf_reserve(&events, sizeof(firewall_event), 0);
		if (!e)
			return TC_ACT_SHOT;
		e->type = EVENT_BLOCK_IP_OUT;
		e->d_ip = ipaddr;
		e->protocol = BPF_CORE_READ(ip, protocol);
		bpf_ringbuf_submit(e, 0);
		bpf_printk("block ip : %pI4", &ip->daddr);
		return TC_ACT_SHOT;
	}

	if (BPF_CORE_READ(ip, protocol) == 17)
	{

		struct udphdr *udp = (void *)(ip + 1);
		if ((void *)(udp + 1) > data_end)
		{
			return TC_ACT_OK;
		}
		__u16 ipport = BPF_CORE_READ(udp, dest);
		if (bpf_map_lookup_elem(&port_blacklist, &ipport))
		{
			firewall_event *e = bpf_ringbuf_reserve(&events, sizeof(firewall_event), 0);
			if (!e)
				return TC_ACT_SHOT;
			e->type = EVENT_BLOCK_PORT_OUT;
			e->d_ip = ipaddr;
			e->protocol = BPF_CORE_READ(ip, protocol);
			e->d_port = ipport;
			bpf_ringbuf_submit(e, 0);
			bpf_printk("src ip: %u ,port:%u,is block\n", ipaddr, ipport);
			return TC_ACT_SHOT;
		}
	}

	if (BPF_CORE_READ(ip, protocol) == 6)
	{
		struct tcphdr *tcp = (void *)(ip + 1);
		if ((void *)(tcp + 1) > data_end)
		{
			return TC_ACT_OK;
		}
		__u16 ipport = BPF_CORE_READ(tcp, dest);
		if (bpf_map_lookup_elem(&port_blacklist, &ipport))
		{
			firewall_event *e = bpf_ringbuf_reserve(&events, sizeof(firewall_event), 0);
			if (!e)
				return TC_ACT_SHOT;
			e->type = EVENT_BLOCK_PORT_OUT;
			e->d_ip = ipaddr;
			e->protocol = BPF_CORE_READ(ip, protocol);
			e->d_port = ipport;
			bpf_ringbuf_submit(e, 0);
			bpf_printk("src ip: %u ,port:%u,is block\n", ipaddr, ipport);
			return TC_ACT_SHOT;
		}
	}

	bpf_printk("receive the data,the ip is %pI4", &ip->daddr);
	return TC_ACT_OK;
}
