// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define TASK_COMM_LEN 16

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); // key: IP地址
	__type(value, __u32); // value: 随便，1就行
} blacklist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16); // key: IP地址
	__type(value, __u32); // value: 随便，1就行
} port_blacklist SEC(".maps");

struct pkt_stats {
    __u64 packets;   // 包数量
    __u64 bytes;     // 字节数
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);            // key: IP地址
    __type(value, struct pkt_stats); // value: 统计数据
} stats SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;

	

	struct ethhdr *eth = data;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return XDP_PASS;
	}
	

	__u32 ipaddr = ip->saddr;
	struct pkt_stats *value = bpf_map_lookup_elem(&stats,&ipaddr);
	if(value)
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

		bpf_map_update_elem(&stats,&ipaddr,&init,BPF_ANY);
	}
	

	if (ip->protocol == 17) {
		
		struct udphdr *udp = (void *)(ip + 1);
		if((void*)(udp+1)>data_end)
		{
			return XDP_PASS;
		}
		__u16 ipport = udp->dest;
		if (bpf_map_lookup_elem(&blacklist, &ipaddr) ||
		    bpf_map_lookup_elem(&port_blacklist, &ipport)) {
			bpf_printk("src ip: %u ,port:%u,is block\n", ipaddr,ipport);
			return XDP_DROP;
		}
	}

	if (ip->protocol == 6) {
		struct tcphdr *tcp = (void *)(ip + 1);
		if((void*)(tcp+1)>data_end)
		{
			return XDP_PASS;
		}
		__u16 ipport = tcp->dest;
		if (bpf_map_lookup_elem(&blacklist, &ipaddr) ||
		    bpf_map_lookup_elem(&port_blacklist, &ipport)) {
			bpf_printk("src ip: %u ,port:%u,is block\n", ipaddr,ipport);
			return XDP_DROP;
		}
	}

	// bpf_printk("src ip: %u\n", bpf_ntohl(ip->saddr));

	return XDP_PASS;
}
