// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "firewall.skel.h"
#include <linux/types.h>
#include <net/if.h>
#include <signal.h>
#include <linux/if_link.h> // XDP_FLAGS_SKB_MODE 在这里
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include "firewall.h"

static volatile int keep_running = 1;

void *thread_fn(void *arg)
{
	// arg 是传进来的参数，需要强转

	struct firewall_bpf *skel = (struct firewall_bpf *)arg;

	char buf_m[128];

	while (fgets(buf_m, sizeof(buf_m), stdin) != NULL)
	{
		buf_m[strcspn(buf_m, "\n")] = '\0';

		if (strcmp(buf_m, "list") == 0)
		{
			__u32 key = 0, next_key;
			__u32 value;
			printf("polling...\n");
			fflush(stdout);
			while (bpf_map__get_next_key(skel->maps.blacklist, &key, &next_key,
										 sizeof(key)) == 0)
			{
				bpf_map__lookup_elem(skel->maps.blacklist, &next_key,
									 sizeof(next_key), &value, sizeof(value), 0);
				struct in_addr ip_addr = {.s_addr = next_key};
				printf("IP: %-16s\n", inet_ntoa(ip_addr));

				key = next_key;
			}
		}
		else if (strncmp(buf_m, "add ", 4) == 0)
		{
			char *ip = buf_m + 4;
			__u32 val = 1;
			struct in_addr addr;
			inet_aton(ip, &addr);
			bpf_map__update_elem(skel->maps.blacklist, &addr.s_addr,
								 sizeof(addr.s_addr), &val, sizeof(val), BPF_ANY);
		}
		else if (strncmp(buf_m, "del ", 4) == 0)
		{
			char *ip = buf_m + 4;
			struct in_addr addr;
			inet_aton(ip, &addr);
			bpf_map__delete_elem(skel->maps.blacklist, &addr.s_addr,
								 sizeof(addr.s_addr), 0);
		}
	}

	return NULL;
}

void sig_handler(int sig)
{
	keep_running = 0;
}

struct pkt_stats
{
	__u64 packets;
	__u64 bytes;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int ring_buf_callback(void *ctx, void *data, size_t size)
{
	firewall_event *e = (firewall_event *)data;
	struct in_addr addr;

	if (e->type == EVENT_BLOCK_IP_IN)
	{
		addr.s_addr = e->s_ip;
		printf("block in ip :%s\n", inet_ntoa(addr));
	}

	if (e->type == EVENT_BLOCK_IP_OUT)
	{
		addr.s_addr = e->d_ip;
		printf("block out ip :%s\n", inet_ntoa(addr));
	}
	if (e->type == EVENT_BLOCK_PORT_IN)
	{
		addr.s_addr = e->s_ip;
		printf("block out ip :%s,block port : %d\n", inet_ntoa(addr), e->s_port);
	}

	if (e->type == EVENT_BLOCK_PORT_OUT)
	{
		addr.s_addr = e->d_ip;
		printf("block out ip :%s,block port : %d\n", inet_ntoa(addr), e->d_port);
	}
	return 0;
}

int main(int argc, char **argv)
{
	int opt;
	char *ens = NULL;
	char *b_ip[100];
	int i_ip = 0;
	char *b_port[100];
	int i_port = 0;

	while ((opt = getopt(argc, argv, "i:b:p:")) != -1)
	{
		switch (opt)
		{
		case 'i':
			ens = optarg;
			printf("网卡: %s\n", optarg);
			break;
		case 'b':
			printf("黑名单IP: %s\n", optarg);
			b_ip[i_ip] = optarg;
			i_ip++;
			break;
		case 'p':
			b_port[i_port] = optarg;
			i_port++;
			printf("黑名单端口: %s\n", optarg);
			break;
		}
	}

	if (!ens)
	{
		fprintf(stderr, "Usage: %s -i <interface> [-b <ip>] [-p <port>]\n", argv[0]);
		return 1;
	}

	int ifindex = if_nametoindex(ens);
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex,
						.attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	bool hook_created = false;

	struct firewall_bpf *skel;
	int err;
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// pid_t key = 0, next_key;
	// __u64 value;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = firewall_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* ensure BPF program only handles write() syscalls from our process */

	/* Load & verify BPF programs */
	err = firewall_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST)
	{
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_egress);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err)
	{
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = firewall_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	struct ring_buffer *ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events), ring_buf_callback, NULL, NULL);

	__u32 val = 1;
	for (int i = 0; i < i_ip; i++)
	{
		struct in_addr addr;
		inet_aton(b_ip[i], &addr);
		bpf_map__update_elem(skel->maps.blacklist, &addr.s_addr, sizeof(addr.s_addr), &val,
							 sizeof(val), BPF_ANY);
	}
	for (int i = 0; i < i_port; i++)
	{
		__u16 port = htons(atoi(b_port[i]));
		bpf_map__update_elem(skel->maps.port_blacklist, &port, sizeof(port), &val,
							 sizeof(val), BPF_ANY);
	}

	if (!ifindex)
	{
		fprintf(stderr, "Failed to get ifindex\n");
		goto cleanup;
	}

	int prog_fd = bpf_program__fd(skel->progs.xdp_prog);
	if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0)
	{
		fprintf(stderr, "Failed to attach XDP\n");
		goto cleanup;
	}

	pthread_t tid;
	// 创建线程，把 skel 传进去
	pthread_create(&tid, NULL, thread_fn, skel);

	while (keep_running)
	{
		ring_buffer__poll(ring_buf, 100);
	}
	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err)
	{
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}
	pthread_cancel(tid);
	pthread_join(tid, NULL);
	bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	firewall_bpf__destroy(skel);
	return -err;
}
