
#ifndef __FIREWALL_H
#define __FIREWALL_H
#ifndef __BPF_SIDE__
#include <linux/types.h>
#endif

enum EventType
{
    EVENT_BLOCK_IP_IN,
    EVENT_BLOCK_IP_OUT,
    EVENT_BLOCK_PORT_IN,
    EVENT_BLOCK_PORT_OUT
};

typedef struct
{
    __u32 d_ip;
    __u32 s_ip;
    __u8 protocol;
    __u16 d_port;
    __u16 s_port;
    enum EventType type;
} firewall_event;
#endif
