//
// Created by zhf on 24-3-16.
//

#ifndef ZEUSNET_KERNEL_HOOK_TCP_V4_RCV_H
#define ZEUSNET_KERNEL_HOOK_TCP_V4_RCV_H
#include "ftrace_hook_api.h"
void resolve_tcp_v4_rcv_inner_functions_address(void);
int ip_self_defined_tcp_v4_rcv(struct sk_buff* skb);
void add_tcp_v4_do_rcv_to_hook(void);
extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;
#endif // ZEUSNET_KERNEL_HOOK_TCP_V4_RCV_H
