//
// Created by zhf on 24-4-12.
//

#ifndef ZEUSNET_KERNEL_TRANSPORT_UDP_SENDMSG_H
#define ZEUSNET_KERNEL_TRANSPORT_UDP_SENDMSG_H
#include "support_ftrace_hook_api.h"
#include "lir_configuration.h"
#include "lir_data_structure.h"
void add_udp_sendmsg_to_hook(void);
int lir_udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;
#endif // ZEUSNET_KERNEL_TRANSPORT_UDP_SENDMSG_H
