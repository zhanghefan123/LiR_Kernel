//
// Created by zhf on 24-4-3.
//

#ifndef ZEUSNET_KERNEL_SELF_DEFINED_TCP_V4_DO_RCV_H
#define ZEUSNET_KERNEL_SELF_DEFINED_TCP_V4_DO_RCV_H
#include <net/ip.h>
#include <net/tcp.h>
int self_defined_tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb, const struct tcphdr* th);
void resolve_tcp_v4_do_rcv_inner_function_address(void);
#endif // ZEUSNET_KERNEL_SELF_DEFINED_TCP_V4_DO_RCV_H
