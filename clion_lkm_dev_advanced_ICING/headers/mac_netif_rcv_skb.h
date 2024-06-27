//
// Created by zhf on 24-4-12.
//

#ifndef ZEUSNET_KERNEL_MAC_NETIF_RCV_SKB_H
#define ZEUSNET_KERNEL_MAC_NETIF_RCV_SKB_H
#include "support_ftrace_hook_api.h"
#include "lir_configuration.h"
void add_netif_rcv_skb_to_hook(void);
void resolve_netif_rcv_skb_inner_functions_address(void);
int self_defined__netif_receive_skb_core(struct sk_buff **pskb, bool pfmemalloc,struct packet_type **ppt_prev);
int self_defined__netif_receive_skb_one_core(struct sk_buff *skb, bool pfmemalloc);
extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;
#endif // ZEUSNET_KERNEL_MAC_NETIF_RCV_SKB_H
