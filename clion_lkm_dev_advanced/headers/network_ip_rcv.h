//
// Created by zhf on 24-4-14.
//

#ifndef ZEUSNET_KERNEL_NETWORK_IP_RCV_H
#define ZEUSNET_KERNEL_NETWORK_IP_RCV_H
#include <net/ip.h>
int self_defined_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
                        struct net_device *orig_dev, u64 start);
void resolve_network_ip_rcv_inner_functions_address(void);
int self_defined_ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb, u64 start);
#endif //ZEUSNET_KERNEL_NETWORK_IP_RCV_H
