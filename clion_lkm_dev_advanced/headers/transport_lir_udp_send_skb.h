//
// Created by zhf on 24-4-12.
//

#ifndef ZEUSNET_KERNEL_TRANSPORT_LIR_UDP_SEND_SKB_H
#define ZEUSNET_KERNEL_TRANSPORT_LIR_UDP_SEND_SKB_H
#include <net/ip.h>
int lir_udp_send_skb(struct sk_buff *skb,
                     struct inet_cork *cork,
                     struct net_device *output_dev,
                     __be16 sport,
                     __be16 dport);
#endif // ZEUSNET_KERNEL_TRANSPORT_LIR_UDP_SEND_SKB_H
