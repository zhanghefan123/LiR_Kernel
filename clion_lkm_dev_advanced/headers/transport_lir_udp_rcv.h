//
// Created by zhf on 24-4-13.
//

#ifndef ZEUSNET_KERNEL_TRANSPORT_LIR_UDP_RCV_H
#define ZEUSNET_KERNEL_TRANSPORT_LIR_UDP_RCV_H
#include <net/ip.h>
int lir_udp_rcv(struct sk_buff* skb);
void resolve_transport_lir_udp_rcv_inner_functions_address(void);
#endif // ZEUSNET_KERNEL_TRANSPORT_LIR_UDP_RCV_H
