//
// Created by zhf on 24-4-3.
//

#ifndef ZEUSNET_KERNEL_SELF_DEFINED_TCP_RCV_ESTABLISHED_H
#define ZEUSNET_KERNEL_SELF_DEFINED_TCP_RCV_ESTABLISHED_H
#include <net/ip.h>
#include <net/tcp.h>
void resolve_self_defined_tcp_rcv_established_inner_functions_address(void);
void self_defined_tcp_rcv_established(struct sock *sk, struct sk_buff *skb);
#define FLAG_DATA		0x01 /* Incoming frame contained data.		*/
#define FLAG_SLOWPATH		0x100 /* Do not skip RFC checks for window update.*/
#define FLAG_UPDATE_TS_RECENT	0x4000 /* tcp_replace_ts_recent() */
#define TCP_HP_BITS (~(TCP_RESERVED_BITS|TCP_FLAG_PSH))
#endif // ZEUSNET_KERNEL_SELF_DEFINED_TCP_RCV_ESTABLISHED_H
