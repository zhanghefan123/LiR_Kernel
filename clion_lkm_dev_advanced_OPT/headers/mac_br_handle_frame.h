//
// Created by zhf on 24-4-12.
//

#ifndef ZEUSNET_KERNEL_MAC_BR_HANDLE_FRAME_H
#define ZEUSNET_KERNEL_MAC_BR_HANDLE_FRAME_H
#include <net/ip.h>
rx_handler_result_t self_defined_br_handle_frame(struct sk_buff **pskb); // 网桥接受frame并转发的逻辑
void resolve_br_handle_frame_inner_functions_address(void); // 解析内部需要用到的没有EXPOSED的函数
int self_defined_br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb);
#endif // ZEUSNET_KERNEL_MAC_BR_HANDLE_FRAME_H
