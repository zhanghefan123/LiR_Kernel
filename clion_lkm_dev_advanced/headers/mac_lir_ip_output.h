//
// Created by zhf on 24-4-12.
//

#ifndef ZEUSNET_KERNEL_MAC_LIR_IP_OUTPUT_H
#define ZEUSNET_KERNEL_MAC_LIR_IP_OUTPUT_H
#include <net/ip.h>
#include "network_lir_header.h"
struct lir_fraglist_iter {
    struct sk_buff	*frag;
    struct lirhdr	*lir_header;
    int		offset;
    unsigned int	hlen;
};
struct neighbour *lir_ip_neigh_for_gw(struct net_device* output_dev);
int lir_ip_output(struct net *, struct sock *,struct sk_buff *, struct net_device* output_dev);
int lir_ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_dev);
int lir__ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_dev);
int lir_ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_dev);
int lir_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
                 unsigned int mtu, struct net_device *output_dev,
                 int (*output)(struct net *, struct sock *, struct sk_buff *, struct net_device *output_dev));
int lir_do_fragment(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_dev,
                    int (*output)(struct net *, struct sock *, struct sk_buff*, struct net_device* output_dev));
#endif //ZEUSNET_KERNEL_MAC_LIR_IP_OUTPUT_H
