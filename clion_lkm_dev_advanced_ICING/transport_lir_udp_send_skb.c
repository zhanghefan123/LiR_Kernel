//
// Created by zhf on 24-4-12.
//
#include "headers/support_tools.h"
#include "headers/transport_lir_udp_send_skb.h"
#include "headers/network_lir_make_skb.h"
#include <net/udp.h>

int lir_udp_send_skb(struct sk_buff *skb,
                     struct inet_cork *cork,
                     struct net_device *output_dev,
                     __be16 sport,
                     __be16 dport){
    // --------------      initialize        --------------
    struct sock *sk = skb->sk;
    struct inet_sock *inet = inet_sk(sk);
    struct udphdr *uh;
    int err;
    int offset = skb_transport_offset(skb);
    bool is_udplite = false;
    int len = skb->len - offset;
    int datalen = len - sizeof(*uh);
    __wsum csum = 0;
    // --------------      initialize        --------------
    // --------------    set udp header      --------------
    uh = udp_hdr(skb);
    uh->source = sport;
    uh->dest = dport;
    uh->len = htons(len);
    uh->check = 0; // dont calculate check sum
    // --------------    set udp header      --------------
    if (uh->check == 0)
        uh->check = CSUM_MANGLED_0;
    err = lir_send_skb(sock_net(sk), skb, output_dev);

    if (err) {
        // LOG_WITH_PREFIX("lir send skb error");
        if (err == -ENOBUFS && !inet->recverr) {
            UDP_INC_STATS(sock_net(sk),
                          UDP_MIB_SNDBUFERRORS, is_udplite);
            err = 0;
        }
    } else{
        // LOG_WITH_PREFIX("lir send skb success");
        UDP_INC_STATS(sock_net(sk),
                      UDP_MIB_OUTDATAGRAMS, is_udplite);
    }

    return err;
}