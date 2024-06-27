//
// Created by zhf on 24-4-13.
//
#include <net/udp.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/busy_poll.h>
#include <asm-generic/rwonce.h>
#include <trace/events/udp.h>
#include "headers/support_tools.h"
#include "headers/support_ftrace_hook_api.h"
#include "headers/transport_lir_udp_rcv.h"
#include "headers/network_lir_rcv.h"

asmlinkage int (*orig_sk_filter_trim_cap)(struct sock *sk, struct sk_buff *skb, unsigned int cap);
asmlinkage void (*orig_ipv4_pktinfo_prepare)(const struct sock *sk, struct sk_buff *skb);
asmlinkage int (*orig_udp_unicast_rcv_skb)(struct sock *sk, struct sk_buff *skb,struct udphdr *uh);
DEFINE_STATIC_KEY_FALSE(udp_encap_needed_key);

void resolve_transport_lir_udp_rcv_inner_functions_address(void){
    LOG_WITH_EDGE("start to resolve lir_udp_rcv inner functions address");
    orig_sk_filter_trim_cap = get_function_address("sk_filter_trim_cap");
    LOG_RESOLVED(orig_sk_filter_trim_cap, "sk_filter_trim_cap");
    orig_ipv4_pktinfo_prepare = get_function_address("ipv4_pktinfo_prepare");
    LOG_RESOLVED(orig_ipv4_pktinfo_prepare, "ipv4_pktinfo_prepare");
    orig_udp_unicast_rcv_skb = get_function_address("udp_unicast_rcv_skb");
    LOG_RESOLVED(orig_udp_unicast_rcv_skb, "udp_unicast_rcv_skb");
    LOG_WITH_EDGE("end to resolve lir_udp_rcv inner functions address");
}

// --------------------------- static ---------------------------

static inline struct sock *copy__udp4_lib_lookup_skb(struct sk_buff *skb,
                                                 __be16 sport, __be16 dport,
                                                 struct udp_table *udptable)
{
    const struct lirhdr *lir_header = lir_hdr(skb);

    return __udp4_lib_lookup(dev_net(skb->dev), lir_header->source, sport,
                             lir_header->destination, dport, inet_iif(skb),
                             inet_sdif(skb), udptable, skb); // 这个是暴露的 EXPOSED 的函数
}

static inline int udplite_checksum_init(struct sk_buff *skb, struct udphdr *uh)
{
    u16 cscov;

    /* In UDPv4 a zero checksum means that the transmitter generated no
     * checksum. UDP-Lite (like IPv6) mandates checksums, hence packets
     * with a zero checksum field are illegal.                            */
    if (uh->check == 0) {
        net_dbg_ratelimited("UDPLite: zeroed checksum field\n");
        return 1;
    }

    cscov = ntohs(uh->len);

    if (cscov == 0)		 /* Indicates that full coverage is required. */
        ;
    else if (cscov < 8  || cscov > skb->len) {
        /*
         * Coverage length violates RFC 3828: log and discard silently.
         */
        net_dbg_ratelimited("UDPLite: bad csum coverage %d/%d\n",
                            cscov, skb->len);
        return 1;

    } else if (cscov < skb->len) {
        UDP_SKB_CB(skb)->partial_cov = 1;
        UDP_SKB_CB(skb)->cscov = cscov;
        if (skb->ip_summed == CHECKSUM_COMPLETE)
            skb->ip_summed = CHECKSUM_NONE;
        skb->csum_valid = 0;
    }

    return 0;
}

static inline int udp4_csum_init(struct sk_buff *skb, struct udphdr *uh,
                                 int proto)
{
    int err;

    UDP_SKB_CB(skb)->partial_cov = 0;
    UDP_SKB_CB(skb)->cscov = skb->len;

    if (proto == IPPROTO_UDPLITE) {
        err = udplite_checksum_init(skb, uh);
        if (err)
            return err;

        if (UDP_SKB_CB(skb)->partial_cov) {
            skb->csum = inet_compute_pseudo(skb, proto);
            return 0;
        }
    }

    /* Note, we are only interested in != 0 or == 0, thus the
     * force to int.
     */
    err = (__force int)skb_checksum_init_zero_check(skb, proto, uh->check,
                                                    inet_compute_pseudo);
    if (err)
        return err;

    if (skb->ip_summed == CHECKSUM_COMPLETE && !skb->csum_valid) {
        /* If SW calculated the value, we know it's bad */
        if (skb->csum_complete_sw)
            return 1;

        /* HW says the value is bad. Let's validate that.
         * skb->csum is no longer the full packet checksum,
         * so don't treat it as such.
         */
        skb_checksum_complete_unset(skb);
    }

    return 0;
}

// --------------------------- static ---------------------------


int lir_udp_rcv(struct sk_buff* skb){
    struct sock *sk;
    struct udphdr *uh;
    unsigned short ulen;
    struct net *net = dev_net(skb->dev);
    bool refcounted;
    int drop_reason;
    struct udp_table *udptable = &udp_table;
    int proto = IPPROTO_UDP;
    // LOG_WITH_PREFIX("lir udp rcv called");

    drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;

    /*
     *  Validate the packet.
     */
    if (!pskb_may_pull(skb, sizeof(struct udphdr)))
        goto drop;		/* No space for header. */

    uh   = udp_hdr(skb);
    ulen = ntohs(uh->len);

    if (ulen > skb->len)
        goto short_packet;

    if (proto == IPPROTO_UDP) {
        /* UDP validates ulen. */
        if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
            goto short_packet;
        uh = udp_hdr(skb);
    }

    uh->check = 0; // 说明不需要再校验了

    if (udp4_csum_init(skb, uh, proto))
        goto csum_error;

    sk = skb_steal_sock(skb, &refcounted);
    if (sk) {
        struct dst_entry *dst = skb_dst(skb);
        int ret;

        if (unlikely(rcu_dereference(sk->sk_rx_dst) != dst))
            udp_sk_rx_dst_set(sk, dst);

        ret = orig_udp_unicast_rcv_skb(sk, skb, uh);
        if (refcounted)
            sock_put(sk);
        return ret;
    }

    sk = copy__udp4_lib_lookup_skb(skb, uh->source, uh->dest, udptable);
    if (sk) {
        return orig_udp_unicast_rcv_skb(sk, skb, uh);
    }


    if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
        goto drop;
    nf_reset_ct(skb);

    if (udp_lib_checksum_complete(skb))
        goto csum_error;

    drop_reason = SKB_DROP_REASON_NO_SOCKET;
    __UDP_INC_STATS(net, UDP_MIB_NOPORTS, proto == IPPROTO_UDPLITE);
    icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

    kfree_skb_reason(skb, drop_reason);
    return 0;

    short_packet:
    drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
    goto drop;

    csum_error:
    drop_reason = SKB_DROP_REASON_UDP_CSUM;
    __UDP_INC_STATS(net, UDP_MIB_CSUMERRORS, proto == IPPROTO_UDPLITE);
    drop:
    __UDP_INC_STATS(net, UDP_MIB_INERRORS, proto == IPPROTO_UDPLITE);
    kfree_skb_reason(skb, drop_reason);
    return 0;
}