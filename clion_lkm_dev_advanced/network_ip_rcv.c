//
// Created by zhf on 24-4-14.
//
#include "headers/support_tools.h"
#include "headers/network_ip_rcv.h"
#include "headers/support_ftrace_hook_api.h"
#include <linux/inetdevice.h>
#include <net/route.h>

asmlinkage struct sk_buff *(*orig_ip_rcv_core)(struct sk_buff *skb, struct net *net);
asmlinkage int (*orig_tcp_v4_early_demux)(struct sk_buff *skb);
asmlinkage int (*orig_udp_v4_early_demux)(struct sk_buff *skb);
asmlinkage int (*orig_ip_forward)(struct sk_buff *skb);


void resolve_network_ip_rcv_inner_functions_address(void){
    LOG_WITH_EDGE("start to resolve network ip_rcv inner functions address");
    orig_ip_rcv_core = get_function_address("ip_rcv_core");
    LOG_RESOLVED(orig_ip_rcv_core, "ip_rcv_core");
    orig_tcp_v4_early_demux = get_function_address("tcp_v4_early_demux");
    LOG_RESOLVED(orig_tcp_v4_early_demux, "tcp_v4_early_demux");
    orig_udp_v4_early_demux = get_function_address("udp_v4_early_demux");
    LOG_RESOLVED(orig_udp_v4_early_demux, "udp_v4_early_demux");
    orig_ip_forward = get_function_address("ip_forward");
    LOG_RESOLVED(orig_ip_forward, "ip_forward");
    LOG_WITH_EDGE("end to resolve network ip_rcv inner functions address");
}

// ------------------------- static ----------------------------

static bool ip_can_use_hint(const struct sk_buff *skb, const struct iphdr *iph,
                            const struct sk_buff *hint) {
    return hint && !skb_dst(skb) && ip_hdr(hint)->daddr == iph->daddr &&
           ip_hdr(hint)->tos == iph->tos;
}


static inline bool skb_valid_dst(const struct sk_buff *skb) {
    struct dst_entry *dst = skb_dst(skb);

    return dst && !(dst->flags & DST_METADATA);
}

static inline bool ip_rcv_options(struct sk_buff *skb, struct net_device *dev) {
    struct ip_options *opt;
    const struct iphdr *iph;

    /* It looks as overkill, because not all
       IP options require packet mangling.
       But it is the easiest for now, especially taking
       into account that combination of IP options
       and running sniffer is extremely rare condition.
                          --ANK (980813)
    */
    if (skb_cow(skb, skb_headroom(skb))) {
        __IP_INC_STATS(dev_net(dev), IPSTATS_MIB_INDISCARDS);
        goto drop;
    }

    iph = ip_hdr(skb);
    opt = &(IPCB(skb)->opt);
    opt->optlen = iph->ihl * 4 - sizeof(struct iphdr);

    if (ip_options_compile(dev_net(dev), opt, skb)) {
        __IP_INC_STATS(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
        goto drop;
    }

    if (unlikely(opt->srr)) {
        struct in_device *in_dev = __in_dev_get_rcu(dev);

        if (in_dev) {
            if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
                if (IN_DEV_LOG_MARTIANS(in_dev))
                    net_info_ratelimited("source route option %pI4 -> %pI4\n",
                                         &iph->saddr,
                                         &iph->daddr);
                goto drop;
            }
        }

        if (ip_options_rcv_srr(skb, dev))
            goto drop;
    }

    return false;
    drop:
    return true;
}


static int ip_rcv_finish_core(struct net *net, struct sock *sk,
                              struct sk_buff *skb, struct net_device *dev,
                              const struct sk_buff *hint)
{
    const struct iphdr *iph = ip_hdr(skb);
    int err, drop_reason;
    struct rtable *rt;

    drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;

    if (ip_can_use_hint(skb, iph, hint)) {
        err = ip_route_use_hint(skb, iph->daddr, iph->saddr, iph->tos,
                                dev, hint);
        if (unlikely(err))
            goto drop_error;
    }

    if (READ_ONCE(net->ipv4.sysctl_ip_early_demux) &&
        !skb_dst(skb) &&
        !skb->sk &&
        !ip_is_fragment(iph)) {
        switch (iph->protocol) {
            case IPPROTO_TCP:
                if (READ_ONCE(net->ipv4.sysctl_tcp_early_demux)) {
                    orig_tcp_v4_early_demux(skb);

                    /* must reload iph, skb->head might have changed */
                    iph = ip_hdr(skb);
                }
                break;
            case IPPROTO_UDP:
                if (READ_ONCE(net->ipv4.sysctl_udp_early_demux)) {
                    err = orig_udp_v4_early_demux(skb);
                    if (unlikely(err))
                        goto drop_error;

                    /* must reload iph, skb->head might have changed */
                    iph = ip_hdr(skb);
                }
                break;
        }
    }

    /*
     *	Initialise the virtual path cache for the packet. It describes
     *	how the packet travels inside Linux networking.
     */
    if (!skb_valid_dst(skb)) {
        err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
                                   iph->tos, dev);
        if (unlikely(err))
            goto drop_error;
    }

//#ifdef CONFIG_IP_ROUTE_CLASSID
//    if (unlikely(skb_dst(skb)->tclassid)) {
//        struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
//        u32 idx = skb_dst(skb)->tclassid;
//        st[idx&0xFF].o_packets++;
//        st[idx&0xFF].o_bytes += skb->len;
//        st[(idx>>16)&0xFF].i_packets++;
//        st[(idx>>16)&0xFF].i_bytes += skb->len;
//    }
//#endif

    if (iph->ihl > 5 && ip_rcv_options(skb, dev))
        goto drop;

    rt = skb_rtable(skb);
    if (rt->rt_type == RTN_MULTICAST) {
        __IP_UPD_PO_STATS(net, IPSTATS_MIB_INMCAST, skb->len);
    } else if (rt->rt_type == RTN_BROADCAST) {
        __IP_UPD_PO_STATS(net, IPSTATS_MIB_INBCAST, skb->len);
    } else if (skb->pkt_type == PACKET_BROADCAST ||
               skb->pkt_type == PACKET_MULTICAST) {
        struct in_device *in_dev = __in_dev_get_rcu(dev);

        /* RFC 1122 3.3.6:
         *
         *   When a host sends a datagram to a link-layer broadcast
         *   address, the IP destination address MUST be a legal IP
         *   broadcast or IP multicast address.
         *
         *   A host SHOULD silently discard a datagram that is received
         *   via a link-layer broadcast (see Section 2.4) but does not
         *   specify an IP multicast or broadcast destination address.
         *
         * This doesn't explicitly say L2 *broadcast*, but broadcast is
         * in a way a form of multicast and the most common use case for
         * this is 802.11 protecting against cross-station spoofing (the
         * so-called "hole-196" attack) so do it for both.
         */
        if (in_dev &&
            IN_DEV_ORCONF(in_dev, DROP_UNICAST_IN_L2_MULTICAST)) {
            drop_reason = SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST;
            goto drop;
        }
    }

    return NET_RX_SUCCESS;

    drop:
    kfree_skb_reason(skb, drop_reason);
    return NET_RX_DROP;

    drop_error:
    if (err == -EXDEV) {
        drop_reason = SKB_DROP_REASON_IP_RPFILTER;
        __NET_INC_STATS(net, LINUX_MIB_IPRPFILTER);
    }
    goto drop;
}
// ------------------------- static ----------------------------

int self_defined_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
           struct net_device *orig_dev, u64 start)
{
    struct net *net = dev_net(dev);

    skb = orig_ip_rcv_core(skb, net);
    if (skb == NULL)
        return NET_RX_DROP;

    return self_defined_ip_rcv_finish(net, NULL,skb, start);
    //    NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
    //                   net, NULL, skb, dev, NULL,
    //                   ip_rcv_finish);
}

int self_defined_ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb, u64 start)
{
    struct net_device *dev = skb->dev;
    int ret;
    u64 time_elapsed;
    /* if ingress device is enslaved to an L3 master device pass the
     * skb to its handler for processing
     */
    skb = l3mdev_ip_rcv(skb);
    if (!skb)
        return NET_RX_SUCCESS;
    ret = ip_rcv_finish_core(net, sk, skb, dev, NULL);
    if (ret != NET_RX_DROP){
        bool output = skb_dst(skb)->input == orig_ip_forward;
        ret = dst_input(skb);
        if(output){
            time_elapsed = ktime_get_real_ns() - start;
            printk(KERN_EMERG "[zeusnet's kernel info]:ip rcv take %llu ns\n", time_elapsed);
        }
    }
    return ret;
}
