//
// Created by zhf on 24-4-12.
//
#include <net/ip.h>
#include <net/dsa.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <linux/if_vlan.h>
#include <uapi/linux/bpf.h>
#include <linux/netfilter_netdev.h>
#include "headers/mac_br_handle_frame.h"
#include "headers/support_tools.h"
#include "headers/mac_netif_rcv_skb.h"
#include "headers/network_lir_rcv.h"

asmlinkage int (*orig__netif_receive_skb_one_core)(struct sk_buff *skb, bool pfmemalloc);
asmlinkage int (*orig_skb_do_redirect)(struct sk_buff *);
asmlinkage bool (*orig_vlan_do_receive)(struct sk_buff **skb);
asmlinkage int(*orig_ip_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
asmlinkage int (*orig_ipv6_rcv)(struct sk_buff *skb, struct net_device *dev,struct packet_type *pt, struct net_device *orig_dev);
struct list_head* ptype_base_copy __read_mostly; // 结构体对象也需要解析
struct list_head* ptype_all_copy __read_mostly;	 // 结构体对象也需要解析

void resolve_netif_rcv_skb_inner_functions_address(void){
    LOG_WITH_EDGE("start to resolve netif_rcv_skb inner functions address");
    orig_skb_do_redirect = get_function_address("skb_do_redirect");
    LOG_RESOLVED(orig_skb_do_redirect, "skb_do_redirect");
    orig_vlan_do_receive = get_function_address("vlan_do_receive");
    LOG_RESOLVED(orig_vlan_do_receive, "vlan_do_receive");
    orig_ipv6_rcv = get_function_address("ipv6_rcv");
    LOG_RESOLVED(orig_ipv6_rcv, "ipv6_rcv");
    orig_ip_rcv = get_function_address("ip_rcv");
    LOG_RESOLVED(orig_ip_rcv, "ip_rcv");
    ptype_base_copy = get_function_address("ptype_base");
    LOG_RESOLVED(ptype_base_copy, "ptype_base");
    ptype_all_copy = get_function_address("ptype_all");
    LOG_RESOLVED(ptype_all_copy, "ptype_all");
    LOG_WITH_EDGE("end to resolve netif_rcv_skb inner functions address");
}

asmlinkage int hook__netif_receive_skb_one_core(struct sk_buff *skb, bool pfmemalloc) {
    return self_defined__netif_receive_skb_one_core(skb, pfmemalloc);
}

void add_netif_rcv_skb_to_hook(void){
    hooks[number_of_hook].name = "__netif_receive_skb_one_core";
    hooks[number_of_hook].function = hook__netif_receive_skb_one_core;
    hooks[number_of_hook].original = &orig__netif_receive_skb_one_core;
    number_of_hook += 1;
}

#define net_timestamp_check(COND, SKB)                      \
    if (static_branch_unlikely(&netstamp_needed_key)) {     \
        if ((COND) && !(SKB)->tstamp)                       \
            (SKB)->tstamp = ktime_get_real();               \
    }                                                       \

int netdev_tstamp_prequeue __read_mostly = 1;
static DEFINE_STATIC_KEY_FALSE(generic_xdp_needed_key);
static DEFINE_STATIC_KEY_FALSE(ingress_needed_key);

// ---------------------------------- static ----------------------------------
static bool skb_pfmemalloc_protocol(struct sk_buff *skb)
{
    switch (skb->protocol) {
        case htons(ETH_P_ARP):
        case htons(ETH_P_IP):
        case htons(ETH_P_IPV6):
        case htons(ETH_P_8021Q):
        case htons(ETH_P_8021AD):
            return true;
        default:
            return false;
    }
}

static inline int deliver_skb(struct sk_buff *skb,
                              struct packet_type *pt_prev,
                              struct net_device *orig_dev)
{
    if (unlikely(skb_orphan_frags_rx(skb, GFP_ATOMIC)))
        return -ENOMEM;
    refcount_inc(&skb->users);
    return pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
}

static inline void deliver_ptype_list_skb(struct sk_buff *skb,
                                          struct packet_type **pt,
                                          struct net_device *orig_dev,
                                          __be16 type,
                                          struct list_head *ptype_list)
{
    struct packet_type *ptype, *pt_prev = *pt;

    list_for_each_entry_rcu(ptype, ptype_list, list) {
        if (ptype->type != type)
            continue;
        if (pt_prev)
            deliver_skb(skb, pt_prev, orig_dev);
        pt_prev = ptype;
    }
    *pt = pt_prev;
}

static inline struct sk_buff *
sch_handle_ingress(struct sk_buff *skb, struct packet_type **pt_prev, int *ret,
                   struct net_device *orig_dev, bool *another)
{
#ifdef CONFIG_NET_CLS_ACT
    struct mini_Qdisc *miniq = rcu_dereference_bh(skb->dev->miniq_ingress);
    struct tcf_result cl_res;

    /* If there's at least one ingress present somewhere (so
     * we get here via enabled static key), remaining devices
     * that are not configured with an ingress qdisc will bail
     * out here.
     */
    if (!miniq)
        return skb;

    if (*pt_prev) {
        *ret = deliver_skb(skb, *pt_prev, orig_dev);
        *pt_prev = NULL;
    }

    qdisc_skb_cb(skb)->pkt_len = skb->len;
    tc_skb_cb(skb)->mru = 0;
    tc_skb_cb(skb)->post_ct = false;
    skb->tc_at_ingress = 1;
    mini_qdisc_bstats_cpu_update(miniq, skb);

    switch (tcf_classify(skb, miniq->block, miniq->filter_list, &cl_res, false)) {
        case TC_ACT_OK:
        case TC_ACT_RECLASSIFY:
            skb->tc_index = TC_H_MIN(cl_res.classid);
            break;
        case TC_ACT_SHOT:
            mini_qdisc_qstats_cpu_drop(miniq);
            kfree_skb_reason(skb, SKB_DROP_REASON_TC_INGRESS);
            return NULL;
        case TC_ACT_STOLEN:
        case TC_ACT_QUEUED:
        case TC_ACT_TRAP:
            consume_skb(skb);
            return NULL;
        case TC_ACT_REDIRECT:
            /* skb_mac_header check was done by cls/act_bpf, so
             * we can safely push the L2 header back before
             * redirecting to another netdev
             */
            __skb_push(skb, skb->mac_len);
            if (orig_skb_do_redirect(skb) == -EAGAIN) {
                __skb_pull(skb, skb->mac_len);
                *another = true;
                break;
            }
            return NULL;
        case TC_ACT_CONSUMED:
            return NULL;
        default:
            break;
    }
#endif /* CONFIG_NET_CLS_ACT */
    return skb;
}

static inline int nf_ingress(struct sk_buff *skb, struct packet_type **pt_prev,
                             int *ret, struct net_device *orig_dev)
{
    if (nf_hook_ingress_active(skb)) {
        int ingress_retval;

        if (*pt_prev) {
            *ret = deliver_skb(skb, *pt_prev, orig_dev);
            *pt_prev = NULL;
        }

        rcu_read_lock();
        ingress_retval = nf_hook_ingress(skb);
        rcu_read_unlock();
        return ingress_retval;
    }
    return 0;
}

// ---------------------------------- static ----------------------------------


int self_defined__netif_receive_skb_core(struct sk_buff **pskb, bool pfmemalloc,struct packet_type **ppt_prev) {
    struct packet_type *ptype, *pt_prev;
    rx_handler_func_t *rx_handler;
    struct sk_buff *skb = *pskb;
    struct net_device *orig_dev;
    bool deliver_exact = false;
    int ret = NET_RX_DROP;
    __be16 type;

    net_timestamp_check(!netdev_tstamp_prequeue, skb);

    orig_dev = skb->dev;

    skb_reset_network_header(skb);
    if (!skb_transport_header_was_set(skb))
        skb_reset_transport_header(skb);
    skb_reset_mac_len(skb);

    pt_prev = NULL;

    another_round:
    skb->skb_iif = skb->dev->ifindex;

    __this_cpu_inc(softnet_data.processed);

    if (static_branch_unlikely(&generic_xdp_needed_key)) {
        int ret2;

        migrate_disable();
        ret2 = do_xdp_generic(rcu_dereference(skb->dev->xdp_prog), skb);
        migrate_enable();

        if (ret2 != XDP_PASS) {
            ret = NET_RX_DROP;
            goto out;
        }
    }

    if (eth_type_vlan(skb->protocol)) {
        skb = skb_vlan_untag(skb);
        if (unlikely(!skb))
            goto out;
    }

    if (skb_skip_tc_classify(skb))
        goto skip_classify;

    if (pfmemalloc)
        goto skip_taps;

    list_for_each_entry_rcu(ptype, ptype_all_copy, list) {
        if (pt_prev)
            ret = deliver_skb(skb, pt_prev, orig_dev);
        pt_prev = ptype;
    }

    list_for_each_entry_rcu(ptype, &skb->dev->ptype_all, list) {
        if (pt_prev)
            ret = deliver_skb(skb, pt_prev, orig_dev);
        pt_prev = ptype;
    }

    skip_taps:
#ifdef CONFIG_NET_INGRESS
    if (static_branch_unlikely(&ingress_needed_key)) {
        bool another = false;

        nf_skip_egress(skb, true);
        skb = sch_handle_ingress(skb, &pt_prev, &ret, orig_dev,
                                 &another);
        if (another)
            goto another_round;
        if (!skb)
            goto out;

        nf_skip_egress(skb, false);
        if (nf_ingress(skb, &pt_prev, &ret, orig_dev) < 0)
            goto out;
    }
#endif
    skb_reset_redirect(skb);
    skip_classify:
    if (pfmemalloc && !skb_pfmemalloc_protocol(skb)){
        goto drop;
    }

    if (skb_vlan_tag_present(skb)) {
        if (pt_prev) {
            ret = deliver_skb(skb, pt_prev, orig_dev);
            pt_prev = NULL;
        }
        if (orig_vlan_do_receive(&skb))
            goto another_round;
        else if (unlikely(!skb))
            goto out;
    }
    rx_handler = rcu_dereference(skb->dev->rx_handler);
    if (rx_handler) {
        if (pt_prev) {
            ret = deliver_skb(skb, pt_prev, orig_dev);
            pt_prev = NULL;
        }
        switch (self_defined_br_handle_frame(&skb)) {
            case RX_HANDLER_CONSUMED:
                ret = NET_RX_SUCCESS;
                goto out;
            case RX_HANDLER_ANOTHER:
                goto another_round;
            case RX_HANDLER_EXACT:
                deliver_exact = true;
                break;
            case RX_HANDLER_PASS:
                break;
            default:
                BUG();
        }
    }

    if (unlikely(skb_vlan_tag_present(skb)) && !netdev_uses_dsa(skb->dev)) {
        check_vlan_id:
        if (skb_vlan_tag_get_id(skb)) {
            /* Vlan id is non 0 and vlan_do_receive() above couldn't
             * find vlan device.
             */
            skb->pkt_type = PACKET_OTHERHOST;
        } else if (eth_type_vlan(skb->protocol)) {
            /* Outer header is 802.1P with vlan 0, inner header is
             * 802.1Q or 802.1AD and vlan_do_receive() above could
             * not find vlan dev for vlan id 0.
             */
            __vlan_hwaccel_clear_tag(skb);
            skb = skb_vlan_untag(skb);
            if (unlikely(!skb))
                goto out;
            if (orig_vlan_do_receive(&skb))
                /* After stripping off 802.1P header with vlan 0
                 * vlan dev is found for inner header.
                 */
                goto another_round;
            else if (unlikely(!skb))
                goto out;
            else
                /* We have stripped outer 802.1P vlan 0 header.
                 * But could not find vlan dev.
                 * check again for vlan id to set OTHERHOST.
                 */
                goto check_vlan_id;
        }
        /* Note: we might in the future use prio bits
         * and set skb->priority like in vlan_do_receive()
         * For the time being, just ignore Priority Code Point
         */
        __vlan_hwaccel_clear_tag(skb);
    }

    type = skb->protocol;

    /* deliver only exact match when indicated */
    if (likely(!deliver_exact)) {
        deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type,
                               &ptype_base_copy[ntohs(type) &
                                                PTYPE_HASH_MASK]);
    }

    deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type,
                           &orig_dev->ptype_specific);

    if (unlikely(skb->dev != orig_dev)) {
        deliver_ptype_list_skb(skb, &pt_prev, orig_dev, type,
                               &skb->dev->ptype_specific);
    }

    if (pt_prev) {
        if (unlikely(skb_orphan_frags_rx(skb, GFP_ATOMIC)))
            goto drop;
        *ppt_prev = pt_prev;
    } else {
        drop:
        if (!deliver_exact)
            dev_core_stats_rx_dropped_inc(skb->dev);
        else
            dev_core_stats_rx_nohandler_inc(skb->dev);
        kfree_skb_reason(skb, SKB_DROP_REASON_UNHANDLED_PROTO);
        /* Jamal, now you will not able to escape explaining
         * me how you were going to use this. :-)
         */
        ret = NET_RX_DROP;
    }

    out:
    /* The invariant here is that if *ppt_prev is not NULL
     * then skb should also be non-NULL.
     *
     * Apparently *ppt_prev assignment above holds this invariant due to
     * skb dereferencing near it.
     */
    *pskb = skb;
    return ret;
}

int self_defined__netif_receive_skb_one_core(struct sk_buff *skb, bool pfmemalloc) {
    struct net_device *orig_dev = skb->dev;
    struct packet_type *pt_prev = NULL;
    int ret;

    ret = self_defined__netif_receive_skb_core(&skb, pfmemalloc, &pt_prev);
    if (pt_prev)
        if (pt_prev->func == orig_ip_rcv) {
            ret = lir_rcv(skb, skb->dev, pt_prev, orig_dev);
        } else {
            ret = pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
        }
    // 原来的代码
    //        ret = INDIRECT_CALL_INET(pt_prev->func, orig_ipv6_rcv, orig_ip_rcv, skb,
    //                                 skb->dev, pt_prev, orig_dev);
    return ret;
}

