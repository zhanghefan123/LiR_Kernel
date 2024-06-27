//
// Created by zhf on 24-4-12.
//
#include "headers/br_private.h"
#include "headers/support_tools.h"
#include "headers/support_ftrace_hook_api.h"
#include "headers/mac_br_handle_frame.h"
#include <uapi/linux/netfilter_bridge.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/nf_queue.h>

DEFINE_STATIC_KEY_FALSE(br_mst_used);
asmlinkage void (*orig_br_handle_ingress_vlan_tunnel)(struct sk_buff *skb, struct net_bridge_port *p, struct net_bridge_vlan_group *vg);
asmlinkage bool (*orig_br_should_learn)(struct net_bridge_port *p, struct sk_buff *skb, u16 *vid);
asmlinkage void (*orig_br_fdb_update)(struct net_bridge *br, struct net_bridge_port *source, const unsigned char *addr, u16 vid, unsigned long flags);
asmlinkage bool (*orig_br_allowed_ingress)(const struct net_bridge *br,struct net_bridge_vlan_group *vg, struct sk_buff *skb,u16 *vid, u8 *state,struct net_bridge_vlan **vlan);
asmlinkage struct net_bridge_fdb_entry *(*orig_br_fdb_find_rcu)(struct net_bridge *br,const unsigned char *addr,__u16 vid);
asmlinkage void (*orig_nbp_switchdev_frame_mark)(const struct net_bridge_port *p,struct sk_buff *skb);
asmlinkage void (*orig_br_do_proxy_suppress_arp)(struct sk_buff *skb, struct net_bridge *br,u16 vid, struct net_bridge_port *p);
asmlinkage struct nd_msg *(*orig_br_is_nd_neigh_msg)(struct sk_buff *skb, struct nd_msg *msg);
asmlinkage void (*orig_br_do_suppress_nd)(struct sk_buff *skb, struct net_bridge *br,u16 vid, struct net_bridge_port *p, struct nd_msg *msg);
asmlinkage bool (*orig_br_allowed_egress)(struct net_bridge_vlan_group *vg, const struct sk_buff *skb);
asmlinkage struct sk_buff *(*orig_br_handle_vlan)(struct net_bridge *br,const struct net_bridge_port *port,struct net_bridge_vlan_group *vg,struct sk_buff *skb);
asmlinkage void (*orig_br_multicast_count)(struct net_bridge *br,const struct net_bridge_port *p,const struct sk_buff *skb, u8 type, u8 dir);
asmlinkage struct net_bridge_mdb_entry *(*orig_br_mdb_get)(struct net_bridge_mcast *brmctx,struct sk_buff *skb, u16 vid);
asmlinkage void (*orig_br_flood)(struct net_bridge *br, struct sk_buff *skb,enum br_pkt_type pkt_type, bool local_rcv, bool local_orig);
asmlinkage void (*orig_br_multicast_flood)(struct net_bridge_mdb_entry *mdst, struct sk_buff *skb,struct net_bridge_mcast *brmctx,bool local_rcv, bool local_orig);
asmlinkage int (*orig_br_multicast_rcv)(struct net_bridge_mcast **brmctx,struct net_bridge_mcast_port **pmctx,struct net_bridge_vlan *vlan,struct sk_buff *skb, u16 vid);

void resolve_br_handle_frame_inner_functions_address(void){
    LOG_WITH_EDGE("start to resolve br_handle_frame_finish inner function address");
    orig_br_handle_ingress_vlan_tunnel = get_function_address("br_handle_ingress_vlan_tunnel");
    LOG_RESOLVED(orig_br_handle_ingress_vlan_tunnel, "br_handle_ingress_vlan_tunnel");
    orig_br_should_learn = get_function_address("br_should_learn");
    LOG_RESOLVED(orig_br_should_learn, "br_should_learn");
    orig_br_fdb_update = get_function_address("br_fdb_update");
    LOG_RESOLVED(orig_br_fdb_update, "br_fdb_update");
    orig_br_allowed_ingress = get_function_address("br_allowed_ingress");
    LOG_RESOLVED(orig_br_allowed_ingress, "br_allowed_ingress");
    orig_br_fdb_find_rcu = get_function_address("br_fdb_find_rcu");
    LOG_RESOLVED(orig_br_fdb_find_rcu, "br_fdb_find_rcu");
    orig_nbp_switchdev_frame_mark = get_function_address("nbp_switchdev_frame_mark");
    LOG_RESOLVED(orig_nbp_switchdev_frame_mark, "nbp_switchdev_frame_mark");
    orig_br_do_proxy_suppress_arp = get_function_address("br_do_proxy_suppress_arp");
    LOG_RESOLVED(orig_br_do_proxy_suppress_arp, "br_do_proxy_suppress_arp");
    orig_br_is_nd_neigh_msg = get_function_address("br_is_nd_neigh_msg");
    LOG_RESOLVED(orig_br_is_nd_neigh_msg, "br_is_nd_neigh_msg");
    orig_br_do_suppress_nd = get_function_address("br_do_suppress_nd");
    LOG_RESOLVED(orig_br_do_suppress_nd, "br_do_suppress_nd");
    orig_br_allowed_egress = get_function_address("br_allowed_egress");
    LOG_RESOLVED(orig_br_allowed_egress, "br_allowed_egress");
    orig_br_handle_vlan = get_function_address("br_handle_vlan");
    LOG_RESOLVED(orig_br_handle_vlan, "br_handle_vlan");
    orig_br_multicast_count = get_function_address("br_multicast_count");
    LOG_RESOLVED(orig_br_multicast_count, "br_multicast_count");
    orig_br_mdb_get = get_function_address("br_mdb_get");
    LOG_RESOLVED(orig_br_mdb_get, "br_mdb_get");
    orig_br_flood = get_function_address("br_flood");
    LOG_RESOLVED(orig_br_flood, "br_flood");
    orig_br_multicast_flood = get_function_address("br_multicast_flood");
    LOG_RESOLVED(orig_br_multicast_flood, "br_multicast_flood");
    orig_br_multicast_rcv = get_function_address("br_multicast_rcv");
    LOG_RESOLVED(orig_br_multicast_rcv, "br_multicast_rcv");
    LOG_RESOLVED(orig_br_handle_ingress_vlan_tunnel, "br_handle_ingress_vlan_tunnel");
}

// ------------------------------- static -------------------------------

static void copy__br_handle_local_finish(struct sk_buff *skb)
{
    struct net_bridge_port *p = br_port_get_rcu(skb->dev);
    u16 vid = 0;

    /* check if vlan is allowed, to avoid spoofing */
    if ((p->flags & BR_LEARNING) &&
        nbp_state_should_learn(p) &&
        !br_opt_get(p->br, BROPT_NO_LL_LEARN) &&
        orig_br_should_learn(p, skb, &vid))
        orig_br_fdb_update(p->br, p, eth_hdr(skb)->h_source, vid, 0);
}

/* note: already called with rcu_read_lock */
static int br_handle_local_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    copy__br_handle_local_finish(skb);

    /* return 1 to signal the okfn() was called so it's ok to use the skb */
    return 1;
}

static int br_process_frame_type(struct net_bridge_port *p,
                                 struct sk_buff *skb)
{
    struct br_frame_type *tmp;

    hlist_for_each_entry_rcu(tmp, &p->br->frame_type_list, list)
            if (unlikely(tmp->type == skb->protocol))
                return tmp->frame_handler(p, skb);

    return 0;
}

static int self_defined_nf_hook_bridge_pre(struct sk_buff *skb, struct sk_buff **pskb)
{
    // LOG_WITH_PREFIX("nf_hook_bridge_pre");
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
    struct nf_hook_entries *e = NULL;
    struct nf_hook_state state;
    unsigned int verdict, i;
    struct net *net;
    int ret;

    net = dev_net(skb->dev);
#ifdef HAVE_JUMP_LABEL
    if (!static_key_false(&nf_hooks_needed[NFPROTO_BRIDGE][NF_BR_PRE_ROUTING]))
		goto frame_finish;
#endif

//    e = rcu_dereference(net->nf.hooks_bridge[NF_BR_PRE_ROUTING]);
    if (!e){
        // LOG_WITH_PREFIX("goto frame finish");
        goto frame_finish;
    }


    nf_hook_state_init(&state, NF_BR_PRE_ROUTING,
                       NFPROTO_BRIDGE, skb->dev, NULL, NULL,
                       net, br_handle_frame_finish);

    for (i = 0; i < e->num_hook_entries; i++) {
        verdict = nf_hook_entry_hookfn(&e->hooks[i], skb, &state);
        switch (verdict & NF_VERDICT_MASK) {
            case NF_ACCEPT:
                if (BR_INPUT_SKB_CB(skb)->br_netfilter_broute) {
                    *pskb = skb;
                    LOG_WITH_PREFIX("RX_HANDLER_PASS");
                    return RX_HANDLER_PASS;
                }
                break;
            case NF_DROP:
                kfree_skb(skb);
                LOG_WITH_PREFIX("NF_DROP");
                return RX_HANDLER_CONSUMED;
            case NF_QUEUE:
                ret = nf_queue(skb, &state, i, verdict);
                if (ret == 1)
                    continue;
                return RX_HANDLER_CONSUMED;
            default: /* STOLEN */
                return RX_HANDLER_CONSUMED;
        }
    }
    frame_finish:
    net = dev_net(skb->dev);
    self_defined_br_handle_frame_finish(net, NULL, skb);
#else
    self_defined_br_handle_frame_finish(dev_net(skb->dev), NULL, skb);
#endif
    return RX_HANDLER_CONSUMED;
}

static int br_netif_receive_skb(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    br_drop_fake_rtable(skb);
    return netif_receive_skb(skb);
}

static int br_pass_frame_up(struct sk_buff *skb)
{
    struct net_device *indev, *brdev = BR_INPUT_SKB_CB(skb)->brdev;
    struct net_bridge *br = netdev_priv(brdev);
    struct net_bridge_vlan_group *vg;

    dev_sw_netstats_rx_add(brdev, skb->len);

    vg = br_vlan_group_rcu(br);

    /* Reset the offload_fwd_mark because there could be a stacked
     * bridge above, and it should not think this bridge it doing
     * that bridge's work forwarding out its ports.
     */
    br_switchdev_frame_unmark(skb);

    /* Bridge is just like any other port.  Make sure the
     * packet is allowed except in promisc mode when someone
     * may be running packet capture.
     */
    if (!(brdev->flags & IFF_PROMISC) &&
        !orig_br_allowed_egress(vg, skb)) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    indev = skb->dev;
    skb->dev = brdev;
    skb = orig_br_handle_vlan(br, NULL, vg, skb);
    if (!skb)
        return NET_RX_DROP;
    /* update the multicast stats if the packet is IGMP/MLD */
    orig_br_multicast_count(br, NULL, skb, br_multicast_igmp_type(skb),
                            BR_MCAST_DIR_TX);

    return NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN,
                   dev_net(indev), NULL, skb, indev, NULL,
                   br_netif_receive_skb);
}


// ------------------------------- static -------------------------------

/**
 *
 * @param pskb
 * @return
 */
rx_handler_result_t self_defined_br_handle_frame(struct sk_buff **pskb){
    struct net_bridge_port *p;
    struct sk_buff *skb = *pskb;
    const unsigned char *dest = eth_hdr(skb)->h_dest;

    if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
        return RX_HANDLER_PASS;

    if (!is_valid_ether_addr(eth_hdr(skb)->h_source)){
        goto drop;
    }


    skb = skb_share_check(skb, GFP_ATOMIC);
    if (!skb){
        return RX_HANDLER_CONSUMED;
    }


    memset(skb->cb, 0, sizeof(struct br_input_skb_cb));

    p = br_port_get_rcu(skb->dev);
    if (p->flags & BR_VLAN_TUNNEL)
        orig_br_handle_ingress_vlan_tunnel(skb, p, nbp_vlan_group_rcu(p));

    if (unlikely(is_link_local_ether_addr(dest))) {
        u16 fwd_mask = p->br->group_fwd_mask_required;

        /*
         * See IEEE 802.1D Table 7-10 Reserved addresses
         *
         * Assignment		 		Value
         * Bridge Group Address		01-80-C2-00-00-00
         * (MAC Control) 802.3		01-80-C2-00-00-01
         * (Link Aggregation) 802.3	01-80-C2-00-00-02
         * 802.1X PAE address		01-80-C2-00-00-03
         *
         * 802.1AB LLDP 		01-80-C2-00-00-0E
         *
         * Others reserved for future standardization
         */
        fwd_mask |= p->group_fwd_mask;
        switch (dest[5]) {
            case 0x00:	/* Bridge Group Address */
                /* If STP is turned off,
                   then must forward to keep loop detection */
                if (p->br->stp_enabled == BR_NO_STP ||
                    fwd_mask & (1u << dest[5]))
                    goto forward;
                *pskb = skb;
                copy__br_handle_local_finish(skb);
                return RX_HANDLER_PASS;

            case 0x01:	/* IEEE MAC (Pause) */
                goto drop;

            case 0x0E:	/* 802.1AB LLDP */
                fwd_mask |= p->br->group_fwd_mask;
                if (fwd_mask & (1u << dest[5]))
                    goto forward;
                *pskb = skb;
                copy__br_handle_local_finish(skb);
                return RX_HANDLER_PASS;

            default:
                /* Allow selective forwarding for most other protocols */
                fwd_mask |= p->br->group_fwd_mask;
                if (fwd_mask & (1u << dest[5]))
                    goto forward;
        }

        /* The else clause should be hit when nf_hook():
         *   - returns < 0 (drop/error)
         *   - returns = 0 (stolen/nf_queue)
         * Thus return 1 from the okfn() to signal the skb is ok to pass
         */
        if (NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN,
                    dev_net(skb->dev), NULL, skb, skb->dev, NULL,
                    br_handle_local_finish) == 1) {
            return RX_HANDLER_PASS;
        } else {
            return RX_HANDLER_CONSUMED;
        }
    }

    if (unlikely(br_process_frame_type(p, skb))){
        return RX_HANDLER_PASS;
    }


    forward:
    if (br_mst_is_enabled(p->br))
        goto defer_stp_filtering;

    switch (p->state) {
        case BR_STATE_FORWARDING:
        case BR_STATE_LEARNING:
        defer_stp_filtering:
            if (ether_addr_equal(p->br->dev->dev_addr, dest))
                skb->pkt_type = PACKET_HOST;

            return self_defined_nf_hook_bridge_pre(skb, pskb);
        default:
        drop:
            kfree_skb(skb);
    }
    return RX_HANDLER_CONSUMED;
}

/* note: already called with rcu_read_lock */
int self_defined_br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct net_bridge_port *p = br_port_get_rcu(skb->dev);
    enum br_pkt_type pkt_type = BR_PKT_UNICAST;
    struct net_bridge_fdb_entry *dst = NULL;
    struct net_bridge_mcast_port *pmctx;
    struct net_bridge_mdb_entry *mdst;
    bool local_rcv, mcast_hit = false;
    struct net_bridge_mcast *brmctx;
    struct net_bridge_vlan *vlan;
    struct net_bridge *br;
    u16 vid = 0;
    u8 state;

    if(is_broadcast_ether_addr(eth_hdr(skb)->h_dest))
    {
        // LOG_WITH_PREFIX("received packet with broadcast address");
    }
    // LOG_WITH_PREFIX("received packet");

    if (!p)
        goto drop;

    br = p->br;

    if (br_mst_is_enabled(br)) {
        state = BR_STATE_FORWARDING;
    } else {
        if (p->state == BR_STATE_DISABLED)
            goto drop;

        state = p->state;
    }

    brmctx = &p->br->multicast_ctx;
    pmctx = &p->multicast_ctx;
    if (!orig_br_allowed_ingress(p->br, nbp_vlan_group_rcu(p), skb, &vid,
                                 &state, &vlan))
        goto out;

    if (p->flags & BR_PORT_LOCKED) {
        struct net_bridge_fdb_entry *fdb_src =
                orig_br_fdb_find_rcu(br, eth_hdr(skb)->h_source, vid);

        if (!fdb_src || READ_ONCE(fdb_src->dst) != p ||
            test_bit(BR_FDB_LOCAL, &fdb_src->flags))
            goto drop;
    }

    orig_nbp_switchdev_frame_mark(p, skb);

    /* insert into forwarding database after filtering to avoid spoofing */
    if (p->flags & BR_LEARNING)
        orig_br_fdb_update(br, p, eth_hdr(skb)->h_source, vid, 0);

    local_rcv = !!(br->dev->flags & IFF_PROMISC);
    if (is_multicast_ether_addr(eth_hdr(skb)->h_dest)) {
        /* by definition the broadcast is also a multicast address */
        if (is_broadcast_ether_addr(eth_hdr(skb)->h_dest)) {
            pkt_type = BR_PKT_BROADCAST;
            if((eth_hdr(skb)->h_proto != htons(ETH_P_ARP)) && (is_broadcast_ether_addr(eth_hdr(skb)->h_dest))) {
                // printk(KERN_EMERG "don't pass to the upper layer\n");
                local_rcv = false;
            } else {
                local_rcv = true;
            }
        } else {
            pkt_type = BR_PKT_MULTICAST;
            if (orig_br_multicast_rcv(&brmctx, &pmctx, vlan, skb, vid))
                goto drop;
        }
    }

    if (state == BR_STATE_LEARNING)
        goto drop;

    BR_INPUT_SKB_CB(skb)->brdev = br->dev;
    BR_INPUT_SKB_CB(skb)->src_port_isolated = !!(p->flags & BR_ISOLATED);

    if (IS_ENABLED(CONFIG_INET) &&
        (skb->protocol == htons(ETH_P_ARP) ||
         skb->protocol == htons(ETH_P_RARP))) {
        orig_br_do_proxy_suppress_arp(skb, br, vid, p);
    } else if (IS_ENABLED(CONFIG_IPV6) &&
               skb->protocol == htons(ETH_P_IPV6) &&
               br_opt_get(br, BROPT_NEIGH_SUPPRESS_ENABLED) &&
               pskb_may_pull(skb, sizeof(struct ipv6hdr) +
                                  sizeof(struct nd_msg)) &&
               ipv6_hdr(skb)->nexthdr == IPPROTO_ICMPV6) {
        struct nd_msg *msg, _msg;

        msg = orig_br_is_nd_neigh_msg(skb, &_msg);
        if (msg)
            orig_br_do_suppress_nd(skb, br, vid, p, msg);
    }

    switch (pkt_type) {
        case BR_PKT_MULTICAST:
            mdst = orig_br_mdb_get(brmctx, skb, vid);
            if ((mdst || BR_INPUT_SKB_CB_MROUTERS_ONLY(skb)) &&
                br_multicast_querier_exists(brmctx, eth_hdr(skb), mdst)) {
                if ((mdst && mdst->host_joined) ||
                    br_multicast_is_router(brmctx, skb)) {
                    local_rcv = true;
                    br->dev->stats.multicast++;
                }
                mcast_hit = true;
            } else {
                local_rcv = true;
                br->dev->stats.multicast++;
            }
            break;
        case BR_PKT_UNICAST:
            dst = orig_br_fdb_find_rcu(br, eth_hdr(skb)->h_dest, vid);
            break;
        default:
            break;
    }

    if (dst) {
        unsigned long now = jiffies;

        if (test_bit(BR_FDB_LOCAL, &dst->flags)){
            if((eth_hdr(skb)->h_proto != htons(ETH_P_ARP)) && (is_broadcast_ether_addr(eth_hdr(skb)->h_dest))){
                // printk(KERN_EMERG "don't pass to the upper layer\n");
            } else {
                return br_pass_frame_up(skb);
            }
        }
        if (now != dst->used)
            dst->used = now;
        br_forward(dst->dst, skb, local_rcv, false);
    } else {
        if (!mcast_hit)
            orig_br_flood(br, skb, pkt_type, local_rcv, false);
        else
            orig_br_multicast_flood(mdst, skb, brmctx, local_rcv, false);
    }
    // if the packet is arp we need to pass
    if((eth_hdr(skb)->h_proto != htons(ETH_P_ARP)) && (is_broadcast_ether_addr(eth_hdr(skb)->h_dest))){
        // printk(KERN_EMERG "don't pass to the upper layer\n");
        local_rcv = false;
    }
    // printk(KERN_EMERG "received packet\n");
    if (local_rcv)
        return br_pass_frame_up(skb);

    out:
    return 0;
    drop:
    kfree_skb(skb);
    goto out;
}