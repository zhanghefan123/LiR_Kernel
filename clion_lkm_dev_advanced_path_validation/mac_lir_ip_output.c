//
// Created by zhf on 24-4-12.
//
#include <net/icmp.h>
#include <linux/bpf-cgroup.h>
#include "headers/support_tools.h"
#include "headers/mac_lir_ip_output.h"
#include "headers/support_ftrace_hook_api.h"
#include "headers/network_lir_header.h"
#include "headers/network_lir_send_check.h"


// ------------------------ static ------------------------
static void lir_options_fragment(struct sk_buff *skb)
{
    unsigned char *optptr = skb_network_header(skb) + sizeof(struct lirhdr);
    struct ip_options *opt = &(IPCB(skb)->opt);
    int  l = opt->optlen;
    int  optlen;

    while (l > 0) {
        switch (*optptr) {
            case IPOPT_END:
                return;
            case IPOPT_NOOP:
                l--;
                optptr++;
                continue;
        }
        optlen = optptr[1];
        if (optlen < 2 || optlen > l)
            return;
        if (!IPOPT_COPIED(*optptr))
            memset(optptr, IPOPT_NOOP, optlen);
        l -= optlen;
        optptr += optlen;
    }
    opt->ts = 0;
    opt->rr = 0;
    opt->rr_needaddr = 0;
    opt->ts_needaddr = 0;
    opt->ts_needtime = 0;
}


static void lir_frag_ipcb(struct sk_buff *from, struct sk_buff *to,
                          bool first_frag)
{
    /* Copy the flags to each fragment. */
    IPCB(to)->flags = IPCB(from)->flags;

    /* ANK: dirty, but effective trick. Upgrade options only if
     * the segment to be fragmented was THE FIRST (otherwise,
     * options are already fixed) and make it ONCE
     * on the initial skb, so that all the following fragments
     * will inherit fixed options.
     */
    if (first_frag)
        lir_options_fragment(from);
}


static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
    to->pkt_type = from->pkt_type;
    to->priority = from->priority;
    to->protocol = from->protocol;
    to->skb_iif = from->skb_iif;
    skb_dst_drop(to);
    skb_dst_copy(to, from);
    to->dev = from->dev;
    to->mark = from->mark;

    skb_copy_hash(to, from);

#ifdef CONFIG_NET_SCHED
    to->tc_index = from->tc_index;
#endif
    nf_copy(to, from);
    skb_ext_copy(to, from);
#if IS_ENABLED(CONFIG_IP_VS)
    to->ipvs_property = from->ipvs_property;
#endif
    skb_copy_secmark(to, from);
}


static struct sk_buff *lir_frag_next(struct sk_buff *skb, struct ip_frag_state *state)
{
    unsigned int len = state->left;
    struct sk_buff *skb2;
    struct lirhdr *lir_header;

    /* IF: it doesn't fit, use 'mtu' - the data space left */
    if (len > state->mtu)
        len = state->mtu;
    /* IF: we are not sending up to and including the packet end
       then align the next start on an eight byte boundary */
    if (len < state->left)	{
        len &= ~7;
    }

    /* Allocate buffer */
    skb2 = alloc_skb(len + state->hlen + state->ll_rs, GFP_ATOMIC);
    if (!skb2)
        return ERR_PTR(-ENOMEM);

    /*
     *	Set up data on packet
     */

    ip_copy_metadata(skb2, skb);
    skb_reserve(skb2, state->ll_rs);
    skb_put(skb2, len + state->hlen);
    skb_reset_network_header(skb2);
    skb2->transport_header = skb2->network_header + state->hlen;

    /*
     *	Charge the memory for the fragment to any owner
     *	it might possess
     */

    if (skb->sk)
        skb_set_owner_w(skb2, skb->sk);

    /*
     *	Copy the packet header into the new buffer.
     */

    skb_copy_from_linear_data(skb, skb_network_header(skb2), state->hlen);

    /*
     *	Copy a block of the IP datagram.
     */
    if (skb_copy_bits(skb, state->ptr, skb_transport_header(skb2), len))
        BUG();
    state->left -= len;

    /*
     *	Fill in the new header fields.
     */
    lir_header = lir_hdr(skb2);
    lir_header->frag_off = htons((state->offset >> 3));
    if (state->DF)
        lir_header->frag_off |= htons(IP_DF);

    /*
     *	Added AC : If we are fragmenting a fragment that's not the
     *		   last fragment then keep MF on each bit
     */
    if (state->left > 0 || state->not_last_frag)
        lir_header->frag_off |= htons(IP_MF);
    state->ptr += len;
    state->offset += len;

    lir_header->total_len = htons(len + state->hlen);

    lir_send_check(lir_header);

    return skb2;
}

static void lir_frag_init(struct sk_buff *skb, unsigned int hlen,
                         unsigned int ll_rs, unsigned int mtu, bool DF,
                         struct ip_frag_state *state)
{
    struct lirhdr *lir_header = lir_hdr(skb);

    state->DF = DF;
    state->hlen = hlen;
    state->ll_rs = ll_rs;
    state->mtu = mtu;

    state->left = skb->len - hlen;	/* Space per frame */
    state->ptr = hlen;		/* Where to start from */

    state->offset = (ntohs(lir_header->frag_off) & IP_OFFSET) << 3;
    state->not_last_frag = lir_header->frag_off & htons(IP_MF);
}

static inline struct sk_buff *lir_fraglist_next(struct lir_fraglist_iter *iter)
{
    struct sk_buff *skb = iter->frag;

    iter->frag = skb->next;
    skb_mark_not_on_list(skb);

    return skb;
}

static inline bool lir_is_fragment(const struct lirhdr *lir_header)
{
    return (lir_header->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}

static void lir_fraglist_init(struct sk_buff *skb, struct lirhdr *lir_header,
                             unsigned int hlen, struct lir_fraglist_iter *iter)
{
    unsigned int first_len = skb_pagelen(skb);

    iter->frag = skb_shinfo(skb)->frag_list;
    skb_frag_list_init(skb);

    iter->offset = 0;
    iter->lir_header = lir_header;
    iter->hlen = hlen;

    skb->data_len = first_len - skb_headlen(skb);
    skb->len = first_len;
    lir_header->total_len = htons(first_len);
    lir_header->frag_off = htons(IP_MF);

    lir_send_check(lir_header);
}

static void lir_fraglist_prepare(struct sk_buff *skb, struct lir_fraglist_iter *iter)
{
    unsigned int hlen = iter->hlen;
    struct lirhdr *lir_header = iter->lir_header;
    struct sk_buff *frag;

    frag = iter->frag;
    frag->ip_summed = CHECKSUM_NONE;
    skb_reset_transport_header(frag);
    __skb_push(frag, hlen);
    skb_reset_network_header(frag);
    memcpy(skb_network_header(frag), lir_header, hlen);
    iter->lir_header = lir_hdr(frag);
    lir_header = iter->lir_header;
    lir_header->total_len = htons(frag->len);
    ip_copy_metadata(frag, skb);
    iter->offset += skb->len - hlen;
    lir_header->frag_off = htons(iter->offset >> 3);
    if (frag->next)
        lir_header->frag_off |= htons(IP_MF);
    /* Ready, complete checksum */
    lir_send_check(lir_header);
}


// ------------------------ static ------------------------

struct neighbour *lir_ip_neigh_for_gw(struct net_device *output_dev) {
    struct neighbour *neigh;

    // zhf add code
    // ----------------- destination address set to broadcast ---------------
    // printk(KERN_EMERG "[zeusnet's kernel info]:output interface name %s\n", output_dev->name);
    // ----------------- destination address set to broadcast ---------------

    // only ipv4 available
    neigh = ip_neigh_gw4(output_dev, INADDR_BROADCAST);
    return neigh;
}

int lir_ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_dev) {
    int ret;

    ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
    switch (ret) {
        case NET_XMIT_SUCCESS:
            return lir__ip_finish_output(net, sk, skb, output_dev);
        case NET_XMIT_CN:
            return lir__ip_finish_output(net, sk, skb, output_dev) ?: ret;
        default:
            kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
            return ret;
    }
}

int lir_ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_dev) {
    struct net_device *dev = output_dev;
    unsigned int hh_len = LL_RESERVED_SPACE(dev);
    struct neighbour *neigh;
    bool is_v6gw = false;

    if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
        skb = skb_expand_head(skb, hh_len);
        if (!skb)
            return -ENOMEM;
    }

    rcu_read_lock_bh();
    neigh = lir_ip_neigh_for_gw(output_dev);
    if (!IS_ERR(neigh)) {
        int res;

        sock_confirm_neigh(skb, neigh);
        /* if crossing protocols, can not use the cached header */
        res = neigh_output(neigh, skb, is_v6gw);
        rcu_read_unlock_bh();
        return res;
    }
    rcu_read_unlock_bh();

    net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
                        __func__);
    kfree_skb_reason(skb, SKB_DROP_REASON_NEIGH_CREATEFAIL);
    return -EINVAL;
}

int lir__ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_dev) {
    unsigned int mtu;

    mtu = output_dev->mtu;

    if (skb->len > mtu || IPCB(skb)->frag_max_size)
        return lir_fragment(net, sk, skb, mtu, output_dev,lir_ip_finish_output2);

    return lir_ip_finish_output2(net, sk, skb, output_dev);
}


int lir_ip_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_dev) {
    IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);

    skb->dev = output_dev;
    skb->protocol = htons(ETH_P_IP);

    return lir_ip_finish_output(net, sk, skb, output_dev);
}

int lir_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
                 unsigned int mtu, struct net_device *output_dev,
                 int (*output)(struct net *, struct sock *, struct sk_buff *, struct net_device *output_dev)) {
    // 拿到数据包的 ip 头
    struct lirhdr *lir_header = lir_hdr(skb);

    // 和 IP_DF 按位与为0, 说明 IP_DF 位没有被设置，说明是允许分片的
    if ((lir_header->frag_off & htons(IP_DF)) == 0){
        // 如果是的情况，直接调用 lir_do_fragment 就可以了
        return lir_do_fragment(net, sk, skb, output_dev, output);
    }


    // -------------------- 不太可能出现的情况 --------------------
    // 如果 skb->ignore_df 为 0 代表不允许分片, 数据包还是进来了，那么将直接进行丢包
    if (unlikely(!skb->ignore_df ||
                 (IPCB(skb)->frag_max_size &&
                  IPCB(skb)->frag_max_size > mtu))) {
        IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
        icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
                  htonl(mtu));
        kfree_skb(skb);
        return -EMSGSIZE;
    }
    // -------------------- 不太可能出现的情况 --------------------
    return lir_do_fragment(net, sk, skb, output_dev, output);
}

int lir_do_fragment(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_dev,
                    int (*output)(struct net *, struct sock *, struct sk_buff*, struct net_device* output_dev)){
    struct lirhdr *lir_header;
    struct sk_buff *skb2;
    bool mono_delivery_time = skb->mono_delivery_time;
    unsigned int mtu, hlen, ll_rs;
    struct lir_fraglist_iter iter;
    ktime_t tstamp = skb->tstamp;
    struct ip_frag_state state;
    int err = 0;


    /* for offloaded checksums cleanup checksum before fragmentation */
    if (skb->ip_summed == CHECKSUM_PARTIAL &&
        (err = skb_checksum_help(skb)))
        goto fail;

    /*
     *	Point into the IP datagram header.
     */

    lir_header = lir_hdr(skb);

    // zhf add code
    mtu = output_dev->mtu;
    // ------------------------------ 原来的代码 ------------------------------
    //    mtu = ip_skb_dst_mtu(sk, skb);
    if (IPCB(skb)->frag_max_size && IPCB(skb)->frag_max_size < mtu)
        mtu = IPCB(skb)->frag_max_size;
    // ------------------------------ 原来的代码 -----------------------------
    // hlen = iph->ihl * 4;
    hlen = ntohs(lir_header->header_len);
    mtu = mtu - hlen;	/* Size of data space 数据部分的长度 = mtu - 头部的长度*/
    IPCB(skb)->flags |= IPSKB_FRAG_COMPLETE;
    ll_rs = LL_RESERVED_SPACE(output_dev); // 预计链路曾需要预先留下的空间


    /* When frag_list is given, use it. First, check its validity:
     * some transformers could create wrong frag_list or break existing
     * one, it is not prohibited. In this case fall back to copying.
     *
     * LATER: this step can be merged to real generation of fragments,
     * we can switch to copy when see the first bad fragment.
     */
    if (skb_has_frag_list(skb)) {
        struct sk_buff *frag, *frag2;
        unsigned int first_len = skb_pagelen(skb);

        if (first_len - hlen > mtu ||
            ((first_len - hlen) & 7) ||
            lir_is_fragment(lir_header) ||
            skb_cloned(skb) ||
            skb_headroom(skb) < ll_rs)
            goto slow_path;

        skb_walk_frags(skb, frag) {
            /* Correct geometry. */
            if (frag->len > mtu ||
                ((frag->len & 7) && frag->next) ||
                skb_headroom(frag) < hlen + ll_rs)
                goto slow_path_clean;

            /* Partially cloned skb? */
            if (skb_shared(frag))
                goto slow_path_clean;

            BUG_ON(frag->sk);
            if (skb->sk) {
                frag->sk = skb->sk;
                frag->destructor = sock_wfree;
            }
            skb->truesize -= frag->truesize;
        }

        /* Everything is OK. Generate! */
        lir_fraglist_init(skb, lir_header, hlen, &iter);

        for (;;) {
            /* Prepare header of the next frame,
             * before previous one went down. */
            if (iter.frag) {
                bool first_frag = (iter.offset == 0);

                IPCB(iter.frag)->flags = IPCB(skb)->flags;
                lir_fraglist_prepare(skb, &iter);
                if (first_frag && IPCB(skb)->opt.optlen) {
                    /* ipcb->opt is not populated for frags
                     * coming from __ip_make_skb(),
                     * ip_options_fragment() needs optlen
                     */
                    IPCB(iter.frag)->opt.optlen =
                            IPCB(skb)->opt.optlen;
                    lir_options_fragment(iter.frag);
                    lir_send_check(iter.lir_header);
                }
            }

            skb_set_delivery_time(skb, tstamp, mono_delivery_time);
            err = output(net, sk, skb, output_dev);

            if (!err)
                IP_INC_STATS(net, IPSTATS_MIB_FRAGCREATES);
            if (err || !iter.frag)
                break;

            skb = lir_fraglist_next(&iter);
        }

        if (err == 0) {
            IP_INC_STATS(net, IPSTATS_MIB_FRAGOKS);
            return 0;
        }

        kfree_skb_list(iter.frag);

        IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
        return err;

        slow_path_clean:
        skb_walk_frags(skb, frag2) {
            if (frag2 == frag)
                break;
            frag2->sk = NULL;
            frag2->destructor = NULL;
            skb->truesize += frag2->truesize;
        }
    }

    slow_path:
    /*
     *	Fragment the datagram.
     */

    lir_frag_init(skb, hlen, ll_rs, mtu, IPCB(skb)->flags & IPSKB_FRAG_PMTU,
                 &state);

    /*
     *	Keep copying data until we run out.
     */

    while (state.left > 0) {
        bool first_frag = (state.offset == 0);

        skb2 = lir_frag_next(skb, &state);
        if (IS_ERR(skb2)) {
            err = PTR_ERR(skb2);
            goto fail;
        }
        lir_frag_ipcb(skb, skb2, first_frag);

        /*
         *	Put this fragment into the sending queue.
         */
        skb_set_delivery_time(skb2, tstamp, mono_delivery_time);
        err = output(net, sk, skb2, output_dev);
        if (err)
            goto fail;

        IP_INC_STATS(net, IPSTATS_MIB_FRAGCREATES);
    }
    consume_skb(skb);
    IP_INC_STATS(net, IPSTATS_MIB_FRAGOKS);
    return err;

    fail:
    kfree_skb(skb);
    IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
    return err;
}