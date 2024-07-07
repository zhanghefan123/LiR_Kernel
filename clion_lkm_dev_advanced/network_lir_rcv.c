//
// Created by zhf on 24-4-13.
//
#include <net/protocol.h>
#include <net/xfrm.h>
#include <net/icmp.h>
#include <asm-generic/rwonce.h>
#include "headers/support_tools.h"
#include "headers/lir_data_structure.h"
#include "headers/network_lir_rcv.h"
#include "headers/network_lir_send_check.h"
#include "headers/mac_lir_ip_output.h"
#include "headers/transport_lir_udp_rcv.h"
#include "headers/network_ip_rcv.h"
#include "headers/lir_routing_table_structure.h"

asmlinkage int (*orig_tcp_v4_rcv)(struct sk_buff *skb);
extern asmlinkage int (*orig_ip_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

void resolve_network_lir_rcv_inner_functions_address(void){
    LOG_WITH_EDGE("start to resolve lir_rcv inner functions address");
    orig_tcp_v4_rcv = get_function_address("tcp_v4_rcv");
    LOG_RESOLVED(orig_tcp_v4_rcv, "tcp_v4_rcv");
    LOG_WITH_EDGE("end to resolve lir_rcv inner functions address");
}

// ----------------------------- static -----------------------------
struct ipq {
    struct inet_frag_queue q;

    u8		ecn; /* RFC3168 support */
    u16		max_df_size; /* largest frag with DF set seen */
    int             iif;
    unsigned int    rid;
    struct inet_peer *peer;
};

static struct ipq *lir_find(struct net *net, struct lirhdr *lir_header,
                           u32 user, int vif)
{
    struct frag_v4_compare_key key = {
            .saddr = lir_header->source,
            .daddr = lir_header->destination,
            .user = user,
            .vif = vif,
            .id = lir_header->id,
            .protocol = lir_header->protocol,
    };
    struct inet_frag_queue *q;

    q = inet_frag_find(net->ipv4.fqdir, &key);
    if (!q)
        return NULL;

    return container_of(q, struct ipq, q);
}

static int lir_frag_too_far(struct ipq *qp)
{
    struct inet_peer *peer = qp->peer;
    unsigned int max = qp->q.fqdir->max_dist;
    unsigned int start, end;

    int rc;

    if (!peer || !max)
        return 0;

    start = qp->rid;
    end = atomic_inc_return(&peer->rid);
    qp->rid = end;

    rc = qp->q.fragments_tail && (end - start) > max;

    if (rc)
        __IP_INC_STATS(qp->q.fqdir->net, IPSTATS_MIB_REASMFAILS);

    return rc;
}

static int lir_frag_reinit(struct ipq *qp)
{
    unsigned int sum_truesize = 0;

    if (!mod_timer(&qp->q.timer, jiffies + qp->q.fqdir->timeout)) {
        refcount_inc(&qp->q.refcnt);
        return -ETIMEDOUT;
    }

    sum_truesize = inet_frag_rbtree_purge(&qp->q.rb_fragments);
    sub_frag_mem_limit(qp->q.fqdir, sum_truesize);

    qp->q.flags = 0;
    qp->q.len = 0;
    qp->q.meat = 0;
    qp->q.rb_fragments = RB_ROOT;
    qp->q.fragments_tail = NULL;
    qp->q.last_run_head = NULL;
    qp->iif = 0;
    qp->ecn = 0;

    return 0;
}

static void ipq_kill(struct ipq *ipq)
{
    inet_frag_kill(&ipq->q);
}

static void ipq_put(struct ipq *ipq)
{
    inet_frag_put(&ipq->q);
}

static bool ip_frag_coalesce_ok(const struct ipq *qp)
{
    return qp->q.key.v4.user == IP_DEFRAG_LOCAL_DELIVER;
}

static int lir_frag_reasm(struct ipq *qp, struct sk_buff *skb,
                         struct sk_buff *prev_tail, struct net_device *dev){
    struct net *net = qp->q.fqdir->net;
    struct lirhdr *lir_header;
    void *reasm_data;
    int len, err;
    u8 ecn;

    ipq_kill(qp);

    ecn = ip_frag_ecn_table[qp->ecn];
    if (unlikely(ecn == 0xff)) {
        err = -EINVAL;
        goto out_fail;
    }

    /* Make the one we just received the head. */
    reasm_data = inet_frag_reasm_prepare(&qp->q, skb, prev_tail);
    if (!reasm_data)
        goto out_nomem;

    len = ntohs(lir_hdr(skb)->header_len) + qp->q.len;
    err = -E2BIG;
    if (len > 65535)
        goto out_oversize;

    inet_frag_reasm_finish(&qp->q, skb, reasm_data,
                           ip_frag_coalesce_ok(qp));

    skb->dev = dev;
    IPCB(skb)->frag_max_size = max(qp->max_df_size, qp->q.max_size);

    lir_header = lir_hdr(skb);
    lir_header->total_len = htons(len);

    /* When we set IP_DF on a refragmented skb we must also force a
     * call to ip_fragment to avoid forwarding a DF-skb of size s while
     * original sender only sent fragments of size f (where f < s).
     *
     * We only set DF/IPSKB_FRAG_PMTU if such DF fragment was the largest
     * frag seen to avoid sending tiny DF-fragments in case skb was built
     * from one very small df-fragment and one large non-df frag.
     */
    if (qp->max_df_size == qp->q.max_size) {
        IPCB(skb)->flags |= IPSKB_FRAG_PMTU;
        lir_header->frag_off = htons(IP_DF);
    } else {
        lir_header->frag_off = 0;
    }

    lir_send_check(lir_header);

    __IP_INC_STATS(net, IPSTATS_MIB_REASMOKS);
    qp->q.rb_fragments = RB_ROOT;
    qp->q.fragments_tail = NULL;
    qp->q.last_run_head = NULL;
    return 0;

    out_nomem:
    net_dbg_ratelimited("queue_glue: no memory for gluing queue %p\n", qp);
    err = -ENOMEM;
    goto out_fail;
    out_oversize:
    net_info_ratelimited("Oversized IP packet from %pI4\n", &qp->q.key.v4.saddr);
    out_fail:
    __IP_INC_STATS(net, IPSTATS_MIB_REASMFAILS);
    return err;
}

static int lir_frag_queue(struct ipq *qp, struct sk_buff *skb)
{
    struct net *net = qp->q.fqdir->net;
    int ihl, end, flags, offset;
    struct sk_buff *prev_tail;
    struct net_device *dev;
    unsigned int fragsize;
    int err = -ENOENT;
    u8 ecn;

    if (qp->q.flags & INET_FRAG_COMPLETE)
        goto err;

    if (!(IPCB(skb)->flags & IPSKB_FRAG_COMPLETE) &&
        unlikely(lir_frag_too_far(qp)) &&
        unlikely(err = lir_frag_reinit(qp))) {
        ipq_kill(qp);
        goto err;
    }

    offset = ntohs(lir_hdr(skb)->frag_off);
    flags = offset & ~IP_OFFSET;
    offset &= IP_OFFSET;
    offset <<= 3;		/* offset is in 8-byte chunks */
    ihl = ntohs(lir_hdr(skb)->header_len);
    // ihl = ip_hdrlen(skb);

    /* Determine the position of this fragment. */
    end = offset + skb->len - skb_network_offset(skb) - ihl;
    err = -EINVAL;

    /* Is this the final fragment? */
    if ((flags & IP_MF) == 0) {
        /* If we already have some bits beyond end
         * or have different end, the segment is corrupted.
         */
        if (end < qp->q.len ||
            ((qp->q.flags & INET_FRAG_LAST_IN) && end != qp->q.len))
            goto discard_qp;
        qp->q.flags |= INET_FRAG_LAST_IN;
        qp->q.len = end;
    } else {
        if (end&7) {
            end &= ~7;
            if (skb->ip_summed != CHECKSUM_UNNECESSARY)
                skb->ip_summed = CHECKSUM_NONE;
        }
        if (end > qp->q.len) {
            /* Some bits beyond end -> corruption. */
            if (qp->q.flags & INET_FRAG_LAST_IN)
                goto discard_qp;
            qp->q.len = end;
        }
    }
    if (end == offset)
        goto discard_qp;

    err = -ENOMEM;
    if (!pskb_pull(skb, skb_network_offset(skb) + ihl))
        goto discard_qp;

    err = pskb_trim_rcsum(skb, end - offset);
    if (err)
        goto discard_qp;

    /* Note : skb->rbnode and skb->dev share the same location. */
    dev = skb->dev;
    /* Makes sure compiler wont do silly aliasing games */
    barrier();

    prev_tail = qp->q.fragments_tail;
    err = inet_frag_queue_insert(&qp->q, skb, offset, end);
    if (err)
        goto insert_error;

    if (dev)
        qp->iif = dev->ifindex;

    qp->q.stamp = skb->tstamp;
    qp->q.mono_delivery_time = skb->mono_delivery_time;
    qp->q.meat += skb->len;
    qp->ecn |= ecn;
    add_frag_mem_limit(qp->q.fqdir, skb->truesize);
    if (offset == 0)
        qp->q.flags |= INET_FRAG_FIRST_IN;

    fragsize = skb->len + ihl;

    if (fragsize > qp->q.max_size)
        qp->q.max_size = fragsize;

    if (lir_hdr(skb)->frag_off & htons(IP_DF) &&
        fragsize > qp->max_df_size)
        qp->max_df_size = fragsize;

    if (qp->q.flags == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
        qp->q.meat == qp->q.len) {
        unsigned long orefdst = skb->_skb_refdst;

        skb->_skb_refdst = 0UL;
        err = lir_frag_reasm(qp, skb, prev_tail, dev);
        skb->_skb_refdst = orefdst;
        if (err)
            inet_frag_kill(&qp->q);
        return err;
    }

    skb_dst_drop(skb);
    return -EINPROGRESS;

    insert_error:
    if (err == IPFRAG_DUP) {
        kfree_skb(skb);
        return -EINVAL;
    }
    err = -EINVAL;
    __IP_INC_STATS(net, IPSTATS_MIB_REASM_OVERLAPS);
    discard_qp:
    inet_frag_kill(&qp->q);
    __IP_INC_STATS(net, IPSTATS_MIB_REASMFAILS);
    err:
    kfree_skb(skb);
    return err;
}


// ----------------------------- static -----------------------------

int lir_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){
    u64 start = ktime_get_real_ns();
    int result;
    if(TEST_IF_LIR_PACKET(skb)){
        struct net* net = dev_net(dev);  // 通过输入接口获取网络命名空间
        skb = lir_rcv_core(skb, net);
        if (skb == NULL){
            return NET_RX_DROP;
        }
        result = lir_rcv_finish(net, skb, start);
        return result;
    } else {
        result = self_defined_ip_rcv(skb, dev, pt, orig_dev, start);
        return result;
    }
}

/**
 * corresponding to ip_rcv_core
 * @return
 */
struct sk_buff* lir_rcv_core(struct sk_buff* skb, struct net* net){
    struct lirhdr* lir_header = lir_hdr(skb);
    int drop_reason;
    u32 len;
    __u16 header_length = ntohs(lir_header->header_len);
    skb->pkt_type = PACKET_HOST; // modify the packet type set in mac layer
    skb = skb_share_check(skb, GFP_ATOMIC); // share check
    if (!skb) {
        __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
        goto out;
    }
    // ---------------- 确保有足够的空间  ----------------
    if(!pskb_may_pull(skb, header_length)){
        goto inhdr_error;
    }
    // ---------------- 确保有足够的空间  ----------------

    lir_header = lir_hdr(skb);

    // -----------------   检查校验和 50~60ns ------------------
    //    u64 start = ktime_get_real_ns();
    //    if(!check_checksum(lir_header)){
    //        printk(KERN_EMERG "checksum error\n");
    //        goto csum_error;
    //    }
    //    u64 time_elapsed = ktime_get_real_ns() - start;
    //    printk(KERN_EMERG "CheckSum Time elapsed %llu ns \n", time_elapsed);

    // -----------------   检查校验和  ------------------

    // -----------------   安全的检查  ------------------
    len = ntohs(lir_header->total_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (header_length))
        goto inhdr_error;
    if (pskb_trim_rcsum(skb, len)) {
        __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
        goto drop;
    }
    // -----------------   安全的检查  ------------------

    // -----------------   设置传输曾  ------------------
    skb->transport_header = skb->network_header + header_length;
    // -----------------   设置传输曾  ------------------

    // - Remove any debris in the socket control block -
    // memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
    // IPCB(skb)->iif = skb->skb_iif;
    // - Remove any debris in the socket control block -

    // ---- Must drop socket now because of tproxy. ----
    if (!skb_sk_is_prefetched(skb))
        skb_orphan(skb);
    // ---- Must drop socket now because of tproxy. ----

    return skb;

    csum_error:
    drop_reason = SKB_DROP_REASON_IP_CSUM;
    __IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
    inhdr_error:
    if (drop_reason == SKB_DROP_REASON_NOT_SPECIFIED)
        drop_reason = SKB_DROP_REASON_IP_INHDR;
    __IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
    drop:
    kfree_skb_reason(skb, drop_reason);
    out:
    return NULL;
}

/**
 * 在 lir_rcv_core 检查之后调用的核心包处理函数
 * @param net 网络命名空间
 * @param sk
 * @param skb
 * @return
 */
int lir_rcv_finish(struct net* net, struct sk_buff *skb, u64 start){
    u64 time_elapsed;
    struct net_device* dev = skb->dev;
    int ret;
    ret = lir_rcv_finish_core(net, skb, dev);
    time_elapsed = ktime_get_real_ns() - start;
    if (ret == NET_RX_SUCCESS){
        ret = lir_local_deliver(skb);
    } else if (ret == NET_RX_REENCODING_FORWARD) {
        printk(KERN_EMERG "LiR Reencoding Forward Time Consumption: %llu ns\n", time_elapsed);
    }
    else {
        printk(KERN_EMERG "LiR Direct Forward Time Consumption: %llu ns\n", time_elapsed);
    }
    return ret;
}

/**
 *
 * @param net 网络命名空间
 * @param skb 传入的数据包
 * @param dev 传入的接口
 * @return
 */
int lir_rcv_finish_core(struct net *net, struct sk_buff *skb, struct net_device *dev) {
    // ------------------------- zhf add code -------------------------
    // 对于 lir 来说一定是存在 option 字段的，所以我们不需要进行判断是否存在选项字段
    return lir_rcv_options_and_forward_packets(net, skb, dev);
    // ------------------------- zhf add code -------------------------
}

int lir_rcv_options_and_forward_packets(struct net *current_net_namespace, struct sk_buff *skb, struct net_device *dev) {
    // 1. 重新封装节点消耗的时间
    //    1. 根据数据包内的目的节点查找路由条目 (快速)
    //    2. 重置布隆过滤器 (快速)
    //    3. 插入指定数量的链路标识 (快速)
    //    4. 将数据包转出 (耗时)

    // 2. 直接转发节点消耗的时间
    //    1. 重建布隆过滤器 (快速)
    //    2. 遍历转发表，判断每一个表项中的链路标识是否被封装在布隆过滤器之中 (快速)
    //    3. 如果是的话，不能直接将收到的数据包转出，而需要利用 skb_clone 将数据包拷贝一份 (耗时)，再将数据包从特定接口转发出去，因为可能有多个出接口。
    //    4. 当遍历转发表完成之后, 需要将 skb 删除。(耗时)
    //    (3,4) 是导致转发节点超过重新封装节点的原因
    int index;  // 索引
    struct lirhdr *lir_header = lir_hdr(skb); // 获取 lir 头
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(current_net_namespace->crypto_nlsk); // 获取自定义数据结构
    struct bloom_filter *net_bloom_filter = lir_data_structure->bloom_filter; // 从自定义数据结构中拿到布隆过滤器
    unsigned long* bloom_filter_bitset; // 我们需要注意的是 net_bloom_filter->bitset 之中存储的是指向一个堆的指针，我们不能让这个指针指向的空间丢掉，所以提前存储一下
    struct NewInterfaceTable* new_interface_table = lir_data_structure->new_interface_table; // 拿到接口表
    int intermediate_satellite_id = lir_header->intermediate;
    u8 * opt_data_pointer = (u8 *) &(lir_header[1]); // opt 数据部分
    bloom_filter_bitset = net_bloom_filter->bitset;  // 将 option 字段的内容进行拷贝 // 不能删除
    net_bloom_filter->bitset = (unsigned long*)(opt_data_pointer);
    bool local_deliver = (lir_data_structure->satellite_id == lir_header->destination);
    if(local_deliver){
        net_bloom_filter->bitset = bloom_filter_bitset;
        return NET_RX_SUCCESS;
    }
    // --------------------------------------------- 现在的实现方式 -- 使用新的接口表 ---------------------------------------------
    if(intermediate_satellite_id == lir_data_structure->satellite_id) {
        // route and deliver
        int encoding_count = get_encoding_count(current_net_namespace);
        struct RoutingTableEntry *routing_table_entry = find_entry_in_routing_table(
                lir_data_structure->lir_routing_table,
                lir_data_structure->satellite_id,
                lir_header->destination);
        reset_bloom_filter(net_bloom_filter);
        for (index = 0; (index < encoding_count) && (index < routing_table_entry->length_of_path); index++) {
            push_element_into_bloom_filter(net_bloom_filter, &(routing_table_entry->link_identifiers[index]), sizeof(int));
        }
        lir_header->intermediate = routing_table_entry->node_ids[index - 1];
        net_bloom_filter->bitset = bloom_filter_bitset;
        lir_send_check(lir_header);
        lir_packet_forward(skb, routing_table_entry->output_interface, current_net_namespace);
        return NET_RX_REENCODING_FORWARD;
    }
    // direct forward or local deliver
    else {
        for(index = 0; index < new_interface_table->number_of_interfaces; index++){
            struct NewInterfaceEntry new_interface_entry = new_interface_table->interface_entry_array[index];
            if(0 == check_element_in_bloom_filter(net_bloom_filter, &(new_interface_entry.link_identifier), sizeof(int))){
                if(dev->ifindex == new_interface_entry.interface->ifindex){
                    continue;
                } else {
                    lir_packet_forward(skb, new_interface_entry.interface, current_net_namespace);
                }
            }
        }
        net_bloom_filter->bitset = bloom_filter_bitset; // 不能删除 // 将 net_bloom_filter->bitset 还原,以便进行后续的销毁
        //        kfree_skb(skb);
        return NET_RX_DROP;
    }
}

/**
 * 向上层进行交付
 */
int lir_local_deliver(struct sk_buff *skb){
    struct net *net = dev_net(skb->dev);

    if (lir_is_fragment(lir_hdr(skb))) {
        LOG_WITH_PREFIX("fragment handle");
        if (lir_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
            return 0;
    }
    // 核心的向上层交付的函数
    lir_local_deliver_finish(net, skb);
    return 0;
}

/**
 * 核心的向上层交付的函数
 */
int lir_local_deliver_finish(struct net *net, struct sk_buff *skb)
{
    skb_clear_delivery_time(skb);
    __skb_pull(skb, skb_network_header_len(skb));

    rcu_read_lock();
    // ---------------------------------------------------------------
    lir_protocol_deliver_rcu(net, skb, lir_hdr(skb)->protocol);
    // ---------------------------------------------------------------
    rcu_read_unlock();

    return 0;
}

/**
 * 根据协议号的不同向上层进行交付
 * @param net 网络命名空间
 * @param skb 数据包
 * @param protocol 协议
 */
void lir_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol){
    const struct net_protocol *ipprot;
    int raw, ret;

    resubmit:
    ipprot = rcu_dereference(inet_protos[protocol]);
    if (ipprot) {
        if (!ipprot->no_policy) {
            if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
                kfree_skb_reason(skb,
                                 SKB_DROP_REASON_XFRM_POLICY);
                return;
            }
            nf_reset_ct(skb);
        }
        if(ipprot->handler == orig_tcp_v4_rcv){
            // original code
            orig_tcp_v4_rcv(skb);
            // zhf modified code - current tcp v4 rcv is not implemented
            // ret = self_defined_tcp_v4_rcv(skb);
        } else {
            // LOG_WITH_PREFIX("lir_udp_rcv skb");
            ret = lir_udp_rcv(skb);
        }
        if (ret < 0) {
            protocol = -ret;
            goto resubmit;
        }
        __IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
    } else {
        if (!raw) {
            if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
                __IP_INC_STATS(net, IPSTATS_MIB_INUNKNOWNPROTOS);
                icmp_send(skb, ICMP_DEST_UNREACH,
                          ICMP_PROT_UNREACH, 0);
            }
            kfree_skb_reason(skb, SKB_DROP_REASON_IP_NOPROTO);
        } else {
            __IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
            consume_skb(skb);
        }
    }
}

/**
 * 是否是分片
 * @param lir_header lir 首部
 * @return
 */
bool lir_is_fragment(const struct lirhdr* lir_header){
    return (lir_header->frag_off & htons(IP_MF | IP_OFFSET));
}

/**
 * 进行分片的重组
 * @param net 网络命名空间
 * @param skb 数据包
 * @param user 用户
 * @return
 */
int lir_defrag(struct net *net, struct sk_buff *skb, u32 user){
    struct net_device *dev = skb->dev ? : skb_dst(skb)->dev;
    int vif = l3mdev_master_ifindex_rcu(dev);
    struct ipq *qp;

    __IP_INC_STATS(net, IPSTATS_MIB_REASMREQDS);
    skb_orphan(skb);

    /* Lookup (or create) queue header */
    qp = lir_find(net, lir_hdr(skb), user, vif);
    if (qp) {
        int ret;

        spin_lock(&qp->q.lock);

        ret = lir_frag_queue(qp, skb);

        spin_unlock(&qp->q.lock);
        ipq_put(qp);
        return ret;
    }

    __IP_INC_STATS(net, IPSTATS_MIB_REASMFAILS);
    kfree_skb(skb);
    return -ENOMEM;
}

/**
 * 进行 lir 数据包的转发
 * @param skb 要转发的数据包
 * @param output_dev 出接口
 * @param current_net_namespace 当前的网络命名空间
 * @return
 */
int lir_packet_forward(struct sk_buff* skb, struct net_device* output_dev, struct net* current_net_namespace){
    u32 mtu;
    struct sock* sk = NULL;
    SKB_DR(reason);
    mtu = READ_ONCE(output_dev->mtu);  // set mtu
    skb_cow(skb, LL_RESERVED_SPACE(output_dev)+0);
    // -------------------------------------------------

    // ------------- we current not modify the option so we don't need to update -------------
    // later work
    // ------------- we current not modify the option so we don't need to update -------------

    skb->dev = output_dev;
    skb->protocol = htons(ETH_P_IP);

    // 当超过mtu限制的时候，需要进行分片
    if (skb->len > mtu || IPCB(skb)->frag_max_size){
        return lir_fragment(current_net_namespace, sk, skb, mtu, output_dev, lir_ip_finish_output2);
    }
    return lir_ip_finish_output2(current_net_namespace, sk, skb, output_dev);
}
