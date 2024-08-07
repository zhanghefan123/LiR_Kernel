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
#include "headers/session_path_table.h"

asmlinkage int (*orig_tcp_v4_rcv)(struct sk_buff *skb);

extern asmlinkage int
(*orig_ip_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

void resolve_network_lir_rcv_inner_functions_address(void) {
    LOG_WITH_EDGE("start to resolve lir_rcv inner functions address");
    orig_tcp_v4_rcv = get_function_address("tcp_v4_rcv");
    LOG_RESOLVED(orig_tcp_v4_rcv, "tcp_v4_rcv");
    LOG_WITH_EDGE("end to resolve lir_rcv inner functions address");
}

// ----------------------------- static -----------------------------
struct ipq {
    struct inet_frag_queue q;
    u8 ecn; /* RFC3168 support */
    u16 max_df_size; /* largest frag with DF set seen */
    int iif;
    unsigned int rid;
    struct inet_peer *peer;
};

static struct ipq *lir_find(struct net *net, struct lirhdr *lir_header,
                            u32 user, int vif) {
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

static int lir_frag_too_far(struct ipq *qp) {
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

static int lir_frag_reinit(struct ipq *qp) {
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

static void ipq_kill(struct ipq *ipq) {
    inet_frag_kill(&ipq->q);
}

static void ipq_put(struct ipq *ipq) {
    inet_frag_put(&ipq->q);
}

static bool ip_frag_coalesce_ok(const struct ipq *qp) {
    return qp->q.key.v4.user == IP_DEFRAG_LOCAL_DELIVER;
}

static int lir_frag_reasm(struct ipq *qp, struct sk_buff *skb,
                          struct sk_buff *prev_tail, struct net_device *dev) {
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

static int lir_frag_queue(struct ipq *qp, struct sk_buff *skb) {
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
    offset <<= 3;        /* offset is in 8-byte chunks */
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
        if (end & 7) {
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

int lir_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
    u64 start = ktime_get_real_ns();
    int result;
    if (TEST_IF_LIR_PACKET(skb)) {
        struct net *net = dev_net(dev);  // 通过输入接口获取网络命名空间
        skb = lir_rcv_core(skb, net);
        if (skb == NULL) {
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
struct sk_buff *lir_rcv_core(struct sk_buff *skb, struct net *net) {
    struct lirhdr *lir_header = lir_hdr(skb);
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
    if (!pskb_may_pull(skb, header_length)) {
        goto inhdr_error;
    }
    // ---------------- 确保有足够的空间  ----------------

    lir_header = lir_hdr(skb);

    // -----------------   检查校验和  ------------------
    //    if(!check_checksum(lir_header)){
    //        goto csum_error;
    //    }
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
int lir_rcv_finish(struct net *net, struct sk_buff *skb, u64 start) {
    u64 time_elapsed;
    struct net_device *dev = skb->dev;
    int ret;
    ret = lir_rcv_finish_core(net, skb, dev);
    time_elapsed = ktime_get_real_ns() - start;
    if (ret == NET_RX_SUCCESS) { // 本地收包
        ret = lir_local_deliver(skb);
    } else if(ret == NET_RX_FIRST_HOP_PACKET){
        printk(KERN_EMERG "opt_forward_time_elapsed: %llu ns\n", time_elapsed);
        ret = NET_RX_DROP;
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

/**
 * print the upstream nodes of current node
 * @param icing_path
 * @param current_path_index
 * @param source_node_id
 */
//void print_upstream_node_sequence(struct single_hop_icing *icing_path, int current_path_index, int source_node_id) {
//    LOG_WITH_EDGE("UPSTREAM NODE SEQUENCE");
//    if (current_path_index == 0) {
//        printk(KERN_EMERG "upstream node: %d\n", source_node_id);
//    } else {
//        int index;
//        for (index = 0; index < current_path_index; index++) {
//            printk(KERN_EMERG "upstream node: %d\n", icing_path[index].node_id_5);
//        }
//    }
//    LOG_WITH_EDGE("UPSTREAM NODE SEQUENCE");
//}

/**
 * print the downstream nodes of current node
 * @param icing_path
 * @param current_path_index
 * @param length_of_path
 */
//void print_downstream_node_sequence(struct single_hop_icing *icing_path, int current_path_index, int length_of_path) {
//    LOG_WITH_EDGE("DOWNSTREAM NODE SEQUENCE");
//    int index;
//    for (index = current_path_index + 1; index < length_of_path; index++) {
//        printk(KERN_EMERG "down stream node %d\n", icing_path[index].node_id_5);
//    }
//    LOG_WITH_EDGE("DOWNSTREAM NODE SEQUENCE");
//}

//bool validate_packet(struct lirhdr *lir_header,
//                     struct single_hop_icing *icing_path,
//                     struct single_node_validation_icing *validation_list,
//                     int current_path_index,
//                     struct net *current_net_namespace,
//                     int source_satellite_id,
//                     int current_satellite_id) {
//    unsigned char *static_fields_hash = calculate_static_fields_hash_of_lir(lir_header, current_net_namespace);
//    struct shash_desc *hmac_data_structure = get_hmac_data_structure(current_net_namespace);
//    bool validation_result;
//    if (current_path_index == 0) {
//        char key_from_source_to_current[20];
//        sprintf(key_from_source_to_current, "key-%d-%d", source_satellite_id, current_satellite_id);
//        unsigned char *hmac_result = calculate_hmac(hmac_data_structure,
//                                                    static_fields_hash,
//                                                    HASH_OUTPUT_LENGTH_IN_BYTES,
//                                                    key_from_source_to_current);
//        bool same = COMPARE_MEMORY((unsigned char *) (&validation_list[current_path_index]), hmac_result,
//                                   ICING_VALIDATION_SIZE_IN_BYTES);
//        if (same) {
//            LOG_WITH_PREFIX("VALIDATION PASSED");
//            validation_result = true;
//        } else {
//            LOG_WITH_PREFIX("VALIDATION NOT PASSED");
//            validation_result = false;
//        }
//        // print_hash_or_hmac_result(hmac_result, ICING_VALIDATION_SIZE_IN_BYTES);
//        kfree(hmac_result);
//    } else {
//        int index;
//        char key_from_source_to_current[20];
//        sprintf(key_from_source_to_current, "key-%d-%d", source_satellite_id, current_satellite_id);
//        unsigned char *hmac_result_final = calculate_hmac(hmac_data_structure,
//                                                          static_fields_hash,
//                                                          HASH_OUTPUT_LENGTH_IN_BYTES,
//                                                          key_from_source_to_current); // get the hmac(source-to-current)
//        for (index = 0; index < current_path_index; index++) {
//            char key_from_intermediate_to_current[20];
//            __u32 upstream_node = icing_path[index].node_id_5;
//            sprintf(key_from_intermediate_to_current, "key-%d-%d", upstream_node, current_satellite_id);
//            unsigned char *hmac_result_temp = calculate_hmac(hmac_data_structure,
//                                                             static_fields_hash,
//                                                             HASH_OUTPUT_LENGTH_IN_BYTES,
//                                                             key_from_intermediate_to_current); // get the hmac(intermediate-to-current)
//            XOR_MEMORY(hmac_result_final, hmac_result_temp, ICING_VALIDATION_SIZE_IN_BYTES); // xor the result
//            kfree(hmac_result_temp);
//        }
//        bool same = COMPARE_MEMORY((unsigned char *) (&validation_list[current_path_index]), hmac_result_final,
//                                    ICING_VALIDATION_SIZE_IN_BYTES);
//        if (same) {
//            LOG_WITH_PREFIX("VALIDATION PASSED");
//            validation_result = true;
//        } else {
//            LOG_WITH_PREFIX("VALIDATION NOT PASSED");
//            validation_result = false;
//        }
//        kfree(hmac_result_final);
//    }
//    kfree(static_fields_hash);
//    return validation_result;
//}

//void update_validation_fields(struct lirhdr* lir_header,
//                              struct single_hop_icing* icing_path,
//                              struct single_node_validation_icing* validation_list,
//                              int current_path_index,
//                              int current_satellite_id,
//                              struct net* current_net_namespace,
//                              int length_of_path){
//    unsigned char* static_fields_hash = calculate_static_fields_hash_of_lir(lir_header,current_net_namespace); // calculate hash
//    struct shash_desc* hmac_data_structure = get_hmac_data_structure(current_net_namespace); // get hmac data structure
//    int index;
//    for(index = current_path_index + 1; index < length_of_path; index++){
//        char key_from_current_to_downstream_node[20];
//        int downstream_node_id = (int)(icing_path[index].node_id_5);
//        sprintf(key_from_current_to_downstream_node,"key-%d-%d", current_satellite_id, downstream_node_id);
//        unsigned char* hmac_result = calculate_hmac(hmac_data_structure,
//                                                    static_fields_hash,
//                                                    HASH_OUTPUT_LENGTH_IN_BYTES,
//                                                    key_from_current_to_downstream_node);
//        XOR_MEMORY((unsigned char*)(&(validation_list[index])), hmac_result, ICING_VALIDATION_SIZE_IN_BYTES);
//        kfree(hmac_result);
//    }
//    kfree(static_fields_hash);
//}

void print_first_lir_packet(struct net *current_net_namespace,
                            unsigned char *extension_header_start,
                            int extension_header_length,
                            int path_length,
                            struct single_hop_field *path) {
    int index;
    struct shash_desc *hash_data_structure = get_hash_data_structure(current_net_namespace);
    LOG_WITH_EDGE("RECEIVED FIRST OPT PACKET");
    unsigned char *path_hash = calculate_fixed_length_hash(hash_data_structure, extension_header_start,
                                                           extension_header_length);
    // print_hash_or_hmac_result(path_hash, HASH_OUTPUT_LENGTH_IN_BYTES);
    kfree(path_hash);
    printk(KERN_EMERG "path length = %d\n", path_length);
    for (index = 0; index < path_length + 1; index++) {
        printk(KERN_EMERG "[node id %d link identifier %d]\n", path[index].node_id, path[index].link_identifier);
    }
    LOG_WITH_EDGE("RECEIVED FIRST OPT PACKET");
}

struct net_device *
store_in_session_path_table(struct hlist_head *session_path_table, struct NewInterfaceTable *new_interface_table,
                            struct single_hop_field *path_pointer,unsigned char* session_id_pointer,
                            int length_of_path, int current_index,
                            int source, int destination, int current_satellite_id) {
    int index;
    struct net_device *output_dev;
    struct SessionPathTableEntry *session_path_table_entry = init_session_table_entry();
    session_path_table_entry->source_id = source;
    session_path_table_entry->destination_id = destination;
    session_path_table_entry->current_index = current_index - 1;
    bool is_destination = (current_satellite_id == destination);
    // -------------------------------- get session id -------------------------------------
    memcpy(&(session_path_table_entry->sessionid1), session_id_pointer, SESSION_ID_SIZE_IN_BYTES);
    // print_hash_or_hmac_result(session_id_pointer, SESSION_ID_SIZE_IN_BYTES);
    // -------------------------------- get session id -------------------------------------
    // -------------------------------- get encrypt sequence -------------------------------
    if (is_destination) {
        session_path_table_entry->encrypt_order = (int *) (kmalloc(sizeof(int) * length_of_path, GFP_KERNEL));
        session_path_table_entry->encrypt_order[0] = destination;
        // when length of path = 3
        // index = 1 index = 2 ----corresponding to----> B C
        session_path_table_entry->encrypt_length = length_of_path;
        for (index = 1; index < length_of_path; index++) {
            session_path_table_entry->encrypt_order[index] = path_pointer[index].node_id;
        }
    }
    // -------------------------------- get encrypt sequence -------------------------------

    // -------------------------------- get network device ---------------------------------
    int current_link_identifier = path_pointer[current_index].link_identifier;
    for (index = 0; index < new_interface_table->number_of_interfaces; index++) {
        struct NewInterfaceEntry new_interface_entry = new_interface_table->interface_entry_array[index];
        int entry_corresponding_link_identifier = new_interface_entry.link_identifier;
        if (entry_corresponding_link_identifier == current_link_identifier) {
            output_dev = new_interface_entry.interface;
        }
    }
    // -------------------------------- get network device ---------------------------------
    // -------------------------------- insert the entry -----------------------------------
    session_path_table_entry->output_device = output_dev;
    add_entry_into_session_table(session_path_table, session_path_table_entry);
    // -------------------------------- insert the entry -----------------------------------
    //    LOG_WITH_PREFIX(final_output_message);
    return output_dev;
}

int forward_and_deliver_first_skb(struct sk_buff *skb, struct net *current_net_namespace) {
    struct lirhdr *lir_header = lir_hdr(skb);
    unsigned char *extension_header_start = (unsigned char *) (&lir_header[1]);
    struct length_of_path *length_of_path_struct = (struct length_of_path *) (extension_header_start);
    unsigned char* session_id_pointer = extension_header_start + sizeof(struct length_of_path);
    struct single_hop_field *path_pointer = (struct single_hop_field *) (session_id_pointer + sizeof(struct sessionid));
    struct NewInterfaceTable *new_interface_table = get_new_interface_table_from_net_namespace(current_net_namespace);
    struct hlist_head *session_path_table = get_session_path_table_from_net_namespace(current_net_namespace);
    struct net_device *output_dev;
    int path_length = length_of_path_struct->length_of_path;
    int current_path_index = ntohs(lir_header->current_path_index);
    int current_satellite_id = get_satellite_id(current_net_namespace);
    int source_satellite_id = ntohs(lir_header->source);
    int destination_satellite_id = ntohs(lir_header->destination);
    // -------------------------------- PRINT PATH --------------------------------
    output_dev = store_in_session_path_table(session_path_table, new_interface_table,
                                             path_pointer, session_id_pointer,
                                             path_length, current_path_index,
                                             source_satellite_id, destination_satellite_id,
                                             current_satellite_id);
    // -------------------------------- PRINT PATH --------------------------------
    bool local_deliver = (destination_satellite_id == current_satellite_id);
    if (local_deliver) {
        return NET_RX_SUCCESS;
    } else {
        lir_header->current_path_index = htons(current_path_index + 1);
        lir_packet_forward(skb, output_dev, current_net_namespace);
        // printk(KERN_EMERG "The packet should be forwarded from %s\n", output_dev->name);
        return NET_RX_DROP;
    }
}

/**
 * 处理opt首包
 * @param current_net_namespace 当前的网络命名空间
 * @param skb 数据包
 * @param dev 入接口
 * @return
 */
int handle_first_opt_packet(struct net *current_net_namespace, struct sk_buff *skb, struct net_device *dev) {
    // ----------------   log the packet  ----------------
    // LOG_WITH_PREFIX("RECEIVED FIRST LIR PACKET");
    // ----------------   log the packet  ----------------
    return forward_and_deliver_first_skb(skb, current_net_namespace);
}

/**
 * 处理opt非首包
 * @param current_net_namespace 当前的网络命名空间
 * @param skb 数据包
 * @param dev 入接口
 * @return
 */
int handle_other_opt_packets(struct net *current_net_namespace, struct sk_buff *skb, struct net_device *dev) {
    int index;
    struct lirhdr *lir_header = lir_hdr(skb);  // 拿到 lir header
    int source = ntohs(lir_header->source);  // 拿到包的 source
    int destination = ntohs(lir_header->destination);  // 拿到包的 destination
    u64* sessionid = (u64*)(&lir_header[1]); // sessionid
    unsigned char *pvf_pointer = (unsigned char *)(sessionid) + (sizeof(struct sessionid));  // 拿到指向 pvf 的指针
    unsigned char *ovfs_pointer = pvf_pointer + sizeof(struct path_validation_field);  // 拿到指向 ovf 数组的指针
    struct origin_path_validation_field *opvs = (struct origin_path_validation_field *) ovfs_pointer;
    struct hlist_head *session_path_table = get_session_path_table_from_net_namespace(current_net_namespace); // 获取会话路径表
    struct SessionPathTableEntry *session_path_table_entry = find_entry_in_session_path_table(session_path_table,
                                                                                              sessionid[0],
                                                                                              sessionid[1]);  // 通过源和目的进行表项的获取
    // first packet
    bool first_hop_packet = false;
    // update current hop
    if (lir_header->current_hop == 1){
        lir_header->current_hop = lir_header->current_hop + 1;
        first_hop_packet = true;
    }
    if (session_path_table_entry) { // 如果找到了路由表项
        // -------------------------------------------------- opv 字段验证 --------------------------------------------------
        int current_satellite_id = get_satellite_id(current_net_namespace); // 拿到当前卫星的 id
        struct udphdr* udp_header = udp_hdr(skb); // 拿到 udp 的首部
        struct shash_desc *hmac_data_structure = get_hmac_data_structure(current_net_namespace); // 计算 hmac_data
        unsigned char *opv_hmac_result;  // 计算 hmac_result
        int current_index = session_path_table_entry->current_index;  // 需要验证的 ovf 的索引
        char key_from_source_to_current[20]; // 存储对称密钥的字符串
        sprintf(key_from_source_to_current, "key-%d-%d", source, current_satellite_id);  // 填充存储对称密钥的字符串
        opv_hmac_result = calculate_hmac(hmac_data_structure,pvf_pointer,OPT_VALIDATION_SIZE_IN_BYTES,key_from_source_to_current); // 计算 hmac 结果
        bool same = COMPARE_MEMORY((unsigned char *) (&opvs[current_index]), opv_hmac_result, OPT_VALIDATION_SIZE_IN_BYTES);  // 进行内存比较
        kfree(opv_hmac_result);
        if (same) { // 如果结果一致说明验证通过, 这个时候 payload hash 还没有被释放，所以最后要注意进行释放
            // LOG_WITH_PREFIX("VALIDATION PASSED");
        } else {  // 如果结果不一致，说明验证不通过，释放所有的 hash 以及 hmac 计算结果，以及skb
            // LOG_WITH_PREFIX("VALIDATION NOT PASSED");
            kfree_skb(skb);
            return NET_RX_DROP;
        }
        unsigned char* payload_hash = calculate_payload_hash(udp_header, current_net_namespace); // 首部的后面就是数据部分，所以计算载荷的哈希
        // -------------------------------------------------- opv 字段验证 --------------------------------------------------
        bool local_deliver = (destination == current_satellite_id);
        if (local_deliver) { // 如果数据包是本地交付，需要进行 pvf 字段的还原。
            // 进行还原 A->B->C->D 则加密的顺序为 KD KB KC
            // 打印加密的顺序
            unsigned char temp_result[OPT_VALIDATION_SIZE_IN_BYTES];
            unsigned char *hmac_result_pvf;
            for (index = 0; index < session_path_table_entry->encrypt_length; index++) {
                char key[20];
                sprintf(key, "key-%d-%d", session_path_table_entry->source_id,
                        session_path_table_entry->encrypt_order[index]);
                if (index == 0) {
                    hmac_result_pvf = calculate_hmac(hmac_data_structure,
                                                     payload_hash,
                                                     HASH_OUTPUT_LENGTH_IN_BYTES,
                                                     key);
                    memcpy(temp_result, hmac_result_pvf, OPT_VALIDATION_SIZE_IN_BYTES);
                    kfree(hmac_result_pvf);
                } else {
                    hmac_result_pvf = calculate_hmac(hmac_data_structure,
                                                     temp_result,
                                                     OPT_VALIDATION_SIZE_IN_BYTES,
                                                     key);
                    memcpy(temp_result, hmac_result_pvf, OPT_VALIDATION_SIZE_IN_BYTES);
                    kfree(hmac_result_pvf);
                }
            }
            kfree(payload_hash);  // 释放 payload hash
            return NET_RX_SUCCESS;
        } else { // 如果数据包并非本地交付，需要进行转发
            // -------------------------------------------------- pvf 字段更新 --------------------------------------------------
            unsigned char *pvf_hmac_result = calculate_hmac(hmac_data_structure,
                                                            pvf_pointer,
                                                            sizeof(struct path_validation_field),
                                                            key_from_source_to_current);
            memcpy(pvf_pointer, pvf_hmac_result, sizeof(struct path_validation_field));
            kfree(pvf_hmac_result); // 释放 hmac_result
            // -------------------------------------------------- pvf 字段更新 --------------------------------------------------
            lir_packet_forward(skb, session_path_table_entry->output_device, current_net_namespace);
            kfree(payload_hash);  // 释放 payload hash

            if(first_hop_packet){
                return NET_RX_FIRST_HOP_PACKET;
            } else {
                return NET_RX_DROP;
            }
        }
    } else {  // 如果没有找到路由表项, 则
        LOG_WITH_PREFIX("cannot find session table entry");
        kfree_skb(skb);
        return NET_RX_DROP;
    }
}

int lir_rcv_options_and_forward_packets(struct net *current_net_namespace, struct sk_buff *skb, struct net_device *dev) {
    bool first_packet = TEST_IF_FIRST_OPT_PACKET(skb);
    if (first_packet) { // 第一个数据包是用来进行路径的构建的
        return handle_first_opt_packet(current_net_namespace, skb, dev);
    } else { // 其余的数据包才是用来真正的进行通信的
        return handle_other_opt_packets(current_net_namespace, skb, dev);
    }
}

/**
 * 向上层进行交付
 */
int lir_local_deliver(struct sk_buff *skb) {
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
int lir_local_deliver_finish(struct net *net, struct sk_buff *skb) {
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
void lir_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol) {
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
        if (ipprot->handler == orig_tcp_v4_rcv) {
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
bool lir_is_fragment(const struct lirhdr *lir_header) {
    return (lir_header->frag_off & htons(IP_MF | IP_OFFSET));
}

/**
 * 进行分片的重组
 * @param net 网络命名空间
 * @param skb 数据包
 * @param user 用户
 * @return
 */
int lir_defrag(struct net *net, struct sk_buff *skb, u32 user) {
    struct net_device *dev = skb->dev ?: skb_dst(skb)->dev;
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
int lir_packet_forward(struct sk_buff *skb, struct net_device *output_dev, struct net *current_net_namespace) {
    u32 mtu;
    struct lirhdr *lir_header;    /* Our header */
    struct sock *sk = NULL;
    SKB_DR(reason);
    mtu = READ_ONCE(output_dev->mtu);  // set mtu
    skb_cow(skb, LL_RESERVED_SPACE(output_dev) + 0);
    lir_header = lir_hdr(skb);
    // -------------------------------------------------

    // ------------- we current not modify the option so we don't need to update -------------
    // later work
    // ------------- we current not modify the option so we don't need to update -------------

    skb->dev = output_dev;
    skb->protocol = htons(ETH_P_IP);

    // 当超过mtu限制的时候，需要进行分片
    if (skb->len > mtu || IPCB(skb)->frag_max_size) {
        return lir_fragment(current_net_namespace, sk, skb, mtu, output_dev, lir_ip_finish_output2);
    }
    return lir_ip_finish_output2(current_net_namespace, sk, skb, output_dev);
}
