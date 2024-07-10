//
// Created by zhf on 24-4-12.
//
#include "headers/support_tools.h"
#include "headers/network_lir_header.h"
#include "headers/network_lir_make_skb.h"
#include "headers/support_ftrace_hook_api.h"
#include "headers/network_lir_option_field_mean.h"
#include "headers/network_lir_send_check.h"
#include "headers/mac_lir_ip_output.h"
#include "headers/lir_routing_table_structure.h"
#include "headers/network_lir_header.h"
#include "headers/network_sk_data.h"

// --------------------- static ---------------------
static u32 *ip_idents_mask_pointer __read_mostly;
static atomic_t *ip_idents __read_mostly;
static u32 *ip_tstamps __read_mostly;

void resolve_lir_make_skb_inner_functions_address(void) {
    LOG_WITH_EDGE("start to resolve lir_make_skb inner functions address");
    ip_idents = get_function_address("ip_idents");
    LOG_RESOLVED(ip_idents, "ip_idents");
    ip_tstamps = get_function_address("ip_tstamps");
    LOG_RESOLVED(ip_tstamps, "ip_tstamps");
    ip_idents_mask_pointer = get_function_address("ip_idents_mask");
    LOG_RESOLVED(ip_idents_mask_pointer, "ip_idents_mask");
    LOG_WITH_EDGE("end to resolve lir_make_skb inner functions address");
}


static void ip_cork_release(struct inet_cork *cork) {
    cork->flags &= ~IPCORK_OPT;
    kfree(cork->opt);
    cork->opt = NULL;
}

static void __ip_flush_pending_frames(struct sock *sk,
                                      struct sk_buff_head *queue,
                                      struct inet_cork *cork) {
    struct sk_buff *skb;

    while ((skb = __skb_dequeue_tail(queue)) != NULL)
        kfree_skb(skb);

    ip_cork_release(cork);
}

static u32 ip_idents_reserve(u32 hash, int segs) {
    u32 bucket, old, now = (u32) jiffies;
    atomic_t * p_id;
    u32 * p_tstamp;
    u32 delta = 0;

    bucket = hash & (*ip_idents_mask_pointer);
    p_tstamp = ip_tstamps + bucket;
    p_id = ip_idents + bucket;
    old = READ_ONCE(*p_tstamp);

    if (old != now && cmpxchg(p_tstamp, old, now) == old)
        delta = prandom_u32_max(now - old);

    /* If UBSAN reports an error there, please make sure your compiler
     * supports -fno-strict-overflow before reporting it that was a bug
     * in UBSAN, and it has been fixed in GCC-8.
     */
    return atomic_add_return(segs + delta, p_id) - segs;
}
// --------------------- static ---------------------

// 成功检查
int lir_setup_cork(struct sock *sk,
                   struct inet_cork *cork,
                   struct ipcm_cookie *ipc,
                   struct net_device *output_dev) {
    cork->fragsize = output_dev->mtu;
    if (!inetdev_valid_mtu(cork->fragsize))
        return -ENETUNREACH; // 返回错误
    cork->gso_size = ipc->gso_size;
    cork->length = 0;
    cork->ttl = ipc->ttl;
    cork->tos = ipc->tos;
    cork->mark = ipc->sockc.mark;
    cork->priority = ipc->priority;
    cork->transmit_time = ipc->sockc.transmit_time;
    cork->tx_flags = 0;
    sock_tx_timestamp(sk, ipc->sockc.tsflags, &cork->tx_flags);
    return 0;
}

// 成功检查
/**
 *
 * @param sk
 * @param lir_return_data_structure
 * @param app_and_transport_length
 * @param flags
 * @param getfrag
 * @param from 就是上层传下来的 app 的长度
 * @param cork
 * @param ipc
 * @param source_node_id
 * @param destination_node_id
 * @return
 */
struct sk_buff *lir_make_skb(struct sock *sk,
                             struct LirReturnDataStructure *lir_return_data_structure,
                             int app_length,
                             int app_and_transport_length,
                             unsigned int flags,
                             int getfrag(void *from, char *to, int offset,
                                         int len, int odd, struct sk_buff *skb),
                             void *from,
                             struct inet_cork *cork,
                             struct ipcm_cookie *ipc,
                             __u16 source_node_id,
                             __u16 destination_node_id) {
    // --------------      initialize        --------------
    struct sk_buff_head queue; // 队列
    int err; // 错误
    if (flags & MSG_PROBE) { return NULL; }
    __skb_queue_head_init(&queue); // 进行 skb queue 的初始化
    cork->flags = 0;
    cork->addr = 0;
    cork->opt = NULL;
    err = lir_setup_cork(sk, cork, ipc, lir_return_data_structure->output_interface);
    if (err) {
        return ERR_PTR(err);
    }
    // --------------      initialize        --------------
    err = lir_append_data(sk, &queue, lir_return_data_structure,
                          app_and_transport_length, flags,
                          getfrag, from, &current->task_frag,
                          cork);
    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork); // 这里面不会有和 ip 首部相关的操作
        return ERR_PTR(err);
    }

    return lir_make_skb_core(sk, &queue, cork, lir_return_data_structure,
                             source_node_id, destination_node_id);
}

__u16 get_opt_header_total_length(struct LirReturnDataStructure *lir_return_data_structure, bool first_packet) {
    // if the packet is the first packet, we should adopt different logic
    // A->B->C->D the length of path is 3
    int length_of_path = lir_return_data_structure->routing_table_entry->length_of_path;
    if (first_packet) {
        return (__u16) (sizeof(struct lirhdr)) + (__u16) (sizeof(struct length_of_path)) + (__u16) (sizeof(struct single_hop_field) * (length_of_path + 1));
        // for above example
        // length of path = 3
        // single_hop_field[0] = {node_id: A}
        // single_hop_field[1] = {node_id: B link_identifier: L1}
        // single_hop_field[2] = {node_id: C link_identifier: L2}
        // single_hop_field[3] = {node_id: D}
    } else {
        return (__u16) (sizeof(struct lirhdr)) +
               (__u16) (sizeof(struct path_validation_field)) +    // PVF 字段
               (__u16) (sizeof(struct origin_path_validation_field)) * (length_of_path); // OPV 字段
    }
}

// 成功检查
int lir_append_data(struct sock *sk,
                    struct sk_buff_head *queue,
                    struct LirReturnDataStructure *lir_return_data_structure,
                    int app_and_transport_length,
                    unsigned int flags,
                    int getfrag(void *from, char *to, int offset,
                                int len, int odd, struct sk_buff *skb),
                    void *from,
                    struct page_frag *pfrag,
                    struct inet_cork *cork) {
    // --------------      initialize        --------------
    bool first_packet = get_first_packet_status(sk);
    struct inet_sock *inet = inet_sk(sk);
    struct sk_buff *skb;            // 数据包
    int second_layer_header_length; // 二层头部长度
    int mtu; // 最大传输单元
    int err;
    int offset;
    unsigned int wmem_alloc_delta = 0;
    int extension_header_length = 0; // 额外报头 - 比如 ipsec
    unsigned int fragment_header_length; // 单一分片的长度
    unsigned int max_fragment_length;  // 单一分片所能承载的最大长度
    unsigned int transport_header_length = sizeof(struct udphdr); // 传输层头部，这里只针对udp
    unsigned int max_non_fragment_size = IP_MAX_MTU;
    int csummode = CHECKSUM_NONE;
    struct ubuf_info *uarg = NULL;
    int copy;  // 本次能拷贝的数据量
    bool paged, extra_uref = false;
    u32 tskey = 0;
    paged = cork->gso_size != 0;
    skb = skb_peek_tail(queue); // 从队列尾部取，因为这个 skb 当前容纳的数据可能还没有达到 mtu
    mtu = LIR_MTU;
    second_layer_header_length = LL_RESERVED_SPACE(lir_return_data_structure->output_interface);
    fragment_header_length = get_opt_header_total_length(lir_return_data_structure, first_packet); // 分片长度就是 lir 头部的长度
    max_fragment_length = ((mtu - fragment_header_length) & ~7) +
                          fragment_header_length; // 因为 IP 首部的片段偏移量只有13位，且以8字节为单位，否则首部的偏移量就无法进行正确的设置，这里是进行8字节对其下的最大结果
    if (cork->tx_flags & SKBTX_ANY_SW_TSTAMP &&
        sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID)
        tskey = atomic_inc_return(&sk->sk_tskey) - 1;
    if (cork->length + app_and_transport_length > max_non_fragment_size - fragment_header_length) {
        return -EMSGSIZE;
    }
    // --------------      initialize        --------------

    // --------------       create skb     --------------
    if (!skb) {
        goto alloc_new_skb;
    }

    while (app_and_transport_length > 0) {
        copy = mtu - skb->len;
        if (copy < app_and_transport_length) {
            copy = max_fragment_length - skb->len;
        }
        if (copy <= 0) {
            char *data;
            unsigned int datalen;
            unsigned int fraglen;
            unsigned int fraggap; // fraggap 的范围一定在 [0-8) 内
            unsigned int alloclen, alloc_extra;
            unsigned int pagedlen;
            struct sk_buff *skb_prev;

            alloc_new_skb: // 分配新的 skb

            skb_prev = skb;
            // 如果存在上一个数据包
            if (skb_prev) {
                fraggap = skb_prev->len - max_fragment_length;
            } else {
                fraggap = 0;
            }
            datalen = app_and_transport_length + fraggap;
            if (datalen > mtu - fragment_header_length)
                // 重新计算这个数据包所需要保存的大小
                datalen = max_fragment_length - fragment_header_length;
            fraglen = datalen + fragment_header_length;
            pagedlen = 0;
            alloc_extra = second_layer_header_length + 15;
            alloc_extra += extension_header_length;
            if (datalen == app_and_transport_length + fraggap) {
                alloc_extra += 0;
            }
            if ((flags & MSG_MORE) &&
                !(lir_return_data_structure->output_interface->features & NETIF_F_SG))
                alloclen = mtu;
            else if (!paged &&
                     (fraglen + alloc_extra < SKB_MAX_ALLOC ||
                      !(lir_return_data_structure->output_interface->features & NETIF_F_SG)))
                alloclen = fraglen;
            else {
                alloclen = min_t(int, fraglen, MAX_HEADER);
                pagedlen = fraglen - alloclen;
            }
            alloclen += alloc_extra;
            if (transport_header_length) {
                skb = sock_alloc_send_skb(sk, alloclen,
                                          (flags & MSG_DONTWAIT), &err);
            } else {
                skb = NULL;
                if (refcount_read(&sk->sk_wmem_alloc) + wmem_alloc_delta <=
                    2 * sk->sk_sndbuf)
                    skb = alloc_skb(alloclen,
                                    sk->sk_allocation);
                if (unlikely(!skb))
                    err = -ENOBUFS;
            }
            // 如果 skb 分配失败，那么本次调用失败
            if (!skb)
                goto error;

            skb->ip_summed = csummode;
            skb->csum = 0;
            skb_reserve(skb, second_layer_header_length); // reserve the length for skb

            data = skb_put(skb, fraglen + extension_header_length - pagedlen);
            skb_set_network_header(skb, extension_header_length);
            // update the position of transport header
            skb->transport_header = (skb->network_header +
                                     fragment_header_length); // update the position of transport header
            data += fragment_header_length + extension_header_length;

            if (fraggap) {
                // 将上一个 skb 的末尾的没有对其的拷贝过来
                skb->csum = skb_copy_and_csum_bits(
                        skb_prev, max_fragment_length,
                        data + transport_header_length, fraggap);
                skb_prev->csum = csum_sub(skb_prev->csum,
                                          skb->csum);
                data += fraggap;
                pskb_trim_unique(skb_prev, max_fragment_length);
            }

            copy = datalen - transport_header_length - fraggap - pagedlen;
            if (copy > 0 && getfrag(from, data + transport_header_length, offset, copy, fraggap, skb) < 0) {
                err = -EFAULT;
                kfree_skb(skb);
                goto error;
            }
            offset += copy;
            app_and_transport_length -= copy + transport_header_length;
            transport_header_length = 0;
            extension_header_length = 0;
            csummode = CHECKSUM_NONE;

            /* only the initial fragment is time stamped */
            skb_shinfo(skb)->tx_flags = cork->tx_flags;
            cork->tx_flags = 0;
            skb_shinfo(skb)->tskey = tskey;
            tskey = 0;
            skb_zcopy_set(skb, uarg, &extra_uref);

            if ((flags & MSG_CONFIRM) && !skb_prev)
                skb_set_dst_pending_confirm(skb, 1);

            if (!skb->destructor) {
                skb->destructor = sock_wfree;
                skb->sk = sk;
                wmem_alloc_delta += skb->truesize;
            }
            __skb_queue_tail(queue, skb);
            continue;
        }
        if (copy > app_and_transport_length)
            copy = app_and_transport_length;

        if (!(lir_return_data_structure->output_interface->features & NETIF_F_SG) &&
            skb_tailroom(skb) >= copy) {
            unsigned int off;

            off = skb->len;
            if (getfrag(from, skb_put(skb, copy),
                        offset, copy, off, skb) < 0) {
                __skb_trim(skb, off);
                err = -EFAULT;
                goto error;
            }
        } else if (!uarg || !uarg->zerocopy) {
            int i = skb_shinfo(skb)->nr_frags;

            err = -ENOMEM;
            if (!sk_page_frag_refill(sk, pfrag))
                goto error;

            if (!skb_can_coalesce(skb, i, pfrag->page,
                                  pfrag->offset)) {
                err = -EMSGSIZE;
                if (i == MAX_SKB_FRAGS)
                    goto error;

                __skb_fill_page_desc(skb, i, pfrag->page,
                                     pfrag->offset, 0);
                skb_shinfo(skb)->nr_frags = ++i;
                get_page(pfrag->page);
            }
            copy = min_t(int, copy, pfrag->size - pfrag->offset);
            if (getfrag(from,
                        page_address(pfrag->page) + pfrag->offset,
                        offset, copy, skb->len, skb) < 0)
                goto error_efault;

            pfrag->offset += copy;
            skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
            skb->len += copy;
            skb->data_len += copy;
            skb->truesize += copy;
            wmem_alloc_delta += copy;
        } else {
            err = skb_zerocopy_iter_dgram(skb, from, copy);
            if (err < 0)
                goto error;
        }
        offset += copy;
        app_and_transport_length -= copy;
    }
    // --------------       create skb     --------------
    // --------------     error handler    --------------
    if (wmem_alloc_delta)
        refcount_add(wmem_alloc_delta, &sk->sk_wmem_alloc);
    return 0;

    error_efault:
    err = -EFAULT;
    error:
    net_zcopy_put_abort(uarg, extra_uref);
    IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
    refcount_add(wmem_alloc_delta, &sk->sk_wmem_alloc);
    return err;
    // --------------     error handler    --------------
}

// 成功检查
void lir_select_id(struct net *net, struct sk_buff *skb, struct sock *sk,
                   int segs, __u16 source_node_id, __u16 destination_node_id) {
    struct lirhdr *lir_header = lir_hdr(skb);

    /* We had many attacks based on IPID, use the private
     * generator as much as we can.
     */
    if (sk && inet_sk(sk)->inet_daddr) {
        lir_header->id = htons(inet_sk(sk)->inet_id);
        inet_sk(sk)->inet_id += segs;
        return;
    }
    if ((lir_header->frag_off & htons(IP_DF)) && !skb->ignore_df) {
        lir_header->id = 0;
    } else {
        /* Unfortunately we need the big hammer to get a suitable IPID */
        lir_select_id_core(net, lir_header, segs, source_node_id, destination_node_id);
    }
}

// 成功检查
void lir_select_id_core(struct net *net, struct lirhdr *lir_header, int segs,
                        __u16 source_node_id, __u16 destination_node_id) {
    u32 hash, id;

    /* Note the following code is not safe, but this is okay. */
    if (unlikely(siphash_key_is_zero(&net->ipv4.ip_id_key)))
        get_random_bytes(&net->ipv4.ip_id_key,
                         sizeof(net->ipv4.ip_id_key));

    hash = siphash_3u32((__force u32) source_node_id,
                        (__force u32) destination_node_id,
                        lir_header->protocol,
                        &net->ipv4.ip_id_key);
    id = ip_idents_reserve(hash, segs);
    lir_header->id = htons(id);
}

/**
 * 填充
 * @param lir_header
 * @param lir_return_data_structure
 * @param first_packet
 */
void fill_lir_header_length(struct lirhdr *lir_header,
                            struct LirReturnDataStructure *lir_return_data_structure,
                            bool first_packet) {
    lir_header->header_len = get_opt_header_total_length(lir_return_data_structure, first_packet);
    lir_header->header_len = htons(lir_header->header_len);
}

/**
 * 根据是否是 first packet 进行 version number 的设置
 * @param lir_header
 */
void set_lir_header_version(struct lirhdr *lir_header, bool first_packet) {
    if (first_packet) {
        lir_header->version = FIRST_OPT_PACKET_VERSION_NUMBER;
    } else {
        lir_header->version = OTHER_OPT_PACKET_VERSION_NUMBER;
    }
}

// 成功检查
struct sk_buff *lir_make_skb_core(struct sock *sk,
                                  struct sk_buff_head *queue,
                                  struct inet_cork *cork,
                                  struct LirReturnDataStructure *lir_return_data_structure,
                                  __u16 source_node_id,
                                  __u16 destination_node_id) {
    // --------------      initialize        --------------
    u64 start = ktime_get_real_ns();  // 获取开始的时间
    u64 time_elapsed;  // 执行的时间
    bool first_packet = get_first_packet_status(sk);
    unsigned char* payload_hash = NULL;
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct lirhdr *lir_header;
    struct net *net = sock_net(sk);
    __be16 df = 0;
    skb = __skb_dequeue(queue);
    if (!skb) {
        goto out;
    }
    tail_skb = &(skb_shinfo(skb)->frag_list);
    struct udphdr* udp_header = udp_hdr(skb); // get udp header
    // --------------      initialize        --------------

    /* move skb->data to ip header from ext header */
    if (skb->data < skb_network_header(skb))
        __skb_pull(skb, skb_network_offset(skb));
    while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
        __skb_pull(tmp_skb, skb_network_header_len(skb));
        *tail_skb = tmp_skb;
        tail_skb = &(tmp_skb->next);
        skb->len += tmp_skb->len;
        skb->data_len += tmp_skb->len;
        skb->truesize += tmp_skb->truesize;
        tmp_skb->destructor = NULL;
        tmp_skb->sk = NULL;
    }

    skb->ignore_df = ip_sk_ignore_df(sk);
    if (inet->pmtudisc == IP_PMTUDISC_DO ||
        inet->pmtudisc == IP_PMTUDISC_PROBE ||
        (skb->len <= lir_return_data_structure->output_interface->mtu))
        df = htons(IP_DF);
    lir_header = lir_hdr(skb);
    set_lir_header_version(lir_header, first_packet);
    lir_header->protocol = sk->sk_protocol; // udp upper layer protocol
    lir_header->frag_off = df;
    lir_header->source = htons(source_node_id);
    lir_header->destination = htons(destination_node_id);
    lir_header->current_path_index = htons(1);
    lir_select_id(net, skb, sk, 1, source_node_id, destination_node_id);
    fill_lir_header_length(lir_header, lir_return_data_structure, first_packet);
    // ------------------------- 计算 payload hash -----------------------------
    // 计算方式: 拿到 udp 首部之后的数据部分即可
    payload_hash = calculate_payload_hash(udp_header, net);
    // ------------------------- 计算 payload hash -----------------------------
    fill_opt_field(lir_header, lir_return_data_structure, net, first_packet, payload_hash);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = (cork->transmit_time);
    out:
    time_elapsed = ktime_get_real_ns() - start;
    printk(KERN_EMERG "opt_make_skb_time_elapsed: %llu ns\n", time_elapsed);
    return skb;
}

/**
 * 进行 opt 字段的填充
 * @param lir_header lir 网络层首部
 * @param lir_return_data_structure 路由的查找结果
 * @param current_net_namespace 当前的网络命名空间
 * @param first_packet 是否是第一个数据包
 * @param payload_hash 数据包载荷部分的哈希
 */
void fill_opt_field(struct lirhdr *lir_header,
                    struct LirReturnDataStructure *lir_return_data_structure,
                    struct net *current_net_namespace,
                    bool first_packet,
                    unsigned char* payload_hash) {
    if (first_packet) { // 处理第一个数据包
        struct RoutingTableEntry *routing_table_entry = lir_return_data_structure->routing_table_entry;  // 获取路由表项
        struct shash_desc* hash_data_structure = get_hash_data_structure(current_net_namespace);  // 计算 hash
        int length_of_path = routing_table_entry->length_of_path; // 计算长度
        int source = get_satellite_id(current_net_namespace);  // 拿到 id
        int index;  // 拿到索引
        int extension_header_length = (int)(sizeof(struct length_of_path)) + (int) ((length_of_path + 1) * (sizeof(struct single_hop_field)));  // 计算额外包头的长度
        unsigned char* extension_header_start = (unsigned char*)(&lir_header[1]); // 拿到额外包头的开始
        struct length_of_path * length_of_path_tmp = (struct length_of_path*)(extension_header_start);  //
        length_of_path_tmp->length_of_path = length_of_path;
        struct single_hop_field *opt_path = (struct single_hop_field *) (extension_header_start + sizeof(struct length_of_path));
        opt_path[0].node_id = source; // 第一个存源节点 id
        opt_path[0].link_identifier = routing_table_entry->link_identifiers[0]; // 然后存链路标识
        for (index = 0; index < length_of_path - 1; index++) {
            opt_path[index + 1].node_id = routing_table_entry->node_ids[index];
            opt_path[index + 1].link_identifier = routing_table_entry->link_identifiers[index + 1];
        }
        opt_path[length_of_path].node_id = routing_table_entry->node_ids[length_of_path - 1];
        opt_path[length_of_path].link_identifier = -1;
        unsigned char* path_hash = calculate_fixed_length_hash(hash_data_structure, extension_header_start, extension_header_length);
        // print_hash_or_hmac_result(path_hash, HASH_OUTPUT_LENGTH_IN_BYTES);
        kfree(path_hash);
    } else { // 处理其他的数据包
        struct RoutingTableEntry* routing_table_entry = lir_return_data_structure->routing_table_entry;  // 从路由查找结果之中获取路由表项
        int length_of_path = routing_table_entry->length_of_path;  // 获取路径长度
        int final_node = routing_table_entry->node_ids[routing_table_entry->length_of_path-1]; // 获取路径最后一个节点id

        struct LirDataStructure* lir_data_structure = get_lir_data_structure(current_net_namespace); // 获取在 namespace 之中的 LiRDataStructure
        struct shash_desc* hmac_data_structure = lir_data_structure->hmac_data_structure; // 获取 hmac_data_structure
        int current_satellite_id = lir_data_structure->satellite_id; // 获取当前卫星id

        int pvf_size = sizeof(struct path_validation_field);  // pvf 字段的长度 (单位为字节)
        int opvs_size = sizeof(struct origin_path_validation_field) * length_of_path; // ovfs 字段的长度 (单位为字节)
        struct path_validation_field* pvf = (struct path_validation_field*)kmalloc(pvf_size, GFP_KERNEL); // 为 pvf 分配内存
        struct origin_path_validation_field* opvs = (struct origin_path_validation_field*)kmalloc(opvs_size, GFP_KERNEL); // 为 opvs 分配内存

        // assume there are four nodes and length of path = 3
        // A---->B---->C---->D node ids = [B,C,D].
        // --------------------------------initialize pvf--------------------------------
        char key_from_source_to_end[20];

        sprintf(key_from_source_to_end, "key-%d-%d", current_satellite_id, final_node);
        unsigned char* pvf0_hmac_result = calculate_hmac(hmac_data_structure,
                                                    payload_hash,
                                                    HASH_OUTPUT_LENGTH_IN_BYTES,
                                                    key_from_source_to_end);
        memcpy(pvf, pvf0_hmac_result, OPT_VALIDATION_SIZE_IN_BYTES); // 将计算出来的 hmac 结果拷贝, pvf0 = MACKD(DATAHASH)
        // print_hash_or_hmac_result((unsigned char *) pvf, OPT_VALIDATION_SIZE_IN_BYTES);
        // --------------------------------initialize pvf--------------------------------
        // --------------------------------initialize opvs-------------------------------
        int index;
        // there are three opvs for B,C,D
        for(index = 0; index < length_of_path; index++){
            char key_from_source_to_intermediate[20];
            sprintf(key_from_source_to_intermediate, "key-%d-%d", current_satellite_id, routing_table_entry->node_ids[index]);
            unsigned char* pvfi_hmac_result;
            if (index == 0){  // 如果是第一个，则要用到 PVF0
                // PVF1 = MACKB(MACKD(DATAHASH))
                pvfi_hmac_result = calculate_hmac(hmac_data_structure,
                                                                 pvf0_hmac_result,
                                                                 OPT_VALIDATION_SIZE_IN_BYTES,
                                                                 key_from_source_to_intermediate);
                // COPY the PVF1 to the OPV[0] || and when intermediate satellite receive it, it simply applies the MACK1(PVF0) then can verify the result
                memcpy(&opvs[index], pvfi_hmac_result, OPT_VALIDATION_SIZE_IN_BYTES); // HMAC_OUTPUT_LENGTH_IN_BYTES = 32 bytes || OPT_VALIDATION_SIZE_IN_BYTES=16 bytes
                // PVF0 is utilized, then we can free the memory.
                kfree(pvf0_hmac_result);
            } else if (index == (length_of_path - 1)){ // 如果是最后一个记得要释放 pvf_new_hmac_result
                // PVF3 = MACKC(PVF1)
                unsigned char* pvf_new_hmac_result = calculate_hmac(hmac_data_structure,
                                                                    pvfi_hmac_result,
                                                                    OPT_VALIDATION_SIZE_IN_BYTES,
                                                                    key_from_source_to_intermediate);
                // OPV[2] = MACKD(PVF2)
                memcpy(&opvs[index], pvf_new_hmac_result, OPT_VALIDATION_SIZE_IN_BYTES);
                // PVF2 is utilized , then we can free the memory
                kfree(pvfi_hmac_result);
                kfree(pvf_new_hmac_result);
            } else { // 如果不是第一个也不是最后一个
                // PVF2 = MACKC(PVF1)
                unsigned char* pvf_new_hmac_result = calculate_hmac(hmac_data_structure,
                                                                    pvfi_hmac_result,
                                                                    OPT_VALIDATION_SIZE_IN_BYTES,
                                                                    key_from_source_to_intermediate);
                // OPV[1] = PVF2
                memcpy(&opvs[index], pvf_new_hmac_result, OPT_VALIDATION_SIZE_IN_BYTES);
                // PVF1 is utilized , then we can free the memory
                kfree(pvfi_hmac_result);
                pvfi_hmac_result = pvf_new_hmac_result;
            }
        }
        // --------------------------------initialize opvs-------------------------------
        // --------------------------------initialize ovfs-------------------------------
        //        int index;
        //        for(index = 0; index < length_of_path; index++){
        //            char key_from_source_to_intermediate[20];
        //            sprintf(key_from_source_to_intermediate, "key-%d-%d", current_satellite_id, routing_table_entry->node_ids[index]);
        //            unsigned char* hmac_result_new = calculate_hmac(hmac_data_structure,
        //                                                            payload_hash,
        //                                                            HASH_OUTPUT_LENGTH_IN_BYTES,
        //                                                            key_from_source_to_intermediate);
        //            memcpy(&ovfs[index], hmac_result_new, OPT_VALIDATION_SIZE_IN_BYTES);
        //            kfree(hmac_result_new);
        //        }
        //        kfree(payload_hash);  // 用完了数据包载荷部分的哈希就将其进行释放
        // --------------------------------initialize ovfs-------------------------------
        // ----------------------------place into lirheader------------------------------
        unsigned char* copy_source = (unsigned char*)(pvf);
        unsigned char* copy_destination = ((unsigned char*)lir_header) + sizeof(struct lirhdr);
        memcpy(copy_destination, copy_source, pvf_size);

        copy_source = (unsigned char*)(opvs);
        copy_destination = ((unsigned char*)lir_header) + sizeof(struct lirhdr) + pvf_size;
        memcpy(copy_destination, copy_source, opvs_size);
        // ----------------------------place into lirheader------------------------------
        kfree(pvf);
        kfree(opvs);
    }
}

int lir_send_skb(struct net *net, struct sk_buff *skb, struct net_device *output_dev) {
    int err;
    struct lirhdr *lir_header = lir_hdr(skb);
    struct sock *sk = skb->sk;

    lir_header->total_len = htons(skb->len);
    lir_send_check(lir_header);

    skb->protocol = htons(ETH_P_IP);
    err = lir_ip_output(net, sk, skb, output_dev);

    if (err) {
        if (err > 0)
            err = net_xmit_errno(err);
        if (err)
            IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
    }

    return err;
}

// for length we need to modify two locations

// first place: fragment header length must be correct: it represents for the total network header length
// second place: the header_len field in lir_header