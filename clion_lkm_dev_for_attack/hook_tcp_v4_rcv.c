//
// Created by zhf on 24-3-16.
//

#include <net/ip.h>
#include <net/tcp.h>
#include <net/xfrm.h>
#include <trace/events/tcp.h>
#include "headers/tools.h"
#include "headers/hook_tcp_v4_rcv.h"
#include "headers/self_defined_tcp_v4_do_rcv.h"

asmlinkage void (*orig_tcp_v4_fill_cb)(struct sk_buff *skb, const struct iphdr *iph,const struct tcphdr *th);
asmlinkage void (*orig_tcp_v4_restore_cb)(struct sk_buff *skb);
asmlinkage void (*orig_tcp_v4_send_reset)(const struct sock *sk, struct sk_buff *skb);
asmlinkage void (*orig_tcp_v4_send_ack)(const struct sock *sk,
                                       struct sk_buff *skb, u32 seq, u32 ack,
                                       u32 win, u32 tsval, u32 tsecr, int oif,
                                       struct tcp_md5sig_key *key,
                                       int reply_flags, u8 tos);
asmlinkage struct sock *(*orig_cookie_v4_check)(struct sock *sk, struct sk_buff *skb);
asmlinkage int (*orig_tcp_v4_rcv)(struct sk_buff* skb);

DEFINE_STATIC_KEY_FALSE(ip4_min_ttl);

void resolve_tcp_v4_rcv_inner_functions_address(void){
    LOG_WITH_EDGE("start to resolve tcp_v4_rcv inner functions");
    orig_tcp_v4_fill_cb = get_function_address("tcp_v4_fill_cb");
    LOG_RESOLVED(orig_tcp_v4_fill_cb, "tcp_v4_fill_cb");
    orig_tcp_v4_restore_cb = get_function_address("tcp_v4_restore_cb");
    LOG_RESOLVED(orig_tcp_v4_restore_cb, "tcp_v4_restore_cb");
    orig_tcp_v4_send_reset = get_function_address("tcp_v4_send_reset");
    LOG_RESOLVED(orig_tcp_v4_send_reset, "tcp_v4_send_reset");
    orig_tcp_v4_send_ack = get_function_address("tcp_v4_send_ack");
    LOG_RESOLVED(orig_tcp_v4_send_ack, "tcp_v4_send_ack");
    orig_cookie_v4_check = get_function_address("cookie_v4_check");
    LOG_RESOLVED(orig_cookie_v4_check, "cookie_v4_check");
    LOG_WITH_EDGE("end to resolve tcp_v4_rcv inner functions");
}

asmlinkage int hook_tcp_v4_rcv(struct sk_buff*skb){
    return ip_self_defined_tcp_v4_rcv(skb);
}

void add_tcp_v4_do_rcv_to_hook(void){
    hooks[number_of_hook].name = "tcp_v4_rcv";
    hooks[number_of_hook].function = hook_tcp_v4_rcv;
    hooks[number_of_hook].original = &orig_tcp_v4_rcv;
    number_of_hook += 1;
}


// ------------------------------ static -----------------------------------
static void tcp_v4_timewait_ack(struct sock *sk, struct sk_buff *skb)
{
    struct inet_timewait_sock *tw = inet_twsk(sk);
    struct tcp_timewait_sock *tcptw = tcp_twsk(sk);

    orig_tcp_v4_send_ack(sk, skb,
                    tcptw->tw_snd_nxt, tcptw->tw_rcv_nxt,
                    tcptw->tw_rcv_wnd >> tw->tw_rcv_wscale,
                    tcp_time_stamp_raw() + tcptw->tw_ts_offset,
                    tcptw->tw_ts_recent,
                    tw->tw_bound_dev_if,
                    tcp_twsk_md5_key(tcptw),
                    tw->tw_transparent ? IP_REPLY_ARG_NOSRCCHECK : 0,
                    tw->tw_tos
    );

    inet_twsk_put(tw);
}

// ------------------------------ static -----------------------------------
int ip_self_defined_tcp_v4_rcv(struct sk_buff *skb)
{
    struct net *net = dev_net(skb->dev);
    enum skb_drop_reason drop_reason;
    int sdif = inet_sdif(skb);
    int dif = inet_iif(skb);
    const struct iphdr *iph;
    const struct tcphdr *th;
    bool refcounted;
    struct sock *sk;
    int ret;


    drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
    if (skb->pkt_type != PACKET_HOST)
        goto discard_it;

    /* Count it even if it's bad */
    __TCP_INC_STATS(net, TCP_MIB_INSEGS);

    if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
        goto discard_it;

    th = (const struct tcphdr *)skb->data;

    if (unlikely(th->doff < sizeof(struct tcphdr) / 4)) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        goto bad_packet;
    }
    if (!pskb_may_pull(skb, th->doff * 4))
        goto discard_it;

    /* An explanation is required here, I think.
     * Packet length and doff are validated by header prediction,
     * provided case of th->doff==0 is eliminated.
     * So, we defer the checks. */

    if (skb_checksum_init(skb, IPPROTO_TCP, inet_compute_pseudo))
        goto csum_error;

    th = (const struct tcphdr *)skb->data;
    iph = ip_hdr(skb);
    lookup:
    sk = __inet_lookup_skb(&tcp_hashinfo, skb, __tcp_hdrlen(th), th->source,
                           th->dest, sdif, &refcounted);


    if (!sk){
        goto no_tcp_socket;
    }


    process:
    if (sk->sk_state == TCP_TIME_WAIT)
        goto do_time_wait;

    if (sk->sk_state == TCP_NEW_SYN_RECV) {
        struct request_sock *req = inet_reqsk(sk);
        bool req_stolen = false;
        struct sock *nsk;

        sk = req->rsk_listener;
        if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
            drop_reason = SKB_DROP_REASON_XFRM_POLICY;
        else
            drop_reason = tcp_inbound_md5_hash(sk, skb,
                                               &iph->saddr, &iph->daddr,
                                               AF_INET, dif, sdif);
        if (unlikely(drop_reason)) {
            sk_drops_add(sk, skb);
            reqsk_put(req);
            goto discard_it;
        }
        if (tcp_checksum_complete(skb)) {
            reqsk_put(req);
            goto csum_error;
        }
        if (unlikely(sk->sk_state != TCP_LISTEN)) {
            nsk = reuseport_migrate_sock(sk, req_to_sk(req), skb);
            if (!nsk) {
                inet_csk_reqsk_queue_drop_and_put(sk, req);
                goto lookup;
            }
            sk = nsk;
            /* reuseport_migrate_sock() has already held one sk_refcnt
             * before returning.
             */
        } else {
            /* We own a reference on the listener, increase it again
             * as we might lose it too soon.
             */
            sock_hold(sk);
        }
        refcounted = true;
        nsk = NULL;
        if (!tcp_filter(sk, skb)) {
            th = (const struct tcphdr *)skb->data;
            iph = ip_hdr(skb);
            orig_tcp_v4_fill_cb(skb, iph, th);
            nsk = tcp_check_req(sk, skb, req, false, &req_stolen);
        } else {
            drop_reason = SKB_DROP_REASON_SOCKET_FILTER;
        }
        if (!nsk) {
            reqsk_put(req);
            if (req_stolen) {
                /* Another cpu got exclusive access to req
                 * and created a full blown socket.
                 * Try to feed this packet to this socket
                 * instead of discarding it.
                 */
                orig_tcp_v4_restore_cb(skb);
                sock_put(sk);
                goto lookup;
            }
            goto discard_and_relse;
        }
        nf_reset_ct(skb);
        if (nsk == sk) {
            reqsk_put(req);
            orig_tcp_v4_restore_cb(skb);
        } else if (tcp_child_process(sk, nsk, skb)) {
            orig_tcp_v4_send_reset(nsk, skb);
            goto discard_and_relse;
        } else {
            sock_put(sk);
            return 0;
        }
    }

    if (static_branch_unlikely(&ip4_min_ttl)) {
        /* min_ttl can be changed concurrently from do_ip_setsockopt() */
        if (unlikely(iph->ttl < READ_ONCE(inet_sk(sk)->min_ttl))) {
            __NET_INC_STATS(net, LINUX_MIB_TCPMINTTLDROP);
            LOG_WITH_PREFIX("__NET_INC_STATS(net, LINUX_MIB_TCPMINTTLDROP); dropped");
            goto discard_and_relse;
        }
    }

    if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb)) {
        drop_reason = SKB_DROP_REASON_XFRM_POLICY;
        LOG_WITH_PREFIX("xfrm4_policy_check dropped");
        goto discard_and_relse;
    }

    drop_reason = tcp_inbound_md5_hash(sk, skb, &iph->saddr,
                                       &iph->daddr, AF_INET, dif, sdif);
    if (drop_reason){
        LOG_WITH_PREFIX("tcp_inbound_md5_hash dropped");
        goto discard_and_relse;
    }


    nf_reset_ct(skb);

    if (tcp_filter(sk, skb)) {
        drop_reason = SKB_DROP_REASON_SOCKET_FILTER;
        goto discard_and_relse;
    }
    th = (const struct tcphdr *)skb->data;
    iph = ip_hdr(skb);
    orig_tcp_v4_fill_cb(skb, iph, th);

    skb->dev = NULL;

    if (sk->sk_state == TCP_LISTEN) {
        ret = self_defined_tcp_v4_do_rcv(sk, skb, th);
        goto put_and_return;
    }

    sk_incoming_cpu_update(sk);

    bh_lock_sock_nested(sk);
    tcp_segs_in(tcp_sk(sk), skb);
    ret = 0;
    if (!sock_owned_by_user(sk)) {
        ret = self_defined_tcp_v4_do_rcv(sk, skb, th);
    } else {
        if (tcp_add_backlog(sk, skb, &drop_reason))
            goto discard_and_relse;
    }
    bh_unlock_sock(sk);

    put_and_return:
    if (refcounted)
        sock_put(sk);

    return ret;

    no_tcp_socket:
    drop_reason = SKB_DROP_REASON_NO_SOCKET;
    if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
        goto discard_it;

    orig_tcp_v4_fill_cb(skb, iph, th);

    if (tcp_checksum_complete(skb)) {
        csum_error:
        drop_reason = SKB_DROP_REASON_TCP_CSUM;
        trace_tcp_bad_csum(skb);
        __TCP_INC_STATS(net, TCP_MIB_CSUMERRORS);
        bad_packet:
        __TCP_INC_STATS(net, TCP_MIB_INERRS);
    } else {
        orig_tcp_v4_send_reset(NULL, skb);
    }

    discard_it:
    SKB_DR_OR(drop_reason, NOT_SPECIFIED);
    /* Discard frame. */
    kfree_skb_reason(skb, drop_reason);
    return 0;

    discard_and_relse:
    sk_drops_add(sk, skb);
    if (refcounted)
        sock_put(sk);
    goto discard_it;

    do_time_wait:
    if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
        drop_reason = SKB_DROP_REASON_XFRM_POLICY;
        inet_twsk_put(inet_twsk(sk));
        goto discard_it;
    }

    orig_tcp_v4_fill_cb(skb, iph, th);

    if (tcp_checksum_complete(skb)) {
        inet_twsk_put(inet_twsk(sk));
        goto csum_error;
    }
    switch (tcp_timewait_state_process(inet_twsk(sk), skb, th)) {
        case TCP_TW_SYN: {
            struct sock *sk2 = inet_lookup_listener(dev_net(skb->dev),
                                                    &tcp_hashinfo, skb,
                                                    __tcp_hdrlen(th),
                                                    iph->saddr, th->source,
                                                    iph->daddr, th->dest,
                                                    inet_iif(skb),
                                                    sdif);
            if (sk2) {
                inet_twsk_deschedule_put(inet_twsk(sk));
                sk = sk2;
                orig_tcp_v4_restore_cb(skb);
                refcounted = false;
                goto process;
            }
        }
            /* to ACK */
            fallthrough;
        case TCP_TW_ACK:
            tcp_v4_timewait_ack(sk, skb);
            break;
        case TCP_TW_RST:
            orig_tcp_v4_send_reset(sk, skb);
            inet_twsk_deschedule_put(inet_twsk(sk));
            goto discard_it;
        case TCP_TW_SUCCESS:;
    }
    goto discard_it;
}