//
// Created by zhf on 24-4-3.
//
#include <net/busy_poll.h>
#include <trace/events/tcp.h>
#include "headers/tools.h"
#include "headers/ftrace_hook_api.h"
#include "headers/self_defined_tcp_v4_do_rcv.h"
#include "headers/self_defined_tcp_rcv_established.h"

extern asmlinkage void (*orig_tcp_v4_send_reset)(const struct sock *sk, struct sk_buff *skb);

extern asmlinkage struct sock *(*orig_cookie_v4_check)(struct sock *sk, struct sk_buff *skb);

void resolve_tcp_v4_do_rcv_inner_function_address(void){
    LOG_WITH_EDGE("start to resolve tcp_v4_do_rcv inner function address");
    LOG_WITH_EDGE("end to resolve tcp_v4_do_rcv inner function address");
}

// ------------------------- static ------------------------------

static struct sock *tcp_v4_cookie_check(struct sock *sk, struct sk_buff *skb)
{
#ifdef CONFIG_SYN_COOKIES
    const struct tcphdr *th = tcp_hdr(skb);

    if (!th->syn)
        sk = orig_cookie_v4_check(sk, skb);
#endif
    return sk;
}

// ------------------------- static ------------------------------

int self_defined_tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb, const struct tcphdr* th){
    enum skb_drop_reason reason;
    struct sock *rsk;

    if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */

        struct dst_entry *dst;

        dst = rcu_dereference_protected(sk->sk_rx_dst,
                                        lockdep_sock_is_held(sk));

        sock_rps_save_rxhash(sk, skb);
        sk_mark_napi_id(sk, skb);
        if (dst) {
            if (sk->sk_rx_dst_ifindex != skb->skb_iif ||
                !INDIRECT_CALL_1(dst->ops->check, ipv4_dst_check,
                                 dst, 0)) {
                RCU_INIT_POINTER(sk->sk_rx_dst, NULL);
                dst_release(dst);
            }
        }

        self_defined_tcp_rcv_established(sk, skb);
        return 0;
    }

    reason = SKB_DROP_REASON_NOT_SPECIFIED;
    if (tcp_checksum_complete(skb))
        goto csum_err;

    if (sk->sk_state == TCP_LISTEN) {
        struct sock *nsk = tcp_v4_cookie_check(sk, skb);

        if (!nsk)
            goto discard;
        if (nsk != sk) {
            if (tcp_child_process(sk, nsk, skb)) {
                rsk = nsk;
                goto reset;
            }
            return 0;
        }
    } else
        sock_rps_save_rxhash(sk, skb);

    if (tcp_rcv_state_process(sk, skb)) {
        rsk = sk;
        goto reset;
    }
    return 0;

    reset:
    orig_tcp_v4_send_reset(rsk, skb);
    discard:
    kfree_skb_reason(skb, reason);
    /* Be careful here. If this function gets more complicated and
     * gcc suffers from register pressure on the x86, sk (in %ebx)
     * might be destroyed here. This current version compiles correctly,
     * but you have been warned.
     */
    return 0;

    csum_err:
    reason = SKB_DROP_REASON_TCP_CSUM;
    trace_tcp_bad_csum(skb);
    TCP_INC_STATS(sock_net(sk), TCP_MIB_CSUMERRORS);
    TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
    goto discard;
}