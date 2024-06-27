//
// Created by zhf on 24-4-3.
//
#include <linux/rcupdate.h>
#include <trace/events/tcp.h>
#include "headers/tools.h"
#include "headers/ftrace_hook_api.h"
#include "headers/self_defined_tcp_rcv_established.h"

asmlinkage int (*orig_tcp_ack)(struct sock *sk, const struct sk_buff *skb, int flag);
asmlinkage bool (*orig_tcp_try_coalesce)(struct sock *sk, struct sk_buff *to, struct sk_buff *from, bool *fragstolen);
asmlinkage void (*orig_tcp_event_data_recv)(struct sock *sk, struct sk_buff *skb);
asmlinkage void (*orig__tcp_ack_snd_check)(struct sock *sk, int ofo_possible);
asmlinkage void (*orig_tcp_urg)(struct sock *sk, struct sk_buff *skb, const struct tcphdr *th);
asmlinkage void (*orig_tcp_data_queue)(struct sock *sk, struct sk_buff *skb);
asmlinkage void (*orig_tcp_fastopen_active_disable)(struct sock *sk);
asmlinkage void (*orig__tcp_push_pending_frames)(struct sock *sk, unsigned int cur_mss,
                                          int nonagle);
asmlinkage void (*orig_tcp_send_ack)(struct sock *sk);
asmlinkage void (*orig_tcp_mstamp_refresh)(struct tcp_sock *tp);
asmlinkage void (*orig_tcp_data_ready)(struct sock *sk);
asmlinkage unsigned int (*orig_tcp_current_mss)(struct sock *sk);
asmlinkage void (*orig_tcp_check_space)(struct sock *sk);
asmlinkage void (*orig_tcp_reset)(struct sock *sk, struct sk_buff *skb);
asmlinkage bool (*orig_tcp_oow_rate_limited)(struct net *net, const struct sk_buff *skb,
                                             int mib_idx, u32 *last_oow_ack_time);

void resolve_self_defined_tcp_rcv_established_inner_functions_address(void){
    LOG_WITH_EDGE("start to resolve self_defined_tcp_rcv_established inner functions address");
    orig_tcp_oow_rate_limited = get_function_address("tcp_oow_rate_limited");
    LOG_RESOLVED(orig_tcp_oow_rate_limited, "tcp_oow_rate_limited");
    orig_tcp_reset = get_function_address("tcp_reset");
    LOG_RESOLVED(orig_tcp_reset, "tcp_reset");
    orig_tcp_check_space = get_function_address("tcp_check_space");
    LOG_RESOLVED(orig_tcp_check_space, "tcp_check_space");
    orig_tcp_current_mss = get_function_address("tcp_current_mss");
    LOG_RESOLVED(orig_tcp_current_mss, "tcp_current_mss");
    orig_tcp_data_ready = get_function_address("tcp_data_ready");
    LOG_RESOLVED(orig_tcp_data_ready, "tcp_data_ready");
    orig_tcp_mstamp_refresh = get_function_address("tcp_mstamp_refresh");
    LOG_RESOLVED(orig_tcp_mstamp_refresh, "tcp_mstamp_refresh");
    orig_tcp_send_ack = get_function_address("tcp_send_ack");
    LOG_RESOLVED(orig_tcp_send_ack, "tcp_send_ack");
    orig__tcp_push_pending_frames = get_function_address("__tcp_push_pending_frames");
    LOG_RESOLVED(orig__tcp_push_pending_frames, "__tcp_push_pending_frames");
    orig_tcp_fastopen_active_disable = get_function_address("tcp_fastopen_active_disable");
    LOG_RESOLVED(orig_tcp_fastopen_active_disable, "tcp_fastopen_active_disable");
    orig_tcp_ack = get_function_address("tcp_ack");
    LOG_RESOLVED(orig_tcp_ack, "tcp_ack");
    orig_tcp_try_coalesce = get_function_address("tcp_try_coalesce");
    LOG_RESOLVED(orig_tcp_try_coalesce, "tcp_try_coalesce");
    orig_tcp_event_data_recv = get_function_address("tcp_event_data_recv");
    LOG_RESOLVED(orig_tcp_event_data_recv, "tcp_event_data_recv");
    orig__tcp_ack_snd_check = get_function_address("__tcp_ack_snd_check");
    LOG_RESOLVED(orig__tcp_ack_snd_check, "__tcp_ack_snd_check");
    orig_tcp_urg = get_function_address("tcp_urg");
    LOG_RESOLVED(orig_tcp_urg, "tcp_urg");
    orig_tcp_data_queue = get_function_address("tcp_data_queue");
    LOG_RESOLVED(orig_tcp_data_queue, "tcp_data_queue");
    LOG_WITH_EDGE("end to resolve self_defined_tcp_rcv_established inner functions address");
}

// ------------------------------------- static -------------------------------------
static inline void tcp_ack_snd_check(struct sock *sk)
{
    if (!inet_csk_ack_scheduled(sk)) {
        /* We sent a data segment already. */
        return;
    }
    orig__tcp_ack_snd_check(sk, 1);
}

static bool tcp_parse_aligned_timestamp(struct tcp_sock *tp, const struct tcphdr *th)
{
    const __be32 *ptr = (const __be32 *)(th + 1);

    if (*ptr == htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16)
                      | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP)) {
        tp->rx_opt.saw_tstamp = 1;
        ++ptr;
        tp->rx_opt.rcv_tsval = ntohl(*ptr);
        ++ptr;
        if (*ptr)
            tp->rx_opt.rcv_tsecr = ntohl(*ptr) - tp->tsoffset;
        else
            tp->rx_opt.rcv_tsecr = 0;
        return true;
    }
    return false;
}

/* Fast parse options. This hopes to only see timestamps.
 * If it is wrong it falls back on tcp_parse_options().
 */
static bool tcp_fast_parse_options(const struct net *net,
                                   const struct sk_buff *skb,
                                   const struct tcphdr *th, struct tcp_sock *tp)
{
    /* In the spirit of fast parsing, compare doff directly to constant
     * values.  Because equality is used, short doff can be ignored here.
     */
    if (th->doff == (sizeof(*th) / 4)) {
        tp->rx_opt.saw_tstamp = 0;
        return false;
    } else if (tp->rx_opt.tstamp_ok &&
               th->doff == ((sizeof(*th) + TCPOLEN_TSTAMP_ALIGNED) / 4)) {
        if (tcp_parse_aligned_timestamp(tp, th))
            return true;
    }

    tcp_parse_options(net, skb, &tp->rx_opt, 1, NULL);
    if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr)
        tp->rx_opt.rcv_tsecr -= tp->tsoffset;

    return true;
}

static void tcp_drop_reason(struct sock *sk, struct sk_buff *skb,
                            enum skb_drop_reason reason)
{
    sk_drops_add(sk, skb);
    kfree_skb_reason(skb, reason);
}

static inline bool tcp_may_update_window(const struct tcp_sock *tp,
                                         const u32 ack, const u32 ack_seq,
                                         const u32 nwin)
{
    return	after(ack, tp->snd_una) ||
              after(ack_seq, tp->snd_wl1) ||
              (ack_seq == tp->snd_wl1 && nwin > tp->snd_wnd);
}

static int tcp_disordered_ack(const struct sock *sk, const struct sk_buff *skb)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    const struct tcphdr *th = tcp_hdr(skb);
    u32 seq = TCP_SKB_CB(skb)->seq;
    u32 ack = TCP_SKB_CB(skb)->ack_seq;

    return (/* 1. Pure ACK with correct sequence number. */
            (th->ack && seq == TCP_SKB_CB(skb)->end_seq && seq == tp->rcv_nxt) &&

            /* 2. ... and duplicate ACK. */
            ack == tp->snd_una &&

            /* 3. ... and does not update window. */
            !tcp_may_update_window(tp, ack, seq, ntohs(th->window) << tp->rx_opt.snd_wscale) &&

            /* 4. ... and sits in replay window. */
            (s32)(tp->rx_opt.ts_recent - tp->rx_opt.rcv_tsval) <= (inet_csk(sk)->icsk_rto * 1024) / HZ);
}

static inline bool tcp_paws_discard(const struct sock *sk,
                                    const struct sk_buff *skb)
{
    const struct tcp_sock *tp = tcp_sk(sk);

    return !tcp_paws_check(&tp->rx_opt, TCP_PAWS_WINDOW) &&
           !tcp_disordered_ack(sk, skb);
}

static void tcp_rcv_spurious_retrans(struct sock *sk, const struct sk_buff *skb)
{
    /* When the ACK path fails or drops most ACKs, the sender would
     * timeout and spuriously retransmit the same segment repeatedly.
     * The receiver remembers and reflects via DSACKs. Leverage the
     * DSACK state and change the txhash to re-route speculatively.
     */
    if (TCP_SKB_CB(skb)->seq == tcp_sk(sk)->duplicate_sack[0].start_seq &&
        sk_rethink_txhash(sk))
        NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPDUPLICATEDATAREHASH);
}

static bool tcp_reset_check(const struct sock *sk, const struct sk_buff *skb)
{
    struct tcp_sock *tp = tcp_sk(sk);
    return unlikely(TCP_SKB_CB(skb)->seq == (tp->rcv_nxt - 1) &&
                    (1 << sk->sk_state) & (TCPF_CLOSE_WAIT | TCPF_LAST_ACK |
                                           TCPF_CLOSING));
}

static void tcp_dsack_set(struct sock *sk, u32 seq, u32 end_seq)
{
    struct tcp_sock *tp = tcp_sk(sk);

    if (tcp_is_sack(tp) && READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_dsack)) {
        int mib_idx;

        if (before(seq, tp->rcv_nxt))
            mib_idx = LINUX_MIB_TCPDSACKOLDSENT;
        else
            mib_idx = LINUX_MIB_TCPDSACKOFOSENT;

        NET_INC_STATS(sock_net(sk), mib_idx);

        tp->rx_opt.dsack = 1;
        tp->duplicate_sack[0].start_seq = seq;
        tp->duplicate_sack[0].end_seq = end_seq;
    }
}

static void bpf_skops_parse_hdr(struct sock *sk, struct sk_buff *skb)
{
    bool unknown_opt = tcp_sk(sk)->rx_opt.saw_unknown &&
                       BPF_SOCK_OPS_TEST_FLAG(tcp_sk(sk),
                                              BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG);
    bool parse_all_opt = BPF_SOCK_OPS_TEST_FLAG(tcp_sk(sk),
                                                BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG);
    struct bpf_sock_ops_kern sock_ops;

    if (likely(!unknown_opt && !parse_all_opt))
        return;

    /* The skb will be handled in the
     * bpf_skops_established() or
     * bpf_skops_write_hdr_opt().
     */
    switch (sk->sk_state) {
        case TCP_SYN_RECV:
        case TCP_SYN_SENT:
        case TCP_LISTEN:
            return;
    }

    sock_owned_by_me(sk);

    memset(&sock_ops, 0, offsetof(struct bpf_sock_ops_kern, temp));
    sock_ops.op = BPF_SOCK_OPS_PARSE_HDR_OPT_CB;
    sock_ops.is_fullsock = 1;
    sock_ops.sk = sk;
    bpf_skops_init_skb(&sock_ops, skb, tcp_hdrlen(skb));

    BPF_CGROUP_RUN_PROG_SOCK_OPS(&sock_ops);
}


static void tcp_send_dupack(struct sock *sk, const struct sk_buff *skb)
{
    struct tcp_sock *tp = tcp_sk(sk);

    if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
        before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
        NET_INC_STATS(sock_net(sk), LINUX_MIB_DELAYEDACKLOST);
        tcp_enter_quickack_mode(sk, TCP_MAX_QUICKACKS);

        if (tcp_is_sack(tp) && READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_dsack)) {
            u32 end_seq = TCP_SKB_CB(skb)->end_seq;

            tcp_rcv_spurious_retrans(sk, skb);
            if (after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt))
                end_seq = tp->rcv_nxt;
            tcp_dsack_set(sk, TCP_SKB_CB(skb)->seq, end_seq);
        }
    }

    orig_tcp_send_ack(sk);
}

static inline bool tcp_sequence(const struct tcp_sock *tp, u32 seq, u32 end_seq)
{
    return	!before(end_seq, tp->rcv_wup) &&
              !after(seq, tp->rcv_nxt + tcp_receive_window(tp));
}

static bool __tcp_oow_rate_limited(struct net *net, int mib_idx,
                                   u32 *last_oow_ack_time)
{
    if (*last_oow_ack_time) {
        s32 elapsed = (s32)(tcp_jiffies32 - *last_oow_ack_time);

        if (0 <= elapsed &&
            elapsed < READ_ONCE(net->ipv4.sysctl_tcp_invalid_ratelimit)) {
            NET_INC_STATS(net, mib_idx);
            return true;	/* rate-limited: don't send yet! */
        }
    }

    *last_oow_ack_time = tcp_jiffies32;

    return false;	/* not rate-limited: go ahead, send dupack now! */
}

/* RFC 5961 7 [ACK Throttling] */
static void tcp_send_challenge_ack(struct sock *sk)
{
    /* unprotected vars, we dont care of overwrites */
    static u32 challenge_timestamp;
    static unsigned int challenge_count;
    struct tcp_sock *tp = tcp_sk(sk);
    struct net *net = sock_net(sk);
    u32 count, now;

    /* First check our per-socket dupack rate limit. */
    if (__tcp_oow_rate_limited(net,
                               LINUX_MIB_TCPACKSKIPPEDCHALLENGE,
                               &tp->last_oow_ack_time))
        return;

    /* Then check host-wide RFC 5961 rate limit. */
    now = jiffies / HZ;
    if (now != challenge_timestamp) {
        u32 ack_limit = READ_ONCE(net->ipv4.sysctl_tcp_challenge_ack_limit);
        u32 half = (ack_limit + 1) >> 1;

        challenge_timestamp = now;
        WRITE_ONCE(challenge_count, half + prandom_u32_max(ack_limit));
    }
    count = READ_ONCE(challenge_count);
    if (count > 0) {
        WRITE_ONCE(challenge_count, count - 1);
        NET_INC_STATS(net, LINUX_MIB_TCPCHALLENGEACK);
        orig_tcp_send_ack(sk);
    }
}

/* Does PAWS and seqno based validation of an incoming segment, flags will
 * play significant role here.
 */
static bool tcp_validate_incoming(struct sock *sk, struct sk_buff *skb,
                                  const struct tcphdr *th, int syn_inerr)
{
    struct tcp_sock *tp = tcp_sk(sk);
    SKB_DR(reason);

//    if(th->rst){
//        LOG_WITH_PREFIX("RST INTO TCP_VALIDATE_INCOMING");
//    }

    /* RFC1323: H1. Apply PAWS check first. */
    if (tcp_fast_parse_options(sock_net(sk), skb, th, tp) &&
        tp->rx_opt.saw_tstamp &&
        tcp_paws_discard(sk, skb)) {
        if (!th->rst) {
            NET_INC_STATS(sock_net(sk), LINUX_MIB_PAWSESTABREJECTED);
            if (!orig_tcp_oow_rate_limited(sock_net(sk), skb,
                                      LINUX_MIB_TCPACKSKIPPEDPAWS,
                                      &tp->last_oow_ack_time))
                tcp_send_dupack(sk, skb);
            SKB_DR_SET(reason, TCP_RFC7323_PAWS);
            goto discard;
        }
        /* Reset is accepted even if it did not pass PAWS. */
    }

    /* Step 1: check sequence number */
    if (!tcp_sequence(tp, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq)) {
        /* RFC793, page 37: "In all states except SYN-SENT, all reset
         * (RST) segments are validated by checking their SEQ-fields."
         * And page 69: "If an incoming segment is not acceptable,
         * an acknowledgment should be sent in reply (unless the RST
         * bit is set, if so drop the segment and return)".
         */
        if (!th->rst) {
            if (th->syn)
                goto syn_challenge;
            if (!orig_tcp_oow_rate_limited(sock_net(sk), skb,
                                      LINUX_MIB_TCPACKSKIPPEDSEQ,
                                      &tp->last_oow_ack_time))
                tcp_send_dupack(sk, skb);
        } else if (tcp_reset_check(sk, skb)) {
            goto reset; // the right position is here
        }
        // LOG_WITH_PREFIX("discard here");
        SKB_DR_SET(reason, TCP_INVALID_SEQUENCE);
        goto discard;
    }

    /* Step 2: check RST bit */
    if (th->rst) {
        /* RFC 5961 3.2 (extend to match against (RCV.NXT - 1) after a
         * FIN and SACK too if available):
         * If seq num matches RCV.NXT or (RCV.NXT - 1) after a FIN, or
         * the right-most SACK block,
         * then
         *     RESET the connection
         * else
         *     Send a challenge ACK
         */
        LOG_WITH_PREFIX("HERE");
        printk(KERN_EMERG "current seq %u -- tp->rcv_nxt = %u\n", TCP_SKB_CB(skb)->seq, tp->rcv_nxt);
        if (TCP_SKB_CB(skb)->seq == tp->rcv_nxt ||
            tcp_reset_check(sk, skb))
            goto reset;

        if (tcp_is_sack(tp) && tp->rx_opt.num_sacks > 0) {
            struct tcp_sack_block *sp = &tp->selective_acks[0];
            int max_sack = sp[0].end_seq;
            int this_sack;

            for (this_sack = 1; this_sack < tp->rx_opt.num_sacks;
                 ++this_sack) {
                max_sack = after(sp[this_sack].end_seq,
                                 max_sack) ?
                           sp[this_sack].end_seq : max_sack;
            }

            if (TCP_SKB_CB(skb)->seq == max_sack)
                goto reset;
        }

        /* Disable TFO if RST is out-of-order
         * and no data has been received
         * for current active TFO socket
         */
        if (tp->syn_fastopen && !tp->data_segs_in &&
            sk->sk_state == TCP_ESTABLISHED)
            orig_tcp_fastopen_active_disable(sk);
        LOG_WITH_PREFIX("discard");
        tcp_send_challenge_ack(sk);
        SKB_DR_SET(reason, TCP_RESET);
        goto discard;
    }

    /* step 3: check security and precedence [ignored] */

    /* step 4: Check for a SYN
     * RFC 5961 4.2 : Send a challenge ack
     */
    if (th->syn) {
        syn_challenge:
        if (syn_inerr)
            TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
        NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPSYNCHALLENGE);
        LOG_WITH_PREFIX("send challenge ack");
        tcp_send_challenge_ack(sk);
        SKB_DR_SET(reason, TCP_INVALID_SYN);
        goto discard;
    }

    bpf_skops_parse_hdr(sk, skb);

    return true;

    discard:
    tcp_drop_reason(sk, skb, reason);
    return false;

    reset:
    orig_tcp_reset(sk, skb);
    __kfree_skb(skb);
    return false;
}

/* If we update tp->rcv_nxt, also update tp->bytes_received */
static void tcp_rcv_nxt_update(struct tcp_sock *tp, u32 seq)
{
    u32 delta = seq - tp->rcv_nxt;

    sock_owned_by_me((struct sock *)tp);
    tp->bytes_received += delta;
    WRITE_ONCE(tp->rcv_nxt, seq);
}


static int __must_check tcp_queue_rcv(struct sock *sk, struct sk_buff *skb,
                                      bool *fragstolen)
{
    int eaten;
    struct sk_buff *tail = skb_peek_tail(&sk->sk_receive_queue);

    eaten = (tail &&
             orig_tcp_try_coalesce(sk, tail,
                                   skb, fragstolen)) ? 1 : 0;
    tcp_rcv_nxt_update(tcp_sk(sk), TCP_SKB_CB(skb)->end_seq);
    if (!eaten) {
        __skb_queue_tail(&sk->sk_receive_queue, skb);
        skb_set_owner_r(skb, sk);
    }
    return eaten;
}

static inline void tcp_push_pending_frames_same(struct sock *sk)
{
    if (tcp_send_head(sk)) {
        struct tcp_sock *tp = tcp_sk(sk);

        orig__tcp_push_pending_frames(sk, orig_tcp_current_mss(sk), tp->nonagle);
    }
}

static inline void tcp_data_snd_check(struct sock *sk)
{
    tcp_push_pending_frames_same(sk);
    orig_tcp_check_space(sk);
}

static void tcp_store_ts_recent(struct tcp_sock *tp)
{
    tp->rx_opt.ts_recent = tp->rx_opt.rcv_tsval;
    tp->rx_opt.ts_recent_stamp = ktime_get_seconds();
}

static void tcp_rcv_rtt_update(struct tcp_sock *tp, u32 sample, int win_dep)
{
    u32 new_sample = tp->rcv_rtt_est.rtt_us;
    long m = sample;

    if (new_sample != 0) {
        /* If we sample in larger samples in the non-timestamp
         * case, we could grossly overestimate the RTT especially
         * with chatty applications or bulk transfer apps which
         * are stalled on filesystem I/O.
         *
         * Also, since we are only going for a minimum in the
         * non-timestamp case, we do not smooth things out
         * else with timestamps disabled convergence takes too
         * long.
         */
        if (!win_dep) {
            m -= (new_sample >> 3);
            new_sample += m;
        } else {
            m <<= 3;
            if (m < new_sample)
                new_sample = m;
        }
    } else {
        /* No previous measure. */
        new_sample = m << 3;
    }

    tp->rcv_rtt_est.rtt_us = new_sample;
}

static inline void tcp_rcv_rtt_measure_ts(struct sock *sk,
                                          const struct sk_buff *skb)
{
    struct tcp_sock *tp = tcp_sk(sk);

    if (tp->rx_opt.rcv_tsecr == tp->rcv_rtt_last_tsecr)
        return;
    tp->rcv_rtt_last_tsecr = tp->rx_opt.rcv_tsecr;

    if (TCP_SKB_CB(skb)->end_seq -
        TCP_SKB_CB(skb)->seq >= inet_csk(sk)->icsk_ack.rcv_mss) {
        u32 delta = tcp_time_stamp(tp) - tp->rx_opt.rcv_tsecr;
        u32 delta_us;

        if (likely(delta < INT_MAX / (USEC_PER_SEC / TCP_TS_HZ))) {
            if (!delta)
                delta = 1;
            delta_us = delta * (USEC_PER_SEC / TCP_TS_HZ);
            tcp_rcv_rtt_update(tp, delta_us, 0);
        }
    }
}

// ------------------------------------- static -------------------------------------

void self_defined_tcp_rcv_established(struct sock *sk, struct sk_buff *skb)
{
    enum skb_drop_reason reason = SKB_DROP_REASON_NOT_SPECIFIED;
    const struct tcphdr *th = (const struct tcphdr *)skb->data;
    struct tcp_sock *tp = tcp_sk(sk);
    unsigned int len = skb->len;

    // zhf add code
    // ---------------------------------------
    //    if(th->rst){
    //        LOG_WITH_PREFIX("tcp_rcv_established");
    //    }
    // ---------------------------------------

    /* TCP congestion window tracking */
    // trace_tcp_probe(sk, skb);

    orig_tcp_mstamp_refresh(tp);
    if (unlikely(!rcu_access_pointer(sk->sk_rx_dst)))
        inet_csk(sk)->icsk_af_ops->sk_rx_dst_set(sk, skb);
    /*
     *	Header prediction.
     *	The code loosely follows the one in the famous
     *	"30 instruction TCP receive" Van Jacobson mail.
     *
     *	Van's trick is to deposit buffers into socket queue
     *	on a device interrupt, to call tcp_recv function
     *	on the receive process context and checksum and copy
     *	the buffer to user space. smart...
     *
     *	Our current scheme is not silly either but we take the
     *	extra cost of the net_bh soft interrupt processing...
     *	We do checksum and copy also but from device to kernel.
     */

    tp->rx_opt.saw_tstamp = 0;

    /*	pred_flags is 0xS?10 << 16 + snd_wnd
     *	if header_prediction is to be made
     *	'S' will always be tp->tcp_header_len >> 2
     *	'?' will be 0 for the fast path, otherwise pred_flags is 0 to
     *  turn it off	(when there are holes in the receive
     *	 space for instance)
     *	PSH flag is ignored.
     */

    if ((tcp_flag_word(th) & TCP_HP_BITS) == tp->pred_flags &&
        TCP_SKB_CB(skb)->seq == tp->rcv_nxt &&
        !after(TCP_SKB_CB(skb)->ack_seq, tp->snd_nxt)) {
        int tcp_header_len = tp->tcp_header_len;

        /* Timestamp header prediction: tcp_header_len
         * is automatically equal to th->doff*4 due to pred_flags
         * match.
         */

        /* Check timestamp */
        if (tcp_header_len == sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) {
            /* No? Slow path! */
            if (!tcp_parse_aligned_timestamp(tp, th))
                goto slow_path;

            /* If PAWS failed, check it more carefully in slow path */
            if ((s32)(tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent) < 0)
                goto slow_path;

            /* DO NOT update ts_recent here, if checksum fails
             * and timestamp was corrupted part, it will result
             * in a hung connection since we will drop all
             * future packets due to the PAWS test.
             */
        }

        if (len <= tcp_header_len) {
            /* Bulk data transfer: sender */
            if (len == tcp_header_len) {
                /* Predicted packet is in window by definition.
                 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
                 * Hence, check seq<=rcv_wup reduces to:
                 */
                if (tcp_header_len ==
                    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
                    tp->rcv_nxt == tp->rcv_wup)
                    tcp_store_ts_recent(tp);

                /* We know that such packets are checksummed
                 * on entry.
                 */
                orig_tcp_ack(sk, skb, 0);
                __kfree_skb(skb);
                tcp_data_snd_check(sk);
                /* When receiving pure ack in fast path, update
                 * last ts ecr directly instead of calling
                 * tcp_rcv_rtt_measure_ts()
                 */
                tp->rcv_rtt_last_tsecr = tp->rx_opt.rcv_tsecr;
                return;
            } else { /* Header too small */
                reason = SKB_DROP_REASON_PKT_TOO_SMALL;
                TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
                goto discard;
            }
        } else {
            int eaten = 0;
            bool fragstolen = false;

            if (tcp_checksum_complete(skb))
                goto csum_error;

            if ((int)skb->truesize > sk->sk_forward_alloc)
                goto step5;

            /* Predicted packet is in window by definition.
             * seq == rcv_nxt and rcv_wup <= rcv_nxt.
             * Hence, check seq<=rcv_wup reduces to:
             */
            if (tcp_header_len ==
                (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
                tp->rcv_nxt == tp->rcv_wup)
                tcp_store_ts_recent(tp);

            tcp_rcv_rtt_measure_ts(sk, skb);

            NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPHPHITS);

            /* Bulk data transfer: receiver */
            skb_dst_drop(skb);
            __skb_pull(skb, tcp_header_len);
            eaten = tcp_queue_rcv(sk, skb, &fragstolen);

            orig_tcp_event_data_recv(sk, skb);

            if (TCP_SKB_CB(skb)->ack_seq != tp->snd_una) {
                /* Well, only one small jumplet in fast path... */
                orig_tcp_ack(sk, skb, FLAG_DATA);
                tcp_data_snd_check(sk);
                if (!inet_csk_ack_scheduled(sk))
                    goto no_ack;
            } else {
                tcp_update_wl(tp, TCP_SKB_CB(skb)->seq);
            }

            orig__tcp_ack_snd_check(sk, 0);
            no_ack:
            if (eaten)
                kfree_skb_partial(skb, fragstolen);
            orig_tcp_data_ready(sk);
            return;
        }
    }

    slow_path:
    if (len < (th->doff << 2) || tcp_checksum_complete(skb))
        goto csum_error;

    if (!th->ack && !th->rst && !th->syn) {
        reason = SKB_DROP_REASON_TCP_FLAGS;
        goto discard;
    }

    /*
     *	Standard slow path.
     */

    if (!tcp_validate_incoming(sk, skb, th, 1)){
        // LOG_WITH_PREFIX("not pass tcp_validate_incoming");
        return;
    }


    step5:
    reason = orig_tcp_ack(sk, skb, FLAG_SLOWPATH | FLAG_UPDATE_TS_RECENT);
    if ((int)reason < 0) {
        reason = -reason;
        goto discard;
    }
    tcp_rcv_rtt_measure_ts(sk, skb);

    /* Process urgent data. */
    orig_tcp_urg(sk, skb, th);

    /* step 7: process the segment text */
    orig_tcp_data_queue(sk, skb);

    tcp_data_snd_check(sk);
    tcp_ack_snd_check(sk);
    return;

    csum_error:
    reason = SKB_DROP_REASON_TCP_CSUM;
    trace_tcp_bad_csum(skb);
    TCP_INC_STATS(sock_net(sk), TCP_MIB_CSUMERRORS);
    TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);

    discard:
    tcp_drop_reason(sk, skb, reason);
}