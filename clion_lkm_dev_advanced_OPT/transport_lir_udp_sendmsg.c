//
// Created by zhf on 24-4-12.
//
#include "headers/support_tools.h"
#include "headers/transport_lir_udp_sendmsg.h"
#include "headers/network_lir_make_skb.h"
#include "headers/transport_lir_udp_send_skb.h"
#include "headers/network_sk_data.h"
#include <linux/inetdevice.h>
#include <net/udp.h>
#include <asm-generic/rwonce.h>

asmlinkage int (*orig_udp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t len); // 原来的 udp_sendmsg

asmlinkage int hook_udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len){
    if(TEST_IF_LIR_SOCKET(sk)){
        return lir_udp_sendmsg(sk, msg, len);
    } else {
        return orig_udp_sendmsg(sk, msg, len);
    }
}

int lir_udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len){
    // --------------      initialize        --------------
    struct inet_sock *inet = inet_sk(sk);
    struct udp_sock *udp_sock = udp_sk(sk);  // get udp sock
    DECLARE_SOCKADDR(struct sockaddr_in*, usin, msg->msg_name); // set address
    struct LirReturnDataStructure lir_return_data_structure; // result
    int udp_and_app_len = (int) (len) + (int) sizeof(struct udphdr); // len is the app len
    int udp_len = sizeof(struct udphdr);
    struct net *current_net_namespace = sock_net(sk);
    struct sk_buff *skb_to_sent;
    struct ipcm_cookie ipc;
    struct inet_cork cork;
    int err;
    bool is_udplite = false;
    int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
    getfrag = ip_generic_getfrag;
    __be16 dport;
    __be16 sport;
    __u16 source_node_id = get_satellite_id(current_net_namespace);  // 源节点编号
    __u16 destination_node_id;                                       // 目的节点编号

    // --------------    init sk->user_data  --------------
    init_or_update_network_sk_data(sk);
    bool first_packet = get_first_packet_status(sk);
    if(first_packet){
        LOG_WITH_PREFIX("FIRST PACKET");
    } else {
        LOG_WITH_PREFIX("NOT FIRST PACKET");
    }
    // --------------    init sk->user_data  --------------


    // --------------      initialize        --------------

    // --------------  get daddr dport sport --------------
    dport = usin->sin_port;
    sport = inet->inet_sport;
    // --------------  get daddr dport sport --------------

    // --------------        set ipc         --------------
    ipcm_init_sk(&ipc, inet);
    ipc.gso_size = READ_ONCE(udp_sock->gso_size);
    // --------------        set ipc         --------------

    // --------------       get route        --------------
    lir_return_data_structure = get_destination_list_and_construct_bf(current_net_namespace, inet->inet_opt);
    destination_node_id = lir_return_data_structure.destination_node_id;
    // --------------       get route        --------------

    // --------------     create skb (IP)    --------------
    skb_to_sent = lir_make_skb(sk, &lir_return_data_structure,
                               udp_and_app_len,
                               msg->msg_flags, getfrag, msg,
                               &cork, &ipc,
                               source_node_id, destination_node_id);
    err = PTR_ERR(skb_to_sent);
    // --------------     create skb (IP)    --------------

    // --------------  set UDP and send skb  --------------
    if (!IS_ERR_OR_NULL(skb_to_sent)) {
        // zhf add code
        err = lir_udp_send_skb(skb_to_sent, &cork, lir_return_data_structure.output_interface,
                               sport, dport);
    }
    // --------------  set UDP and send skb  --------------
    if(!err){
        return len;
    }
    if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
        UDP_INC_STATS(sock_net(sk),
                      UDP_MIB_SNDBUFERRORS, is_udplite);
    }
    return err;
}


void add_udp_sendmsg_to_hook(void){
    hooks[number_of_hook].name = "udp_sendmsg";
    hooks[number_of_hook].function = hook_udp_sendmsg;
    hooks[number_of_hook].original = &orig_udp_sendmsg;
    number_of_hook += 1;
}