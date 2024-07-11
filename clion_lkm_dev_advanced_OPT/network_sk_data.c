//
// Created by zhf on 24-4-26.
//
#include "headers/support_tools.h"
#include "headers/network_sk_data.h"

void init_or_update_network_sk_data(struct sock *sock){
    // judge the existence
    if(sock->sk_user_data) {
        // LOG_WITH_PREFIX("sk user data not null");
        struct NetworkSkData* network_sk_data = (struct NetworkSkData*)(sock->sk_user_data);
        network_sk_data->first_packet = false; // true -> first packet false -> other packets
    } else {
        // LOG_WITH_PREFIX("sk user data null");
        struct NetworkSkData* network_sk_data = (struct NetworkSkData*)(kmalloc(sizeof(struct NetworkSkData), GFP_KERNEL));
        network_sk_data->first_packet = true;
        sock->sk_user_data = (struct sock*)(network_sk_data);
    }
}

void set_session_id(struct sock* sock, u64 sessionid1, u64 sessionid2){
    if(sock->sk_user_data){
        struct NetworkSkData* network_sk_data = (struct NetworkSkData*)(sock->sk_user_data);
        network_sk_data->sessionid1 = sessionid1;
        network_sk_data->sessionid2 = sessionid2;
    }
}

struct NetworkSkData* get_network_sk_data(struct sock* sock){
    if(sock->sk_user_data){
        return (struct NetworkSkData*)(sock->sk_user_data);
    } else {
        return NULL;
    }
}

bool get_first_packet_status(struct sock* sock){
    if(sock->sk_user_data){
        struct NetworkSkData* network_sk_data = (struct NetworkSkData*)(sock->sk_user_data);
        return network_sk_data->first_packet;
    } else {
        return false;
    }
}