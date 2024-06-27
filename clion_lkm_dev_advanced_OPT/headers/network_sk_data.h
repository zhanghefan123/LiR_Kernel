//
// Created by zhf on 24-4-26.
//

#ifndef ZEUSNET_KERNEL_NETWORK_SK_DATA_H
#define ZEUSNET_KERNEL_NETWORK_SK_DATA_H

#include <net/ip.h>

struct NetworkSkData {
    bool first_packet;
};

void init_or_update_network_sk_data(struct sock *sock);

bool get_first_packet_status(struct sock* sock);

#endif // ZEUSNET_KERNEL_NETWORK_SK_DATA_H
