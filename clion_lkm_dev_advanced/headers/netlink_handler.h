//
// Created by 张贺凡 on 2024/2/5.
//

#ifndef ZEUSNET_KERNEL_NETLINK_HANDLER_H
#define ZEUSNET_KERNEL_NETLINK_HANDLER_H
#include <net/sock.h>
#include <net/genetlink.h>
#include "lir_routing_table_structure.h"
int construct_new_interface_table_handler(struct sk_buff* request, struct genl_info* info);
int set_bloom_filter_attrs(struct sk_buff* request, struct genl_info* info);
int bind_net_to_sat_id_handler(struct sk_buff* request, struct genl_info* info);
int calculate_length_message_handler(struct sk_buff* request, struct genl_info* info);
int insert_route_message_handler(struct sk_buff* request, struct genl_info *info);
int search_route_message_handler(struct sk_buff* request, struct genl_info* info);
int find_dev_by_name_handler(struct sk_buff* request, struct genl_info* info);
int retrieve_new_interface_table_handler(struct sk_buff* request, struct genl_info* info);
int get_bind_id_handler(struct sk_buff* request, struct genl_info* info);
int set_encoding_count_handler(struct sk_buff* request, struct genl_info* info);
#endif
