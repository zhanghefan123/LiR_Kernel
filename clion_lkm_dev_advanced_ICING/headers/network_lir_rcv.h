//
// Created by zhf on 24-4-13.
//

#ifndef ZEUSNET_KERNEL_NETWORK_LIR_IP_RCV_H
#define ZEUSNET_KERNEL_NETWORK_LIR_IP_RCV_H
#include <net/ip.h>
#include "network_lir_header.h"
#include "support_ftrace_hook_api.h"
#include "lir_configuration.h"
extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;
void resolve_network_lir_rcv_inner_functions_address(void);
int lir_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
struct sk_buff* lir_rcv_core(struct sk_buff* skb, struct net* net);
int lir_rcv_finish(struct net* net, struct sk_buff *skb, u64 start);
int lir_local_deliver(struct sk_buff *skb);
bool lir_is_fragment(const struct lirhdr* lir_header);
int lir_defrag(struct net *net, struct sk_buff *skb, u32 user);
void print_upstream_node_sequence(struct single_hop_icing* icing_path, int current_path_index, int source_node_id);
void print_downstream_node_sequence(struct single_hop_icing* icing_path, int current_path_index, int length_of_path);
int lir_rcv_finish_core(struct net *net, struct sk_buff *skb, struct net_device *dev);
int lir_rcv_options_and_forward_packets(struct net *current_net_namespace, struct sk_buff *skb, struct net_device *dev);
bool validate_packet(struct lirhdr *lir_header,
                     struct single_hop_icing *icing_path,
                     struct single_node_validation_icing* validation_list,
                     int current_path_index,
                     struct net *current_net_namespace,
                     int source_node_id,
                     int current_satellite_id);
void update_validation_fields(struct lirhdr* lir_header,
                              struct single_hop_icing* icing_path,
                              struct single_node_validation_icing* validation_list,
                              int current_path_index,
                              int current_satellite_id,
                              struct net* current_net_namespace,
                              int length_of_path);
int lir_packet_forward(struct sk_buff* skb, struct net_device* output_dev, struct net* current_net_namespace);
int lir_local_deliver_finish(struct net *net, struct sk_buff *skb);
void lir_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol);
#endif // ZEUSNET_KERNEL_NETWORK_LIR_IP_RCV_H
