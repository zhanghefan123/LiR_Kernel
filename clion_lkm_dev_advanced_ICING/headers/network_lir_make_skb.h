//
// Created by zhf on 24-4-12.
//

#ifndef ZEUSNET_KERNEL_NETWORK_LIR_MAKE_SKB_H
#define ZEUSNET_KERNEL_NETWORK_LIR_MAKE_SKB_H

#include <net/ip.h>
#include "lir_data_structure.h"

int get_icing_validation_size(struct LirReturnDataStructure *lir_return_data_structure);

void fill_icing_field(struct udphdr *udp_header,
                      struct lirhdr *lir_header,
                      struct LirReturnDataStructure *lir_return_data_structure,
                      struct net *net);

void resolve_lir_make_skb_inner_functions_address(void);

struct sk_buff *lir_make_skb(struct sock *sk,
                             struct LirReturnDataStructure *lir_return_data_structure,
                             int app_and_transport_length,
                             unsigned int flags,
                             int getfrag(void *from, char *to, int offset,
                                         int len, int odd, struct sk_buff *skb),
                             void *from,
                             struct inet_cork *cork,
                             struct ipcm_cookie *ipc,
                             __u16 source_node_id,
                             __u16 destination_node_id);

int lir_setup_cork(struct sock *sk,
                   struct inet_cork *cork,
                   struct ipcm_cookie *ipc,
                   struct net_device *output_dev);

int lir_append_data(struct sock *sk,
                    struct sk_buff_head *queue,
                    struct LirReturnDataStructure *lir_return_data_structure,
                    int app_and_transport_length,
                    unsigned int flags,
                    int getfrag(void *from, char *to, int offset,
                                int len, int odd, struct sk_buff *skb),
                    void *from,
                    struct page_frag *pfrag,
                    struct inet_cork *cork);

void fill_lir_header_length(struct lirhdr *lir_header, struct LirReturnDataStructure *lir_return_data_structure);

struct sk_buff *lir_make_skb_core(struct sock *sk,
                                  struct sk_buff_head *queue,
                                  struct inet_cork *cork,
                                  struct LirReturnDataStructure *lir_return_data_structure,
                                  __u16 source_node_id,
                                  __u16 destination_node_id);

void fill_lir_header_option_part(struct sk_buff *skb, struct LirReturnDataStructure *lir_return_data_structure);

int get_icing_header_total_length(struct LirReturnDataStructure *lir_return_data_structure);

void lir_select_id(struct net *net, struct sk_buff *skb, struct sock *sk,
                   int segs, __u16 source_node_id,
                   __u16 destination_node_id);

void lir_select_id_core(struct net *net, struct lirhdr *iph, int segs,
                        __u16 source_node_id,
                        __u16 destination_node_id);

int lir_send_skb(struct net *net, struct sk_buff *skb, struct net_device *output_dev);

void lir_send_check(struct lirhdr *lir_header);

__sum16 lir_fast_csum(const void *lir_header, unsigned int header_length);

#endif // ZEUSNET_KERNEL_NETWORK_LIR_MAKE_SKB_H
