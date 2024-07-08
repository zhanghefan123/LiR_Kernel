//
// Created by zhf on 24-4-12.
//

#ifndef ZEUSNET_KERNEL_LIR_ROUTING_TABLE_STRUCTURE_H
#define ZEUSNET_KERNEL_LIR_ROUTING_TABLE_STRUCTURE_H
#include "net/ip.h"
#include "linux/types.h"
#include "net/net_namespace.h"
#include "lir_data_structure.h"
#include "lir_bloom_filter.h"

#define BUCKET_COUNT 1000
#define HASH_SEED 1234

// lir 路由表结构体
struct RoutingTableEntry {
    int source_id;       // 源节点的 id
    int destination_id;  // 目的节点的 id
    int length_of_path;  // 路径的长度
    int *link_identifiers; // 到目的节点的链路表示序列
    int *node_ids;       // 节点序列
    struct hlist_node pointer; // 指针指向的是下一个节点
    unsigned long *bitset; // 插入 link_identifiers 所对应的 bitset
    struct net_device* output_interface; // 出接口所对应的接口表项
    u32 effective_bytes; // bitset 所对应的有效的字节数
    char* route_str_repr; // 路由的字符串表示
};

struct RoutingTableEntry* init_routing_table_entry(int bitset_length);

void free_routing_table_entry(struct RoutingTableEntry *routing_table_entry);

struct hlist_head *init_routing_table(void);

int delete_routing_table(struct hlist_head *head_pointer_list);

struct hlist_head *hash_and_get_bucket_for_routing_table(struct hlist_head *head_pointer_list,
                                                         int source_id,
                                                         int destination_id);

int routing_entry_equal_judgement(struct RoutingTableEntry *entry, int source_id, int destination_id);

struct RoutingTableEntry* generate_single_route(struct net* current_net_namespace, char* corresponding_message);

int add_entry_to_routing_table(struct hlist_head *head_pointer_list,
                               struct RoutingTableEntry *routing_table_entry);

struct RoutingTableEntry *find_entry_in_routing_table(struct hlist_head *head_pointer_list,
                                                      int source_id,
                                                      int destination_id);

void print_routing_table_entry(struct RoutingTableEntry *entry);

int print_routing_table(struct hlist_head *head_pointer_list);

void test_routing_table(void);

void rebuild_routing_table_with_new_bf_settings(struct bloom_filter* bloom_filter, struct hlist_head* lir_routing_table);

struct RoutingTableEntry* get_routing_table_entry_by_iph(struct net* current_net_namespace, struct iphdr*);

// 根据选项进行单个路由表条目的获取
struct RoutingTableEntry* get_routing_table_entry_by_sock_opt(struct net *current_net_namespace, struct ip_options_rcu *opt);

// 进行目的节点的列表的获取
struct LirReturnDataStructure get_destination_list_and_construct_bf(struct net *current_net_namespace, struct ip_options_rcu *opt);

#endif //ZEUSNET_KERNEL_LIR_ROUTING_TABLE_STRUCTURE_H
