//
// Created by zhf on 24-4-12.
//

#ifndef ZEUSNET_KERNEL_LIR_DATA_STRUCTURE_H
#define ZEUSNET_KERNEL_LIR_DATA_STRUCTURE_H
#include "lir_routing_table_structure.h"
#include "lir_bloom_filter.h"
#include "lir_configuration.h"
#include "lir_interface_table_structure.h"
#include "crypto_function.h"
// ----------------------- net namespace 之中额外定义的数据结构 -----------------------
struct LirDataStructure {
    struct hlist_head* lir_routing_table; // 路由表指针的存储
    struct NewInterfaceTable* new_interface_table; // new interface table storage
    struct bloom_filter* bloom_filter;  // 全网需要统一布隆过滤器的使用
    int satellite_id; // 卫星的id
    int* link_identifiers; // 单颗卫星所具有的链路标识
    int number_of_link_identifiers; // 链路标识的数量
    bool initializing; // 是否是初始化阶段
    struct bloom_filter* route_bloom_filter; // 用于 tcp 的
    struct net_device* output_interface; // 出接口
    struct shash_desc* hmac_data_structure; // calculate hmac
    struct shash_desc* hash_data_structure; // calculate hash
};
// ----------------------- net namespace 之中额外定义的数据结构 -----------------------

// ----------------------- 返回的数据结构 -----------------------
struct LirReturnDataStructure {
    struct bloom_filter* bloom_filter; // 结果布隆过滤器
    struct net_device* output_interface; // 出接口
    int destination_node_id;           // 目的卫星编号
    struct RoutingTableEntry* routing_table_entry;
};
// ----------------------- 返回的数据结构 -----------------------

// ----------------------------- new interface table ------------------------------
void set_new_interface_table_in_lir_data_structure(struct net* net_namespace, struct NewInterfaceTable* new_interface_table);
struct NewInterfaceTable* get_new_interface_table_from_net_namespace(struct net* net_namespace);
// ----------------------------- new interface table ------------------------------

// ----------------------------- 初始化额外定义的数据结构 -----------------------------
void init_lir_data_structure_in_net_namespace(struct net* net_namespace);
void free_lir_data_structure_in_net_namespace(struct net* net_namespace);
// ----------------------------- 初始化额外定义的数据结构 -----------------------------

// ----------------------------- 获取与设置数据结构的属性 -----------------------------
struct LirDataStructure* get_lir_data_structure(struct net* net_namespace);
struct hlist_head* get_lir_routing_table_from_net_namespace(struct net* net_namespace);
void set_satellite_id(struct net* net_namespace, int satellite_id);
int get_satellite_id(struct net* net_namespace);
struct bloom_filter* get_bloom_filter(struct net* net_namespace);
bool get_if_initializing(struct net* net_namespace);
void set_initialized(struct net* net_namespace);
// ----------------------------- 获取与设置数据结构的属性 -----------------------------

// ----------------------------- get crypto related attributes -----------------------------
struct shash_desc* get_hmac_data_structure(struct net* net_namespace);
struct shash_desc* get_hash_data_structure(struct net* net_namespace);
// ----------------------------- get crypto related attributes -----------------------------
#endif // ZEUSNET_KERNEL_LIR_DATA_STRUCTURE_H
