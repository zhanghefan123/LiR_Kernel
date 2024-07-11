//
// Created by zhf on 24-7-4.
//

#ifndef LINUX_KERNEL_MODULE_WITH_CLION_IDE_SUPPORT_CMAKE_SESSION_PATH_TABLE_H
#define LINUX_KERNEL_MODULE_WITH_CLION_IDE_SUPPORT_CMAKE_SESSION_PATH_TABLE_H

#include "net/ip.h"
#include "linux/types.h"
#include "net/net_namespace.h"

// OPT 路径存储表结构体
struct SessionPathTableEntry {
    u64 sessionid1;     // sessionid 的第一个 64 位
    u64 sessionid2;     // sessionid 的第二个 64 位
    int source_id;       // 源节点的 id  key1
    int destination_id;  // 目的节点 id  key2
    struct net_device *output_device;  // 提前进行出接口的存储
    int current_index; // 当前索引，用来判断应该看哪一个 ovf
    int *encrypt_order; // 仅对最后的目的节点有效, A->B->C->D 则加密的顺序为 D B C
    int encrypt_length; // 加密的数量
    //    int upstream_node_count; // 上游节点的数量
    //    int *upstream_nodes; // 上游节点的存储
    //    int downstream_node_count; // 下游节点的数量
    //    int *downstream_nodes; // 下游节点的存储
    struct hlist_node pointer; // 指针指向的是下一个节点
};

struct hlist_head *init_session_path_table(void);

struct SessionPathTableEntry *init_session_table_entry(void);

int delete_session_path_table(struct hlist_head *head_pointer_list);

struct hlist_head *hash_and_get_bucket_for_session_table(struct hlist_head *head_pointer_list,
                                                         u64 sessionid1,
                                                         u64 sessionid2);

int session_path_entry_equal_judgement(struct SessionPathTableEntry *entry, u64 sessionid1, u64 sessionid2);

int add_entry_into_session_table(struct hlist_head *head_pointer_list,
                                 struct SessionPathTableEntry *session_path_table_entry);

struct SessionPathTableEntry *find_entry_in_session_path_table(struct hlist_head *head_pointer_list,
                                                               u64 sessionid1,
                                                               u64 sessionid2);

void print_session_table_entry(struct SessionPathTableEntry *entry);

void free_session_path_table_entry(struct SessionPathTableEntry *session_path_table_entry);

#endif //LINUX_KERNEL_MODULE_WITH_CLION_IDE_SUPPORT_CMAKE_SESSION_PATH_TABLE_H
