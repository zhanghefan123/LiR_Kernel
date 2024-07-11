//
// Created by zhf on 24-7-4.
//
#include "headers/session_path_table.h"
#include "headers/lir_routing_table_structure.h"
#include "headers/support_tools.h"

struct hlist_head *init_session_path_table(void) {
    int index;
    struct hlist_head *head_pointer_list = NULL;
    head_pointer_list = (struct hlist_head *) kmalloc(sizeof(struct hlist_head) * BUCKET_COUNT, GFP_KERNEL);
    if (NULL == head_pointer_list) {
        LOG_WITH_PREFIX("alloc memory for head_pointer_list failed");
    }
    for (index = 0; index < BUCKET_COUNT; index++) {
        INIT_HLIST_HEAD(&head_pointer_list[index]);
    }
    return head_pointer_list;
}

struct SessionPathTableEntry *init_session_table_entry(void) {
    struct SessionPathTableEntry *session_path_table_entry = (struct SessionPathTableEntry *) kmalloc(
            sizeof(struct SessionPathTableEntry), GFP_KERNEL);
    return session_path_table_entry;
}

int delete_session_path_table(struct hlist_head *head_pointer_list) {
    int index;
    struct hlist_head *hash_bucket = NULL;
    struct SessionPathTableEntry *current_entry = NULL;
    struct hlist_node *next;
    for (index = 0; index < BUCKET_COUNT; index++) {
        hash_bucket = &head_pointer_list[index];
        // 每一个 hash_bucket 都被初始化过了，所以不能为NULL
        if (NULL == hash_bucket) {
            LOG_WITH_PREFIX("hash bucket is null");
            return -1;
        }
        hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
            hlist_del(&current_entry->pointer);
            free_session_path_table_entry(current_entry);
        }
    }
    // 清空 head_pointer_list 引入的 memory 开销
    kfree(head_pointer_list);
    head_pointer_list = NULL;
    LOG_WITH_PREFIX("delete session table succeed!");
    return 0;
}

struct hlist_head *hash_and_get_bucket_for_session_table(struct hlist_head *head_pointer_list,
                                                         u64 session_id1,
                                                         u64 session_id2){
    u32 hash_value;
    u32 index_of_bucket;
    u64 source_dest_pair[2] = {session_id1, session_id2};
    hash_value = jhash(source_dest_pair, sizeof(u64) * 2, HASH_SEED);
    index_of_bucket = hash_value % BUCKET_COUNT;
    return &head_pointer_list[index_of_bucket];
}

int session_path_entry_equal_judgement(struct SessionPathTableEntry *entry, u64 sessionid1, u64 sessionid2) {
    if (entry == NULL) {
        return 1;
    }
    // 只要第一个路由表项的 sessionid1 和 第二个路由表项的 sessionid2 相同
    if ((entry->sessionid1 == sessionid1) && (entry->sessionid2 == sessionid2)) {
        return 0;
    } else {
        return 1;
    }
}

int add_entry_into_session_table(struct hlist_head *head_pointer_list,
                                 struct SessionPathTableEntry *session_path_table_entry) {
    struct hlist_head *hash_bucket = NULL;
    struct SessionPathTableEntry *current_entry = NULL;
    struct hlist_node *next = NULL;
    hash_bucket = hash_and_get_bucket_for_session_table(head_pointer_list,
                                                        session_path_table_entry->sessionid1,
                                                        session_path_table_entry->sessionid2);
    if (NULL == hash_bucket) {
        LOG_WITH_PREFIX("cannot find hash bucket");
        kfree(session_path_table_entry);
        return -1;  // 找不到 hash_bucket
    }
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == session_path_entry_equal_judgement(current_entry,
                                                    session_path_table_entry->sessionid1,
                                                    session_path_table_entry->sessionid2)) {
            LOG_WITH_PREFIX("already exists route entry");
            free_session_path_table_entry(session_path_table_entry);
            return -2;  // 已经存在
        }
    }
    // 这个时候说明我们真的需要创建一个自己的 node
    INIT_HLIST_NODE(&session_path_table_entry->pointer);
    hlist_add_head(&session_path_table_entry->pointer, hash_bucket);
    return 0;
}

struct SessionPathTableEntry *find_entry_in_session_path_table(struct hlist_head *head_pointer_list,
                                                               u64 session_id1,
                                                               u64 session_id2) {
    struct hlist_head *hash_bucket = NULL;
    struct SessionPathTableEntry *current_entry;
    struct hlist_node *next;
    hash_bucket = hash_and_get_bucket_for_session_table(head_pointer_list, session_id1, session_id2);
    if (NULL == hash_bucket) {
        LOG_WITH_PREFIX("cannot find entry because cannot find hash bucket");
        return NULL;
    }
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == session_path_entry_equal_judgement(current_entry, session_id1, session_id2)) {
            return current_entry;
        }
    }
    return NULL;
}

void print_session_table_entry(struct SessionPathTableEntry *entry) {
    char message[200];
    char item[50];
    sprintf(message, "source: %d, destination: %d ", entry->source_id, entry->destination_id);
    if(entry->output_device){
        sprintf(item, "interface name: %s ", entry->output_device->name);
        strcat(message, item);
    }
    sprintf(item, "current_index: %d ", entry->current_index);
    LOG_WITH_PREFIX(message);
}

void free_session_path_table_entry(struct SessionPathTableEntry *session_path_table_entry) {
    if(session_path_table_entry != NULL){
        if(session_path_table_entry->encrypt_order){
            kfree(session_path_table_entry->encrypt_order);
        }
    }
}