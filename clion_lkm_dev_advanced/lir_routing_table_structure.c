//
// Created by kernel-dbg on 24-2-1.
//
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/inetdevice.h>
#include "headers/support_tools.h"
#include "headers/lir_data_structure.h"
#include "headers/network_lir_option_field_mean.h"
#include "headers/lir_routing_table_structure.h"

/**
 * 进行路由表项的初始化
 * @param bloom_filter_total_length 布隆过滤器的最大大小，一般被初始化为5
 * @return
 */
struct RoutingTableEntry* init_routing_table_entry(int bloom_filter_total_length){
    struct RoutingTableEntry* routing_table_entry = (struct RoutingTableEntry*)(kmalloc(sizeof(struct RoutingTableEntry),GFP_KERNEL));
    routing_table_entry->bitset = (unsigned long*)(kmalloc(sizeof(unsigned long) * bloom_filter_total_length, GFP_KERNEL));
    return routing_table_entry;
}


/**
 * 进行路由表的初始化并返回
 */
struct hlist_head *init_routing_table(void) {
    int index;
    // 链地址法的左侧竖直列表
    struct hlist_head *head_pointer_list = NULL;
    head_pointer_list = (struct hlist_head *) kmalloc(sizeof(struct hlist_head) * BUCKET_COUNT, GFP_KERNEL);
    if (NULL == head_pointer_list) {
        LOG_WITH_PREFIX("alloc memory for head_pointer_list failed!");
    }
    // 初始化表头
    for (index = 0; index < BUCKET_COUNT; index++) {
        INIT_HLIST_HEAD(&head_pointer_list[index]);
    }
    return head_pointer_list;
}

/**
 * 进行哈希值的计算
 * @param head_pointer_list 链地址法头指针列表
 * @param source_id 源节点 id
 * @param destination_id 目的节点 id
 * @return 源目节点对对应的头指针
 */
struct hlist_head *hash_and_get_bucket_for_routing_table(struct hlist_head *head_pointer_list,
                                                         int source_id,
                                                         int destination_id) {
    u32 hash_value;
    u32 index_of_bucket;
    int source_dest_pair[2] = {source_id, destination_id};
    hash_value = jhash(source_dest_pair, sizeof(int) * 2, HASH_SEED);
    index_of_bucket = hash_value % BUCKET_COUNT;
    return &head_pointer_list[index_of_bucket];
}

/**
 * 判断两个路由表项是否相等
 * @param left 第一个路由表项
 * @param right 第二个路由表项
 * @return 1 代表不相等 0 代表相等
 */
int routing_entry_equal_judgement(struct RoutingTableEntry *entry, int source_id, int destination_id) {
    if (entry == NULL) {
        return 1;
    }
    // 只要第一个路由表项的 source_id 和 第二个路由表项的 destination_id 相同
    if ((entry->source_id == source_id) && (entry->destination_id == destination_id)) {
        return 0;
    } else {
        return 1;
    }
}

/**
 * 根据单行信息进行单条路由的生成
 * @param current_net_namespace 当前的网络命名空寂那
 * @param corresponding_message 相应的单行信息
 * @return
 */
struct RoutingTableEntry* generate_single_route(struct net* current_net_namespace, char* corresponding_message){
    // each satellite pair sat1 and sat2 should have key1 and key2
    // when search the routing table, the key should be the same
    struct RoutingTableEntry *entry = init_routing_table_entry(BLOOM_FILTER_TOTAL_LENGTH);
    struct bloom_filter* bloom_filter = get_bloom_filter(current_net_namespace);
    struct NewInterfaceTable* new_interface_table = get_new_interface_table_from_net_namespace(current_net_namespace);
    char *single_number = NULL;
    const char *delimeter = ","; // 注意分隔符只要一个字符
    int count = 0;
    int number;
    int link_identifier_index = 0;
    int node_index = 0;
    // 开始的时候首先进行布隆过滤器的重置,准备向布隆过滤器之中存放内容
    reset_bloom_filter(bloom_filter);
    while (true) {

        single_number = strsep(&corresponding_message, delimeter);
        if (single_number == NULL || (strcmp(single_number, "") == 0)) {
            break;
        } else {
            number = (int) (simple_strtol(single_number, NULL, 10));
            if (count == 0) {
                entry->source_id = number;
            } else if (count == 1) {
                entry->destination_id = number;
            } else if (count == 2) {
                // get the length of the identifier sequence
                entry->length_of_path = number;
                entry->link_identifiers = (int *) (kmalloc(sizeof(int) * entry->length_of_path, GFP_KERNEL));
                entry->node_ids = (int*) (kmalloc(sizeof(int) * entry->length_of_path, GFP_KERNEL));
            } else {
                // 如果是链路序列的第一个链路标识，我们可以通过这个标识找到对应的接口表项，并存储在路由表项之中
                if(count == 3){
                    struct NewInterfaceEntry output_interface_entry = find_entry_in_new_interface_table(new_interface_table, number);
                    entry->output_interface = output_interface_entry.interface;
                    entry->link_identifiers[link_identifier_index] = number;
                    link_identifier_index += 1;
                    push_element_into_bloom_filter(bloom_filter, &number, sizeof(int));
                } else if(count % 2 == 1){ // link identifier
                    entry->link_identifiers[link_identifier_index] = number;
                    link_identifier_index += 1;
                    push_element_into_bloom_filter(bloom_filter, &number, sizeof(int));
                } else if (count % 2 == 0){ // node id
                    entry->node_ids[node_index] = number;
                    node_index += 1;
                }
                // entry->link_identifiers[count - 3] = number;
                // 向布隆过滤器之中存放内容
            }
        }
        count += 1;
    }
    entry->effective_bytes = bloom_filter->effective_bytes;
    // printk(KERN_EMERG "bloom filter params bitset: %d, hash_seed: %d, hash funcs: %d", bloom_filter->bitset_mask, bloom_filter->hash_seed, bloom_filter->nr_hash_funcs);
    // 将结束插入的布隆过滤器二进制数组内容拷贝到路由表项的二进制向量之中
    memcpy(entry->bitset, bloom_filter->bitset, bloom_filter->effective_bytes);
    // 结束的时候进行布隆过滤器的重置
    reset_bloom_filter(bloom_filter);
    return entry;
}


/**
 * add_entry_to_routing_table 将路由条目添加到路由表之中
 * @param current_net_namespace 当前的网络命名空间
 * @param head_pointer_list 链地址法头指针列表
 * @param routing_table_entry 其中已经赋值好的路由表项
 * @return 返回0说明成功创建
 */
int add_entry_to_routing_table(struct hlist_head *head_pointer_list,
                               struct RoutingTableEntry *routing_table_entry) {
    struct hlist_head *hash_bucket = NULL;
    struct RoutingTableEntry *current_entry = NULL;
    struct hlist_node *next = NULL;
    // 首先找到对应的应该存放的 bucket
    hash_bucket = hash_and_get_bucket_for_routing_table(head_pointer_list,
                                                        routing_table_entry->source_id,
                                                        routing_table_entry->destination_id);
    if (NULL == hash_bucket) {
        LOG_WITH_PREFIX("cannot find hash bucket");
        kfree(routing_table_entry);
        return -1;  // 找不到 hash_bucket
    }
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == routing_entry_equal_judgement(current_entry,
                                               routing_table_entry->source_id,
                                               routing_table_entry->destination_id)) {
            LOG_WITH_PREFIX("already exists route entry");
            free_routing_table_entry(routing_table_entry);
            return -2;  // 已经存在
        }
    }
    // 这个时候说明我们真的需要创建一个自己的 node
    INIT_HLIST_NODE(&routing_table_entry->pointer);
    hlist_add_head(&routing_table_entry->pointer, hash_bucket);
    return 0;
}

/**
 * 在路由表之中找到
 * @param head_pointer_list 链地址法头指针列表
 * @param source_id 源节点 id
 * @param destination_id 目的节点 id
 * @return NULL (not found) || current_entry (found)
 */
struct RoutingTableEntry *find_entry_in_routing_table(struct hlist_head *head_pointer_list,
                                                      int source_id,
                                                      int destination_id) {
    struct hlist_head *hash_bucket = NULL;
    struct RoutingTableEntry *current_entry;
    struct hlist_node *next;
    hash_bucket = hash_and_get_bucket_for_routing_table(head_pointer_list, source_id, destination_id);
    if (NULL == hash_bucket) {
        LOG_WITH_PREFIX("cannot find entry because cannot find hash bucket");
        return NULL;
    }
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == routing_entry_equal_judgement(current_entry, source_id, destination_id)) {
            return current_entry;
        }
    }
    return NULL;
}

/**
 * 进行路由表项所占用的空间的释放
 * @param routing_table_entry 要释放空间的路由表项
 */
void free_routing_table_entry(struct RoutingTableEntry *routing_table_entry) {
    if (routing_table_entry != NULL) {
        if (routing_table_entry->link_identifiers != NULL) {
            kfree(routing_table_entry->link_identifiers);
        }
        if (routing_table_entry->bitset != NULL){
            kfree(routing_table_entry->bitset);
        }
        if(routing_table_entry->node_ids != NULL){
            kfree(routing_table_entry->node_ids);
        }
        kfree(routing_table_entry);
    }
}

/**
 * 进行路由表的之中每个节点的内存的释放，以及所有节点的删除
 * @param head_pointer_list 链地址法头指针列表
 * @return not zero -- delete failed zero -- delete success
 */
int delete_routing_table(struct hlist_head *head_pointer_list) {
    int index;
    struct hlist_head *hash_bucket = NULL;
    struct RoutingTableEntry *current_entry = NULL;
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
            free_routing_table_entry(current_entry);
        }
    }
    // 清空 head_pointer_list 引入的 memory 开销
    kfree(head_pointer_list);
    head_pointer_list = NULL;
    LOG_WITH_PREFIX("delete routing table succeed!");
    return 0;
}

/**
 * 进行单个路由表项的打印
 */
void print_routing_table_entry(struct RoutingTableEntry *entry) {
    char message[200];
    char number[10];
    char bitset_str[50];
    int index;
    sprintf(message, "source: %d destination %d ", entry->source_id, entry->destination_id);
    for (index = 0; index < entry->length_of_path; index++) {
        sprintf(number, "(%d|%d)->", entry->link_identifiers[index], entry->node_ids[index]);
        strcat(message, number);
    }
    sprintf(bitset_str, "bitset %ld %ld %ld %ld\n", entry->bitset[0], entry->bitset[1], entry->bitset[2], entry->bitset[3]);
    LOG_WITH_PREFIX(bitset_str);
    LOG_WITH_PREFIX(message);
}

/**
 * 进行路由表的打印
 * @param head_pointer_list 要打印的路由表
 */
int print_routing_table(struct hlist_head *head_pointer_list) {
    int index;
    struct hlist_head *hash_bucket = NULL;
    struct RoutingTableEntry *current_entry = NULL;
    struct hlist_node *next;
    LOG_WITH_EDGE("start print routing table");
    // 每一个 hash_bucket 都被初始化过了，所以不能为NULL
    for (index = 0; index < BUCKET_COUNT; index++) {
        hash_bucket = &head_pointer_list[index];
        if (NULL == hash_bucket) {
            LOG_WITH_PREFIX("hash bucket is null");
            return -1;
        }
        hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
            // 进行 current_entry 的打印
            print_routing_table_entry(current_entry);
        }
    }
    LOG_WITH_EDGE("stop print routing table");
    return 0;
}

/**
 * 进行路由表的测试
 */
void test_routing_table(void) {
    struct RoutingTableEntry *find_entry = NULL;
    struct hlist_head *head_pointer_list = init_routing_table();

    // --------------------- 进行一条路由的信息的初始化 ---------------------
    int source_id = 1;
    int destination_id = 10;
    int length = 2;
    int *link_identifiers = (int *) kmalloc(sizeof(int) * 2, GFP_KERNEL);
    link_identifiers[0] = 100;
    link_identifiers[1] = 200;
    struct RoutingTableEntry *routing_table_entry = init_routing_table_entry(BLOOM_FILTER_TOTAL_LENGTH);
    routing_table_entry->source_id = source_id;
    routing_table_entry->destination_id = destination_id;
    routing_table_entry->length_of_path = length;
    routing_table_entry->link_identifiers = link_identifiers;
    // --------------------- 进行一条路由的信息的初始化 ---------------------

    // ------------------------ 进行路由的插入以及查询以及最终路由表的删除 ------------------------
    LOG_WITH_EDGE("start testing routing table");
    // 进行路由条目的插入
    add_entry_to_routing_table(head_pointer_list, routing_table_entry);
    // 进行路由条目的查找
    find_entry = find_entry_in_routing_table(head_pointer_list, source_id, destination_id);
    printk(KERN_EMERG "[zeusnet's kernel info]:source_id: %d destination_id: %d\n", find_entry->source_id,
           find_entry->destination_id);
    delete_routing_table(head_pointer_list);
    LOG_WITH_EDGE("stop  testing routing table");
    // ------------------------ 进行路由的插入以及查询以及最终路由表的删除 ------------------------
}

/**
 * 根据 ip 地址进行选取
 * @param current_net_namespace 当前的网络命名空间
 * @param iph ip 首部
 * @return
 */
struct RoutingTableEntry* get_routing_table_entry_by_iph(struct net* current_net_namespace, struct iphdr* iph){
    struct RoutingTableEntry* routing_table_entry; // 结果路由表项
    struct hlist_head* lir_routing_table = get_lir_routing_table_from_net_namespace(current_net_namespace); // 从网络命名空间之中获取路由表
    u8 * opt_data_pointer = (u8 *) &(iph[1]); // 拿到ip选项部分的第一个字节
    int current_satellite_id = get_satellite_id(current_net_namespace);
    int source_satellite_id = *(opt_data_pointer + OPTION_START_INDEX - 1); // 在选项部分存储了源的卫星的编号
    routing_table_entry = find_entry_in_routing_table(lir_routing_table, current_satellite_id, source_satellite_id); // 根据源卫星查找路由
    return routing_table_entry;
}

/**
 * 根据 ip 选项进行路由表条目的获取
 * @param current_net_namespace 当前的网络命名空间
 * @param opt ip 选项
 * @return
 */
struct RoutingTableEntry* get_routing_table_entry_by_sock_opt(struct net *current_net_namespace, struct ip_options_rcu *opt){
    struct RoutingTableEntry* routing_table_entry; // 结果路由表项
    int destination_satellite_id = opt->opt.__data[OPTION_START_INDEX + 1];    // 获取目的节点
    struct hlist_head *lir_routing_table = get_lir_routing_table_from_net_namespace(current_net_namespace); // 获取路由表
    int current_satellite_id = get_satellite_id(current_net_namespace);
    routing_table_entry = find_entry_in_routing_table(lir_routing_table, current_satellite_id, destination_satellite_id);
    return routing_table_entry;
}

/**
 * 进行目的地址列表的获取并且构建bf
 * @param current_net_namespace 当前的网络命名空间
 * @param opt ip 选项
 */
struct LirReturnDataStructure get_destination_list_and_construct_bf(struct net *current_net_namespace, struct ip_options_rcu *opt) {
    struct LirReturnDataStructure lir_return_data_structure = {
            .output_interface = NULL
    };
    struct net_device* output_interface;
    struct bloom_filter *net_bloom_filter = get_bloom_filter(current_net_namespace);
    struct hlist_head *lir_routing_table = get_lir_routing_table_from_net_namespace(current_net_namespace);
    int current_satellite_id = get_satellite_id(current_net_namespace);
    int intermediate_satellite_id = -1;
    // 当前已经获取的目的地的数量
    int count = 0;
    // 当前获取的目的地的编号
    int destination;
    // 目的地的数量
    int size_of_destination = opt->opt.__data[OPTION_START_INDEX];
    // 进行布隆过滤器的重置
    reset_bloom_filter(net_bloom_filter);
    // 主节点的编号
    int primary_node;
    while (true) {
        // 目的表项
        struct RoutingTableEntry *lir_routing_entry;
        // 如果当前已经获取的目的地的数量 == 目的地的总数
        if (count == size_of_destination) {
            break;
        }
        if (count == 0){
            // 获取目的节点
            destination = opt->opt.__data[OPTION_START_INDEX + count + 1];
            // 第一个目的节点将被视为主节点
            primary_node = destination;
            // 计算从源节点到主节点的路由
            lir_routing_entry = find_entry_in_routing_table(lir_routing_table, current_satellite_id, primary_node);
            // 设置出接口
            output_interface = lir_routing_entry->output_interface;
            // 打印条目
            // print_routing_table_entry(lir_routing_entry);
            // 存储目的节点编号
            lir_return_data_structure.destination_node_id = destination;
        } else {
            // 获取目的节点
            destination = opt->opt.__data[OPTION_START_INDEX + count + 1];
            // 计算从主节点到其他节点的路由
            lir_routing_entry = find_entry_in_routing_table(lir_routing_table, primary_node, destination);
            // 打印条目
            // print_routing_table_entry(lir_routing_entry);
        }
        // ----------------------------------------------分段封装的代码----------------------------------------------
        // 情况1: encoding_count <= 0
        int encoding_count = get_encoding_count(current_net_namespace);
        if(encoding_count <= 0){
            int index;
            // 找到了相应的路由条目之后，将路由条目中存储的布隆过滤器和现有的布隆过滤器相或
            u8* net_bloom_filter_bit_set = (u8*)(net_bloom_filter->bitset);
            u8* routing_entry_bit_set = (u8*)(lir_routing_entry->bitset);
            for(index = 0; index < net_bloom_filter->effective_bytes; index++){
                net_bloom_filter_bit_set[index] |= routing_entry_bit_set[index];
            }
        }
        // 情况2: encoding_count > 0
        else{
            // 2 --> 3 --> 4 --> 5 --> 6
            int index;
            for(index = 0; (index < encoding_count) && (index < lir_routing_entry->length_of_path); index++){
                push_element_into_bloom_filter(net_bloom_filter, &(lir_routing_entry->link_identifiers[index]), sizeof(int));
            }
            intermediate_satellite_id = lir_routing_entry->node_ids[index-1];
            // printk(KERN_EMERG "intermediate node id = %d\n", intermediate_satellite_id);
        }
        // ----------------------------------------------分段封装的代码----------------------------------------------
        count++;
    }
    // 拷贝一份布隆过滤器并进行返回
    lir_return_data_structure.bloom_filter = net_bloom_filter;
    lir_return_data_structure.output_interface = output_interface;
    lir_return_data_structure.intermediate_node_id = intermediate_satellite_id;
    return lir_return_data_structure;
}

/**
 * 根据给定的新的布隆过滤器的设置，进行重新的bitset的计算
 */
void rebuild_routing_table_with_new_bf_settings(struct bloom_filter* bloom_filter, struct hlist_head* lir_routing_table){
    struct hlist_head *hash_bucket = NULL;
    struct RoutingTableEntry *current_entry = NULL;
    struct hlist_node *next;
    int index;

    for (index = 0; index < BUCKET_COUNT; index++) {
        hash_bucket = &lir_routing_table[index];
        // 拿到 hash_bucket 之后，遍历这个链表
        hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
            // 重新根据布隆过滤器计算 bitset
            // 首先将旧的布隆过滤器二进制向量给清空
            reset_bloom_filter(bloom_filter);
            // 首先将 bitset 进行清空
            memset(current_entry->bitset, 0, sizeof(unsigned long) * bloom_filter->total_length);
            // 重新根据布隆过滤器进行计算
            push_elements_into_bloom_filter(bloom_filter, current_entry->length_of_path, current_entry->link_identifiers);
            // 计算出了新的布隆过滤器之后进行拷贝
            memcpy(current_entry->bitset, bloom_filter->bitset, sizeof(unsigned long) * bloom_filter->effective_bytes);
            // 重新填充 route entry 的 effective_bytes 部分
            current_entry->effective_bytes = bloom_filter->effective_bytes;
        }
    }
}