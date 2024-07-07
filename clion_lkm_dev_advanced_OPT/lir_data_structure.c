#include "headers/lir_data_structure.h"
#include "headers/session_path_table.h"

/**
 * set new interface table in lir data structure
 * @param net_namespace
 * @param new_interface_table
 */
void set_new_interface_table_in_lir_data_structure(struct net* net_namespace, struct NewInterfaceTable* new_interface_table){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
    lir_data_structure->new_interface_table = new_interface_table;
}

struct NewInterfaceTable* get_new_interface_table_from_net_namespace(struct net* net_namespace){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
    if(NULL == lir_data_structure){
        return NULL;
    }
    return lir_data_structure->new_interface_table;
}



/**
 * 进行 lir 数据结构的初始化
 * @param net_namespace 当前的网络命名空间
 */
void init_lir_data_structure_in_net_namespace(struct net* net_namespace){
    // ---------------------- 初始化路由表和接口表 --------------------------
    struct hlist_head* lir_session_path_table = init_session_path_table();
    struct hlist_head* lir_routing_table = init_routing_table();
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)kmalloc(sizeof(struct LirDataStructure), GFP_KERNEL);
    struct bloom_filter * lir_bloom_filter = init_bloom_filter(BLOOM_FILTER_TOTAL_LENGTH);
    lir_data_structure->session_path_table = lir_session_path_table;
    lir_data_structure->lir_routing_table = lir_routing_table;
    lir_data_structure->new_interface_table = NULL;
    lir_data_structure->initializing = true;
    lir_data_structure->bloom_filter = lir_bloom_filter;
    lir_data_structure->number_of_link_identifiers = 0;
    lir_data_structure->link_identifiers = kmalloc(sizeof(int) * MAX_INTERFACE_COUNT, GFP_KERNEL);
    lir_data_structure->hmac_data_structure = generate_hmac_data_structure();
    lir_data_structure->hash_data_structure = generate_hash_data_structure();
    // ----------------------   初始化链路标识数组 -------------------------
    net_namespace->crypto_nlsk = (struct sock*)(lir_data_structure);
}



/**
 * 进行 lir 数据结构的释放
 * @param net_namespace 当前的网络命名空间
 */
void free_lir_data_structure_in_net_namespace(struct net* net_namespace){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
    delete_session_path_table(lir_data_structure->session_path_table);
    delete_routing_table(lir_data_structure->lir_routing_table);
    delete_bloom_filter(lir_data_structure->bloom_filter);
    delete_new_interface_table(lir_data_structure->new_interface_table);
    kfree(lir_data_structure->link_identifiers);
    kfree(lir_data_structure);
    free_crypto_data_structure(lir_data_structure->hmac_data_structure);
    free_crypto_data_structure(lir_data_structure->hash_data_structure);
    net_namespace->crypto_nlsk = NULL;
}

/**
 * 获取 lir 数据结构
 * @param current_net_namespace 当前的网络命名空间
 * @return
 */
struct LirDataStructure* get_lir_data_structure(struct net* current_net_namespace){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(current_net_namespace->crypto_nlsk);
    return lir_data_structure;
}

/**
 * 通过网络命名空间获取路由表
 * @param net_namespace 当前的网络命名空间
 * @return 路由表
 */
struct hlist_head* get_lir_routing_table_from_net_namespace(struct net* net_namespace){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
    return lir_data_structure->lir_routing_table;
}

struct hlist_head* get_session_path_table_from_net_namespace(struct net* net_namespace){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
    return lir_data_structure->session_path_table;
}

/**
 * 通过网络命名空间获取接口表
 * @param net_namespace 当前的网络命名空间
 * @return 接口表
 */
//struct hlist_head* get_lir_interface_table_from_net_namespace(struct net* net_namespace){
//    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
//    if(NULL == lir_data_structure){
//        return NULL;
//    }
//    return lir_data_structure->lir_interface_table;
//}

/**
 * 设置网络命名空间对应的卫星 id
 * @param net_namespace 当前的网络命名空间
 * @param satellite_id 卫星的id
 */
void set_satellite_id(struct net* net_namespace, int satellite_id){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
    lir_data_structure->satellite_id = satellite_id;
}

/**
 * 通过网络命名空间获取卫星的 id
 * @param net_namespace 当前的网络命名空间
 * @return
 */
int get_satellite_id(struct net* net_namespace){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
    return lir_data_structure->satellite_id;
}

/**
 * 通过网络命名空间获取布隆过滤器
 * @param net_namespace 当前的网络命名空间
 * @return
 */
struct bloom_filter* get_bloom_filter(struct net* net_namespace){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
    return lir_data_structure->bloom_filter;
}

/**
 * 判断当前是否经历了初始化阶段，如果为true表示尚未进行初始化阶段，如果为 false 表示已经进行了初始化阶段
 * @param net_namespace 当前的网络命名空间
 * @return
 */
bool get_if_initializing(struct net* net_namespace){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
    return lir_data_structure->initializing;
}

/**
 * 表示已经经过了初始化阶段
 * @param net_namespace 当前的网络命名空间
 */
void set_initialized(struct net* net_namespace){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
    lir_data_structure->initializing = false;
}

/**
 * get hmac calculation function
 * @param net_namespace
 * @return
 */
struct shash_desc* get_hmac_data_structure(struct net* net_namespace){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
    return lir_data_structure->hmac_data_structure;
}

/**
 * get hash calculation function
 * @param net_namespace
 * @return
 */
struct shash_desc* get_hash_data_structure(struct net* net_namespace){
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(net_namespace->crypto_nlsk);
    return lir_data_structure->hash_data_structure;
}