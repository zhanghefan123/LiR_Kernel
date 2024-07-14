//
// Created by zhf on 24-4-17.
//
#include "headers/crypto_function.h"
#include "headers/lir_data_structure.h"
#include "headers/network_lir_header.h"

unsigned char *calculate_static_fields_hash_of_bpt(struct lirhdr *lir_header,
                                                   struct udphdr *udp_header,
                                                   struct net *net) {
    int block_size = 2;
    char* memory_blocks[block_size]; // 内存区块数组
    int size_of_each_block[block_size]; // 最终的多个内存区块的哈希结果
    unsigned char* output;
    // ----------------------------- 创建第一个 memory block -----------------------------
    memory_blocks[0] = (char*)(lir_header);
    int size_of_lir_header = (int)(sizeof(struct lirhdr)) - 4;
    __u16 original_check_sum = lir_header->check;
    __u16 original_total_len = lir_header->total_len;
    __u16 original_current_hop = lir_header->current_hop;
    lir_header->check = 0;
    lir_header->total_len = 0;
    lir_header->current_hop = 0;
    size_of_each_block[0] = size_of_lir_header;
    // ----------------------------- 创建第一个 memory block -----------------------------
    // ----------------------------- 创建第二个 memory block -----------------------------
    char* start_of_app_data = (char*)(udp_header) + sizeof(struct udphdr);
    memory_blocks[1] = start_of_app_data;
    size_of_each_block[1] = strlen(start_of_app_data);
    // ----------------------------- 创建第二个 memory block -----------------------------
    // -----------------------------   准备进行哈希值的计算   ------------------------------
    output = calculate_static_fields_hash_of_multiple_memory_blocks(memory_blocks, size_of_each_block, block_size, net);
    // -----------------------------   准备进行哈希值的计算   ------------------------------
    // -----------------------------   准备进行字段的还原过程  -----------------------------
    lir_header->check = original_check_sum;
    lir_header->total_len = original_total_len;
    lir_header->current_hop = original_current_hop;
    // -----------------------------   准备进行字段的还原过程  -----------------------------
    return output;
}

/**
 * 计算多个不同的区块之中的哈希值
 * @param memory_blocks 内存的区块
 * @param size_of_each_block 每个区块的大小
 * @param block_size 单个区块的大小
 */
unsigned char* calculate_static_fields_hash_of_multiple_memory_blocks(char** memory_blocks, int* size_of_each_block, int block_size, struct net* net){
    int index;  // 当前处理的内存块的索引
    struct shash_desc* hash_data_structure = get_hash_data_structure(net);  // hash 数据结构
    unsigned char* output = kmalloc(sizeof(unsigned char) * HASH_OUTPUT_LENGTH_IN_BYTES, GFP_KERNEL); // 哈希的输出结果
    if(crypto_shash_init(hash_data_structure)){
        return NULL;
    }
    for(index=0; index < (block_size); index++){  // 进行所有的内存块的遍历，并进行哈希值的更新
        int size_of_block = size_of_each_block[index];
        char* memory_block = memory_blocks[index];
        // printk(KERN_EMERG "memory block %d block size %d\n", index, size_of_block);
        // print_hash_or_hmac_result((unsigned char*)(memory_blocks[index]), size_of_block);
        if(crypto_shash_update(hash_data_structure, memory_block, size_of_block)){
            return NULL;
        }
    }
    // 进行结果的输出
    if(crypto_shash_final(hash_data_structure, output)){
        return NULL;
    }
    // print_hash_or_hmac_result(output, HASH_OUTPUT_LENGTH_IN_BYTES);
    return output;
}

struct shash_desc *generate_hash_data_structure(void) {
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    char *hash_algorithm = "sha3-256";
    tfm = crypto_alloc_shash(hash_algorithm, 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_EMERG "create failed\n");
        return NULL;
    }
    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash) {
        printk(KERN_EMERG "Failed to allocate shash desc.\n");
        crypto_free_shash(tfm);
        return NULL;
    }
    shash->tfm = tfm;
    return shash;
}

struct shash_desc *generate_hmac_data_structure(void) {
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    char *hmac_algorithm = "hmac(sha3-256)";
    tfm = crypto_alloc_shash(hmac_algorithm, 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_EMERG "create failed\n");
        return NULL;
    }
    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash) {
        printk(KERN_EMERG "Failed to allocate shash desc.\n");
        crypto_free_shash(tfm);
        return NULL;
    }
    shash->tfm = tfm;
    return shash;
}

void free_crypto_data_structure(struct shash_desc *hmac_data_structure) {
    if (hmac_data_structure) {
        if (hmac_data_structure->tfm) {
            printk(KERN_EMERG "free tfm\n");
            crypto_free_shash(hmac_data_structure->tfm);
        }
        printk(KERN_EMERG "free shash\n");
        kfree(hmac_data_structure);
    }
}

// return the heap memory / remember to release
u32 *calculate_hmac(struct shash_desc *hmac_data_structure, unsigned char *data, int length_of_data, char *key) {
    unsigned char hmac_output[HMAC_OUTPUT_LENGTH_IN_BYTES];
    u32 * real_output = (u32 *) (kmalloc(sizeof(u32), GFP_KERNEL));
    // set key in hmac
    if (crypto_shash_setkey(hmac_data_structure->tfm, key, strlen(key))) {
        printk(KERN_ERR "Failed to set key.\n");
        crypto_free_shash(hmac_data_structure->tfm);
        kfree(hmac_data_structure);
        return NULL;
    }
    // calculate digest
    if (crypto_shash_digest(hmac_data_structure, data, length_of_data, hmac_output)) {
        printk(KERN_ERR "Failed to compute HMAC.\n");
        crypto_free_shash(hmac_data_structure->tfm);
        kfree(hmac_data_structure);
        return NULL;
    }
    // copy hmac_output to real_output, here only used 32 out of 256
    memcpy(real_output, hmac_output, sizeof(u32));
    return real_output;
}

unsigned char *calculate_hash(struct shash_desc *hash_data_structure, char *data) {
    unsigned char *output = kmalloc(sizeof(unsigned char) * 20, GFP_KERNEL);
    if (crypto_shash_init(hash_data_structure)) {
        return NULL;
    }
    if (crypto_shash_update(hash_data_structure, data, strlen(data))) {
        return NULL;
    }
    if (crypto_shash_final(hash_data_structure, output)) {
        return NULL;
    }
    return output;
}

void print_hash_or_hmac_result(unsigned char *output, int length) {
    int i;
    printk(KERN_CONT "RESULT ");
    for (i = 0; i < length; i++)
        printk(KERN_CONT "%02x", output[i]);
    printk(KERN_CONT "\n");
}

void test_hash_and_hmac(struct net *current_net_namespace) {
    // ----------------------------------------- test hash function -----------------------------------------
    struct LirDataStructure *lir_data_structure = (struct LirDataStructure *) (current_net_namespace->crypto_nlsk);
    unsigned char *hash_result = calculate_hash(lir_data_structure->hash_data_structure, "123");
    // ----------------------------------------- test hash function -----------------------------------------
    char key_from_source_to_intermediate[20];
    sprintf(key_from_source_to_intermediate, "key-%d-%d", 1, 2);
    u32 * hmac_result = calculate_hmac(lir_data_structure->hmac_data_structure,
                                       hash_result, HASH_OUTPUT_LENGTH_IN_BYTES, key_from_source_to_intermediate);
    print_hash_or_hmac_result((unsigned char *) hmac_result, 4);
    *hmac_result = (*hmac_result) ^ (u32) (1);
    print_hash_or_hmac_result((unsigned char *) hmac_result, 4);
    kfree(hash_result);
    kfree(hmac_result);
}

