//
// Created by zhf on 24-4-17.
//
#include "headers/crypto_function.h"
#include "headers/lir_data_structure.h"
#include <crypto/dh.h>
#include <crypto/kpp.h>

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

/**
 * 进行icing之中字段的静态哈希的计算。
 * @param lir_header lir 首部
 * @param udp_header udp 首部
 * @param net 网络命名空间
 * @param length_of_path 路径的长度
 * @return
 */
unsigned char *calculate_static_fields_hash_of_icing(struct lirhdr *lir_header,
                                                     struct udphdr *udp_header,
                                                     struct net *net,
                                                     int length_of_path) {
    int block_size = 2;
    char* memory_blocks[block_size]; // 内存区块数组
    int size_of_each_block[block_size]; // 每个内存区块的长度
    unsigned char* output; // 最终的多个内存区块的哈希结果
    // --------------------------------------- 创建第一个 memory block ---------------------------------------
    memory_blocks[0] = (char*)(lir_header);
    int size_of_icing_path = (int) (sizeof(struct single_hop_icing)) * length_of_path; // ICING 路径字段的长度
    __u16 original_current_path_index = lir_header->current_path_index; // 提前进行 current_path_index 的存储，因为其不纳入计算
    __u16 original_check_sum = lir_header->check;
    __u16 original_id = lir_header->id;
    __u16 original_current_hop = lir_header->current_hop;
    lir_header->id = 0;
    lir_header->current_path_index = 0; // 将不纳入哈希计算的字段置为0
    lir_header->check = 0; // 不将check纳入哈希计算
    lir_header->current_hop = 0;
    int size_of_lir_header_and_icing_path = (int)(sizeof(struct lirhdr)) + size_of_icing_path; // LIR 标准头长度 + ICING 路径的长度
    size_of_each_block[0] = size_of_lir_header_and_icing_path;
    // --------------------------------------- 创建第一个 memory block ---------------------------------------
    // --------------------------------------- 创建第二个 memory block ---------------------------------------
    char* start_of_app_data = (char*)(udp_header) + sizeof(struct udphdr); // 获取 app 的索引
    memory_blocks[1] = start_of_app_data;
    size_of_each_block[1] = strlen(start_of_app_data);
    // --------------------------------------- 创建第二个 memory block ---------------------------------------
    // ---------------------------------------      准备计算哈希值      ---------------------------------------
    output = calculate_static_fields_hash_of_multiple_memory_blocks(memory_blocks, size_of_each_block, block_size, net);
    // ---------------------------------------      准备计算哈希值      ---------------------------------------
    // ---------------------------------------      进行字段的还原      ---------------------------------------
    lir_header->current_path_index = original_current_path_index;
    lir_header->check = original_check_sum;
    lir_header->id = original_id;
    lir_header->current_hop = original_current_hop;
    // ---------------------------------------      进行字段的还原      ---------------------------------------
    return output;
}

unsigned char *calculate_static_fields_hash_of_lir(struct lirhdr *lir_header, struct net *net) {
    struct shash_desc *hash_data_structure = get_hash_data_structure(net);  // get hash data structure
    char *last_char = (char *) &(lir_header[1]) - sizeof(__u16);
    char old_char = *last_char;
    __u16 old_check_sum = lir_header->check;
    *last_char = '\0';
    unsigned char *static_fields_hash = calculate_hash(hash_data_structure, (char *) (lir_header)); // RETURN 32 BYTES
    *last_char = old_char;
    lir_header->check = old_check_sum;
    return static_fields_hash;
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
unsigned char *
calculate_hmac(struct shash_desc *hmac_data_structure, unsigned char *data, int length_of_data, char *key) {
    unsigned char hmac_output[HMAC_OUTPUT_LENGTH_IN_BYTES];
    unsigned char *real_output = (unsigned char *) (kmalloc(sizeof(unsigned char) * ICING_VALIDATION_SIZE_IN_BYTES,
                                                            GFP_KERNEL));
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
    // copy hmac_output to real_output
    memcpy(real_output, hmac_output, sizeof(unsigned char) * ICING_VALIDATION_SIZE_IN_BYTES);
    return real_output;
}

// RETURN 32 BYTES
unsigned char *calculate_hash(struct shash_desc *hash_data_structure, char *data) {
    unsigned char *output = kmalloc(sizeof(unsigned char) * HASH_OUTPUT_LENGTH_IN_BYTES, GFP_KERNEL);
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

