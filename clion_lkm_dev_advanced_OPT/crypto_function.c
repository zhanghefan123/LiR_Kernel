//
// Created by zhf on 24-4-17.
//
#include "headers/crypto_function.h"
#include "headers/lir_data_structure.h"
#include <crypto/dh.h>
#include <crypto/kpp.h>

/**
 * @param net 网络命名空间
 * @param route_str_repr 路径的字符串表示
 * @return 计算出来的 SESSIONID (只进行 path 的哈希)
 */
unsigned char* calculate_session_id(struct net* net, char* route_str_repr){
    struct shash_desc* hash_data_structure = get_hash_data_structure(net);
    unsigned char* path_hash = calculate_hash(hash_data_structure, route_str_repr);  // 获取payload哈希
    print_hash_or_hmac_result(path_hash, HASH_OUTPUT_LENGTH_IN_BYTES); // 输出哈希结果
    return path_hash;
}

struct shash_desc* generate_hash_data_structure(void){
    struct crypto_shash* tfm;
    struct shash_desc *shash;
    char* hash_algorithm = "sha3-256";  // change from sha1 to sha3-256
    tfm = crypto_alloc_shash(hash_algorithm, 0, 0);
    if(IS_ERR(tfm)){
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
        printk(KERN_EMERG "memory block %d block size %d\n", index, size_of_block);
        print_hash_or_hmac_result((unsigned char*)(memory_blocks[index]), size_of_block);
        if(crypto_shash_update(hash_data_structure, memory_block, size_of_block)){
            return NULL;
        }
    }
    // 进行结果的输出
    if(crypto_shash_final(hash_data_structure, output)){
        return NULL;
    }
    print_hash_or_hmac_result(output, HASH_OUTPUT_LENGTH_IN_BYTES);
    return output;
}

struct shash_desc* generate_hmac_data_structure(void){
    struct crypto_shash* tfm;
    struct shash_desc *shash;
    char* hmac_algorithm = "hmac(sha3-256)";
    tfm = crypto_alloc_shash(hmac_algorithm, 0, 0);
    if(IS_ERR(tfm)){
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
 * 进行 lir 的 payload 部分的 hash 的运算
 * @param lir_header lir 的头部
 * @param net 网络命名空间
 * @return
 */
unsigned char* calculate_static_fields_hash_of_lir(struct lirhdr* lir_header, struct net* net){
    struct shash_desc* hash_data_structure = get_hash_data_structure(net);  // get hash data structure
    char* last_char = (char*)&(lir_header[1]) - sizeof(__u16);
    char old_char = *last_char;
    __u16 old_check_sum = lir_header->check;
    *last_char = '\0';
    unsigned char* static_fields_hash = calculate_hash(hash_data_structure, (char*)(lir_header)); // RETURN 32 BYTES
    *last_char = old_char;
    lir_header->check = old_check_sum;
    return static_fields_hash;
}

/**
 * 计算 payload 部分的哈希值
 * @param udp_header 传输曾指针
 * @param app_length app 数据的长度
 * @return
 */
unsigned char* calculate_payload_hash(struct udphdr* udp_header, struct net* net){
    char* app_start = (char*)(udp_header) + sizeof(struct udphdr); // 获取 app 起始的位置
    struct shash_desc* hash_data_structure = get_hash_data_structure(net);  // 获取哈希数据结构
    unsigned char* static_fields_hash = calculate_hash(hash_data_structure, app_start);  // 获取payload哈希
    print_hash_or_hmac_result(static_fields_hash, HASH_OUTPUT_LENGTH_IN_BYTES); // 输出哈希结果
    return static_fields_hash;
}

void free_crypto_data_structure(struct shash_desc* hmac_data_structure){
    if(hmac_data_structure){
        if(hmac_data_structure->tfm){
            printk(KERN_EMERG "free tfm\n");
            crypto_free_shash(hmac_data_structure->tfm);
        }
        printk(KERN_EMERG "free shash\n");
        kfree(hmac_data_structure);
    }
}


// return the heap memory / remember to release
unsigned char* calculate_hmac(struct shash_desc* hmac_data_structure, unsigned char* data, int length_of_data, char* key){
    unsigned char hmac_output[HMAC_OUTPUT_LENGTH_IN_BYTES];
    unsigned char* real_output = (unsigned char*)(kmalloc(sizeof(unsigned char) * OPT_VALIDATION_SIZE_IN_BYTES, GFP_KERNEL));
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
    memcpy(real_output, hmac_output, sizeof(unsigned char) * OPT_VALIDATION_SIZE_IN_BYTES);
    return real_output;
}

// RETURN 32 BYTES
unsigned char* calculate_hash(struct shash_desc* hash_data_structure, char* data){
    unsigned char* output = kmalloc(sizeof(unsigned char) * HASH_OUTPUT_LENGTH_IN_BYTES, GFP_KERNEL);
    if(crypto_shash_init(hash_data_structure)){
        return NULL;
    }
    if(crypto_shash_update(hash_data_structure, data, strlen(data))){
        return NULL;
    }
    if(crypto_shash_final(hash_data_structure, output)){
        return NULL;
    }
    return output;
}

unsigned char* calculate_fixed_length_hash(struct shash_desc* hash_data_structure, unsigned char* data, int length_of_data){
    unsigned char old_char = data[length_of_data];
    data[length_of_data] = '\0';
    unsigned char* result = calculate_hash(hash_data_structure, (char*)data);
    data[length_of_data] = old_char;
    return result;
}

void print_hash_or_hmac_result(unsigned char* output, int length){
    int i;
    printk(KERN_CONT "RESULT ");
    for (i = 0; i < length; i++)
        printk(KERN_CONT "%02x", output[i]);
    printk(KERN_CONT "\n");
}

