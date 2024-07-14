//
// Created by zhf on 24-4-17.
//

#ifndef ZEUSNET_KERNEL_CRYPTO_FUNCTION_H
#define ZEUSNET_KERNEL_CRYPTO_FUNCTION_H
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include "network_lir_header.h"
#define HASH_OUTPUT_LENGTH_IN_BYTES 32
#define HMAC_OUTPUT_LENGTH_IN_BYTES 32
struct shash_desc* generate_hash_data_structure(void);
struct shash_desc* generate_hmac_data_structure(void);
void free_crypto_data_structure(struct shash_desc* hmac_data_structure);
unsigned char* calculate_hash(struct shash_desc* hash_data_structure, char* data);
u32* calculate_hmac(struct shash_desc* hmac_data_structure, unsigned char* data, int length_of_data ,char* key);
void print_hash_or_hmac_result(unsigned char* output, int length);
void test_hash_and_hmac(struct net* current_net_namespace);
unsigned char *calculate_static_fields_hash_of_bpt(struct lirhdr *lir_header,
                                                   struct udphdr *udp_header,
                                                   struct net *net);
unsigned char* calculate_static_fields_hash_of_multiple_memory_blocks(char** memory_blocks, int* size_of_each_block, int block_size, struct net* net);
#endif // ZEUSNET_KERNEL_CRYPTO_FUNCTION_H
