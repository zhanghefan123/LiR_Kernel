//
// Created by zhf on 24-4-17.
//

#ifndef ZEUSNET_KERNEL_CRYPTO_FUNCTION_H
#define ZEUSNET_KERNEL_CRYPTO_FUNCTION_H
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#define LENGTH_OF_HASH 20
struct shash_desc* generate_hash_data_structure(void);
struct shash_desc* generate_hmac_data_structure(void);
void free_crypto_data_structure(struct shash_desc* hmac_data_structure);
unsigned char* calculate_hash(struct shash_desc* hash_data_structure, char* data);
u32* calculate_hmac(struct shash_desc* hmac_data_structure, unsigned char* data, int length_of_data ,char* key);
void print_hash_or_hmac_result(unsigned char* output, int length);
void test_hash_and_hmac(struct net* current_net_namespace);
#endif // ZEUSNET_KERNEL_CRYPTO_FUNCTION_H
