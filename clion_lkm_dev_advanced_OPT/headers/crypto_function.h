//
// Created by zhf on 24-4-17.
//

#ifndef ZEUSNET_KERNEL_CRYPTO_FUNCTION_H
#define ZEUSNET_KERNEL_CRYPTO_FUNCTION_H
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include "network_lir_header.h"
// SHA1 only have 160 bits and 20 bytes
// SHA3-256 have 256 bits and 32 bytes
#define HASH_OUTPUT_LENGTH_IN_BYTES 32
#define HMAC_OUTPUT_LENGTH_IN_BYTES 32
#define OPT_VALIDATION_SIZE_IN_BYTES 16
struct shash_desc* generate_hash_data_structure(void);
struct shash_desc* generate_hmac_data_structure(void);
unsigned char* calculate_static_fields_hash_of_lir(struct lirhdr* lir_header, struct net* net);
unsigned char* calculate_payload_hash(struct udphdr* lir_header, struct net* net);
void free_crypto_data_structure(struct shash_desc* hmac_data_structure);
unsigned char* calculate_hash(struct shash_desc* hash_data_structure, char* data);
unsigned char* calculate_fixed_length_hash(struct shash_desc* hash_data_structure, unsigned char* data, int length_of_data);
unsigned char* calculate_hmac(struct shash_desc* hmac_data_structure, unsigned char* data, int length_of_data, char* key);
void print_hash_or_hmac_result(unsigned char* output, int length);
#endif // ZEUSNET_KERNEL_CRYPTO_FUNCTION_H
