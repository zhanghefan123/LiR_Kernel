//
// Created by kernel-dbg on 24-2-1.
//

#ifndef ZEUSNET_KERNEL_LIR_BLOOM_FILTER_H
#define ZEUSNET_KERNEL_LIR_BLOOM_FILTER_H
#include <asm-generic/int-ll64.h>
#define BLOOM_FILTER_TOTAL_LENGTH 5
struct bloom_filter {
    int total_length; // note that total length may not be full used
    u32 bitset_mask; // bitset mask can be 31 represent for 32 bit - bitset can be 63 represent for 63 bit
    u32 hash_seed; // hash seed
    u32 aligned_u32_count; // number of u32 values in this array
    u32 nr_hash_funcs; // number of hash functions
    unsigned long* bitset; // bloom filter bitset and how to assign it
    u32 effective_bytes; // the effective bytes in bloom filter, it should be calculated while in the bloom filter params setting
};
struct bloom_filter* copy_bloom_filter(struct bloom_filter* bloom_filter);
void reset_bloom_filter(struct bloom_filter* old_bloom_filter);
struct bloom_filter* init_bloom_filter(int total_length);
void delete_bloom_filter(struct bloom_filter* bf);
u32 bloom_hash_function(struct bloom_filter* bloom, void* value, u32 value_size, u32 index);
void push_element_into_bloom_filter(struct bloom_filter* bloom, void* value, u32 value_size);
void push_elements_into_bloom_filter(struct bloom_filter* bloom, int length, int* value);
int check_element_in_bloom_filter(struct bloom_filter* bloom, void* value, u32 value_size);
void printk_binary_u32(u32 n);
void printk_binary_u8(u8 n);
void test_self_defined_bloom_filter(void);
#endif
