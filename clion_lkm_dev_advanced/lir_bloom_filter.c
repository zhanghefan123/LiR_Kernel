//
// Created by zhf on 24-4-12.
//
//
// Created by kernel-dbg on 24-2-1.
//
#include "headers/lir_bloom_filter.h"
#include "headers/support_tools.h"
#include <linux/kernel.h>
#include <linux/jhash.h>
#include <asm-generic/bitops/instrumented-atomic.h>
#include <asm-generic/bitops/instrumented-non-atomic.h>

/**
 * 进行布隆过滤器的初始化
 * @param total_length 总长度 (8字节为单位)
 */
struct bloom_filter* init_bloom_filter(int total_length){
    struct bloom_filter* created_bloom_filter = (struct bloom_filter*)kmalloc(sizeof (struct bloom_filter), GFP_KERNEL);
    created_bloom_filter->total_length = total_length;
    created_bloom_filter->aligned_u32_count = 0x0;
    created_bloom_filter->bitset = (unsigned long*)kmalloc(sizeof(unsigned long) * total_length, GFP_KERNEL);
    memset(created_bloom_filter->bitset, 0, total_length);
    return created_bloom_filter;
}

/**
 * 进行布隆过滤器的克隆，返回新的布隆过滤器
 * @param old_bloom_filter 想要进行克隆的布隆过滤器
 * @return 新创建出来的布隆过滤器
 */
struct bloom_filter* copy_bloom_filter(struct bloom_filter* old_bloom_filter){
    struct bloom_filter* new_bloom_filter = init_bloom_filter(old_bloom_filter->total_length);
    LOG_WITH_PREFIX("copy bloom filter");
    new_bloom_filter->bitset_mask = old_bloom_filter->bitset_mask;
    new_bloom_filter->hash_seed = old_bloom_filter->hash_seed;
    new_bloom_filter->aligned_u32_count = old_bloom_filter->aligned_u32_count;
    new_bloom_filter->nr_hash_funcs = old_bloom_filter->nr_hash_funcs;
    new_bloom_filter->effective_bytes = old_bloom_filter->effective_bytes;
    memcpy(new_bloom_filter->bitset, old_bloom_filter->bitset, sizeof(unsigned long) * old_bloom_filter->total_length);
    return new_bloom_filter;
}

/**
 * 进行布隆过滤器的重置，即将其中的二进制数组全部置为0
 * @param bloom_filter
 */
void reset_bloom_filter(struct bloom_filter* bloom_filter){
    if(bloom_filter->bitset != NULL){
        memset(bloom_filter->bitset, 0, bloom_filter->total_length);
    }
}

/**
 * 进行布隆过滤器的释放
 * @param bf 要释放的 bf
 */
void delete_bloom_filter(struct bloom_filter* bf){
    if(bf != NULL){
        if(bf->bitset != NULL){
            kfree(bf->bitset);
        }
        kfree(bf);
    }
    LOG_WITH_PREFIX("delete bloom filter");
}

/**
 * 将一个传入的值首先通过hash函数映射到一个从 [0, bitset_mask-1] 的索引
 * @param bloom 布隆过滤器
 * @param value 要插入到布隆过滤器之中的值
 * @param value_size 值的大小 (字节)
 * @param random_value 随便取值
 * @return 从 [0, bitset_mask] 的索引, 所以一般取 31 63 这种
 */
u32 bloom_hash_function(struct bloom_filter* bloom, void* value, u32 value_size, u32 random_value){
    u32 h; // hash value
    // if the value is aligned to 32 bits, use jhash2
    if(bloom->aligned_u32_count){
        h = jhash2(value, bloom->aligned_u32_count, bloom->hash_seed + random_value);
    }
        // if the value is not aligned to 32 bits, use jhash
    else {
        h = jhash(value, value_size, bloom->hash_seed + random_value);
    }
    return h % bloom->bitset_mask;
}

/**
 * 将一个值插入到布隆过滤器之中
 * @param bloom 布隆过滤器
 * @param value 要插入到布隆过滤器之中的值
 * @param value_size 值的大小 (字节)
 * @return void
 */
void push_element_into_bloom_filter(struct bloom_filter* bloom, void* value, u32 value_size){
    u32 i;
    u32 hash;
    for(i = 0; i < bloom->nr_hash_funcs; i++){
        hash = bloom_hash_function(bloom, value, value_size, i);
        set_bit(hash, bloom->bitset);
    }
}

/**
 * 将元素列表放入布隆过滤器之中
 * @param bloom 布隆过滤器
 * @param length 要插入的数组的长度
 * @param value 值
 * @param value_size 值的大小 (字节)
 */
void push_elements_into_bloom_filter(struct bloom_filter* bloom, int length, int* value){
    int index;
    for(index = 0; index < length; index++) {
        push_element_into_bloom_filter(bloom, &(value[index]), sizeof(int));
    }
}

/**
 * 将一个值插入到布隆过滤器之中
 * @param bloom 布隆过滤器
 * @param value 要检查的值
 * @param value_size 值的大小 (字节)
 * @return 如果元素可能被插入则返回0,如果元素没有插入则返回1
 */
int check_element_in_bloom_filter(struct bloom_filter* bloom, void* value, u32 value_size){
    u32 i;
    u32 hash;
    for(i = 0; i < bloom->nr_hash_funcs; i++){
        hash = bloom_hash_function(bloom, value, value_size, i);
        if(!test_bit(hash, bloom->bitset)){
            // 说明元素从来没有被插入过
            return 1;
        }
    }
    return 0; // 说明元素可能被插入过
}

/*
 * 进行32bit的打印
 */
void printk_binary_u32(u32 n){
    int i;
    printk(KERN_EMERG "[zeusnet's kernel info]:binary: ");
    for(i = 0; i<=31; i++){
        printk(KERN_CONT KERN_EMERG "%c", (n&(1ul<<i)?'1':'0'));
    }
}

/**
 * 进行8bit的打印
 */
void printk_binary_u8(u8 n){
    int i;
    printk(KERN_EMERG "[zeusnet's kernel info]:binary: ");
    for(i = 0; i<=7; i++){
        printk(KERN_CONT KERN_EMERG "%c", (n&(1ul<<i)?'1':'0'));
    }
    printk(KERN_EMERG "\n");
}

/**
 * 进行自定义布隆过滤器的测试
 */
void test_self_defined_bloom_filter(void){
    int total_length = 1; // 8 bytes
    // ---------------------------- 创建布隆过滤器 ----------------------------
    struct bloom_filter* bloom_filter_tmp = init_bloom_filter(total_length);
    bloom_filter_tmp->bitset_mask = 0x3F;
    bloom_filter_tmp->hash_seed = 0x12;
    bloom_filter_tmp->aligned_u32_count = 0x0;
    bloom_filter_tmp->nr_hash_funcs = 0x05;
    // ---------------------------- 创建布隆过滤器 ----------------------------
    int i;
    u8* u8_pointer;
    u32 low32_bits;
    u32 high32_bits;
    u32 first_insert_element = 0x5;
    u32 second_insert_element = 0x6;
    u32 third_not_insert_element = 0x7;
    LOG_WITH_EDGE("start to test bloom filter");
    // 进行元素1的插入
    push_element_into_bloom_filter(bloom_filter_tmp, &first_insert_element, sizeof(first_insert_element));
    if(0 == check_element_in_bloom_filter(bloom_filter_tmp, &first_insert_element, sizeof(first_insert_element))){
        LOG_WITH_PREFIX("check success for the first element!");
    } else {
        LOG_WITH_PREFIX("check failed for the first element!");
    }
    // 进行元素2的插入
    push_element_into_bloom_filter(bloom_filter_tmp, &second_insert_element, sizeof(second_insert_element));
    if(0 == check_element_in_bloom_filter(bloom_filter_tmp, &second_insert_element, sizeof(second_insert_element))){
        LOG_WITH_PREFIX("check success for the second element!");
    } else {
        LOG_WITH_PREFIX("check failed for the second element!");
    }
    // 进行元素3的判断
    if(0 == check_element_in_bloom_filter(bloom_filter_tmp, &third_not_insert_element, sizeof(third_not_insert_element))){
        LOG_WITH_PREFIX("check failed for the third element!");
    } else {
        LOG_WITH_PREFIX("check success for the third element!");
    }
    low32_bits = (u32)bloom_filter_tmp->bitset[0];
    printk_binary_u32(low32_bits);
    high32_bits = (u32)(bloom_filter_tmp->bitset[0] >> 32);
    printk_binary_u32(high32_bits);
    for(i = 0; i < 8; i++){
        u8_pointer = (u8*)(bloom_filter_tmp->bitset) + i;
        printk_binary_u8(*u8_pointer);
    }
    delete_bloom_filter(bloom_filter_tmp);
    LOG_WITH_EDGE("end to test bloom filter");
}

