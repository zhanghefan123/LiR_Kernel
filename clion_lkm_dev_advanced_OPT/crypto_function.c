//
// Created by zhf on 24-4-17.
//
#include "headers/crypto_function.h"
#include "headers/lir_data_structure.h"
#include <crypto/dh.h>
#include <crypto/kpp.h>

struct shash_desc* generate_hash_data_structure(void){
    struct crypto_shash* tfm;
    struct shash_desc *shash;
    tfm = crypto_alloc_shash("sha1", 0, 0);
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

struct shash_desc* generate_hmac_data_structure(void){
    struct crypto_shash* tfm;
    struct shash_desc *shash;
    tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
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

