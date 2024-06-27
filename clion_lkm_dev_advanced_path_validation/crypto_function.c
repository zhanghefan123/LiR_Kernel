//
// Created by zhf on 24-4-17.
//
#include "headers/crypto_function.h"
#include "headers/lir_data_structure.h"

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
u32* calculate_hmac(struct shash_desc* hmac_data_structure, unsigned char* data, int length_of_data, char* key){
    unsigned char hmac_output[20];
    u32* real_output = (u32*)(kmalloc(sizeof(u32), GFP_KERNEL));
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
    memcpy(real_output, hmac_output, sizeof(u32));
    return real_output;
}

unsigned char* calculate_hash(struct shash_desc* hash_data_structure, char* data){
    unsigned char* output = kmalloc(sizeof(unsigned char) * 20, GFP_KERNEL);
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

void print_hash_or_hmac_result(unsigned char* output, int length){
    int i;
    printk(KERN_CONT "RESULT ");
    for (i = 0; i < length; i++)
        printk(KERN_CONT "%02x", output[i]);
    printk(KERN_CONT "\n");
}

void test_hash_and_hmac(struct net* current_net_namespace){
    // ----------------------------------------- test hash function -----------------------------------------
    struct LirDataStructure* lir_data_structure = (struct LirDataStructure*)(current_net_namespace->crypto_nlsk);
    unsigned char* hash_result = calculate_hash(lir_data_structure->hash_data_structure, "123");
    // ----------------------------------------- test hash function -----------------------------------------
    char key_from_source_to_intermediate[20];
    sprintf(key_from_source_to_intermediate, "key-%d-%d", 1, 2);
    u32* hmac_result = calculate_hmac(lir_data_structure->hmac_data_structure,
                                                hash_result,  LENGTH_OF_HASH, key_from_source_to_intermediate);
    print_hash_or_hmac_result((unsigned char*)hmac_result, 4);
    *hmac_result = (*hmac_result) ^ (u32)(1);
    print_hash_or_hmac_result((unsigned char*)hmac_result, 4);
    kfree(hash_result);
    kfree(hmac_result);
}

