#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include "headers/cypher_test.h"

int hmac_test_init(void) {
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    char *data = "Hello, world!";
    char *key = "secret key1";
    unsigned char output[20]; // SHA256 输出大小
    int i;

    tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to load transform: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash) {
        printk(KERN_ERR "Failed to allocate shash desc.\n");
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    shash->tfm = tfm;
    if (crypto_shash_setkey(shash->tfm, key, strlen(key))) {
        printk(KERN_ERR "Failed to set key.\n");
        crypto_free_shash(shash->tfm);
        kfree(shash);
        return -EAGAIN;
    }

    if (crypto_shash_digest(shash, data, strlen(data), output)) {
        printk(KERN_ERR "Failed to compute HMAC.\n");
        crypto_free_shash(shash->tfm);
        kfree(shash);
        return -EINVAL;
    }
    printk(KERN_INFO "HMAC-SHA256(\"%s\") = ", data);
    for (i = 0; i < sizeof(output); i++)
        printk(KERN_CONT "%02x", output[i]);
    printk(KERN_CONT "\n");

    crypto_free_shash(shash->tfm);
    kfree(shash);
    return 0;
}

void hmac_test_exit(void)
{
    printk(KERN_INFO "HMAC test module unloaded.\n");
}
