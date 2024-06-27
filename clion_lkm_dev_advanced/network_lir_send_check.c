//
// Created by zhf on 24-4-12.
//

#include "headers/network_lir_send_check.h"

// ------------------------- static -----------------------------

static unsigned short from32to16(unsigned int x)
{
    /* add up 16-bit and 16-bit for 16+c bit */
    x = (x & 0xffff) + (x >> 16);
    /* add up carry.. */
    x = (x & 0xffff) + (x >> 16);
    return x;
}

static unsigned int do_csum(const unsigned char *buff, int len)
{
    unsigned int result = 0;
    int odd;

    if (len <= 0)
        goto out;
    odd = 1 & (unsigned long)buff;
    if (odd) {
#ifdef __LITTLE_ENDIAN
        result += (*buff << 8);
#else
        result = *buff;
#endif
        len--;
        buff++;
    }
    if (len >= 2) {
        if (2 & (unsigned long)buff) {
            result += *(unsigned short *)buff;
            len -= 2;
            buff += 2;
        }
        if (len >= 4) {
            const unsigned char *end = buff +
                                       ((unsigned int)len & ~3);
            unsigned int carry = 0;

            do {
                unsigned int w = *(unsigned int *)buff;

                buff += 4;
                result += carry;
                result += w;
                carry = (w > result);
            } while (buff < end);
            result += carry;
            result = (result & 0xffff) + (result >> 16);
        }
        if (len & 2) {
            result += *(unsigned short *)buff;
            buff += 2;
        }
    }
    if (len & 1)
#ifdef __LITTLE_ENDIAN
        result += *buff;
#else
    result += (*buff << 8);
#endif
    result = from32to16(result);
    if (odd)
        result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
    out:
    return result;
}

// ------------------------- static -----------------------------


void lir_send_check(struct lirhdr *lir_header){
    lir_header->check = 0;
    lir_header->check = lir_fast_csum((unsigned char *)lir_header, ntohs(lir_header->header_len));
}

__sum16 lir_fast_csum(const void *lir_header, unsigned int lir_header_length)
{
    return (__force __sum16)~do_csum(lir_header, lir_header_length);
}

bool check_checksum(struct lirhdr* lir_header){
    __u16 header_length = ntohs(lir_header->header_len); // 转换为主机字节序
    __u16 old_check_sum = lir_header->check;                 // 提前存储
    lir_header->check = 0;                               // 将校验和设置为0
    __u16 current_check_sum = lir_fast_csum((unsigned char *)lir_header, header_length);  // 计算新的校验和
    if(old_check_sum == current_check_sum){
        // restore the old check
        lir_header->check = old_check_sum;
        return true;
    } else {
        lir_header->check = old_check_sum;
        return false;
    }
}