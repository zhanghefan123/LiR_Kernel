//
// Created by zhf on 24-4-12.
//

#ifndef ZEUSNET_KERNEL_NETWORK_LIR_SEND_CHECK_H
#define ZEUSNET_KERNEL_NETWORK_LIR_SEND_CHECK_H
#include <net/ip.h>
#include "network_lir_header.h"
void lir_send_check(struct lirhdr *lir_header);
__sum16 lir_fast_csum(const void *lir_header, unsigned int header_length);
bool check_checksum(struct lirhdr* lir_header);
#endif //ZEUSNET_KERNEL_NETWORK_LIR_SEND_CHECK_H
