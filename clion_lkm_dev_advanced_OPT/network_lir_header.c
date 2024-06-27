//
// Created by zhf on 24-4-12.
//
#include "headers/network_lir_header.h"
#include "headers/support_tools.h"
#include "headers/lir_configuration.h"

struct lirhdr* lir_hdr(const struct sk_buff* skb){
    return (struct lirhdr*) skb_network_header(skb);
}

void PRINT_LIR_HEADER(struct lirhdr* lir_header){
    LOG_WITH_EDGE("LIR_HEADER");
    __u16 header_length = ntohs(lir_header->header_len);
    __u16 total_length = ntohs(lir_header->total_len);
    __u16 option_field_length = header_length - sizeof(struct lirhdr);
    __u16 source = ntohs(lir_header->source);
    __u16 destination = ntohs(lir_header->destination);
    printk(KERN_EMERG "lir_header->protocol %d\n", lir_header->protocol);
    printk(KERN_EMERG "lir_header->header_length %d\n", header_length);
    printk(KERN_EMERG "lir_header->total_length %d\n", total_length);
    printk(KERN_EMERG "lir_header->option field length %d\n", option_field_length);
    printk(KERN_EMERG "lir_header->source node id %d\n", source);
    printk(KERN_EMERG "lir_header->destination node id %d\n", destination);
    LOG_WITH_EDGE("LIR_HEADER");
}

bool TEST_IF_LIR_PACKET(struct sk_buff* skb){
    struct lirhdr* lir_header = lir_hdr(skb);
    if((lir_header->version == FIRST_OPT_PACKET_VERSION_NUMBER) ||
    (lir_header->version == OTHER_OPT_PACKET_VERSION_NUMBER)){
        return true;
    } else {
        return false;
    }
}

bool TEST_IF_FIRST_OPT_PACKET(struct sk_buff* skb){
    struct lirhdr* lir_header = lir_hdr(skb);
    if(lir_header->version == FIRST_OPT_PACKET_VERSION_NUMBER){
        return true;
    } else {
        return false;
    }
}

