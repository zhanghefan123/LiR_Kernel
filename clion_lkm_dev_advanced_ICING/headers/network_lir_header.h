//
// Created by zhf on 24-4-12.
//

#ifndef ZEUSNET_KERNEL_NETWORK_LIR_HEADER_H
#define ZEUSNET_KERNEL_NETWORK_LIR_HEADER_H
#include <uapi/linux/types.h>
#include <linux/byteorder/little_endian.h>
#include <net/ip.h>
struct lirhdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8	useless:4,
            version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8	version:4,
  		    ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
    __u8 protocol;          // upper layer protocol
    __u16 id;               // record the fragment belongings -- use to fragment can't delete
    __u16 header_len;       // header length
    __u16 total_len;        // total length
    __be16	frag_off;       // MF DF 以及 切片偏移量以及 -- use to fragment can't delete
    __sum16	check;          // 校验和
    __u16 source;           // 源节点编号 -- use to fragment can't delete
    __u16 destination;      // 目的节点编号 -- use to fragment can't delete
    __u16 current_hop;      // 当前已经经过的跳数
    __u16 length_of_path;   // 路径的长
    __u16 current_path_index;    // current path of index
};

// single hop path fields for icing
struct single_hop_icing {
    __u32 node_id_1;
    __u32 node_id_2;
    __u32 node_id_3;
    __u32 node_id_4;
    __u32 node_id_5;
    __u32 tag;
};

// single hop validation fields for icings
struct single_node_validation_icing {
    __u32 proof_first;
    __u32 proof_second;
    __u32 proof_third;  // 96 bits of the PoPs
};

struct lirhdr* lir_hdr(const struct sk_buff* skb);
void PRINT_LIR_HEADER(struct lirhdr* lir_header);
bool TEST_IF_LIR_PACKET(struct sk_buff* skb);
#endif // ZEUSNET_KERNEL_NETWORK_LIR_HEADER_H
