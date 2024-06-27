//
// Created by kernel-dbg on 24-1-31.
//

#ifndef ZEUSNET_KERNEL_NETLINK_SERVER_H
#define ZEUSNET_KERNEL_NETLINK_SERVER_H
#include <net/genetlink.h>
void netlink_server_init(void);
void netlink_server_exit(void);
/**
 * 消息的类型，用户空间同样需要定义相应的代码
 */
enum {
    EXMPL_NLA_UNSPEC, // corresponding value = 0
    EXMPL_NLA_DATA, // 数据部分
    EXMPL_NLA_LEN, // 数据的长度
    __EXMPL_NLA_MAX,  // corresponding value == 3
};
/**
 * 命令的类型，用户空间同样需要定义相应的命令类型
 */
enum {
    CMD_UNSPEC,
    CMD_INSERT_ROUTES,
    CMD_CALCULATE_LENGTH,
    CMD_SEARCH_ROUTE,
    CMD_FIND_DEV_BY_INDEX,
    // CMD_CONSTRUCT_INTERFACE_TABLE,
    CMD_BIND_NET_TO_SAT_NAME,
    CMD_SET_BLOOM_FILTER_ATTRS,
    CMD_CONSTRUCT_NEW_INTERFACE_TABLE
};
#define VERSION_NR 1
extern struct genl_family exmpl_genl_family;
extern const struct genl_ops exmpl_gnl_ops_echo[];
extern struct nla_policy attr_type_mapping[__EXMPL_NLA_MAX];
#endif
