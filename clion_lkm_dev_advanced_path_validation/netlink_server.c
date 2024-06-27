//
// Created by zhf on 24-4-12.
//
//
// Created by kernel-dbg on 24-1-30.
//

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <net/genetlink.h>
#include "headers/netlink_handler.h"
#include "headers/netlink_server.h"

/**
 * 定义属性和类型的一个映射关系
 */
struct nla_policy attr_type_mapping[__EXMPL_NLA_MAX] = {
        [EXMPL_NLA_DATA] = {.type = NLA_NUL_STRING},
        [EXMPL_NLA_LEN] = {.type = NLA_U32}
};

/**
 * 命令和实际的函数的映射
 */
const struct genl_ops exmpl_gnl_ops_echo[] = {
        // 接收到用户空间下发的路由条目插入命令，绑定相应的 callback function
        {
                .cmd = CMD_INSERT_ROUTES,
                .policy = attr_type_mapping,
                .doit = insert_route_message_handler,
        },
        // 接收到用户空间下发的计算长度的命令，绑定相应的 callback function
        {
                .cmd = CMD_CALCULATE_LENGTH,
                .policy = attr_type_mapping,
                .doit = calculate_length_message_handler
        },
        // 接收到用户空间下发的查找路由的命令，绑定响应的 callback function
        {
                .cmd = CMD_SEARCH_ROUTE,
                .policy = attr_type_mapping,
                .doit = search_route_message_handler
        }
        ,{
                .cmd = CMD_FIND_DEV_BY_INDEX,
                .policy = attr_type_mapping,
                .doit = find_dev_by_name_handler
        },
//        {
//            .cmd = CMD_CONSTRUCT_INTERFACE_TABLE,
//            .policy = attr_type_mapping,
//            .doit = construct_interface_table_handler
//        },
        {
                .cmd = CMD_BIND_NET_TO_SAT_NAME,
                .policy = attr_type_mapping,
                .doit = bind_net_to_sat_id_handler
        }, {
                .cmd = CMD_SET_BLOOM_FILTER_ATTRS,
                .policy = attr_type_mapping,
                .doit = set_bloom_filter_attrs
        }, {
                .cmd = CMD_CONSTRUCT_NEW_INTERFACE_TABLE,
                .policy = attr_type_mapping,
                .doit = construct_new_interface_table_handler
        }
};

/**
 * 定义generate_netlink协议的内容
 */
struct genl_family exmpl_genl_family __ro_after_init = {
        .name = "EXMPL_GENL",  // 需要在用户空间使用
        .version = VERSION_NR,  // 版本号
        .maxattr = __EXMPL_NLA_MAX - 1, // 最大属性数量
        .module = THIS_MODULE, // 当前模块
        .ops = exmpl_gnl_ops_echo, // 命令和实际的函数的映射
        .n_ops = ARRAY_SIZE(exmpl_gnl_ops_echo), // 映射数量
        .netnsok = true // 一定需要添加这个从而可以让网络命名空间生效
};

/**
 * netlink 的启动方法
 * 无参数
 * 无返回值
 */
void netlink_server_init(void){
    genl_register_family(&exmpl_genl_family);
}

/**
 * netlink 的结束方法
 * 无参数
 * 无返回值
 */
void netlink_server_exit(void){
    genl_unregister_family(&exmpl_genl_family);
}

MODULE_LICENSE("GPL");