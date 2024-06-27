//
// Created by kernel-dbg on 24-1-31.
//
#include <linux/string.h>
#include <linux/slab.h>
#include "headers/support_tools.h"

bool TEST_IF_LIR_SOCKET(struct sock* sk){
    return sock_flag(sk, SOCK_DBG);
}

/**
 * log_with_prefix 带有前缀的输出
 * @param msg 用户想要输出的消息
 * @return 不进行返回
 */
void LOG_WITH_PREFIX(char* msg){
    const char* prefix = LOG_PREFIX;
    size_t prefix_length = strlen(prefix);
    size_t msg_length = strlen(msg);
    size_t total_length = prefix_length + msg_length + 2;
    char total_msg[total_length];
    memcpy(total_msg, prefix, prefix_length);
    memcpy(total_msg + prefix_length, msg, msg_length);
    total_msg[total_length - 2] = '\n';
    total_msg[total_length - 1] = '\0';
    printk(KERN_EMERG "%s", total_msg);
}

/**
 * 进行有边框的输出用户想要输出的信息
 * @param msg 用户想要输出的信息
 */
void LOG_WITH_EDGE(char* msg){
    char final_output_msg[101];
    int length_of_msg = (int)strlen(msg);
    int length_of_each_edge = (100 - length_of_msg) / 2;
    memset(final_output_msg, (int)('-'), length_of_each_edge);
    final_output_msg[length_of_each_edge] = '\0';
    strcat(final_output_msg, msg);
    memset(final_output_msg + strlen(final_output_msg), (int)('-'), 100-strlen(final_output_msg));
    final_output_msg[100] = '\0';
    LOG_WITH_PREFIX(final_output_msg);
}

/**
 * 进行路由表的打印
 */
void PRINT_RT(struct rtable* rt){
    LOG_WITH_EDGE("info of rtable");
    printk(KERN_EMERG "[zeusnet's kernel info]:rt->dst_entry.dev->name = %s\n", rt->dst.dev->name);
    printk(KERN_EMERG "[zeusnet's kernel info]:rt->rt_genid = %d\n", rt->rt_genid);
    printk(KERN_EMERG "[zeusnet's kernel info]:rt->rt_type = %d\n", rt->rt_type);
    printk(KERN_EMERG "[zeusnet's kernel info]:rt->rt_is_input = %d\n", rt->rt_is_input);
    printk(KERN_EMERG "[zeusnet's kernel info]:rt->rt_uses_gateway = %d\n", rt->rt_uses_gateway);
    printk(KERN_EMERG "[zeusnet's kernel info]:rt->rt_iif = %d\n", rt->rt_iif);
    printk(KERN_EMERG "[zeusnet's kernel info]:rt->rt_gw_family = %d\n", rt->rt_gw_family);
    LOG_WITH_EDGE("info of rtable");
}


void LOG_RESOLVED(void* pointer, const char* function_name){
    if(pointer){
        printk(KERN_EMERG "[zeusnet's kernel info]:%s resolved\n", function_name);
    } else {
        LOG_WITH_PREFIX("error");
    }
}