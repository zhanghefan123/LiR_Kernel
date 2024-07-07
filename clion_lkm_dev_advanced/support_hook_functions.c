//
// Created by kernel-dbg on 24-2-1.
//
#include <net/sock.h>
#include "headers/support_tools.h"
#include "headers/support_hook_functions.h"
#include "headers/support_ftrace_hook_api.h"
#include "headers/support_resolve_function_address.h"
#include "headers/mac_netif_rcv_skb.h"
#include "headers/transport_lir_udp_sendmsg.h"
#include "headers/network_lir_rcv.h"
#include "headers/ip_route_input_noref_without_cache.h"
#include "headers/ip_route_output_flow_without_cache.h"

// 我们添加的 hook 列表, 假设最多10个
struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];

// 我们当前的 hook 的个数
int number_of_hook = 0;


// 进行hook的安装
int install_hook_functions(void) {
    resolve_function_address();
    add_hook_functions();
    fh_install_hooks(hooks, number_of_hook);
    LOG_WITH_PREFIX("already install hooks");
    tidy();
    return 0;
}

// 添加到 hooks 数组之中
void add_hook_functions(){
    add_netif_rcv_skb_to_hook();
    add_udp_sendmsg_to_hook();
//    add_ip_route_input_noref_to_hook();
//    add_ip_route_output_flow_to_hook();
}


/**
 * 进行 hook 的卸载
 */
void uninstall_hook_functions(void) {
    fh_remove_hooks(hooks, number_of_hook);
    LOG_WITH_PREFIX("already uninstall hooks\n");
}

/**
 * 进行清理任务
 */
void tidy(void) {
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
}

/**
 * 进行钩子函数的绑定
 */
void start_install_hooks(void) {
    install_hook_functions();
}

/**
 * 进行钩子函数的解绑
 */
void exit_uninstall_hooks(void) {
    uninstall_hook_functions();
}