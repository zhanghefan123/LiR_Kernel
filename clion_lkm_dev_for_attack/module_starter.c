//
// Created by kernel-dbg on 24-2-1.
//
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/net_namespace.h>
#include "headers/hook_functions.h"
#include "headers/tools.h"

/**
 * 进行网络命名空间的初始化
 * @param net 网络命名空间
 * @return
 */
static int __net_init module_net_init(struct net* net){
    LOG_WITH_EDGE("net init process");
    LOG_WITH_EDGE("net init process");
    return 0;
}

/**
 * 进行网络命名空间的释放
 * @param net 网络命名空间
 * 无返回值
 */
static void __net_exit module_net_exit(struct net* net){
    LOG_WITH_EDGE("net exit process");
    LOG_WITH_EDGE("net exit process");
}

/**
 * 记住网络命名空间的相关操作
 */
static struct pernet_operations net_namespace_operations = {
        .init = module_net_init,
        .exit = module_net_exit
};

/**
 * 自己编写的模块的启动方法
 * 无参数
 * @return 0
 */
static int __init module_init_function(void){
    register_pernet_subsys(&net_namespace_operations);
    start_install_hooks();
    return 0;
}

/**
 * 自己编写的模块的结束方法
 * 无参数
 * 无返回值
 */
static void __exit module_exit_function(void){
    unregister_pernet_subsys(&net_namespace_operations);
    exit_uninstall_hooks();
}

module_init(module_init_function);
module_exit(module_exit_function);

MODULE_LICENSE("GPL");