//
// Created by 张贺凡 on 2024/2/5.
//
#include "headers/support_tools.h"
#include "headers/netlink_handler.h"
#include "headers/lir_routing_table_structure.h"
#include "headers/netlink_server.h"
#include "headers/lir_data_structure.h"
#include <linux/kstrtox.h>

/**
 * 进行布隆过滤器的参数的设置
 * 我们需要注意的是，在进行布隆过滤器的重新设置的时候，所有的路由表项之中的布隆过滤器也应该重新进行计算。
 * @param request 用户空间发送来的请求
 * @param info generate_netlink 的信息
 * @return 0 失败则返回 -EINVAL
 */
int set_bloom_filter_attrs(struct sk_buff *request, struct genl_info *info) {
    // 网络命名空间
    struct net *current_net_namespace = sock_net(request->sk);
    // 响应的报文
    struct sk_buff *reply;
    // 缓存 - 用户空间下发的数据
    char *buffer;
    // 消息头
    void *msg_head;
    // 响应消息
    char response_msg[1024];
    // 分隔符
    const char *delimeter = ",";
    // 单个属性值 (str)
    char *single_attr_str;
    // 单个属性值 (u32)
    u32 single_attr_u32;
    // 当前是第几个属性
    int count = 0;
    // 进行网络空间内布隆过滤器的获取
    struct bloom_filter *bloom_filter = get_bloom_filter(current_net_namespace);
    // 进行路由表的获取
    struct hlist_head *lir_routing_table = get_lir_routing_table_from_net_namespace(current_net_namespace);
    // 有效的bit位
    u32 effective_bits;
    // 判断是否经历了初始化阶段
    bool initializing;

    // -------------------- 进行预先的校验 -----------------------
    // 判断 generate netlink info 是否为空
    if (info == NULL) {
        return -EINVAL;
    }
    // 判断是否有数据
    if (!info->attrs[EXMPL_NLA_DATA]) {
        return -EINVAL;
    }
    // -------------------- 进行预先的校验 -----------------------

    // -------------------- 准备进行消息的处理 --------------------
    buffer = nla_data(info->attrs[EXMPL_NLA_DATA]);
    while (true) {
        single_attr_str = strsep(&buffer, delimeter);
        if (single_attr_str == NULL || (strcmp(single_attr_str, "") == 0)) {
            break;
        } else {
            // 设置属性的顺序分别是 bitset_mask hash_seed aligned_u32_count nr_hash_funcs
            single_attr_u32 = (int) (simple_strtol(single_attr_str, NULL, 10));
            if (count == 0) {
                bloom_filter->bitset_mask = (single_attr_u32 - 1);
                effective_bits = single_attr_u32;
                bloom_filter->effective_bytes = (effective_bits + BITS_PER_BYTE - 1) / BITS_PER_BYTE;
            } else if (count == 1) {
                bloom_filter->hash_seed = single_attr_u32;
            } else if (count == 2) {
                bloom_filter->nr_hash_funcs = single_attr_u32;
            } else {
                return -EINVAL;
            }
        }
        count += 1;
    }

    // --------------------------------------------- 打印到内核说明参数设置完成 ---------------------------------------------
    LOG_WITH_EDGE("bloom filter params set up");
    printk(KERN_EMERG "[zeusnet's kernel info]:bitset_mask: %d, hash_seed: %d, aligned_u32_count %d, nr_hash_funcs: %d, effective_bytes: %d\n",
           bloom_filter->bitset_mask,
           bloom_filter->hash_seed,
           bloom_filter->aligned_u32_count,
           bloom_filter->nr_hash_funcs,
           bloom_filter->effective_bytes);
    LOG_WITH_EDGE("bLoom filter params set up");
    // --------------------------------------------- 打印到内核说明参数设置完成 ---------------------------------------------


    // --------------------------------------------- 判断是否需要进行路由表的重建 ---------------------------------------------
    initializing = get_if_initializing(current_net_namespace);
    if(!initializing){
        // 仅仅完成了参数的设置还不够，我们还需要进行所有的路由表项的遍历，并计算相应的 bitset
        rebuild_routing_table_with_new_bf_settings(bloom_filter, lir_routing_table);
        LOG_WITH_PREFIX("entry bloom filter array set up");
    } else {
        set_initialized(current_net_namespace);
        LOG_WITH_PREFIX("initializing stage not rebuild routing table");
    }
    // --------------------------------------------- 打印到内核说明参数设置完成 ---------------------------------------------

    // -------------------- 准备进行消息的处理 --------------------
    // 进行内存的分配
    reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    // 看是否成功的进行了分配
    if (reply == NULL) {
        return -ENOMEM;
    }
    // 进行返回消息的构建
    // 首先进行消息头的构建
    msg_head = genlmsg_put_reply(reply, info, &exmpl_genl_family, 0, info->genlhdr->cmd);
    if (msg_head == NULL) {
        return -ENOMEM;
    }
    // 将响应消息的内容进行填充
    snprintf(response_msg, sizeof(response_msg), "bloom filter params set up");
    // 进行响应消息的构建
    if (0 != nla_put_string(reply, EXMPL_NLA_DATA, response_msg)) {
        return -EINVAL;
    }
    if (0 != nla_put_u32(reply, EXMPL_NLA_DATA, 1)) {
        return -EINVAL;
    }
    // 结束响应消息的构建
    genlmsg_end(reply, msg_head);
    // 进行消息的返回
    if (0 != genlmsg_reply(reply, info)) {
        return -EINVAL;
    }
    return 0;
    // -------------------- 准备进行消息的回复 --------------------
}

/**
 * 将网络命名空间和卫星的id进行相互绑定
 * @param request 用户空间发送的请求
 * @param info generate_netlink 的信息
 * @return  0 失败则返回 -EINVAL
 */
int bind_net_to_sat_id_handler(struct sk_buff *request, struct genl_info *info) {
    // 网络命名空间
    struct net *current_net_namespace = sock_net(request->sk);
    // 响应的报文
    struct sk_buff *reply;
    // 缓存 - 用户空间下发的数据
    char *buffer;
    // 消息头
    void *msg_head;
    // 响应消息
    char response_msg[1024];
    int satellite_id;

    // 判断 generate netlink info 是否为空
    if (info == NULL) {
        return -EINVAL;
    }
    // 判断是否有数据
    if (!info->attrs[EXMPL_NLA_DATA]) {
        return -EINVAL;
    }

    // ------------------------ 准备进行消息的处理 ------------------------
    buffer = nla_data(info->attrs[EXMPL_NLA_DATA]);
    satellite_id = (int) (simple_strtol(buffer, NULL, 10));
    set_satellite_id(current_net_namespace, satellite_id);
    // 打印到内核说明完成绑定
    LOG_WITH_EDGE("bind process");
    printk(KERN_EMERG "[zeusnet's kernel info]:satellite_name %d set up\n", get_satellite_id(current_net_namespace));
    LOG_WITH_EDGE("bind process");
    // ------------------------ 准备进行消息的处理 ------------------------

    // ------------------------ 准备进行消息的回复 ------------------------
    // 进行内存的分配
    reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    // 看是否成功的进行了分配
    if (reply == NULL) {
        return -ENOMEM;
    }
    // 进行返回消息的构建
    // 首先进行消息头的构建
    msg_head = genlmsg_put_reply(reply, info, &exmpl_genl_family, 0, info->genlhdr->cmd);
    if (msg_head == NULL) {
        return -ENOMEM;
    }
    // 将响应消息的内容进行填充
    snprintf(response_msg, sizeof(response_msg), "satellite_name %d set up", get_satellite_id(current_net_namespace));
    // 进行响应消息的构建
    if (0 != nla_put_string(reply, EXMPL_NLA_DATA, response_msg)) {
        return -EINVAL;
    }
    if (0 != nla_put_u32(reply, EXMPL_NLA_DATA, 1)) {
        return -EINVAL;
    }
    // 结束响应消息的构建
    genlmsg_end(reply, msg_head);
    // 进行消息的返回
    if (0 != genlmsg_reply(reply, info)) {
        return -EINVAL;
    }
    return 0;
    // ------------------------ 准备进行消息的回复 ------------------------
}


/**
 * 命令类型为 CMD_CALCULATE_ROUTES 的回调函数
 * @param request 从用户空间下来的请求
 * @param info netlink 的详细信息
 * @return
 */
int calculate_length_message_handler(struct sk_buff *request, struct genl_info *info) {
    // 响应的报文
    struct sk_buff *reply;
    // 缓存
    char *buffer;
    // 消息头
    void *msg_head;
    // 响应消息
    char *response_msg;
    // 判断 generate netlink info 是否为空
    if (info == NULL) {
        return -EINVAL;
    }
    // 判断是否有数据
    if (!info->attrs[EXMPL_NLA_DATA]) {
        return -EINVAL;
    }
    // 进行消息类型的获取
    // 进行数据的获取
    buffer = nla_data(info->attrs[EXMPL_NLA_DATA]);
    // 准备进行消息的回复
    // 进行内存的分配
    reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    // 看是否成功的进行了分配
    if (reply == NULL) {
        return -ENOMEM;
    }
    // 进行返回消息的构建
    // 首先进行消息头的构建
    msg_head = genlmsg_put_reply(reply, info, &exmpl_genl_family, 0, info->genlhdr->cmd);
    if (msg_head == NULL) {
        return -ENOMEM;
    }
    // 添加响应消息的构建
    response_msg = STRING_WITH_PREFIX("kernel received CMD_CALCULATE_LENGTH");
    if (0 != nla_put_string(reply, EXMPL_NLA_DATA, response_msg)) {
        return -EINVAL;
    }
    if (0 != nla_put_u32(reply, EXMPL_NLA_LEN, strlen(buffer))) {
        return -EINVAL;
    }
    // 结束响应消息的构建
    genlmsg_end(reply, msg_head);
    // 进行消息的返回
    if (0 != genlmsg_reply(reply, info)) {
        return -EINVAL;
    }
    return 0;
}


/**
 * A->B->C->D
 *  1  2  3  3 link identifiers
 *  B  C  D  3 satellites
 * 命令类型为 CMD_INSERT_ROUTES 的回调函数
 * @param request 接受上层下来的请求
 * @param info netlink 的详细信息
 * @return 0 失败则返回 -EINVAL
 */
int insert_route_message_handler(struct sk_buff *request, struct genl_info *info) {
    // 网络命名空间
    struct net *current_net_namespace = sock_net(request->sk);
    // 响应的报文
    struct sk_buff *reply;
    // 缓存 - 用户空间下发的数据
    char *buffer;
    // 消息头
    void *msg_head;
    // 分隔符
    const char *delimeter = "\n";
    // 单行字符串
    char *single_line = "";
    // 响应字符串
    char *response_msg;
    // 获取网络命名空间之中存储的路由表
    struct hlist_head *lir_routing_table = get_lir_routing_table_from_net_namespace(current_net_namespace);
    // 统计收到了多少条路由
    int number_of_inserted_routes = 0;

    // 判断 generate netlink info 是否为空
    if (info == NULL) {
        return -EINVAL;
    }
    // 判断是否有数据
    if (!info->attrs[EXMPL_NLA_DATA]) {
        return -EINVAL;
    }

    // ------------------------ 准备进行消息的处理 ------------------------
    buffer = nla_data(info->attrs[EXMPL_NLA_DATA]);

    while (true) {
        single_line = strsep(&buffer, delimeter);
        if (single_line == NULL || (strcmp(single_line, "") == 0)) {
            break;
        } else {
            // 在这里准备进行单行消息的读取
            // LOG_WITH_PREFIX(single_line);
            struct RoutingTableEntry *route_entry = generate_single_route(current_net_namespace, single_line);
            // 将路由表项添加到路由表之中
            add_entry_to_routing_table(lir_routing_table,
                                       route_entry);
            number_of_inserted_routes += 1;
        }
    }
    print_routing_table(lir_routing_table);
    // ------------------------ 准备进行消息的处理 ------------------------

    // ------------------------ 准备进行消息的回复 ------------------------
    // 进行内存的分配
    reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    // 看是否成功的进行了分配
    if (reply == NULL) {
        return -ENOMEM;
    }
    // 进行返回消息的构建
    // 首先进行消息头的构建
    msg_head = genlmsg_put_reply(reply, info, &exmpl_genl_family, 0, info->genlhdr->cmd);
    if (msg_head == NULL) {
        return -ENOMEM;
    }
    // 添加响应消息的构建
    response_msg = STRING_WITH_PREFIX("kernel receive CMD_INSERT_ROUTES");
    if (0 != nla_put_string(reply, EXMPL_NLA_DATA, response_msg)) {
        return -EINVAL;
    }
    if (0 != nla_put_u32(reply, EXMPL_NLA_LEN, number_of_inserted_routes)) {
        return -EINVAL;
    }
    // 结束响应消息的构建
    genlmsg_end(reply, msg_head);
    // 进行消息的返回
    if (0 != genlmsg_reply(reply, info)) {
        return -EINVAL;
    }
    return 0;
    // ------------------------ 准备进行消息的回复 ------------------------
}

/**
 * 命令类型为 CMD_SEARCH_ROUTES 的回调函数
 * @param request 接受上层下来的请求
 * @param info netlink 的详细信息
 * @return 0 失败则返回 -EINVAL
 */
int search_route_message_handler(struct sk_buff *request, struct genl_info *info) {
    // 获取网络命名空间
    struct net *current_net_namespace = sock_net(request->sk);
    // 获取网络命名空间之中存在的路由表
    struct hlist_head *lir_routing_table = get_lir_routing_table_from_net_namespace(current_net_namespace);
    // 查找到的路由表条目
    struct RoutingTableEntry *routing_table_entry = NULL;
    // 响应报文
    struct sk_buff *reply;
    // 缓存 - 用户空间下发的数据
    char *buffer;
    // 消息头
    void *msg_head;
    // 响应字符串
    char response_msg[1024];
    // 分隔符
    char *delimeter = ",";
    // 源或目的节点编号的字符串形式
    char *single_number_str = NULL;
    // 源或目的节点编号的数值形式
    int single_number;
    // 源节点编号
    int source;
    // 目的节点编号
    int destination;
    // 当前收到的是第几个元素
    int count = 0;
    // for 循环索引
    int index = 0;
    // 查询开始时间
    u64 start;
    // 查询结束时间
    u64 interval;

    // 判断 generate netlink info 是否为空
    if (info == NULL) {
        return -EINVAL;
    }
    // 判断是否有数据
    if (!info->attrs[EXMPL_NLA_DATA]) {
        return -EINVAL;
    }

    // ------------------ 准备进行用户空间消息的处理 --------------------
    buffer = nla_data(info->attrs[EXMPL_NLA_DATA]);
    // 这里要读取的有源节点的 id 以及 目的节点的 id
    while (true) {
        single_number_str = strsep(&buffer, delimeter);
        if (single_number_str == NULL || (strcmp(single_number_str, "") == 0)) {
            break;
        } else {
            single_number = (int) (simple_strtol(single_number_str, NULL, 10));
            if (count == 0) {
                source = single_number;
            } else if (count == 1) {
                destination = single_number;
            } else {
                return -EINVAL;
            }
        }
        count += 1;
    }
    // 如果count!=2说明没有接收到两个参数，需要进行报错
    if (count != 2) {
        return -EINVAL;
    } else {
        // 打印收到的两个参数
        printk(KERN_EMERG "[zeusnet's kernel info]:search route with source %d to destination %d\n", source,
               destination);
    }
    // ------------------ 准备进行用户空间消息的处理 --------------------

    // ---------------------- 准备进行消息的回复 ----------------------
    // 进行内存的分配
    reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    // 看是否成功的进行了分配
    if (reply == NULL) {
        return -ENOMEM;
    }
    // 进行返回消息的构建
    // 首先进行消息头的构建
    msg_head = genlmsg_put_reply(reply, info, &exmpl_genl_family, 0, info->genlhdr->cmd);
    if (msg_head == NULL) {
        return -ENOMEM;
    }
    // 根据源节点的和目的节点进行路由的搜索
    // start = ktime_get_real_ns(); // 开始
    routing_table_entry = find_entry_in_routing_table(lir_routing_table, source, destination);
    if (routing_table_entry  != NULL){
        // interval = ktime_get_real_ns() - start;
        // 形成 response msg
        snprintf(response_msg, sizeof(response_msg), "search routes [%llu ns]: ", interval);
        // 形成找到的路由表的字符串
        for (index = 0; index < routing_table_entry->length_of_path; index++) {
            int current_link_identifier = routing_table_entry->link_identifiers[index];
            char message_tmp[10];
            snprintf(message_tmp, sizeof(message_tmp), "%d->", current_link_identifier);
            strcat(response_msg, message_tmp);
        }
    } else {
        strcpy(response_msg, "cannot find route");
    }

    // snprintf(response_msg, sizeof(response_msg), );
    // 添加响应消息的构建
    if (0 != nla_put_string(reply, EXMPL_NLA_DATA, response_msg)) {
        return -EINVAL;
    }
    if (0 != nla_put_u32(reply, EXMPL_NLA_LEN, 1)) {
        return -EINVAL;
    }
    // 结束响应消息的构建
    genlmsg_end(reply, msg_head);
    // 进行消息的返回
    if (0 != genlmsg_reply(reply, info)) {
        return -EINVAL;
    }
    return 0;
    // ---------------------- 准备进行消息的回复 ----------------------

    return 0;
}

/**
 * 命令类型为 CMD_FIND_DEV_BY_INDEX 的回调函数
 * @param request 接受上层下来的请求
 * @param info netlink 的详细信息
 * @return 0 失败则返回 -EINVAL
 */
int find_dev_by_name_handler(struct sk_buff *request, struct genl_info *info) {
    // 网络命名空间
    struct net *current_net_namespace = sock_net(request->sk);
    // 响应的报文
    struct sk_buff *reply;
    // 缓存 - 用户空间下发的数据
    char *buffer;
    // 消息头
    void *msg_head;
    // 单个数字
    int ifindex;
    // 响应消息
    char response_msg[1024];

    // 判断 generate netlink info 是否为空
    if (info == NULL) {
        return -EINVAL;
    }
    // 判断是否有数据
    if (!info->attrs[EXMPL_NLA_DATA]) {
        return -EINVAL;
    }

    // ------------------------ 准备进行消息的处理 ------------------------
    buffer = nla_data(info->attrs[EXMPL_NLA_DATA]);
    // 获取 ifindex
    ifindex = (int) (simple_strtol(buffer, NULL, 10));
    // 进行dev的查找
    struct net_device *interface = dev_get_by_index(current_net_namespace, ifindex);
    dev_put(interface);
    // ------------------------ 准备进行消息的处理 ------------------------

    // ------------------------ 准备进行消息的回复 ------------------------
    // 进行内存的分配
    reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    // 看是否成功的进行了分配
    if (reply == NULL) {
        return -ENOMEM;
    }
    // 进行返回消息的构建
    // 首先进行消息头的构建
    msg_head = genlmsg_put_reply(reply, info, &exmpl_genl_family, 0, info->genlhdr->cmd);
    if (msg_head == NULL) {
        return -ENOMEM;
    }
    // 将响应消息的内容进行填充
    snprintf(response_msg, sizeof(response_msg), "interface name: %s", interface->name);
    // 进行响应消息的构建
    if (0 != nla_put_string(reply, EXMPL_NLA_DATA, response_msg)) {
        return -EINVAL;
    }
    if (0 != nla_put_u32(reply, EXMPL_NLA_DATA, 1)) {
        return -EINVAL;
    }
    // 结束响应消息的构建
    genlmsg_end(reply, msg_head);
    // 进行消息的返回
    if (0 != genlmsg_reply(reply, info)) {
        return -EINVAL;
    }
    return 0;
    // ------------------------ 准备进行消息的回复 ------------------------
}

int construct_new_interface_table_handler(struct sk_buff* request, struct genl_info* info){
    // line count
    int line_count = 0;
    // number of interfaces
    int number_of_interfaces;
    // current_interface
    int current_interface = 0;
    // new interface table
    struct NewInterfaceTable* new_interface_table;
    // 获取网络命名空间
    struct net *current_net_namespace = sock_net(request->sk);
    // 响应的报文
    struct sk_buff *reply;
    // 缓存 - 用户空间下发的数据
    char *buffer;
    // 消息头
    void *msg_head;
    // 分隔符
    const char *line_delimeter = "\n";
    // 单行字符串
    char *single_line = "";
    // 响应字符串
    char *response_msg;
    // 获取网络命名空间之中存储的接口表
    // struct hlist_head *interface_table = get_lir_interface_table_from_net_namespace(current_net_namespace);
    // 判断 generate netlink info 是否为空
    if (info == NULL) {
        return -EINVAL;
    }
    // 判断是否有数据
    if (!info->attrs[EXMPL_NLA_DATA]) {
        return -EINVAL;
    }
    // ------------------------ 准备进行消息的处理 ------------------------
    buffer = nla_data(info->attrs[EXMPL_NLA_DATA]);
    while (true) {
        single_line = strsep(&buffer, line_delimeter);
        // for the first line, it indicates the number of interfaces
        if (single_line == NULL || (strcmp(single_line, "") == 0)) {
            break;
        }
        if(line_count == 0){
            // get number of interfaces
            number_of_interfaces = (int) (simple_strtol(single_line, NULL, 10));
            // create interface table
            new_interface_table = init_new_interface_table(number_of_interfaces);
            // set interface table in lir_data_structure
            set_new_interface_table_in_lir_data_structure(current_net_namespace, new_interface_table);
            line_count += 1;
            continue;
        }
        // each line is a combination of ifindex and link identifier
        generate_single_new_interface_table_entry(current_net_namespace, new_interface_table, single_line, current_interface);
        current_interface += 1;
    }
    // ------------------------ 准备进行消息的回复 ------------------------
    reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    // 看是否成功的进行了分配
    if (reply == NULL) {
        return -ENOMEM;
    }
    // 进行返回消息的构建
    // 首先进行消息头的构建
    msg_head = genlmsg_put_reply(reply, info, &exmpl_genl_family, 0, info->genlhdr->cmd);
    if (msg_head == NULL) {
        return -ENOMEM;
    }
    // 添加响应消息的构建
    response_msg = STRING_WITH_PREFIX("kernel build new interface table");
    if (0 != nla_put_string(reply, EXMPL_NLA_DATA, response_msg)) {
        return -EINVAL;
    }
    if (0 != nla_put_u32(reply, EXMPL_NLA_LEN, 1)) {
        return -EINVAL;
    }
    // 结束响应消息的构建
    genlmsg_end(reply, msg_head);
    // 进行消息的返回
    if (0 != genlmsg_reply(reply, info)) {
        return -EINVAL;
    }
    return 0;
    // ------------------------ 准备进行消息的回复 ------------------------
}
