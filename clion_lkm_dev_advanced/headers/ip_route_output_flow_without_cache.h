//
// Created by zhf on 24-4-5.
//

#ifndef ZEUSNET_KERNEL_IP_ROUTE_OUTPUT_FLOW_WITHOUT_CACHE_H
#define ZEUSNET_KERNEL_IP_ROUTE_OUTPUT_FLOW_WITHOUT_CACHE_H
#include <net/ip.h>
#include "support_ftrace_hook_api.h"
#include "lir_configuration.h"
struct rtable *self_defined__mkroute_output(const struct fib_result *res,
                                            const struct flowi4 *fl4, int orig_oif,
                                            struct net_device *dev_out,
                                            unsigned int flags);
void resolve_ip_route_output_flow_inner_function_address(void);
struct rtable *self_defined_ip_route_output_key_hash(struct net *net, struct flowi4 *fl4,
                                                     const struct sk_buff *skb);
struct rtable *self_defined_ip_route_output_key_hash_rcu(struct net *net, struct flowi4 *fl4,
                                                         struct fib_result *res,
                                                         const struct sk_buff *skb);
struct rtable *self_defined_ip_route_output_flow(struct net * net, struct flowi4 *flp4, const struct sock *sk);
void add_ip_route_output_flow_to_hook(void);
extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;
#endif //ZEUSNET_KERNEL_IP_ROUTE_OUTPUT_FLOW_WITHOUT_CACHE_H
