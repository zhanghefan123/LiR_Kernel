//
// Created by zhf on 24-4-5.
//

#ifndef ZEUSNET_KERNEL_IP_ROUTE_INPUT_FLOW_WITHOUT_CACHE_H
#define ZEUSNET_KERNEL_IP_ROUTE_INPUT_FLOW_WITHOUT_CACHE_H
#include <net/ip.h>
#include "support_ftrace_hook_api.h"
#include "lir_configuration.h"
void add_ip_route_input_noref_to_hook(void);
void resolve_ip_route_input_noref_inner_function_address(void);
int self_defined_ip_route_input_noref(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                                      u8 tos, struct net_device *dev);
int self_defined_ip_route_input_rcu(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                                    u8 tos, struct net_device *dev, struct fib_result *res);
int self_defined_ip_route_input_slow(struct sk_buff *skb, __be32 daddr, __be32 saddr,
                                     u8 tos, struct net_device *dev,
                                     struct fib_result *res);
int self_defined_ip_mkroute_input(struct sk_buff *skb,
                                  struct fib_result *res,
                                  struct in_device *in_dev,
                                  __be32 daddr, __be32 saddr, u32 tos,
                                  struct flow_keys *hkeys);
int self_defined__mkroute_input(struct sk_buff *skb,
                                const struct fib_result *res,
                                struct in_device *in_dev,
                                __be32 daddr, __be32 saddr, u32 tos);
extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;
#endif // ZEUSNET_KERNEL_IP_ROUTE_INPUT_FLOW_WITHOUT_CACHE_H
