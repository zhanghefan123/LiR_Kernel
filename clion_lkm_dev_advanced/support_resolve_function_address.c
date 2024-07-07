//
// Created by root on 2/8/24.
//
#include "headers/support_resolve_function_address.h"
#include "headers/mac_br_handle_frame.h"
#include "headers/mac_netif_rcv_skb.h"
#include "headers/network_lir_make_skb.h"
#include "headers/network_lir_rcv.h"
#include "headers/transport_lir_udp_rcv.h"
#include "headers/network_ip_rcv.h"
#include "headers/ip_route_output_flow_without_cache.h"
#include "headers/ip_route_input_noref_without_cache.h"

/*
 * 使用 kallsyms_lookup_name 进行函数地址的查找
 */
void resolve_function_address(void){
    resolve_br_handle_frame_inner_functions_address();
    resolve_netif_rcv_skb_inner_functions_address();
    resolve_lir_make_skb_inner_functions_address();
    resolve_network_lir_rcv_inner_functions_address();
    resolve_transport_lir_udp_rcv_inner_functions_address();
    resolve_network_ip_rcv_inner_functions_address();
    resolve_ip_route_input_noref_inner_function_address();
    resolve_ip_route_output_flow_inner_function_address();
}