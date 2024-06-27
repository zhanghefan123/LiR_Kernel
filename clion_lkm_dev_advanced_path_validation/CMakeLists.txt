cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

project("Linux Kernel Module with CLion IDE support / CMake" VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find kernel headers
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(KernelHeaders REQUIRED)


# find MODULE_LICENSE("GPL"), MODULE_AUTHOR() etc.
# thanks to "merseyviking" from stack overflow
add_definitions(-D__KERNEL__ -DMODULE)

# this is needed in order for CLion IDE to provide syntax highlightning
# this is independent from the actual kernel object that is built
add_executable(dummy
        # add all *.h and *.c files here that # CLion should cover
        support_tools.c
        support_module_starter.c
        support_ftrace_hook_api.c
        support_hook_functions.c
        support_resolve_function_address.c
        netlink_server.c
        netlink_handler.c
        lir_bloom_filter.c
        lir_data_structure.c
        lir_routing_table_structure.c
        lir_interface_table_structure.c
        mac_br_handle_frame.c
        mac_netif_rcv_skb.c
        mac_lir_ip_output.c
        transport_lir_udp_sendmsg.c
        transport_lir_udp_send_skb.c
        transport_lir_udp_rcv.c
        network_lir_make_skb.c
        network_lir_send_check.c
        network_lir_header.c
        network_lir_rcv.c
        network_ip_rcv.c
        cypher_test.c
        crypto_function.c
)

set(HEADERS_DIR include)

# CLion IDE will find symbols from <linux/*>
target_include_directories("dummy" PRIVATE ${HEADERS_DIR})