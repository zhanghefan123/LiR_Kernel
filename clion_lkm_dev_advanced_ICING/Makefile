# this is a make file for a kernel object
# see online for more information
CONFIG_MODULE_SIG=n
# will build "hello.ko"
obj-m += lir.o

# we have no file "hello.c" in this example
# therefore we specify: module hello.ko relies on
# main.c and greet.c ... it's this makefile module magic thing..
# see online resources for more information
# YOU DON'T need this IF you have *.c-file with the name of the
# final kernel module :)
lir-objs := \
	support_tools.o \
	support_ftrace_hook_api.o \
	support_hook_functions.o \
	support_module_starter.o \
	support_resolve_function_address.o \
	netlink_server.o \
	netlink_handler.o \
	lir_bloom_filter.o \
	lir_data_structure.o \
	lir_routing_table_structure.o \
	lir_interface_table_structure.o\
	mac_br_handle_frame.o \
	mac_netif_rcv_skb.o \
	mac_lir_ip_output.o \
	transport_lir_udp_sendmsg.o \
	transport_lir_udp_send_skb.o \
	transport_lir_udp_rcv.o \
	network_lir_make_skb.o \
	network_lir_send_check.o \
	network_lir_header.o \
	network_lir_rcv.o \
	network_ip_rcv.o \
	crypto_function.o \


OUTPUT_DIR = "./build"



all: compile
	echo "successful make"

compile:
	make -C /lib/modules/5.19.0/build/ M=$(PWD) modules  #

mv:
	mv .*.cmd *.ko *.o *.mod *.mod.c Module.symvers modules.order $(OUTPUT_DIR)

clean:
	rm -rf .*.cmd *.ko *.o *.mod *.mod.c Module.symvers modules.order
	# make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
