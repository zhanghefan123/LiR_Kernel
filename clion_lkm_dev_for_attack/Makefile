# this is a make file for a kernel object
# see online for more information
CONFIG_MODULE_SIG=n
# will build "hello.ko"
obj-m += attack.o

# we have no file "hello.c" in this example
# therefore we specify: module hello.ko relies on
# main.c and greet.c ... it's this makefile module magic thing..
# see online resources for more information
# YOU DON'T need this IF you have *.c-file with the name of the
# final kernel module :)
attack-objs := \
	tools.o \
	ftrace_hook_api.o \
	hook_functions.o \
	module_starter.o \
	resolve_function_address.o \
	hook_tcp_v4_rcv.o \
	self_defined_tcp_v4_do_rcv.o \
	self_defined_tcp_rcv_established.o

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
