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
        tools.c
        module_starter.c
        ftrace_hook_api.c
        hook_functions.c
        resolve_function_address.c
        hook_tcp_v4_rcv.c
        self_defined_tcp_v4_do_rcv.c
        self_defined_tcp_rcv_established.c
)

set(HEADERS_DIR include)

# CLion IDE will find symbols from <linux/*>
target_include_directories("dummy" PRIVATE ${HEADERS_DIR})