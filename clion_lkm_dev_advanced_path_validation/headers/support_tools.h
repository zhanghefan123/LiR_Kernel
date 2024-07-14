#ifndef ZEUSNET_KERNEL_TOOLS_H
#define ZEUSNET_KERNEL_TOOLS_H
#include <net/route.h>
#define LOG_PREFIX "[zeusnet's kernel info]:"
#define STRING_WITH_PREFIX(v) LOG_PREFIX v
void LOG_WITH_PREFIX(char* msg);
void LOG_WITH_EDGE(char* msg);
void PRINT_RT(struct rtable* rt);
void LOG_RESOLVED(void* pointer, const char* function_name);
bool TEST_IF_LIR_SOCKET(struct sock* sk);
bool COMPARE_MEMORY(const unsigned char* first_memory, const unsigned char* second_memory, int length_in_bytes);
void XOR_MEMORY(unsigned char* destination_memory, const unsigned char* source_memory, int length_in_bytes);

#endif
