//
// Created by zhf on 24-4-27.
//

#ifndef LINUX_KERNEL_MODULE_WITH_CLION_IDE_SUPPORT_CMAKE_OPT_PATH_TABLE_H
#define LINUX_KERNEL_MODULE_WITH_CLION_IDE_SUPPORT_CMAKE_OPT_PATH_TABLE_H
#include "network_lir_header.h"
#define OPT_BUCKET_COUNT 1000
#define HASH_SEED 1234

struct OptPathTableEntry{
    int length_of_path;  // A->B->C->D then the length of path equals to four
    int current_path_index; // where i am
    struct single_hop_field* path;  // the path transmitted by the source
};

struct OptPathTableEntry* init_opt_path_table_entry();

#endif //LINUX_KERNEL_MODULE_WITH_CLION_IDE_SUPPORT_CMAKE_OPT_PATH_TABLE_H
