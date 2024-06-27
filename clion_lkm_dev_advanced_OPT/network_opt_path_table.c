//
// Created by zhf on 24-4-27.
//
#include "headers/network_opt_path_table.h"

struct OptPathTableEntry* init_opt_path_table_entry(){
    struct OptPathTableEntry* opt_path_table_entry = (struct OptPathTableEntry*)(kmalloc(sizeof(struct OptPathTableEntry), GFP_KERNEL));
    opt_path_table_entry->current_path_index = -1;
    opt_path_table_entry->length_of_path = -1;
    return opt_path_table_entry;
}