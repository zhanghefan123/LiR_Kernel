//
// Created by zhf on 24-3-11.
//
#include "headers/support_tools.h"
#include "headers/lir_interface_table_structure.h"

struct NewInterfaceTable* init_new_interface_table(int number_of_interfaces){
    struct NewInterfaceTable* new_interface_table = (struct NewInterfaceTable*)(kmalloc(sizeof(struct NewInterfaceTable),GFP_KERNEL));
    new_interface_table->number_of_interfaces = number_of_interfaces;
    new_interface_table->interface_entry_array = (struct NewInterfaceEntry*)(kmalloc(number_of_interfaces * sizeof(struct NewInterfaceEntry), GFP_KERNEL));
    return new_interface_table;
}

void delete_new_interface_table(struct NewInterfaceTable* new_interface_table){
    if(new_interface_table != NULL) {
        if (new_interface_table->interface_entry_array != NULL) {
            kfree(new_interface_table->interface_entry_array);
            LOG_WITH_PREFIX("delete new interface table succeed!");
        }
        kfree(new_interface_table);
    }
}

void generate_single_new_interface_table_entry(struct net* current_net_namespace, struct NewInterfaceTable* new_interface_table, char* corresponding_message, int index){
    char* single_element = NULL;
    char* delimiter = ",";
    int count = 0;
    while (true) {
        single_element = strsep(&corresponding_message, delimiter);
        if (single_element == NULL || (strcmp(single_element, "") == 0)) {
            break;
        } else {
            if (count == 0) {
                // 获取 link identifier
                new_interface_table->interface_entry_array[index].link_identifier = (int) (simple_strtol(single_element, NULL, 10));
            } else if (count == 1) {
                // 通过 ifindex 进行 interface 的获取并进行赋值
                int ifindex = (int) (simple_strtol(single_element, NULL, 10));
                new_interface_table->interface_entry_array[index].interface = dev_get_by_index(current_net_namespace, ifindex);
                dev_put(new_interface_table->interface_entry_array[index].interface);
            }
        }
        count += 1;
    }
}

struct NewInterfaceEntry find_entry_in_new_interface_table(struct NewInterfaceTable* new_interface_table, int link_identifier){
    int index;
    struct NewInterfaceEntry empty_entry= {};
    for(index = 0; index < new_interface_table->number_of_interfaces; index++){
        struct NewInterfaceEntry current_entry = new_interface_table->interface_entry_array[index];
        if(current_entry.link_identifier == link_identifier){
            return current_entry;
        }
    }
    return empty_entry;
}