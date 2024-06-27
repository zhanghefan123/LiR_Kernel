//
// Created by zhf on 24-3-11.
//

#ifndef ZEUSNET_KERNEL_LIR_INTERFACE_TABLE_STRUCTURE_H
#define ZEUSNET_KERNEL_LIR_INTERFACE_TABLE_STRUCTURE_H

#include <net/ip.h>

struct NewInterfaceEntry {
    int link_identifier; // corresponding link identifier
    struct net_device *interface; // corresponding interface
};

struct NewInterfaceTable {
    int number_of_interfaces; // number of interfaces
    struct NewInterfaceEntry *interface_entry_array; // interface_entry_array
};

struct NewInterfaceTable *init_new_interface_table(int number_of_interfaces);

void delete_new_interface_table(struct NewInterfaceTable *new_interface_table);

void generate_single_new_interface_table_entry(struct net *current_net_namespace,
                                               struct NewInterfaceTable *new_interface_table,
                                               char *corresponding_message,
                                               int index);

struct NewInterfaceEntry find_entry_in_new_interface_table(struct NewInterfaceTable* new_interface_table, int link_identifier);
#endif // ZEUSNET_KERNEL_LIR_INTERFACE_TABLE_STRUCTURE_H
