//
// Created by kernel-dbg on 24-2-1.
//

#ifndef ZEUSNET_KERNEL_HOOK_UDP_H
#define ZEUSNET_KERNEL_HOOK_UDP_H
int install_hook_functions(void);
void uninstall_hook_functions(void);
void tidy(void);
void start_install_hooks(void);
void exit_uninstall_hooks(void);
void add_hook_functions(void);
#endif
