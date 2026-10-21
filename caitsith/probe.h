#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/security.h>
#ifndef __init
#include <linux/init.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/cred.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <linux/uio.h>
#include <linux/seq_file.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
#error This module supports only 2.6.0 and later kernels.
#endif
#ifndef CONFIG_SECURITY
#error You must choose CONFIG_SECURITY=y for building this module.
#endif
#ifndef CONFIG_KALLSYMS
#error You must choose CONFIG_KALLSYMS=y for building this module.
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0) && !defined(CONFIG_KALLSYMS_ALL)
#error You must choose CONFIG_KALLSYMS_ALL=y for building this module.
#endif
#ifndef CONFIG_PROC_FS
#error You must choose CONFIG_PROC_FS=y for building this module.
#endif
#ifndef CONFIG_MODULES
#error You must choose CONFIG_MODULES=y for building this module.
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
#include <linux/kallsyms.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0) || (defined(RHEL_MAJOR) && RHEL_MAJOR == 9 && defined(RHEL_MINOR) && RHEL_MINOR >= 6)
#include <linux/lsm_hooks.h>
struct lsm_static_calls_table * __init probe_static_calls_table(void);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0) && !defined(SECURITY_NAME_MAX)
#include <linux/lsm_hooks.h>
extern struct security_hook_heads probe_dummy_security_hook_heads;
struct security_hook_heads * __init probe_security_hook_heads(void);
#else
struct security_operations;
struct security_operations * __init probe_security_ops(void);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
void * __init probe_find_task_by_vpid(void);
void * __init probe_find_task_by_pid_ns(void);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
void * __init probe_vfsmount_lock(void);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
void * __init probe___d_path(void);
#else
void * __init probe_d_absolute_path(void);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
void * __init probe_ksize(void);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
void * __init probe_copy_to_kernel_nofault(void);
#endif
