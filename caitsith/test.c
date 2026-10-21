/*
 * test.c
 *
 * Copyright (C) 2010-2013  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 */
#include "probe.h"

/**
 * cs_init - Initialize this module.
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int __init cs_init(void)
{
	void *ptr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0) || (defined(RHEL_MAJOR) && RHEL_MAJOR == 9 && defined(RHEL_MINOR) && RHEL_MINOR >= 6)
	ptr = probe_static_calls_table();
	if (!ptr)
		goto out;
	printk(KERN_INFO "static_calls_table=%lx\n", (unsigned long) ptr);
#elif defined(LSM_HOOK_INIT)
	ptr = probe_security_hook_heads();
	if (!ptr)
		goto out;
	printk(KERN_INFO "security_hook_heads=%lx\n", (unsigned long) ptr);
#else
	ptr = probe_security_ops();
	if (!ptr)
		goto out;
	printk(KERN_INFO "security_ops=%lx\n", (unsigned long) ptr);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	ptr = probe_find_task_by_vpid();
	if (!ptr)
		goto out;
	printk(KERN_INFO "find_task_by_vpid=%lx\n", (unsigned long) ptr);
	ptr = probe_find_task_by_pid_ns();
	if (!ptr)
		goto out;
	printk(KERN_INFO "find_task_by_pid_ns=%lx\n", (unsigned long) ptr);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	ptr = probe_vfsmount_lock();
	if (!ptr)
		goto out;
	printk(KERN_INFO "vfsmount_lock=%lx\n", (unsigned long) ptr);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
	ptr = probe___d_path();
	if (!ptr)
		goto out;
	printk(KERN_INFO "__d_path=%lx\n", (unsigned long) ptr);
#else
	ptr = probe_d_absolute_path();
	if (!ptr)
		goto out;
	printk(KERN_INFO "d_absolute_path=%lx\n", (unsigned long) ptr);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	ptr = probe_ksize();
	if (!ptr)
		goto out;
	printk(KERN_INFO "ksize=%lx\n", (unsigned long) ptr);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	ptr = probe_copy_to_kernel_nofault();
	if (!ptr)
		goto out;
	printk(KERN_INFO "copy_to_kernel_nofault=%lx\n", (unsigned long) ptr);
#endif
	printk(KERN_INFO "All dependent symbols have been guessed.\n");
	printk(KERN_INFO "Please verify these addresses using System.map for this kernel (e.g. /boot/System.map-`uname -r` ).\n");
	printk(KERN_INFO "If these addresses are correct, you can try loading CaitSith module on this kernel.\n");
	return 0;
out:
	printk(KERN_INFO "Sorry, I couldn't guess dependent symbols.\n");
	printk(KERN_INFO "I need some changes for supporting your environment.\n");
	printk(KERN_INFO "Please contact the author.\n");
	return -EINVAL;
}

/**
 * cs_exit - Exit this module.
 *
 * Returns nothing.
 */
static void cs_exit(void)
{
}

module_init(cs_init);
module_exit(cs_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Symbol resolve test for CaitSith");
