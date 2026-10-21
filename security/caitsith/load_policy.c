/*
 * security/caitsith/load_policy.c
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 0.2.16   2026/09/28
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/namei.h>

/*
 * TOMOYO specific part start.
 */

#include <linux/caitsith.h>

/**
 * cs_setup - Set enable/disable upon boot.
 *
 * @str: "off" to disable, "on" to enable.
 *
 * Returns 0.
 */
static int __init cs_setup(char *str)
{
	if (!strcmp(str, "off"))
		caitsith_ops.disabled = 1;
	else if (!strcmp(str, "on"))
		caitsith_ops.disabled = 0;
	return 0;
}

__setup("caitsith=", cs_setup);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
#include "lsm2caitsith.c"
#endif

#ifndef CONFIG_CAITSITH_OMIT_USERSPACE_LOADER

/* Path to the policy loader. (default = CONFIG_CAITSITH_POLICY_LOADER) */
static const char *cs_loader;

/**
 * cs_loader_setup - Set policy loader.
 *
 * @str: Program to use as a policy loader (e.g. /sbin/caitsith-init ).
 *
 * Returns 0.
 */
static int __init cs_loader_setup(char *str)
{
	cs_loader = str;
	return 0;
}

__setup("CS_loader=", cs_loader_setup);

/**
 * cs_policy_loader_exists - Check whether /sbin/caitsith-init exists.
 *
 * Returns true if /sbin/caitsith-init exists, false otherwise.
 */
static _Bool cs_policy_loader_exists(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
	struct path path;

	if (!cs_loader)
		cs_loader = CONFIG_CAITSITH_POLICY_LOADER;
	if (kern_path(cs_loader, LOOKUP_FOLLOW, &path) == 0) {
		path_put(&path);
		return 1;
	}
#else
	struct nameidata nd;

	if (!cs_loader)
		cs_loader = CONFIG_CAITSITH_POLICY_LOADER;
	if (path_lookup(cs_loader, LOOKUP_FOLLOW, &nd) == 0) {
		path_put(&nd.path);
		return 1;
	}
#endif
	printk(KERN_INFO "Not activating CaitSith as %s does not exist.\n",
	       cs_loader);
	return 0;
}

/* Path to the trigger. (default = CONFIG_CAITSITH_ACTIVATION_TRIGGER) */
static const char *cs_trigger;

/**
 * cs_trigger_setup - Set trigger for activation.
 *
 * @str: Program to use as an activation trigger (e.g. /sbin/init ).
 *
 * Returns 0.
 */
static int __init cs_trigger_setup(char *str)
{
	cs_trigger = str;
	return 0;
}

__setup("CS_trigger=", cs_trigger_setup);

/**
 * cs_load_policy - Run external policy loader to load policy.
 *
 * @filename: The program about to start.
 *
 * Returns nothing.
 *
 * This function checks whether @filename is /sbin/init, and if so
 * invoke /sbin/caitsith-init and wait for the termination of
 * /sbin/caitsith-init and then continues invocation of /sbin/init.
 * /sbin/caitsith-init reads policy files in /etc/caitsith/ directory and
 * writes to /sys/kernel/security/caitsith/ interfaces.
 */
static void cs_load_policy(const char *filename)
{
	static _Bool done;

	if (caitsith_ops.disabled || done)
		return;
	if (!cs_trigger)
		cs_trigger = CONFIG_CAITSITH_ACTIVATION_TRIGGER;
	if (strcmp(filename, cs_trigger))
		return;
	if (!cs_policy_loader_exists())
		return;
	done = 1;
	{
		char *argv[2];
		char *envp[3];

		printk(KERN_INFO "Calling %s to load policy. Please wait.\n",
		       cs_loader);
		argv[0] = (char *) cs_loader;
		argv[1] = NULL;
		envp[0] = "HOME=/";
		envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
		envp[2] = NULL;
		call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	}
	if (caitsith_ops.check_profile)
		caitsith_ops.check_profile();
	else
		panic("Failed to load policy.");
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
 
/**
 * cs_start_execve - Load policy before calling search_binary_handler().
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @rp:  Pointer to "struct cs_request_info *".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_start_execve(struct linux_binprm *bprm, struct cs_request_info **rp)
{
#ifndef CONFIG_CAITSITH_OMIT_USERSPACE_LOADER
	cs_load_policy(bprm->filename);
#endif
	/*
	 * cs_load_policy() executes /sbin/ccs-init if bprm->filename is
	 * /sbin/init. /sbin/ccs-init executes /etc/ccs/ccs-load-module to
	 * load loadable kernel module. The loadable kernel module modifies
	 * "struct caitsith_ops". Thus, we need to transfer control to
	 * cs_start_execve() in security/caitsith/permission.c
	 * if "struct caitsith_ops" was modified.
	 */
	if (caitsith_ops.start_execve != cs_start_execve)
		return caitsith_ops.start_execve(bprm, rp);
	return 0;
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)

/**
 * cs_search_binary_handler - Load policy before calling search_binary_handler().
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_search_binary_handler(struct linux_binprm *bprm)
{
#ifndef CONFIG_CAITSITH_OMIT_USERSPACE_LOADER
	cs_load_policy(bprm->filename);
#endif
	/*
	 * cs_load_policy() executes /sbin/caitsith-init if bprm->filename is
	 * /sbin/init. /sbin/caitsith-init executes
	 * /etc/caitsith/caitsith-load-module to load loadable kernel module.
	 * The loadable kernel module modifies "struct caitsith_ops". Thus,
	 * we need to transfer control to cs_search_binary_handler() in
	 * security/caitsith/permission.c if "struct caitsith_ops" was
	 * modified.
	 */
	if (caitsith_ops.search_binary_handler != cs_search_binary_handler)
		return caitsith_ops.search_binary_handler(bprm);
	return search_binary_handler(bprm);
}

#else

/**
 * cs_search_binary_handler - Load policy before calling search_binary_handler().
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @regs: Pointer to "struct pt_regs".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_search_binary_handler(struct linux_binprm *bprm,
				    struct pt_regs *regs)
{
#ifndef CONFIG_CAITSITH_OMIT_USERSPACE_LOADER
	cs_load_policy(bprm->filename);
#endif
	/*
	 * cs_load_policy() executes /sbin/caitsith-init if bprm->filename is
	 * /sbin/init. /sbin/caitsith-init executes
	 * /etc/caitsith/caitsith-load-module to load loadable kernel module.
	 * The loadable kernel module modifies "struct caitsith_ops". Thus,
	 * we need to transfer control to cs_search_binary_handler() in
	 * security/caitsith/permission.c if "struct caitsith_ops" was
	 * modified.
	 */
	if (caitsith_ops.search_binary_handler != cs_search_binary_handler)
		return caitsith_ops.search_binary_handler(bprm, regs);
	return search_binary_handler(bprm, regs);
}

#endif

/*
 * Some exports for loadable kernel module part.
 *
 * Although scripts/checkpatch.pl complains about use of "extern" in C file,
 * we don't put these into security/caitsith/internal.h because we want to
 * split built-in part and loadable kernel module part.
 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
extern spinlock_t vfsmount_lock;
#endif

/* For exporting variables and functions. */
const struct caitsith_exports caitsith_exports = {
#ifndef CONFIG_CAITSITH_OMIT_USERSPACE_LOADER
	.load_policy = cs_load_policy,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	.d_absolute_path = d_absolute_path,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	.__d_path = __d_path,
#else
	.vfsmount_lock = &vfsmount_lock,
#endif
	.find_task_by_vpid = find_task_by_vpid,
	.find_task_by_pid_ns = find_task_by_pid_ns,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	.ksize = ksize,
#endif
};
#ifdef CONFIG_CAITSITH_LKM
/* Only caitsith module need to access this struct. */
EXPORT_SYMBOL_GPL(caitsith_exports);
#endif

/* Members are updated by loadable kernel module. */
struct caitsith_operations caitsith_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	.start_execve = cs_start_execve,
#else
	.search_binary_handler = cs_search_binary_handler,
#endif
#ifdef CONFIG_CAITSITH_DISABLE_BY_DEFAULT
	.disabled = 1,
#endif
};
/*
 * Non-GPL modules might need to access this struct via inlined functions
 * embedded into include/linux/security.h and include/net/ip.h
 */
EXPORT_SYMBOL(caitsith_ops);
