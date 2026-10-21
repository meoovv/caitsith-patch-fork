/*
 * lsm.c
 *
 * Copyright (C) 2010-2013  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Version: 0.2.16   2026/09/28
 */

#include "caitsith.h"
#include "probe.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
#define USE_UMODE_T
#else
#include "check_umode_t.h"
#endif

/* Prototype definition. */
static void cs_task_security_gc(void);
static int cs_copy_cred_security(const struct cred *new,
				 const struct cred *old, gfp_t gfp);
static struct cs_security *cs_find_cred_security(const struct cred *cred);
static DEFINE_SPINLOCK(cs_task_security_list_lock);
static atomic_t cs_in_execve_tasks = ATOMIC_INIT(0);

/*
 * List of "struct cs_security" for "struct pid".
 *
 * All instances on this list is guaranteed that "struct cs_security"->pid !=
 * NULL. Also, instances on this list that are in execve() are guaranteed that
 * "struct cs_security"->cred remembers "struct linux_binprm"->cred with a
 * refcount on "struct linux_binprm"->cred.
 */
struct list_head cs_task_security_list[CS_MAX_TASK_SECURITY_HASH];

/*
 * List of "struct cs_security" for "struct cred".
 *
 * Since the number of "struct cred" is nearly equals to the number of
 * "struct pid", we allocate hash tables like cs_task_security_list.
 *
 * All instances on this list are guaranteed that "struct cs_security"->pid ==
 * NULL and "struct cs_security"->cred != NULL.
 */
static struct list_head cs_cred_security_list[CS_MAX_TASK_SECURITY_HASH];

/* Dummy security context for avoiding NULL pointer dereference. */
static struct cs_security cs_oom_security = {
	.cs_domain_info = &cs_kernel_domain
};

/* Dummy security context for avoiding NULL pointer dereference. */
static struct cs_security cs_default_security = {
	.cs_domain_info = &cs_kernel_domain
};

/* For exporting variables and functions. */
struct caitsith_exports caitsith_exports;

/* Function pointers originally registered by register_security(). */
static struct security_operations original_security_ops /* = *security_ops; */;

#define wait_ready(op) while (!original_security_ops.op) smp_rmb()

#if !defined(CONFIG_CAITSITH_DEBUG)
#define cs_debug_trace(pos) do { } while (0)
#else
#define cs_debug_trace(pos)						\
	do {								\
		static bool done;					\
		if (!done) {						\
			printk(KERN_INFO				\
			       "CAITSITH: Debug trace: " pos " of 4\n"); \
			done = true;					\
		}							\
	} while (0)
#endif

/**
 * cs_clear_execve - Release memory used by do_execve().
 *
 * @ret:      0 if do_execve() succeeded, negative value otherwise.
 * @security: Pointer to "struct cs_security".
 *
 * Returns nothing.
 */
static void cs_clear_execve(int ret, struct cs_security *security)
{
	struct cs_request_info *r;

	if (security == &cs_default_security || security == &cs_oom_security)
		return;
	r = security->r;
	security->r = NULL;
	if (!r)
		return;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
	/*
	 * Drop refcount on "struct cred" in "struct linux_binprm" and forget
	 * it.
	 */
	put_cred(security->cred);
	security->cred = NULL;
#endif
	atomic_dec(&cs_in_execve_tasks);
	cs_finish_execve(ret, r);
}

/**
 * cs_rcu_free - RCU callback for releasing "struct cs_security".
 *
 * @rcu: Pointer to "struct rcu_head".
 *
 * Returns nothing.
 */
static void cs_rcu_free(struct rcu_head *rcu)
{
	struct cs_security *ptr = container_of(rcu, typeof(*ptr), rcu);
	struct cs_request_info *r = ptr->r;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	/*
	 * If this security context was associated with "struct pid" and
	 * ptr->cs_flags has CS_TASK_IS_IN_EXECVE set, it indicates that a
	 * "struct task_struct" associated with this security context exited
	 * immediately after do_execve() has failed.
	 */
	if (ptr->pid && (ptr->cs_flags & CS_TASK_IS_IN_EXECVE)) {
		cs_debug_trace("1");
		atomic_dec(&cs_in_execve_tasks);
	}
#else
	/*
	 * If this security context was associated with "struct pid" and
	 * remembers "struct cred" in "struct linux_binprm", it indicates that
	 * a "struct task_struct" associated with this security context exited
	 * immediately after do_execve() has failed.
	 */
	if (ptr->pid && ptr->cred) {
		cs_debug_trace("1");
		put_cred(ptr->cred);
		atomic_dec(&cs_in_execve_tasks);
	}
#endif
	/*
	 * If this security context was associated with "struct pid",
	 * drop refcount obtained by get_pid() in cs_find_task_security().
	 */
	if (ptr->pid) {
		cs_debug_trace("2");
		put_pid(ptr->pid);
	}
	if (r) {
		cs_debug_trace("3");
		kfree(r->handler_path);
		kfree(r);
	}
	kfree(ptr);
}

/**
 * cs_del_security - Release "struct cs_security".
 *
 * @ptr: Pointer to "struct cs_security".
 *
 * Returns nothing.
 */
static void cs_del_security(struct cs_security *ptr)
{
	unsigned long flags;

	if (ptr == &cs_default_security || ptr == &cs_oom_security)
		return;
	spin_lock_irqsave(&cs_task_security_list_lock, flags);
	list_del_rcu(&ptr->list);
	spin_unlock_irqrestore(&cs_task_security_list_lock, flags);
	call_rcu(&ptr->rcu, cs_rcu_free);
}

/**
 * cs_add_cred_security - Add "struct cs_security" to list.
 *
 * @ptr: Pointer to "struct cs_security".
 *
 * Returns nothing.
 */
static void cs_add_cred_security(struct cs_security *ptr)
{
	unsigned long flags;
	struct list_head *list = &cs_cred_security_list
		[hash_ptr((void *) ptr->cred, CS_TASK_SECURITY_HASH_BITS)];
#ifdef CONFIG_CAITSITH_DEBUG
	if (ptr->pid)
		printk(KERN_INFO "CAITSITH: \"struct cs_security\"->pid != NULL\n");
#endif
	ptr->pid = NULL;
	spin_lock_irqsave(&cs_task_security_list_lock, flags);
	list_add_rcu(&ptr->list, list);
	spin_unlock_irqrestore(&cs_task_security_list_lock, flags);
}

/**
 * cs_task_create - Make snapshot of security context for new task.
 *
 * @clone_flags: Flags passed to clone().
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_task_create(unsigned long clone_flags)
{
	int rc;
	struct cs_security *old_security;
	struct cs_security *new_security;
	struct cred *cred = prepare_creds();

	if (!cred)
		return -ENOMEM;
	wait_ready(task_create);
	rc = original_security_ops.task_create(clone_flags);
	if (rc) {
		abort_creds(cred);
		return rc;
	}
	old_security = cs_find_task_security(current);
	new_security = cs_find_cred_security(cred);
	new_security->cs_domain_info = old_security->cs_domain_info;
	new_security->cs_flags = old_security->cs_flags;
	return commit_creds(cred);
}

/**
 * cs_cred_prepare - Allocate memory for new credentials.
 *
 * @new: Pointer to "struct cred".
 * @old: Pointer to "struct cred".
 * @gfp: Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_cred_prepare(struct cred *new, const struct cred *old,
			   gfp_t gfp)
{
	int rc;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	/*
	 * For checking whether reverting domain transition is needed or not.
	 *
	 * See cs_find_task_security() for reason.
	 */
	if ((gfp & GFP_KERNEL) == GFP_KERNEL)
		cs_find_task_security(current);
#endif
	rc = cs_copy_cred_security(new, old, gfp);
	if (rc)
		return rc;
	if ((gfp & GFP_KERNEL) == GFP_KERNEL)
		cs_task_security_gc();
	wait_ready(cred_prepare);
	rc = original_security_ops.cred_prepare(new, old, gfp);
	if (rc)
		cs_del_security(cs_find_cred_security(new));
	return rc;
}

/**
 * cs_cred_free - Release memory used by credentials.
 *
 * @cred: Pointer to "struct cred".
 *
 * Returns nothing.
 */
static void cs_cred_free(struct cred *cred)
{
	wait_ready(cred_free);
	original_security_ops.cred_free(cred);
	cs_del_security(cs_find_cred_security(cred));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)

/**
 * cs_alloc_cred_security - Allocate memory for new credentials.
 *
 * @cred: Pointer to "struct cred".
 * @gfp:  Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_alloc_cred_security(const struct cred *cred, gfp_t gfp)
{
	struct cs_security *new_security = kzalloc(sizeof(*new_security),
						   gfp);
	if (!new_security)
		return -ENOMEM;
	new_security->cred = cred;
	cs_add_cred_security(new_security);
	return 0;
}

/**
 * cs_cred_alloc_blank - Allocate memory for new credentials.
 *
 * @new: Pointer to "struct cred".
 * @gfp: Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_cred_alloc_blank(struct cred *new, gfp_t gfp)
{
	int rc = cs_alloc_cred_security(new, gfp);

	if (rc)
		return rc;
	wait_ready(cred_alloc_blank);
	rc = original_security_ops.cred_alloc_blank(new, gfp);
	if (rc)
		cs_del_security(cs_find_cred_security(new));
	return rc;
}

/**
 * cs_cred_transfer - Transfer "struct cs_security" between credentials.
 *
 * @new: Pointer to "struct cred".
 * @old: Pointer to "struct cred".
 *
 * Returns nothing.
 */
static void cs_cred_transfer(struct cred *new, const struct cred *old)
{
	struct cs_security *new_security;
	struct cs_security *old_security;

	wait_ready(cred_transfer);
	original_security_ops.cred_transfer(new, old);
	new_security = cs_find_cred_security(new);
	old_security = cs_find_cred_security(old);
	if (new_security == &cs_default_security ||
	    new_security == &cs_oom_security ||
	    old_security == &cs_default_security ||
	    old_security == &cs_oom_security)
		return;
	new_security->cs_flags = old_security->cs_flags;
	new_security->cs_domain_info = old_security->cs_domain_info;
}

#endif

/**
 * cs_bprm_committing_creds - A hook which is called when do_execve() succeeded.
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns nothing.
 */
static void cs_bprm_committing_creds(struct linux_binprm *bprm)
{
	struct cs_security *old_security;
	struct cs_security *new_security;

	wait_ready(bprm_committing_creds);
	original_security_ops.bprm_committing_creds(bprm);
	old_security = cs_current_security();
	if (old_security == &cs_default_security ||
	    old_security == &cs_oom_security)
		return;
	cs_clear_execve(0, old_security);
	/* Update current task's cred's domain for future fork(). */
	new_security = cs_find_cred_security(bprm->cred);
	new_security->cs_flags = old_security->cs_flags;
	new_security->cs_domain_info = old_security->cs_domain_info;
}

#ifndef CONFIG_CAITSITH_OMIT_USERSPACE_LOADER

/**
 * cs_policy_loader_exists - Check whether /sbin/caitsith-init exists.
 *
 * Returns true if /sbin/caitsith-init exists, false otherwise.
 */
static _Bool cs_policy_loader_exists(void)
{
	struct path path;

	if (kern_path(CONFIG_CAITSITH_POLICY_LOADER, LOOKUP_FOLLOW, &path)
	    == 0) {
		path_put(&path);
		return 1;
	}
	printk(KERN_INFO "Not activating CaitSith as %s does not exist.\n",
	       CONFIG_CAITSITH_POLICY_LOADER);
	return 0;
}

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

	if (done)
		return;
	if (strcmp(filename, CONFIG_CAITSITH_ACTIVATION_TRIGGER))
		return;
	if (!cs_policy_loader_exists())
		return;
	done = 1;
	{
		char *argv[2];
		char *envp[3];

		printk(KERN_INFO "Calling %s to load policy. Please wait.\n",
		       CONFIG_CAITSITH_POLICY_LOADER);
		argv[0] = (char *) CONFIG_CAITSITH_POLICY_LOADER;
		argv[1] = NULL;
		envp[0] = "HOME=/";
		envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
		envp[2] = NULL;
		call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	}
	cs_check_profile();
}

#endif

/**
 * cs_bprm_check_security - Check permission for execve().
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_bprm_check_security(struct linux_binprm *bprm)
{
	struct cs_security *security = cs_current_security();

	if (security == &cs_default_security || security == &cs_oom_security)
		return -ENOMEM;
	if (!security->r) {
		int rc;
#ifndef CONFIG_CAITSITH_OMIT_USERSPACE_LOADER
		if (!cs_policy_loaded)
			cs_load_policy(bprm->filename);
#endif
		rc = cs_start_execve(bprm, &security->r);
		if (security->r) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
			/*
			 * Get refcount on "struct cred" in
			 * "struct linux_binprm" and remember it.
			 */
			get_cred(bprm->cred);
			security->cred = bprm->cred;
#endif
			atomic_inc(&cs_in_execve_tasks);
		}
		if (rc)
			return rc;
	}
	wait_ready(bprm_check_security);
	return original_security_ops.bprm_check_security(bprm);
}

/**
 * cs_open - Check permission for open().
 *
 * @f: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_open(struct file *f)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	return cs_open_permission(&f->f_path, f->f_flags);
#elif defined(RHEL_MAJOR) && RHEL_MAJOR == 6
	return cs_open_permission(&f->f_path, f->f_flags);
#else
	return cs_open_permission(&f->f_path, f->f_flags + 1);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)

/**
 * cs_file_open - Check permission for open().
 *
 * @f:    Pointer to "struct file".
 * @cred: Pointer to "struct cred".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_file_open(struct file *f, const struct cred *cred)
{
	int rc = cs_open(f);

	if (rc)
		return rc;
	wait_ready(file_open);
	return original_security_ops.file_open(f, cred);
}

#else

/**
 * cs_dentry_open - Check permission for open().
 *
 * @f:    Pointer to "struct file".
 * @cred: Pointer to "struct cred".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_dentry_open(struct file *f, const struct cred *cred)
{
	int rc = cs_open(f);

	if (rc)
		return rc;
	wait_ready(dentry_open);
	return original_security_ops.dentry_open(f, cred);
}

#endif

#if defined(CONFIG_SECURITY_PATH)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)

/**
 * cs_path_chown - Check permission for chown()/chgrp().
 *
 * @path:  Pointer to "struct path".
 * @user:  User ID.
 * @group: Group ID.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_chown(struct path *path, kuid_t user, kgid_t group)
{
	int rc = cs_chown_permission(path, user, group);

	if (rc)
		return rc;
	wait_ready(path_chown);
	return original_security_ops.path_chown(path, user, group);
}

/**
 * cs_path_chmod - Check permission for chmod().
 *
 * @path: Pointer to "struct path".
 * @mode: Mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_chmod(struct path *path, umode_t mode)
{
	int rc = cs_chmod_permission(path, mode);

	if (rc)
		return rc;
	wait_ready(path_chmod);
	return original_security_ops.path_chmod(path, mode);
}

/**
 * cs_path_chroot - Check permission for chroot().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_chroot(struct path *path)
{
	int rc = cs_chroot_permission(path);

	if (rc)
		return rc;
	wait_ready(path_chroot);
	return original_security_ops.path_chroot(path);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)

/**
 * cs_path_chown - Check permission for chown()/chgrp().
 *
 * @path:  Pointer to "struct path".
 * @user:  User ID.
 * @group: Group ID.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_chown(struct path *path, uid_t user, gid_t group)
{
	int rc = cs_chown_permission(path, user, group);

	if (rc)
		return rc;
	wait_ready(path_chown);
	return original_security_ops.path_chown(path, user, group);
}

#if defined(USE_UMODE_T)

/**
 * cs_path_chmod - Check permission for chmod().
 *
 * @path: Pointer to "struct path".
 * @mode: Mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_chmod(struct path *path, umode_t mode)
{
	int rc = cs_chmod_permission(path, mode);

	if (rc)
		return rc;
	wait_ready(path_chmod);
	return original_security_ops.path_chmod(path, mode);
}

#else

/**
 * cs_path_chmod - Check permission for chmod().
 *
 * @dentry: Pointer to "struct dentry".
 * @vfsmnt: Pointer to "struct vfsmount".
 * @mode:   Mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_chmod(struct dentry *dentry, struct vfsmount *vfsmnt,
			 mode_t mode)
{
	struct path path = { .mnt = vfsmnt, .dentry = dentry };
	int rc = cs_chmod_permission(&path, mode);

	if (rc)
		return rc;
	wait_ready(path_chmod);
	return original_security_ops.path_chmod(dentry, vfsmnt, mode);
}

#endif

/**
 * cs_path_chroot - Check permission for chroot().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_chroot(struct path *path)
{
	int rc = cs_chroot_permission(path);

	if (rc)
		return rc;
	wait_ready(path_chroot);
	return original_security_ops.path_chroot(path);
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)

/**
 * cs_path_truncate - Check permission for truncate().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_truncate(struct path *path)
{
	int rc = cs_truncate_permission(path);

	if (rc)
		return rc;
	wait_ready(path_truncate);
	return original_security_ops.path_truncate(path);
}

#else

/**
 * cs_path_truncate - Check permission for truncate().
 *
 * @path:       Pointer to "struct path".
 * @length:     New length.
 * @time_attrs: New time attributes.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_truncate(struct path *path, loff_t length,
			    unsigned int time_attrs)
{
	int rc = cs_truncate_permission(path);

	if (rc)
		return rc;
	wait_ready(path_truncate);
	return original_security_ops.path_truncate(path, length, time_attrs);
}

#endif

#endif

/**
 * cs_inode_setattr - Check permission for chown()/chgrp()/chmod()/truncate().
 *
 * @dentry: Pointer to "struct dentry".
 * @attr:   Pointer to "struct iattr".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	int rc = 0;
#if !defined(CONFIG_SECURITY_PATH) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	struct path path = { .mnt = NULL, .dentry = dentry };
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	if (attr->ia_valid & ATTR_UID)
		rc = cs_chown_permission(&path, attr->ia_uid, INVALID_GID);
	if (!rc && (attr->ia_valid & ATTR_GID))
		rc = cs_chown_permission(&path, INVALID_UID, attr->ia_gid);
#else
	if (attr->ia_valid & ATTR_UID)
		rc = cs_chown_permission(&path, attr->ia_uid, -1);
	if (!rc && (attr->ia_valid & ATTR_GID))
		rc = cs_chown_permission(&path, -1, attr->ia_gid);
#endif
	if (!rc && (attr->ia_valid & ATTR_MODE))
		rc = cs_chmod_permission(&path, attr->ia_mode);
#endif
#if !defined(CONFIG_SECURITY_PATH)
	if (!rc && (attr->ia_valid & ATTR_SIZE))
		rc = cs_truncate_permission(&path);
#endif
	if (rc)
		return rc;
	wait_ready(inode_setattr);
	return original_security_ops.inode_setattr(dentry, attr);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)

/**
 * cs_inode_getattr - Check permission for stat().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_getattr(const struct path *path)
{
	int rc = cs_getattr_permission(path);

	if (rc)
		return rc;
	wait_ready(inode_getattr);
	return original_security_ops.inode_getattr(path);
}

#else

/**
 * cs_inode_getattr - Check permission for stat().
 *
 * @mnt:    Pointer to "struct vfsmount".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	struct path path = { .mnt = mnt, .dentry = dentry };
	int rc = cs_getattr_permission(&path);

	if (rc)
		return rc;
	wait_ready(inode_getattr);
	return original_security_ops.inode_getattr(mnt, dentry);
}

#endif

#if defined(CONFIG_SECURITY_PATH)

#if defined(USE_UMODE_T)

/**
 * cs_path_mknod - Check permission for mknod().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 * @dev:    Device major/minor number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_mknod(struct path *dir, struct dentry *dentry,
			 umode_t mode, unsigned int dev)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };
	int rc = cs_mknod_permission(&path, mode, dev);

	if (rc)
		return rc;
	wait_ready(path_mknod);
	return original_security_ops.path_mknod(dir, dentry, mode, dev);
}

/**
 * cs_path_mkdir - Check permission for mkdir().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_mkdir(struct path *dir, struct dentry *dentry,
			 umode_t mode)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };
	int rc = cs_mkdir_permission(&path, mode);

	if (rc)
		return rc;
	wait_ready(path_mkdir);
	return original_security_ops.path_mkdir(dir, dentry, mode);
}

#else

/**
 * cs_path_mknod - Check permission for mknod().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 * @dev:    Device major/minor number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_mknod(struct path *dir, struct dentry *dentry, int mode,
			 unsigned int dev)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };
	int rc = cs_mknod_permission(&path, mode, dev);

	if (rc)
		return rc;
	wait_ready(path_mknod);
	return original_security_ops.path_mknod(dir, dentry, mode, dev);
}

/**
 * cs_path_mkdir - Check permission for mkdir().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_mkdir(struct path *dir, struct dentry *dentry, int mode)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };
	int rc = cs_mkdir_permission(&path, mode);

	if (rc)
		return rc;
	wait_ready(path_mkdir);
	return original_security_ops.path_mkdir(dir, dentry, mode);
}

#endif

/**
 * cs_path_rmdir - Check permission for rmdir().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_rmdir(struct path *dir, struct dentry *dentry)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };
	int rc = cs_rmdir_permission(&path);

	if (rc)
		return rc;
	wait_ready(path_rmdir);
	return original_security_ops.path_rmdir(dir, dentry);
}

/**
 * cs_path_unlink - Check permission for unlink().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_unlink(struct path *dir, struct dentry *dentry)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };
	int rc = cs_unlink_permission(&path);

	if (rc)
		return rc;
	wait_ready(path_unlink);
	return original_security_ops.path_unlink(dir, dentry);
}

/**
 * cs_path_symlink - Check permission for symlink().
 *
 * @dir:      Pointer to "struct path".
 * @dentry:   Pointer to "struct dentry".
 * @old_name: Content of symbolic link.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_symlink(struct path *dir, struct dentry *dentry,
			   const char *old_name)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };
	int rc = cs_symlink_permission(&path, old_name);

	if (rc)
		return rc;
	wait_ready(path_symlink);
	return original_security_ops.path_symlink(dir, dentry, old_name);
}

/**
 * cs_path_rename - Check permission for rename().
 *
 * @old_dir:    Pointer to "struct path".
 * @old_dentry: Pointer to "struct dentry".
 * @new_dir:    Pointer to "struct path".
 * @new_dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_rename(struct path *old_dir, struct dentry *old_dentry,
			  struct path *new_dir, struct dentry *new_dentry)
{
	struct path old = { .mnt = old_dir->mnt, .dentry = old_dentry };
	struct path new = { .mnt = new_dir->mnt, .dentry = new_dentry };
	int rc = cs_rename_permission(&old, &new);

	if (rc)
		return rc;
	wait_ready(path_rename);
	return original_security_ops.path_rename(old_dir, old_dentry, new_dir,
						 new_dentry);
}

/**
 * cs_path_link - Check permission for link().
 *
 * @old_dentry: Pointer to "struct dentry".
 * @new_dir:    Pointer to "struct path".
 * @new_dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_link(struct dentry *old_dentry, struct path *new_dir,
			struct dentry *new_dentry)
{
	struct path old = { .mnt = new_dir->mnt, .dentry = old_dentry };
	struct path new = { .mnt = new_dir->mnt, .dentry = new_dentry };
	int rc = cs_link_permission(&old, &new);

	if (rc)
		return rc;
	wait_ready(path_link);
	return original_security_ops.path_link(old_dentry, new_dir,
					       new_dentry);
}

#else

#if defined(USE_UMODE_T)

/**
 * cs_inode_mknod - Check permission for mknod().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 * @dev:    Device major/minor number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_mknod(struct inode *dir, struct dentry *dentry,
			  umode_t mode, dev_t dev)
{
	struct path path = { .mnt = NULL, .dentry = dentry };
	int rc = cs_mknod_permission(&path, mode, dev);

	if (rc)
		return rc;
	wait_ready(inode_mknod);
	return original_security_ops.inode_mknod(dir, dentry, mode, dev);
}

/**
 * cs_inode_mkdir - Check permission for mkdir().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_mkdir(struct inode *dir, struct dentry *dentry,
			  umode_t mode)
{
	struct path path = { .mnt = NULL, .dentry = dentry };
	int rc = cs_mkdir_permission(&path, mode);

	if (rc)
		return rc;
	wait_ready(inode_mkdir);
	return original_security_ops.inode_mkdir(dir, dentry, mode);
}

#else

/**
 * cs_inode_mknod - Check permission for mknod().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 * @dev:    Device major/minor number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_mknod(struct inode *dir, struct dentry *dentry, int mode,
			  dev_t dev)
{
	struct path path = { .mnt = NULL, .dentry = dentry };
	int rc = cs_mknod_permission(&path, mode, dev);

	if (rc)
		return rc;
	wait_ready(inode_mknod);
	return original_security_ops.inode_mknod(dir, dentry, mode, dev);
}

/**
 * cs_inode_mkdir - Check permission for mkdir().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	struct path path = { .mnt = NULL, .dentry = dentry };
	int rc = cs_mkdir_permission(&path, mode);

	if (rc)
		return rc;
	wait_ready(inode_mkdir);
	return original_security_ops.inode_mkdir(dir, dentry, mode);
}

#endif

/**
 * cs_inode_rmdir - Check permission for rmdir().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct path path = { .mnt = NULL, .dentry = dentry };
	int rc = cs_rmdir_permission(&path);

	if (rc)
		return rc;
	wait_ready(inode_rmdir);
	return original_security_ops.inode_rmdir(dir, dentry);
}

/**
 * cs_inode_unlink - Check permission for unlink().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	struct path path = { .mnt = NULL, .dentry = dentry };
	int rc = cs_unlink_permission(&path);

	if (rc)
		return rc;
	wait_ready(inode_unlink);
	return original_security_ops.inode_unlink(dir, dentry);
}

/**
 * cs_inode_symlink - Check permission for symlink().
 *
 * @dir:      Pointer to "struct inode".
 * @dentry:   Pointer to "struct dentry".
 * @old_name: Content of symbolic link.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_symlink(struct inode *dir, struct dentry *dentry,
			    const char *old_name)
{
	struct path path = { .mnt = NULL, .dentry = dentry };
	int rc = cs_symlink_permission(&path, old_name);

	if (rc)
		return rc;
	wait_ready(inode_symlink);
	return original_security_ops.inode_symlink(dir, dentry, old_name);
}

/**
 * cs_inode_rename - Check permission for rename().
 *
 * @old_dir:    Pointer to "struct inode".
 * @old_dentry: Pointer to "struct dentry".
 * @new_dir:    Pointer to "struct inode".
 * @new_dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			   struct inode *new_dir, struct dentry *new_dentry)
{
	struct path old = { .mnt = NULL, .dentry = old_dentry };
	struct path new = { .mnt = NULL, .dentry = new_dentry };
	int rc = cs_rename_permission(&old, &new);

	if (rc)
		return rc;
	wait_ready(inode_rename);
	return original_security_ops.inode_rename(old_dir, old_dentry, new_dir,
						  new_dentry);
}

/**
 * cs_inode_link - Check permission for link().
 *
 * @old_dentry: Pointer to "struct dentry".
 * @dir:        Pointer to "struct inode".
 * @new_dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_link(struct dentry *old_dentry, struct inode *dir,
			 struct dentry *new_dentry)
{
	struct path old = { .mnt = NULL, .dentry = old_dentry };
	struct path new = { .mnt = NULL, .dentry = new_dentry };
	int rc = cs_link_permission(&old, &new);

	if (rc)
		return rc;
	wait_ready(inode_link);
	return original_security_ops.inode_link(old_dentry, dir, new_dentry);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)

/**
 * cs_inode_create - Check permission for creat().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_create(struct inode *dir, struct dentry *dentry,
			   umode_t mode)
{
	struct path path = { .mnt = NULL, .dentry = dentry };
	int rc = cs_mknod_permission(&path, mode, 0);

	if (rc)
		return rc;
	wait_ready(inode_create);
	return original_security_ops.inode_create(dir, dentry, mode);
}

#else

/**
 * cs_inode_create - Check permission for creat().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_create(struct inode *dir, struct dentry *dentry,
			   int mode)
{
	struct path path = { .mnt = NULL, .dentry = dentry };
	int rc = cs_mknod_permission(&path, mode, 0);

	if (rc)
		return rc;
	wait_ready(inode_create);
	return original_security_ops.inode_create(dir, dentry, mode);
}

#endif

#endif

#ifdef CONFIG_SECURITY_NETWORK

#include <net/sock.h>

/* Structure for remembering an accept()ed socket's status. */
struct cs_socket_tag {
	struct list_head list;
	struct inode *inode;
	int status;
	struct rcu_head rcu;
};

/*
 * List for managing accept()ed sockets.
 * Since we don't need to keep an accept()ed socket into this list after
 * once the permission was granted, the number of entries in this list is
 * likely small. Therefore, we don't use hash tables.
 */
static LIST_HEAD(cs_accepted_socket_list);
/* Lock for protecting cs_accepted_socket_list . */
static DEFINE_SPINLOCK(cs_accepted_socket_list_lock);

/**
 * cs_socket_rcu_free - RCU callback for releasing "struct cs_socket_tag".
 *
 * @rcu: Pointer to "struct rcu_head".
 *
 * Returns nothing.
 */
static void cs_socket_rcu_free(struct rcu_head *rcu)
{
	struct cs_socket_tag *ptr = container_of(rcu, typeof(*ptr), rcu);

	kfree(ptr);
}

/**
 * cs_update_socket_tag - Update tag associated with accept()ed sockets.
 *
 * @inode:  Pointer to "struct inode".
 * @status: New status.
 *
 * Returns nothing.
 *
 * If @status == 0, memory for that socket will be released after RCU grace
 * period.
 */
static void cs_update_socket_tag(struct inode *inode, int status)
{
	struct cs_socket_tag *ptr;
	/*
	 * Protect whole section because multiple threads may call this
	 * function with same "sock" via cs_validate_socket().
	 */
	spin_lock(&cs_accepted_socket_list_lock);
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, &cs_accepted_socket_list, list) {
		if (ptr->inode != inode)
			continue;
		ptr->status = status;
		if (status)
			break;
		list_del_rcu(&ptr->list);
		call_rcu(&ptr->rcu, cs_socket_rcu_free);
		break;
	}
	rcu_read_unlock();
	spin_unlock(&cs_accepted_socket_list_lock);
}

/**
 * cs_validate_socket - Check post accept() permission if needed.
 *
 * @sock: Pointer to "struct socket".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_validate_socket(struct socket *sock)
{
	struct inode *inode = SOCK_INODE(sock);
	struct cs_socket_tag *ptr;
	int ret = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(ptr, &cs_accepted_socket_list, list) {
		if (ptr->inode != inode)
			continue;
		ret = ptr->status;
		break;
	}
	rcu_read_unlock();
	if (ret <= 0)
		/*
		 * This socket is not an accept()ed socket or this socket is
		 * an accept()ed socket and post accept() permission is done.
		 */
		return ret;
	/*
	 * Check post accept() permission now.
	 *
	 * Strictly speaking, we need to pass both listen()ing socket and
	 * accept()ed socket to __cs_socket_post_accept_permission().
	 * But since socket's family and type are same for both sockets,
	 * passing the accept()ed socket in place for the listen()ing socket
	 * will work.
	 */
	ret = cs_socket_post_accept_permission(sock, sock);
	/*
	 * If permission was granted, we forget that this is an accept()ed
	 * socket. Otherwise, we remember that this socket needs to return
	 * error for subsequent socketcalls.
	 */
	cs_update_socket_tag(inode, ret);
	return ret;
}

/**
 * cs_socket_accept - Check permission for accept().
 *
 * @sock:    Pointer to "struct socket".
 * @newsock: Pointer to "struct socket".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * This hook is used for setting up environment for doing post accept()
 * permission check. If dereferencing sock->ops->something() were ordered by
 * rcu_dereference(), we could replace sock->ops with "a copy of original
 * sock->ops with modified sock->ops->accept()" using rcu_assign_pointer()
 * in order to do post accept() permission check before returning to userspace.
 * If we make the copy in security_socket_post_create(), it would be possible
 * to safely replace sock->ops here, but we don't do so because we don't want
 * to allocate memory for sockets which do not call sock->ops->accept().
 * Therefore, we do post accept() permission check upon next socket syscalls
 * rather than between sock->ops->accept() and returning to userspace.
 * This means that if a socket was close()d before calling some socket
 * syscalls, post accept() permission check will not be done.
 */
static int cs_socket_accept(struct socket *sock, struct socket *newsock)
{
	struct cs_socket_tag *ptr;
	int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;
	wait_ready(socket_accept);
	rc = original_security_ops.socket_accept(sock, newsock);
	if (rc) {
		kfree(ptr);
		return rc;
	}
	/*
	 * Subsequent LSM hooks will receive "newsock". Therefore, I mark
	 * "newsock" as "an accept()ed socket but post accept() permission
	 * check is not done yet" by allocating memory using inode of the
	 * "newsock" as a search key.
	 */
	ptr->inode = SOCK_INODE(newsock);
	ptr->status = 1; /* Check post accept() permission later. */
	spin_lock(&cs_accepted_socket_list_lock);
	list_add_tail_rcu(&ptr->list, &cs_accepted_socket_list);
	spin_unlock(&cs_accepted_socket_list_lock);
	return 0;
}

/**
 * cs_socket_listen - Check permission for listen().
 *
 * @sock:    Pointer to "struct socket".
 * @backlog: Backlog parameter.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_socket_listen(struct socket *sock, int backlog)
{
	int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	rc = cs_socket_listen_permission(sock);
	if (rc)
		return rc;
	wait_ready(socket_listen);
	return original_security_ops.socket_listen(sock, backlog);
}

/**
 * cs_socket_connect - Check permission for connect().
 *
 * @sock:     Pointer to "struct socket".
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_socket_connect(struct socket *sock, struct sockaddr *addr,
			     int addr_len)
{
	int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	rc = cs_socket_connect_permission(sock, addr, addr_len);
	if (rc)
		return rc;
	wait_ready(socket_connect);
	return original_security_ops.socket_connect(sock, addr, addr_len);
}

/**
 * cs_socket_bind - Check permission for bind().
 *
 * @sock:     Pointer to "struct socket".
 * @addr:     Pointer to "struct sockaddr".
 * @addr_len: Size of @addr.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_socket_bind(struct socket *sock, struct sockaddr *addr,
			  int addr_len)
{
	int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	rc = cs_socket_bind_permission(sock, addr, addr_len);
	if (rc)
		return rc;
	wait_ready(socket_bind);
	return original_security_ops.socket_bind(sock, addr, addr_len);
}

/**
 * cs_socket_sendmsg - Check permission for sendmsg().
 *
 * @sock: Pointer to "struct socket".
 * @msg:  Pointer to "struct msghdr".
 * @size: Size of message.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_socket_sendmsg(struct socket *sock, struct msghdr *msg,
			     int size)
{
	int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	rc = cs_socket_sendmsg_permission(sock, msg, size);
	if (rc)
		return rc;
	wait_ready(socket_sendmsg);
	return original_security_ops.socket_sendmsg(sock, msg, size);
}

/**
 * cs_socket_recvmsg - Check permission for recvmsg().
 *
 * @sock:  Pointer to "struct socket".
 * @msg:   Pointer to "struct msghdr".
 * @size:  Size of message.
 * @flags: Flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_socket_recvmsg(struct socket *sock, struct msghdr *msg,
			     int size, int flags)
{
	int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	wait_ready(socket_recvmsg);
	return original_security_ops.socket_recvmsg(sock, msg, size, flags);
}

/**
 * cs_socket_getsockname - Check permission for getsockname().
 *
 * @sock: Pointer to "struct socket".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_socket_getsockname(struct socket *sock)
{
	int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	wait_ready(socket_getsockname);
	return original_security_ops.socket_getsockname(sock);
}

/**
 * cs_socket_getpeername - Check permission for getpeername().
 *
 * @sock: Pointer to "struct socket".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_socket_getpeername(struct socket *sock)
{
	int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	wait_ready(socket_getpeername);
	return original_security_ops.socket_getpeername(sock);
}

/**
 * cs_socket_getsockopt - Check permission for getsockopt().
 *
 * @sock:    Pointer to "struct socket".
 * @level:   Level.
 * @optname: Option's name,
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_socket_getsockopt(struct socket *sock, int level, int optname)
{
	int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	wait_ready(socket_getsockopt);
	return original_security_ops.socket_getsockopt(sock, level, optname);
}

/**
 * cs_socket_setsockopt - Check permission for setsockopt().
 *
 * @sock:    Pointer to "struct socket".
 * @level:   Level.
 * @optname: Option's name,
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_socket_setsockopt(struct socket *sock, int level, int optname)
{
	int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	wait_ready(socket_setsockopt);
	return original_security_ops.socket_setsockopt(sock, level, optname);
}

/**
 * cs_socket_shutdown - Check permission for shutdown().
 *
 * @sock: Pointer to "struct socket".
 * @how:  Shutdown mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_socket_shutdown(struct socket *sock, int how)
{
	int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	wait_ready(socket_shutdown);
	return original_security_ops.socket_shutdown(sock, how);
}

#define SOCKFS_MAGIC 0x534F434B

/**
 * cs_inode_free_security - Release memory associated with an inode.
 *
 * @inode: Pointer to "struct inode".
 *
 * Returns nothing.
 *
 * We use this hook for releasing memory associated with an accept()ed socket.
 */
static void cs_inode_free_security(struct inode *inode)
{
	wait_ready(inode_free_security);
	original_security_ops.inode_free_security(inode);
	if (inode->i_sb && inode->i_sb->s_magic == SOCKFS_MAGIC)
		cs_update_socket_tag(inode, 0);
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)

/**
 * cs_sb_pivotroot - Check permission for pivot_root().
 *
 * @old_path: Pointer to "struct path".
 * @new_path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	int rc = cs_pivot_root_permission(old_path, new_path);

	if (rc)
		return rc;
	wait_ready(sb_pivotroot);
	return original_security_ops.sb_pivotroot(old_path, new_path);
}

/**
 * cs_sb_mount - Check permission for mount().
 *
 * @dev_name:  Name of device file.
 * @path:      Pointer to "struct path".
 * @type:      Name of filesystem type. Maybe NULL.
 * @flags:     Mount options.
 * @data_page: Optional data. Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_sb_mount(char *dev_name, struct path *path, char *type,
		       unsigned long flags, void *data_page)
{
	int rc = cs_mount_permission(dev_name, path, type, flags, data_page);

	if (rc)
		return rc;
	wait_ready(sb_mount);
	return original_security_ops.sb_mount(dev_name, path, type, flags,
					      data_page);
}

#else

/**
 * cs_sb_pivotroot - Check permission for pivot_root().
 *
 * @old_path: Pointer to "struct path".
 * @new_path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	int rc = cs_pivot_root_permission(old_path, new_path);

	if (rc)
		return rc;
	wait_ready(sb_pivotroot);
	return original_security_ops.sb_pivotroot(old_path, new_path);
}

/**
 * cs_sb_mount - Check permission for mount().
 *
 * @dev_name:  Name of device file.
 * @path:      Pointer to "struct path".
 * @type:      Name of filesystem type. Maybe NULL.
 * @flags:     Mount options.
 * @data_page: Optional data. Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_sb_mount(const char *dev_name, struct path *path,
		       const char *type, unsigned long flags, void *data_page)
{
	int rc = cs_mount_permission(dev_name, path, type, flags, data_page);

	if (rc)
		return rc;
	wait_ready(sb_mount);
	return original_security_ops.sb_mount(dev_name, path, type, flags,
					      data_page);
}

#endif

/**
 * cs_sb_umount - Check permission for umount().
 *
 * @mnt:   Pointer to "struct vfsmount".
 * @flags: Unmount flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_sb_umount(struct vfsmount *mnt, int flags)
{
	struct path path = { .mnt = mnt, .dentry = mnt->mnt_root };
	int rc = cs_umount_permission(&path, flags);

	if (rc)
		return rc;
	wait_ready(sb_umount);
	return original_security_ops.sb_umount(mnt, flags);
}

/**
 * cs_file_fcntl - Check permission for fcntl().
 *
 * @file: Pointer to "struct file".
 * @cmd:  Command number.
 * @arg:  Value for @cmd.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_file_fcntl(struct file *file, unsigned int cmd,
			 unsigned long arg)
{
	int rc = cs_fcntl_permission(file, cmd, arg);

	if (rc)
		return rc;
	wait_ready(file_fcntl);
	return original_security_ops.file_fcntl(file, cmd, arg);
}

/**
 * cs_file_ioctl - Check permission for ioctl().
 *
 * @filp: Pointer to "struct file".
 * @cmd:  Command number.
 * @arg:  Value for @cmd.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_file_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long arg)
{
	int rc = cs_ioctl_permission(filp, cmd, arg);

	if (rc)
		return rc;
	wait_ready(file_ioctl);
	return original_security_ops.file_ioctl(filp, cmd, arg);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33) && defined(CONFIG_SYSCTL_SYSCALL)

/**
 * cs_prepend - Copy of prepend() in fs/dcache.c.
 *
 * @buffer: Pointer to "struct char *".
 * @buflen: Pointer to int which holds size of @buffer.
 * @str:    String to copy.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * @buffer and @buflen are updated upon success.
 */
static int cs_prepend(char **buffer, int *buflen, const char *str)
{
	int namelen = strlen(str);

	if (*buflen < namelen)
		return -ENOMEM;
	*buflen -= namelen;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

/**
 * cs_sysctl_permission - Check permission for sysctl().
 *
 * @table: Pointer to "struct ctl_table".
 * @op:    Operation. (MAY_READ and/or MAY_WRITE)
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_sysctl(struct ctl_table *table, int op)
{
	int error;
	struct cs_path_info buf;
	int buflen;
	char *buffer;

	wait_ready(sysctl);
	error = original_security_ops.sysctl(table, op);
	if (error)
		return error;
	op &= MAY_READ | MAY_WRITE;
	if (!op)
		return 0;
	buffer = NULL;
	buf.name = NULL;
	error = -ENOMEM;
	buflen = 4096;
	buffer = kmalloc(buflen, GFP_NOFS);
	if (buffer) {
		char *end = buffer + buflen;
		*--end = '\0';
		buflen--;
		while (table) {
			char num[32];
			const char *sp = table->procname;

			if (!sp) {
				memset(num, 0, sizeof(num));
				snprintf(num, sizeof(num) - 1, "=%d=",
					 table->ctl_name);
				sp = num;
			}
			if (cs_prepend(&end, &buflen, sp) ||
			    cs_prepend(&end, &buflen, "/"))
				goto out;
			table = table->parent;
		}
		if (cs_prepend(&end, &buflen, "proc:/sys"))
			goto out;
		buf.name = cs_encode(end);
	}
	if (buf.name) {
		cs_fill_path_info(&buf);
		if (op & MAY_READ)
			error = cs_sysctl_permission(CS_MAC_READ, &buf);
		else
			error = 0;
		if (!error && (op & MAY_WRITE))
			error = cs_sysctl_permission(CS_MAC_WRITE, &buf);
	}
out:
	kfree(buf.name);
	kfree(buffer);
	return error;
}

#endif

/*
 * Why not to copy all operations by "original_security_ops = *ops" ?
 * Because copying byte array is not atomic. Reader checks
 * original_security_ops.op != NULL before doing original_security_ops.op().
 * Thus, modifying original_security_ops.op has to be atomic.
 */
#define swap_security_ops(op)						\
	original_security_ops.op = ops->op; smp_wmb(); ops->op = cs_##op

/**
 * cs_update_security_ops - Overwrite original "struct security_operations".
 *
 * @ops: Pointer to "struct security_operations".
 *
 * Returns nothing.
 */
static void __init cs_update_security_ops(struct security_operations *ops)
{
	/* Security context allocator. */
	swap_security_ops(task_create);
	swap_security_ops(cred_prepare);
	swap_security_ops(cred_free);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	swap_security_ops(cred_alloc_blank);
	swap_security_ops(cred_transfer);
#endif
	/* Security context updater for successful execve(). */
	swap_security_ops(bprm_check_security);
	swap_security_ops(bprm_committing_creds);
	/* Various permission checker. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	swap_security_ops(file_open);
#else
	swap_security_ops(dentry_open);
#endif
	swap_security_ops(file_fcntl);
	swap_security_ops(file_ioctl);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33) && defined(CONFIG_SYSCTL_SYSCALL)
	swap_security_ops(sysctl);
#endif
	swap_security_ops(sb_pivotroot);
	swap_security_ops(sb_mount);
	swap_security_ops(sb_umount);
#if defined(CONFIG_SECURITY_PATH)
	swap_security_ops(path_mknod);
	swap_security_ops(path_mkdir);
	swap_security_ops(path_rmdir);
	swap_security_ops(path_unlink);
	swap_security_ops(path_symlink);
	swap_security_ops(path_rename);
	swap_security_ops(path_link);
	swap_security_ops(path_truncate);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	swap_security_ops(path_chmod);
	swap_security_ops(path_chown);
	swap_security_ops(path_chroot);
#endif
#else
	swap_security_ops(inode_mknod);
	swap_security_ops(inode_mkdir);
	swap_security_ops(inode_rmdir);
	swap_security_ops(inode_unlink);
	swap_security_ops(inode_symlink);
	swap_security_ops(inode_rename);
	swap_security_ops(inode_link);
	swap_security_ops(inode_create);
#endif
	swap_security_ops(inode_setattr);
	swap_security_ops(inode_getattr);
#ifdef CONFIG_SECURITY_NETWORK
	swap_security_ops(inode_free_security);
	swap_security_ops(socket_bind);
	swap_security_ops(socket_connect);
	swap_security_ops(socket_listen);
	swap_security_ops(socket_sendmsg);
	swap_security_ops(socket_recvmsg);
	swap_security_ops(socket_getsockname);
	swap_security_ops(socket_getpeername);
	swap_security_ops(socket_getsockopt);
	swap_security_ops(socket_setsockopt);
	swap_security_ops(socket_shutdown);
	swap_security_ops(socket_accept);
#endif
}

#undef swap_security_ops

/**
 * cs_init - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __init cs_init(void)
{
	struct security_operations *ops = probe_security_ops();

	if (!ops)
		goto out;
	caitsith_exports.find_task_by_vpid = probe_find_task_by_vpid();
	if (!caitsith_exports.find_task_by_vpid)
		goto out;
	caitsith_exports.find_task_by_pid_ns = probe_find_task_by_pid_ns();
	if (!caitsith_exports.find_task_by_pid_ns)
		goto out;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	caitsith_exports.vfsmount_lock = probe_vfsmount_lock();
	if (!caitsith_exports.vfsmount_lock)
		goto out;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
	caitsith_exports.__d_path = probe___d_path();
	if (!caitsith_exports.__d_path)
		goto out;
#else
	caitsith_exports.d_absolute_path = probe_d_absolute_path();
	if (!caitsith_exports.d_absolute_path)
		goto out;
#endif
	{
		int idx;

		for (idx = 0; idx < CS_MAX_TASK_SECURITY_HASH; idx++) {
			INIT_LIST_HEAD(&cs_cred_security_list[idx]);
			INIT_LIST_HEAD(&cs_task_security_list[idx]);
		}
	}
	cs_init_module();
	cs_update_security_ops(ops);
	return 0;
out:
	return -EINVAL;
}

module_init(cs_init);
MODULE_LICENSE("GPL");

/**
 * cs_used_by_cred - Check whether the given domain is in use or not.
 *
 * @domain: Pointer to "struct cs_domain_info".
 *
 * Returns true if @domain is in use, false otherwise.
 *
 * Caller holds rcu_read_lock().
 */
bool cs_used_by_cred(const struct cs_domain_info *domain)
{
	int idx;
	struct cs_security *ptr;

	for (idx = 0; idx < CS_MAX_TASK_SECURITY_HASH; idx++) {
		struct list_head *list = &cs_cred_security_list[idx];

		list_for_each_entry_rcu(ptr, list, list) {
			struct cs_request_info *r = ptr->r;

			if (ptr->cs_domain_info == domain ||
			    (r && r->previous_domain == domain)) {
				return true;
			}
		}
	}
	return false;
}

/**
 * cs_add_task_security - Add "struct cs_security" to list.
 *
 * @ptr:  Pointer to "struct cs_security".
 * @list: Pointer to "struct list_head".
 *
 * Returns nothing.
 */
static void cs_add_task_security(struct cs_security *ptr,
				 struct list_head *list)
{
	unsigned long flags;

	spin_lock_irqsave(&cs_task_security_list_lock, flags);
	list_add_rcu(&ptr->list, list);
	spin_unlock_irqrestore(&cs_task_security_list_lock, flags);
}

/**
 * cs_find_task_security - Find "struct cs_security" for given task.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns pointer to "struct cs_security" on success, &cs_oom_security on
 * out of memory, &cs_default_security otherwise.
 *
 * If @task is current thread and "struct cs_security" for current thread was
 * not found, I try to allocate it. But if allocation failed, current thread
 * will be killed by SIGKILL. Note that if current->pid == 1, sending SIGKILL
 * won't work.
 */
struct cs_security *cs_find_task_security(const struct task_struct *task)
{
	struct cs_security *ptr;
	struct list_head *list = &cs_task_security_list
		[hash_ptr((void *) task, CS_TASK_SECURITY_HASH_BITS)];
	/* Make sure INIT_LIST_HEAD() in cs_mm_init() takes effect. */
	while (!list->next)
		smp_rmb();
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, list, list) {
		if (ptr->pid != task->pids[PIDTYPE_PID].pid)
			continue;
		rcu_read_unlock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
		/*
		 * Current thread needs to transit from old domain to new
		 * domain before do_execve() succeeds in order to check
		 * permission for interpreters and environment variables using
		 * new domain's ACL rules. The domain transition has to be
		 * visible from other CPU in order to allow interactive
		 * enforcing mode. Also, the domain transition has to be
		 * reverted if do_execve() failed. However, an LSM hook for
		 * reverting domain transition is missing.
		 *
		 * security_prepare_creds() is called from prepare_creds() from
		 * prepare_bprm_creds() from do_execve() before setting
		 * current->in_execve flag, and current->in_execve flag is
		 * cleared by the time next do_execve() request starts.
		 * This means that we can emulate the missing LSM hook for
		 * reverting domain transition, by calling this function from
		 * security_prepare_creds().
		 *
		 * If current->in_execve is not set but ptr->cs_flags has
		 * CS_TASK_IS_IN_EXECVE set, it indicates that do_execve()
		 * has failed and reverting domain transition is needed.
		 */
		if (task == current &&
		    (ptr->cs_flags & CS_TASK_IS_IN_EXECVE) &&
		    !current->in_execve) {
			cs_debug_trace("4");
			cs_clear_execve(-1, ptr);
		}
#else
		/*
		 * Current thread needs to transit from old domain to new
		 * domain before do_execve() succeeds in order to check
		 * permission for interpreters and environment variables using
		 * new domain's ACL rules. The domain transition has to be
		 * visible from other CPU in order to allow interactive
		 * enforcing mode. Also, the domain transition has to be
		 * reverted if do_execve() failed. However, an LSM hook for
		 * reverting domain transition is missing.
		 *
		 * When do_execve() failed, "struct cred" in
		 * "struct linux_binprm" is scheduled for destruction.
		 * But current thread returns to userspace without waiting for
		 * destruction. The security_cred_free() LSM hook is called
		 * after an RCU grace period has elapsed. Since some CPU may be
		 * doing long long RCU read side critical section, there is
		 * no guarantee that security_cred_free() is called before
		 * current thread again calls do_execve().
		 *
		 * To be able to revert domain transition before processing
		 * next do_execve() request, current thread gets a refcount on
		 * "struct cred" in "struct linux_binprm" and memorizes it.
		 * Current thread drops the refcount and forgets it when
		 * do_execve() succeeded.
		 *
		 * Therefore, if current thread hasn't forgotten it and
		 * current thread is the last one using that "struct cred",
		 * it indicates that do_execve() has failed and reverting
		 * domain transition is needed.
		 */
		if (task == current && ptr->cred &&
		    atomic_read(&ptr->cred->usage) == 1) {
			cs_debug_trace("4");
			cs_clear_execve(-1, ptr);
		}
#endif
		return ptr;
	}
	rcu_read_unlock();
	if (task != current) {
		/*
		 * If a thread does nothing after fork(), caller will reach
		 * here because "struct cs_security" for that thread is not
		 * yet allocated. But that thread is keeping a snapshot of
		 * "struct cs_security" taken as of cs_task_create()
		 * associated with that thread's "struct cred".
		 *
		 * Since that snapshot will be used as initial data when that
		 * thread allocates "struct cs_security" for that thread, we
		 * can return that snapshot rather than &cs_default_security.
		 *
		 * Since this function is called by only cs_select_one() and
		 * cs_read_pid() (via cs_task_domain() and cs_task_flags()),
		 * it is guaranteed that caller has called rcu_read_lock()
		 * (via cs_tasklist_lock()) before finding this thread and
		 * this thread is valid. Therefore, we can do __task_cred(task)
		 * like get_robust_list() does.
		 */
		return cs_find_cred_security(__task_cred(task));
	}
	/* Use GFP_ATOMIC because caller may have called rcu_read_lock(). */
	ptr = kzalloc(sizeof(*ptr), GFP_ATOMIC);
	if (!ptr) {
		printk(KERN_WARNING "Unable to allocate memory for pid=%u\n",
		       task->pid);
		send_sig(SIGKILL, current, 0);
		return &cs_oom_security;
	}
	*ptr = *cs_find_cred_security(task->cred);
	/* We can shortcut because task == current. */
	ptr->pid = get_pid(((struct task_struct *) task)->
			   pids[PIDTYPE_PID].pid);
	ptr->cred = NULL;
	cs_add_task_security(ptr, list);
	return ptr;
}

/**
 * cs_copy_cred_security - Allocate memory for new credentials.
 *
 * @new: Pointer to "struct cred".
 * @old: Pointer to "struct cred".
 * @gfp: Memory allocation flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_copy_cred_security(const struct cred *new,
				 const struct cred *old, gfp_t gfp)
{
	struct cs_security *old_security = cs_find_cred_security(old);
	struct cs_security *new_security =
		kzalloc(sizeof(*new_security), gfp);
	if (!new_security)
		return -ENOMEM;
	*new_security = *old_security;
	new_security->cred = new;
	cs_add_cred_security(new_security);
	return 0;
}

/**
 * cs_find_cred_security - Find "struct cs_security" for given credential.
 *
 * @cred: Pointer to "struct cred".
 *
 * Returns pointer to "struct cs_security" on success, &cs_default_security
 * otherwise.
 */
static struct cs_security *cs_find_cred_security(const struct cred *cred)
{
	struct cs_security *ptr;
	struct list_head *list = &cs_cred_security_list
		[hash_ptr((void *) cred, CS_TASK_SECURITY_HASH_BITS)];
	rcu_read_lock();
	list_for_each_entry_rcu(ptr, list, list) {
		if (ptr->cred != cred)
			continue;
		rcu_read_unlock();
		return ptr;
	}
	rcu_read_unlock();
	return &cs_default_security;
}

/**
 * cs_task_security_gc - Do garbage collection for "struct task_struct".
 *
 * Returns nothing.
 *
 * Since security_task_free() is missing, I can't release memory associated
 * with "struct task_struct" when a task dies. Therefore, I hold a reference on
 * "struct pid" and runs garbage collection when associated
 * "struct task_struct" has gone.
 */
static void cs_task_security_gc(void)
{
	static DEFINE_SPINLOCK(lock);
	static atomic_t gc_counter = ATOMIC_INIT(0);
	unsigned int idx;
	/*
	 * If some process is doing execve(), try to garbage collection now.
	 * We should kfree() memory associated with "struct cs_security"->r
	 * as soon as execve() has completed in order to compensate for lack of
	 * security_bprm_free() and security_task_free() hooks.
	 *
	 * Otherwise, reduce frequency for performance reason.
	 */
	if (!atomic_read(&cs_in_execve_tasks) &&
	    atomic_inc_return(&gc_counter) < 1024)
		return;
	if (!spin_trylock(&lock))
		return;
	atomic_set(&gc_counter, 0);
	rcu_read_lock();
	for (idx = 0; idx < CS_MAX_TASK_SECURITY_HASH; idx++) {
		struct cs_security *ptr;
		struct list_head *list = &cs_task_security_list[idx];

		list_for_each_entry_rcu(ptr, list, list) {
			if (pid_task(ptr->pid, PIDTYPE_PID))
				continue;
			cs_del_security(ptr);
		}
	}
	rcu_read_unlock();
	spin_unlock(&lock);
}
