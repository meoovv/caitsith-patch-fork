/*
 * lsm.c
 *
 * Copyright (C) 2010-2013  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Version: 0.2.16   2026/09/28
 */

#include "caitsith.h"
#include "probe.h"

/* Prototype definition. */
struct cs_security *cs_find_task_security(const struct task_struct *task);
static int cs_alloc_task_security(const struct task_struct *task);
static void cs_free_task_security(const struct task_struct *task);
static void cs_add_task_security(struct cs_security *ptr,
				 struct list_head *list);
static void cs_rcu_free(struct rcu_head *rcu);

/* List of "struct cs_security" for "struct task_struct". */
struct list_head cs_task_security_list[CS_MAX_TASK_SECURITY_HASH];
/* Lock for protecting cs_task_security_list[]. */
static DEFINE_SPINLOCK(cs_task_security_list_lock);
/* Dummy marker for calling security_bprm_free(). */
static const unsigned long cs_bprm_security;

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
	cs_finish_execve(ret, r);
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
 * cs_alloc_task_security - Allocate memory for new tasks.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_alloc_task_security(const struct task_struct *task)
{
	struct cs_security *old_security = cs_current_security();
	struct cs_security *new_security = kzalloc(sizeof(*new_security),
						   GFP_KERNEL);
	struct list_head *list = &cs_task_security_list
		[hash_ptr((void *) task, CS_TASK_SECURITY_HASH_BITS)];
	if (!new_security)
		return -ENOMEM;
	new_security->task = task;
	new_security->cs_domain_info = old_security->cs_domain_info;
	new_security->cs_flags = old_security->cs_flags;
	cs_add_task_security(new_security, list);
	return 0;
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
		if (ptr->task != task)
			continue;
		rcu_read_unlock();
		return ptr;
	}
	rcu_read_unlock();
	if (task != current)
		return &cs_default_security;
	/* Use GFP_ATOMIC because caller may have called rcu_read_lock(). */
	ptr = kzalloc(sizeof(*ptr), GFP_ATOMIC);
	if (!ptr) {
		printk(KERN_WARNING "Unable to allocate memory for pid=%u\n",
		       task->pid);
		send_sig(SIGKILL, current, 0);
		return &cs_oom_security;
	}
	*ptr = cs_default_security;
	ptr->task = task;
	cs_add_task_security(ptr, list);
	return ptr;
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

	kfree(ptr);
}

/**
 * cs_free_task_security - Release memory associated with "struct task_struct".
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns nothing.
 */
static void cs_free_task_security(const struct task_struct *task)
{
	unsigned long flags;
	struct cs_security *ptr = cs_find_task_security(task);

	if (ptr == &cs_default_security || ptr == &cs_oom_security)
		return;
	spin_lock_irqsave(&cs_task_security_list_lock, flags);
	list_del_rcu(&ptr->list);
	spin_unlock_irqrestore(&cs_task_security_list_lock, flags);
	call_rcu(&ptr->rcu, cs_rcu_free);
}

/**
 * cs_task_alloc_security - Allocate memory for new tasks.
 *
 * @p: Pointer to "struct task_struct".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_task_alloc_security(struct task_struct *p)
{
	int rc = cs_alloc_task_security(p);

	if (rc)
		return rc;
	wait_ready(task_alloc_security);
	rc = original_security_ops.task_alloc_security(p);
	if (rc)
		cs_free_task_security(p);
	return rc;
}

/**
 * cs_task_free_security - Release memory for "struct task_struct".
 *
 * @p: Pointer to "struct task_struct".
 *
 * Returns nothing.
 */
static void cs_task_free_security(struct task_struct *p)
{
	wait_ready(task_free_security);
	original_security_ops.task_free_security(p);
	cs_free_task_security(p);
}

/**
 * cs_bprm_alloc_security - Allocate memory for "struct linux_binprm".
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_bprm_alloc_security(struct linux_binprm *bprm)
{
	int rc;

	wait_ready(bprm_alloc_security);
	rc = original_security_ops.bprm_alloc_security(bprm);
	if (bprm->security || rc)
		return rc;
	/*
	 * Update bprm->security to &cs_bprm_security so that
	 * security_bprm_free() is called even if do_execve() failed at
	 * search_binary_handler() without allocating memory at
	 * security_bprm_alloc(). This trick assumes that active LSM module
	 * does not access bprm->security if that module did not allocate
	 * memory at security_bprm_alloc().
	 */
	bprm->security = (void *) &cs_bprm_security;
	return 0;
}

/**
 * cs_bprm_free_security - Release memory for "struct linux_binprm".
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns nothing.
 */
static void cs_bprm_free_security(struct linux_binprm *bprm)
{
	/*
	 * If do_execve() succeeded, bprm->security will be updated to NULL at
	 * security_bprm_compute_creds()/security_bprm_apply_creds() if
	 * bprm->security was set to &cs_bprm_security at
	 * security_bprm_alloc().
	 *
	 * If do_execve() failed, bprm->security remains at &cs_bprm_security
	 * if bprm->security was set to &cs_bprm_security at
	 * security_bprm_alloc().
	 *
	 * And do_execve() does not call security_bprm_free() if do_execve()
	 * failed and bprm->security == NULL. Therefore, do not call
	 * original_security_ops.bprm_free_security() if bprm->security remains
	 * at &cs_bprm_security .
	 */
	if (bprm->security != &cs_bprm_security) {
		wait_ready(bprm_free_security);
		original_security_ops.bprm_free_security(bprm);
	}
	/*
	 * If do_execve() succeeded,
	 * cs_clear_execve(0, cs_current_security());
	 * is called before calling below one.
	 * Thus, below call becomes no-op if do_execve() succeeded.
	 */
	cs_clear_execve(-1, cs_current_security());
}

/**
 * cs_bprm_apply_creds - A hook which is called when do_execve() succeeded.
 *
 * @bprm:   Pointer to "struct linux_binprm".
 * @unsafe: Unsafe flag.
 *
 * Returns nothing.
 */
static void cs_bprm_apply_creds(struct linux_binprm *bprm, int unsafe)
{
	if (bprm->security == &cs_bprm_security)
		bprm->security = NULL;
	wait_ready(bprm_apply_creds);
	original_security_ops.bprm_apply_creds(bprm, unsafe);
	cs_clear_execve(0, cs_current_security());
}

#ifndef CONFIG_CAITSITH_OMIT_USERSPACE_LOADER

/**
 * cs_policy_loader_exists - Check whether /sbin/caitsith-init exists.
 *
 * Returns true if /sbin/caitsith-init exists, false otherwise.
 */
static _Bool cs_policy_loader_exists(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
	struct path path;

	if (kern_path(CONFIG_CAITSITH_POLICY_LOADER, LOOKUP_FOLLOW, &path)
	    == 0) {
		path_put(&path);
		return 1;
	}
#else
	struct nameidata nd;

	if (path_lookup(CONFIG_CAITSITH_POLICY_LOADER, LOOKUP_FOLLOW, &nd)
	    == 0) {
		path_put(&nd.path);
		return 1;
	}
#endif
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
	return cs_open_permission(&f->f_path, f->f_flags + 1);
}

/**
 * cs_dentry_open - Check permission for open().
 *
 * @f: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_dentry_open(struct file *f)
{
	int rc = cs_open(f);

	if (rc)
		return rc;
	wait_ready(dentry_open);
	return original_security_ops.dentry_open(f);
}

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
	struct path path = { .mnt = NULL, .dentry = dentry };

	if (attr->ia_valid & ATTR_UID)
		rc = cs_chown_permission(&path, attr->ia_uid, -1);
	if (!rc && (attr->ia_valid & ATTR_GID))
		rc = cs_chown_permission(&path, -1, attr->ia_gid);
	if (!rc && (attr->ia_valid & ATTR_MODE))
		rc = cs_chmod_permission(&path, attr->ia_mode);
	if (!rc && (attr->ia_valid & ATTR_SIZE))
		rc = cs_truncate_permission(&path);
	if (rc)
		return rc;
	wait_ready(inode_setattr);
	return original_security_ops.inode_setattr(dentry, attr);
}

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

#if defined(CONFIG_SYSCTL_SYSCALL)

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
	swap_security_ops(task_alloc_security);
	swap_security_ops(task_free_security);
	swap_security_ops(bprm_alloc_security);
	swap_security_ops(bprm_free_security);
	/* Security context updater for successful execve(). */
	swap_security_ops(bprm_check_security);
	swap_security_ops(bprm_apply_creds);
	/* Various permission checker. */
	swap_security_ops(dentry_open);
	swap_security_ops(file_fcntl);
	swap_security_ops(file_ioctl);
#if defined(CONFIG_SYSCTL_SYSCALL)
	swap_security_ops(sysctl);
#endif
	swap_security_ops(sb_pivotroot);
	swap_security_ops(sb_mount);
	swap_security_ops(sb_umount);
	swap_security_ops(inode_mknod);
	swap_security_ops(inode_mkdir);
	swap_security_ops(inode_rmdir);
	swap_security_ops(inode_unlink);
	swap_security_ops(inode_symlink);
	swap_security_ops(inode_rename);
	swap_security_ops(inode_link);
	swap_security_ops(inode_create);
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
	caitsith_exports.vfsmount_lock = probe_vfsmount_lock();
	if (!caitsith_exports.vfsmount_lock)
		goto out;
	caitsith_exports.ksize = probe_ksize();
	if (!caitsith_exports.ksize)
		goto out;
	{
		int idx;

		for (idx = 0; idx < CS_MAX_TASK_SECURITY_HASH; idx++)
			INIT_LIST_HEAD(&cs_task_security_list[idx]);
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
	return false;
}
