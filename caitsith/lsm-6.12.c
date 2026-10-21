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
static int __cs_alloc_task_security(const struct task_struct *task);
static void __cs_free_task_security(const struct task_struct *task);

/* Dummy security context for avoiding NULL pointer dereference. */
static struct cs_security cs_oom_security = {
	.cs_domain_info = &cs_kernel_domain
};

/* Dummy security context for avoiding NULL pointer dereference. */
static struct cs_security cs_default_security = {
	.cs_domain_info = &cs_kernel_domain
};

/* List of "struct cs_security". */
struct list_head cs_task_security_list[CS_MAX_TASK_SECURITY_HASH];
/* Lock for protecting cs_task_security_list[]. */
static DEFINE_SPINLOCK(cs_task_security_list_lock);

/* For exporting variables and functions. */
struct caitsith_exports caitsith_exports;

#if !defined(CONFIG_CAITSITH_DEBUG)
#define cs_debug_trace(pos) do { } while (0)
#else
#define cs_debug_trace(pos)						\
	do {								\
		static bool done;					\
		if (!done) {						\
			printk(KERN_INFO				\
			       "CAITSITH: Debug trace: " pos " of 2\n"); \
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
	struct cs_request_info *r = security->r;

	if (security == &cs_default_security || security == &cs_oom_security ||
	    !r)
		return;
	security->r = NULL;
	cs_finish_execve(ret, r);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
/**
 * cs_task_alloc_security - Allocate memory for new tasks.
 *
 * @p: Pointer to "struct task_struct".
 * @clone_flags: Flags passed to clone().
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_task_alloc_security(struct task_struct *p, u64 clone_flags)
{
	return __cs_alloc_task_security(p);
}
#else
/**
 * cs_task_alloc_security - Allocate memory for new tasks.
 *
 * @p: Pointer to "struct task_struct".
 * @clone_flags: Flags passed to clone().
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_task_alloc_security(struct task_struct *p,
				  unsigned long clone_flags)
{
	return __cs_alloc_task_security(p);
}
#endif

/**
 * cs_task_free_security - Release memory for "struct task_struct".
 *
 * @p: Pointer to "struct task_struct".
 *
 * Returns nothing.
 */
static void cs_task_free_security(struct task_struct *p)
{
	struct cs_security *ptr = cs_find_task_security(p);
	struct cs_request_info *r = ptr->r;

	/*
	 * Since an LSM hook for reverting domain transition is missing,
	 * cs_finish_execve() is not called if exited immediately after
	 * execve() failed.
	 */
	if (r) {
		cs_debug_trace("2");
		kfree(r->handler_path);
		kfree(r);
		ptr->r = NULL;
	}
	__cs_free_task_security(p);
}

/**
 * __cs_free_task_security - Release memory associated with "struct task_struct".
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns nothing.
 */
static void __cs_free_task_security(const struct task_struct *task)
{
	unsigned long flags;
	struct cs_security *ptr = cs_find_task_security(task);

	if (ptr == &cs_default_security || ptr == &cs_oom_security)
		return;
	spin_lock_irqsave(&cs_task_security_list_lock, flags);
	list_del_rcu(&ptr->list);
	spin_unlock_irqrestore(&cs_task_security_list_lock, flags);
	kfree_rcu(ptr, rcu);
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
	/*
	 * For checking whether reverting domain transition is needed or not.
	 *
	 * See cs_find_task_security() for reason.
	 */
	if ((gfp & GFP_KERNEL) == GFP_KERNEL)
		cs_find_task_security(current);
	return 0;
}

/**
 * cs_bprm_committing_creds - A hook which is called when do_execve() succeeded.
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns nothing.
 */
static void cs_bprm_committing_creds(const struct linux_binprm *bprm)
{
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
	if (security->r)
		return 0;
#ifndef CONFIG_CAITSITH_OMIT_USERSPACE_LOADER
	if (!cs_policy_loaded)
		cs_load_policy(bprm->filename);
#endif
	return cs_start_execve(bprm, &security->r);
}

/**
 * cs_file_open - Check permission for open().
 *
 * @f:    Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_file_open(struct file *f)
{
	return cs_open_permission(&f->f_path, f->f_flags);
}

/**
 * cs_file_truncate - Check permission for truncate().
 *
 * @file: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_file_truncate(struct file *file)
{
	return cs_truncate_permission(&file->f_path);

}

#ifdef CONFIG_SECURITY_PATH

/**
 * cs_path_chown - Check permission for chown()/chgrp().
 *
 * @path:  Pointer to "struct path".
 * @user:  User ID.
 * @group: Group ID.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_chown(const struct path *path, kuid_t user, kgid_t group)
{
	return cs_chown_permission(path, user, group);
}

/**
 * cs_path_chmod - Check permission for chmod().
 *
 * @path: Pointer to "struct path".
 * @mode: Mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_chmod(const struct path *path, umode_t mode)
{
	return cs_chmod_permission(path, mode);
}

/**
 * cs_path_chroot - Check permission for chroot().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_chroot(const struct path *path)
{
	return cs_chroot_permission(path);
}

/**
 * cs_path_truncate - Check permission for truncate().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_truncate(const struct path *path)
{
	return cs_truncate_permission(path);
}

#else

/**
 * cs_inode_setattr - Check permission for chown()/chgrp()/chmod()/truncate().
 *
 * @mnt_idmap: Pointer to "struct mnt_idmap".
 * @dentry:    Pointer to "struct dentry".
 * @attr:      Pointer to "struct iattr".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_setattr(struct mnt_idmap *mnt_idmap, struct dentry *dentry, struct iattr *attr)
{
	int rc = 0;
	struct path path = { .mnt = NULL, .dentry = dentry };

	if (attr->ia_valid & ATTR_UID)
		rc = cs_chown_permission(&path, attr->ia_uid, INVALID_GID);
	if (!rc && (attr->ia_valid & ATTR_GID))
		rc = cs_chown_permission(&path, INVALID_UID, attr->ia_gid);
	if (!rc && (attr->ia_valid & ATTR_MODE))
		rc = cs_chmod_permission(&path, attr->ia_mode);
	if (!rc && (attr->ia_valid & ATTR_SIZE))
		rc = cs_truncate_permission(&path);
	return rc;
}

#endif

/**
 * cs_inode_getattr - Check permission for stat().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_inode_getattr(const struct path *path)
{
	return cs_getattr_permission(path);
}

#ifdef CONFIG_SECURITY_PATH

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
static int cs_path_mknod(const struct path *dir, struct dentry *dentry,
			 umode_t mode, unsigned int dev)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };

	return cs_mknod_permission(&path, mode, dev);
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
static int cs_path_mkdir(const struct path *dir, struct dentry *dentry,
			 umode_t mode)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };

	return cs_mkdir_permission(&path, mode);
}

/**
 * cs_path_rmdir - Check permission for rmdir().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_rmdir(const struct path *dir, struct dentry *dentry)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };

	return cs_rmdir_permission(&path);
}

/**
 * cs_path_unlink - Check permission for unlink().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_unlink(const struct path *dir, struct dentry *dentry)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };

	return cs_unlink_permission(&path);
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
static int cs_path_symlink(const struct path *dir, struct dentry *dentry,
			   const char *old_name)
{
	struct path path = { .mnt = dir->mnt, .dentry = dentry };

	return cs_symlink_permission(&path, old_name);
}

/**
 * cs_path_rename - Check permission for rename().
 *
 * @old_dir:    Pointer to "struct path".
 * @old_dentry: Pointer to "struct dentry".
 * @new_dir:    Pointer to "struct path".
 * @new_dentry: Pointer to "struct dentry".
 * @flags:      Rename flags.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_path_rename(const struct path *old_dir,
			  struct dentry *old_dentry,
			  const struct path *new_dir,
			  struct dentry *new_dentry,
			  const unsigned int flags)
{
	struct path old = { .mnt = old_dir->mnt, .dentry = old_dentry };
	struct path new = { .mnt = new_dir->mnt, .dentry = new_dentry };

	if (flags & RENAME_EXCHANGE) {
		const int err = cs_rename_permission(&new, &old);

		if (err)
			return err;
	}
	return cs_rename_permission(&old, &new);
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
static int cs_path_link(struct dentry *old_dentry, const struct path *new_dir,
			struct dentry *new_dentry)
{
	struct path old = { .mnt = new_dir->mnt, .dentry = old_dentry };
	struct path new = { .mnt = new_dir->mnt, .dentry = new_dentry };

	return cs_link_permission(&old, &new);
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
static int cs_inode_mknod(struct inode *dir, struct dentry *dentry,
			  umode_t mode, dev_t dev)
{
	struct path path = { .mnt = NULL, .dentry = dentry };

	return cs_mknod_permission(&path, mode, dev);
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

	return cs_mkdir_permission(&path, mode);
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

	return cs_rmdir_permission(&path);
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

	return cs_unlink_permission(&path);
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

	return cs_symlink_permission(&path, old_name);
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

	return cs_rename_permission(&old, &new);
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

	return cs_link_permission(&old, &new);
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
			   umode_t mode)
{
	struct path path = { .mnt = NULL, .dentry = dentry };

	return cs_mknod_permission(&path, mode, 0);
}

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
		kfree_rcu(ptr, rcu);
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
	const int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;
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
	const int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	return cs_socket_listen_permission(sock);
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
	const int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	return cs_socket_connect_permission(sock, addr, addr_len);
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
	const int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	return cs_socket_bind_permission(sock, addr, addr_len);
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
	const int rc = cs_validate_socket(sock);

	if (rc < 0)
		return rc;
	return cs_socket_sendmsg_permission(sock, msg, size);
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
	return cs_validate_socket(sock);
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
	return cs_validate_socket(sock);
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
	return cs_validate_socket(sock);
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
	return cs_validate_socket(sock);
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
	return cs_validate_socket(sock);
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
	return cs_validate_socket(sock);
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
static int cs_sb_pivotroot(const struct path *old_path,
			   const struct path *new_path)
{
	return cs_pivot_root_permission(old_path, new_path);
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
static int cs_sb_mount(const char *dev_name, const struct path *path,
		       const char *type, unsigned long flags, void *data_page)
{
	return cs_mount_permission(dev_name, path, type, flags, data_page);
}

/**
 * cs_move_mount - Check permission for move_mount().
 *
 * @from_path: Pointer to "struct path".
 * @to_path:   Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_move_mount(const struct path *from_path,
			 const struct path *to_path)
{
	return cs_move_mount_permission(from_path, to_path);
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

	return cs_umount_permission(&path, flags);
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
	return cs_fcntl_permission(file, cmd, arg);
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
	return cs_ioctl_permission(filp, cmd, arg);
}

#define LSM_HOOK(RET, DEFAULT, NAME, ...) typedef RET (NAME##_t)(__VA_ARGS__);
#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK

/*
 * Define prototype of wrapper function, static call slot for calling original function from
 * wrapper function, and static key for controlling whether to call original function from
 * wrapper function.
 */
#define DEFINE_PROTO_HOOK_KEY(NAME)					\
	static NAME##_t wrapped_##NAME;					\
	DEFINE_STATIC_CALL_NULL(original_##NAME, wrapped_##NAME);	\
	DEFINE_STATIC_KEY_FALSE_RO(original_##NAME##_enabled);
DEFINE_PROTO_HOOK_KEY(task_free)
DEFINE_PROTO_HOOK_KEY(cred_prepare)
DEFINE_PROTO_HOOK_KEY(task_alloc)
DEFINE_PROTO_HOOK_KEY(bprm_check_security)
DEFINE_PROTO_HOOK_KEY(bprm_committing_creds)
DEFINE_PROTO_HOOK_KEY(file_open)
DEFINE_PROTO_HOOK_KEY(file_fcntl)
DEFINE_PROTO_HOOK_KEY(file_ioctl)
DEFINE_PROTO_HOOK_KEY(file_ioctl_compat)
DEFINE_PROTO_HOOK_KEY(sb_pivotroot)
DEFINE_PROTO_HOOK_KEY(sb_mount)
DEFINE_PROTO_HOOK_KEY(move_mount)
DEFINE_PROTO_HOOK_KEY(sb_umount)
DEFINE_PROTO_HOOK_KEY(file_truncate)
#ifdef CONFIG_SECURITY_PATH
DEFINE_PROTO_HOOK_KEY(path_mknod)
DEFINE_PROTO_HOOK_KEY(path_mkdir)
DEFINE_PROTO_HOOK_KEY(path_rmdir)
DEFINE_PROTO_HOOK_KEY(path_unlink)
DEFINE_PROTO_HOOK_KEY(path_symlink)
DEFINE_PROTO_HOOK_KEY(path_rename)
DEFINE_PROTO_HOOK_KEY(path_link)
DEFINE_PROTO_HOOK_KEY(path_truncate)
DEFINE_PROTO_HOOK_KEY(path_chmod)
DEFINE_PROTO_HOOK_KEY(path_chown)
DEFINE_PROTO_HOOK_KEY(path_chroot)
#else
DEFINE_PROTO_HOOK_KEY(inode_mknod)
DEFINE_PROTO_HOOK_KEY(inode_mkdir)
DEFINE_PROTO_HOOK_KEY(inode_rmdir)
DEFINE_PROTO_HOOK_KEY(inode_unlink)
DEFINE_PROTO_HOOK_KEY(inode_symlink)
DEFINE_PROTO_HOOK_KEY(inode_rename)
DEFINE_PROTO_HOOK_KEY(inode_link)
DEFINE_PROTO_HOOK_KEY(inode_create)
DEFINE_PROTO_HOOK_KEY(inode_setattr)
#endif
DEFINE_PROTO_HOOK_KEY(inode_getattr)
#ifdef CONFIG_SECURITY_NETWORK
DEFINE_PROTO_HOOK_KEY(inode_free_security)
DEFINE_PROTO_HOOK_KEY(socket_bind)
DEFINE_PROTO_HOOK_KEY(socket_connect)
DEFINE_PROTO_HOOK_KEY(socket_listen)
DEFINE_PROTO_HOOK_KEY(socket_sendmsg)
DEFINE_PROTO_HOOK_KEY(socket_recvmsg)
DEFINE_PROTO_HOOK_KEY(socket_getsockname)
DEFINE_PROTO_HOOK_KEY(socket_getpeername)
DEFINE_PROTO_HOOK_KEY(socket_getsockopt)
DEFINE_PROTO_HOOK_KEY(socket_setsockopt)
DEFINE_PROTO_HOOK_KEY(socket_shutdown)
DEFINE_PROTO_HOOK_KEY(socket_accept)
#endif
#undef DEFINE_PROTO_HOOK_KEY

/* Wrapper functions. */

static void wrapped_task_free(struct task_struct *p)
{
	if (static_branch_unlikely(&original_task_free_enabled)) {
		static_call(original_task_free)(p);
	}
	cs_task_free_security(p);
}

static int wrapped_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	if (static_branch_unlikely(&original_cred_prepare_enabled)) {
		const int ret = static_call(original_cred_prepare)(new, old, gfp);

		if (ret)
			return ret;
	}
	return cs_cred_prepare(new, old, gfp);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
static int wrapped_task_alloc(struct task_struct *p, u64 clone_flags)
{
	if (static_branch_unlikely(&original_task_alloc_enabled)) {
		const int ret = static_call(original_task_alloc)(p, clone_flags);

		if (ret)
			return ret;
	}
	return cs_task_alloc_security(p, clone_flags);
}
#else
static int wrapped_task_alloc(struct task_struct *p, unsigned long clone_flags)
{
	if (static_branch_unlikely(&original_task_alloc_enabled)) {
		const int ret = static_call(original_task_alloc)(p, clone_flags);

		if (ret)
			return ret;
	}
	return cs_task_alloc_security(p, clone_flags);
}
#endif

static int wrapped_bprm_check_security(struct linux_binprm *bprm)
{
	if (static_branch_unlikely(&original_bprm_check_security_enabled)) {
		const int ret = static_call(original_bprm_check_security)(bprm);

		if (ret)
			return ret;
	}
	return cs_bprm_check_security(bprm);
}

#if defined(RHEL_MAJOR) && RHEL_MAJOR == 9 && defined(RHEL_MINOR) && RHEL_MINOR >= 6
static void wrapped_bprm_committing_creds(struct linux_binprm *bprm)
{
	if (static_branch_unlikely(&original_bprm_committing_creds_enabled)) {
		static_call(original_bprm_committing_creds)(bprm);
	}
	cs_bprm_committing_creds(bprm);
}
#else
static void wrapped_bprm_committing_creds(const struct linux_binprm *bprm)
{
	if (static_branch_unlikely(&original_bprm_committing_creds_enabled)) {
		static_call(original_bprm_committing_creds)(bprm);
	}
	cs_bprm_committing_creds(bprm);
}
#endif

static int wrapped_file_open(struct file *f)
{
	if (static_branch_unlikely(&original_file_open_enabled)) {
		const int ret = static_call(original_file_open)(f);

		if (ret)
			return ret;
	}
	return cs_file_open(f);
}

static int wrapped_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (static_branch_unlikely(&original_file_fcntl_enabled)) {
		const int ret = static_call(original_file_fcntl)(file, cmd, arg);

		if (ret)
			return ret;
	}
	return cs_file_fcntl(file, cmd, arg);
}

static int wrapped_file_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	if (static_branch_unlikely(&original_file_ioctl_enabled)) {
		const int ret = static_call(original_file_ioctl)(filp, cmd, arg);

		if (ret)
			return ret;
	}
	return cs_file_ioctl(filp, cmd, arg);
}

static int wrapped_file_ioctl_compat(struct file *filp, unsigned int cmd, unsigned long arg)
{
	if (static_branch_unlikely(&original_file_ioctl_compat_enabled)) {
		const int ret = static_call(original_file_ioctl_compat)(filp, cmd, arg);

		if (ret)
			return ret;
	}
	return cs_file_ioctl(filp, cmd, arg);
}

static int wrapped_sb_pivotroot(const struct path *old_path, const struct path *new_path)
{
	if (static_branch_unlikely(&original_sb_pivotroot_enabled)) {
		const int ret = static_call(original_sb_pivotroot)(old_path, new_path);

		if (ret)
			return ret;
	}
	return cs_sb_pivotroot(old_path, new_path);
}

static int wrapped_sb_mount(const char *dev_name, const struct path *path,
			    const char *type, unsigned long flags, void *data_page)
{
	if (static_branch_unlikely(&original_sb_mount_enabled)) {
		const int ret = static_call(original_sb_mount)(dev_name, path, type, flags, data_page);

		if (ret)
			return ret;
	}
	return cs_sb_mount(dev_name, path, type, flags, data_page);
}

static int wrapped_move_mount(const struct path *from_path, const struct path *to_path)
{
	if (static_branch_unlikely(&original_move_mount_enabled)) {
		const int ret = static_call(original_move_mount)(from_path, to_path);

		if (ret)
			return ret;
	}
	return cs_move_mount(from_path, to_path);
}

static int wrapped_sb_umount(struct vfsmount *mnt, int flags)
{
	if (static_branch_unlikely(&original_sb_umount_enabled)) {
		const int ret = static_call(original_sb_umount)(mnt, flags);

		if (ret)
			return ret;
	}
	return cs_sb_umount(mnt, flags);
}

static int wrapped_file_truncate(struct file *file)
{
	if (static_branch_unlikely(&original_file_truncate_enabled)) {
		const int ret = static_call(original_file_truncate)(file);

		if (ret)
			return ret;
	}
	return cs_file_truncate(file);
}

#ifdef CONFIG_SECURITY_PATH

static int wrapped_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode,
			      unsigned int dev)
{
	if (static_branch_unlikely(&original_path_mknod_enabled)) {
		const int ret = static_call(original_path_mknod)(dir, dentry, mode, dev);

		if (ret)
			return ret;
	}
	return cs_path_mknod(dir, dentry, mode, dev);
}

static int wrapped_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)
{
	if (static_branch_unlikely(&original_path_mkdir_enabled)) {
		const int ret = static_call(original_path_mkdir)(dir, dentry, mode);

		if (ret)
			return ret;
	}
	return cs_path_mkdir(dir, dentry, mode);
}

static int wrapped_path_rmdir(const struct path *dir, struct dentry *dentry)
{
	if (static_branch_unlikely(&original_path_rmdir_enabled)) {
		const int ret = static_call(original_path_rmdir)(dir, dentry);

		if (ret)
			return ret;
	}
	return cs_path_rmdir(dir, dentry);
}

static int wrapped_path_unlink(const struct path *dir, struct dentry *dentry)
{
	if (static_branch_unlikely(&original_path_unlink_enabled)) {
		const int ret = static_call(original_path_unlink)(dir, dentry);

		if (ret)
			return ret;
	}
	return cs_path_unlink(dir, dentry);
}

static int wrapped_path_symlink(const struct path *dir, struct dentry *dentry,
				const char *old_name)
{
	if (static_branch_unlikely(&original_path_symlink_enabled)) {
		const int ret = static_call(original_path_symlink)(dir, dentry, old_name);

		if (ret)
			return ret;
	}
	return cs_path_symlink(dir, dentry, old_name);
}

static int wrapped_path_rename(const struct path *old_dir, struct dentry *old_dentry,
			       const struct path *new_dir, struct dentry *new_dentry,
			       const unsigned int flags)
{
	if (static_branch_unlikely(&original_path_rename_enabled)) {
		const int ret = static_call(original_path_rename)(old_dir, old_dentry, new_dir, new_dentry, flags);

		if (ret)
			return ret;
	}
	return cs_path_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

static int wrapped_path_link(struct dentry *old_dentry, const struct path *new_dir,
			     struct dentry *new_dentry)
{
	if (static_branch_unlikely(&original_path_link_enabled)) {
		const int ret = static_call(original_path_link)(old_dentry, new_dir, new_dentry);

		if (ret)
			return ret;
	}
	return cs_path_link(old_dentry, new_dir, new_dentry);
}

static int wrapped_path_truncate(const struct path *path)
{
	if (static_branch_unlikely(&original_path_truncate_enabled)) {
		const int ret = static_call(original_path_truncate)(path);

		if (ret)
			return ret;
	}
	return cs_path_truncate(path);
}

static int wrapped_path_chmod(const struct path *path, umode_t mode)
{
	if (static_branch_unlikely(&original_path_chmod_enabled)) {
		const int ret = static_call(original_path_chmod)(path, mode);

		if (ret)
			return ret;
	}
	return cs_path_chmod(path, mode);
}

static int wrapped_path_chown(const struct path *path, kuid_t user, kgid_t group)
{
	if (static_branch_unlikely(&original_path_chown_enabled)) {
		const int ret = static_call(original_path_chown)(path, user, group);

		if (ret)
			return ret;
	}
	return cs_path_chown(path, user, group);
}

static int wrapped_path_chroot(const struct path *path)
{
	if (static_branch_unlikely(&original_path_chroot_enabled)) {
		const int ret = static_call(original_path_chroot)(path);

		if (ret)
			return ret;
	}
	return cs_path_chroot(path);
}

#else

static int wrapped_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	if (static_branch_unlikely(&original_inode_mknod_enabled)) {
		const int ret = static_call(original_inode_mknod)(dir, dentry, mode, dev);

		if (ret)
			return ret;
	}
	return cs_inode_mknod(dir, dentry, mode, dev);
}

static int wrapped_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	if (static_branch_unlikely(&original_inode_mkdir_enabled)) {
		const int ret = static_call(original_inode_mkdir)(dir, dentry, mode);

		if (ret)
			return ret;
	}
	return cs_inode_mkdir(dir, dentry, mode);
}

static int wrapped_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (static_branch_unlikely(&original_inode_rmdir_enabled)) {
		const int ret = static_call(original_inode_rmdir)(dir, dentry);

		if (ret)
			return ret;
	}
	return cs_inode_rmdir(dir, dentry);
}

static int wrapped_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	if (static_branch_unlikely(&original_inode_unlink_enabled)) {
		const int ret = static_call(original_inode_unlink)(dir, dentry);

		if (ret)
			return ret;
	}
	return cs_inode_unlink(dir, dentry);
}

static int wrapped_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name)
{
	if (static_branch_unlikely(&original_inode_symlink_enabled)) {
		const int ret = static_call(original_inode_symlink)(dir, dentry, old_name);

		if (ret)
			return ret;
	}
	return cs_inode_symlink(dir, dentry, old_name);
}

static int wrapped_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
				struct inode *new_dir, struct dentry *new_dentry)
{
	if (static_branch_unlikely(&original_inode_rename_enabled)) {
		const int ret = static_call(original_inode_rename)(old_dir, old_dentry, new_dir, new_dentry);

		if (ret)
			return ret;
	}
	return cs_inode_rename(old_dir, old_dentry, new_dir, new_dentry);
}

static int wrapped_inode_link(struct dentry *old_dentry, struct inode *dir,
			      struct dentry *new_dentry)
{
	if (static_branch_unlikely(&original_inode_link_enabled)) {
		const int ret = static_call(original_inode_link)(old_dentry, dir, new_dentry);

		if (ret)
			return ret;
	}
	return cs_inode_link(old_dentry, dir, new_dentry);
}

static int wrapped_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	if (static_branch_unlikely(&original_inode_create_enabled)) {
		const int ret = static_call(original_inode_create)(dir, dentry, mode);

		if (ret)
			return ret;
	}
	return cs_inode_create(dir, dentry, mode);
}

static int wrapped_inode_setattr(struct mnt_idmap *mnt_idmap, struct dentry *dentry,
				 struct iattr *attr)
{
	if (static_branch_unlikely(&original_inode_setattr_enabled)) {
		const int ret = static_call(original_inode_setattr)(mnt_idmap, dentry, attr);

		if (ret)
			return ret;
	}
	return cs_inode_setattr(mnt_idmap, dentry, attr);
}

#endif

static int wrapped_inode_getattr(const struct path *path)
{
	if (static_branch_unlikely(&original_inode_getattr_enabled)) {
		const int ret = static_call(original_inode_getattr)(path);

		if (ret)
			return ret;
	}
	return cs_inode_getattr(path);
}

#ifdef CONFIG_SECURITY_NETWORK

static int wrapped_socket_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	if (static_branch_unlikely(&original_socket_bind_enabled)) {
		const int ret = static_call(original_socket_bind)(sock, addr, addr_len);

		if (ret)
			return ret;
	}
	return cs_socket_bind(sock, addr, addr_len);
}

static int wrapped_socket_connect(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	if (static_branch_unlikely(&original_socket_connect_enabled)) {
		const int ret = static_call(original_socket_connect)(sock, addr, addr_len);

		if (ret)
			return ret;
	}
	return cs_socket_connect(sock, addr, addr_len);
}

static int wrapped_socket_listen(struct socket *sock, int backlog)
{
	if (static_branch_unlikely(&original_socket_listen_enabled)) {
		const int ret = static_call(original_socket_listen)(sock, backlog);

		if (ret)
			return ret;
	}
	return cs_socket_listen(sock, backlog);
}

static int wrapped_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	if (static_branch_unlikely(&original_socket_sendmsg_enabled)) {
		const int ret = static_call(original_socket_sendmsg)(sock, msg, size);

		if (ret)
			return ret;
	}
	return cs_socket_sendmsg(sock, msg, size);
}

static int wrapped_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size, int flags)
{
	if (static_branch_unlikely(&original_socket_recvmsg_enabled)) {
		const int ret = static_call(original_socket_recvmsg)(sock, msg, size, flags);

		if (ret)
			return ret;
	}
	return cs_socket_recvmsg(sock, msg, size, flags);
}

static int wrapped_socket_getsockname(struct socket *sock)
{
	if (static_branch_unlikely(&original_socket_getsockname_enabled)) {
		const int ret = static_call(original_socket_getsockname)(sock);

		if (ret)
			return ret;
	}
	return cs_socket_getsockname(sock);
}

static int wrapped_socket_getpeername(struct socket *sock)
{
	if (static_branch_unlikely(&original_socket_getpeername_enabled)) {
		const int ret = static_call(original_socket_getpeername)(sock);

		if (ret)
			return ret;
	}
	return cs_socket_getpeername(sock);
}

static int wrapped_socket_getsockopt(struct socket *sock, int level, int optname)
{
	if (static_branch_unlikely(&original_socket_getsockopt_enabled)) {
		const int ret = static_call(original_socket_getsockopt)(sock, level, optname);

		if (ret)
			return ret;
	}
	return cs_socket_getsockopt(sock, level, optname);
}

static int wrapped_socket_setsockopt(struct socket *sock, int level, int optname)
{
	if (static_branch_unlikely(&original_socket_setsockopt_enabled)) {
		const int ret = static_call(original_socket_setsockopt)(sock, level, optname);

		if (ret)
			return ret;
	}
	return cs_socket_setsockopt(sock, level, optname);
}

static int wrapped_socket_shutdown(struct socket *sock, int how)
{
	if (static_branch_unlikely(&original_socket_shutdown_enabled)) {
		const int ret = static_call(original_socket_shutdown)(sock, how);

		if (ret)
			return ret;
	}
	return cs_socket_shutdown(sock, how);
}

static int wrapped_socket_accept(struct socket *sock, struct socket *newsock)
{
	if (static_branch_unlikely(&original_socket_accept_enabled)) {
		const int ret = static_call(original_socket_accept)(sock, newsock);

		if (ret)
			return ret;
	}
	return cs_socket_accept(sock, newsock);
}

static void wrapped_inode_free_security(struct inode *inode)
{
	if (static_branch_unlikely(&original_inode_free_security_enabled)) {
		static_call(original_inode_free_security)(inode);
	}
	cs_inode_free_security(inode);
}

#endif

long (*my_copy_to_kernel_nofault) (void *dst, const void *src, size_t size);

#if defined(CONFIG_STRICT_KERNEL_RWX) && !defined(CONFIG_SECURITY_WRITABLE_HOOKS)
#include <linux/uaccess.h> /* copy_to_kernel_nofault() */
#define NEED_TO_CHECK_HOOKS_ARE_WRITABLE

#if defined(CONFIG_X86)
#define MAX_RO_PAGES 64
static struct page *ro_pages[MAX_RO_PAGES] __initdata;
static unsigned int ro_pages_len __initdata;

static bool __init lsm_test_page_ro(void *addr)
{
	unsigned int i;
	int unused;
	struct page *page;

	page = (struct page *) lookup_address((unsigned long) addr, &unused);
	if (!page)
		return false;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	if (test_bit(_PAGE_BIT_RW, &(page->flags.f)))
		return true;
#else
	if (test_bit(_PAGE_BIT_RW, &(page->flags)))
		return true;
#endif
	for (i = 0; i < ro_pages_len; i++)
		if (page == ro_pages[i])
			return true;
	if (ro_pages_len == MAX_RO_PAGES)
		return false;
	ro_pages[ro_pages_len++] = page;
	return true;
}

static bool __init check_ro_pages(struct lsm_static_calls_table *hooks)
{
	void *start = (void *) ((((unsigned long) hooks) / PAGE_SIZE) * PAGE_SIZE);
	const void *end = (void *) (((((unsigned long) hooks) + sizeof(*hooks) +
				      PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE);

	if (!my_copy_to_kernel_nofault(hooks, hooks, sizeof(void *)))
		return true;
	while (start < end) {
		if (!lsm_test_page_ro(start))
			return false;
		start += PAGE_SIZE;
	}
	return true;
}
#else
static bool __init check_ro_pages(struct lsm_static_calls_table *hooks)
{
	return !my_copy_to_kernel_nofault(hooks, hooks, sizeof(void *));
}
#endif
#endif

/**
 * cs_init - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __init cs_init(void)
{
	int idx;
	struct lsm_static_calls_table *ptr = probe_static_calls_table();

	if (!ptr)
		goto out;
	my_copy_to_kernel_nofault = probe_copy_to_kernel_nofault();
	if (!my_copy_to_kernel_nofault)
		goto out;
#if defined(NEED_TO_CHECK_HOOKS_ARE_WRITABLE)
	if (!check_ro_pages(ptr)) {
		printk(KERN_INFO "Can't update static_calls_table due to write protected. Retry with rodata=off kernel command line option added.\n");
		return -EINVAL;
	}
#endif
	caitsith_exports.find_task_by_vpid = probe_find_task_by_vpid();
	if (!caitsith_exports.find_task_by_vpid)
		goto out;
	caitsith_exports.find_task_by_pid_ns = probe_find_task_by_pid_ns();
	if (!caitsith_exports.find_task_by_pid_ns)
		goto out;
	caitsith_exports.d_absolute_path = probe_d_absolute_path();
	if (!caitsith_exports.d_absolute_path)
		goto out;
	for (idx = 0; idx < CS_MAX_TASK_SECURITY_HASH; idx++)
		INIT_LIST_HEAD(&cs_task_security_list[idx]);
	cs_init_module();
#if defined(NEED_TO_CHECK_HOOKS_ARE_WRITABLE) && defined(CONFIG_X86)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	for (idx = 0; idx < ro_pages_len; idx++)
		set_bit(_PAGE_BIT_RW, &(ro_pages[idx]->flags.f));
#else
	for (idx = 0; idx < ro_pages_len; idx++)
		set_bit(_PAGE_BIT_RW, &(ro_pages[idx]->flags));
#endif
#endif

#define add_new_hook(NAME)						\
	do {								\
		int i;							\
									\
		for (i = 0; i < MAX_LSM_COUNT - 1; i++)			\
			if (!static_key_enabled(&ptr->NAME[i].active->key)) \
				break;					\
		static_call_update(original_##NAME, ptr->NAME[i].key->func); \
		mb(); /* Reorder not allowed. */			\
		__static_call_update(ptr->NAME[i].key, ptr->NAME[i].trampoline,	\
				     wrapped_##NAME);			\
		mb(); /* Reorder not allowed. */			\
		if (!static_key_enabled(&ptr->NAME[i].active->key))	\
			static_key_enable(&ptr->NAME[i].active->key);	\
		else							\
			static_key_enable(&original_##NAME##_enabled.key); \
	} while (0)
	/* Security context allocator. */
	add_new_hook(task_free);
	add_new_hook(cred_prepare);
	add_new_hook(task_alloc);
	/* Security context updater for successful execve(). */
	add_new_hook(bprm_check_security);
	add_new_hook(bprm_committing_creds);
	/* Various permission checker. */
	add_new_hook(file_open);
	add_new_hook(file_fcntl);
	add_new_hook(file_ioctl);
	add_new_hook(file_ioctl_compat);
	add_new_hook(sb_pivotroot);
	add_new_hook(sb_mount);
	add_new_hook(move_mount);
	add_new_hook(sb_umount);
	add_new_hook(file_truncate);
#ifdef CONFIG_SECURITY_PATH
	add_new_hook(path_mknod);
	add_new_hook(path_mkdir);
	add_new_hook(path_rmdir);
	add_new_hook(path_unlink);
	add_new_hook(path_symlink);
	add_new_hook(path_rename);
	add_new_hook(path_link);
	add_new_hook(path_truncate);
	add_new_hook(path_chmod);
	add_new_hook(path_chown);
	add_new_hook(path_chroot);
#else
	add_new_hook(inode_mknod);
	add_new_hook(inode_mkdir);
	add_new_hook(inode_rmdir);
	add_new_hook(inode_unlink);
	add_new_hook(inode_symlink);
	add_new_hook(inode_rename);
	add_new_hook(inode_link);
	add_new_hook(inode_create);
	add_new_hook(inode_setattr);
#endif
	add_new_hook(inode_getattr);
#ifdef CONFIG_SECURITY_NETWORK
	add_new_hook(inode_free_security);
	add_new_hook(socket_bind);
	add_new_hook(socket_connect);
	add_new_hook(socket_listen);
	add_new_hook(socket_sendmsg);
	add_new_hook(socket_recvmsg);
	add_new_hook(socket_getsockname);
	add_new_hook(socket_getpeername);
	add_new_hook(socket_getsockopt);
	add_new_hook(socket_setsockopt);
	add_new_hook(socket_shutdown);
	add_new_hook(socket_accept);
#endif
#undef add_new_hook

#if defined(NEED_TO_CHECK_HOOKS_ARE_WRITABLE) && defined(CONFIG_X86)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	for (idx = 0; idx < ro_pages_len; idx++)
		clear_bit(_PAGE_BIT_RW, &(ro_pages[idx]->flags.f));
#else
	for (idx = 0; idx < ro_pages_len; idx++)
		clear_bit(_PAGE_BIT_RW, &(ro_pages[idx]->flags));
#endif
#endif
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
 * __cs_alloc_task_security - Allocate memory for new tasks.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int __cs_alloc_task_security(const struct task_struct *task)
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
			cs_debug_trace("1");
			cs_clear_execve(-1, ptr);
		}
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
