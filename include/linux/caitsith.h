/*
 * include/linux/caitsith.h
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 0.2.16   2026/09/28
 */

#ifndef _LINUX_CAITSITH_H
#define _LINUX_CAITSITH_H

#include <linux/version.h>

#ifndef __user
#define __user
#endif

struct nameidata;
struct path;
struct dentry;
struct vfsmount;
struct linux_binprm;
struct pt_regs;
struct file;
struct ctl_table;
struct socket;
struct sockaddr;
struct sock;
struct sk_buff;
struct msghdr;
struct pid_namespace;
struct cs_request_info;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
/*
 * Don't depend on prototype definition, for exec_binprm() is a static function
 * which is implicitly inlined by compiler.
 */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
int search_binary_handler(struct linux_binprm *bprm);
#else
int search_binary_handler(struct linux_binprm *bprm, struct pt_regs *regs);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
#include <linux/lsm2caitsith.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
/* Obtain definition of kuid_t and kgid_t. */
#include <linux/uidgid.h>
#endif

#ifdef CONFIG_CAITSITH

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
/* Obtain prototype of __d_path(). */
#include <linux/dcache.h>
#endif

/* For exporting variables and functions. */
struct caitsith_exports {
	void (*load_policy)(const char *filename);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	char * (*d_absolute_path)(const struct path *, char *, int);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	typeof(__d_path) (*__d_path);
#else
	spinlock_t *vfsmount_lock;
#endif
	struct task_struct * (*find_task_by_vpid)(pid_t nr);
	struct task_struct * (*find_task_by_pid_ns)(pid_t nr,
						    struct pid_namespace *ns);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	size_t (*ksize)(const void *objp);
#endif
};

/* For doing access control. */
struct caitsith_operations {
	void (*check_profile)(void);
	int (*chroot_permission)(const struct path *path);
	int (*pivot_root_permission)(const struct path *old_path,
				     const struct path *new_path);
	int (*mount_permission)(const char *dev_name, const struct path *path,
				const char *type, unsigned long flags,
				void *data_page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	int (*move_mount_permission) (const struct path *from_path,
				      const struct path *to_path);
#endif
	int (*umount_permission)(struct vfsmount *mnt, int flags);
	_Bool(*lport_reserved) (const u16 port); /* Not implemented. */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
	void (*save_open_mode)(int mode);
	void (*clear_open_mode)(void);
	int (*open_permission)(struct dentry *dentry, struct vfsmount *mnt,
			       const int flag);
#else
	int (*open_permission)(struct file *file);
#endif
	int (*ptrace_permission)(long request, long pid);
	int (*ioctl_permission)(struct file *filp, unsigned int cmd,
				unsigned long arg);
	int (*parse_table)(int __user *name, int nlen, void __user *oldval,
			   void __user *newval, struct ctl_table *table);
	_Bool(*capable) (const u8 operation);
	int (*mknod_permission)(struct dentry *dentry, struct vfsmount *mnt,
				unsigned int mode, unsigned int dev);
	int (*mkdir_permission)(struct dentry *dentry, struct vfsmount *mnt,
				unsigned int mode);
	int (*rmdir_permission)(struct dentry *dentry, struct vfsmount *mnt);
	int (*unlink_permission)(struct dentry *dentry, struct vfsmount *mnt);
	int (*symlink_permission)(struct dentry *dentry, struct vfsmount *mnt,
				  const char *from);
	int (*truncate_permission)(struct dentry *dentry,
				   struct vfsmount *mnt);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
	int (*rename_permission)(struct dentry *old_dentry,
				 struct dentry *new_dentry,
				 struct vfsmount *mnt,
				 const unsigned int flags);
#else
	int (*rename_permission)(struct dentry *old_dentry,
				 struct dentry *new_dentry,
				 struct vfsmount *mnt);
#endif
	int (*link_permission)(struct dentry *old_dentry,
			       struct dentry *new_dentry,
			       struct vfsmount *mnt);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	int (*open_exec_permission)(struct dentry *dentry,
				    struct vfsmount *mnt);
	int (*uselib_permission)(struct dentry *dentry, struct vfsmount *mnt);
#endif
	int (*fcntl_permission)(struct file *file, unsigned int cmd,
				unsigned long arg);
	int (*kill_permission)(pid_t pid, int sig);
	int (*tgkill_permission)(pid_t tgid, pid_t pid, int sig);
	int (*tkill_permission)(pid_t pid, int sig);
	int (*socket_create_permission)(int family, int type, int protocol);
	int (*socket_listen_permission)(struct socket *sock);
	int (*socket_connect_permission)(struct socket *sock,
					 struct sockaddr *addr, int addr_len);
	int (*socket_bind_permission)(struct socket *sock,
				      struct sockaddr *addr, int addr_len);
	int (*socket_post_accept_permission)(struct socket *sock,
					     struct socket *newsock);
	int (*socket_sendmsg_permission)(struct socket *sock,
					 struct msghdr *msg, int size);
	int (*socket_post_recvmsg_permission)(struct sock *sk,
					      struct sk_buff *skb, int flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	int (*chown_permission)(struct dentry *dentry, struct vfsmount *mnt,
				kuid_t user, kgid_t group);
#else
	int (*chown_permission)(struct dentry *dentry, struct vfsmount *mnt,
				uid_t user, gid_t group);
#endif
	int (*chmod_permission)(struct dentry *dentry, struct vfsmount *mnt,
				mode_t mode);
	int (*getattr_permission)(struct vfsmount *mnt,
				  struct dentry *dentry);
	int (*sigqueue_permission)(pid_t pid, int sig);
	int (*tgsigqueue_permission)(pid_t tgid, pid_t pid, int sig);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	int (*start_execve) (struct linux_binprm *bprm, struct cs_request_info **rp);
	void (*finish_execve) (int retval, struct cs_request_info *r);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	int (*search_binary_handler)(struct linux_binprm *bprm);
#else
	int (*search_binary_handler)(struct linux_binprm *bprm,
				     struct pt_regs *regs);
#endif
#ifdef CONFIG_CAITSITH_USE_EXTERNAL_TASK_SECURITY
	int (*alloc_task_security)(const struct task_struct *task);
	void (*free_task_security)(const struct task_struct *task);
#endif
	_Bool disabled;
};

extern struct caitsith_operations caitsith_ops;

static inline int ccs_chroot_permission(const struct path *path)
{
	int (*func)(const struct path *) = caitsith_ops.chroot_permission;

	return func ? func(path) : 0;
}

static inline int ccs_pivot_root_permission(const struct path *old_path,
					    const struct path *new_path)
{
	int (*func)(const struct path *, const struct path *)
		= caitsith_ops.pivot_root_permission;
	return func ? func(old_path, new_path) : 0;
}

static inline int ccs_mount_permission(const char *dev_name,
				       const struct path *path,
				       const char *type, unsigned long flags,
				       void *data_page)
{
	int (*func)(const char *, const struct path *, const char *,
		     unsigned long, void *) = caitsith_ops.mount_permission;
	return func ? func(dev_name, path, type, flags, data_page) : 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
static inline int ccs_move_mount_permission(const struct path *from_path,
					    const struct path *to_path)
{
	int (*func) (const struct path *, const struct path *) =
		caitsith_ops.move_mount_permission;
	return func ? func(from_path, to_path) : 0;
}
#endif

static inline int ccs_umount_permission(struct vfsmount *mnt, int flags)
{
	int (*func)(struct vfsmount *, int)
		= caitsith_ops.umount_permission;
	return func ? func(mnt, flags) : 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)

static inline void ccs_save_open_mode(int mode)
{
	void (*func)(int) = caitsith_ops.save_open_mode;

	if (func)
		func(mode);
}

static inline void ccs_clear_open_mode(void)
{
	void (*func)(void) = caitsith_ops.clear_open_mode;

	if (func)
		func();
}

static inline int ccs_open_permission(struct dentry *dentry,
				      struct vfsmount *mnt, const int flag)
{
	int (*func)(struct dentry *, struct vfsmount *, const int)
		= caitsith_ops.open_permission;
	return func ? func(dentry, mnt, flag) : 0;
}

#else

static inline int ccs_open_permission(struct file *filp)
{
	int (*func)(struct file *) = caitsith_ops.open_permission;

	return func ? func(filp) : 0;
}

#endif

static inline int ccs_fcntl_permission(struct file *file, unsigned int cmd,
				       unsigned long arg)
{
	int (*func)(struct file *, unsigned int, unsigned long)
		= caitsith_ops.fcntl_permission;
	return func ? func(file, cmd, arg) : 0;
}

static inline int ccs_ioctl_permission(struct file *filp, unsigned int cmd,
				       unsigned long arg)
{
	int (*func)(struct file *, unsigned int, unsigned long)
		= caitsith_ops.ioctl_permission;
	return func ? func(filp, cmd, arg) : 0;
}

static inline int ccs_parse_table(int __user *name, int nlen,
				  void __user *oldval, void __user *newval,
				  struct ctl_table *table)
{
	int (*func)(int __user *, int, void __user *, void __user *,
		     struct ctl_table *) = caitsith_ops.parse_table;
	return func ? func(name, nlen, oldval, newval, table) : 0;
}

static inline int ccs_mknod_permission(struct dentry *dentry,
				       struct vfsmount *mnt, unsigned int mode,
				       unsigned int dev)
{
	int (*func)(struct dentry *, struct vfsmount *, unsigned int,
		     unsigned int) = caitsith_ops.mknod_permission;
	return func ? func(dentry, mnt, mode, dev) : 0;
}

static inline int ccs_mkdir_permission(struct dentry *dentry,
				       struct vfsmount *mnt, unsigned int mode)
{
	int (*func)(struct dentry *, struct vfsmount *, unsigned int)
		= caitsith_ops.mkdir_permission;
	return func ? func(dentry, mnt, mode) : 0;
}

static inline int ccs_rmdir_permission(struct dentry *dentry,
				       struct vfsmount *mnt)
{
	int (*func)(struct dentry *, struct vfsmount *)
		= caitsith_ops.rmdir_permission;
	return func ? func(dentry, mnt) : 0;
}

static inline int ccs_unlink_permission(struct dentry *dentry,
					struct vfsmount *mnt)
{
	int (*func)(struct dentry *, struct vfsmount *)
		= caitsith_ops.unlink_permission;
	return func ? func(dentry, mnt) : 0;
}

static inline int ccs_symlink_permission(struct dentry *dentry,
					 struct vfsmount *mnt,
					 const char *from)
{
	int (*func)(struct dentry *, struct vfsmount *, const char *)
		= caitsith_ops.symlink_permission;
	return func ? func(dentry, mnt, from) : 0;
}

static inline int ccs_truncate_permission(struct dentry *dentry,
					  struct vfsmount *mnt)
{
	int (*func)(struct dentry *, struct vfsmount *)
		= caitsith_ops.truncate_permission;
	return func ? func(dentry, mnt) : 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
static inline int ccs_rename_permission(struct dentry *old_dentry,
					struct dentry *new_dentry,
					struct vfsmount *mnt,
					const unsigned int flags)
{
	int (*func)(struct dentry *, struct dentry *, struct vfsmount *,
		    const unsigned int) = caitsith_ops.rename_permission;
	return func ? func(old_dentry, new_dentry, mnt, flags) : 0;
}
#else
static inline int ccs_rename_permission(struct dentry *old_dentry,
					struct dentry *new_dentry,
					struct vfsmount *mnt)
{
	int (*func)(struct dentry *, struct dentry *, struct vfsmount *)
		= caitsith_ops.rename_permission;
	return func ? func(old_dentry, new_dentry, mnt) : 0;
}
#endif

static inline int ccs_link_permission(struct dentry *old_dentry,
				      struct dentry *new_dentry,
				      struct vfsmount *mnt)
{
	int (*func)(struct dentry *, struct dentry *, struct vfsmount *)
		= caitsith_ops.link_permission;
	return func ? func(old_dentry, new_dentry, mnt) : 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)

static inline int ccs_open_exec_permission(struct dentry *dentry,
					   struct vfsmount *mnt)
{
	int (*func)(struct dentry *, struct vfsmount *)
		= caitsith_ops.open_exec_permission;
	return func ? func(dentry, mnt) : 0;
}

static inline int ccs_uselib_permission(struct dentry *dentry,
					struct vfsmount *mnt)
{
	int (*func)(struct dentry *, struct vfsmount *)
		= caitsith_ops.uselib_permission;
	return func ? func(dentry, mnt) : 0;
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)

static inline int ccs_chown_permission(struct dentry *dentry,
				       struct vfsmount *mnt, kuid_t user,
				       kgid_t group)
{
	int (*func)(struct dentry *, struct vfsmount *, kuid_t, kgid_t)
		= caitsith_ops.chown_permission;
	return func ? func(dentry, mnt, user, group) : 0;
}

#else

static inline int ccs_chown_permission(struct dentry *dentry,
				       struct vfsmount *mnt, uid_t user,
				       gid_t group)
{
	int (*func)(struct dentry *, struct vfsmount *, uid_t, gid_t)
		= caitsith_ops.chown_permission;
	return func ? func(dentry, mnt, user, group) : 0;
}

#endif

static inline int ccs_chmod_permission(struct dentry *dentry,
				       struct vfsmount *mnt, mode_t mode)
{
	int (*func)(struct dentry *, struct vfsmount *, mode_t)
		= caitsith_ops.chmod_permission;
	return func ? func(dentry, mnt, mode) : 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)

/* Define as a macro here, for exec_binprm() is a static function. */
#define ccs_exec_binprm(bprm)\
	({\
	struct cs_request_info *r = NULL;	\
	void (*func) (int, struct cs_request_info *r);\
	int retval = caitsith_ops.start_execve(bprm, &r);\
	if (!retval)\
		retval = exec_binprm(bprm);\
	func = caitsith_ops.finish_execve;\
	if (func)\
		func(retval, r);\
	retval;\
	})

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)

static inline int ccs_search_binary_handler(struct linux_binprm *bprm)
{
	return caitsith_ops.search_binary_handler(bprm);
}

#else

static inline int ccs_search_binary_handler(struct linux_binprm *bprm,
					    struct pt_regs *regs)
{
	return caitsith_ops.search_binary_handler(bprm, regs);
}

#endif

#else

static inline int ccs_chroot_permission(const struct path *path)
{
	return 0;
}

static inline int ccs_pivot_root_permission(const struct path *old_path,
					    const struct path *new_path)
{
	return 0;
}

static inline int ccs_mount_permission(const char *dev_name,
				       const struct path *path,
				       const char *type, unsigned long flags,
				       void *data_page)
{
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
static inline int ccs_move_mount_permission(const struct path *from_path,
					    const struct path *to_path)
{
	return 0;
}
#endif

static inline int ccs_umount_permission(struct vfsmount *mnt, int flags)
{
	return 0;
}

static inline void ccs_save_open_mode(int mode)
{
}

static inline void ccs_clear_open_mode(void)
{
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)

static inline int ccs_open_permission(struct dentry *dentry,
				      struct vfsmount *mnt, const int flag)
{
	return 0;
}

#else

static inline int ccs_open_permission(struct file *filp)
{
	return 0;
}

#endif

static inline int ccs_ioctl_permission(struct file *filp, unsigned int cmd,
				       unsigned long arg)
{
	return 0;
}

static inline int ccs_parse_table(int __user *name, int nlen,
				  void __user *oldval, void __user *newval,
				  struct ctl_table *table)
{
	return 0;
}

static inline int ccs_mknod_permission(struct dentry *dentry,
				       struct vfsmount *mnt, unsigned int mode,
				       unsigned int dev)
{
	return 0;
}

static inline int ccs_mkdir_permission(struct dentry *dentry,
				       struct vfsmount *mnt, unsigned int mode)
{
	return 0;
}

static inline int ccs_rmdir_permission(struct dentry *dentry,
				       struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_unlink_permission(struct dentry *dentry,
					struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_symlink_permission(struct dentry *dentry,
					 struct vfsmount *mnt,
					 const char *from)
{
	return 0;
}

static inline int ccs_truncate_permission(struct dentry *dentry,
					  struct vfsmount *mnt)
{
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
static inline int ccs_rename_permission(struct dentry *old_dentry,
					struct dentry *new_dentry,
					struct vfsmount *mnt,
					const unsigned int flags)
{
	return 0;
}
#else
static inline int ccs_rename_permission(struct dentry *old_dentry,
					struct dentry *new_dentry,
					struct vfsmount *mnt)
{
	return 0;
}
#endif

static inline int ccs_link_permission(struct dentry *old_dentry,
				      struct dentry *new_dentry,
				      struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_open_exec_permission(struct dentry *dentry,
					   struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_uselib_permission(struct dentry *dentry,
					struct vfsmount *mnt)
{
	return 0;
}

static inline int ccs_fcntl_permission(struct file *file, unsigned int cmd,
				       unsigned long arg)
{
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)

static inline int ccs_chown_permission(struct dentry *dentry,
				       struct vfsmount *mnt, kuid_t user,
				       kgid_t group)
{
	return 0;
}

#else

static inline int ccs_chown_permission(struct dentry *dentry,
				       struct vfsmount *mnt, uid_t user,
				       gid_t group)
{
	return 0;
}

#endif

static inline int ccs_chmod_permission(struct dentry *dentry,
				       struct vfsmount *mnt, mode_t mode)
{
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)

/* Define as a macro here, for exec_binprm() is a static function. */
#define ccs_exec_binprm(bprm) exec_binprm(bprm)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)

static inline int ccs_search_binary_handler(struct linux_binprm *bprm)
{
	return search_binary_handler(bprm);
}

#else

static inline int ccs_search_binary_handler(struct linux_binprm *bprm,
					    struct pt_regs *regs)
{
	return search_binary_handler(bprm, regs);
}

#endif

#endif

#ifdef CONFIG_CAITSITH_USE_EXTERNAL_TASK_SECURITY

static inline int ccs_alloc_task_security(const struct task_struct *task)
{
	int (*func)(const struct task_struct *)
		= caitsith_ops.alloc_task_security;
	return func ? func(task) : 0;
}

static inline void ccs_free_task_security(const struct task_struct *task)
{
	void (*func)(const struct task_struct *)
		= caitsith_ops.free_task_security;
	if (func)
		func(task);
}

#else

static inline int ccs_alloc_task_security(const struct task_struct *task)
{
	return 0;
}

static inline void ccs_free_task_security(const struct task_struct *task)
{
}

#endif

#ifdef CONFIG_CAITSITH_GETATTR

static inline int ccs_getattr_permission(struct vfsmount *mnt,
					 struct dentry *dentry)
{
	int (*func)(struct vfsmount *, struct dentry *)
		= caitsith_ops.getattr_permission;
	return func ? func(mnt, dentry) : 0;
}

#else

static inline int ccs_getattr_permission(struct vfsmount *mnt,
					 struct dentry *dentry)
{
	return 0;
}

#endif

#ifdef CONFIG_CAITSITH_NETWORK

static inline int ccs_socket_listen_permission(struct socket *sock)
{
	int (*func)(struct socket *)
		= caitsith_ops.socket_listen_permission;
	return func ? func(sock) : 0;
}

static inline int ccs_socket_connect_permission(struct socket *sock,
						struct sockaddr *addr,
						int addr_len)
{
	int (*func)(struct socket *, struct sockaddr *, int)
		= caitsith_ops.socket_connect_permission;
	return func ? func(sock, addr, addr_len) : 0;
}

static inline int ccs_socket_bind_permission(struct socket *sock,
					     struct sockaddr *addr,
					     int addr_len)
{
	int (*func)(struct socket *, struct sockaddr *, int)
		= caitsith_ops.socket_bind_permission;
	return func ? func(sock, addr, addr_len) : 0;
}

static inline int ccs_socket_post_accept_permission(struct socket *sock,
						    struct socket *newsock)
{
	int (*func)(struct socket *, struct socket *)
		= caitsith_ops.socket_post_accept_permission;
	return func ? func(sock, newsock) : 0;
}

static inline int ccs_socket_sendmsg_permission(struct socket *sock,
						struct msghdr *msg,
						int size)
{
	int (*func)(struct socket *, struct msghdr *, int)
		= caitsith_ops.socket_sendmsg_permission;
	return func ? func(sock, msg, size) : 0;
}

#else

static inline int ccs_socket_listen_permission(struct socket *sock)
{
	return 0;
}

static inline int ccs_socket_connect_permission(struct socket *sock,
						struct sockaddr *addr,
						int addr_len)
{
	return 0;
}

static inline int ccs_socket_bind_permission(struct socket *sock,
					     struct sockaddr *addr,
					     int addr_len)
{
	return 0;
}

static inline int ccs_socket_post_accept_permission(struct socket *sock,
						    struct socket *newsock)
{
	return 0;
}

static inline int ccs_socket_sendmsg_permission(struct socket *sock,
						struct msghdr *msg,
						int size)
{
	return 0;
}

#endif

#ifdef CONFIG_CAITSITH_NETWORK_RECVMSG

static inline int ccs_socket_post_recvmsg_permission(struct sock *sk,
						     struct sk_buff *skb,
						     int flags)
{
	int (*func)(struct sock *, struct sk_buff *, int)
		= caitsith_ops.socket_post_recvmsg_permission;
	return func ? func(sk, skb, flags) : 0;
}

#else

static inline int ccs_socket_post_recvmsg_permission(struct sock *sk,
						     struct sk_buff *skb,
						     int flags)
{
	return 0;
}

#endif

static inline _Bool ccs_lport_reserved(const u16 port)
{
	return 0;
}

#ifdef CONFIG_CAITSITH_CAPABILITY

static inline _Bool ccs_capable(const u8 operation)
{
	_Bool (*func)(const u8) = caitsith_ops.capable;

	return func ? func(operation) : 1;
}

static inline int ccs_socket_create_permission(int family, int type,
					       int protocol)
{
	int (*func)(int, int, int) = caitsith_ops.socket_create_permission;

	return func ? func(family, type, protocol) : 0;
}

#else

static inline _Bool ccs_capable(const u8 operation)
{
	return 1;
}

static inline int ccs_socket_create_permission(int family, int type,
					       int protocol)
{
	return 0;
}

#endif

#ifdef CONFIG_CAITSITH_PTRACE

static inline int ccs_ptrace_permission(long request, long pid)
{
	int (*func)(long, long) = caitsith_ops.ptrace_permission;

	return func ? func(request, pid) : 0;
}

#else

static inline int ccs_ptrace_permission(long request, long pid)
{
	return 0;
}

#endif

#ifdef CONFIG_CAITSITH_SIGNAL

static inline int ccs_kill_permission(pid_t pid, int sig)
{
	int (*func)(pid_t, int) = caitsith_ops.kill_permission;

	return func ? func(pid, sig) : 0;
}

static inline int ccs_tgkill_permission(pid_t tgid, pid_t pid, int sig)
{
	int (*func)(pid_t, pid_t, int) = caitsith_ops.tgkill_permission;

	return func ? func(tgid, pid, sig) : 0;
}

static inline int ccs_tkill_permission(pid_t pid, int sig)
{
	int (*func)(pid_t, int) = caitsith_ops.tkill_permission;

	return func ? func(pid, sig) : 0;
}

static inline int ccs_sigqueue_permission(pid_t pid, int sig)
{
	int (*func)(pid_t, int) = caitsith_ops.sigqueue_permission;

	return func ? func(pid, sig) : 0;
}

static inline int ccs_tgsigqueue_permission(pid_t tgid, pid_t pid, int sig)
{
	int (*func)(pid_t, pid_t, int) = caitsith_ops.tgsigqueue_permission;

	return func ? func(tgid, pid, sig) : 0;
}

#else

static inline int ccs_kill_permission(pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_tgkill_permission(pid_t tgid, pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_tkill_permission(pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_sigqueue_permission(pid_t pid, int sig)
{
	return 0;
}

static inline int ccs_tgsigqueue_permission(pid_t tgid, pid_t pid, int sig)
{
	return 0;
}

#endif

/* Index numbers for Capability Controls. */
enum ccs_capability_acl_index {
	/* socket(PF_ROUTE, *, *)                                      */
	CCS_USE_ROUTE_SOCKET,
	/* socket(PF_PACKET, *, *)                                     */
	CCS_USE_PACKET_SOCKET,
	/* sys_reboot()                                                */
	CCS_SYS_REBOOT,
	/* sys_vhangup()                                               */
	CCS_SYS_VHANGUP,
	/* do_settimeofday(), sys_adjtimex()                           */
	CCS_SYS_SETTIME,
	/* sys_nice(), sys_setpriority()                               */
	CCS_SYS_NICE,
	/* sys_sethostname(), sys_setdomainname()                      */
	CCS_SYS_SETHOSTNAME,
	/* sys_create_module(), sys_init_module(), sys_delete_module() */
	CCS_USE_KERNEL_MODULE,
	/* sys_kexec_load()                                            */
	CCS_SYS_KEXEC_LOAD,
	CCS_MAX_CAPABILITY_INDEX
};

#endif
