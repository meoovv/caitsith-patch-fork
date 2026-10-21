/*
 * security/caitsith/realpath.c
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 0.2.16   2026/09/28
 */

#include "internal.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
#include <linux/nsproxy.h>
#include <linux/mnt_namespace.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/proc_fs.h>
#endif

/***** SECTION1: Constants definition *****/

/***** SECTION2: Structure definition *****/

/***** SECTION3: Prototype definition section *****/

static char *cs_get_absolute_path(const struct path *path, char * const buffer,
				  const int buflen);
static char *cs_get_dentry_path(struct dentry *dentry, char * const buffer,
				const int buflen);
static char *cs_get_local_path(struct dentry *dentry, char * const buffer,
			       const int buflen);
static int cs_const_part_length(const char *filename);

/***** SECTION4: Standalone functions section *****/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)

/**
 * cs_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void cs_realpath_lock(void)
{
	/* dcache_lock is locked by __d_path(). */
	/* vfsmount_lock is locked by __d_path(). */
}

/**
 * cs_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void cs_realpath_unlock(void)
{
	/* vfsmount_lock is unlocked by __d_path(). */
	/* dcache_lock is unlocked by __d_path(). */
}

#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 36)

/**
 * cs_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void cs_realpath_lock(void)
{
	spin_lock(&dcache_lock);
	/* vfsmount_lock is locked by __d_path(). */
}

/**
 * cs_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void cs_realpath_unlock(void)
{
	/* vfsmount_lock is unlocked by __d_path(). */
	spin_unlock(&dcache_lock);
}

#elif defined(D_PATH_DISCONNECT) && !defined(CONFIG_SUSE_KERNEL)

/**
 * cs_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 *
 * Original unambiguous-__d_path.diff in patches.apparmor.tar.bz2 inversed the
 * order of holding dcache_lock and vfsmount_lock. That patch was applied on
 * (at least) SUSE 11.1 and Ubuntu 8.10 and Ubuntu 9.04 kernels.
 *
 * However, that patch was updated to use original order and the updated patch
 * is applied to (as far as I know) only SUSE kernels.
 *
 * Therefore, I need to use original order for SUSE 11.1 kernels and inversed
 * order for other kernels. I detect it by checking D_PATH_DISCONNECT and
 * CONFIG_SUSE_KERNEL. I don't know whether other distributions are using the
 * updated patch or not. If you got deadlock, check fs/dcache.c for locking
 * order, and add " && 0" to this "#elif " block if fs/dcache.c uses original
 * order.
 */
static inline void cs_realpath_lock(void)
{
	spin_lock(caitsith_exports.vfsmount_lock);
	spin_lock(&dcache_lock);
}

/**
 * cs_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void cs_realpath_unlock(void)
{
	spin_unlock(&dcache_lock);
	spin_unlock(caitsith_exports.vfsmount_lock);
}

#else

/**
 * cs_realpath_lock - Take locks for __d_path().
 *
 * Returns nothing.
 */
static inline void cs_realpath_lock(void)
{
	spin_lock(&dcache_lock);
	spin_lock(caitsith_exports.vfsmount_lock);
}

/**
 * cs_realpath_unlock - Release locks for __d_path().
 *
 * Returns nothing.
 */
static inline void cs_realpath_unlock(void)
{
	spin_unlock(caitsith_exports.vfsmount_lock);
	spin_unlock(&dcache_lock);
}

#endif

/***** SECTION5: Variables definition section *****/

/***** SECTION6: Dependent functions section *****/

/**
 * cs_get_absolute_path - Get the path of a dentry but ignores chroot'ed root.
 *
 * @path:   Pointer to "struct path".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 *
 * Caller holds the dcache_lock and vfsmount_lock.
 * Based on __d_path() in fs/dcache.c
 */
static char *cs_get_absolute_path(const struct path *path, char * const buffer,
				  const int buflen)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	if (buflen < 256)
		return ERR_PTR(-ENOMEM);
	return caitsith_exports.d_absolute_path(path, buffer, buflen - 1);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
	/*
	 * __d_path() will start returning NULL by backporting commit 02125a82
	 * "fix apparmor dereferencing potentially freed dentry, sanitize
	 * __d_path() API".
	 *
	 * Unfortunately, __d_path() after applying that commit always returns
	 * NULL when root is empty. d_absolute_path() is provided for TOMOYO
	 * 2.x and AppArmor but CaitSith does not use it, for CaitSith
	 * might be built as a loadable kernel module and there is no warrantee
	 * that CaitSith is recompiled after applying that commit. Also,
	 * I don't want to search /proc/kallsyms for d_absolute_path() because
	 * I want to keep CaitSith architecture independent. Thus, supply
	 * non empty root like AppArmor's d_namespace_path() did.
	 */
	static bool cs_no_empty;
	char *pos;

	if (buflen < 256)
		return ERR_PTR(-ENOMEM);
	if (!cs_no_empty) {
		struct path root = { };

		pos = caitsith_exports.__d_path(path, &root, buffer,
						buflen - 1);
	} else {
		pos = NULL;
	}
	if (!pos) {
		struct task_struct *task = current;
		struct path root;
		struct path tmp;

		spin_lock(&task->fs->lock);
		root.mnt = task->nsproxy->mnt_ns->root;
		root.dentry = root.mnt->mnt_root;
		path_get(&root);
		spin_unlock(&task->fs->lock);
		tmp = root;
		pos = caitsith_exports.__d_path(path, &tmp, buffer,
						buflen - 1);
		path_put(&root);
		if (pos)
			return pos;
		/* Remember if __d_path() needs non empty root. */
		cs_no_empty = true;
		pos = ERR_PTR(-EINVAL);
	}
	return pos;
#else
	char *pos = buffer + buflen - 1;
	struct dentry *dentry = path->dentry;
	struct vfsmount *vfsmnt = path->mnt;
	const char *name;
	int len;

	if (buflen < 256)
		goto out;

	*pos = '\0';
	for (;;) {
		struct dentry *parent;

		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			if (vfsmnt->mnt_parent == vfsmnt)
				break;
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		parent = dentry->d_parent;
		name = dentry->d_name.name;
		len = dentry->d_name.len;
		pos -= len;
		if (pos <= buffer)
			goto out;
		memmove(pos, name, len);
		*--pos = '/';
		dentry = parent;
	}
	if (*pos == '/')
		pos++;
	len = dentry->d_name.len;
	pos -= len;
	if (pos < buffer)
		goto out;
	memmove(pos, dentry->d_name.name, len);
	return pos;
out:
	return ERR_PTR(-ENOMEM);
#endif
}

/**
 * cs_get_dentry_path - Get the path of a dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 *
 * Based on dentry_path() in fs/dcache.c
 */
static char *cs_get_dentry_path(struct dentry *dentry, char * const buffer,
				const int buflen)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
	if (buflen < 256)
		return ERR_PTR(-ENOMEM);
	/* rename_lock is locked/unlocked by dentry_path_raw(). */
	return dentry_path_raw(dentry, buffer, buflen - 1);
#else
	char *pos = buffer + buflen - 1;

	if (buflen < 256)
		return ERR_PTR(-ENOMEM);
	*pos = '\0';
	spin_lock(&dcache_lock);
	while (!IS_ROOT(dentry)) {
		struct dentry *parent = dentry->d_parent;
		const char *name = dentry->d_name.name;
		const int len = dentry->d_name.len;

		pos -= len;
		if (pos <= buffer) {
			pos = ERR_PTR(-ENOMEM);
			break;
		}
		memmove(pos, name, len);
		*--pos = '/';
		dentry = parent;
	}
	spin_unlock(&dcache_lock);
	if (pos == buffer + buflen - 1)
		*--pos = '/';
	return pos;
#endif
}

/**
 * cs_get_local_path - Get the path of a dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 */
static char *cs_get_local_path(struct dentry *dentry, char * const buffer,
			       const int buflen)
{
	struct super_block *sb = dentry->d_sb;
	char *pos = cs_get_dentry_path(dentry, buffer, buflen);

	if (IS_ERR(pos))
		return pos;
	/* Convert from $PID to self if $PID is current thread. */
	if (sb->s_magic == PROC_SUPER_MAGIC && *pos == '/') {
		char *ep;
		const pid_t pid = (pid_t) simple_strtoul(pos + 1, &ep, 10);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
		if (*ep == '/' && pid && pid ==
		    task_tgid_nr_ns(current, proc_pid_ns(sb))) {
			pos = ep - 5;
			if (pos < buffer)
				goto out;
			memmove(pos, "/self", 5);
		}
#else
		if (*ep == '/' && pid && pid ==
		    task_tgid_nr_ns(current, sb->s_fs_info)) {
			pos = ep - 5;
			if (pos < buffer)
				goto out;
			memmove(pos, "/self", 5);
		}
#endif
		goto prepend_filesystem_name;
	}
	/* Use filesystem name for unnamed devices. */
	if (!MAJOR(sb->s_dev))
		goto prepend_filesystem_name;
	{
		struct inode *inode = d_backing_inode(sb->s_root);

		/*
		 * Use filesystem name if filesystems does not support rename()
		 * operation.
		 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
		if (inode->i_op && !inode->i_op->rename)
			goto prepend_filesystem_name;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		if (!inode->i_op->rename && !inode->i_op->rename2)
			goto prepend_filesystem_name;
#else
		if (!inode->i_op->rename)
			goto prepend_filesystem_name;
#endif
	}
	/* Prepend device name. */
	{
		char name[64];
		int name_len;
		const dev_t dev = sb->s_dev;

		name[sizeof(name) - 1] = '\0';
		snprintf(name, sizeof(name) - 1, "dev(%u,%u):", MAJOR(dev),
			 MINOR(dev));
		name_len = strlen(name);
		pos -= name_len;
		if (pos < buffer)
			goto out;
		memmove(pos, name, name_len);
		return pos;
	}
	/* Prepend filesystem name. */
prepend_filesystem_name:
	{
		const char *name = sb->s_type->name;
		const int name_len = strlen(name);

		pos -= name_len + 1;
		if (pos < buffer)
			goto out;
		memmove(pos, name, name_len);
		pos[name_len] = ':';
	}
	return pos;
out:
	return ERR_PTR(-ENOMEM);
}

/**
 * cs_realpath - Returns realpath(3) of the given pathname but ignores chroot'ed root.
 *
 * @path: Pointer to "struct path".
 *
 * Returns the realpath of the given @path on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *cs_realpath(const struct path *path)
{
	char *buf = NULL;
	char *name = NULL;
	unsigned int buf_len = PAGE_SIZE / 2;
	struct dentry *dentry = path->dentry;
	struct super_block *sb;

	if (!dentry)
		return NULL;
	sb = dentry->d_sb;
	while (1) {
		char *pos;
		struct inode *inode;

		buf_len <<= 1;
		kfree(buf);
		buf = kmalloc(buf_len, GFP_NOFS);
		if (!buf)
			break;
		/* To make sure that pos is '\0' terminated. */
		buf[buf_len - 1] = '\0';
		/* For "pipe:[\$]" and "socket:[\$]". */
		if (dentry->d_op && dentry->d_op->d_dname) {
			pos = dentry->d_op->d_dname(dentry, buf, buf_len - 1);
			goto encode;
		}
		inode = d_backing_inode(sb->s_root);
		/*
		 * Use local name for "filesystems without rename() operation
		 * and device file" or "path without vfsmount" or "absolute
		 * name is unavailable" cases.
		 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
		if (!path->mnt ||
		    (inode->i_op && !inode->i_op->rename &&
		     !(sb->s_type->fs_flags & FS_REQUIRES_DEV)))
			pos = ERR_PTR(-EINVAL);
		else {
			/* Get absolute name for the rest. */
			cs_realpath_lock();
			pos = cs_get_absolute_path(path, buf, buf_len - 1);
			cs_realpath_unlock();
		}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		if (!path->mnt ||
		    (!inode->i_op->rename && !inode->i_op->rename2 &&
		     !(sb->s_type->fs_flags & FS_REQUIRES_DEV)))
			pos = ERR_PTR(-EINVAL);
		else
			pos = cs_get_absolute_path(path, buf, buf_len - 1);
#else
		if (!path->mnt ||
		    (!inode->i_op->rename &&
		     !(sb->s_type->fs_flags & FS_REQUIRES_DEV)))
			pos = ERR_PTR(-EINVAL);
		else
			pos = cs_get_absolute_path(path, buf, buf_len - 1);
#endif
		if (pos == ERR_PTR(-EINVAL))
			pos = cs_get_local_path(path->dentry, buf,
						buf_len - 1);
encode:
		if (IS_ERR(pos))
			continue;
		name = cs_encode(pos);
		break;
	}
	kfree(buf);
	if (!name)
		cs_warn_oom(__func__);
	return name;
}

/**
 * cs_encode2 - Encode binary string to ascii string.
 *
 * @str:     String in binary format. Maybe NULL.
 * @str_len: Size of @str in byte.
 *
 * Returns pointer to @str in ascii format on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *cs_encode2(const char *str, int str_len)
{
	int i;
	int len;
	const char *p = str;
	char *cp;
	char *cp0;

	if (!p)
		return NULL;
	len = str_len;
	for (i = 0; i < str_len; i++) {
		const unsigned char c = p[i];

		if (!(c > ' ' && c < 127 && c != '\\'))
			len += 3;
	}
	len++;
	cp = kzalloc(len, GFP_NOFS);
	if (!cp)
		return NULL;
	cp0 = cp;
	p = str;
	for (i = 0; i < str_len; i++) {
		const unsigned char c = p[i];

		if (c > ' ' && c < 127 && c != '\\') {
			*cp++ = c;
		} else {
			*cp++ = '\\';
			*cp++ = (c >> 6) + '0';
			*cp++ = ((c >> 3) & 7) + '0';
			*cp++ = (c & 7) + '0';
		}
	}
	return cp0;
}

/**
 * cs_encode - Encode binary string to ascii string.
 *
 * @str: String in binary format. Maybe NULL.
 *
 * Returns pointer to @str in ascii format on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
char *cs_encode(const char *str)
{
	return str ? cs_encode2(str, strlen(str)) : NULL;
}

/**
 * cs_const_part_length - Evaluate the initial length without a pattern in a token.
 *
 * @filename: The string to evaluate. Maybe NULL.
 *
 * Returns the initial length without a pattern in @filename.
 */
static int cs_const_part_length(const char *filename)
{
	char c;
	int len = 0;

	if (!filename)
		return 0;
	while (1) {
		c = *filename++;
		if (!c)
			break;
		if (c != '\\') {
			len++;
			continue;
		}
		c = *filename++;
		switch (c) {
		case '0':   /* "\ooo" */
		case '1':
		case '2':
		case '3':
			c = *filename++;
			if (c < '0' || c > '7')
				break;
			c = *filename++;
			if (c < '0' || c > '7')
				break;
			len += 4;
			continue;
		}
		break;
	}
	return len;
}

/**
 * cs_fill_path_info - Fill in "struct cs_path_info" members.
 *
 * @ptr: Pointer to "struct cs_path_info" to fill in.
 *
 * Returns nothing.
 *
 * The caller sets "struct cs_path_info"->name.
 */
void cs_fill_path_info(struct cs_path_info *ptr)
{
	const char *name = ptr->name;
	const int len = strlen(name);

	ptr->total_len = len;
	ptr->const_len = cs_const_part_length(name);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	ptr->hash = full_name_hash(NULL, name, len);
#else
	ptr->hash = full_name_hash(name, len);
#endif
}

/**
 * cs_get_exe - Get cs_realpath() of current process.
 *
 * Returns the cs_realpath() of current process on success, NULL otherwise.
 *
 * This function uses kzalloc(), so the caller must kfree()
 * if this function didn't return NULL.
 */
char *cs_get_exe(void)
{
	struct mm_struct *mm;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	struct vm_area_struct *vma;
#endif
	struct file *exe_file;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
	if (current->flags & PF_KTHREAD)
		return kstrdup("<kernel>", GFP_NOFS);
#else
	if (segment_eq(get_fs(), KERNEL_DS))
		return kstrdup("<kernel>", GFP_NOFS);
#endif
	mm = current->mm;
	if (!mm)
		goto task_has_no_mm;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0) || (defined(RHEL_MAJOR) && RHEL_MAJOR == 9)
	/* Not using get_mm_exe_file() as it is not exported. */
	rcu_read_lock();
	exe_file = rcu_dereference(mm->exe_file);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
	if (exe_file && !get_file_rcu(&exe_file))
		exe_file = NULL;
#else
	if (exe_file && !get_file_rcu(exe_file))
		exe_file = NULL;
#endif
	rcu_read_unlock();
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	exe_file = get_mm_exe_file(mm);
#else
	down_read(&mm->mmap_sem);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)
	/* Not using get_mm_exe_file() as it is not exported. */
	exe_file = mm->exe_file;
#else
	exe_file = NULL;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
			exe_file = vma->vm_file;
			break;
		}
	}
#endif
	if (exe_file)
		get_file(exe_file);
	up_read(&mm->mmap_sem);
#endif
	if (exe_file) {
		char *cp = cs_realpath(&exe_file->f_path);

		fput(exe_file);
		return cp;
	}
task_has_no_mm:
	/* I'don't know. */
	return kstrdup("<unknown>", GFP_NOFS);
}

/**
 * cs_get_exename - Get cs_realpath() of current process.
 *
 * @buf: Pointer to "struct cs_path_info".
 *
 * Returns true on success, false otherwise.
 *
 * This function uses kzalloc(), so the caller must kfree()
 * if this function returned true.
 */
bool cs_get_exename(struct cs_path_info *buf)
{
	buf->name = cs_get_exe();
	if (buf->name) {
		cs_fill_path_info(buf);
		return true;
	}
	return false;
}
