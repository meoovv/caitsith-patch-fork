/*
 * security/caitsith/internal.h
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 0.2.16   2026/09/28
 */

#ifndef _SECURITY_CAITSITH_INTERNAL_H
#define _SECURITY_CAITSITH_INTERNAL_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#error This module supports only 2.6.27 and later kernels.
#endif
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/utime.h>
#include <linux/file.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 38)
#include <linux/smp_lock.h>
#endif
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/poll.h>
#include <linux/binfmts.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <linux/ptrace.h>
#include <linux/namei.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
#include <linux/fs_struct.h>
#endif
#include <linux/hash.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33) && defined(CONFIG_SYSCTL_SYSCALL)
#include <linux/sysctl.h>
#endif
#include <linux/kthread.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/magic.h>
#endif
#include <linux/uaccess.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif
#include <net/sock.h>
#include <net/af_unix.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>
#include <linux/ctype.h>
#include <linux/magic.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0) || (defined(RHEL_MAJOR) && RHEL_MAJOR >= 8 && defined(RHEL_MINOR) && RHEL_MINOR >= 4)
#include <uapi/linux/mount.h>
#endif

#ifndef fallthrough
#define fallthrough do {} while (0)
#endif

#ifndef current_uid
#define current_uid()   (current->uid)
#endif
#ifndef current_gid
#define current_gid()   (current->gid)
#endif
#ifndef current_euid
#define current_euid()  (current->euid)
#endif
#ifndef current_egid
#define current_egid()  (current->egid)
#endif
#ifndef current_suid
#define current_suid()  (current->suid)
#endif
#ifndef current_sgid
#define current_sgid()  (current->sgid)
#endif
#ifndef current_fsuid
#define current_fsuid() (current->fsuid)
#endif
#ifndef current_fsgid
#define current_fsgid() (current->fsgid)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
#define d_inode(dentry) (dentry)->d_inode
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)

/**
 * __list_del_entry - Deletes entry from list without re-initialization.
 *
 * @entry: Pointer to "struct list_head".
 *
 * Returns nothing.
 *
 * This is for compatibility with older kernels.
 */
static inline void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

#endif

#ifndef list_for_each_entry_safe

/**
 * list_for_each_entry_safe - Iterate over list of given type safe against removal of list entry.
 *
 * @pos:    The "type *" to use as a loop cursor.
 * @n:      Another "type *" to use as temporary storage.
 * @head:   Pointer to "struct list_head".
 * @member: The name of the list_struct within the struct.
 *
 * This is for compatibility with older kernels.
 */
#define list_for_each_entry_safe(pos, n, head, member)                  \
	for (pos = list_entry((head)->next, typeof(*pos), member),      \
		     n = list_entry(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#endif

#ifndef srcu_dereference

/**
 * srcu_dereference - Fetch SRCU-protected pointer with checking.
 *
 * @p:  The pointer to read, prior to dereferencing.
 * @ss: Pointer to "struct srcu_struct".
 *
 * Returns @p.
 *
 * This is for compatibility with older kernels.
 */
#define srcu_dereference(p, ss) rcu_dereference(p)

#endif

#ifndef list_for_each_entry_srcu

/**
 * list_for_each_entry_srcu - Iterate over rcu list of given type.
 *
 * @pos:    The type * to use as a loop cursor.
 * @head:   The head for your list.
 * @member: The name of the list_struct within the struct.
 * @ss:     Pointer to "struct srcu_struct".
 *
 * As of 3.8, this macro is not provided because only CaitSith wants it.
 */
#define list_for_each_entry_srcu(pos, head, member, ss)			\
	for (pos = list_entry(srcu_dereference((head)->next, ss),	\
			      typeof(*pos), member);			\
	     prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry(srcu_dereference(pos->member.next, ss),	\
			      typeof(*pos), member))

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)

/**
 * from_kuid - Convert kuid_t to uid_t.
 *
 * @ns:  Unused.
 * @uid: kuid_t value.
 *
 * Returns uid seen from init's user namespace.
 */
#define from_kuid(ns, uid) (uid)

/**
 * from_kgid - Convert kgid_t to gid_t.
 *
 * @ns:  Unused.
 * @gid: kgid_t value.
 *
 * Returns gid seen from init's user namespace.
 */
#define from_kgid(ns, gid) (gid)

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#define d_backing_inode(upper) ((upper)->d_inode)
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
#define d_is_dir(dentry) ({ struct inode *inode = d_backing_inode(dentry); \
			inode && S_ISDIR(inode->i_mode); })
#endif

/*
 * TOMOYO specific part start.
 */

#include <linux/caitsith.h>

/* Enumeration definition for internal use. */

/* Index numbers for "struct cs_condition". */
enum cs_conditions_index {
	/* 0 */
	CS_INVALID_CONDITION,
	CS_SELF_UID,             /* current_uid()   */
	CS_SELF_EUID,            /* current_euid()  */
	CS_SELF_SUID,            /* current_suid()  */
	CS_SELF_FSUID,           /* current_fsuid() */
	CS_SELF_GID,             /* current_gid()   */
	CS_SELF_EGID,            /* current_egid()  */
	CS_SELF_SGID,            /* current_sgid()  */
	CS_SELF_FSGID,           /* current_fsgid() */
	CS_SELF_PID,             /* sys_getpid()   */
	/* 10 */
	CS_SELF_PPID,            /* sys_getppid()  */
	CS_TASK_TYPE,            /*
				  * ((u8) task->cs_flags) &
				  *  CS_TASK_IS_EXECUTE_HANDLER
				  */
	CS_SELF_DOMAIN,
	CS_SELF_ACL_GROUP,
	CS_SELF_EXE,
	CS_EXEC_ARGC,            /* "struct linux_binprm *"->argc */
	CS_EXEC_ENVC,            /* "struct linux_binprm *"->envc */
	CS_OBJ_IS_SOCKET,        /* S_IFSOCK */
	CS_OBJ_IS_SYMLINK,       /* S_IFLNK */
	CS_OBJ_IS_FILE,          /* S_IFREG */
	/* 20 */
	CS_OBJ_IS_BLOCK_DEV,     /* S_IFBLK */
	CS_OBJ_IS_DIRECTORY,     /* S_IFDIR */
	CS_OBJ_IS_CHAR_DEV,      /* S_IFCHR */
	CS_OBJ_IS_FIFO,          /* S_IFIFO */
	CS_MODE_SETUID,          /* S_ISUID */
	CS_MODE_SETGID,          /* S_ISGID */
	CS_MODE_STICKY,          /* S_ISVTX */
	CS_MODE_OWNER_READ,      /* S_IRUSR */
	CS_MODE_OWNER_WRITE,     /* S_IWUSR */
	CS_MODE_OWNER_EXECUTE,   /* S_IXUSR */
	/* 30 */
	CS_MODE_GROUP_READ,      /* S_IRGRP */
	CS_MODE_GROUP_WRITE,     /* S_IWGRP */
	CS_MODE_GROUP_EXECUTE,   /* S_IXGRP */
	CS_MODE_OTHERS_READ,     /* S_IROTH */
	CS_MODE_OTHERS_WRITE,    /* S_IWOTH */
	CS_MODE_OTHERS_EXECUTE,  /* S_IXOTH */
	CS_TASK_EXECUTE_HANDLER, /* CS_TASK_IS_EXECUTE_HANDLER */
	CS_HANDLER_PATH,
	CS_ACL_GROUP,
	CS_TRANSIT_DOMAIN,
	/* 40 */
	CS_COND_SARG0,
	CS_COND_SARG1,
	CS_COND_SARG2,
	CS_COND_SARG3,
	CS_COND_NARG0,
	CS_COND_NARG1,
	CS_COND_NARG2,
	CS_COND_IPARG,
	CS_COND_DOMAIN,
	CS_IMM_GROUP,
	/* 50 */
	CS_IMM_NAME_ENTRY,
	CS_IMM_NUMBER_ENTRY1,
	CS_IMM_NUMBER_ENTRY2,
#ifdef CONFIG_CAITSITH_NETWORK
	CS_IMM_IPV4ADDR_ENTRY1,
	CS_IMM_IPV4ADDR_ENTRY2,
	CS_IMM_IPV6ADDR_ENTRY1,
	CS_IMM_IPV6ADDR_ENTRY2,
#endif
	CS_ARGV_ENTRY,
	CS_ENVP_ENTRY,
	CS_PATH_ATTRIBUTE_START = 192,
	CS_PATH_ATTRIBUTE_END = 255
} __packed;

enum cs_path_attribute_index {
	CS_PATH_ATTRIBUTE_UID,
	CS_PATH_ATTRIBUTE_GID,
	CS_PATH_ATTRIBUTE_INO,
	CS_PATH_ATTRIBUTE_TYPE,
	CS_PATH_ATTRIBUTE_MAJOR,
	CS_PATH_ATTRIBUTE_MINOR,
	CS_PATH_ATTRIBUTE_PERM,
	CS_PATH_ATTRIBUTE_DEV_MAJOR,
	CS_PATH_ATTRIBUTE_DEV_MINOR,
	CS_PATH_ATTRIBUTE_FSMAGIC,
	CS_MAX_PATH_ATTRIBUTE
} __packed;

/* Index numbers for group entries. */
enum cs_group_id {
	CS_STRING_GROUP,
	CS_NUMBER_GROUP,
#ifdef CONFIG_CAITSITH_NETWORK
	CS_IP_GROUP,
#endif
	CS_MAX_GROUP
} __packed;

/* Index numbers for functionality. */
enum cs_mac_index {
	CS_MAC_EXECUTE,
	CS_MAC_READ,
	CS_MAC_WRITE,
	CS_MAC_APPEND,
	CS_MAC_CREATE,
	CS_MAC_UNLINK,
#ifdef CONFIG_CAITSITH_GETATTR
	CS_MAC_GETATTR,
#endif
	CS_MAC_MKDIR,
	CS_MAC_RMDIR,
	CS_MAC_MKFIFO,
	CS_MAC_MKSOCK,
	CS_MAC_TRUNCATE,
	CS_MAC_SYMLINK,
	CS_MAC_MKBLOCK,
	CS_MAC_MKCHAR,
	CS_MAC_LINK,
	CS_MAC_RENAME,
	CS_MAC_CHMOD,
	CS_MAC_CHOWN,
	CS_MAC_CHGRP,
	CS_MAC_IOCTL,
	CS_MAC_CHROOT,
	CS_MAC_MOUNT,
	CS_MAC_UMOUNT,
	CS_MAC_PIVOT_ROOT,
#ifdef CONFIG_CAITSITH_NETWORK
	CS_MAC_INET_STREAM_BIND,
	CS_MAC_INET_STREAM_LISTEN,
	CS_MAC_INET_STREAM_CONNECT,
	CS_MAC_INET_STREAM_ACCEPT,
	CS_MAC_INET_DGRAM_BIND,
	CS_MAC_INET_DGRAM_SEND,
#ifdef CONFIG_CAITSITH_NETWORK_RECVMSG
	CS_MAC_INET_DGRAM_RECV,
#endif
	CS_MAC_INET_RAW_BIND,
	CS_MAC_INET_RAW_SEND,
#ifdef CONFIG_CAITSITH_NETWORK_RECVMSG
	CS_MAC_INET_RAW_RECV,
#endif
	CS_MAC_UNIX_STREAM_BIND,
	CS_MAC_UNIX_STREAM_LISTEN,
	CS_MAC_UNIX_STREAM_CONNECT,
	CS_MAC_UNIX_STREAM_ACCEPT,
	CS_MAC_UNIX_DGRAM_BIND,
	CS_MAC_UNIX_DGRAM_SEND,
#ifdef CONFIG_CAITSITH_NETWORK_RECVMSG
	CS_MAC_UNIX_DGRAM_RECV,
#endif
	CS_MAC_UNIX_SEQPACKET_BIND,
	CS_MAC_UNIX_SEQPACKET_LISTEN,
	CS_MAC_UNIX_SEQPACKET_CONNECT,
	CS_MAC_UNIX_SEQPACKET_ACCEPT,
#endif
#ifdef CONFIG_CAITSITH_ENVIRON
	CS_MAC_ENVIRON,
#endif
#ifdef CONFIG_CAITSITH_PTRACE
	CS_MAC_PTRACE,
#endif
#ifdef CONFIG_CAITSITH_SIGNAL
	CS_MAC_SIGNAL,
#endif
	CS_MAC_MODIFY_POLICY,
#ifdef CONFIG_CAITSITH_CAPABILITY
	CS_MAC_USE_NETLINK_SOCKET,
	CS_MAC_USE_PACKET_SOCKET,
	CS_MAC_USE_REBOOT,
	CS_MAC_USE_VHANGUP,
	CS_MAC_SET_TIME,
	CS_MAC_SET_PRIORITY,
	CS_MAC_SET_HOSTNAME,
	CS_MAC_USE_KERNEL_MODULE,
	CS_MAC_USE_NEW_KERNEL,
#endif
#ifdef CONFIG_CAITSITH_AUTO_DOMAIN_TRANSITION
	CS_MAC_AUTO_DOMAIN_TRANSITION,
#endif
#ifdef CONFIG_CAITSITH_MANUAL_DOMAIN_TRANSITION
	CS_MAC_MANUAL_DOMAIN_TRANSITION,
#endif
	CS_MAX_MAC_INDEX,
	/* Map undefined functions to CS_MAX_MAC_INDEX */
#ifndef CONFIG_CAITSITH_GETATTR
	CS_MAC_GETATTR = CS_MAX_MAC_INDEX,
#endif
#ifndef CONFIG_CAITSITH_NETWORK
	CS_MAC_INET_STREAM_BIND = CS_MAX_MAC_INDEX,
	CS_MAC_INET_STREAM_LISTEN = CS_MAX_MAC_INDEX,
	CS_MAC_INET_STREAM_CONNECT = CS_MAX_MAC_INDEX,
	CS_MAC_INET_STREAM_ACCEPT = CS_MAX_MAC_INDEX,
	CS_MAC_INET_DGRAM_BIND = CS_MAX_MAC_INDEX,
	CS_MAC_INET_DGRAM_SEND = CS_MAX_MAC_INDEX,
	CS_MAC_INET_RAW_BIND = CS_MAX_MAC_INDEX,
	CS_MAC_INET_RAW_SEND = CS_MAX_MAC_INDEX,
	CS_MAC_UNIX_STREAM_BIND = CS_MAX_MAC_INDEX,
	CS_MAC_UNIX_STREAM_LISTEN = CS_MAX_MAC_INDEX,
	CS_MAC_UNIX_STREAM_CONNECT = CS_MAX_MAC_INDEX,
	CS_MAC_UNIX_STREAM_ACCEPT = CS_MAX_MAC_INDEX,
	CS_MAC_UNIX_DGRAM_BIND = CS_MAX_MAC_INDEX,
	CS_MAC_UNIX_DGRAM_SEND = CS_MAX_MAC_INDEX,
	CS_MAC_UNIX_SEQPACKET_BIND = CS_MAX_MAC_INDEX,
	CS_MAC_UNIX_SEQPACKET_LISTEN = CS_MAX_MAC_INDEX,
	CS_MAC_UNIX_SEQPACKET_CONNECT = CS_MAX_MAC_INDEX,
	CS_MAC_UNIX_SEQPACKET_ACCEPT = CS_MAX_MAC_INDEX,
#endif
#ifndef CONFIG_CAITSITH_NETWORK_RECVMSG
	CS_MAC_INET_DGRAM_RECV = CS_MAX_MAC_INDEX,
	CS_MAC_INET_RAW_RECV = CS_MAX_MAC_INDEX,
	CS_MAC_UNIX_DGRAM_RECV = CS_MAX_MAC_INDEX,
#endif
#ifndef CONFIG_CAITSITH_ENVIRON
	CS_MAC_ENVIRON = CS_MAX_MAC_INDEX,
#endif
#ifndef CONFIG_CAITSITH_PTRACE
	CS_MAC_PTRACE = CS_MAX_MAC_INDEX,
#endif
#ifndef CONFIG_CAITSITH_SIGNAL
	CS_MAC_SIGNAL = CS_MAX_MAC_INDEX,
#endif
#ifndef CONFIG_CAITSITH_CAPABILITY
	CS_MAC_USE_NETLINK_SOCKET = CS_MAX_MAC_INDEX,
	CS_MAC_USE_PACKET_SOCKET = CS_MAX_MAC_INDEX,
	CS_MAC_USE_REBOOT = CS_MAX_MAC_INDEX,
	CS_MAC_USE_VHANGUP = CS_MAX_MAC_INDEX,
	CS_MAC_SET_TIME = CS_MAX_MAC_INDEX,
	CS_MAC_SET_PRIORITY = CS_MAX_MAC_INDEX,
	CS_MAC_SET_HOSTNAME = CS_MAX_MAC_INDEX,
	CS_MAC_USE_KERNEL_MODULE = CS_MAX_MAC_INDEX,
	CS_MAC_USE_NEW_KERNEL = CS_MAX_MAC_INDEX,
#endif
#ifndef CONFIG_CAITSITH_AUTO_DOMAIN_TRANSITION
	CS_MAC_AUTO_DOMAIN_TRANSITION = CS_MAX_MAC_INDEX,
#endif
#ifndef CONFIG_CAITSITH_MANUAL_DOMAIN_TRANSITION
	CS_MAC_MANUAL_DOMAIN_TRANSITION = CS_MAX_MAC_INDEX,
#endif
} __packed;

/* Index numbers for statistic information. */
enum cs_memory_stat_type {
	CS_MEMORY_POLICY,
	CS_MEMORY_AUDIT,
	CS_MEMORY_QUERY,
	CS_MAX_MEMORY_STAT
} __packed;

enum cs_matching_result {
	CS_MATCHING_UNMATCHED,
	CS_MATCHING_ALLOWED,
	CS_MATCHING_DENIED,
	CS_MAX_MATCHING
} __packed;

/* Index numbers for stat(). */
enum cs_path_stat_index {
	/* Do not change this order. */
	CS_PATH1,
	CS_PATH1_PARENT,
	CS_PATH2,
	CS_PATH2_PARENT,
	CS_MAX_PATH_STAT
} __packed;

/* Index numbers for entry type. */
enum cs_policy_id {
	CS_ID_GROUP,
#ifdef CONFIG_CAITSITH_NETWORK
	CS_ID_IP_GROUP,
#endif
	CS_ID_STRING_GROUP,
	CS_ID_NUMBER_GROUP,
	CS_ID_CONDITION,
	CS_ID_NAME,
	CS_ID_ACL,
	CS_ID_DOMAIN,
	CS_ID_ACL_GROUPS,
	CS_MAX_POLICY
} __packed;

/* Index numbers for statistic information. */
enum cs_policy_stat_type {
	CS_STAT_POLICY_UPDATES,
	CS_STAT_REQUEST_DENIED,
	CS_MAX_POLICY_STAT
} __packed;

/* Index numbers for /sys/kernel/security/caitsith/ interfaces. */
enum cs_securityfs_interface_index {
	CS_POLICY,
	CS_PROCESS_STATUS,
	CS_AUDIT,
	CS_VERSION,
	CS_QUERY,
#ifdef CONFIG_CAITSITH_EXECUTE_HANDLER
	CS_EXECUTE_HANDLER,
#endif
} __packed;

/* Index numbers for special mount operations. */
enum cs_special_mount {
	CS_MOUNT_BIND,            /* mount --bind /source /dest   */
	CS_MOUNT_MOVE,            /* mount --move /old /new       */
	CS_MOUNT_REMOUNT,         /* mount -o remount /dir        */
	CS_MOUNT_MAKE_UNBINDABLE, /* mount --make-unbindable /dir */
	CS_MOUNT_MAKE_PRIVATE,    /* mount --make-private /dir    */
	CS_MOUNT_MAKE_SLAVE,      /* mount --make-slave /dir      */
	CS_MOUNT_MAKE_SHARED,     /* mount --make-shared /dir     */
	CS_MAX_SPECIAL_MOUNT
} __packed;

/* Index numbers for type of numeric values. */
enum cs_value_type {
	CS_VALUE_TYPE_INVALID,
	CS_VALUE_TYPE_DECIMAL,
	CS_VALUE_TYPE_OCTAL,
	CS_VALUE_TYPE_HEXADECIMAL,
} __packed;

/* Constants definition for internal use. */

/*
 * TOMOYO uses this hash only when appending a string into the string table.
 * Frequency of appending strings is very low. So we don't need large (e.g.
 * 64k) hash size. 256 will be sufficient.
 */
#define CS_HASH_BITS 8
#define CS_MAX_HASH (1u << CS_HASH_BITS)

#define CS_MAX_ACL_GROUPS 60
#define CS_ACL_GROUPS_INLINE 4

/*
 * TOMOYO checks only SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET.
 * Therefore, we don't need SOCK_MAX.
 */
#define CS_SOCK_MAX 6

/* Size of temporary buffer for execve() operation. */
#define CS_EXEC_TMPSIZE     4096

/* Patterns for auditing logs quota. */
#define CS_MAX_LOG_QUOTA 256

/* Garbage collector is trying to kfree() this element. */
#define CS_GC_IN_PROGRESS -1

/* Current thread is doing open(3) ? */
#define CS_OPEN_FOR_IOCTL_ONLY           2
/* Current thread is doing do_execve() ? */
#define CS_TASK_IS_IN_EXECVE             4
/* Current thread is running as an execute handler program? */
#define CS_TASK_IS_EXECUTE_HANDLER       8
/*
 * Current thread is allowed to modify policy via
 * /sys/kernel/security/caitsith/ interface?
 */
#define CS_TASK_IS_MANAGER              16

/*
 * Retry this request. Returned by cs_supervisor() if policy violation has
 * occurred in enforcing mode and the userspace daemon decided to retry.
 *
 * We must choose a positive value in order to distinguish "granted" (which is
 * 0) and "rejected" (which is a negative value) and "retry".
 */
#define CS_RETRY_REQUEST 1

/* Size of read buffer for /sys/kernel/security/caitsith/ interface. */
#define CS_MAX_IO_READ_QUEUE 64

/* Structure definition for internal use. */

/* Common header for holding ACL entries. */
struct cs_acl_head {
	struct list_head list;
	s8 is_deleted; /* true or false or CS_GC_IN_PROGRESS */
} __packed;

/* Common header for shared entries. */
struct cs_shared_acl_head {
	struct list_head list;
	atomic_t users;
} __packed;

/* Common header for individual entries. */
struct cs_acl_info {
	struct list_head list;
	struct list_head acl_info_list;
	struct cs_condition *cond; /* Maybe NULL. */
	bool is_deleted;
	bool is_deny;
	u16 priority;
	u8 audit;
};


extern struct list_head cs_acl_groups_list;

/* Structure for "string_group"/"number_group"/"ip_group" directive. */
struct cs_group {
	struct cs_shared_acl_head head;
	/* Name of group (without leading "@"). */
	const struct cs_path_info *group_name;
	/*
	 * List of "struct cs_string_group" or "struct cs_number_group" or
	 * "struct cs_ip_group".
	 */
	struct list_head member_list;
};

/* Structure for "string_group" directive. */
struct cs_string_group {
	struct cs_acl_head head;
	const struct cs_path_info *member_name;
};

/* Structure for "number_group" directive. */
struct cs_number_group {
	struct cs_acl_head head;
	u8 radix;
	unsigned long value[2];
};

/* Structure for "ip_group" directive. */
struct cs_ip_group {
	struct cs_acl_head head;
	bool is_ipv6;
	/* Structure for holding an IP address. */
	struct in6_addr ip[2]; /* Big endian. */
};

/* Subset of "struct stat". Used by conditional ACL and audit logs. */
struct cs_mini_stat {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	kuid_t uid;
	kgid_t gid;
#else
	uid_t uid;
	gid_t gid;
#endif
	u64 ino;
	umode_t mode;
	dev_t dev;
	dev_t rdev;
	unsigned long fsmagic;
};

/* Structure for dumping argv[] and envp[] of "struct linux_binprm". */
struct cs_page_dump {
	struct page *page;    /* Previously dumped page. */
	char *data;           /* Contents of "page". Size is PAGE_SIZE. */
};

/* Structure for entries which follows "struct cs_condition". */
union cs_condition_element {
	struct {
		enum cs_conditions_index left;
		enum cs_conditions_index right;
		bool is_not;
		u8 radix;
	};
	struct cs_group *group;
	const struct cs_path_info *path;
	u32 ip; /* Repeat 4 times if IPv6 address. */
	unsigned long value;
};

/* Structure for optional arguments. */
struct cs_condition {
	struct cs_shared_acl_head head;
	u32 size; /* Memory size allocated for this entry. */
	/* union cs_condition_element condition[]; */
};

/* Structure for holding a token. */
struct cs_path_info {
	const char *name;
	u32 hash;          /* = full_name_hash(name, strlen(name)) */
	u32 total_len;     /* = strlen(name)                       */
	u32 const_len;     /* = cs_const_part_length(name)        */
};

/* Structure for request info. */
struct cs_request_info {
	/* For holding parameters. */
	struct cs_request_param {
		const struct cs_path_info *s[4];
		unsigned long i[3];
#ifdef CONFIG_CAITSITH_NETWORK
		const u8 *ip; /* Big endian. */
		bool is_ipv6;
#endif
	} param;
	/* For holding pathnames and attributes. */
	struct {
		/*
		 * True if cs_get_attributes() was already called, false
		 * otherwise.
		 */
		bool validate_done;
		/* True if @stat[] is valid. */
		bool stat_valid[CS_MAX_PATH_STAT];
		/* Pointer to file objects. */
		struct path path[2];
		/*
		 * Information on @path[0], @path[0]'s parent directory,
		 * @path[1] and @path[1]'s parent directory.
		 */
		struct cs_mini_stat stat[CS_MAX_PATH_STAT];
		/*
		 * Name of @path[0] and @path[1].
		 * Cleared by cs_clear_request_info().
		 */
		struct cs_path_info pathname[2];
	} obj;
	struct {
		struct linux_binprm *bprm;
		struct cs_domain_info *previous_domain;
		struct cs_acl_groups *previous_acl_groups;
		/* For execute_handler. */
		char *handler; /* kstrdup(handler_path->name, GFP_NOFS) */
		/* For dumping argv[] and envp[]. */
		struct cs_page_dump dump;
		/* For temporary use. Size is CS_EXEC_TMPSIZE bytes. */
		char *tmp;
	};
	/*
	 * Name of current thread's executable.
	 * Cleared by cs_clear_request_info().
	 */
	struct cs_path_info exename;
	/*
	 * Matching "struct cs_acl_info" is copied. Used for caitsith-queryd.
	 * Valid until cs_read_unlock().
	 */
	struct cs_acl_info *matched_acl;
	/*
	 * Matching handler and domain transition are copied.
	 * Valid until cs_read_unlock().
	 */
	const struct cs_path_info *handler_path;
	const struct cs_path_info *transition;
	const struct cs_path_info *handler_path_candidate;
	const struct cs_path_info *transition_candidate;


	const struct cs_path_info *acl_group_candidates[CS_ACL_GROUPS_INLINE];
	const struct cs_path_info **acl_group_candidates_ext;
	u8 acl_group_count;
	struct cs_acl_groups *acl_groups;


	/*
	 * For holding operation index used for this request.
	 * One of values in "enum cs_mac_index".
	 */
	enum cs_mac_index type;
	/* For holding matching result. */
	enum cs_matching_result result;
	/*
	 * For counting number of retries made for this request.
	 * This counter is incremented whenever cs_supervisor() returned
	 * CS_RETRY_REQUEST.
	 */
	u8 retry;
	/* For holding max audit log count for this matching entry. */
	u8 audit;
	/*
	 * Set to true if condition could not be checked due to out of memory.
	 * This flag is used for returning out of memory flag back to
	 * cs_check_acl_list(). Thus, this flag will not be set if out of
	 * memory occurred before cs_check_acl_list() is called.
	 */
	bool failed_by_oom;
};

/* Structure for domain information. */
struct cs_domain_info {
	struct list_head list;
	/* Name of this domain. Never NULL. */
	const struct cs_path_info *domainname;
};

struct cs_acl_groups {
	struct cs_shared_acl_head head;
	u8 len;
	const struct cs_path_info *names[];	
};


/* Structure for holding string data. */
struct cs_name {
	struct cs_shared_acl_head head;
	int size; /* Memory size allocated for this entry. */
	struct cs_path_info entry;
};

/*
 * Structure for reading/writing policy via /sys/kernel/security/caitsith/
 * interfaces.
 */
struct cs_io_buffer {
	/* Exclusive lock for this structure.   */
	struct mutex io_sem;
	char __user *read_user_buf;
	size_t read_user_buf_avail;
	struct {
		struct list_head *group;
		struct list_head *acl;
		struct list_head *subacl;
		const union cs_condition_element *cond;
		size_t avail;
		unsigned int step;
		unsigned int query_index;
		u16 index;
		u8 cond_step;
		u8 w_pos;
		enum cs_mac_index acl_index;
		bool eof;
		bool print_this_acl_only;
		bool version_done;
		bool stat_done;
		bool quota_done;
		bool group_done;
		const char *w[CS_MAX_IO_READ_QUEUE];
	} r;
	struct {
		char *data;
		struct cs_acl_info *acl;
		size_t avail;
		enum cs_mac_index acl_index;
		bool is_delete;
		bool is_deny;
		u16 priority;
	} w;
	/* Buffer for reading.                  */
	char *read_buf;
	/* Size of read buffer.                 */
	size_t readbuf_size;
	/* Buffer for writing.                  */
	char *write_buf;
	/* Size of write buffer.                */
	size_t writebuf_size;
	/* Type of interface. */
	enum cs_securityfs_interface_index type;
	/* Users counter protected by cs_io_buffer_list_lock. */
	u8 users;
	/* List for telling GC not to kfree() elements. */
	struct list_head list;
};

/* Structure for representing YYYY/MM/DD hh/mm/ss. */
struct cs_time {
	u16 year;
	u8 month;
	u8 day;
	u8 hour;
	u8 min;
	u8 sec;
};

/* Prototype definition for "struct caitsith_operations". */

void __init cs_permission_init(void);
void __init cs_mm_init(void);

/* Prototype definition for internal use. */

bool cs_dump_page(struct linux_binprm *bprm, unsigned long pos,
		  struct cs_page_dump *dump);
bool cs_get_exename(struct cs_path_info *buf);
bool cs_manager(void);
bool cs_transit_domain(const char *domainname);
char *cs_encode(const char *str);
char *cs_encode2(const char *str, int str_len);
char *cs_realpath(const struct path *path);
char *cs_get_exe(void);
int cs_audit_log(struct cs_request_info *r);
int cs_check_acl(struct cs_request_info *r, const bool clear);
void cs_del_condition(struct list_head *element);
void cs_fill_path_info(struct cs_path_info *ptr);
void cs_get_attributes(struct cs_request_info *r);
void cs_notify_gc(struct cs_io_buffer *head, const bool is_register);
void cs_populate_patharg(struct cs_request_info *r, const bool first);
void cs_transition_failed(const char *domainname);
void cs_warn_oom(const char *function);

void cs_clear_request_info(struct cs_request_info *r);
void cs_kick_gc(void);
bool cs_memory_ok(const void *ptr);

/* Variable definition for internal use. */

extern bool cs_policy_loaded;
extern struct cs_domain_info cs_kernel_domain;
extern struct cs_path_info cs_null_name;
extern struct list_head cs_acl_list[CS_MAX_MAC_INDEX];
extern struct list_head cs_condition_list;
extern struct list_head cs_domain_list;
extern struct list_head cs_group_list[CS_MAX_GROUP];
extern struct list_head cs_name_list[CS_MAX_HASH];
extern struct mutex cs_policy_lock;
extern struct srcu_struct cs_ss;
extern unsigned int cs_memory_used[CS_MAX_MEMORY_STAT];

/* Inlined functions for internal use. */

/**
 * cs_pathcmp - strcmp() for "struct cs_path_info" structure.
 *
 * @a: Pointer to "struct cs_path_info".
 * @b: Pointer to "struct cs_path_info".
 *
 * Returns true if @a != @b, false otherwise.
 */
static inline bool cs_pathcmp(const struct cs_path_info *a,
			      const struct cs_path_info *b)
{
	return a->hash != b->hash || strcmp(a->name, b->name);
}

/**
 * cs_read_lock - Take lock for protecting policy.
 *
 * Returns index number for cs_read_unlock().
 */
static inline int cs_read_lock(void)
{
	return srcu_read_lock(&cs_ss);
}

/**
 * cs_read_unlock - Release lock for protecting policy.
 *
 * @idx: Index number returned by cs_read_lock().
 *
 * Returns nothing.
 */
static inline void cs_read_unlock(const int idx)
{
	srcu_read_unlock(&cs_ss, idx);
}

/**
 * cs_tasklist_lock - Take lock for reading list of "struct task_struct".
 *
 * Returns nothing.
 */
static inline void cs_tasklist_lock(void)
{
	rcu_read_lock();
}

/**
 * cs_tasklist_unlock - Release lock for reading list of "struct task_struct".
 *
 * Returns nothing.
 */
static inline void cs_tasklist_unlock(void)
{
	rcu_read_unlock();
}

/**
 * cs_sys_getppid - Copy of getppid().
 *
 * Returns parent process's PID.
 *
 * Alpha does not have getppid() defined. To be able to build this module on
 * Alpha, I have to copy getppid() from kernel/timer.c.
 */
static inline pid_t cs_sys_getppid(void)
{
	pid_t pid;

	rcu_read_lock();
	pid = task_tgid_vnr(rcu_dereference(current->real_parent));
	rcu_read_unlock();
	return pid;
}

/**
 * cs_sys_getpid - Copy of getpid().
 *
 * Returns current thread's PID.
 *
 * Alpha does not have getpid() defined. To be able to build this module on
 * Alpha, I have to copy getpid() from kernel/timer.c.
 */
static inline pid_t cs_sys_getpid(void)
{
	return task_tgid_vnr(current);
}

/**
 * cs_put_condition - Drop reference on "struct cs_condition".
 *
 * @cond: Pointer to "struct cs_condition". Maybe NULL.
 *
 * Returns nothing.
 */
static inline void cs_put_condition(struct cs_condition *cond)
{
	if (cond)
		atomic_dec(&cond->head.users);
}

/**
 * cs_put_group - Drop reference on "struct cs_group".
 *
 * @group: Pointer to "struct cs_group". Maybe NULL.
 *
 * Returns nothing.
 */
static inline void cs_put_group(struct cs_group *group)
{
	if (group)
		atomic_dec(&group->head.users);
}

/**
 * cs_put_name - Drop reference on "struct cs_name".
 *
 * @name: Pointer to "struct cs_path_info". Maybe NULL.
 *
 * Returns nothing.
 */
static inline void cs_put_name(const struct cs_path_info *name)
{
	if (name)
		atomic_dec(&container_of(name, struct cs_name, entry)->
			   head.users);
}


static inline void cs_acl_groups_put(struct cs_acl_groups *g)  
{  
	if (!g || !atomic_dec_and_test(&g->head.users))  
		return;  
	cs_kick_gc();
}


/* For importing variables and functions. */
extern const struct caitsith_exports caitsith_exports;

/**
 * cs_ksize - Wrapper for ksize().
 *
 * @obj: Pointer to object.
 *
 * Returns ksize(@obj).
 */
static inline size_t cs_ksize(const void *obj)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	return caitsith_exports.ksize(obj);
#else
	return ksize(obj);
#endif
}

#ifdef CONFIG_CAITSITH_USE_EXTERNAL_TASK_SECURITY

/*
 * Structure for holding "struct cs_domain_info *" and "u32 cs_flags" for
 * each "struct task_struct".
 *
 * "struct cs_domain_info *" and "u32 cs_flags" for each "struct task_struct"
 * are maintained outside that "struct task_struct". Therefore, cs_security
 * != task_struct . This keeps KABI for distributor's prebuilt kernels but
 * entails slow access.
 *
 * Memory for this structure is allocated when current thread tries to access
 * it. Therefore, if memory allocation failed, current thread will be killed by
 * SIGKILL. Note that if current->pid == 1, sending SIGKILL won't work.
 */
struct cs_security {
	struct list_head list;
	const struct task_struct *task;
	struct cs_domain_info *cs_domain_info;
	struct cs_acl_groups *cs_acl_groups;
	u32 cs_flags;
	struct rcu_head rcu;
};

#define CS_TASK_SECURITY_HASH_BITS 12
#define CS_MAX_TASK_SECURITY_HASH (1u << CS_TASK_SECURITY_HASH_BITS)
extern struct list_head cs_task_security_list[CS_MAX_TASK_SECURITY_HASH];

struct cs_security *cs_find_task_security(const struct task_struct *task);

/**
 * cs_current_security - Get "struct cs_security" for current thread.
 *
 * Returns pointer to "struct cs_security" for current thread.
 */
static inline struct cs_security *cs_current_security(void)
{
	return cs_find_task_security(current);
}

/**
 * cs_task_domain - Get "struct cs_domain_info" for specified thread.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns pointer to "struct cs_security" for specified thread.
 */
static inline struct cs_domain_info *cs_task_domain(struct task_struct *task)
{
	struct cs_domain_info *domain;

	rcu_read_lock();
	domain = cs_find_task_security(task)->cs_domain_info;
	rcu_read_unlock();
	return domain;
}

/**
 * cs_current_domain - Get "struct cs_domain_info" for current thread.
 *
 * Returns pointer to "struct cs_domain_info" for current thread.
 */
static inline struct cs_domain_info *cs_current_domain(void)
{
	return cs_find_task_security(current)->cs_domain_info;
}

/**
 * cs_task_flags - Get flags for specified thread.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns flags for specified thread.
 */
static inline u32 cs_task_flags(struct task_struct *task)
{
	u32 cs_flags;

	rcu_read_lock();
	cs_flags = cs_find_task_security(task)->cs_flags;
	rcu_read_unlock();
	return cs_flags;
}

/**
 * cs_current_flags - Get flags for current thread.
 *
 * Returns flags for current thread.
 */
static inline u32 cs_current_flags(void)
{
	return cs_find_task_security(current)->cs_flags;
}

#else

/*
 * "struct cs_domain_info *" and "u32 cs_flags" for each "struct task_struct"
 * are maintained inside that "struct task_struct". Therefore, cs_security ==
 * task_struct . This allows fast access but breaks KABI checks for
 * distributor's prebuilt kernels due to changes in "struct task_struct".
 */
#define cs_security task_struct

/**
 * cs_current_security - Get "struct cs_security" for current thread.
 *
 * Returns pointer to "struct cs_security" for current thread.
 *
 * If current thread does not belong to a domain (which is true for initial
 * init_task in order to hide cs_kernel_domain from this module),
 * current thread enters into cs_kernel_domain.
 */
static inline struct cs_security *cs_current_security(void)
{
	struct task_struct *task = current;

	if (!task->cs_domain_info)
		task->cs_domain_info = &cs_kernel_domain;
	return task;
}

/**
 * cs_task_domain - Get "struct cs_domain_info" for specified thread.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns pointer to "struct cs_security" for specified thread.
 */
static inline struct cs_domain_info *cs_task_domain(struct task_struct *task)
{
	struct cs_domain_info *domain = task->cs_domain_info;

	return domain ? domain : &cs_kernel_domain;
}

/**
 * cs_current_domain - Get "struct cs_domain_info" for current thread.
 *
 * Returns pointer to "struct cs_domain_info" for current thread.
 */
static inline struct cs_domain_info *cs_current_domain(void)
{
	return cs_current_security()->cs_domain_info;
}

/**
 * cs_task_flags - Get flags for specified thread.
 *
 * @task: Pointer to "struct task_struct".
 *
 * Returns flags for specified thread.
 */
static inline u32 cs_task_flags(struct task_struct *task)
{
	return task->cs_flags;
}

/**
 * cs_current_flags - Get flags for current thread.
 *
 * Returns flags for current thread.
 */
static inline u32 cs_current_flags(void)
{
	return current->cs_flags;
}

#endif

#endif
