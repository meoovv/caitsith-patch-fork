/*
 * policy_io.c
 *
 * Copyright (C) 2005-2012  NTT DATA CORPORATION
 *
 * Version: 0.2.16   2026/09/28
 */

#include "caitsith.h"

/***** SECTION1: Constants definition *****/

/* Define this to enable debug mode. */
/* #define DEBUG_CONDITION */

#ifdef DEBUG_CONDITION
#define dprintk printk
#else
#define dprintk(...) do { } while (0)
#endif

/* String table for operation. */
static const char * const cs_mac_keywords[CS_MAX_MAC_INDEX] = {
	[CS_MAC_EXECUTE]    = "execute",
	[CS_MAC_READ]       = "read",
	[CS_MAC_WRITE]      = "write",
	[CS_MAC_APPEND]     = "append",
	[CS_MAC_CREATE]     = "create",
	[CS_MAC_UNLINK]     = "unlink",
#ifdef CONFIG_CAITSITH_GETATTR
	[CS_MAC_GETATTR]    = "getattr",
#endif
	[CS_MAC_MKDIR]      = "mkdir",
	[CS_MAC_RMDIR]      = "rmdir",
	[CS_MAC_MKFIFO]     = "mkfifo",
	[CS_MAC_MKSOCK]     = "mksock",
	[CS_MAC_TRUNCATE]   = "truncate",
	[CS_MAC_SYMLINK]    = "symlink",
	[CS_MAC_MKBLOCK]    = "mkblock",
	[CS_MAC_MKCHAR]     = "mkchar",
	[CS_MAC_LINK]       = "link",
	[CS_MAC_RENAME]     = "rename",
	[CS_MAC_CHMOD]      = "chmod",
	[CS_MAC_CHOWN]      = "chown",
	[CS_MAC_CHGRP]      = "chgrp",
	[CS_MAC_IOCTL]      = "ioctl",
	[CS_MAC_CHROOT]     = "chroot",
	[CS_MAC_MOUNT]      = "mount",
	[CS_MAC_UMOUNT]     = "unmount",
	[CS_MAC_PIVOT_ROOT] = "pivot_root",
#ifdef CONFIG_CAITSITH_NETWORK
	[CS_MAC_INET_STREAM_BIND]       = "inet_stream_bind",
	[CS_MAC_INET_STREAM_LISTEN]     = "inet_stream_listen",
	[CS_MAC_INET_STREAM_CONNECT]    = "inet_stream_connect",
	[CS_MAC_INET_STREAM_ACCEPT]     = "inet_stream_accept",
	[CS_MAC_INET_DGRAM_BIND]        = "inet_dgram_bind",
	[CS_MAC_INET_DGRAM_SEND]        = "inet_dgram_send",
	[CS_MAC_INET_RAW_BIND]          = "inet_raw_bind",
	[CS_MAC_INET_RAW_SEND]          = "inet_raw_send",
	[CS_MAC_UNIX_STREAM_BIND]       = "unix_stream_bind",
	[CS_MAC_UNIX_STREAM_LISTEN]     = "unix_stream_listen",
	[CS_MAC_UNIX_STREAM_CONNECT]    = "unix_stream_connect",
	[CS_MAC_UNIX_STREAM_ACCEPT]     = "unix_stream_accept",
	[CS_MAC_UNIX_DGRAM_BIND]        = "unix_dgram_bind",
	[CS_MAC_UNIX_DGRAM_SEND]        = "unix_dgram_send",
	[CS_MAC_UNIX_SEQPACKET_BIND]    = "unix_seqpacket_bind",
	[CS_MAC_UNIX_SEQPACKET_LISTEN]  = "unix_seqpacket_listen",
	[CS_MAC_UNIX_SEQPACKET_CONNECT] = "unix_seqpacket_connect",
	[CS_MAC_UNIX_SEQPACKET_ACCEPT]  = "unix_seqpacket_accept",
#endif
#ifdef CONFIG_CAITSITH_ENVIRON
	[CS_MAC_ENVIRON] = "environ",
#endif
	[CS_MAC_MODIFY_POLICY]      = "modify_policy",
#ifdef CONFIG_CAITSITH_CAPABILITY
	[CS_MAC_USE_NETLINK_SOCKET] = "use_netlink_socket",
	[CS_MAC_USE_PACKET_SOCKET]  = "use_packet_socket",
#endif
#ifdef CONFIG_CAITSITH_AUTO_DOMAIN_TRANSITION
	[CS_MAC_AUTO_DOMAIN_TRANSITION]   = "auto_domain_transition",
#endif
#ifdef CONFIG_CAITSITH_MANUAL_DOMAIN_TRANSITION
	[CS_MAC_MANUAL_DOMAIN_TRANSITION] = "manual_domain_transition",
#endif
};

/* String table for grouping keywords. */
static const char * const cs_group_name[CS_MAX_GROUP] = {
	[CS_STRING_GROUP] = "string_group",
	[CS_NUMBER_GROUP] = "number_group",
#ifdef CONFIG_CAITSITH_NETWORK
	[CS_IP_GROUP]     = "ip_group",
#endif
};

/* String table for stat info. */
static const char * const cs_memory_headers[CS_MAX_MEMORY_STAT] = {
	[CS_MEMORY_POLICY] = "policy",
	[CS_MEMORY_AUDIT]  = "audit",
	[CS_MEMORY_QUERY]  = "query",
};

#define F(bit) (1ULL << bit)

#define CS_ALL_OK				\
	(F(CS_MAC_EXECUTE) |			\
	 F(CS_MAC_READ) |			\
	 F(CS_MAC_WRITE) |			\
	 F(CS_MAC_APPEND) |			\
	 F(CS_MAC_CREATE) |			\
	 F(CS_MAC_UNLINK) |			\
	 F(CS_MAC_GETATTR) |			\
	 F(CS_MAC_MKDIR) |			\
	 F(CS_MAC_RMDIR) |			\
	 F(CS_MAC_MKFIFO) |			\
	 F(CS_MAC_MKSOCK) |			\
	 F(CS_MAC_TRUNCATE) |			\
	 F(CS_MAC_SYMLINK) |			\
	 F(CS_MAC_MKBLOCK) |			\
	 F(CS_MAC_MKCHAR) |			\
	 F(CS_MAC_LINK) |			\
	 F(CS_MAC_RENAME) |			\
	 F(CS_MAC_CHMOD) |			\
	 F(CS_MAC_CHOWN) |			\
	 F(CS_MAC_CHGRP) |			\
	 F(CS_MAC_IOCTL) |			\
	 F(CS_MAC_CHROOT) |			\
	 F(CS_MAC_MOUNT) |			\
	 F(CS_MAC_UMOUNT) |			\
	 F(CS_MAC_PIVOT_ROOT) |			\
	 F(CS_MAC_INET_STREAM_BIND) |		\
	 F(CS_MAC_INET_STREAM_LISTEN) |		\
	 F(CS_MAC_INET_STREAM_CONNECT) |	\
	 F(CS_MAC_INET_STREAM_ACCEPT) |		\
	 F(CS_MAC_INET_DGRAM_BIND) |		\
	 F(CS_MAC_INET_DGRAM_SEND) |		\
	 F(CS_MAC_INET_RAW_BIND) |		\
	 F(CS_MAC_INET_RAW_SEND) |		\
	 F(CS_MAC_UNIX_STREAM_BIND) |		\
	 F(CS_MAC_UNIX_STREAM_LISTEN) |		\
	 F(CS_MAC_UNIX_STREAM_CONNECT) |	\
	 F(CS_MAC_UNIX_STREAM_ACCEPT) |		\
	 F(CS_MAC_UNIX_DGRAM_BIND) |		\
	 F(CS_MAC_UNIX_DGRAM_SEND) |		\
	 F(CS_MAC_UNIX_SEQPACKET_BIND) |	\
	 F(CS_MAC_UNIX_SEQPACKET_LISTEN) |	\
	 F(CS_MAC_UNIX_SEQPACKET_CONNECT) |	\
	 F(CS_MAC_UNIX_SEQPACKET_ACCEPT) |	\
	 F(CS_MAC_ENVIRON) |			\
	 F(CS_MAC_MODIFY_POLICY) |		\
	 F(CS_MAC_USE_NETLINK_SOCKET) |		\
	 F(CS_MAC_USE_PACKET_SOCKET) |		\
	 F(CS_MAC_AUTO_DOMAIN_TRANSITION) |	\
	 F(CS_MAC_MANUAL_DOMAIN_TRANSITION))

#define CS_PATH_SELF_OK				\
	(F(CS_MAC_EXECUTE) |			\
	 F(CS_MAC_READ) |			\
	 F(CS_MAC_WRITE) |			\
	 F(CS_MAC_APPEND) |			\
	 F(CS_MAC_UNLINK) |			\
	 F(CS_MAC_GETATTR) |			\
	 F(CS_MAC_RMDIR) |			\
	 F(CS_MAC_TRUNCATE) |			\
	 F(CS_MAC_CHMOD) |			\
	 F(CS_MAC_CHOWN) |			\
	 F(CS_MAC_CHGRP) |			\
	 F(CS_MAC_IOCTL) |			\
	 F(CS_MAC_CHROOT) |			\
	 F(CS_MAC_UMOUNT) |			\
	 F(CS_MAC_ENVIRON))

#define CS_PATH_PARENT_OK			\
	(F(CS_MAC_CREATE) |			\
	 F(CS_MAC_MKDIR) |			\
	 F(CS_MAC_MKFIFO) |			\
	 F(CS_MAC_MKSOCK) |			\
	 F(CS_MAC_SYMLINK) |			\
	 F(CS_MAC_MKBLOCK) |			\
	 F(CS_MAC_MKCHAR))

#define CS_PATH_OK (CS_PATH_SELF_OK | CS_PATH_PARENT_OK)

#define CS_RENAME_OR_LINK_OK (F(CS_MAC_LINK) | F(CS_MAC_RENAME))

#define CS_EXECUTE_OR_ENVIRON_OK (F(CS_MAC_EXECUTE) | F(CS_MAC_ENVIRON))

#define CS_MKDEV_OK (F(CS_MAC_MKBLOCK) | F(CS_MAC_MKCHAR))

#define CS_PATH_PERM_OK				\
	(F(CS_MAC_MKDIR) |			\
	 F(CS_MAC_MKBLOCK) |			\
	 F(CS_MAC_MKCHAR) |			\
	 F(CS_MAC_MKFIFO) |			\
	 F(CS_MAC_MKSOCK) |			\
	 F(CS_MAC_CREATE) |			\
	 F(CS_MAC_CHMOD))

#define CS_IP_SOCKET_OK				\
	(F(CS_MAC_INET_STREAM_BIND) |		\
	 F(CS_MAC_INET_STREAM_LISTEN) |		\
	 F(CS_MAC_INET_STREAM_CONNECT) |	\
	 F(CS_MAC_INET_STREAM_ACCEPT) |		\
	 F(CS_MAC_INET_DGRAM_BIND) |		\
	 F(CS_MAC_INET_DGRAM_SEND))

#define CS_RAW_SOCKET_OK			\
	(F(CS_MAC_INET_RAW_BIND) |		\
	 F(CS_MAC_INET_RAW_SEND))

#define CS_INET_SOCKET_OK (CS_IP_SOCKET_OK | CS_RAW_SOCKET_OK)

#define CS_UNIX_SOCKET_OK			\
	(F(CS_MAC_UNIX_STREAM_BIND) |		\
	 F(CS_MAC_UNIX_STREAM_LISTEN) |		\
	 F(CS_MAC_UNIX_STREAM_CONNECT) |	\
	 F(CS_MAC_UNIX_STREAM_ACCEPT) |		\
	 F(CS_MAC_UNIX_DGRAM_BIND) |		\
	 F(CS_MAC_UNIX_DGRAM_SEND) |		\
	 F(CS_MAC_UNIX_SEQPACKET_BIND) |	\
	 F(CS_MAC_UNIX_SEQPACKET_LISTEN) |	\
	 F(CS_MAC_UNIX_SEQPACKET_CONNECT) |	\
	 F(CS_MAC_UNIX_SEQPACKET_ACCEPT))

enum cs_var_type {
	CS_TYPE_INVALID,
	CS_TYPE_NUMBER,
	CS_TYPE_STRING,
	CS_TYPE_IPADDR,
	CS_TYPE_FILEPERM,
	CS_TYPE_FILETYPE,
	CS_TYPE_TASKTYPE,
	CS_TYPE_ASSIGN,
} __packed;

/* String table for conditions. */
static const struct {
	const char * const keyword;
	const enum cs_var_type left_type;
	const enum cs_var_type right_type;
	const enum cs_conditions_index cmd;
	const u64 available;
} cs_conditions[] = {
	{ "addr",                    CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG0,            CS_UNIX_SOCKET_OK },
	{ "argc",                    CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_EXEC_ARGC,             CS_EXECUTE_OR_ENVIRON_OK },
	{ "block",                   CS_TYPE_INVALID,  CS_TYPE_FILETYPE,
	  CS_OBJ_IS_BLOCK_DEV,      CS_ALL_OK },
	{ "char",                    CS_TYPE_INVALID,  CS_TYPE_FILETYPE,
	  CS_OBJ_IS_CHAR_DEV,       CS_ALL_OK },
	{ "cmd",                     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_COND_NARG0,            F(CS_MAC_IOCTL) },
	{ "data",                    CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG3,            F(CS_MAC_MOUNT) },
	{ "dev_major",               CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_COND_NARG1,            CS_MKDEV_OK },
	{ "dev_minor",               CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_COND_NARG2,            CS_MKDEV_OK },
	{ "directory",               CS_TYPE_INVALID,  CS_TYPE_FILETYPE,
	  CS_OBJ_IS_DIRECTORY,      CS_ALL_OK },
	{ "domain",                  CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG0,            F(CS_MAC_MANUAL_DOMAIN_TRANSITION) },
	{ "envc",                    CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_EXEC_ENVC,             CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec",                    CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG1,            CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.fsmagic",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_FSMAGIC,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.gid",                CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_GID,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.ino",                CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_INO,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.major",              CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_MAJOR,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.minor",              CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_MINOR,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.parent.fsmagic",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_FSMAGIC,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.parent.gid",         CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_GID,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.parent.ino",         CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_INO,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.parent.major",       CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_MAJOR,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.parent.minor",       CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_MINOR,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.parent.perm",        CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_PERM,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.parent.uid",         CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_UID,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.perm",               CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_PERM,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.type",               CS_TYPE_FILETYPE, CS_TYPE_FILETYPE,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_TYPE,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "exec.uid",                CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_UID,
	  CS_EXECUTE_OR_ENVIRON_OK },
	{ "execute_handler",         CS_TYPE_INVALID,  CS_TYPE_TASKTYPE,
	  CS_TASK_EXECUTE_HANDLER,  CS_ALL_OK },
	{ "fifo",                    CS_TYPE_INVALID,  CS_TYPE_FILETYPE,
	  CS_OBJ_IS_FIFO,           CS_ALL_OK },
	{ "file",                    CS_TYPE_INVALID,  CS_TYPE_FILETYPE,
	  CS_OBJ_IS_FILE,           CS_ALL_OK },
	{ "flags",                   CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_COND_NARG0,            F(CS_MAC_MOUNT) | F(CS_MAC_UMOUNT) },
	{ "fstype",                  CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG2,            F(CS_MAC_MOUNT) },
	{ "gid",                     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_COND_NARG0,            F(CS_MAC_CHGRP) },
	{ "group_execute",           CS_TYPE_INVALID,  CS_TYPE_FILEPERM,
	  CS_MODE_GROUP_EXECUTE,    CS_ALL_OK },
	{ "group_read",              CS_TYPE_INVALID,  CS_TYPE_FILEPERM,
	  CS_MODE_GROUP_READ,       CS_ALL_OK },
	{ "group_write",             CS_TYPE_INVALID,  CS_TYPE_FILEPERM,
	  CS_MODE_GROUP_WRITE,      CS_ALL_OK },
	{ "handler",                 CS_TYPE_ASSIGN,   CS_TYPE_INVALID,
	  CS_HANDLER_PATH,          F(CS_MAC_EXECUTE) },
	{ "ip",                      CS_TYPE_IPADDR,   CS_TYPE_INVALID,
	  CS_COND_IPARG,            CS_INET_SOCKET_OK },
	{ "name",                    CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG2,            F(CS_MAC_ENVIRON) },
	{ "new_path",                CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG1,            CS_RENAME_OR_LINK_OK },
	{ "new_path.dev_major",      CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_DEV_MAJOR,
	  F(CS_MAC_RENAME) },
	{ "new_path.dev_minor",      CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_DEV_MINOR,
	  F(CS_MAC_RENAME) },
	{ "new_path.fsmagic",        CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_FSMAGIC,
	  F(CS_MAC_RENAME) },
	{ "new_path.gid",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_GID,
	  F(CS_MAC_RENAME) },
	{ "new_path.ino",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_INO,
	  F(CS_MAC_RENAME) },
	{ "new_path.major",          CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_MAJOR,
	  F(CS_MAC_RENAME) },
	{ "new_path.minor",          CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_MINOR,
	  F(CS_MAC_RENAME) },
	{ "new_path.parent.fsmagic", CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_FSMAGIC,
	  CS_RENAME_OR_LINK_OK },
	{ "new_path.parent.gid",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_GID,
	  CS_RENAME_OR_LINK_OK },
	{ "new_path.parent.ino",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_INO,
	  CS_RENAME_OR_LINK_OK },
	{ "new_path.parent.major",   CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_MAJOR,
	  CS_RENAME_OR_LINK_OK },
	{ "new_path.parent.minor",   CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_MINOR,
	  CS_RENAME_OR_LINK_OK },
	{ "new_path.parent.perm",    CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_PERM,
	  CS_RENAME_OR_LINK_OK },
	{ "new_path.parent.uid",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_UID,
	  CS_RENAME_OR_LINK_OK },
	{ "new_path.perm",           CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_PERM,
	  F(CS_MAC_RENAME) },
	{ "new_path.type",           CS_TYPE_FILETYPE, CS_TYPE_FILETYPE,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_TYPE,
	  F(CS_MAC_RENAME) },
	{ "new_path.uid",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_UID,
	  F(CS_MAC_RENAME) },
	{ "new_root",                CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG0,            F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.dev_major",      CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_DEV_MAJOR,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.dev_minor",      CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_DEV_MINOR,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.fsmagic",        CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_FSMAGIC,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.gid",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_GID,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.ino",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_INO,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.major",          CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_MAJOR,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.minor",          CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_MINOR,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.parent.fsmagic", CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_FSMAGIC,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.parent.gid",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_GID,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.parent.ino",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_INO,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.parent.major",   CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_MAJOR,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.parent.minor",   CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_MINOR,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.parent.perm",    CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_PERM,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.parent.uid",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_UID,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.perm",           CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_PERM,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.type",           CS_TYPE_FILETYPE, CS_TYPE_FILETYPE,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_TYPE,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "new_root.uid",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_UID,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "old_path",                CS_TYPE_STRING,    CS_TYPE_STRING,
	  CS_COND_SARG0,            CS_RENAME_OR_LINK_OK },
	{ "old_path.dev_major",      CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_DEV_MAJOR,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.dev_minor",      CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_DEV_MINOR,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.fsmagic",        CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_FSMAGIC,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.gid",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_GID,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.ino",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_INO,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.major",          CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_MAJOR,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.minor",          CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_MINOR,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.parent.fsmagic", CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_FSMAGIC,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.parent.gid",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_GID,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.parent.ino",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_INO,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.parent.major",   CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_MAJOR,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.parent.minor",   CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_MINOR,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.parent.perm",    CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_PERM,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.parent.uid",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_UID,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.perm",           CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_PERM,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.type",           CS_TYPE_FILETYPE, CS_TYPE_FILETYPE,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_TYPE,
	  CS_RENAME_OR_LINK_OK },
	{ "old_path.uid",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_UID,
	  CS_RENAME_OR_LINK_OK },
	{ "others_execute",          CS_TYPE_INVALID,  CS_TYPE_FILEPERM,
	  CS_MODE_OTHERS_EXECUTE,   CS_ALL_OK },
	{ "others_read",             CS_TYPE_INVALID,  CS_TYPE_FILEPERM,
	  CS_MODE_OTHERS_READ,      CS_ALL_OK },
	{ "others_write",            CS_TYPE_INVALID,  CS_TYPE_FILEPERM,
	  CS_MODE_OTHERS_WRITE,     CS_ALL_OK },
	{ "owner_execute",           CS_TYPE_INVALID,  CS_TYPE_FILEPERM,
	  CS_MODE_OWNER_EXECUTE,    CS_ALL_OK },
	{ "owner_read",              CS_TYPE_INVALID,  CS_TYPE_FILEPERM,
	  CS_MODE_OWNER_READ,       CS_ALL_OK },
	{ "owner_write",             CS_TYPE_INVALID,  CS_TYPE_FILEPERM,
	  CS_MODE_OWNER_WRITE,      CS_ALL_OK },
	{ "path",                    CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG0,            CS_PATH_OK },
	{ "path.dev_major",          CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_DEV_MAJOR,
	  CS_PATH_SELF_OK },
	{ "path.dev_minor",          CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_DEV_MINOR,
	  CS_PATH_SELF_OK },
	{ "path.fsmagic",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_FSMAGIC,
	  CS_PATH_SELF_OK },
	{ "path.gid",                CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_GID,
	  CS_PATH_SELF_OK },
	{ "path.ino",                CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_INO,
	  CS_PATH_SELF_OK },
	{ "path.major",              CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_MAJOR,
	  CS_PATH_SELF_OK },
	{ "path.minor",              CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_MINOR,
	  CS_PATH_SELF_OK },
	{ "path.parent.fsmagic",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_FSMAGIC,
	  CS_PATH_OK },
	{ "path.parent.gid",         CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_GID,
	  CS_PATH_OK },
	{ "path.parent.ino",         CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_INO,
	  CS_PATH_OK },
	{ "path.parent.major",       CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_MAJOR,
	  CS_PATH_OK },
	{ "path.parent.minor",       CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_MINOR,
	  CS_PATH_OK },
	{ "path.parent.perm",        CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_PERM,
	  CS_PATH_OK },
	{ "path.parent.uid",         CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_UID,
	  CS_PATH_OK },
	{ "path.perm",               CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_PERM,
	  CS_PATH_SELF_OK },
	{ "path.type",               CS_TYPE_FILETYPE, CS_TYPE_FILETYPE,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_TYPE,
	  CS_PATH_SELF_OK },
	{ "path.uid",                CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_UID,
	  CS_PATH_SELF_OK },
	{ "perm",                    CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_COND_NARG0,            CS_PATH_PERM_OK },
	{ "port",                    CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_COND_NARG0,            CS_IP_SOCKET_OK },
	{ "proto",                   CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_COND_NARG0,            CS_RAW_SOCKET_OK },
	{ "put_old",                 CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG1,            F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.dev_major",       CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_DEV_MAJOR,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.dev_minor",       CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_DEV_MINOR,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.fsmagic",         CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_FSMAGIC,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.gid",             CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_GID,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.ino",             CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_INO,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.major",           CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_MAJOR,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.minor",           CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_MINOR,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.parent.fsmagic",  CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_FSMAGIC,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.parent.gid",      CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_GID,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.parent.ino",      CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_INO,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.parent.major",    CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_MAJOR,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.parent.minor",    CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_MINOR,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.parent.perm",     CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_PERM,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.parent.uid",      CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_UID,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.perm",            CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_PERM,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.type",            CS_TYPE_FILETYPE, CS_TYPE_FILETYPE,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_TYPE,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "put_old.uid",             CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_UID,
	  F(CS_MAC_PIVOT_ROOT) },
	{ "setgid",                  CS_TYPE_INVALID,  CS_TYPE_FILEPERM,
	  CS_MODE_SETGID,           CS_ALL_OK },
	{ "setuid",                  CS_TYPE_INVALID,  CS_TYPE_FILEPERM,
	  CS_MODE_SETUID,           CS_ALL_OK },
	{ "socket",                  CS_TYPE_INVALID,  CS_TYPE_FILETYPE,
	  CS_OBJ_IS_SOCKET,         CS_ALL_OK },
	{ "source",                  CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG0,            F(CS_MAC_MOUNT) },
	{ "source.dev_major",        CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_DEV_MAJOR,
	  F(CS_MAC_MOUNT) },
	{ "source.dev_minor",        CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_DEV_MINOR,
	  F(CS_MAC_MOUNT) },
	{ "source.fsmagic",          CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_FSMAGIC,
	  F(CS_MAC_MOUNT) },
	{ "source.gid",              CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_GID,
	  F(CS_MAC_MOUNT) },
	{ "source.ino",              CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_INO,
	  F(CS_MAC_MOUNT) },
	{ "source.major",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_MAJOR,
	  F(CS_MAC_MOUNT) },
	{ "source.minor",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_MINOR,
	  F(CS_MAC_MOUNT) },
	{ "source.parent.fsmagic",   CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_FSMAGIC,
	  F(CS_MAC_MOUNT) },
	{ "source.parent.gid",       CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_GID,
	  F(CS_MAC_MOUNT) },
	{ "source.parent.ino",       CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_INO,
	  F(CS_MAC_MOUNT) },
	{ "source.parent.major",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_MAJOR,
	  F(CS_MAC_MOUNT) },
	{ "source.parent.minor",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_MINOR,
	  F(CS_MAC_MOUNT) },
	{ "source.parent.perm",      CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_PERM,
	  F(CS_MAC_MOUNT) },
	{ "source.parent.uid",       CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 16 + CS_PATH_ATTRIBUTE_UID,
	  F(CS_MAC_MOUNT) },
	{ "source.perm",             CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_PERM,
	  F(CS_MAC_MOUNT) },
	{ "source.type",             CS_TYPE_FILETYPE, CS_TYPE_FILETYPE,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_TYPE,
	  F(CS_MAC_MOUNT) },
	{ "source.uid",              CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + CS_PATH_ATTRIBUTE_UID,
	  F(CS_MAC_MOUNT) },
	{ "sticky",                  CS_TYPE_INVALID,  CS_TYPE_FILEPERM,
	  CS_MODE_STICKY,           CS_ALL_OK },
	{ "symlink",                 CS_TYPE_INVALID,  CS_TYPE_FILETYPE,
	  CS_OBJ_IS_SYMLINK,        CS_ALL_OK },
	{ "target",                  CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG1,            F(CS_MAC_MOUNT) | F(CS_MAC_SYMLINK) },
	{ "target.dev_major",        CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_DEV_MAJOR,
	  F(CS_MAC_MOUNT) },
	{ "target.dev_minor",        CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_DEV_MINOR,
	  F(CS_MAC_MOUNT) },
	{ "target.fsmagic",          CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_FSMAGIC,
	  F(CS_MAC_MOUNT) },
	{ "target.gid",              CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_GID,
	  F(CS_MAC_MOUNT) },
	{ "target.ino",              CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_INO,
	  F(CS_MAC_MOUNT) },
	{ "target.major",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_MAJOR,
	  F(CS_MAC_MOUNT) },
	{ "target.minor",            CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_MINOR,
	  F(CS_MAC_MOUNT) },
	{ "target.parent.fsmagic",   CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_FSMAGIC,
	  F(CS_MAC_MOUNT) },
	{ "target.parent.gid",       CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_GID,
	  F(CS_MAC_MOUNT) },
	{ "target.parent.ino",       CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_INO,
	  F(CS_MAC_MOUNT) },
	{ "target.parent.major",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_MAJOR,
	  F(CS_MAC_MOUNT) },
	{ "target.parent.minor",     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_MINOR,
	  F(CS_MAC_MOUNT) },
	{ "target.parent.perm",      CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_PERM,
	  F(CS_MAC_MOUNT) },
	{ "target.parent.uid",       CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 48 + CS_PATH_ATTRIBUTE_UID,
	  F(CS_MAC_MOUNT) },
	{ "target.perm",             CS_TYPE_FILEPERM, CS_TYPE_FILEPERM,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_PERM,
	  F(CS_MAC_MOUNT) },
	{ "target.type",             CS_TYPE_FILETYPE, CS_TYPE_FILETYPE,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_TYPE,
	  F(CS_MAC_MOUNT) },
	{ "target.uid",              CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_PATH_ATTRIBUTE_START + 32 + CS_PATH_ATTRIBUTE_UID,
	  F(CS_MAC_MOUNT) },
	{ "task.domain",             CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_SELF_DOMAIN,           CS_ALL_OK },
	{ "task.egid",               CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_SELF_EGID,             CS_ALL_OK },
	{ "task.euid",               CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_SELF_EUID,             CS_ALL_OK },
	{ "task.exe",                CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_SELF_EXE,              CS_ALL_OK },
	{ "task.fsgid",              CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_SELF_FSGID,            CS_ALL_OK },
	{ "task.fsuid",              CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_SELF_FSUID,            CS_ALL_OK },
	{ "task.gid",                CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_SELF_GID,              CS_ALL_OK },
	{ "task.pid",                CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_SELF_PID,              CS_ALL_OK },
	{ "task.ppid",               CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_SELF_PPID,             CS_ALL_OK },
	{ "task.sgid",               CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_SELF_SGID,             CS_ALL_OK },
	{ "task.suid",               CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_SELF_SUID,             CS_ALL_OK },
	{ "task.type",               CS_TYPE_TASKTYPE, CS_TYPE_INVALID,
	  CS_TASK_TYPE,             CS_ALL_OK },
	{ "task.uid",                CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_SELF_UID,              CS_ALL_OK },
	{ "transition",              CS_TYPE_ASSIGN,   CS_TYPE_INVALID,
	  CS_TRANSIT_DOMAIN,
	  F(CS_MAC_EXECUTE) | F(CS_MAC_AUTO_DOMAIN_TRANSITION) |
	  CS_INET_SOCKET_OK | CS_UNIX_SOCKET_OK },
	{ "uid",                     CS_TYPE_NUMBER,   CS_TYPE_NUMBER,
	  CS_COND_NARG0,            F(CS_MAC_CHOWN) },
	{ "value",                   CS_TYPE_STRING,   CS_TYPE_STRING,
	  CS_COND_SARG3,            F(CS_MAC_ENVIRON) },
};

/***** SECTION2: Structure definition *****/

struct iattr;

/* Structure for query. */
struct cs_query {
	struct list_head list;
	struct cs_acl_info *acl;
	char *query;
	size_t query_len;
	unsigned int serial;
	u8 timer;
	u8 answer;
	u8 retry;
	enum cs_mac_index acl_type;
};

/* Structure for audit log. */
struct cs_log {
	struct list_head list;
	char *log;
	int size;
	enum cs_matching_result result;
};

/* Structure for holding single condition component. */
struct cs_cond_tmp {
	enum cs_conditions_index left;
	enum cs_conditions_index right;
	bool is_not;
	u8 radix;
	enum cs_var_type type;
	struct cs_group *group;
	const struct cs_path_info *path;
	struct in6_addr ipv6[2];
	unsigned long value[2];
	unsigned long argv;
	const struct cs_path_info *envp;
};

/***** SECTION3: Prototype definition section *****/

static bool cs_correct_domain(const unsigned char *domainname);
static bool cs_correct_word(const char *string);
static bool cs_flush(struct cs_io_buffer *head);
static bool cs_print_condition(struct cs_io_buffer *head,
			       const struct cs_condition *cond);
static bool cs_memory_ok(const void *ptr);
static bool cs_read_acl(struct cs_io_buffer *head,
			const struct cs_acl_info *acl);
static bool cs_read_group(struct cs_io_buffer *head);
static bool cs_select_acl(struct cs_io_buffer *head, const char *data);
static bool cs_set_lf(struct cs_io_buffer *head);
static bool cs_str_starts(char **src, const char *find);
static char *cs_init_log(struct cs_request_info *r);
static char *cs_print_bprm(struct linux_binprm *bprm,
			   struct cs_page_dump *dump);
static char *cs_print_trailer(struct cs_request_info *r);
static char *cs_read_token(struct cs_io_buffer *head);
static const char *cs_yesno(const unsigned int value);
static const struct cs_path_info *cs_get_dqword(char *start);
static const struct cs_path_info *cs_get_name(const char *name);
static int cs_open(struct inode *inode, struct file *file);
static int cs_parse_policy(struct cs_io_buffer *head, char *line);
static int cs_release(struct inode *inode, struct file *file);
static int cs_supervisor(struct cs_request_info *r);
static int cs_update_group(struct cs_io_buffer *head,
			   const enum cs_group_id type);
static int cs_write_answer(struct cs_io_buffer *head);
static int cs_write_audit_quota(char *data);
static int cs_write_memory_quota(char *data);
static int cs_write_pid(struct cs_io_buffer *head);
static int cs_write_policy(struct cs_io_buffer *head);
static ssize_t cs_read(struct file *file, char __user *buf, size_t count,
		       loff_t *ppos);
static ssize_t cs_read_self(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos);
static ssize_t cs_write(struct file *file, const char __user *buf,
			size_t count, loff_t *ppos);
static struct cs_condition *cs_get_condition(struct cs_io_buffer *head);
static struct cs_domain_info *cs_find_domain(const char *domainname);
static struct cs_acl_info *cs_find_acl_by_qid(unsigned int serial,
					      enum cs_mac_index *type);
static struct cs_group *cs_get_group(struct cs_io_buffer *head,
				     const enum cs_group_id idx);
static enum cs_value_type cs_parse_ulong(unsigned long *result, char **str);
static unsigned int cs_poll(struct file *file, poll_table *wait);
static void __init cs_create_entry(const char *name, const umode_t mode,
				   struct dentry *parent, const u8 key);
static void __init cs_load_builtin_policy(void);
static void __init cs_securityfs_init(void);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
static void cs_convert_time(time_t time, struct cs_time *stamp);
#else
static void cs_convert_time(time64_t time, struct cs_time *stamp);
#endif
static void cs_io_printf(struct cs_io_buffer *head, const char *fmt, ...)
	__printf(2, 3);
static void cs_normalize_line(unsigned char *buffer);
static void cs_read_log(struct cs_io_buffer *head);
static void cs_read_pid(struct cs_io_buffer *head);
static void cs_read_policy(struct cs_io_buffer *head);
static void cs_read_query(struct cs_io_buffer *head);
static void *cs_commit_ok(void *data, const unsigned int size);
static bool cs_read_quota(struct cs_io_buffer *head);
static void cs_read_stat(struct cs_io_buffer *head);
static void cs_read_version(struct cs_io_buffer *head);
static void cs_set_space(struct cs_io_buffer *head);
static void cs_set_string(struct cs_io_buffer *head, const char *string);
static void cs_update_stat(const u8 index);
static void cs_write_log(struct cs_request_info *r);

#ifdef CONFIG_CAITSITH_NETWORK
static enum cs_conditions_index cs_parse_ipaddr(char *address,
						struct in6_addr ipv6[2]);
static void cs_print_ipv4(struct cs_io_buffer *head, const u32 *ip);
static void cs_print_ipv6(struct cs_io_buffer *head,
			  const struct in6_addr *ip);
static void cs_print_ip(struct cs_io_buffer *head,
			struct cs_ip_group *member);
#endif

#ifdef CONFIG_CAITSITH_MANUAL_DOMAIN_TRANSITION
static ssize_t cs_write_self(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos);
#endif

/***** SECTION4: Standalone functions section *****/

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
/**
 * cs_convert_time - Convert time_t to YYYY/MM/DD hh/mm/ss.
 *
 * @time:  Seconds since 1970/01/01 00:00:00.
 * @stamp: Pointer to "struct cs_time".
 *
 * Returns nothing.
 *
 * This function does not handle Y2038 problem.
 */
static void cs_convert_time(time_t time, struct cs_time *stamp)
{
	static const u16 cs_eom[2][12] = {
		{ 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
		{ 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
	};
	u16 y;
	u8 m;
	bool r;

	stamp->sec = time % 60;
	time /= 60;
	stamp->min = time % 60;
	time /= 60;
	stamp->hour = time % 24;
	time /= 24;
	for (y = 1970; ; y++) {
		const unsigned short days = (y & 3) ? 365 : 366;

		if (time < days)
			break;
		time -= days;
	}
	r = (y & 3) == 0;
	for (m = 0; m < 11 && time >= cs_eom[r][m]; m++)
		;
	if (m)
		time -= cs_eom[r][m - 1];
	stamp->year = y;
	stamp->month = ++m;
	stamp->day = ++time;
}
#else
/**
 * cs_convert_time - Convert time_t to YYYY/MM/DD hh/mm/ss.
 *
 * @time:  Seconds since 1970/01/01 00:00:00.
 * @stamp: Pointer to "struct cs_time".
 *
 * Returns nothing.
 */
static void cs_convert_time(time64_t time, struct cs_time *stamp)
{
	struct tm tm;

	time64_to_tm(time, 0, &tm);
	stamp->sec = tm.tm_sec;
	stamp->min = tm.tm_min;
	stamp->hour = tm.tm_hour;
	stamp->day = tm.tm_mday;
	stamp->month = tm.tm_mon + 1;
	stamp->year = tm.tm_year + 1900;
}
#endif

#ifdef CONFIG_CAITSITH_NETWORK

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)

/*
 * Routines for printing IPv4 or IPv6 address.
 * These are copied from include/linux/kernel.h include/net/ipv6.h
 * include/net/addrconf.h lib/hexdump.c lib/vsprintf.c and simplified.
 */
static inline int ipv6_addr_is_isatap(const struct in6_addr *addr)
{
	return (addr->s6_addr32[2] | htonl(0x02000000)) == htonl(0x02005EFE);
}

static char *ip4_string(char *p, const u8 *addr)
{
	/*
	 * Since this function is called outside vsnprintf(), I can use
	 * sprintf() here.
	 */
	return p +
		sprintf(p, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
}

static char *ip6_compressed_string(char *p, const char *addr)
{
	int i, j, range;
	unsigned char zerolength[8];
	int longest = 1;
	int colonpos = -1;
	u16 word;
	u8 hi, lo;
	bool needcolon = false;
	bool useIPv4;
	struct in6_addr in6;

	memcpy(&in6, addr, sizeof(struct in6_addr));

	useIPv4 = ipv6_addr_v4mapped(&in6) || ipv6_addr_is_isatap(&in6);

	memset(zerolength, 0, sizeof(zerolength));

	if (useIPv4)
		range = 6;
	else
		range = 8;

	/* find position of longest 0 run */
	for (i = 0; i < range; i++) {
		for (j = i; j < range; j++) {
			if (in6.s6_addr16[j] != 0)
				break;
			zerolength[i]++;
		}
	}
	for (i = 0; i < range; i++) {
		if (zerolength[i] > longest) {
			longest = zerolength[i];
			colonpos = i;
		}
	}
	if (longest == 1)		/* don't compress a single 0 */
		colonpos = -1;

	/* emit address */
	for (i = 0; i < range; i++) {
		if (i == colonpos) {
			if (needcolon || i == 0)
				*p++ = ':';
			*p++ = ':';
			needcolon = false;
			i += longest - 1;
			continue;
		}
		if (needcolon) {
			*p++ = ':';
			needcolon = false;
		}
		/* hex u16 without leading 0s */
		word = ntohs(in6.s6_addr16[i]);
		hi = word >> 8;
		lo = word & 0xff;
		if (hi) {
			if (hi > 0x0f)
				p = pack_hex_byte(p, hi);
			else
				*p++ = hex_asc_lo(hi);
			p = pack_hex_byte(p, lo);
		} else if (lo > 0x0f)
			p = pack_hex_byte(p, lo);
		else
			*p++ = hex_asc_lo(lo);
		needcolon = true;
	}

	if (useIPv4) {
		if (needcolon)
			*p++ = ':';
		p = ip4_string(p, &in6.s6_addr[12]);
	}
	*p = '\0';

	return p;
}
#endif

/**
 * cs_print_ipv4 - Print an IPv4 address.
 *
 * @head: Pointer to "struct cs_io_buffer".
 * @ip:   Pointer to "u32" in network byte order.
 *
 * Returns nothing.
 */
static void cs_print_ipv4(struct cs_io_buffer *head, const u32 *ip)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	cs_io_printf(head, "%pI4", ip);
#else
	char addr[sizeof("255.255.255.255")];

	ip4_string(addr, (const u8 *) ip);
	cs_io_printf(head, "%s", addr);
#endif
}

/**
 * cs_print_ipv6 - Print an IPv6 address.
 *
 * @head: Pointer to "struct cs_io_buffer".
 * @ip:   Pointer to "struct in6_addr".
 *
 * Returns nothing.
 */
static void cs_print_ipv6(struct cs_io_buffer *head,
			  const struct in6_addr *ip)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
	cs_io_printf(head, "%pI6c", ip);
#else
	char addr[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255")];

	ip6_compressed_string(addr, (const u8 *) ip);
	cs_io_printf(head, "%s", addr);
#endif
}

/**
 * cs_print_ip - Print an IP address.
 *
 * @head:   Pointer to "struct cs_io_buffer".
 * @member: Pointer to "struct cs_ip_group".
 *
 * Returns nothing.
 */
static void cs_print_ip(struct cs_io_buffer *head,
			struct cs_ip_group *member)
{
	u8 i;

	for (i = 0; i < 2; i++) {
		if (member->is_ipv6)
			cs_print_ipv6(head, &member->ip[i]);
		else
			cs_print_ipv4(head, (const u32 *) &member->ip[i]);
		if (i)
			break;
		if (!memcmp(&member->ip[0], &member->ip[1], 16))
			break;
		cs_set_string(head, "-");
	}
}

#endif

/***** SECTION5: Variables definition section *****/

/* Lock for protecting policy. */
DEFINE_MUTEX(cs_policy_lock);

/* Has /sbin/init started? */
bool cs_policy_loaded;

/* List of "struct cs_group". */
struct list_head cs_group_list[CS_MAX_GROUP];
/* Policy version. Currently only 20120401 is defined. */
static unsigned int cs_policy_version;

/* List of "struct cs_condition". */
LIST_HEAD(cs_condition_list);

/* Wait queue for kernel -> userspace notification. */
static DECLARE_WAIT_QUEUE_HEAD(cs_query_wait);
/* Wait queue for userspace -> kernel notification. */
static DECLARE_WAIT_QUEUE_HEAD(cs_answer_wait);

/* The list for "struct cs_query". */
static LIST_HEAD(cs_query_list);

/* Lock for manipulating cs_query_list. */
static DEFINE_SPINLOCK(cs_query_list_lock);

/*
 * Number of "struct file" referring /sys/kernel/security/caitsith/query
 * interface.
 */
static atomic_t cs_query_observers = ATOMIC_INIT(0);

/* Wait queue for /sys/kernel/security/caitsith/audit interface. */
static DECLARE_WAIT_QUEUE_HEAD(cs_log_wait);

/* The list for "struct cs_log". */
static LIST_HEAD(cs_log);

/* Lock for "struct list_head cs_log". */
static DEFINE_SPINLOCK(cs_log_lock);

/* Length of "struct list_head cs_log". */
static unsigned int cs_log_count[CS_MAX_MATCHING];
/* Quota for audit logs. */
static unsigned int cs_log_quota[CS_MAX_LOG_QUOTA][CS_MAX_MATCHING];

/* Memoy currently used by policy/audit log/query. */
unsigned int cs_memory_used[CS_MAX_MEMORY_STAT];

/* Memory quota for "policy"/"audit log"/"query". */
static unsigned int cs_memory_quota[CS_MAX_MEMORY_STAT];

/* The list for "struct cs_name". */
struct list_head cs_name_list[CS_MAX_HASH];

/* Counter for number of updates. */
static atomic_t cs_stat_updated[CS_MAX_POLICY_STAT];

/* Timestamp counter for last updated. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
static unsigned int cs_stat_modified[CS_MAX_POLICY_STAT];
#else
static time64_t cs_stat_modified[CS_MAX_POLICY_STAT];
#endif

/* Operations for /sys/kernel/security/caitsith/self_domain interface. */
static const struct file_operations cs_self_operations = {
#ifdef CONFIG_CAITSITH_MANUAL_DOMAIN_TRANSITION
	.write = cs_write_self,
#endif
	.read  = cs_read_self,
};

/* Operations for /sys/kernel/security/caitsith/ interface. */
static const struct file_operations cs_operations = {
	.open    = cs_open,
	.release = cs_release,
	.poll    = cs_poll,
	.read    = cs_read,
	.write   = cs_write,
};

/***** SECTION6: Dependent functions section *****/

/**
 * list_for_each_cookie - iterate over a list with cookie.
 *
 * @pos:  Pointer to "struct list_head".
 * @head: Pointer to "struct list_head".
 */
#define list_for_each_cookie(pos, head)					\
	for (pos = pos ? pos : srcu_dereference((head)->next, &cs_ss);	\
	     pos != (head); pos = srcu_dereference(pos->next, &cs_ss))

/**
 * cs_warn_oom - Print out of memory warning message.
 *
 * @function: Function's name.
 *
 * Returns nothing.
 */
void cs_warn_oom(const char *function)
{
	/* Reduce error messages. */
	static pid_t cs_last_pid;
	const pid_t pid = current->pid;

	if (cs_last_pid != pid) {
		printk(KERN_WARNING "ERROR: Out of memory at %s.\n",
		       function);
		cs_last_pid = pid;
	}
	if (!cs_policy_loaded)
		panic("MAC Initialization failed.\n");
}

/**
 * cs_memory_ok - Check memory quota.
 *
 * @ptr:  Pointer to allocated memory. Maybe NULL.
 *
 * Returns true if @ptr is not NULL and quota not exceeded, false otherwise.
 *
 * Caller holds cs_policy_lock mutex.
 */
static bool cs_memory_ok(const void *ptr)
{
	if (ptr) {
		const size_t s = cs_ksize(ptr);

		cs_memory_used[CS_MEMORY_POLICY] += s;
		if (!cs_memory_quota[CS_MEMORY_POLICY] ||
		    cs_memory_used[CS_MEMORY_POLICY] <=
		    cs_memory_quota[CS_MEMORY_POLICY])
			return true;
		cs_memory_used[CS_MEMORY_POLICY] -= s;
	}
	cs_warn_oom(__func__);
	return false;
}

/**
 * cs_get_name - Allocate memory for string data.
 *
 * @name: The string to store into the permernent memory. Maybe NULL.
 *
 * Returns pointer to "struct cs_path_info" on success, NULL otherwise.
 */
static const struct cs_path_info *cs_get_name(const char *name)
{
	struct cs_name *ptr;
	unsigned int hash;
	int len;
	int allocated_len;
	struct list_head *head;

	if (!name)
		return NULL;
	len = strlen(name) + 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	hash = full_name_hash(NULL, name, len - 1);
#else
	hash = full_name_hash((const unsigned char *) name, len - 1);
#endif
	head = &cs_name_list[hash_long(hash, CS_HASH_BITS)];
	if (mutex_lock_killable(&cs_policy_lock))
		return NULL;
	list_for_each_entry(ptr, head, head.list) {
		if (hash != ptr->entry.hash || strcmp(name, ptr->entry.name) ||
		    atomic_read(&ptr->head.users) == CS_GC_IN_PROGRESS)
			continue;
		atomic_inc(&ptr->head.users);
		goto out;
	}
	allocated_len = sizeof(*ptr) + len;
	ptr = kzalloc(allocated_len, GFP_NOFS);
	if (cs_memory_ok(ptr)) {
		ptr->entry.name = ((char *) ptr) + sizeof(*ptr);
		memmove((char *) ptr->entry.name, name, len);
		atomic_set(&ptr->head.users, 1);
		cs_fill_path_info(&ptr->entry);
		ptr->size = allocated_len;
		list_add_tail(&ptr->head.list, head);
	} else {
		kfree(ptr);
		ptr = NULL;
	}
out:
	mutex_unlock(&cs_policy_lock);
	return ptr ? &ptr->entry : NULL;
}

/**
 * cs_read_token - Read a word from a line.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns a word on success, "" otherwise.
 *
 * To allow the caller to skip NULL check, this function returns "" rather than
 * NULL if there is no more words to read.
 */
static char *cs_read_token(struct cs_io_buffer *head)
{
	char *pos = head->w.data;
	char *del = strchr(pos, ' ');

	if (del)
		*del++ = '\0';
	else
		del = pos + strlen(pos);
	head->w.data = del;
	return pos;
}

/**
 * cs_correct_word - Check whether the given string follows the naming rules.
 *
 * @string: The string to check.
 *
 * Returns true if @string follows the naming rules, false otherwise.
 */
static bool cs_correct_word(const char *string)
{
	u8 recursion = 20;
	const char *const start = string;
	u8 in_repetition = 0;

	if (!*string)
		goto out;
	while (*string) {
		unsigned char c = *string++;

		if (in_repetition && c == '/')
			goto out;
		if (c <= ' ' || c >= 127)
			goto out;
		if (c != '\\')
			continue;
		c = *string++;
		if (c >= '0' && c <= '3') {
			unsigned char d;
			unsigned char e;

			d = *string++;
			if (d < '0' || d > '7')
				goto out;
			e = *string++;
			if (e < '0' || e > '7')
				goto out;
			c = ((c - '0') << 6) + ((d - '0') << 3) + (e - '0');
			if (c <= ' ' || c >= 127 || c == '\\')
				continue;
			goto out;
		}
		switch (c) {
		case '+':   /* "\+" */
		case '?':   /* "\?" */
		case 'x':   /* "\x" */
		case 'a':   /* "\a" */
		case '-':   /* "\-" */
			continue;
		}
		/* Reject too deep wildcard that consumes too much stack. */
		if (!recursion--)
			goto out;
		switch (c) {
		case '*':   /* "\*" */
		case '@':   /* "\@" */
		case '$':   /* "\$" */
		case 'X':   /* "\X" */
		case 'A':   /* "\A" */
			continue;
		case '{':   /* "/\{" */
			if (string - 3 < start || *(string - 3) != '/')
				goto out;
			in_repetition = 1;
			continue;
		case '}':   /* "\}/" */
			if (in_repetition != 1 || *string++ != '/')
				goto out;
			in_repetition = 0;
			continue;
		case '(':   /* "/\(" */
			if (string - 3 < start || *(string - 3) != '/')
				goto out;
			in_repetition = 2;
			continue;
		case ')':   /* "\)/" */
			if (in_repetition != 2 || *string++ != '/')
				goto out;
			in_repetition = 0;
			continue;
		}
		goto out;
	}
	if (in_repetition)
		goto out;
	return true;
out:
	return false;
}

/**
 * cs_commit_ok - Allocate memory and check memory quota.
 *
 * @data: Data to copy from.
 * @size: Size in byte.
 *
 * Returns pointer to allocated memory on success, NULL otherwise.
 * @data is zero-cleared on success.
 *
 * Caller holds cs_policy_lock mutex.
 */
static void *cs_commit_ok(void *data, const unsigned int size)
{
	void *ptr = kmalloc(size, GFP_NOFS);

	if (cs_memory_ok(ptr)) {
		memmove(ptr, data, size);
		memset(data, 0, size);
		return ptr;
	}
	kfree(ptr);
	return NULL;
}

/**
 * cs_get_group - Allocate memory for "struct cs_string_group"/"struct cs_number_group"/"struct cs_ip_group".
 *
 * @head: Pointer to "struct cs_io_buffer".
 * @idx:  Index number.
 *
 * Returns pointer to "struct cs_group" on success, NULL otherwise.
 */
static struct cs_group *cs_get_group(struct cs_io_buffer *head,
				     const enum cs_group_id idx)
{
	struct cs_group e = { };
	struct cs_group *group = NULL;
	struct list_head *list;
	const char *group_name = cs_read_token(head);
	bool found = false;

	if (!cs_correct_word(group_name) || idx >= CS_MAX_GROUP)
		return NULL;
	e.group_name = cs_get_name(group_name);
	if (!e.group_name)
		return NULL;
	if (mutex_lock_killable(&cs_policy_lock))
		goto out;
	list = &cs_group_list[idx];
	list_for_each_entry(group, list, head.list) {
		if (e.group_name != group->group_name ||
		    atomic_read(&group->head.users) == CS_GC_IN_PROGRESS)
			continue;
		atomic_inc(&group->head.users);
		found = true;
		break;
	}
	if (!found) {
		struct cs_group *entry = cs_commit_ok(&e, sizeof(e));

		if (entry) {
			INIT_LIST_HEAD(&entry->member_list);
			atomic_set(&entry->head.users, 1);
			list_add_tail_rcu(&entry->head.list, list);
			group = entry;
			found = true;
		}
	}
	mutex_unlock(&cs_policy_lock);
out:
	cs_put_name(e.group_name);
	return found ? group : NULL;
}

/**
 * cs_parse_ulong - Parse an "unsigned long" value.
 *
 * @result: Pointer to "unsigned long".
 * @str:    Pointer to string to parse.
 *
 * Returns one of values in "enum cs_value_type".
 *
 * The @src is updated to point the first character after the value
 * on success.
 */
static enum cs_value_type cs_parse_ulong(unsigned long *result, char **str)
{
	const char *cp = *str;
	char *ep;
	int base = 10;

	if (*cp == '0') {
		char c = *(cp + 1);

		if (c == 'x' || c == 'X') {
			base = 16;
			cp += 2;
		} else if (c >= '0' && c <= '7') {
			base = 8;
			cp++;
		}
	}
	*result = simple_strtoul(cp, &ep, base);
	if (cp == ep)
		return CS_VALUE_TYPE_INVALID;
	*str = ep;
	switch (base) {
	case 16:
		return CS_VALUE_TYPE_HEXADECIMAL;
	case 8:
		return CS_VALUE_TYPE_OCTAL;
	default:
		return CS_VALUE_TYPE_DECIMAL;
	}
}

/**
 * cs_get_dqword - cs_get_name() for a quoted string.
 *
 * @start: String to parse.
 *
 * Returns pointer to "struct cs_path_info" on success, NULL otherwise.
 */
static const struct cs_path_info *cs_get_dqword(char *start)
{
	char *cp = start + strlen(start) - 1;

	if (cp == start || *start++ != '"' || *cp != '"')
		return NULL;
	*cp = '\0';
	if (*start && !cs_correct_word(start))
		return NULL;
	return cs_get_name(start);
}

/**
 * cs_same_condition - Check for duplicated "struct cs_condition" entry.
 *
 * @a: Pointer to "struct cs_condition".
 * @b: Pointer to "struct cs_condition".
 *
 * Returns true if @a == @b, false otherwise.
 */
static inline bool cs_same_condition(const struct cs_condition *a,
				     const struct cs_condition *b)
{
	return a->size == b->size &&
		!memcmp(a + 1, b + 1, a->size - sizeof(*a));
}

/**
 * cs_commit_condition - Commit "struct cs_condition".
 *
 * @entry: Pointer to "struct cs_condition".
 *
 * Returns pointer to "struct cs_condition" on success, NULL otherwise.
 *
 * This function merges duplicated entries. This function returns NULL if
 * @entry is not duplicated but memory quota for policy has exceeded.
 */
static struct cs_condition *cs_commit_condition(struct cs_condition *entry)
{
	struct cs_condition *ptr = kmemdup(entry, entry->size, GFP_NOFS);
	bool found = false;

	if (ptr) {
		kfree(entry);
		entry = ptr;
	}
	if (mutex_lock_killable(&cs_policy_lock)) {
		dprintk(KERN_WARNING "%u: %s failed\n", __LINE__, __func__);
		ptr = NULL;
		found = true;
		goto out;
	}
	list_for_each_entry(ptr, &cs_condition_list, head.list) {
		if (!cs_same_condition(ptr, entry) ||
		    atomic_read(&ptr->head.users) == CS_GC_IN_PROGRESS)
			continue;
		/* Same entry found. Share this entry. */
		atomic_inc(&ptr->head.users);
		found = true;
		break;
	}
	if (!found) {
		if (cs_memory_ok(entry)) {
			atomic_set(&entry->head.users, 1);
			list_add(&entry->head.list, &cs_condition_list);
		} else {
			found = true;
			ptr = NULL;
		}
	}
	mutex_unlock(&cs_policy_lock);
out:
	if (found) {
		cs_del_condition(&entry->head.list);
		kfree(entry);
		entry = ptr;
	}
	return entry;
}

/**
 * cs_correct_domain - Check whether the given domainname follows the naming rules.
 *
 * @domainname: The domainname to check.
 *
 * Returns true if @domainname follows the naming rules, false otherwise.
 */
static bool cs_correct_domain(const unsigned char *domainname)
{
	if (!cs_correct_word(domainname))
		return false;
	while (*domainname) {
		if (*domainname++ != '\\')
			continue;
		if (*domainname < '0' || *domainname++ > '3')
			return false;
	}
	return true;
}

/**
 * cs_normalize_line - Format string.
 *
 * @buffer: The line to normalize.
 *
 * Returns nothing.
 *
 * Leading and trailing whitespaces are removed.
 * Multiple whitespaces are packed into single space.
 */
static void cs_normalize_line(unsigned char *buffer)
{
	unsigned char *sp = buffer;
	unsigned char *dp = buffer;
	bool first = true;

	while (*sp && (*sp <= ' ' || *sp >= 127))
		sp++;
	while (*sp) {
		if (!first)
			*dp++ = ' ';
		first = false;
		while (*sp > ' ' && *sp < 127)
			*dp++ = *sp++;
		while (*sp && (*sp <= ' ' || *sp >= 127))
			sp++;
	}
	*dp = '\0';
}

/**
 * cs_parse_values - Parse an numeric argument.
 *
 * @value: Values to parse.
 * @v:     Pointer to "unsigned long".
 *
 * Returns "enum cs_value_type" if @value is a single value, bitwise-OR-ed
 * value if @value is value range.
 */
static u8 cs_parse_values(char *value, unsigned long v[2])
{
	enum cs_value_type radix1 = cs_parse_ulong(&v[0], &value);
	enum cs_value_type radix2;

	if (radix1 == CS_VALUE_TYPE_INVALID)
		return CS_VALUE_TYPE_INVALID;
	if (!*value) {
		v[1] = v[0];
		return radix1;
	}
	if (*value++ != '-')
		return CS_VALUE_TYPE_INVALID;
	radix2 = cs_parse_ulong(&v[1], &value);
	if (radix2 == CS_VALUE_TYPE_INVALID || *value || v[0] > v[1])
		return CS_VALUE_TYPE_INVALID;
	return radix1 | (radix2 << 2);
}

#ifdef CONFIG_CAITSITH_NETWORK

/**
 * cs_parse_ipaddr - Parse an IP address.
 *
 * @address: Address to parse.
 * @ipv6:    Pointer to "struct in6_addr".
 *
 * Returns one of values in "enum cs_conditions_index".
 */
static enum cs_conditions_index cs_parse_ipaddr(char *address,
						struct in6_addr ipv6[2])
{
	const char *end;

	if (!strchr(address, ':') &&
	    in4_pton(address, -1, ipv6[0].s6_addr, '-', &end) > 0) {
		if (!*end) {
			ipv6[0].s6_addr32[0] = ipv6[0].s6_addr32[0];
			ipv6[1].s6_addr32[0] = ipv6[0].s6_addr32[0];
			return CS_IMM_IPV4ADDR_ENTRY1;
		}
		if (*end++ != '-' ||
		    in4_pton(end, -1, ipv6[1].s6_addr, '\0', &end) <= 0 ||
		    *end || memcmp(&ipv6[0], &ipv6[1], 4) >= 0)
			return CS_INVALID_CONDITION;
		return CS_IMM_IPV4ADDR_ENTRY2;
	}
	if (in6_pton(address, -1, ipv6[0].s6_addr, '-', &end) > 0) {
		if (!*end) {
			ipv6[1] = ipv6[0];
			return CS_IMM_IPV6ADDR_ENTRY1;
		}
		if (*end++ != '-' ||
		    in6_pton(end, -1, ipv6[1].s6_addr, '\0', &end) <= 0 ||
		    *end || memcmp(&ipv6[0], &ipv6[1], 16) >= 0)
			return CS_INVALID_CONDITION;
		return CS_IMM_IPV6ADDR_ENTRY2;
	}
	return CS_INVALID_CONDITION;
}

#endif

/**
 * cs_parse_lefthand - Parse special lefthand conditions.
 *
 * @word: Keyword to search.
 * @mac:  One of values in "enum cs_mac_index".
 * @tmp:  Pointer to "struct cs_cond_tmp".
 *
 * Returns one of values in "enum cs_conditions_index".
 */
static enum cs_conditions_index cs_parse_lefthand
(char *word, const enum cs_mac_index mac, struct cs_cond_tmp *tmp)
{
	if (mac == CS_MAC_EXECUTE || mac == CS_MAC_ENVIRON) {
		tmp->type = CS_TYPE_STRING;
		if (!strncmp(word, "argv[", 5)) {
			word += 5;
			if (cs_parse_ulong(&tmp->argv, &word) ==
			    CS_VALUE_TYPE_DECIMAL && !strcmp(word, "]"))
				return CS_ARGV_ENTRY;
		} else if (!strncmp(word, "envp[\"", 6)) {
			char *end = word + strlen(word) - 2;

			if (!strcmp(end, "\"]")) {
				*end = '\0';
				tmp->envp = cs_get_name(word + 6);
				if (tmp->envp)
					return CS_ENVP_ENTRY;
			}
		}
	}
	return CS_INVALID_CONDITION;
}

/**
 * cs_parse_righthand - Parse special righthand conditions.
 *
 * @word: Keyword to search.
 * @head: Pointer to "struct cs_io_buffer".
 * @tmp:  Pointer to "struct cs_cond_tmp".
 *
 * Returns one of values in "enum cs_conditions_index".
 */
static enum cs_conditions_index cs_parse_righthand
(char *word, struct cs_io_buffer *head, struct cs_cond_tmp *tmp)
{
	const enum cs_var_type type = tmp->type;

	dprintk(KERN_WARNING "%u: tmp->left=%u type=%u\n",
		__LINE__, tmp->left, type);
	if (type == CS_TYPE_ASSIGN) {
		if (tmp->is_not)
			goto out;
		if (!strcmp(word, "NULL"))
			goto null_word;
		tmp->path = cs_get_dqword(word);
		if (tmp->path && tmp->path->const_len == tmp->path->total_len)
			return CS_IMM_NAME_ENTRY;
		goto out;
	}
	if (word[0] == '@' && word[1]) {
		enum cs_group_id g;

		if (type == CS_TYPE_NUMBER || type == CS_TYPE_FILEPERM)
			g = CS_NUMBER_GROUP;
		else if (type == CS_TYPE_STRING)
			g = CS_STRING_GROUP;
#ifdef CONFIG_CAITSITH_NETWORK
		else if (type == CS_TYPE_IPADDR)
			g = CS_IP_GROUP;
#endif
		else
			goto out;
		head->w.data = word + 1;
		tmp->group = cs_get_group(head, g);
		if (tmp->group)
			return CS_IMM_GROUP;
		goto out;
	}
	if (type == CS_TYPE_NUMBER || type == CS_TYPE_FILEPERM) {
		tmp->radix = cs_parse_values(word, tmp->value);
		if (tmp->radix == CS_VALUE_TYPE_INVALID)
			goto out;
		if (tmp->radix >> 2)
			return CS_IMM_NUMBER_ENTRY2;
		else
			return CS_IMM_NUMBER_ENTRY1;
	}
	if (type == CS_TYPE_STRING) {
		dprintk(KERN_WARNING "%u: word='%s'\n", __LINE__, word);
		if (!strcmp(word, "NULL"))
			goto null_word;
		tmp->path = cs_get_dqword(word);
		dprintk(KERN_WARNING "%u: tmp->path=%p\n", __LINE__,
			tmp->path);
		if (tmp->path)
			return CS_IMM_NAME_ENTRY;
		goto out;
	}
#ifdef CONFIG_CAITSITH_NETWORK
	if (type == CS_TYPE_IPADDR)
		return cs_parse_ipaddr(word, tmp->ipv6);
#endif
out:
	dprintk(KERN_WARNING "%u: righthand failed\n", __LINE__);
	return CS_INVALID_CONDITION;
null_word:
	tmp->path = &cs_null_name;
	return CS_IMM_NAME_ENTRY;
}

/**
 * cs_condindex - Get condition's index.
 *
 * @word: Name of condition.
 * @mac:  One of values in "enum cs_mac_index".
 * @tmp:  Pointer to "struct cs_cond_tmp".
 * @left: True if lefthand part, false otherwise.
 *
 * Returns one of values in "enum cs_condition_index".
 */
static enum cs_conditions_index cs_condindex(const char *word,
					     const enum cs_mac_index mac,
					     struct cs_cond_tmp *tmp,
					     const bool lefthand)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cs_conditions); i++) {
		if (!(cs_conditions[i].available & F(mac)) ||
		    strcmp(cs_conditions[i].keyword, word))
			continue;
		tmp->type = lefthand ? cs_conditions[i].left_type :
			cs_conditions[i].right_type;
		if (tmp->type != CS_TYPE_INVALID)
			return cs_conditions[i].cmd;
		break;
	}
	return CS_INVALID_CONDITION;
}

/**
 * cs_parse_cond - Parse single condition.
 *
 * @tmp:  Pointer to "struct cs_cond_tmp".
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
static bool cs_parse_cond(struct cs_cond_tmp *tmp,
			  struct cs_io_buffer *head)
{
	char *left = head->w.data;
	char *right;
	const enum cs_mac_index mac = head->w.acl_index;
	enum cs_var_type type = CS_TYPE_STRING;

	dprintk(KERN_WARNING "%u: type=%u word='%s'\n",
		__LINE__, mac, left);
	right = strchr(left, '=');
	if (!right || right == left)
		return false;
	*right++ = '\0';
	tmp->is_not = (*(right - 2) == '!');
	if (tmp->is_not)
		*(right - 2) = '\0';
	if (!*left || !*right)
		return false;
	tmp->left = cs_condindex(left, mac, tmp, true);
	dprintk(KERN_WARNING "%u: tmp->left=%u\n", __LINE__, tmp->left);
	if (tmp->left == CS_INVALID_CONDITION) {
		tmp->left = cs_parse_lefthand(left, mac, tmp);
		dprintk(KERN_WARNING "%u: tmp->left=%u\n", __LINE__,
			tmp->left);
		if (tmp->left == CS_INVALID_CONDITION)
			return false;
	} else {
		type = tmp->type;
	}
	dprintk(KERN_WARNING "%u: tmp->type=%u\n", __LINE__, tmp->type);
	tmp->right = cs_condindex(right, mac, tmp, false);
	dprintk(KERN_WARNING "%u: tmp->right=%u tmp->type=%u\n",
		__LINE__, tmp->right, tmp->type);
	if (tmp->right != CS_INVALID_CONDITION && type != tmp->type &&
	    !(type == CS_TYPE_FILEPERM && tmp->type == CS_TYPE_NUMBER))
		return false;
	if (tmp->right == CS_INVALID_CONDITION)
		tmp->right = cs_parse_righthand(right, head, tmp);
	dprintk(KERN_WARNING "%u: tmp->right=%u tmp->type=%u\n",
		__LINE__, tmp->right, tmp->type);
	return tmp->right != CS_INVALID_CONDITION;
}

/**
 * cs_get_condition - Parse condition part.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns pointer to "struct cs_condition" on success, NULL otherwise.
 */
static struct cs_condition *cs_get_condition(struct cs_io_buffer *head)
{
	struct cs_condition *entry = kzalloc(PAGE_SIZE, GFP_NOFS);
	union cs_condition_element *condp;
	struct cs_cond_tmp tmp;
	const enum cs_mac_index type = head->w.acl_index;
#ifdef CONFIG_CAITSITH_EXECUTE_HANDLER
	bool handler_path_done = head->w.is_deny ||
		type != CS_MAC_EXECUTE;
#else
	bool handler_path_done = true;
#endif
	bool transit_domain_done = head->w.is_deny ||
		!(F(type) &
		  (F(CS_MAC_EXECUTE) | F(CS_MAC_AUTO_DOMAIN_TRANSITION) |
		   CS_INET_SOCKET_OK | CS_UNIX_SOCKET_OK));
	char *pos = head->w.data;

	if (!entry)
		return NULL;
	condp = (union cs_condition_element *) (entry + 1);
	while (1) {
		memset(&tmp, 0, sizeof(tmp));
		/*
		 * tmp.left = CS_INVALID_CONDITION;
		 * tmp.right = CS_INVALID_CONDITION;
		 */
		while (*pos == ' ')
			pos++;
		if (!*pos)
			break;
		if ((u8 *) condp >= ((u8 *) entry) + PAGE_SIZE
		    - (sizeof(*condp) + sizeof(struct in6_addr) * 2))
			goto out;
		{
			char *next = strchr(pos, ' ');

			if (next)
				*next++ = '\0';
			else
				next = "";
			head->w.data = pos;
			pos = next;
		}
		if (!cs_parse_cond(&tmp, head))
			goto out;
		if (tmp.left == CS_HANDLER_PATH) {
			if (handler_path_done)
				goto out;
			handler_path_done = true;
		}
		if (tmp.left == CS_TRANSIT_DOMAIN) {
			if (transit_domain_done)
				goto out;
			transit_domain_done = true;
		}
		condp->is_not = tmp.is_not;
		condp->left = tmp.left;
		condp->right = tmp.right;
		condp->radix = tmp.radix;
		condp++;
		if (tmp.left == CS_ARGV_ENTRY) {
			condp->value = tmp.argv;
			condp++;
		} else if (tmp.left == CS_ENVP_ENTRY) {
			condp->path = tmp.envp;
			condp++;
		}
		if (tmp.right == CS_IMM_GROUP) {
			condp->group = tmp.group;
			condp++;
		} else if (tmp.right == CS_IMM_NAME_ENTRY) {
			condp->path = tmp.path;
			condp++;
		} else if (tmp.right == CS_IMM_NUMBER_ENTRY1 ||
			   tmp.right == CS_IMM_NUMBER_ENTRY2) {
			condp->value = tmp.value[0];
			condp++;
			if (tmp.right == CS_IMM_NUMBER_ENTRY2) {
				condp->value = tmp.value[1];
				condp++;
			}
#ifdef CONFIG_CAITSITH_NETWORK
		} else if (tmp.right == CS_IMM_IPV4ADDR_ENTRY1 ||
			   tmp.right == CS_IMM_IPV4ADDR_ENTRY2) {
			condp->ip = *(u32 *) &tmp.ipv6[0];
			condp++;
			if (tmp.right == CS_IMM_IPV4ADDR_ENTRY2) {
				condp->ip = *(u32 *) &tmp.ipv6[1];
				condp++;
			}
		} else if (tmp.right == CS_IMM_IPV6ADDR_ENTRY1 ||
			   tmp.right == CS_IMM_IPV6ADDR_ENTRY2) {
			*(struct in6_addr *) condp = tmp.ipv6[0];
			condp = (void *) (((u8 *) condp) +
					  sizeof(struct in6_addr));
			if (tmp.right == CS_IMM_IPV6ADDR_ENTRY2) {
				*(struct in6_addr *) condp = tmp.ipv6[1];
				condp = (void *) (((u8 *) condp) +
						  sizeof(struct in6_addr));
			}
#endif
		}
	}
#ifdef CONFIG_CAITSITH_AUTO_DOMAIN_TRANSITION
	if (!transit_domain_done && type == CS_MAC_AUTO_DOMAIN_TRANSITION)
		goto out;
#endif
	entry->size = (void *) condp - (void *) entry;
	return cs_commit_condition(entry);
out:
	dprintk(KERN_WARNING
		"%u: bad condition: type=%u env='%s' path='%s' group='%s'\n",
		__LINE__, type, tmp.envp ? tmp.envp->name : "",
		tmp.path ? tmp.path->name : "",
		tmp.group ? tmp.group->group_name->name : "");
	cs_put_name(tmp.envp);
	if (tmp.path != &cs_null_name)
		cs_put_name(tmp.path);
	cs_put_group(tmp.group);
	entry->size = (void *) condp - (void *) entry;
	cs_del_condition(&entry->head.list);
	kfree(entry);
	return NULL;
}

/**
 * cs_yesno - Return "yes" or "no".
 *
 * @value: Bool value.
 *
 * Returns "yes" if @value is not 0, "no" otherwise.
 */
static const char *cs_yesno(const unsigned int value)
{
	return value ? "yes" : "no";
}

/**
 * cs_flush - Flush queued string to userspace's buffer.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns true if all data was flushed, false otherwise.
 */
static bool cs_flush(struct cs_io_buffer *head)
{
	while (head->r.w_pos) {
		const char *w = head->r.w[0];
		size_t len = strlen(w);

		if (len) {
			if (len > head->read_user_buf_avail)
				len = head->read_user_buf_avail;
			if (!len)
				return false;
			if (copy_to_user(head->read_user_buf, w, len))
				return false;
			head->read_user_buf_avail -= len;
			head->read_user_buf += len;
			w += len;
		}
		head->r.w[0] = w;
		if (*w)
			return false;
		/* Add '\0' for audit logs and query. */
		if (head->type == CS_AUDIT || head->type == CS_QUERY) {
			if (!head->read_user_buf_avail ||
			    copy_to_user(head->read_user_buf, "", 1))
				return false;
			head->read_user_buf_avail--;
			head->read_user_buf++;
		}
		head->r.w_pos--;
		for (len = 0; len < head->r.w_pos; len++)
			head->r.w[len] = head->r.w[len + 1];
	}
	head->r.avail = 0;
	return true;
}

/**
 * cs_set_string - Queue string to "struct cs_io_buffer" structure.
 *
 * @head:   Pointer to "struct cs_io_buffer".
 * @string: String to print.
 *
 * Returns nothing.
 *
 * Note that @string has to be kept valid until @head is kfree()d.
 * This means that char[] allocated on stack memory cannot be passed to
 * this function. Use cs_io_printf() for char[] allocated on stack memory.
 */
static void cs_set_string(struct cs_io_buffer *head, const char *string)
{
	if (head->r.w_pos < CS_MAX_IO_READ_QUEUE) {
		head->r.w[head->r.w_pos++] = string;
		cs_flush(head);
	} else
		printk(KERN_WARNING "Too many words in a line.\n");
}

/**
 * cs_io_printf - printf() to "struct cs_io_buffer" structure.
 *
 * @head: Pointer to "struct cs_io_buffer".
 * @fmt:  The printf()'s format string, followed by parameters.
 *
 * Returns nothing.
 */
static void cs_io_printf(struct cs_io_buffer *head, const char *fmt, ...)
{
	va_list args;
	size_t len;
	size_t pos = head->r.avail;
	int size = head->readbuf_size - pos;

	if (size <= 0)
		return;
	va_start(args, fmt);
	len = vsnprintf(head->read_buf + pos, size, fmt, args) + 1;
	va_end(args);
	if (pos + len >= head->readbuf_size) {
		printk(KERN_WARNING "Too many words in a line.\n");
		return;
	}
	head->r.avail += len;
	cs_set_string(head, head->read_buf + pos);
}

/**
 * cs_set_space - Put a space to "struct cs_io_buffer" structure.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns nothing.
 */
static void cs_set_space(struct cs_io_buffer *head)
{
	cs_set_string(head, " ");
}

/**
 * cs_set_lf - Put a line feed to "struct cs_io_buffer" structure.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns true if all data was flushed, false otherwise.
 */
static bool cs_set_lf(struct cs_io_buffer *head)
{
	cs_set_string(head, "\n");
	return !head->r.w_pos;
}

/**
 * cs_check_profile - Check policy is loaded.
 *
 * Returns nothing.
 */
void cs_check_profile(void)
{
	cs_policy_loaded = true;
	printk(KERN_INFO "CaitSith (LSM): 0.2.16   2026/09/28\n");
	if (cs_policy_version == 20120401) {
		printk(KERN_INFO "CaitSith module activated.\n");
		return;
	}
	printk(KERN_ERR "Policy version %u is not supported.\n",
	       cs_policy_version);
	printk(KERN_ERR "Userland tools for CaitSith must be installed and policy must be initialized.\n");
	printk(KERN_ERR "Please see https://caitsith.sourceforge.net/ for more information.\n");
	panic("STOP!");
}

/**
 * cs_str_starts - Check whether the given string starts with the given keyword.
 *
 * @src:  Pointer to pointer to the string.
 * @find: Pointer to the keyword.
 *
 * Returns true if @src starts with @find, false otherwise.
 *
 * The @src is updated to point the first character after the @find
 * if @src starts with @find.
 */
static bool cs_str_starts(char **src, const char *find)
{
	const int len = strlen(find);
	char *tmp = *src;

	if (strncmp(tmp, find, len))
		return false;
	tmp += len;
	*src = tmp;
	return true;
}

/**
 * cs_find_domain - Find a domain by the given name.
 *
 * @domainname: The domainname to find.
 *
 * Returns pointer to "struct cs_domain_info" if found, NULL otherwise.
 *
 * Caller holds cs_read_lock().
 */
static struct cs_domain_info *cs_find_domain(const char *domainname)
{
	struct cs_domain_info *domain;
	struct cs_path_info name;

	name.name = domainname;
	cs_fill_path_info(&name);
	list_for_each_entry_srcu(domain, &cs_domain_list, list, srcu_read_lock_held(&cs_ss)) {
		if (!cs_pathcmp(&name, domain->domainname))
			return domain;
	}
	return NULL;
}

/**
 * cs_select_acl - Parse select command.
 *
 * @head: Pointer to "struct cs_io_buffer".
 * @data: String to parse.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds cs_read_lock().
 */
static bool cs_select_acl(struct cs_io_buffer *head, const char *data)
{
	unsigned int qid;
	enum cs_mac_index type;
	struct cs_acl_info *acl;

	if (sscanf(data, "Q=%u", &qid) != 1)
		return false;
	acl = cs_find_acl_by_qid(qid, &type);
	head->w.acl = acl;
	/* Accessing read_buf is safe because head->io_sem is held. */
	if (!head->read_buf)
		return true; /* Do nothing if open(O_WRONLY). */
	memset(&head->r, 0, sizeof(head->r));
	head->r.print_this_acl_only = true;
	if (acl) {
		head->r.acl = &acl->list;
		head->r.acl_index = type;
	} else
		head->r.eof = true;
	cs_io_printf(head, "# Q=%u\n", qid);
	return true;
}

/**
 * cs_update_acl - Update "struct cs_acl_info" entry.
 *
 * @list:   Pointer to "struct list_head".
 * @head:   Pointer to "struct cs_io_buffer".
 * @update: True to store matching entry, false otherwise.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds cs_read_lock().
 */
static int cs_update_acl(struct list_head * const list,
			 struct cs_io_buffer *head, const bool update)
{
	struct cs_acl_info *ptr;
	struct cs_acl_info new_entry = { };
	const bool is_delete = head->w.is_delete;
	int error = is_delete ? -ENOENT : -ENOMEM;

	new_entry.priority = head->w.priority;
	new_entry.is_deny = head->w.is_deny;
	if (head->w.data[0]) {
		new_entry.cond = cs_get_condition(head);
		if (!new_entry.cond)
			return -EINVAL;
	}
	if (mutex_lock_killable(&cs_policy_lock))
		goto out;
	list_for_each_entry_srcu(ptr, list, list, srcu_read_lock_held(&cs_ss)) {
		if (ptr->priority > new_entry.priority)
			break;
		/*
		 * We cannot reuse deleted "struct cs_acl_info" entry because
		 * somebody might be referencing children of this deleted entry
		 * from srcu section. We cannot delete children of this deleted
		 * entry until all children are no longer referenced. Thus, let
		 * the garbage collector wait and delete rather than trying to
		 * reuse this deleted entry.
		 */
		if (ptr->is_deleted || ptr->cond != new_entry.cond ||
		    ptr->priority != new_entry.priority ||
		    ptr->is_deny != new_entry.is_deny)
			continue;
		ptr->is_deleted = is_delete;
		if (!is_delete && update)
			head->w.acl = ptr;
		error = 0;
		break;
	}
	if (error && !is_delete) {
		struct cs_acl_info *entry =
			cs_commit_ok(&new_entry, sizeof(new_entry));

		if (entry) {
			INIT_LIST_HEAD(&entry->acl_info_list);
			list_add_tail_rcu(&entry->list, &ptr->list);
			if (update)
				head->w.acl = entry;
		}
	}
	mutex_unlock(&cs_policy_lock);
out:
	cs_put_condition(new_entry.cond);
	return error;
}

/**
 * cs_parse_entry - Update ACL entry.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds cs_read_lock().
 */
static int cs_parse_entry(struct cs_io_buffer *head)
{
	enum cs_mac_index type;
	const char *operation = cs_read_token(head);

	for (type = 0; type < CS_MAX_MAC_INDEX; type++) {
		if (strcmp(operation, cs_mac_keywords[type]))
			continue;
		head->w.acl_index = type;
		/*
		 * This is_deny is for rejecting handler= and transition=
		 * arguments in "acl" line. handler= and transition= arguments
		 * are accepted for only "allow" line.
		 */
		head->w.is_deny = true;
		return cs_update_acl(&cs_acl_list[type], head, true);
	}
	return -EINVAL;
}

/**
 * cs_print_number - Print number argument.
 *
 * @head:  Pointer to "struct cs_io_buffer".
 * @radix: One of values in "enum cs_value_type".
 * @value: Value to print.
 *
 * Returns nothing.
 */
static void cs_print_number(struct cs_io_buffer *head,
			    const enum cs_value_type radix,
			    const unsigned long value)
{
	switch (radix) {
	case CS_VALUE_TYPE_HEXADECIMAL:
		cs_io_printf(head, "0x%lX", value);
		break;
	case CS_VALUE_TYPE_OCTAL:
		cs_io_printf(head, "0%lo", value);
		break;
	default:
		cs_io_printf(head, "%lu", value);
	}
}

/**
 * cs_condword - Get condition's name.
 *
 * @type: One of values in "enum cs_mac_index".
 * @cond: One of values in "enum cs_condition_index".
 *
 * Returns condition's name.
 */
static const char *cs_condword(const enum cs_mac_index type,
			       const enum cs_conditions_index cond)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cs_conditions); i++) {
		if (!(cs_conditions[i].available & F(type)) ||
		    cs_conditions[i].cmd != cond)
			continue;
		return cs_conditions[i].keyword;
	}
	return "unknown"; /* This should not happen. */
}

/**
 * cs_print_condition_loop - Print condition part.
 *
 * @head: Pointer to "struct cs_io_buffer".
 * @cond: Pointer to "struct cs_condition".
 *
 * Returns true on success, false otherwise.
 */
static bool cs_print_condition_loop(struct cs_io_buffer *head,
				    const struct cs_condition *cond)
{
	const enum cs_mac_index type = head->r.acl_index;
	const union cs_condition_element *condp = head->r.cond;

	while ((void *) condp < (void *) ((u8 *) cond) + cond->size) {
		const bool is_not = condp->is_not;
		const enum cs_conditions_index left = condp->left;
		const enum cs_conditions_index right = condp->right;
		const u8 radix = condp->radix;

		if (!cs_flush(head)) {
			head->r.cond = condp;
			return false;
		}
		condp++;
		cs_set_space(head);
		switch (left) {
		case CS_ARGV_ENTRY:
			cs_io_printf(head, "argv[%lu]", condp->value);
			condp++;
			break;
		case CS_ENVP_ENTRY:
			cs_set_string(head, "envp[\"");
			cs_set_string(head, condp->path->name);
			condp++;
			cs_set_string(head, "\"]");
			break;
		default:
			cs_set_string(head, cs_condword(type, left));
		}
		cs_set_string(head, is_not ? "!=" : "=");
		switch (right) {
		case CS_IMM_GROUP:
			cs_set_string(head, "@");
			cs_set_string(head, condp->group->group_name->name);
			condp++;
			break;
		case CS_IMM_NAME_ENTRY:
			if (condp->path != &cs_null_name) {
				cs_set_string(head, "\"");
				cs_set_string(head, condp->path->name);
				cs_set_string(head, "\"");
			} else {
				cs_set_string(head, "NULL");
			}
			condp++;
			break;
		case CS_IMM_NUMBER_ENTRY1:
		case CS_IMM_NUMBER_ENTRY2:
			cs_print_number(head, radix & 3, condp->value);
			condp++;
			if (right == CS_IMM_NUMBER_ENTRY1)
				break;
			cs_set_string(head, "-");
			cs_print_number(head, (radix >> 2) & 3, condp->value);
			condp++;
			break;
#ifdef CONFIG_CAITSITH_NETWORK
		case CS_IMM_IPV4ADDR_ENTRY1:
		case CS_IMM_IPV4ADDR_ENTRY2:
			cs_print_ipv4(head, &condp->ip);
			condp++;
			if (right == CS_IMM_IPV4ADDR_ENTRY1)
				break;
			cs_set_string(head, "-");
			cs_print_ipv4(head, &condp->ip);
			condp++;
			break;
		case CS_IMM_IPV6ADDR_ENTRY1:
		case CS_IMM_IPV6ADDR_ENTRY2:
			cs_print_ipv6(head, (const struct in6_addr *) condp);
			condp = (void *)
				((u8 *) condp) + sizeof(struct in6_addr);
			if (right == CS_IMM_IPV6ADDR_ENTRY1)
				break;
			cs_set_string(head, "-");
			cs_print_ipv6(head, (const struct in6_addr *) condp);
			condp = (void *)
				((u8 *) condp) + sizeof(struct in6_addr);
			break;
#endif
		default:
			cs_set_string(head, cs_condword(type, right));
		}
	}
	head->r.cond = NULL;
	return true;
}

/**
 * cs_print_condition - Print condition part.
 *
 * @head: Pointer to "struct cs_io_buffer".
 * @cond: Pointer to "struct cs_condition".
 *
 * Returns true on success, false otherwise.
 */
static bool cs_print_condition(struct cs_io_buffer *head,
			       const struct cs_condition *cond)
{
	switch (head->r.cond_step) {
	case 0:
		head->r.cond = (const union cs_condition_element *)
			(cond + 1);
		head->r.cond_step++;
		/* fall through */
		fallthrough;
	case 1:
		if (!cs_print_condition_loop(head, cond))
			return false;
		head->r.cond_step++;
		/* fall through */
		fallthrough;
	case 2:
		head->r.cond = NULL;
		return true;
	}
	return false;
}

/**
 * cs_read_acl - Print an ACL entry.
 *
 * @head: Pointer to "struct cs_io_buffer".
 * @acl:  Pointer to an ACL entry.
 *
 * Returns true on success, false otherwise.
 */
static bool cs_read_acl(struct cs_io_buffer *head,
			const struct cs_acl_info *acl)
{
	const enum cs_mac_index type = head->r.acl_index;

	if (head->r.cond)
		goto print_cond_part;
	if (acl->is_deleted)
		return true;
	if (!cs_flush(head))
		return false;
	cs_io_printf(head, "%u ", acl->priority);
	cs_set_string(head, "acl ");
	cs_set_string(head, cs_mac_keywords[type]);
	if (acl->cond) {
		head->r.cond_step = 0;
print_cond_part:
		if (!cs_print_condition(head, acl->cond))
			return false;
	}
	cs_set_lf(head);
	return true;
}

/**
 * cs_write_pid - Specify PID to obtain domainname.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns 0.
 */
static int cs_write_pid(struct cs_io_buffer *head)
{
	head->r.eof = false;
	return 0;
}

/**
 * cs_read_pid - Read information of a process.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns nothing.
 *
 * Reads the domainname which the specified PID is in or
 * process information of the specified PID on success.
 *
 * Caller holds cs_read_lock().
 */
static void cs_read_pid(struct cs_io_buffer *head)
{
	char *buf = head->write_buf;
	bool task_info = false;
	bool global_pid = false;
	unsigned int pid;
	struct task_struct *p;
	struct cs_domain_info *domain = NULL;
	u32 cs_flags = 0;

	/* Accessing write_buf is safe because head->io_sem is held. */
	if (!buf) {
		head->r.eof = true;
		return; /* Do nothing if open(O_RDONLY). */
	}
	if (head->r.w_pos || head->r.eof)
		return;
	head->r.eof = true;
	if (cs_str_starts(&buf, "info "))
		task_info = true;
	if (cs_str_starts(&buf, "global-pid "))
		global_pid = true;
	pid = (unsigned int) simple_strtoul(buf, NULL, 10);
	cs_tasklist_lock();
	if (global_pid)
		p = caitsith_exports.find_task_by_pid_ns(pid, &init_pid_ns);
	else
		p = caitsith_exports.find_task_by_vpid(pid);
	if (p) {
		domain = cs_task_domain(p);
		cs_flags = cs_task_flags(p);
	}
	cs_tasklist_unlock();
	if (!domain)
		return;
	if (!task_info) {
		cs_io_printf(head, "%u ", pid);
		cs_set_string(head, domain->domainname->name);
	} else {
		cs_io_printf(head, "%u manager=%s execute_handler=%s ", pid,
			     cs_yesno(cs_flags &
				      CS_TASK_IS_MANAGER),
			     cs_yesno(cs_flags &
				      CS_TASK_IS_EXECUTE_HANDLER));
	}
}

/**
 * cs_update_group - Update "struct cs_string_group"/"struct cs_number_group"/"struct cs_ip_group" list.
 *
 * @head: Pointer to "struct cs_io_buffer".
 * @type: Type of this group.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_update_group(struct cs_io_buffer *head,
			   const enum cs_group_id type)
{
	u8 size;
	const bool is_delete = head->w.is_delete;
	int error = is_delete ? -ENOENT : -ENOMEM;
	struct cs_group *group = cs_get_group(head, type);
	char *word = cs_read_token(head);
	union {
		struct cs_acl_head head;
		struct cs_string_group path;
		struct cs_number_group number;
		struct cs_ip_group address;
	} e = { };

	if (!group)
		return -ENOMEM;
	if (!*word) {
		error = -EINVAL;
		goto out;
	}
	if (type == CS_STRING_GROUP) {
		if (!cs_correct_word(word)) {
			error = -EINVAL;
			goto out;
		}
		e.path.member_name = cs_get_name(word);
		if (!e.path.member_name) {
			error = -ENOMEM;
			goto out;
		}
		size = sizeof(e.path);
	} else if (type == CS_NUMBER_GROUP) {
		e.number.radix = cs_parse_values(word, e.number.value);
		if (e.number.radix == CS_VALUE_TYPE_INVALID)
			goto out;
		size = sizeof(e.number);
	} else {
#ifdef CONFIG_CAITSITH_NETWORK
		switch (cs_parse_ipaddr(word, e.address.ip)) {
		case CS_IMM_IPV4ADDR_ENTRY1:
		case CS_IMM_IPV4ADDR_ENTRY2:
			e.address.is_ipv6 = false;
			break;
		case CS_IMM_IPV6ADDR_ENTRY1:
		case CS_IMM_IPV6ADDR_ENTRY2:
			e.address.is_ipv6 = true;
			break;
		default:
			goto out;
		}
		size = sizeof(e.address);
#else
		goto out;
#endif
	}
	if (mutex_lock_killable(&cs_policy_lock) == 0) {
		struct cs_acl_head *entry;

		list_for_each_entry_srcu(entry, &group->member_list,
					 list, srcu_read_lock_held(&cs_ss)) {
			if (entry->is_deleted == CS_GC_IN_PROGRESS ||
			    memcmp(entry + 1, &e.head + 1,
				   size - sizeof(*entry)))
				continue;
			entry->is_deleted = is_delete;
			error = 0;
			break;
		}
		if (error && !is_delete) {
			entry = cs_commit_ok(&e, size);
			if (entry) {
				list_add_tail_rcu(&entry->list,
						  &group->member_list);
				error = 0;
			}
		}
		mutex_unlock(&cs_policy_lock);
	}
	if (type == CS_STRING_GROUP)
		cs_put_name(e.path.member_name);
out:
	cs_put_group(group);
	return error;
}

/**
 * cs_write_policy - Write policy.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_write_policy(struct cs_io_buffer *head)
{
	enum cs_group_id i;
	unsigned int priority;
	char *word = cs_read_token(head);

	if (sscanf(word, "%u", &priority) == 1)
		word = cs_read_token(head);
	else
		priority = 1000;
	if (priority >= 65536 || !*word)
		return -EINVAL;
	head->w.priority = priority;
	if (!head->w.acl)
		goto no_acl_selected;
	head->w.is_deny = !strcmp(word, "deny");
	if (head->w.is_deny || !strcmp(word, "allow"))
		return cs_update_acl(&head->w.acl->acl_info_list, head,
				     false);
	if (!strcmp(word, "audit")) {
		head->w.acl->audit = simple_strtoul(head->w.data, NULL, 10);
		return 0;
	}
	head->w.acl = NULL;
no_acl_selected:
	if (cs_select_acl(head, word))
		return 0;
	if (!strcmp(word, "acl"))
		return cs_parse_entry(head);
	for (i = 0; i < CS_MAX_GROUP; i++)
		if (!strcmp(word, cs_group_name[i]))
			return cs_update_group(head, i);
	if (sscanf(word, "POLICY_VERSION=%u", &cs_policy_version) == 1)
		return 0;
	if (strcmp(word, "quota"))
		return -EINVAL;
	if (cs_str_starts(&head->w.data, "memory "))
		return cs_write_memory_quota(head->w.data);
	return cs_write_audit_quota(head->w.data);
}

/**
 * cs_read_subgroup - Read "struct cs_string_group"/"struct cs_number_group"/"struct cs_ip_group" list.
 *
 * @head:  Pointer to "struct cs_io_buffer".
 * @group: Pointer to "struct cs_group".
 * @idx:   One of values in "enum cs_group_id".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds cs_read_lock().
 */
static bool cs_read_subgroup(struct cs_io_buffer *head,
			     struct cs_group *group,
			     const enum cs_group_id idx)
{
	list_for_each_cookie(head->r.acl, &group->member_list) {
		struct cs_acl_head *ptr =
			list_entry(head->r.acl, typeof(*ptr), list);

		if (ptr->is_deleted)
			continue;
		if (!cs_flush(head))
			return false;
		cs_set_string(head, cs_group_name[idx]);
		cs_set_space(head);
		cs_set_string(head, group->group_name->name);
		cs_set_space(head);
		if (idx == CS_STRING_GROUP) {
			cs_set_string(head, container_of
				      (ptr, struct cs_string_group,
				       head)->member_name->name);
		} else if (idx == CS_NUMBER_GROUP) {
			struct cs_number_group *e =
				container_of(ptr, typeof(*e), head);

			cs_print_number(head, e->radix & 3, e->value[0]);
			if (e->radix >> 2) {
				cs_set_string(head, "-");
				cs_print_number(head, (e->radix >> 2) & 3,
						e->value[1]);
			}
#ifdef CONFIG_CAITSITH_NETWORK
		} else if (idx == CS_IP_GROUP) {
			cs_print_ip(head, container_of
				    (ptr, struct cs_ip_group, head));
#endif
		}
		cs_set_lf(head);
	}
	head->r.acl = NULL;
	return true;
}

/**
 * cs_read_group - Read "struct cs_string_group"/"struct cs_number_group"/"struct cs_ip_group" list.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds cs_read_lock().
 */
static bool cs_read_group(struct cs_io_buffer *head)
{
	while (head->r.step < CS_MAX_GROUP) {
		const enum cs_group_id idx = head->r.step;
		struct list_head *list = &cs_group_list[idx];

		list_for_each_cookie(head->r.group, list) {
			struct cs_group *group =
				list_entry(head->r.group, typeof(*group),
					   head.list);

			if (!cs_read_subgroup(head, group, idx))
				return false;
		}
		head->r.group = NULL;
		head->r.step++;
	}
	head->r.step = 0;
	return true;
}

/**
 * cs_supervisor - Ask for the supervisor's decision.
 *
 * @r: Pointer to "struct cs_request_info".
 *
 * Returns 0 if the supervisor decided to permit the access request,
 * CS_RETRY_REQUEST if the supervisor decided to retry the access request,
 * -EPERM otherwise.
 */
static int cs_supervisor(struct cs_request_info *r)
{
	int error = -EPERM;
	int len;
	static unsigned int cs_serial;
	struct cs_query entry = { };
	bool quota_exceeded = false;

	if (!r->matched_acl)
		return -EPERM;
	/* Get message. */
	entry.query = cs_init_log(r);
	if (!entry.query)
		return -EPERM;
	entry.query_len = strlen(entry.query) + 1;
	len = cs_ksize(entry.query);
	entry.acl = r->matched_acl;
	entry.acl_type = r->type;
	spin_lock(&cs_query_list_lock);
	if (cs_memory_quota[CS_MEMORY_QUERY] &&
	    cs_memory_used[CS_MEMORY_QUERY] + len
	    >= cs_memory_quota[CS_MEMORY_QUERY]) {
		quota_exceeded = true;
	} else {
		entry.serial = cs_serial++;
		entry.retry = r->retry;
		cs_memory_used[CS_MEMORY_QUERY] += len;
		list_add_tail(&entry.list, &cs_query_list);
	}
	spin_unlock(&cs_query_list_lock);
	if (quota_exceeded)
		goto out;
	/* Give 10 seconds for supervisor's opinion. */
	while (entry.timer < 10) {
		wake_up_all(&cs_query_wait);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
		if (wait_event_killable_timeout
		    (cs_answer_wait, entry.answer ||
		     !atomic_read(&cs_query_observers), HZ))
			break;
		else
			entry.timer++;
#else
		if (wait_event_timeout
		    (cs_answer_wait, entry.answer ||
		     !atomic_read(&cs_query_observers) ||
		     fatal_signal_pending(current), HZ))
			break;
		else
			entry.timer++;
#endif
	}
	spin_lock(&cs_query_list_lock);
	list_del(&entry.list);
	cs_memory_used[CS_MEMORY_QUERY] -= len;
	spin_unlock(&cs_query_list_lock);
	switch (entry.answer) {
	case 3: /* Asked to retry by administrator. */
		error = CS_RETRY_REQUEST;
		r->retry++;
		break;
	case 1:
		/* Granted by administrator. */
		error = 0;
		break;
	default:
		/* Timed out or rejected by administrator. */
		break;
	}
out:
	kfree(entry.query);
	return error;
}

/**
 * cs_audit_log - Audit permission check log.
 *
 * @r: Pointer to "struct cs_request_info".
 *
 * Returns 0 to grant the request, CS_RETRY_REQUEST to retry the permission
 * check, -EPERM otherwise.
 */
int cs_audit_log(struct cs_request_info *r)
{
	/* Do not reject if not yet activated. */
	if (!cs_policy_loaded)
		return 0;
	/* Write /sys/kernel/security/caitsith/audit unless quota exceeded. */
	if (cs_log_count[r->result] < cs_log_quota[r->audit][r->result])
		cs_write_log(r);
	/* Nothing more to do unless denied. */
	if (r->result != CS_MATCHING_DENIED)
		return 0;
	/* Update policy violation counter if denied. */
	cs_update_stat(CS_STAT_REQUEST_DENIED);
	/* Nothing more to do unless caitsith-queryd is running. */
	if (!atomic_read(&cs_query_observers))
		return -EPERM;
	/* Ask the caitsith-queryd for decision. */
	return cs_supervisor(r);
}

/**
 * cs_find_acl_by_qid - Get ACL by query id.
 *
 * @serial: Query ID assigned by cs_supervisor().
 * @type:   Pointer to "enum cs_mac_index".
 *
 * Returns pointer to "struct cs_acl_info" if found, NULL otherwise.
 *
 * @type holds "enum cs_mac_index" value if found.
 */
static struct cs_acl_info *cs_find_acl_by_qid(unsigned int serial,
					      enum cs_mac_index *type)
{
	struct cs_query *ptr;
	struct cs_acl_info *acl = NULL;

	spin_lock(&cs_query_list_lock);
	list_for_each_entry(ptr, &cs_query_list, list) {
		if (ptr->serial != serial)
			continue;
		acl = ptr->acl;
		*type = ptr->acl_type;
		break;
	}
	spin_unlock(&cs_query_list_lock);
	return acl;
}

/**
 * cs_read_query - Read access requests which violated policy in enforcing mode.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns nothing.
 */
static void cs_read_query(struct cs_io_buffer *head)
{
	struct list_head *tmp;
	unsigned int pos = 0;
	size_t len = 0;
	char *buf;

	if (head->r.w_pos)
		return;
	kfree(head->read_buf);
	head->read_buf = NULL;
	spin_lock(&cs_query_list_lock);
	list_for_each(tmp, &cs_query_list) {
		struct cs_query *ptr = list_entry(tmp, typeof(*ptr), list);

		if (pos++ != head->r.query_index)
			continue;
		len = ptr->query_len;
		break;
	}
	spin_unlock(&cs_query_list_lock);
	if (!len) {
		head->r.query_index = 0;
		return;
	}
	buf = kzalloc(len + 32, GFP_NOFS);
	if (!buf)
		return;
	pos = 0;
	spin_lock(&cs_query_list_lock);
	list_for_each(tmp, &cs_query_list) {
		struct cs_query *ptr = list_entry(tmp, typeof(*ptr), list);

		if (pos++ != head->r.query_index)
			continue;
		/*
		 * Some query can be skipped because cs_query_list
		 * can change, but I don't care.
		 */
		if (len == ptr->query_len)
			snprintf(buf, len + 31, "Q%u-%hu\n%s", ptr->serial,
				 ptr->retry, ptr->query);
		break;
	}
	spin_unlock(&cs_query_list_lock);
	if (buf[0]) {
		head->read_buf = buf;
		head->r.w[head->r.w_pos++] = buf;
		head->r.query_index++;
	} else {
		kfree(buf);
	}
}

/**
 * cs_write_answer - Write the supervisor's decision.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int cs_write_answer(struct cs_io_buffer *head)
{
	char *data = head->write_buf;
	struct list_head *tmp;
	unsigned int serial;
	unsigned int answer;

	spin_lock(&cs_query_list_lock);
	list_for_each(tmp, &cs_query_list) {
		struct cs_query *ptr = list_entry(tmp, typeof(*ptr), list);

		ptr->timer = 0;
	}
	spin_unlock(&cs_query_list_lock);
	if (sscanf(data, "A%u=%u", &serial, &answer) != 2)
		return -EINVAL;
	spin_lock(&cs_query_list_lock);
	list_for_each(tmp, &cs_query_list) {
		struct cs_query *ptr = list_entry(tmp, typeof(*ptr), list);

		if (ptr->serial != serial)
			continue;
		ptr->answer = (u8) answer;
		/* Remove from cs_query_list. */
		if (ptr->answer) {
			list_del(&ptr->list);
			INIT_LIST_HEAD(&ptr->list);
		}
		break;
	}
	spin_unlock(&cs_query_list_lock);
	wake_up_all(&cs_answer_wait);
	return 0;
}

/**
 * cs_read_version - Get version.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns nothing.
 */
static void cs_read_version(struct cs_io_buffer *head)
{
	if (head->r.eof)
		return;
	cs_set_string(head, "0.2");
	head->r.eof = true;
}

/**
 * cs_update_stat - Update statistic counters.
 *
 * @index: Index for policy type.
 *
 * Returns nothing.
 */
static void cs_update_stat(const u8 index)
{
	atomic_inc(&cs_stat_updated[index]);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	cs_stat_modified[index] = get_seconds();
#else
	cs_stat_modified[index] = ktime_get_real_seconds();
#endif
}

/**
 * cs_read_stat - Read statistic data.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns nothing.
 */
static void cs_read_stat(struct cs_io_buffer *head)
{
	u8 i;

	for (i = 0; i < CS_MAX_POLICY_STAT; i++) {
		static const char * const k[CS_MAX_POLICY_STAT] = {
			[CS_STAT_POLICY_UPDATES] = "Policy updated:",
			[CS_STAT_REQUEST_DENIED] = "Requests denied:",
		};

		cs_io_printf(head, "stat %s %u", k[i],
			     atomic_read(&cs_stat_updated[i]));
		if (cs_stat_modified[i]) {
			struct cs_time stamp;

			cs_convert_time(cs_stat_modified[i], &stamp);
			cs_io_printf(head,
				     " (Last: %04u/%02u/%02u %02u:%02u:%02u)",
				     stamp.year, stamp.month, stamp.day,
				     stamp.hour, stamp.min, stamp.sec);
		}
		cs_set_lf(head);
	}
	for (i = 0; i < CS_MAX_MEMORY_STAT; i++)
		cs_io_printf(head, "stat Memory used by %s: %u\n",
			     cs_memory_headers[i], cs_memory_used[i]);
}

/**
 * cs_read_quota - Read quota data.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns true on success, false otherwise.
 */
static bool cs_read_quota(struct cs_io_buffer *head)
{
	unsigned int i;

	while (head->r.step < CS_MAX_MEMORY_STAT) {
		i = head->r.step++;
		if (!cs_memory_quota[i])
			continue;
		cs_io_printf(head, "quota memory %s %u\n",
			     cs_memory_headers[i], cs_memory_quota[i]);
	}
	while (head->r.step < CS_MAX_LOG_QUOTA + CS_MAX_MEMORY_STAT) {
		unsigned int a;
		unsigned int d;
		unsigned int u;

		if (!cs_flush(head))
			return false;
		i = head->r.step - CS_MAX_MEMORY_STAT;
		a = cs_log_quota[i][CS_MATCHING_ALLOWED];
		d = cs_log_quota[i][CS_MATCHING_DENIED];
		u = cs_log_quota[i][CS_MATCHING_UNMATCHED];
		if (a || d || u)
			cs_io_printf(head,
				     "quota audit[%u] allowed=%u denied=%u unmatched=%u\n",
				     i, a, d, u);
		head->r.step++;
	}
	head->r.step = 0;
	return true;
}

/**
 * cs_write_memory_quota - Set memory quota.
 *
 * @data: Line to parse.
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int cs_write_memory_quota(char *data)
{
	u8 i;

	for (i = 0; i < CS_MAX_MEMORY_STAT; i++)
		if (cs_str_starts(&data, cs_memory_headers[i])) {
			if (*data == ' ')
				data++;
			cs_memory_quota[i] =
				simple_strtoul(data, NULL, 10);
			return 0;
		}
	return -EINVAL;
}

/**
 * cs_write_audit_quota - Set audit log quota.
 *
 * @data: Line to parse.
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int cs_write_audit_quota(char *data)
{
	unsigned int i;

	if (sscanf(data, "audit[%u]", &i) != 1 || i >= CS_MAX_LOG_QUOTA)
		return -EINVAL;
	data = strchr(data, ' ');
	if (!data++)
		return -EINVAL;
	while (1) {
		unsigned int logs;
		char *cp = strchr(data, ' ');

		if (cp)
			*cp++ = '\0';
		if (sscanf(data, "allowed=%u", &logs) == 1)
			cs_log_quota[i][CS_MATCHING_ALLOWED] = logs;
		else if (sscanf(data, "denied=%u", &logs) == 1)
			cs_log_quota[i][CS_MATCHING_DENIED] = logs;
		else if (sscanf(data, "unmatched=%u", &logs) == 1)
			cs_log_quota[i][CS_MATCHING_UNMATCHED] = logs;
		if (!cp)
			break;
		data = cp;
	}
	return 0;
}

/**
 * cs_print_bprm - Print "struct linux_binprm" for auditing.
 *
 * @bprm: Pointer to "struct linux_binprm".
 * @dump: Pointer to "struct cs_page_dump".
 *
 * Returns the contents of @bprm on success, NULL otherwise.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *cs_print_bprm(struct linux_binprm *bprm,
			   struct cs_page_dump *dump)
{
	static const int cs_buffer_len = 4096 * 2;
	char *buffer = kzalloc(cs_buffer_len, GFP_NOFS);
	char *cp;
	char *last_start;
	unsigned long pos = bprm->p;
	int offset = pos % PAGE_SIZE;
	int argv_count = bprm->argc;
	int envp_count = bprm->envc;
	bool skip = false;
	bool env_value = false;

	if (!buffer)
		return NULL;
	cp = buffer + snprintf(buffer, cs_buffer_len - 1, " argc=%d envc=%d",
			       argv_count, envp_count);
	last_start = cp;
	while (argv_count || envp_count) {
		if (!cs_dump_page(bprm, pos, dump)) {
			kfree(buffer);
			return NULL;
		}
		pos += PAGE_SIZE - offset;
		/* Read. */
		while (offset < PAGE_SIZE) {
			const char *kaddr = dump->data;
			const unsigned char c = kaddr[offset++];
			int len;

			/* Check for end of buffer. */
			if (skip) {
				if (c)
					continue;
				goto reset;
			}
			len = buffer + cs_buffer_len - cp - 1;
			if (len <= 32 && c) {
				cp = last_start;
				skip = true;
				continue;
			}
			/* Print argv[$index]=" or envp[" part. */
			if (cp == last_start) {
				int l;

				if (argv_count)
					l = snprintf(cp, len, " argv[%u]=\"",
						     bprm->argc - argv_count);
				else
					l = snprintf(cp, len, " envp[\"");
				cp += l;
				len -= l;
			}
			if (c > ' ' && c < 127 && c != '\\') {
				/* Print "]=" part if printing environ. */
				if (c == '=' && !argv_count && !env_value) {
					cp += snprintf(cp, len, "\"]=\"");
					env_value = true;
				} else
					*cp++ = c;
				continue;
			}
			if (c) {
				*cp++ = '\\';
				*cp++ = (c >> 6) + '0';
				*cp++ = ((c >> 3) & 7) + '0';
				*cp++ = (c & 7) + '0';
				continue;
			}
			/* Print "]=" part if not yet printed. */
			if (!argv_count && !env_value)
				cp += snprintf(cp, len, "\"]=\"");
			*cp++ = '"';
			last_start = cp;
reset:
			skip = false;
			env_value = false;
			if (argv_count)
				argv_count--;
			else if (envp_count)
				envp_count--;
			if (!argv_count && !envp_count)
				break;
		}
		offset = 0;
	}
	*cp = '\0';
	return buffer;
}

/**
 * cs_filetype - Get string representation of file type.
 *
 * @mode: Mode value for stat().
 *
 * Returns file type string.
 */
static inline const char *cs_filetype(const umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case 0:
		return "file";
	case S_IFDIR:
		return "directory";
	case S_IFLNK:
		return "symlink";
	case S_IFIFO:
		return "fifo";
	case S_IFSOCK:
		return "socket";
	case S_IFBLK:
		return "block";
	case S_IFCHR:
		return "char";
	}
	return "unknown"; /* This should not happen. */
}

/**
 * cs_print_trailer - Get misc info of audit log.
 *
 * @r: Pointer to "struct cs_request_info".
 *
 * Returns string representation.
 *
 * This function uses kmalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *cs_print_trailer(struct cs_request_info *r)
{
	const char *handler =
		cs_current_flags() & CS_TASK_IS_EXECUTE_HANDLER ? "" : "!";
	const char *exe = r->exename.name;
	const char *domain = cs_current_domain()->domainname->name;
	const int cs_buffer_len = 2000 + strlen(exe) + strlen(domain);
	char *buffer = kmalloc(cs_buffer_len, GFP_NOFS);
	int pos;
	u8 i;

	if (!buffer)
		return NULL;
	pos = snprintf(buffer, cs_buffer_len - 1,
		       " task.pid=%u task.ppid=%u task.uid=%u task.gid=%u task.euid=%u task.egid=%u task.suid=%u task.sgid=%u task.fsuid=%u task.fsgid=%u task.type%s=execute_handler task.exe=\"%s\" task.domain=\"%s\"",
		       cs_sys_getpid(), cs_sys_getppid(),
		       from_kuid(&init_user_ns, current_uid()),
		       from_kgid(&init_user_ns, current_gid()),
		       from_kuid(&init_user_ns, current_euid()),
		       from_kgid(&init_user_ns, current_egid()),
		       from_kuid(&init_user_ns, current_suid()),
		       from_kgid(&init_user_ns, current_sgid()),
		       from_kuid(&init_user_ns, current_fsuid()),
		       from_kgid(&init_user_ns, current_fsgid()),
		       handler, exe, domain);
	if (!r->obj.path[0].dentry && !r->obj.path[1].dentry)
		goto no_obj_info;
	cs_get_attributes(r);
	for (i = 0; i < CS_MAX_PATH_STAT; i++) {
		const enum cs_conditions_index cond =
			CS_PATH_ATTRIBUTE_START + (i * 16);
		struct cs_mini_stat *stat;
		unsigned int dev;
		umode_t mode;

		if (!r->obj.stat_valid[i])
			continue;
		stat = &r->obj.stat[i];
		mode = stat->mode;
		pos += snprintf(buffer + pos, cs_buffer_len - 1 - pos,
				" %s=%u %s=%u %s=0%o",
				cs_condword(r->type, cond +
					    CS_PATH_ATTRIBUTE_UID),
				from_kuid(&init_user_ns, stat->uid),
				cs_condword(r->type, cond +
					    CS_PATH_ATTRIBUTE_GID),
				from_kgid(&init_user_ns, stat->gid),
				cs_condword(r->type, cond +
					    CS_PATH_ATTRIBUTE_PERM),
				mode & S_IALLUGO);
		/* No need to audit if parent directory. */
		if (i & 1)
			goto skip;
		pos += snprintf(buffer + pos, cs_buffer_len - 1 - pos,
				" %s=%s",
				cs_condword(r->type, cond +
					    CS_PATH_ATTRIBUTE_TYPE),
				cs_filetype(mode));
		/* No need to audit unless block or char. */
		if (!S_ISCHR(mode) && !S_ISBLK(mode))
			goto skip;
		dev = stat->rdev;
		pos += snprintf(buffer + pos, cs_buffer_len - 1 - pos,
				" %s=%u %s=%u",
				cs_condword(r->type, cond +
					    CS_PATH_ATTRIBUTE_DEV_MAJOR),
				MAJOR(dev),
				cs_condword(r->type, cond +
					    CS_PATH_ATTRIBUTE_DEV_MINOR),
				MINOR(dev));
skip:
		dev = stat->dev;
		pos += snprintf(buffer + pos, cs_buffer_len - 1 - pos,
				" %s=%llu %s=%u %s=%u %s=0x%lX",
				cs_condword(r->type, cond +
					    CS_PATH_ATTRIBUTE_INO),
				stat->ino,
				cs_condword(r->type, cond +
					    CS_PATH_ATTRIBUTE_MAJOR),
				MAJOR(dev),
				cs_condword(r->type, cond +
					    CS_PATH_ATTRIBUTE_MINOR),
				MINOR(dev),
				cs_condword(r->type, cond +
					    CS_PATH_ATTRIBUTE_FSMAGIC),
				stat->fsmagic);
	}
no_obj_info:
	if (pos < cs_buffer_len - 1)
		return buffer;
	kfree(buffer);
	return NULL;
}

/**
 * cs_print_param -  Get arg info of audit log.
 *
 * @r:   Pointer to "struct cs_request_info".
 * @buf: Buffer to write.
 * @len: Size of @buf in bytes.
 */
static int cs_print_param(struct cs_request_info *r, char *buf, int len)
{
#ifdef CONFIG_CAITSITH_NETWORK
	/* Make sure that IP address argument is ready. */
	char ip[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255")];

	switch (r->type) {
	case CS_MAC_INET_STREAM_BIND:
	case CS_MAC_INET_STREAM_LISTEN:
	case CS_MAC_INET_STREAM_CONNECT:
	case CS_MAC_INET_STREAM_ACCEPT:
	case CS_MAC_INET_DGRAM_BIND:
	case CS_MAC_INET_DGRAM_SEND:
	case CS_MAC_INET_RAW_BIND:
	case CS_MAC_INET_RAW_SEND:
		if (!r->param.ip)
			return 0;
		if (r->param.is_ipv6) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
			snprintf(ip, sizeof(ip), "%pI6c",
				 (const struct in6_addr *) r->param.ip);
#else
			ip6_compressed_string(ip, (const u8 *) r->param.ip);
#endif
		} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
			snprintf(ip, sizeof(ip), "%pI4", r->param.ip);
#else
			ip4_string(ip, r->param.ip);
#endif
		}
		break;
	default:
		break;
	}
#endif
	/* Make sure that string arguments are ready. */
	if (!r->param.s[0] && r->obj.path[0].dentry) {
		cs_populate_patharg(r, true);
		if (!r->param.s[0])
			return 0;
	}
	if (!r->param.s[1] && r->obj.path[1].dentry) {
		cs_populate_patharg(r, false);
		if (!r->param.s[1])
			return 0;
	}
	switch (r->type) {
		int pos;
		u8 i;
	case CS_MAC_EXECUTE:
		return snprintf(buf, len, " exec=\"%s\" path=\"%s\"",
				r->param.s[1]->name, r->param.s[0]->name);
	case CS_MAC_READ:
	case CS_MAC_WRITE:
	case CS_MAC_APPEND:
	case CS_MAC_UNLINK:
#ifdef CONFIG_CAITSITH_GETATTR
	case CS_MAC_GETATTR:
#endif
	case CS_MAC_RMDIR:
	case CS_MAC_TRUNCATE:
	case CS_MAC_CHROOT:
		return snprintf(buf, len, " path=\"%s\"", r->param.s[0]->name);
	case CS_MAC_CREATE:
	case CS_MAC_MKDIR:
	case CS_MAC_MKFIFO:
	case CS_MAC_MKSOCK:
		return snprintf(buf, len, " path=\"%s\" perm=0%lo",
				r->param.s[0]->name, r->param.i[0]);
	case CS_MAC_SYMLINK:
		return snprintf(buf, len, " path=\"%s\" target=\"%s\"",
				r->param.s[0]->name, r->param.s[1]->name);
	case CS_MAC_MKBLOCK:
	case CS_MAC_MKCHAR:
		return snprintf(buf, len,
				" path=\"%s\" perm=0%lo dev_major=%lu dev_minor=%lu",
				r->param.s[0]->name, r->param.i[0],
				r->param.i[1], r->param.i[2]);
	case CS_MAC_LINK:
	case CS_MAC_RENAME:
		return snprintf(buf, len, " old_path=\"%s\" new_path=\"%s\"",
				r->param.s[0]->name, r->param.s[1]->name);
	case CS_MAC_CHMOD:
		return snprintf(buf, len, " path=\"%s\" perm=0%lo",
				r->param.s[0]->name, r->param.i[0]);
	case CS_MAC_CHOWN:
		return snprintf(buf, len, " path=\"%s\" uid=%lu",
				r->param.s[0]->name, r->param.i[0]);
	case CS_MAC_CHGRP:
		return snprintf(buf, len, " path=\"%s\" gid=%lu",
				r->param.s[0]->name, r->param.i[0]);
	case CS_MAC_IOCTL:
		return snprintf(buf, len, " path=\"%s\" cmd=0x%lX",
				r->param.s[0]->name, r->param.i[0]);
	case CS_MAC_MOUNT:
		pos = 0;
		for (i = 0; i < 4; i++) {
			static const char * const cs_names[4] = {
				"source", "target", "fstype", "data"
			};
			if (i == 3)
				pos += snprintf(buf + pos, pos < len ?
						len - pos : 0, " flags=0x%lX",
						r->param.i[0]);
			if (!r->param.s[i])
				continue;
			pos += snprintf(buf + pos, pos < len ? len - pos : 0,
					" %s=\"%s\"", cs_names[i],
					r->param.s[i]->name);
		}
		return pos;
	case CS_MAC_UMOUNT:
		return snprintf(buf, len, " path=\"%s\" flags=0x%lX",
				r->param.s[0]->name, r->param.i[0]);
	case CS_MAC_PIVOT_ROOT:
		return snprintf(buf, len, " new_root=\"%s\" put_old=\"%s\"",
				r->param.s[0]->name, r->param.s[1]->name);
#ifdef CONFIG_CAITSITH_ENVIRON
	case CS_MAC_ENVIRON:
		return snprintf(buf, len,
				" name=\"%s\" value=\"%s\" exec=\"%s\" path=\"%s\"",
				r->param.s[2]->name, r->param.s[3]->name,
				r->param.s[1]->name, r->param.s[0]->name);
#endif
#ifdef CONFIG_CAITSITH_NETWORK
	case CS_MAC_INET_STREAM_BIND:
	case CS_MAC_INET_STREAM_LISTEN:
	case CS_MAC_INET_STREAM_CONNECT:
	case CS_MAC_INET_STREAM_ACCEPT:
	case CS_MAC_INET_DGRAM_BIND:
	case CS_MAC_INET_DGRAM_SEND:
		return snprintf(buf, len, " ip=%s port=%lu", ip,
				r->param.i[0]);
	case CS_MAC_INET_RAW_BIND:
	case CS_MAC_INET_RAW_SEND:
		return snprintf(buf, len, " ip=%s proto=%lu", ip,
				r->param.i[0]);
	case CS_MAC_UNIX_STREAM_BIND:
	case CS_MAC_UNIX_STREAM_LISTEN:
	case CS_MAC_UNIX_STREAM_CONNECT:
	case CS_MAC_UNIX_STREAM_ACCEPT:
	case CS_MAC_UNIX_DGRAM_BIND:
	case CS_MAC_UNIX_DGRAM_SEND:
	case CS_MAC_UNIX_SEQPACKET_BIND:
	case CS_MAC_UNIX_SEQPACKET_LISTEN:
	case CS_MAC_UNIX_SEQPACKET_CONNECT:
	case CS_MAC_UNIX_SEQPACKET_ACCEPT:
		return snprintf(buf, len, " addr=\"%s\"", r->param.s[0]->name);
#endif
#ifdef CONFIG_CAITSITH_MANUAL_DOMAIN_TRANSITION
	case CS_MAC_MANUAL_DOMAIN_TRANSITION:
		return snprintf(buf, len, " domain=\"%s\"",
				r->param.s[0]->name);
#endif
	default:
		break;
	}
	return 0;
}

/**
 * cs_init_log - Allocate buffer for audit logs.
 *
 * @r: Pointer to "struct cs_request_info".
 *
 * Returns pointer to allocated memory.
 *
 * This function uses kzalloc(), so caller must kfree() if this function
 * didn't return NULL.
 */
static char *cs_init_log(struct cs_request_info *r)
{
	const pid_t gpid = task_pid_nr(current);
	struct cs_time stamp;
	static const char * const k[CS_MAX_MATCHING] = {
		[CS_MATCHING_UNMATCHED] = "unmatched",
		[CS_MATCHING_ALLOWED] = "allowed",
		[CS_MATCHING_DENIED] = "denied",
	};
	char *buf;
	const char *bprm_info;
	const char *trailer;
	int len;

	if (!r->exename.name && !cs_get_exename(&r->exename))
		return NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	cs_convert_time(get_seconds(), &stamp);
#else
	cs_convert_time(ktime_get_real_seconds(), &stamp);
#endif
	trailer = cs_print_trailer(r);
	if (r->bprm)
		bprm_info = cs_print_bprm(r->bprm, &r->dump);
	else
		bprm_info = NULL;
	len = 0;
	while (1) {
		int pos;

		buf = kzalloc(len, GFP_NOFS);
		if (!buf)
			break;
		pos = snprintf(buf, len,
			       "#%04u/%02u/%02u %02u:%02u:%02u# global-pid=%u result=%s priority=%u / %s",
			       stamp.year, stamp.month, stamp.day, stamp.hour,
			       stamp.min, stamp.sec, gpid, k[r->result],
			       r->matched_acl ? r->matched_acl->priority : 0,
			       cs_mac_keywords[r->type]);
		pos += cs_print_param(r, buf + pos,
				      pos < len ? len - pos : 0);
		if (bprm_info)
			pos += snprintf(buf + pos, pos < len ? len - pos : 0,
					"%s", bprm_info);
		if (trailer)
			pos += snprintf(buf + pos, pos < len ? len - pos : 0,
					"%s", trailer);
		pos += snprintf(buf + pos, pos < len ? len - pos : 0,
				"\n") + 1;
		if (pos <= len)
			break;
		kfree(buf);
		len = pos;
	}
	kfree(bprm_info);
	kfree(trailer);
	return buf;
}

/**
 * cs_write_log - Write an audit log.
 *
 * @r: Pointer to "struct cs_request_info".
 *
 * Returns nothing.
 */
static void cs_write_log(struct cs_request_info *r)
{
	struct cs_log *entry;
	bool quota_exceeded = false;
	char *buf = cs_init_log(r);

	if (!buf)
		return;
	entry = kzalloc(sizeof(*entry), GFP_NOFS);
	if (!entry) {
		kfree(buf);
		return;
	}
	entry->log = buf;
	/*
	 * The entry->size is used for memory quota checks.
	 * Don't go beyond strlen(entry->log).
	 */
	entry->size = cs_ksize(buf) + cs_ksize(entry);
	entry->result = r->result;
	spin_lock(&cs_log_lock);
	if (cs_memory_quota[CS_MEMORY_AUDIT] &&
	    cs_memory_used[CS_MEMORY_AUDIT] + entry->size >=
	    cs_memory_quota[CS_MEMORY_AUDIT]) {
		quota_exceeded = true;
	} else {
		cs_memory_used[CS_MEMORY_AUDIT] += entry->size;
		list_add_tail(&entry->list, &cs_log);
		cs_log_count[entry->result]++;
	}
	spin_unlock(&cs_log_lock);
	if (quota_exceeded) {
		kfree(buf);
		kfree(entry);
		return;
	}
	wake_up(&cs_log_wait);
}

/**
 * cs_read_log - Read an audit log.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Returns nothing.
 */
static void cs_read_log(struct cs_io_buffer *head)
{
	struct cs_log *ptr = NULL;

	if (head->r.w_pos)
		return;
	kfree(head->read_buf);
	head->read_buf = NULL;
	spin_lock(&cs_log_lock);
	if (!list_empty(&cs_log)) {
		ptr = list_entry(cs_log.next, typeof(*ptr), list);
		list_del(&ptr->list);
		cs_log_count[ptr->result]--;
		cs_memory_used[CS_MEMORY_AUDIT] -= ptr->size;
	}
	spin_unlock(&cs_log_lock);
	if (ptr) {
		head->read_buf = ptr->log;
		head->r.w[head->r.w_pos++] = head->read_buf;
		kfree(ptr);
	}
}

/**
 * cs_transit_domain - Transit to other domain.
 *
 * @domainname: The name of domain.
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds cs_read_lock().
 */
bool cs_transit_domain(const char *domainname)
{
	struct cs_security *security = cs_current_security();
	struct cs_domain_info e = { };
	struct cs_domain_info *entry = cs_find_domain(domainname);

	if (entry) {
		security->cs_domain_info = entry;
		return true;
	}
	/* Requested domain does not exist. */
	/* Don't create requested domain if domainname is invalid. */
	if (!cs_correct_domain(domainname))
		return false;
	e.domainname = cs_get_name(domainname);
	if (!e.domainname)
		return false;
	if (mutex_lock_killable(&cs_policy_lock))
		goto out;
	entry = cs_find_domain(domainname);
	if (entry)
		goto done;
	entry = cs_commit_ok(&e, sizeof(e));
	if (!entry)
		goto done;
	list_add_tail_rcu(&entry->list, &cs_domain_list);
done:
	mutex_unlock(&cs_policy_lock);
out:
	cs_put_name(e.domainname);
	if (entry)
		security->cs_domain_info = entry;
	return entry != NULL;
}

/**
 * cs_parse_policy - Parse a policy line.
 *
 * @head: Pointer to "struct cs_io_buffer".
 * @line: Line to parse.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Caller holds cs_read_lock().
 */
static int cs_parse_policy(struct cs_io_buffer *head, char *line)
{
	/* Set current line's content. */
	head->w.data = line;
	head->w.is_deny = false;
	head->w.priority = 0;
	/* Delete request? */
	head->w.is_delete = !strncmp(line, "delete ", 7);
	if (head->w.is_delete)
		memmove(line, line + 7, strlen(line + 7) + 1);
	/* Do the update. */
	switch (head->type) {
#ifdef CONFIG_CAITSITH_EXECUTE_HANDLER
	case CS_EXECUTE_HANDLER:
#endif
	case CS_PROCESS_STATUS:
		return cs_write_pid(head);
	case CS_QUERY:
		return cs_write_answer(head);
	case CS_POLICY:
		return cs_write_policy(head);
	default:
		return -EINVAL;
	}
}

/**
 * cs_load_builtin_policy - Load built-in policy.
 *
 * Returns nothing.
 */
static void __init cs_load_builtin_policy(void)
{
	/*
	 * This include file is manually created and contains built-in policy.
	 *
	 * static char [] __initdata cs_builtin_policy = { ... };
	 */
#include "builtin-policy.h"
	const int idx = cs_read_lock();
	struct cs_io_buffer head = { };
	char *start = cs_builtin_policy;

	head.type = CS_POLICY;
	while (1) {
		char *end = strchr(start, '\n');

		if (!end)
			break;
		*end = '\0';
		cs_normalize_line(start);
		head.write_buf = start;
		cs_parse_policy(&head, start);
		start = end + 1;
	}
	cs_read_unlock(idx);
#ifdef CONFIG_CAITSITH_OMIT_USERSPACE_LOADER
	cs_check_profile();
#endif
}

/**
 * cs_read_self - read() for /sys/kernel/security/caitsith/self_domain interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Domainname which current thread belongs to.
 * @count: Size of @buf.
 * @ppos:  Bytes read by now.
 *
 * Returns read size on success, negative value otherwise.
 */
static ssize_t cs_read_self(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos)
{
	const char *domain = cs_current_domain()->domainname->name;
	loff_t len = strlen(domain);
	loff_t pos = *ppos;

	if (pos >= len || !count)
		return 0;
	len -= pos;
	if (count < len)
		len = count;
	if (copy_to_user(buf, domain + pos, len))
		return -EFAULT;
	*ppos += len;
	return len;
}

/**
 * cs_read_subacl - Read sub ACL in ACL entry.
 *
 * @head: Pointer to "struct cs_io_buffer".
 * @list: Pointer to "struct list_head".
 *
 * Returns true on success, false otherwise.
 *
 * Caller holds cs_read_lock().
 */
static bool cs_read_subacl(struct cs_io_buffer *head,
			   const struct list_head *list)
{
	list_for_each_cookie(head->r.subacl, list) {
		struct cs_acl_info *acl =
			list_entry(head->r.subacl, typeof(*acl), list);

		switch (head->r.step) {
		case 3:
			if (acl->is_deleted)
				continue;
			if (!cs_flush(head))
				return false;
			cs_io_printf(head, "    %u ", acl->priority);
			if (acl->is_deny)
				cs_set_string(head, "deny");
			else
				cs_set_string(head, "allow");
			head->r.cond_step = 0;
			head->r.step++;
			/* fall through */
			fallthrough;
		case 4:
			if (!cs_flush(head))
				return false;
			if (acl->cond &&
			    !cs_print_condition(head, acl->cond))
				return false;
			cs_set_lf(head);
			head->r.step--;
		}
	}
	head->r.subacl = NULL;
	return true;
}

/**
 * cs_read_policy - Read policy.
 *
 * @head: Pointer to "struct cs_io_buffer".
 *
 * Caller holds cs_read_lock().
 */
static void cs_read_policy(struct cs_io_buffer *head)
{
	if (head->r.eof)
		return;
	if (head->r.print_this_acl_only)
		goto skip;
	if (!head->r.version_done) {
		cs_io_printf(head, "POLICY_VERSION=%u\n", cs_policy_version);
		head->r.version_done = true;
	}
	if (!head->r.stat_done) {
		cs_read_stat(head);
		head->r.stat_done = true;
	}
	if (!head->r.quota_done) {
		if (!cs_read_quota(head))
			return;
		head->r.quota_done = true;
	}
	if (!head->r.group_done) {
		if (!cs_read_group(head))
			return;
		head->r.group_done = true;
		cs_set_lf(head);
	}
	while (head->r.acl_index < CS_MAX_MAC_INDEX) {
		list_for_each_cookie(head->r.acl,
				     &cs_acl_list[head->r.acl_index]) {
			struct cs_acl_info *ptr;

skip:
			ptr = list_entry(head->r.acl, typeof(*ptr), list);
			switch (head->r.step) {
			case 0:
				if (ptr->is_deleted &&
				    !head->r.print_this_acl_only)
					continue;
				head->r.step++;
				/* fall through */
				fallthrough;
			case 1:
				if (!cs_read_acl(head, ptr))
					return;
				head->r.step++;
				/* fall through */
				fallthrough;
			case 2:
				if (!cs_flush(head))
					return;
				cs_io_printf(head, "    audit %u\n",
					     ptr->audit);
				head->r.step++;
				/* fall through */
				fallthrough;
			case 3:
			case 4:
				if (!cs_read_subacl(head,
						    &ptr->acl_info_list))
					return;
				head->r.step = 5;
				/* fall through */
				fallthrough;
			case 5:
				if (!cs_flush(head))
					return;
				cs_set_lf(head);
				head->r.step = 0;
				if (head->r.print_this_acl_only)
					goto done;
			}
		}
		head->r.acl = NULL;
		head->r.acl_index++;
	}
done:
	head->r.eof = true;
}

/**
 * cs_open - open() for /sys/kernel/security/caitsith/ interface.
 *
 * @inode: Pointer to "struct inode".
 * @file:  Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cs_open(struct inode *inode, struct file *file)
{
	const u8 type = (unsigned long) inode->i_private;
	struct cs_io_buffer *head = kzalloc(sizeof(*head), GFP_NOFS);

	if (!head)
		return -ENOMEM;
	mutex_init(&head->io_sem);
	head->type = type;
#ifdef CONFIG_CAITSITH_EXECUTE_HANDLER
	if (type == CS_EXECUTE_HANDLER) {
		/* Allow execute_handler to read process's status. */
		if (!(cs_current_flags() & CS_TASK_IS_EXECUTE_HANDLER)) {
			kfree(head);
			return -EPERM;
		}
	}
#endif
	if ((file->f_mode & FMODE_READ) && type != CS_AUDIT &&
	    type != CS_QUERY) {
		/* Don't allocate read_buf for poll() access. */
		head->readbuf_size = 4096;
		head->read_buf = kzalloc(head->readbuf_size, GFP_NOFS);
		if (!head->read_buf) {
			kfree(head);
			return -ENOMEM;
		}
	}
	if (file->f_mode & FMODE_WRITE) {
		head->writebuf_size = 4096;
		head->write_buf = kzalloc(head->writebuf_size, GFP_NOFS);
		if (!head->write_buf) {
			kfree(head->read_buf);
			kfree(head);
			return -ENOMEM;
		}
	}
	/*
	 * If the file is /sys/kernel/security/caitsith/query , increment the
	 * observer counter. The obserber counter is used by cs_supervisor() to
	 * see if there is some process monitoring
	 * /sys/kernel/security/caitsith/query .
	 */
	if (type == CS_QUERY)
		atomic_inc(&cs_query_observers);
	file->private_data = head;
	cs_notify_gc(head, true);
	return 0;
}

/**
 * cs_release - close() for /sys/kernel/security/caitsith/ interface.
 *
 * @inode: Pointer to "struct inode".
 * @file:  Pointer to "struct file".
 *
 * Returns 0.
 */
static int cs_release(struct inode *inode, struct file *file)
{
	struct cs_io_buffer *head = file->private_data;

	/*
	 * If the file is /sys/kernel/security/caitsith/query ,
	 * decrement the observer counter.
	 */
	if (head->type == CS_QUERY &&
	    atomic_dec_and_test(&cs_query_observers))
		wake_up_all(&cs_answer_wait);
	cs_notify_gc(head, false);
	return 0;
}

/**
 * cs_poll - poll() for /sys/kernel/security/caitsith/ interface.
 *
 * @file: Pointer to "struct file".
 * @wait: Pointer to "poll_table". Maybe NULL.
 *
 * Returns POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM if ready to read/write,
 * POLLOUT | POLLWRNORM otherwise.
 */
static unsigned int cs_poll(struct file *file, poll_table *wait)
{
	struct cs_io_buffer *head = file->private_data;

	if (head->type == CS_AUDIT) {
		if (!cs_memory_used[CS_MEMORY_AUDIT]) {
			poll_wait(file, &cs_log_wait, wait);
			if (!cs_memory_used[CS_MEMORY_AUDIT])
				return POLLOUT | POLLWRNORM;
		}
	} else if (head->type == CS_QUERY) {
		if (list_empty(&cs_query_list)) {
			poll_wait(file, &cs_query_wait, wait);
			if (list_empty(&cs_query_list))
				return POLLOUT | POLLWRNORM;
		}
	}
	return POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM;
}

/**
 * cs_read - read() for /sys/kernel/security/caitsith/ interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Pointer to buffer.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns bytes read on success, negative value otherwise.
 */
static ssize_t cs_read(struct file *file, char __user *buf, size_t count,
		       loff_t *ppos)
{
	struct cs_io_buffer *head = file->private_data;
	int len;
	int idx;

	if (mutex_lock_killable(&head->io_sem))
		return -EINTR;
	head->read_user_buf = buf;
	head->read_user_buf_avail = count;
	idx = cs_read_lock();
	if (cs_flush(head)) {
		/* Call the policy handler. */
		switch (head->type) {
		case CS_AUDIT:
			cs_read_log(head);
			break;
#ifdef CONFIG_CAITSITH_EXECUTE_HANDLER
		case CS_EXECUTE_HANDLER:
#endif
		case CS_PROCESS_STATUS:
			cs_read_pid(head);
			break;
		case CS_VERSION:
			cs_read_version(head);
			break;
		case CS_QUERY:
			cs_read_query(head);
			break;
		case CS_POLICY:
			cs_read_policy(head);
			break;
		}
		cs_flush(head);
	}
	cs_read_unlock(idx);
	len = head->read_user_buf - buf;
	mutex_unlock(&head->io_sem);
	return len;
}

#ifdef CONFIG_CAITSITH_MANUAL_DOMAIN_TRANSITION

/**
 * cs_write_self - write() for /sys/kernel/security/caitsith/self_domain interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Domainname to transit to.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns @count on success, negative value otherwise.
 *
 * If domain transition was permitted but the domain transition failed, this
 * function returns error rather than terminating current thread with SIGKILL.
 */
static ssize_t cs_write_self(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	char *data;
	int error;

	if (!count || count >= CS_EXEC_TMPSIZE - 10)
		return -ENOMEM;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
	data = kzalloc(count + 1, GFP_NOFS);
	if (!data)
		return -ENOMEM;
	if (copy_from_user(data, buf, count)) {
		error = -EFAULT;
		goto out;
	}
#else
	data = memdup_user_nul(buf, count);
	if (IS_ERR(data))
		return PTR_ERR(data);
#endif
	cs_normalize_line(data);
	if (cs_correct_domain(data)) {
		const int idx = cs_read_lock();
		struct cs_path_info name;
		struct cs_request_info r = { };

		name.name = data;
		cs_fill_path_info(&name);
		/* Check "manual_domain_transition" permission. */
		r.type = CS_MAC_MANUAL_DOMAIN_TRANSITION;
		r.param.s[0] = &name;
		cs_check_acl(&r, true);
		if (r.result != CS_MATCHING_ALLOWED)
			error = -EPERM;
		else
			error = cs_transit_domain(data) ? 0 : -ENOENT;
		cs_read_unlock(idx);
	} else
		error = -EINVAL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
out:
#endif
	kfree(data);
	return error ? error : count;
}

#endif

/**
 * cs_write - write() for /sys/kernel/security/caitsith/ interface.
 *
 * @file:  Pointer to "struct file".
 * @buf:   Pointer to buffer.
 * @count: Size of @buf.
 * @ppos:  Unused.
 *
 * Returns @count on success, negative value otherwise.
 */
static ssize_t cs_write(struct file *file, const char __user *buf,
			size_t count, loff_t *ppos)
{
	struct cs_io_buffer *head = file->private_data;
	int error = count;
	char *cp0;
	int idx;

	if (mutex_lock_killable(&head->io_sem))
		return -EINTR;
	cp0 = head->write_buf;
	head->read_user_buf_avail = 0;
	idx = cs_read_lock();
	/* Read a line and dispatch it to the policy handler. */
	while (count) {
		char c;

		if (head->w.avail >= head->writebuf_size - 1) {
			const int len = head->writebuf_size * 2;
			char *cp = kzalloc(len, GFP_NOFS);

			if (!cp) {
				error = -ENOMEM;
				break;
			}
			memmove(cp, cp0, head->w.avail);
			kfree(cp0);
			head->write_buf = cp;
			cp0 = cp;
			head->writebuf_size = len;
		}
		if (get_user(c, buf)) {
			error = -EFAULT;
			break;
		}
		buf++;
		count--;
		cp0[head->w.avail++] = c;
		if (c != '\n')
			continue;
		cp0[head->w.avail - 1] = '\0';
		head->w.avail = 0;
		cs_normalize_line(cp0);
		/* Don't allow updating policies by non manager programs. */
		if (head->type != CS_PROCESS_STATUS && !cs_manager()) {
			error = -EPERM;
			goto out;
		}
		switch (cs_parse_policy(head, cp0)) {
		case -EPERM:
			error = -EPERM;
			goto out;
		case 0:
			/* Update statistics. */
			if (head->type == CS_POLICY)
				cs_update_stat(CS_STAT_POLICY_UPDATES);
			break;
		}
	}
out:
	cs_read_unlock(idx);
	mutex_unlock(&head->io_sem);
	return error;
}

/**
 * cs_create_entry - Create interface files under /sys/kernel/security/caitsith/ directory.
 *
 * @name:   The name of the interface file.
 * @mode:   The permission of the interface file.
 * @parent: The parent directory.
 * @key:    Type of interface.
 *
 * Returns nothing.
 */
static void __init cs_create_entry(const char *name, const umode_t mode,
				   struct dentry *parent, const u8 key)
{
	securityfs_create_file(name, S_IFREG | mode, parent,
			       (void *) (unsigned long) key, &cs_operations);
}

/**
 * cs_securityfs_init - Initialize /sys/kernel/security/caitsith/ interface.
 *
 * Returns nothing.
 */
static void __init cs_securityfs_init(void)
{
	struct dentry *cs_dir = securityfs_create_dir("caitsith", NULL);

	cs_create_entry("query",            0600, cs_dir, CS_QUERY);
	cs_create_entry("audit",            0400, cs_dir, CS_AUDIT);
	cs_create_entry(".process_status",  0600, cs_dir, CS_PROCESS_STATUS);
	cs_create_entry("version",          0400, cs_dir, CS_VERSION);
#ifdef CONFIG_CAITSITH_EXECUTE_HANDLER
	cs_create_entry(".execute_handler", 0666, cs_dir, CS_EXECUTE_HANDLER);
#endif
	cs_create_entry("policy",           0600, cs_dir, CS_POLICY);
	securityfs_create_file("self_domain", S_IFREG | 0666, cs_dir, NULL,
			       &cs_self_operations);
}

/**
 * cs_init_module - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
int __init cs_init_module(void)
{
	u16 idx;

#ifdef DEBUG_CONDITION
	for (idx = 0; idx < CS_MAX_MAC_INDEX; idx++) {
		if (cs_mac_keywords[idx])
			continue;
		printk(KERN_INFO "cs_mac_keywords[%u]==NULL\n", idx);
		return -EINVAL;
	}
#endif
	if (init_srcu_struct(&cs_ss))
		panic("Out of memory.");
	for (idx = 0; idx < CS_MAX_MAC_INDEX; idx++)
		INIT_LIST_HEAD(&cs_acl_list[idx]);
	for (idx = 0; idx < CS_MAX_GROUP; idx++)
		INIT_LIST_HEAD(&cs_group_list[idx]);
	for (idx = 0; idx < CS_MAX_HASH; idx++)
		INIT_LIST_HEAD(&cs_name_list[idx]);
	cs_null_name.name = "NULL";
	cs_fill_path_info(&cs_null_name);
	cs_kernel_domain.domainname = cs_get_name("<kernel>");
	list_add_tail_rcu(&cs_kernel_domain.list, &cs_domain_list);
	cs_securityfs_init();
	cs_load_builtin_policy();
	return 0;
}
