#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x590a0cf6, "lookup_one" },
	{ 0x92997ed8, "_printk" },
	{ 0xdc50aae2, "__ref_stack_chk_guard" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xa916b694, "strnlen" },
	{ 0x9f984513, "strrchr" },
	{ 0xd7d82d75, "module_put" },
	{ 0x65101c4f, "mntput" },
	{ 0x978a8576, "down_write" },
	{ 0xb81bc836, "up_write" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x5a921311, "strncmp" },
	{ 0xfe66c0cb, "const_current_task" },
	{ 0xc9fe1d62, "iov_iter_kvec" },
	{ 0x2a59e6a5, "__fortify_panic" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x980977ba, "get_fs_type" },
	{ 0x5e3b99e9, "dentry_open" },
	{ 0x62b64272, "filp_close" },
	{ 0x6d160be1, "__kmalloc_cache_noprof" },
	{ 0x905cec26, "dput" },
	{ 0x415fe330, "lockref_get" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x38bfd7a5, "vfs_kern_mount" },
	{ 0xe44854b5, "seq_read_iter" },
	{ 0x754d539c, "strlen" },
	{ 0xeba5e097, "latent_entropy" },
	{ 0xad6f6161, "kmalloc_caches" },
	{ 0xbc314156, "nop_mnt_idmap" },
	{ 0x656e4a6e, "snprintf" },
	{ 0x037a0cba, "kfree" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xdabd4f6b, "module_layout" },
};

MODULE_INFO(depends, "");

