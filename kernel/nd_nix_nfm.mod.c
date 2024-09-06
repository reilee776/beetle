#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xf8cdd757, "module_layout" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0xf4b9b193, "kmalloc_caches" },
	{ 0xde290808, "put_pid" },
	{ 0x58388972, "pv_lock_ops" },
	{ 0x349cba85, "strchr" },
	{ 0x754d539c, "strlen" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x7b4244f7, "device_destroy" },
	{ 0x6ad5f0ce, "__register_chrdev" },
	{ 0x85df9b6c, "strsep" },
	{ 0x65bc2e65, "get_net_ns_by_pid" },
	{ 0x91715312, "sprintf" },
	{ 0xc499ae1e, "kstrdup" },
	{ 0xb44ad4b3, "_copy_to_user" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xb65d55f0, "unregister_pernet_subsys" },
	{ 0x9202ba1c, "current_task" },
	{ 0x2e2b40d2, "strncat" },
	{ 0x27e1a049, "printk" },
	{ 0xe1537255, "__list_del_entry_valid" },
	{ 0xa80a9e09, "netlink_kernel_release" },
	{ 0x9166fada, "strncpy" },
	{ 0x41aed6e7, "mutex_lock" },
	{ 0xfae8f523, "device_create" },
	{ 0x22afdba8, "netlink_unicast" },
	{ 0x6e14fd0d, "pid_task" },
	{ 0xa29abf62, "init_net" },
	{ 0x68f31cbd, "__list_add_valid" },
	{ 0x154a7b04, "nf_register_net_hook" },
	{ 0xab70b232, "nf_unregister_net_hook" },
	{ 0x3c5dfeb0, "__alloc_skb" },
	{ 0xa916b694, "strnlen" },
	{ 0xdb7305a1, "__stack_chk_fail" },
	{ 0x3fa0d062, "kstrtou16" },
	{ 0x183e909f, "register_pernet_subsys" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xf86c8d03, "kmem_cache_alloc_trace" },
	{ 0xdbf17652, "_raw_spin_lock" },
	{ 0xb981a763, "find_get_pid" },
	{ 0x3204fe5f, "__netlink_kernel_create" },
	{ 0x37a0cba, "kfree" },
	{ 0xa46f2f1b, "kstrtouint" },
	{ 0x21e01071, "class_destroy" },
	{ 0x28318305, "snprintf" },
	{ 0xe113bbbc, "csum_partial" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x85a63ef0, "__nlmsg_put" },
	{ 0xe42dbab4, "__class_create" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "4C1F87C87FBDE02D6D91C70");
MODULE_INFO(rhelversion, "8.10");
