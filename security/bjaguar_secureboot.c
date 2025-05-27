// SPDX-License-Identifier: GPL-2.0
/*
 * B-Jaguar kernel secure boot enforcement:
 * Rejects unsigned kernel modules at load time.
 * This is a working implementation for enforcing module signature verification.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module_signature.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>

static int __init bjaguar_secureboot_init(void)
{
    pr_info("B-Jaguar Secure Boot: Enforcing module signature verification\n");

    /* Enforce module signature at kernel level */
#ifdef CONFIG_MODULE_SIG
    /* Set the module sig enforcement flag if not already set */
    if (!is_module_sig_enforced()) {
        set_module_sig_enforced();
        pr_info("B-Jaguar Secure Boot: Module signature enforcement enabled\n");
    }
#else
    pr_warn("B-Jaguar Secure Boot: Kernel not built with CONFIG_MODULE_SIG, cannot enforce module signatures!\n");
#endif

    return 0;
}

static void __exit bjaguar_secureboot_exit(void)
{
    pr_info("B-Jaguar Secure Boot: Module exit\n");
}

module_init(bjaguar_secureboot_init);
module_exit(bjaguar_secureboot_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("B-Jaguar Secure Boot - Kernel module signature enforcement");
MODULE_AUTHOR("MistyPigeon");
