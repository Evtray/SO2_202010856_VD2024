// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/timekeeping.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/string.h>

extern void* sys_call_table[]; 

// variables en  __NR_*
#ifndef __NR_read
#define __NR_read   0
#endif

#ifndef __NR_write
#define __NR_write  1
#endif

#ifndef __NR_open
#define __NR_open   2
#endif

#ifndef __NR_fork
#define __NR_fork   57
#endif

struct my_tracked_syscall_info {
    const char *name;
    unsigned long count;
    u64 last_timestamp_ns;
    asmlinkage long (*original)(const struct pt_regs *);
};

static struct my_tracked_syscall_info monitored_syscalls[] = {
    { .name = "read",  .count = 0, .last_timestamp_ns = 0, .original = NULL},
    { .name = "write", .count = 0, .last_timestamp_ns = 0, .original = NULL},
    { .name = "open",  .count = 0, .last_timestamp_ns = 0, .original = NULL},
    { .name = "fork",  .count = 0, .last_timestamp_ns = 0, .original = NULL},
};
static int monitored_count = 4;

static DEFINE_SPINLOCK(syscall_usage_lock);

static asmlinkage long hooked_read(const struct pt_regs *regs) {
    long ret;
    u64 now = ktime_get_ns();
    unsigned long flags;

    spin_lock_irqsave(&syscall_usage_lock, flags);
    monitored_syscalls[0].count++;
    monitored_syscalls[0].last_timestamp_ns = now;
    spin_unlock_irqrestore(&syscall_usage_lock, flags);

    ret = monitored_syscalls[0].original(regs);
    return ret;
}

static asmlinkage long hooked_write(const struct pt_regs *regs) {
    long ret;
    u64 now = ktime_get_ns();
    unsigned long flags;

    spin_lock_irqsave(&syscall_usage_lock, flags);
    monitored_syscalls[1].count++;
    monitored_syscalls[1].last_timestamp_ns = now;
    spin_unlock_irqrestore(&syscall_usage_lock, flags);

    ret = monitored_syscalls[1].original(regs);
    return ret;
}

static asmlinkage long hooked_open(const struct pt_regs *regs) {
    long ret;
    u64 now = ktime_get_ns();
    unsigned long flags;

    spin_lock_irqsave(&syscall_usage_lock, flags);
    monitored_syscalls[2].count++;
    monitored_syscalls[2].last_timestamp_ns = now;
    spin_unlock_irqrestore(&syscall_usage_lock, flags);

    ret = monitored_syscalls[2].original(regs);
    return ret;
}

static asmlinkage long hooked_fork(const struct pt_regs *regs) {
    long ret;
    u64 now = ktime_get_ns();
    unsigned long flags;

    spin_lock_irqsave(&syscall_usage_lock, flags);
    monitored_syscalls[3].count++;
    monitored_syscalls[3].last_timestamp_ns = now;
    spin_unlock_irqrestore(&syscall_usage_lock, flags);

    ret = monitored_syscalls[3].original(regs);
    return ret;
}

static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;
    asm volatile("mov %0,%%cr0":"+r" (val), "+m" (__force_order));
}

static unsigned long original_cr0;

static void disable_write_protection(void) {
    original_cr0 = read_cr0();
    write_cr0_forced(original_cr0 & ~0x00010000);
}

static void enable_write_protection(void) {
    write_cr0_forced(original_cr0);
}

struct syscall_usage_user {
    char name[16];
    unsigned long count;
    unsigned long long last_timestamp_ns;
};

SYSCALL_DEFINE2(track_syscall_usage, struct syscall_usage_user __user *, buf, int, size)
{
    int i;
    unsigned long flags;

    if (size < monitored_count)
        return -EINVAL;

    spin_lock_irqsave(&syscall_usage_lock, flags);
    for (i = 0; i < monitored_count; i++) {
        struct syscall_usage_user temp;
        strncpy(temp.name, monitored_syscalls[i].name, sizeof(temp.name));
        temp.name[sizeof(temp.name)-1] = '\0'; // Asegurar terminación
        temp.count = monitored_syscalls[i].count;
        temp.last_timestamp_ns = monitored_syscalls[i].last_timestamp_ns;

        if (copy_to_user(&buf[i], &temp, sizeof(temp))) {
            spin_unlock_irqrestore(&syscall_usage_lock, flags);
            return -EFAULT;
        }
    }
    spin_unlock_irqrestore(&syscall_usage_lock, flags);

    return monitored_count;
}

static int __init track_usage_init(void)
{
    monitored_syscalls[0].original = (void*)sys_call_table[__NR_read];
    monitored_syscalls[1].original = (void*)sys_call_table[__NR_write];
    monitored_syscalls[2].original = (void*)sys_call_table[__NR_open];
    monitored_syscalls[3].original = (void*)sys_call_table[__NR_fork];

    disable_write_protection();
    sys_call_table[__NR_read] = (void*)hooked_read;
    sys_call_table[__NR_write] = (void*)hooked_write;
    sys_call_table[__NR_open] = (void*)hooked_open;
    sys_call_table[__NR_fork] = (void*)hooked_fork;
    enable_write_protection();

    printk(KERN_INFO "track_syscall_usage: Módulo cargado. Monitoreando read/write/open/fork.\n");
    return 0;
}

static void __exit track_usage_exit(void)
{
    disable_write_protection();
    sys_call_table[__NR_read]  = (void*)monitored_syscalls[0].original;
    sys_call_table[__NR_write] = (void*)monitored_syscalls[1].original;
    sys_call_table[__NR_open]  = (void*)monitored_syscalls[2].original;
    sys_call_table[__NR_fork]  = (void*)monitored_syscalls[3].original;
    enable_write_protection();

    printk(KERN_INFO "track_syscall_usage: Módulo descargado. Restauradas syscalls originales.\n");
}

module_init(track_usage_init);
module_exit(track_usage_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tu Nombre");
MODULE_DESCRIPTION("Monitoreo de read/write/open/fork con track_syscall_usage por Edwin");