// SPDX-License-Identifier: GPL
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>

static int pid = 0;
module_param(pid, int, 0644);
MODULE_PARM_DESC(pid, "PID del proceso a monitorear");

struct io_stats_user {
    u64 rchar;
    u64 wchar;
    u64 syscr;
    u64 syscw;
    u64 read_bytes;
    u64 write_bytes;
};

static int io_throttle_show(struct seq_file *m, void *v) {
    struct task_struct *task;
    struct io_stats_user stats;

    if (pid == 0) {
        seq_puts(m, "No PID especificado.\n");
        return 0;
    }

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        seq_printf(m, "No existe el proceso con PID %d.\n", pid);
        return 0;
    }

    stats.rchar = task->ioac.rchar;
    stats.wchar = task->ioac.wchar;
    stats.syscr = task->ioac.syscr;
    stats.syscw = task->ioac.syscw;
    stats.read_bytes = task->ioac.read_bytes;
    stats.write_bytes = task->ioac.write_bytes;
    rcu_read_unlock();

    seq_printf(m, "I/O Stats for PID %d:\n", pid);
    seq_printf(m, "rchar: %llu\n", stats.rchar);
    seq_printf(m, "wchar: %llu\n", stats.wchar);
    seq_printf(m, "syscr: %llu\n", stats.syscr);
    seq_printf(m, "syscw: %llu\n", stats.syscw);
    seq_printf(m, "read_bytes: %llu\n", stats.read_bytes);
    seq_printf(m, "write_bytes: %llu\n", stats.write_bytes);

    return 0;
}

static int io_throttle_open(struct inode *inode, struct file *file) {
    return single_open(file, io_throttle_show, NULL);
}

static const struct proc_ops io_throttle_ops = {
    .proc_open    = io_throttle_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int __init io_throttle_init(void) {
    proc_create("io_throttle", 0, NULL, &io_throttle_ops);
    pr_info("io_throttle_mod: Cargado, leer /proc/io_throttle (usar insmod con pid=)\n");
    return 0;
}

static void __exit io_throttle_exit(void) {
    remove_proc_entry("io_throttle", NULL);
    pr_info("io_throttle_mod: Descargado.\n");
}

module_init(io_throttle_init);
module_exit(io_throttle_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Edwin Sandoval");
MODULE_DESCRIPTION("Módulo para mostrar I/O stats de un PID en /proc/io_throttle");