// SPDX-License-Identifier: GPL
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

// Declarar extern las estructuras globales (ajusta según tu código real)
extern struct my_tracked_syscall_info {
    const char *name;
    unsigned long count;
    u64 last_timestamp_ns;
} monitored_syscalls[];

extern int monitored_count;
extern struct my_tracked_syscall_info monitored_syscalls[];


// Función show
static int track_syscalls_show(struct seq_file *m, void *v) {
    int i;
    seq_puts(m, "--- Syscalls Usage ---\n");
    for (i = 0; i < monitored_count; i++) {
        seq_printf(m, "Syscall: %s, Count: %lu, Last Timestamp ns: %llu\n",
                   monitored_syscalls[i].name, 
                   monitored_syscalls[i].count,
                   monitored_syscalls[i].last_timestamp_ns);
    }
    return 0;
}

static int track_syscalls_open(struct inode *inode, struct file *file) {
    return single_open(file, track_syscalls_show, NULL);
}

static const struct proc_ops track_syscalls_ops = {
    .proc_open    = track_syscalls_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int __init track_syscalls_init(void) {
    proc_create("track_syscalls", 0, NULL, &track_syscalls_ops);
    pr_info("track_syscalls_mod: Cargado, leer /proc/track_syscalls\n");
    return 0;
}

static void __exit track_syscalls_exit(void) {
    remove_proc_entry("track_syscalls", NULL);
    pr_info("track_syscalls_mod: Descargado.\n");
}

module_init(track_syscalls_init);
module_exit(track_syscalls_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Edwin Sandoval");
MODULE_DESCRIPTION("Módulo para mostrar uso de syscalls en /proc/track_syscalls");