// SPDX-License-Identifier: GPL
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/vmstat.h>   // Para global_node_page_state()
#include <linux/uaccess.h>
#include <linux/string.h>

// Función para llenar la información de memoria
static void fill_mem_snapshot(struct seq_file *m) {
    struct sysinfo i;
    si_meminfo(&i);

    // Información básica
    unsigned long total_pages = i.totalram;
    unsigned long free_pages = i.freeram;
    unsigned long cached_pages = global_node_page_state(NR_FILE_PAGES)
                                 - global_node_page_state(NR_SHMEM)
                                 - i.bufferram;
    unsigned long buffered_pages = i.bufferram;
    unsigned long active_pages = global_node_page_state(NR_ACTIVE_FILE)
                                 + global_node_page_state(NR_ACTIVE_ANON);
    unsigned long inactive_pages = global_node_page_state(NR_INACTIVE_FILE)
                                   + global_node_page_state(NR_INACTIVE_ANON);

    seq_printf(m, "Total Pages: %lu\n", total_pages);
    seq_printf(m, "Free Pages: %lu\n", free_pages);
    seq_printf(m, "Cached Pages: %lu\n", cached_pages);
    seq_printf(m, "Buffered Pages: %lu\n", buffered_pages);
    seq_printf(m, "Active Pages: %lu\n", active_pages);
    seq_printf(m, "Inactive Pages: %lu\n", inactive_pages);
}

// Función show que se llama cuando hacemos "cat /proc/capture_mem"
static int capture_mem_show(struct seq_file *m, void *v) {
    seq_puts(m, "--- Memory Snapshot ---\n");
    fill_mem_snapshot(m);
    return 0;
}

// Función open para seq_file
static int capture_mem_open(struct inode *inode, struct file *file) {
    return single_open(file, capture_mem_show, NULL);
}

// Uso de struct proc_ops en lugar de file_operations
static const struct proc_ops capture_mem_ops = {
    .proc_open    = capture_mem_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int __init capture_mem_init(void) {
    proc_create("capture_mem", 0, NULL, &capture_mem_ops);
    pr_info("capture_mem_mod: Módulo cargado, lee /proc/capture_mem\n");
    return 0;
}

static void __exit capture_mem_exit(void) {
    remove_proc_entry("capture_mem", NULL);
    pr_info("capture_mem_mod: Módulo descargado.\n");
}

module_init(capture_mem_init);
module_exit(capture_mem_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Edwin Sandoval");
MODULE_DESCRIPTION("Módulo para mostrar snapshot de memoria en /proc/capture_mem");