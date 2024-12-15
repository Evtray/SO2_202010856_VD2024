// SPDX-License-Identifier: GPL
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/statfs.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/namei.h>

// Parámetro para indicar qué partición consultar. Por defecto "/"
static char *partition = "/";
module_param(partition, charp, 0644);
MODULE_PARM_DESC(partition, "Partition to report disk usage for");

// Funciones para obtener info de CPU, Mem y Disco:

static void get_memory_info(struct seq_file *m) {
    struct sysinfo i;
    si_meminfo(&i);
    unsigned long mem_total = i.totalram * i.mem_unit;
    unsigned long mem_free = i.freeram * i.mem_unit;

    seq_printf(m, "Memory Total: %lu kB\n", mem_total / 1024);
    seq_printf(m, "Memory Free: %lu kB\n", mem_free / 1024);
}

static int get_disk_info(struct seq_file *m) {
    struct path path;
    struct kstatfs stat;
    int err;

    err = kern_path(partition, LOOKUP_FOLLOW, &path);
    if (err)
        return err;

    err = vfs_statfs(&path, &stat);
    path_put(&path);
    if (err)
        return err;

    seq_printf(m, "Disk Total: %llu kB\n",
               (unsigned long long)(stat.f_blocks * stat.f_bsize) / 1024);
    seq_printf(m, "Disk Free: %llu kB\n",
               (unsigned long long)(stat.f_bfree * stat.f_bsize) / 1024);
    return 0;
}

// Obtener info de CPU (ejemplo simplificado):
// Leeremos estadísticas acumuladas desde /proc/stat. Esto es tricky en espacio de kernel.
// Una forma educativa: no calcularemos un porcentaje real, sólo mostraremos sumas de tiempos.
#include <linux/kernel_stat.h>

static void get_cpu_info(struct seq_file *m) {
    // Este ejemplo es simplificado. kcpustat_cpu retorna estadisticas de cputime.
    // Para un cálculo de % real, necesitarías medir deltas entre lecturas.
    unsigned int cpu;
    u64 user=0, nice=0, system=0, idle=0, iowait=0, irq=0, softirq=0, steal=0;

    for_each_possible_cpu(cpu) {
        const struct kernel_cpustat *kcs = &kcpustat_cpu(cpu);
        user    += kcs->cpustat[CPUTIME_USER];
        nice    += kcs->cpustat[CPUTIME_NICE];
        system  += kcs->cpustat[CPUTIME_SYSTEM];
        idle    += kcs->cpustat[CPUTIME_IDLE];
        iowait  += kcs->cpustat[CPUTIME_IOWAIT];
        irq     += kcs->cpustat[CPUTIME_IRQ];
        softirq += kcs->cpustat[CPUTIME_SOFTIRQ];
        steal   += kcs->cpustat[CPUTIME_STEAL];
    }

    seq_printf(m, "CPU User: %llu\n", (unsigned long long)user);
    seq_printf(m, "CPU Nice: %llu\n", (unsigned long long)nice);
    seq_printf(m, "CPU System: %llu\n", (unsigned long long)system);
    seq_printf(m, "CPU Idle: %llu\n", (unsigned long long)idle);
    seq_printf(m, "CPU IOWait: %llu\n", (unsigned long long)iowait);
    seq_printf(m, "CPU IRQ: %llu\n", (unsigned long long)irq);
    seq_printf(m, "CPU SoftIRQ: %llu\n", (unsigned long long)softirq);
    seq_printf(m, "CPU Steal: %llu\n", (unsigned long long)steal);
}

static int system_stats_show(struct seq_file *m, void *v) {
    seq_puts(m, "--- System Statistics ---\n");
    get_cpu_info(m);
    seq_puts(m, "\n");
    get_memory_info(m);
    seq_puts(m, "\n");
    if (get_disk_info(m))
        seq_puts(m, "Error reading disk info.\n");
    return 0;
}

static int system_stats_open(struct inode *inode, struct file *file) {
    return single_open(file, system_stats_show, NULL);
}

static const struct proc_ops system_stats_ops = {
    .proc_open    = system_stats_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};


static int __init system_stats_init(void) {
    proc_create("system_stats", 0, NULL, &system_stats_ops);
    pr_info("system_stats module loaded. Read /proc/system_stats\n");
    return 0;
}

static void __exit system_stats_exit(void) {
    remove_proc_entry("system_stats", NULL);
    pr_info("system_stats module unloaded.\n");
}

module_init(system_stats_init);
module_exit(system_stats_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Edwin Sandoval");
MODULE_DESCRIPTION("Módulo que muestra estadísticas de CPU, memoria y disco en /proc/system_stats");