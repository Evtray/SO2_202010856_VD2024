#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

/* Estructura "duplicada" para user-space */
struct tamalloc_proc_info {
    unsigned long vm_kb;
    unsigned long rss_kb;
    unsigned int  rss_percent_of_vm;
    int           oom_adjustment;
};

#ifndef __NR_tamalloc_get_indiviual_stats
#define __NR_tamalloc_get_indiviual_stats 553
#endif

static inline long tamalloc_get_indiviual_stats(pid_t pid,
                                               struct tamalloc_proc_info *info)
{
    return syscall(__NR_tamalloc_get_indiviual_stats, pid, info);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <PID>\n", argv[0]);
        return 1;
    }

    pid_t pid = (pid_t)atoi(argv[1]);
    struct tamalloc_proc_info pinfo;

    long ret = tamalloc_get_indiviual_stats(pid, &pinfo);
    if (ret < 0) {
        perror("tamalloc_get_indiviual_stats syscall");
        return 1;
    }

    printf("=== Estadísticas de Proceso (PID = %d) ===\n", pid);
    printf("Memoria Virtual (KB):    %lu\n", pinfo.vm_kb);
    printf("Memoria Residente (KB):  %lu\n", pinfo.rss_kb);
    printf("Porcentaje de Uso:       %u%%\n", pinfo.rss_percent_of_vm);
    printf("OOM Score (ajuste):      %d\n", pinfo.oom_adjustment);

    return 0;
}