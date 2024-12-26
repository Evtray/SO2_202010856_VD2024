#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

/* Estructura "duplicada" para user-space */
struct tamalloc_global_info {
    unsigned long aggregate_vm_mb;
    unsigned long aggregate_rss_mb;
};

#ifndef __NR_tamalloc_get_global_stats
#define __NR_tamalloc_get_global_stats 552
#endif

static inline long tamalloc_get_global_stats(struct tamalloc_global_info *info)
{
    return syscall(__NR_tamalloc_get_global_stats, info);
}

int main(void)
{
    struct tamalloc_global_info info;

    long ret = tamalloc_get_global_stats(&info);
    if (ret < 0) {
        perror("tamalloc_get_global_stats syscall");
        return 1;
    }

    printf("=== Estadísticas Globales de Memoria ===\n");
    printf("Memoria Virtual Agregada (MB):  %lu\n", info.aggregate_vm_mb);
    printf("Memoria Residente Agregada (MB):%lu\n", info.aggregate_rss_mb);

    return 0;
}