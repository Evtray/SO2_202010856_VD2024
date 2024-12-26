#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

/*
 * Estructura "duplicada" para user-space.
 * Debe coincidir con la definida en el kernel (tamalloc_syscalls.h)
 */
struct tamalloc_global_info {
    unsigned long aggregate_vm_mb;   // Suma de memoria virtual en MB
    unsigned long aggregate_rss_mb;  // Suma de memoria residente en MB
};

#ifndef __NR_tamalloc_get_global_stats
#define __NR_tamalloc_get_global_stats 552
#endif

/*
 * Envuelve la syscall 552 llamando con la estructura de user-space.
 */
static inline long tamalloc_get_global_stats(struct tamalloc_global_info *info)
{
    return syscall(__NR_tamalloc_get_global_stats, info);
}

/*
 * Imprime los datos en una tabla con formato ASCII más presentable.
 */
static void print_global_info(const struct tamalloc_global_info *info)
{
    printf("+---------------------------------------------------------------+\n");
    printf("| tamalloc_get_global_stats (Estadísticas Globales)             |\n");
    printf("+--------------------------------+------------------------------+\n");
    printf("| %-30s | %24lu MB |\n", "Memoria Virtual Agregada", info->aggregate_vm_mb);
    printf("| %-30s | %24lu MB |\n", "Memoria Residente Agregada", info->aggregate_rss_mb);
    printf("+--------------------------------+----------------------------+\n\n");
}

int main(void)
{
    struct tamalloc_global_info info;

    long ret = tamalloc_get_global_stats(&info);
    if (ret < 0) {
        perror("tamalloc_get_global_stats syscall");
        return 1;
    }

    /* Imprimir en formato de tabla */
    print_global_info(&info);

    return 0;
}