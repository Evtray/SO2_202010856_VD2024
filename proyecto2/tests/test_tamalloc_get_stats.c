#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

/* Número de la syscall en la tabla */
#ifndef __NR_tamalloc_get_stats
#define __NR_tamalloc_get_stats 551
#endif

static inline long tamalloc_get_stats(size_t size)
{
    return syscall(__NR_tamalloc_get_stats, size);
}

int main(int argc, char *argv[])
{
    size_t size = 4096; // 4 KB por defecto
    if (argc > 1)
        size = (size_t)atol(argv[1]);

    long addr = tamalloc_get_stats(size);
    if (addr < 0) {
        perror("tamalloc_get_stats syscall");
        return 1;
    }

    printf("[tamalloc_get_stats] Se asignaron %zu bytes en 0x%lx\n", size, addr);

    /* Forzar page fault */
    char *ptr = (char *)addr;
    ptr[0] = 'H';
    ptr[size - 1] = 'Z';

    return 0;
}