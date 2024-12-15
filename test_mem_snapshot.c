#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

struct mem_snapshot {
    unsigned long total_pages;
    unsigned long free_pages;
    unsigned long cached_pages;
    unsigned long buffered_pages;
    unsigned long swap_total;
    unsigned long swap_free;
    unsigned long active_pages;
    unsigned long inactive_pages;
};

int main(void) {
    struct mem_snapshot snap;
    int ret = syscall(462, &snap); // Asumiendo syscall 462 para capture_memory_snapshot
    if (ret < 0) {
        perror("syscall capture_memory_snapshot");
        return 1;
    }

    // Convertir páginas a unidades más comprensibles si se desea
    printf("Total RAM Pages: %lu\n", snap.total_pages);
    printf("Free RAM Pages: %lu\n", snap.free_pages);
    printf("Cached Pages: %lu\n", snap.cached_pages);
    printf("Buffered Pages: %lu\n", snap.buffered_pages);
    printf("Swap Total (pages): %lu\n", snap.swap_total);
    printf("Swap Free (pages): %lu\n", snap.swap_free);
    printf("Active Pages: %lu\n", snap.active_pages);
    printf("Inactive Pages: %lu\n", snap.inactive_pages);

    return 0;
}