#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/vmstat.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/string.h>

struct mem_snapshot {
    unsigned long total_pages;      // Total de páginas de memoria
    unsigned long free_pages;       // Páginas libres
    unsigned long cached_pages;     // Páginas en caché
    unsigned long buffered_pages;   // Páginas en buffers
    unsigned long swap_total;       // Total de espacio swap (en páginas)
    unsigned long swap_free;        // Swap libre (en páginas)
    unsigned long active_pages;     // Páginas activas
    unsigned long inactive_pages;   // Páginas inactivas
    // Puede añadir más campos según las necesidades, como fragmentación
};

static void fill_mem_snapshot(struct mem_snapshot *snap) {
    struct sysinfo i;
    si_meminfo(&i);
    
    snap->total_pages = i.totalram;
    snap->free_pages = i.freeram;
    snap->swap_total = i.totalswap;
    snap->swap_free = i.freeswap;

    // Páginas en caché y buffer
    snap->cached_pages = global_node_page_state(NR_FILE_PAGES)
                         - global_node_page_state(NR_SHMEM)
                         - i.bufferram;
    snap->buffered_pages = i.bufferram;

    // Páginas activas e inactivas (archivos, anónimas)
    snap->active_pages = global_node_page_state(NR_ACTIVE_FILE)
                         + global_node_page_state(NR_ACTIVE_ANON);
    snap->inactive_pages = global_node_page_state(NR_INACTIVE_FILE)
                           + global_node_page_state(NR_INACTIVE_ANON);
}

SYSCALL_DEFINE1(capture_memory_snapshot, struct mem_snapshot __user *, user_snap)
{
    struct mem_snapshot snap;
    fill_mem_snapshot(&snap);

    if (copy_to_user(user_snap, &snap, sizeof(snap)))
        return -EFAULT;

    return 0;
}
