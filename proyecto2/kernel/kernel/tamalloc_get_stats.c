#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/errno.h>
#include <linux/sched.h>

 /*
  * Syscall número 551:
  * long tamalloc_get_stats(size_t size);
  *
  * Asigna 'size' bytes de memoria anónima sin reservar físicamente todas
  * las páginas inmediatamente (MAP_NORESERVE).
  * Devuelve la dirección virtual en espacio de usuario, o un código de error < 0.
  */
SYSCALL_DEFINE1(tamalloc_get_stats, size_t, size)
{
	unsigned long aligned_size, addr;

	if (size == 0)
		return -EINVAL;

	aligned_size = PAGE_ALIGN(size);
	if (!aligned_size)
		return -ENOMEM;

	/*
	 * Se utiliza vm_mmap() para mapear:
	 * MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE
	 */
	addr = vm_mmap(NULL, 0, aligned_size,
		       PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
		       0);
	if (IS_ERR_VALUE(addr)) {
		printk(KERN_ERR "tamalloc_get_stats: Error al mapear memoria.\n");
		return -ENOMEM;
	}

	return addr; 
}