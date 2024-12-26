#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/rcupdate.h>

/* Incluir la cabecera con las estructuras */
#include <linux/tamalloc_syscalls.h>

/*
 * Syscall número 552:
 * long tamalloc_get_global_stats(struct tamalloc_global_info __user *info);
 *
 * Recorre todos los procesos y calcula la suma de:
 *  - Memoria virtual total (VmSize) => aggregate_vm_mb
 *  - Memoria residente total (VmRSS) => aggregate_rss_mb
 * en MB, guardando el resultado en la estructura tamalloc_global_info
 */
SYSCALL_DEFINE1(tamalloc_get_global_stats,
		struct tamalloc_global_info __user *, info)
{
	struct task_struct *task;
	struct tamalloc_global_info kinfo = {0};
	struct mm_struct *mm;

	rcu_read_lock();
	for_each_process(task) {
		if (task->exit_state == EXIT_ZOMBIE)
			continue;

		mm = get_task_mm(task);
		if (!mm)
			continue;

		/* Suma de VmSize (en MB) */
		kinfo.aggregate_vm_mb +=
			(mm->total_vm * PAGE_SIZE) >> 20; // ( /1024 /1024 )

		/* Suma de VmRSS (en MB) */
		kinfo.aggregate_rss_mb +=
			(get_mm_rss(mm) * PAGE_SIZE) >> 20;

		mmput(mm);
	}
	rcu_read_unlock();

	if (copy_to_user(info, &kinfo, sizeof(kinfo)))
		return -EFAULT;

	return 0;
}