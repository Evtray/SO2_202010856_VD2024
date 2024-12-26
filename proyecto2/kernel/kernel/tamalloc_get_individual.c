#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>

/* Incluir la cabecera con las estructuras */
#include <linux/tamalloc_syscalls.h>

/*
 * Syscall número 553:
 * long tamalloc_get_individual_stats(pid_t pid, struct tamalloc_proc_info __user *info);
 *
 * Obtiene la memoria virtual reservada y la residente para el PID indicado,
 * calculando además el porcentaje de uso y capturando oom_score_adj.
 */
SYSCALL_DEFINE2(tamalloc_get_individual_stats,
		pid_t, pid,
		struct tamalloc_proc_info __user *, info)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct tamalloc_proc_info kinfo;

	rcu_read_lock();
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}

	mm = get_task_mm(task);
	if (!mm) {
		rcu_read_unlock();
		return -EINVAL;
	}

	/* Convertimos a KB => (valor * PAGE_SIZE) >> 10 */
	kinfo.vm_kb  = (mm->total_vm     * PAGE_SIZE) >> 10;
	kinfo.rss_kb = (get_mm_rss(mm)   * PAGE_SIZE) >> 10;

	if (kinfo.vm_kb > 0)
		kinfo.rss_percent_of_vm = (kinfo.rss_kb * 100) / kinfo.vm_kb;
	else
		kinfo.rss_percent_of_vm = 0;

	/* Tomamos oom_score_adj como "oom_adjustment" */
	kinfo.oom_adjustment = task->signal->oom_score_adj;

	mmput(mm);
	rcu_read_unlock();

	/* Copiamos la estructura al espacio de usuario */
	if (copy_to_user(info, &kinfo, sizeof(kinfo)))
		return -EFAULT;

	return 0;
}