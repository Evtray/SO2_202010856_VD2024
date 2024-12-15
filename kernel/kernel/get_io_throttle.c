#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/types.h>

struct io_stats_user {
    unsigned long long rchar;
    unsigned long long wchar;
    unsigned long long syscr;
    unsigned long long syscw;
    unsigned long long read_bytes;
    unsigned long long write_bytes;
};

SYSCALL_DEFINE2(get_io_throttle, int, pid, struct io_stats_user __user *, udata)
{
    struct task_struct *task;
    struct io_stats_user stats;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH; 
    }

    // Acceso a las estadísticas en task->ioac
    // Estos campos se encuentran en task->ioac.rchar, etc.
    stats.rchar = task->ioac.rchar;
    stats.wchar = task->ioac.wchar;
    stats.syscr = task->ioac.syscr;
    stats.syscw = task->ioac.syscw;
    stats.read_bytes = task->ioac.read_bytes;
    stats.write_bytes = task->ioac.write_bytes;

    rcu_read_unlock();

    if (copy_to_user(udata, &stats, sizeof(stats)))
        return -EFAULT;

    return 0;
}