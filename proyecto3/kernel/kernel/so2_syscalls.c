#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include "so2_memory_limiter.h"

SYSCALL_DEFINE2(so2_add_memory_limit, pid_t, process_pid, size_t, memory_limit)
{
    int ret;
    ret = so2_internal_add_limit(process_pid, memory_limit);

    if (ret < 0) {
        switch (ret) {
        case -ESRCH:
            return syscall_set_return_value(current, -ESRCH, ESRCH);
        case -EINVAL:
            return syscall_set_return_value(current, -EINVAL, EINVAL);
        case -ENOMEM:
            return syscall_set_return_value(current, -ENOMEM, ENOMEM);
        case -100:
            return syscall_set_return_value(current, -100, 100);
        case -101:
            return syscall_set_return_value(current, -101, 101);
        default:
            return ret; 
        }
    }

    return 0; /* Éxito */
}

/*
 * SYSCALL 2: Obtener la lista de procesos limitados
 * Ejemplo de ID = 558
 */
SYSCALL_DEFINE3(so2_get_memory_limits,
                struct memory_limitation __user *, u_processes_buffer,
                size_t, max_entries,
                int __user *, processes_returned)
{
    int ret;
    ret = so2_internal_get_limits(u_processes_buffer, max_entries, processes_returned);

    if (ret < 0) {
        switch (ret) {
        case -EINVAL:
            return syscall_set_return_value(current, -EINVAL, EINVAL);
        case -EFAULT:
            return syscall_set_return_value(current, -EFAULT, EFAULT);
        default:
            return ret;
        }
    }

    return 0;
}

SYSCALL_DEFINE2(so2_update_memory_limit, pid_t, process_pid, size_t, memory_limit)
{
    int ret;

    if (!so2_user_is_sudoer())
        return syscall_set_return_value(current, -EPERM, EPERM);

    ret = so2_internal_update_limit(process_pid, memory_limit);
    if (ret < 0) {
        switch (ret) {
        case -ESRCH:
            return syscall_set_return_value(current, -ESRCH, ESRCH);
        case -EINVAL:
            return syscall_set_return_value(current, -EINVAL, EINVAL);
        case -100:
            return syscall_set_return_value(current, -100, 100);
        case -102:
            return syscall_set_return_value(current, -102, 102);
        default:
            return ret;
        }
    }
    return 0;
}

SYSCALL_DEFINE1(so2_remove_memory_limit, pid_t, process_pid)
{
    int ret;

    if (!so2_user_is_sudoer())
        return syscall_set_return_value(current, -EPERM, EPERM);

    ret = so2_internal_remove_limit(process_pid);
    if (ret < 0) {
        switch (ret) {
        case -ESRCH:
            return syscall_set_return_value(current, -ESRCH, ESRCH);
        case -EINVAL:
            return syscall_set_return_value(current, -EINVAL, EINVAL);
        case -102:
            return syscall_set_return_value(current, -102, 102);
        default:
            return ret;
        }
    }
    return 0;
}
