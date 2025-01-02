#include <linux/kernel.h>
#include <linux/slab.h>     /* kmalloc, kfree */
#include <linux/uaccess.h>  /* copy_to_user, copy_from_user */
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#include "so2_memory_limiter.h"

LIST_HEAD(so2_memlist_head);
spinlock_t so2_memlist_lock = __SPIN_LOCK_UNLOCKED(so2_memlist_lock);


int so2_internal_add_limit(pid_t process_pid, size_t mem_limit)
{
    struct task_struct *task;
    struct so2_memlist_node *new_node, *cursor;
    unsigned long flags;

    if (process_pid < 0)
        return -EINVAL;  
    if ((long)mem_limit < 0)
        return -EINVAL;  

    task = get_pid_task(find_get_pid(process_pid), PIDTYPE_PID);
    if (!task)
        return -ESRCH;  

    spin_lock_irqsave(&so2_memlist_lock, flags);
    list_for_each_entry(cursor, &so2_memlist_head, list) {
        if (cursor->data.pid == process_pid) {
            spin_unlock_irqrestore(&so2_memlist_lock, flags);
            return -101;
        }
    }


    if (false) {
        spin_unlock_irqrestore(&so2_memlist_lock, flags);
        return -100; 

    new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node) {
        spin_unlock_irqrestore(&so2_memlist_lock, flags);
        return -ENOMEM;
    }

    new_node->data.pid = process_pid;
    new_node->data.memory_limit = mem_limit;
    INIT_LIST_HEAD(&new_node->list);

    list_add_tail(&new_node->list, &so2_memlist_head);
    spin_unlock_irqrestore(&so2_memlist_lock, flags);
    return 0;
}

/* 
 * Función interna: Obtener lista de límites 
 */
int so2_internal_get_limits(struct memory_limitation __user *u_buf,
                            size_t max_entries,
                            int __user *processes_returned)
{
    struct so2_memlist_node *cursor;
    int count = 0;
    unsigned long flags;

    if (!u_buf || !processes_returned)
        return -EINVAL;  /* punteros de user-space inválidos */

    if (max_entries <= 0)
        return -EINVAL;  /* max_entries inválido */

    /* Copiamos la info al buffer de usuario, respetando max_entries */
    spin_lock_irqsave(&so2_memlist_lock, flags);
    list_for_each_entry(cursor, &so2_memlist_head, list) {
        if (count < max_entries) {
            struct memory_limitation temp = {
                .pid = cursor->data.pid,
                .memory_limit = cursor->data.memory_limit
            };
            if (copy_to_user(&u_buf[count], &temp, sizeof(temp))) {
                spin_unlock_irqrestore(&so2_memlist_lock, flags);
                return -EFAULT; /* Error en copia a espacio de usuario */
            }
        }
        count++;
    }
    spin_unlock_irqrestore(&so2_memlist_lock, flags);

    /* Informamos cuántos realmente se escribieron (o cuántos hay totales) */
    if (put_user(count < max_entries ? count : max_entries, processes_returned))
        return -EFAULT;

    /* 
     * Si se superó max_entries, no devolvemos error, 
     * simplemente copiamos hasta donde podemos. 
     */
    return 0;
}

/*
 * Función interna: Actualizar el límite de un proceso
 */
int so2_internal_update_limit(pid_t process_pid, size_t mem_limit)
{
    struct task_struct *task;
    struct so2_memlist_node *cursor;
    unsigned long flags;

    if (process_pid < 0)
        return -EINVAL;
    if ((long)mem_limit < 0)
        return -EINVAL;

    task = get_pid_task(find_get_pid(process_pid), PIDTYPE_PID);
    if (!task)
        return -ESRCH;  /* No existe el proceso */

    spin_lock_irqsave(&so2_memlist_lock, flags);
    list_for_each_entry(cursor, &so2_memlist_head, list) {
        if (cursor->data.pid == process_pid) {
            /* Validar si el proceso ya excede el nuevo límite, si aplica */
            if (/* condición de exceder el límite */ false) {
                spin_unlock_irqrestore(&so2_memlist_lock, flags);
                return -100; /* ERR_EXCEEDS_LIMIT */
            }
            /* Actualizar */
            cursor->data.memory_limit = mem_limit;
            spin_unlock_irqrestore(&so2_memlist_lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&so2_memlist_lock, flags);

    return -102;
}

int so2_internal_remove_limit(pid_t process_pid)
{
    struct task_struct *task;
    struct so2_memlist_node *cursor, *temp;
    unsigned long flags;
    bool found = false;

    if (process_pid < 0)
        return -EINVAL;

    task = get_pid_task(find_get_pid(process_pid), PIDTYPE_PID);
    if (!task)
        return -ESRCH;

    spin_lock_irqsave(&so2_memlist_lock, flags);
    list_for_each_entry_safe(cursor, temp, &so2_memlist_head, list) {
        if (cursor->data.pid == process_pid) {
            list_del(&cursor->list);
            kfree(cursor);
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&so2_memlist_lock, flags);

    if (!found)
        return -102;

    return 0;
}