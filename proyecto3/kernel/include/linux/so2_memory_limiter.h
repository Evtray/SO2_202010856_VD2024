#ifndef _LINUX_SO2_MEMORY_LIMITER_H
#define _LINUX_SO2_MEMORY_LIMITER_H

#include <linux/types.h>
#include <linux/cred.h>   /* Para validaciones de privilegios, si es necesario */
#include <linux/list.h>   /* Para manejar la lista enlazada */
#include <linux/spinlock.h>

struct memory_limitation {
    pid_t  pid;
    size_t memory_limit;
};

#define ERR_ALREADY_IN_LIST  (-101)
#define ERR_NOT_IN_LIST      (-102)
#define ERR_EXCEEDS_LIMIT    (-100)

int so2_internal_add_limit(pid_t process_pid, size_t mem_limit);
int so2_internal_get_limits(struct memory_limitation __user *u_buf,
                            size_t max_entries,
                            int __user *processes_returned);
int so2_internal_update_limit(pid_t process_pid, size_t mem_limit);
int so2_internal_remove_limit(pid_t process_pid);


static inline bool so2_user_is_sudoer(void)
{
    return (current_cred()->uid.val == 0);
}

struct so2_memlist_node {
    struct memory_limitation data;
    struct list_head         list;
};

extern struct list_head  so2_memlist_head;
extern spinlock_t        so2_memlist_lock;

#endif