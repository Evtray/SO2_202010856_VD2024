#ifndef _LINUX_TAMALLOC_SYSCALLS_H
#define _LINUX_TAMALLOC_SYSCALLS_H

struct tamalloc_global_info {
	unsigned long aggregate_vm_mb;
	unsigned long aggregate_rss_mb;
};

struct tamalloc_proc_info {
	unsigned long vm_kb;
	unsigned long rss_kb;
	unsigned int rss_percent_of_vm;
	int oom_adjustment;
};

#endif /* _LINUX_TAMALLOC_SYSCALLS_H */