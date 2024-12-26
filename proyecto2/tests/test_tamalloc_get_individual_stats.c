#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>

/*
 * Estructura usada en el User Space. Debe coincidir con lo definido
 * en el kernel (e.g., include/linux/tamalloc_syscalls.h).
 */
struct tamalloc_proc_info {
    unsigned long vm_kb;             // Memoria virtual (VmSize) en KB
    unsigned long rss_kb;            // Memoria residente (VmRSS) en KB
    unsigned int  rss_percent_of_vm; // (rss_kb / vm_kb) * 100
    int           oom_adjustment;    // Ajuste OOM (oom_score_adj)
};

#ifndef __NR_tamalloc_get_indiviual_stats
#define __NR_tamalloc_get_indiviual_stats 553
#endif

/**
 * Invoca la syscall (553) para consultar estadísticas de un PID.
 */
static inline long tamalloc_get_indiviual_stats(pid_t pid,
                                               struct tamalloc_proc_info *info)
{
    return syscall(__NR_tamalloc_get_indiviual_stats, pid, info);
}

/**
 * Imprime la información del proceso en una tabla alineada.
 */
static void print_proc_info(pid_t pid, const struct tamalloc_proc_info *pinfo)
{
    /* Ajustamos anchos para que la tabla sea consistente. */
    printf("+------------------------------------------------------------------+\n");
    printf("| tamalloc_get_indiviual_stats (PID=%-6d)                         |\n", pid);
    printf("+--------------------------------+----------------------------------+\n");
    printf("| %-30s | %32lu |\n", "Memoria Virtual (KB)", pinfo->vm_kb);
    printf("| %-30s | %32lu |\n", "Memoria Residente (KB)", pinfo->rss_kb);
    printf("| %-30s | %31u%% |\n", "Porcentaje de Uso", pinfo->rss_percent_of_vm);
    printf("| %-30s | %32d |\n", "OOM Score (ajuste)", pinfo->oom_adjustment);
    printf("+--------------------------------+----------------------------------+\n\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <PID>\n", argv[0]);
        fprintf(stderr, "     PID = 0 => consultar TODOS los procesos.\n");
        return 1;
    }

    pid_t pid = (pid_t)atoi(argv[1]);

    /*
     * Caso 1: PID != 0
     *         => Consultamos información de un solo proceso.
     */
    if (pid != 0) {
        struct tamalloc_proc_info pinfo;
        long ret = tamalloc_get_indiviual_stats(pid, &pinfo);
        if (ret < 0) {
            perror("tamalloc_get_indiviual_stats syscall");
            return 1;
        }
        print_proc_info(pid, &pinfo);
    }
    /*
     * Caso 2: PID = 0
     *         => Recorremos /proc para obtener TODOS los procesos
     *            y llamamos a la syscall individual por cada PID.
     */
    else {
        DIR *dp;
        struct dirent *entry;

        dp = opendir("/proc");
        if (!dp) {
            perror("No se pudo abrir /proc");
            return 1;
        }

        while ((entry = readdir(dp)) != NULL) {
            /* Filtrar sólo directorios cuyo nombre sea numérico (PID) */
            if (entry->d_type == DT_DIR) {
                const char *dname = entry->d_name;
                int is_numeric = 1;
                for (int i = 0; dname[i] != '\0'; i++) {
                    if (!isdigit((unsigned char)dname[i])) {
                        is_numeric = 0;
                        break;
                    }
                }
                if (is_numeric) {
                    pid_t current_pid = (pid_t)atoi(dname);
                    if (current_pid > 0) {
                        struct tamalloc_proc_info pinfo;
                        long ret = tamalloc_get_indiviual_stats(current_pid, &pinfo);
                        if (ret == 0) {
                            /* Si la syscall tuvo éxito, imprimimos la tabla */
                            print_proc_info(current_pid, &pinfo);
                        }
                        /* Si ret < 0, seguramente es un hilo kernel o proceso
                           que terminó. Lo ignoramos en silencio. */
                    }
                }
            }
        }
        closedir(dp);
    }

    return 0;
}