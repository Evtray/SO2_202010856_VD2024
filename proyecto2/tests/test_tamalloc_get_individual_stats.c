/******************************************************************************
 * manager_process_horizontal.c
 *
 * Compilación:
 *   gcc -o manager_process_horizontal manager_process_horizontal.c
 *
 * Uso:
 *   ./manager_process_horizontal [PID]
 *   - Si no se pasa un PID, se asume PID=0 (todos los procesos).
 *   - Si <PID> != 0 => se muestra la info de UN SOLO proceso.
 *
 * Descripción:
 *   Invoca la syscall 553 (tamalloc_get_indiviual_stats) y muestra la
 *   información (PID, Virtual, Resident, %Uso y OOM Score)
 *   de forma horizontal (una sola línea por proceso).
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>

struct tamalloc_proc_info {
    unsigned long vm_kb;             // Memoria virtual (VmSize) en KB
    unsigned long rss_kb;            // Memoria residente (VmRSS) en KB
    unsigned int  rss_percent_of_vm; // (rss_kb / vm_kb) * 100
    int           oom_adjustment;    // Ajuste OOM (oom_score_adj)
};

#ifndef __NR_tamalloc_get_indiviual_stats
#define __NR_tamalloc_get_indiviual_stats 553
#endif

static inline long tamalloc_get_indiviual_stats(pid_t pid, struct tamalloc_proc_info *info)
{
    return syscall(__NR_tamalloc_get_indiviual_stats, pid, info);
}

static void print_row_horizontal(pid_t pid, const struct tamalloc_proc_info *pinfo)
{
    printf("| %6d | %13lu | %13lu | %5u%% | %9d |\n",
           pid,
           pinfo->vm_kb,
           pinfo->rss_kb,
           pinfo->rss_percent_of_vm,
           pinfo->oom_adjustment);
}

static void print_header_horizontal(void)
{
    printf("+--------+---------------+---------------+-------+------------+\n");
    printf("|  PID   |  Virtual(KB)  | Resident(KB)  | %%Uso   | OOM Score |\n");
    printf("+--------+---------------+---------------+-------+------------+\n");
}

static void print_footer_horizontal(void)
{
    printf("+--------+---------------+---------------+-------+------------+\n\n");
}

int main(int argc, char *argv[])
{
    pid_t pid = 0;  // Valor por defecto: 0 => consultar TODOS los procesos

    // Si se pasó al menos un argumento, tomamos ese PID
    if (argc >= 2) {
        pid = (pid_t)atoi(argv[1]);
    }

    if (pid != 0) {
        struct tamalloc_proc_info pinfo;
        long ret = tamalloc_get_indiviual_stats(pid, &pinfo);
        if (ret < 0) {
            perror("tamalloc_get_indiviual_stats syscall");
            return 1;
        }

        // Imprimir la tabla (cabecera + row + footer)
        print_header_horizontal();
        print_row_horizontal(pid, &pinfo);
        print_footer_horizontal();
    }
    else {
        DIR *dp;
        struct dirent *entry;

        dp = opendir("/proc");
        if (!dp) {
            perror("No se pudo abrir /proc");
            return 1;
        }

        // Imprimimos la CABECERA antes de iterar
        print_header_horizontal();

        while ((entry = readdir(dp)) != NULL) {
            // Filtrar solo directorios numéricos (PID)
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
                            print_row_horizontal(current_pid, &pinfo);
                        }
                        // Si ret < 0 => kernel thread o proceso terminado => ignorar.
                    }
                }
            }
        }
        closedir(dp);

        print_footer_horizontal();
    }

    return 0;
}