#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <time.h>

struct syscall_usage_user {
    char name[16];
    unsigned long count;
    unsigned long long last_timestamp_ns;
};

int main(void) {
    struct syscall_usage_user info[4]; // Para open, read, write, fork
    
    // Ajusta el número 463 a la syscall que hayas asignado en tu syscall_64.tbl
    int ret = syscall(463, info, 4);
    if (ret < 0) {
        perror("syscall");
        return 1;
    }

    for (int i = 0; i < ret; i++) {
        // Convertir nanosegundos a segundos y nanosegundos restantes
        time_t secs = (time_t)(info[i].last_timestamp_ns / 1000000000ULL);
        long ns = (long)(info[i].last_timestamp_ns % 1000000000ULL);

        struct tm *tm_info = localtime(&secs);
        char buffer[64];
        if (tm_info) {
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
        } else {
            strncpy(buffer, "unknown time", sizeof(buffer));
        }

        printf("Syscall: %s, count: %lu, last_timestamp: %s.%09ld\n", 
               info[i].name, info[i].count, buffer, ns);
    }

    return 0;
}