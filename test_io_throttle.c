#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

struct io_stats_user {
    unsigned long long rchar;
    unsigned long long wchar;
    unsigned long long syscr;
    unsigned long long syscw;
    unsigned long long read_bytes;
    unsigned long long write_bytes;
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <pid>\n", argv[0]);
        return 1;
    }
    int pid = atoi(argv[1]);

    struct io_stats_user stats;
    int ret = syscall(464, pid, &stats);
    if (ret < 0) {
        perror("syscall get_io_throttle");
        return 1;
    }

    printf("I/O Stats for PID %d:\n", pid);
    printf("rchar: %llu\n", stats.rchar);
    printf("wchar: %llu\n", stats.wchar);
    printf("syscr: %llu\n", stats.syscr);
    printf("syscw: %llu\n", stats.syscw);
    printf("read_bytes: %llu\n", stats.read_bytes);
    printf("write_bytes: %llu\n", stats.write_bytes);

    return 0;
}