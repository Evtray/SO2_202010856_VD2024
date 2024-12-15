#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h> // Para syscall()

int main() {
    pid_t pid = syscall(SYS_fork); // Llamar directamente a la syscall fork
    if (pid == 0) {
        // Proceso hijo
        _exit(0);
    } else if (pid > 0) {
        wait(NULL);
    } else {
        perror("fork");
    }
    return 0;
}
