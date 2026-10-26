/* Lab-only stand-in: the launched process exits after forking a child
   that stays. If PID-1 init only waitpids that one child, init exits and
   the kernel kills the leftover grandchild. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

int main(void) {
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 2;
    }
    if (child > 0) {
        printf("parent-exit-nspid=%d\n", (int)getpid());
        fflush(stdout);
        _exit(0);
    }
    printf("grandchild-nspid=%d\n", (int)getpid());
    printf("ready\n");
    fflush(stdout);
    for (;;) {
        pause();
    }
}
