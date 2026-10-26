/* Lab-only stand-in: forks a child that exits and is not reaped, then waits.
   Used to see whether PID-1 init reaps grandchildren. */
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
    if (child == 0) {
        _exit(0);
    }
    printf("zombie-child-nspid=%d\n", (int)child);
    printf("ready\n");
    fflush(stdout);
    for (;;) {
        pause();
    }
}
