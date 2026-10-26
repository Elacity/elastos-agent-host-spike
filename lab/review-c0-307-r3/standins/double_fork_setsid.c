/* Double-fork + setsid. Stays in the PID namespace; grandchild sleeps. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    pid_t mid = fork();
    if (mid < 0) {
        return 2;
    }
    if (mid > 0) {
        _exit(0);
    }
    if (setsid() < 0) {
        return 3;
    }
    pid_t gc = fork();
    if (gc < 0) {
        return 4;
    }
    if (gc > 0) {
        _exit(0);
    }
    printf("standin=double_fork_setsid pid=%d sid=%d\n", getpid(), getsid(0));
    fflush(stdout);
    for (;;) {
        pause();
    }
}
