/* Lab-only demo of #307's fault-pipe protocol after detach.
   Parent reads a close-on-exec pipe. Child forks a helper, the helper
   closes its write end and exits without writing a fault. That is the
   same close-then-die window as close_fault_write + a dead init.
   An empty read is reported as a start. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

int main(void) {
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) {
        perror("pipe2");
        return 2;
    }
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 2;
    }
    if (child == 0) {
        close(fds[0]);
        pid_t init = fork();
        if (init < 0) {
            _exit(2);
        }
        if (init > 0) {
            /* helper: close the write end, then die. No fault record. */
            close(fds[1]);
            _exit(0);
        }
        /* init dies at once, also without writing. */
        close(fds[1]);
        _exit(0);
    }
    close(fds[1]);
    char buf[12];
    ssize_t got = read(fds[0], buf, sizeof buf);
    close(fds[0]);
    int status = 0;
    waitpid(child, &status, 0);
    if (got == 0) {
        printf("empty_pipe_reported_as_start pid=%d\n", (int)child);
        return 0;
    }
    printf("got=%zd errno=%d\n", (ssize_t)got, errno);
    return 1;
}
