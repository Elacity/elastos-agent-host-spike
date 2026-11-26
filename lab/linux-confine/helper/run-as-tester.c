/* Drop to uid/gid 1000 and exec. Used if busybox su is absent. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: run-as-tester command [args...]\n");
        return 2;
    }
    if (setgid(1000) != 0 || setuid(1000) != 0) {
        perror("setuid");
        return 1;
    }
    execvp(argv[1], argv + 1);
    perror("exec");
    return 127;
}
