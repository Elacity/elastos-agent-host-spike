/* Tiny payload. If this image runs after start, an exec escape survived. */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("payload pid=%d\n", getpid());
    fflush(stdout);
    return 0;
}
