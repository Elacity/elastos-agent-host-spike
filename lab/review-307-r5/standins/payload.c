/* Second image: proves a later execve ran. */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argc;
    printf("payload pid=%d\n", (int)getpid());
    fflush(stdout);
    if (argv[1]) {
        int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            (void)write(fd, "payload-ran\n", 12);
            close(fd);
        }
    }
    char buf[8];
    (void)read(0, buf, sizeof buf);
    return 0;
}
