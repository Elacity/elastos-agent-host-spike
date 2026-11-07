/* Confined stand-in for r4 hunts. Static. Writes one line per check, then
 * waits on stdin unless a mode execs away. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef TIOCGWINSZ
#define TIOCGWINSZ 0x5413
#endif

static void pause_stdin(void) {
    char buf[8];
    ssize_t n;
    do {
        n = read(0, buf, sizeof buf);
    } while (n < 0 && errno == EINTR);
}

static int ioctl_fd(int fd) {
    unsigned short ws[4] = {0, 0, 0, 0};
    return ioctl(fd, TIOCGWINSZ, ws);
}

static void list_fds(void) {
    for (int fd = 0; fd < 256; fd++) {
        int flags = fcntl(fd, F_GETFD);
        if (flags < 0) {
            continue;
        }
        struct stat st;
        const char *kind = "other";
        if (fstat(fd, &st) == 0) {
            if (S_ISFIFO(st.st_mode)) {
                kind = "pipe";
            } else if (S_ISSOCK(st.st_mode)) {
                kind = "sock";
            } else if (S_ISCHR(st.st_mode)) {
                kind = "chr";
            } else if (S_ISREG(st.st_mode)) {
                kind = "reg";
            }
        }
        printf("fd %d flags=%d kind=%s\n", fd, flags, kind);
    }
}

static void ioctl_scan(void) {
    for (int fd = 0; fd < 32; fd++) {
        if (fcntl(fd, F_GETFD) < 0) {
            continue;
        }
        if (ioctl_fd(fd) == 0) {
            printf("ioctl_fd_%d ok\n", fd);
        } else {
            printf("ioctl_fd_%d errno=%d\n", fd, errno);
        }
    }
}

static int read_all(int fd, unsigned char *buf, size_t cap, size_t *out) {
    size_t got = 0;
    while (got < cap) {
        ssize_t n = read(fd, buf + got, cap - got);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0) {
            return -1;
        }
        if (n == 0) {
            break;
        }
        got += (size_t)n;
    }
    *out = got;
    return 0;
}

static void exec_path(const char *path) {
    char *argv[] = {(char *)path, NULL};
    char *envp[] = {NULL};
    execve(path, argv, envp);
    printf("exec errno=%d path=%s\n", errno, path);
}

static void memfd_exec(const char *path) {
    int src = open(path, O_RDONLY | O_CLOEXEC);
    if (src < 0) {
        printf("memfd_open_src errno=%d\n", errno);
        return;
    }
    unsigned char *buf = malloc(1 << 20);
    if (!buf) {
        printf("memfd_alloc errno=%d\n", errno);
        close(src);
        return;
    }
    size_t n = 0;
    if (read_all(src, buf, 1 << 20, &n) != 0) {
        printf("memfd_read errno=%d\n", errno);
        close(src);
        free(buf);
        return;
    }
    close(src);
    int mem = (int)syscall(SYS_memfd_create, "fcl-r4", 0);
    if (mem < 0) {
        printf("memfd_create errno=%d\n", errno);
        free(buf);
        return;
    }
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(mem, buf + off, n - off);
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w < 0) {
            printf("memfd_write errno=%d\n", errno);
            close(mem);
            free(buf);
            return;
        }
        off += (size_t)w;
    }
    free(buf);
    char *argv[] = {(char *)"memfd-payload", NULL};
    char *envp[] = {NULL};
    syscall(SYS_execveat, mem, "", argv, envp, AT_EMPTY_PATH);
    printf("memfd_execveat errno=%d\n", errno);
    close(mem);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "wait";
    printf("hunter mode=%s pid=%d\n", mode, (int)getpid());
    fflush(stdout);

    if (strcmp(mode, "listfds") == 0) {
        list_fds();
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "stdin-ioctl") == 0) {
        ioctl_scan();
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "reexec") == 0) {
        if (argc < 3) {
            printf("reexec missing path\n");
            return 2;
        }
        printf("first\n");
        fflush(stdout);
        pause_stdin();
        exec_path(argv[2]);
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "exec") == 0) {
        if (argc < 3) {
            printf("exec missing path\n");
            return 2;
        }
        exec_path(argv[2]);
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "memfd-exec") == 0) {
        if (argc < 3) {
            printf("memfd-exec missing path\n");
            return 2;
        }
        memfd_exec(argv[2]);
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "wait") == 0) {
        pause_stdin();
        return 0;
    }
    printf("unknown mode\n");
    return 2;
}
