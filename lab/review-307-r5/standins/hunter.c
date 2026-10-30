/* Confined stand-in for r5 hunts. Static. One line per check. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef TIOCGWINSZ
#define TIOCGWINSZ 0x5413
#endif
#ifndef TIOCSTI
#define TIOCSTI 0x5412
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010
#endif
#ifndef SYS_io_uring_setup
#ifdef __aarch64__
#define SYS_io_uring_setup 425
#else
#define SYS_io_uring_setup 425
#endif
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
        unsigned char ch = 'x';
        if (ioctl(fd, TIOCSTI, &ch) == 0) {
            printf("tiocsti_fd_%d ok\n", fd);
        } else {
            printf("tiocsti_fd_%d errno=%d\n", fd, errno);
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

static int slurp(const char *path, unsigned char *buf, size_t cap, size_t *out) {
    int src = open(path, O_RDONLY | O_CLOEXEC);
    if (src < 0) {
        return -1;
    }
    int rc = read_all(src, buf, cap, out);
    close(src);
    return rc;
}

static void exec_path(const char *path) {
    char *argv[] = {(char *)path, NULL};
    char *envp[] = {NULL};
    execve(path, argv, envp);
    printf("exec errno=%d path=%s\n", errno, path);
}

static void try_memfd_execveat(const unsigned char *buf, size_t n, unsigned flags, const char *tag) {
    int mem = (int)syscall(SYS_memfd_create, "fcl-r5", (unsigned long)flags);
    if (mem < 0) {
        printf("%s_create errno=%d\n", tag, errno);
        return;
    }
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(mem, buf + off, n - off);
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w < 0) {
            printf("%s_write errno=%d\n", tag, errno);
            close(mem);
            return;
        }
        off += (size_t)w;
    }
    char *argv[] = {(char *)"memfd-payload", NULL};
    char *envp[] = {NULL};
    syscall(SYS_execveat, mem, "", argv, envp, AT_EMPTY_PATH);
    printf("%s_execveat errno=%d\n", tag, errno);
    close(mem);
}

static void memfd_execveat_file(const char *path, unsigned flags, const char *tag) {
    unsigned char *buf = malloc(1 << 20);
    size_t n = 0;
    if (!buf || slurp(path, buf, 1 << 20, &n) != 0) {
        printf("%s_open_src errno=%d\n", tag, errno);
        free(buf);
        return;
    }
    try_memfd_execveat(buf, n, flags, tag);
    free(buf);
}

static void memfd_procfd_exec(const char *path) {
    unsigned char *buf = malloc(1 << 20);
    size_t n = 0;
    if (!buf || slurp(path, buf, 1 << 20, &n) != 0) {
        printf("procfd_open_src errno=%d\n", errno);
        free(buf);
        return;
    }
    int mem = (int)syscall(SYS_memfd_create, "fcl-r5-noexec", 0UL);
    if (mem < 0) {
        printf("procfd_create errno=%d\n", errno);
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
            printf("procfd_write errno=%d\n", errno);
            close(mem);
            free(buf);
            return;
        }
        off += (size_t)w;
    }
    free(buf);
    if (fchmod(mem, 0755) != 0) {
        printf("procfd_fchmod errno=%d\n", errno);
    }
    char procpath[64];
    snprintf(procpath, sizeof procpath, "/proc/self/fd/%d", mem);
    char *argv[] = {procpath, NULL};
    char *envp[] = {NULL};
    execve(procpath, argv, envp);
    printf("procfd_execve errno=%d path=%s\n", errno, procpath);
    close(mem);
}

static void shm_exec(const char *path) {
    unsigned char *buf = malloc(1 << 20);
    size_t n = 0;
    if (!buf || slurp(path, buf, 1 << 20, &n) != 0) {
        printf("shm_open_src errno=%d\n", errno);
        free(buf);
        return;
    }
    shm_unlink("/fcl-r5-shm");
    int shm = shm_open("/fcl-r5-shm", O_RDWR | O_CREAT | O_EXCL, 0755);
    if (shm < 0) {
        printf("shm_open errno=%d\n", errno);
        free(buf);
        return;
    }
    if (ftruncate(shm, (off_t)n) != 0) {
        printf("shm_ftruncate errno=%d\n", errno);
        close(shm);
        shm_unlink("/fcl-r5-shm");
        free(buf);
        return;
    }
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(shm, buf + off, n - off);
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w < 0) {
            printf("shm_write errno=%d\n", errno);
            close(shm);
            shm_unlink("/fcl-r5-shm");
            free(buf);
            return;
        }
        off += (size_t)w;
    }
    free(buf);
    close(shm);
    char *argv[] = {(char *)"/dev/shm/fcl-r5-shm", NULL};
    char *envp[] = {NULL};
    execve("/dev/shm/fcl-r5-shm", argv, envp);
    printf("shm_execve errno=%d\n", errno);
    shm_unlink("/fcl-r5-shm");
}

static void after_reexec_checks(const char *payload) {
    printf("after_reexec pid=%d\n", (int)getpid());
    if (ioctl_fd(0) == 0) {
        printf("after_reexec_ioctl0 ok\n");
    } else {
        printf("after_reexec_ioctl0 errno=%d\n", errno);
    }
    memfd_execveat_file(payload, MFD_CLOEXEC | MFD_EXEC, "persist_mfd");
    memfd_execveat_file(payload, MFD_CLOEXEC, "persist_noexec");
    fflush(stdout);
}

static void recv_rights(void) {
    struct msghdr msg;
    struct iovec iov;
    char iobuf[8];
    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(&msg, 0, sizeof msg);
    memset(cbuf, 0, sizeof cbuf);
    iov.iov_base = iobuf;
    iov.iov_len = sizeof iobuf;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof cbuf;
    ssize_t n = recvmsg(0, &msg, 0);
    if (n < 0) {
        printf("recvmsg errno=%d\n", errno);
        return;
    }
    printf("recvmsg n=%zd\n", n);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        printf("scm_rights none\n");
        return;
    }
    int fd = *((int *)CMSG_DATA(cmsg));
    printf("scm_rights fd=%d\n", fd);
    char buf[32];
    ssize_t r = read(fd, buf, sizeof buf - 1);
    if (r < 0) {
        printf("scm_read errno=%d\n", errno);
    } else {
        buf[r] = 0;
        printf("scm_read n=%zd\n", r);
    }
    close(fd);
}

static void denied_syscalls(void) {
    long p = syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);
    printf("ptrace errno=%d ret=%ld\n", p < 0 ? errno : 0, p);
    struct iovec local;
    struct iovec remote;
    char buf[8] = {0};
    local.iov_base = buf;
    local.iov_len = 1;
    remote.iov_base = buf;
    remote.iov_len = 1;
    long w = syscall(SYS_process_vm_writev, getpid(), &local, 1, &remote, 1, 0);
    printf("process_vm_writev errno=%d ret=%ld\n", w < 0 ? errno : 0, w);
    long u = syscall(SYS_io_uring_setup, 8, (void *)0);
    printf("io_uring_setup errno=%d ret=%ld\n", u < 0 ? errno : 0, u);
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
    if (strcmp(mode, "reexec-self") == 0) {
        if (argc < 3) {
            printf("reexec-self missing payload\n");
            return 2;
        }
        printf("first\n");
        fflush(stdout);
        pause_stdin();
        char *nargv[] = {argv[0], (char *)"after-reexec", argv[2], NULL};
        char *envp[] = {NULL};
        execve(argv[0], nargv, envp);
        printf("exec errno=%d path=%s\n", errno, argv[0]);
        fflush(stdout);
        return 0;
    }
    if (strcmp(mode, "after-reexec") == 0) {
        after_reexec_checks(argc > 2 ? argv[2] : argv[0]);
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
        memfd_execveat_file(argv[2], 0, "memfd");
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "memfd-exec-flag") == 0) {
        if (argc < 3) {
            printf("memfd-exec-flag missing path\n");
            return 2;
        }
        memfd_execveat_file(argv[2], MFD_CLOEXEC | MFD_EXEC, "memfd_exec");
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "memfd-procfd") == 0) {
        if (argc < 3) {
            printf("memfd-procfd missing path\n");
            return 2;
        }
        memfd_procfd_exec(argv[2]);
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "shm-exec") == 0) {
        if (argc < 3) {
            printf("shm-exec missing path\n");
            return 2;
        }
        shm_exec(argv[2]);
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "denied") == 0) {
        denied_syscalls();
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "recv-rights") == 0) {
        recv_rights();
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
