/* Stand-in provider for r7 hunts. Prints one line per probe, then ready. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
#ifndef SYS_io_uring_setup
#if defined(__x86_64__)
#define SYS_io_uring_setup 425
#elif defined(__aarch64__)
#define SYS_io_uring_setup 425
#endif
#endif
#ifndef SYS_userfaultfd
#if defined(__x86_64__)
#define SYS_userfaultfd 323
#elif defined(__aarch64__)
#define SYS_userfaultfd 282
#endif
#endif

static void line(const char *tag, int err) {
    if (err == 0) {
        printf("%s ok\n", tag);
    } else {
        printf("%s errno=%d\n", tag, err);
    }
    fflush(stdout);
}

static void try_process_vm(void) {
    char buf[8];
    struct iovec local = {.iov_base = buf, .iov_len = sizeof(buf)};
    struct iovec remote = {.iov_base = (void *)(uintptr_t)0x1000, .iov_len = sizeof(buf)};
    pid_t parent = getppid();
    if (syscall(SYS_process_vm_readv, parent, &local, 1, &remote, 1, 0) < 0) {
        line("process_vm_readv", errno);
    } else {
        line("process_vm_readv", 0);
    }
    if (syscall(SYS_process_vm_writev, parent, &local, 1, &remote, 1, 0) < 0) {
        line("process_vm_writev", errno);
    } else {
        line("process_vm_writev", 0);
    }
}

static void try_pidfd(void) {
    pid_t parent = getppid();
    int pfd = (int)syscall(SYS_pidfd_open, parent, 0);
    if (pfd < 0) {
        line("pidfd_open_parent", errno);
        return;
    }
    line("pidfd_open_parent", 0);
    int stolen = (int)syscall(SYS_pidfd_getfd, pfd, 1, 0);
    if (stolen < 0) {
        line("pidfd_getfd_parent", errno);
    } else {
        line("pidfd_getfd_parent", 0);
        close(stolen);
    }
    close(pfd);
}

static void try_ptrace_and_child_exec(char *self, char *helper) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        line("ptrace_traceme", errno);
    } else {
        line("ptrace_traceme", 0);
    }
    pid_t parent = getppid();
    if (ptrace(PTRACE_ATTACH, parent, NULL, NULL) < 0) {
        line("ptrace_parent", errno);
    } else {
        line("ptrace_parent", 0);
        ptrace(PTRACE_DETACH, parent, NULL, NULL);
    }

    pid_t child = fork();
    if (child < 0) {
        line("fork_child", errno);
        return;
    }
    if (child == 0) {
        if (helper && helper[0]) {
            char *argv[] = {helper, NULL};
            char *envp[] = {NULL};
            execve(helper, argv, envp);
            int err = errno;
            dprintf(1, "child_exec_helper errno=%d\n", err);
        } else if (self && self[0]) {
            char *argv[] = {self, "child-payload", NULL};
            char *envp[] = {NULL};
            execve(self, argv, envp);
            int err = errno;
            dprintf(1, "child_exec_self errno=%d\n", err);
        }
        _exit(1);
    }
    int status = 0;
    waitpid(child, &status, 0);
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) < 0) {
        line("ptrace_child", errno);
    } else {
        line("ptrace_child", 0);
        ptrace(PTRACE_DETACH, child, NULL, NULL);
    }
}

static void try_proc_files(void) {
    const char *paths[] = {
        "/proc/self/environ",
        "/proc/self/maps",
        "/proc/self/mem",
        "/proc/self/fd",
        "/proc/1/environ",
        "/proc/1/maps",
        "/proc/1/mem",
        "/proc/1/fd",
        NULL,
    };
    for (int i = 0; paths[i]; i++) {
        int flags = O_RDONLY;
        if (strstr(paths[i], "/fd") != NULL) {
            flags |= O_DIRECTORY;
        }
        int fd = open(paths[i], flags);
        if (fd < 0) {
            printf("open %s errno=%d\n", paths[i], errno);
        } else {
            char buf[32];
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n < 0) {
                printf("read %s errno=%d\n", paths[i], errno);
            } else {
                printf("read %s ok n=%zd\n", paths[i], n);
            }
            close(fd);
        }
        fflush(stdout);
    }
}

static void try_prctl_aliases(void) {
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
        line("prctl_dumpable_1", errno);
    } else {
        line("prctl_dumpable_1", 0);
    }
    /* High half of arg1 is 1; low half is 0. Filter only reads ARG1_LOW. */
    if (syscall(SYS_prctl, PR_SET_DUMPABLE, (unsigned long)1 << 32, 0, 0, 0) < 0) {
        line("prctl_dumpable_high32", errno);
    } else {
        line("prctl_dumpable_high32", 0);
    }
#if defined(__x86_64__)
    /* x32 ABI: nr | 0x40000000. First filter returns EPERM. */
    if (syscall(SYS_prctl | 0x40000000, PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
        line("prctl_x32", errno);
    } else {
        line("prctl_x32", 0);
    }
#endif
}

static void try_denied_syscalls(void) {
    if (syscall(SYS_io_uring_setup, 8, (void *)0) < 0) {
        line("io_uring_setup", errno);
    } else {
        line("io_uring_setup", 0);
    }
    if (syscall(SYS_userfaultfd, 0) < 0) {
        line("userfaultfd", errno);
    } else {
        line("userfaultfd", 0);
    }
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_DUMMY;
    attr.disabled = 1;
    if (syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0) < 0) {
        line("perf_event_open", errno);
    } else {
        line("perf_event_open", 0);
    }
}

static void try_core_setup(void) {
    int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    printf("get_dumpable=%d\n", dumpable);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "child-payload") == 0) {
        printf("child_exec_self ran\n");
        fflush(stdout);
        return 0;
    }
    printf("hunter pid=%d ppid=%d\n", getpid(), getppid());
    fflush(stdout);
    try_process_vm();
    try_pidfd();
    try_ptrace_and_child_exec(argv[0], argc >= 3 ? argv[2] : NULL);
    try_proc_files();
    try_prctl_aliases();
    try_denied_syscalls();
    try_core_setup();
    printf("ready\n");
    fflush(stdout);
    char buf[8];
    ssize_t n = read(0, buf, sizeof(buf));
    (void)n;
    return 0;
}
