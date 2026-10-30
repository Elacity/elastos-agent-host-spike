/* Confined stand-in for r6 hunts. Static. One line per check. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/memfd.h>
#include <linux/sched.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <sys/uio.h>
#include <sys/wait.h>
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
#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif
#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000
#endif
#ifndef SYS_clone3
#ifdef __aarch64__
#define SYS_clone3 435
#else
#define SYS_clone3 435
#endif
#endif
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter 426
#endif
#ifndef SYS_io_uring_register
#define SYS_io_uring_register 427
#endif

static void pause_stdin(void) {
    char buf[8];
    ssize_t n;
    do {
        n = read(0, buf, sizeof buf);
    } while (n < 0 && errno == EINTR);
}

static int fd_kind(int fd, char *out, size_t cap) {
    struct stat st;
    if (fstat(fd, &st) != 0) {
        snprintf(out, cap, "err=%d", errno);
        return -1;
    }
    if (S_ISFIFO(st.st_mode)) {
        snprintf(out, cap, "pipe");
    } else if (S_ISSOCK(st.st_mode)) {
        snprintf(out, cap, "sock");
    } else if (S_ISCHR(st.st_mode)) {
        snprintf(out, cap, "chr");
    } else if (S_ISREG(st.st_mode)) {
        snprintf(out, cap, "reg");
    } else {
        snprintf(out, cap, "mode=%o", (unsigned)(st.st_mode & S_IFMT));
    }
    return 0;
}

static void list_fds(void) {
    for (int fd = 0; fd < 256; fd++) {
        if (fcntl(fd, F_GETFD) < 0) {
            continue;
        }
        char kind[32];
        fd_kind(fd, kind, sizeof kind);
        printf("fd %d kind=%s\n", fd, kind);
    }
}

static void try_exec(const char *path, const char *tag) {
    char *argv[] = {(char *)path, (char *)"--payload-child", NULL};
    char *envp[] = {NULL};
    execve(path, argv, envp);
    printf("%s errno=%d path=%s\n", tag, errno, path);
}

static void try_execveat(int dirfd, const char *path, int flags, const char *tag) {
    char *argv[] = {(char *)"execveat", NULL};
    char *envp[] = {NULL};
    syscall(SYS_execveat, dirfd, path, argv, envp, flags);
    printf("%s errno=%d\n", tag, errno);
}

#ifdef __x86_64__
static void try_int80_execve(const char *path) {
    /* i386 execve is syscall 11. int 0x80 uses AUDIT_ARCH_I386. */
    long ret;
    char *argv[] = {(char *)path, NULL};
    char *envp[] = {NULL};
    register long rax asm("eax") = 11;
    register long rbx asm("ebx") = (long)path;
    register long rcx asm("ecx") = (long)argv;
    register long rdx asm("edx") = (long)envp;
    asm volatile("int $0x80" : "+a"(rax) : "b"(rbx), "c"(rcx), "d"(rdx) : "memory");
    ret = rax;
    if (ret < 0) {
        printf("int80_execve errno=%ld\n", -ret);
    } else {
        printf("int80_execve ret=%ld\n", ret);
    }
}

static void try_x32_execve(const char *path) {
    char *argv[] = {(char *)path, NULL};
    char *envp[] = {NULL};
    long nr = (long)SYS_execve | (long)__X32_SYSCALL_BIT;
    long ret = syscall(nr, path, argv, envp);
    printf("x32_execve errno=%d ret=%ld nr=0x%lx\n", ret < 0 ? errno : 0, ret, (unsigned long)nr);
}

static void try_x32_execveat(void) {
    char *argv[] = {(char *)"x", NULL};
    char *envp[] = {NULL};
    long nr = (long)SYS_execveat | (long)__X32_SYSCALL_BIT;
    long ret = syscall(nr, AT_FDCWD, "/proc/self/exe", argv, envp, 0);
    printf("x32_execveat errno=%d ret=%ld\n", ret < 0 ? errno : 0, ret);
}
#endif

struct clone_args_min {
    unsigned long long flags;
    unsigned long long pidfd;
    unsigned long long child_tid;
    unsigned long long parent_tid;
    unsigned long long exit_signal;
    unsigned long long stack;
    unsigned long long stack_size;
    unsigned long long tls;
    unsigned long long set_tid;
    unsigned long long set_tid_size;
    unsigned long long cgroup;
};

static void try_clone3_cgroup(void) {
    struct clone_args_min args;
    memset(&args, 0, sizeof args);
    args.flags = CLONE_INTO_CGROUP;
    args.exit_signal = SIGCHLD;
    args.cgroup = 0;
    long ret = syscall(SYS_clone3, &args, sizeof args);
    printf("clone3_cgroup errno=%d ret=%ld\n", ret < 0 ? errno : 0, ret);
    if (ret == 0) {
        _exit(0);
    }
}

static void try_io_uring(void) {
    /* 64-byte params is enough to reach the syscall. */
    unsigned char params[256];
    memset(params, 0, sizeof params);
    long ret = syscall(SYS_io_uring_setup, 8, params);
    printf("io_uring_setup errno=%d ret=%ld\n", ret < 0 ? errno : 0, ret);
    if (ret >= 0) {
        close((int)ret);
    }
    ret = syscall(SYS_io_uring_enter, 0, 1, 0, 0, (void *)0, 0);
    printf("io_uring_enter errno=%d ret=%ld\n", ret < 0 ? errno : 0, ret);
    ret = syscall(SYS_io_uring_register, 0, 0, (void *)0, 0);
    printf("io_uring_register errno=%d ret=%ld\n", ret < 0 ? errno : 0, ret);
}

static void try_ptrace_sibling(void) {
    pid_t child = fork();
    if (child < 0) {
        printf("ptrace_fork errno=%d\n", errno);
        return;
    }
    if (child == 0) {
        for (;;) {
            pause();
        }
    }
    long ret = syscall(SYS_ptrace, PTRACE_ATTACH, (long)child, 0, 0);
    printf("ptrace_sibling errno=%d ret=%ld child=%d\n", ret < 0 ? errno : 0, ret, (int)child);
    ret = syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);
    printf("ptrace_traceme errno=%d ret=%ld\n", ret < 0 ? errno : 0, ret);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
}

static void try_dumpable(void) {
    int before = prctl(PR_GET_DUMPABLE);
    printf("dumpable_get errno=%d val=%d\n", before < 0 ? errno : 0, before);
    int rc = prctl(PR_SET_DUMPABLE, 1);
    printf("dumpable_set1 errno=%d ret=%d\n", rc < 0 ? errno : 0, rc);
    rc = prctl(PR_SET_DUMPABLE, 0);
    printf("dumpable_set0 errno=%d ret=%d\n", rc < 0 ? errno : 0, rc);
    rc = prctl(PR_SET_DUMPABLE, 1);
    printf("dumpable_reset1 errno=%d ret=%d\n", rc < 0 ? errno : 0, rc);
    rc = prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    printf("set_ptracer_any errno=%d ret=%d\n", rc < 0 ? errno : 0, rc);
    int mem = open("/proc/self/mem", O_RDWR);
    if (mem < 0) {
        printf("self_mem_open errno=%d\n", errno);
    } else {
        char one = 0;
        ssize_t n = pread(mem, &one, 1, (off_t)(uintptr_t)&try_dumpable);
        printf("self_mem_pread n=%zd errno=%d\n", n, n < 0 ? errno : 0);
        n = pwrite(mem, &one, 1, (off_t)(uintptr_t)&try_dumpable);
        printf("self_mem_pwrite n=%zd errno=%d\n", n, n < 0 ? errno : 0);
        close(mem);
    }
}

static void try_dup2_inherited(int from) {
    char kind[32];
    if (fcntl(from, F_GETFD) < 0) {
        printf("inherit_fd_%d gone errno=%d\n", from, errno);
        return;
    }
    fd_kind(from, kind, sizeof kind);
    printf("inherit_fd_%d kind=%s\n", from, kind);
    if (dup2(from, 0) < 0) {
        printf("dup2_%d_to_0 errno=%d\n", from, errno);
        return;
    }
    fd_kind(0, kind, sizeof kind);
    printf("dup2_%d_to_0 ok stdin=%s\n", from, kind);
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
    ssize_t n = recvmsg(0, &msg, MSG_DONTWAIT);
    if (n < 0) {
        printf("recvmsg_after_dup2 errno=%d\n", errno);
        return;
    }
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
        printf("scm_rights_after_dup2 ok\n");
    } else {
        printf("scm_rights_after_dup2 none n=%zd\n", n);
    }
}

static void try_tiocsti(int fd) {
    unsigned char ch = 'x';
    if (ioctl(fd, TIOCSTI, &ch) == 0) {
        printf("tiocsti_fd_%d ok\n", fd);
    } else {
        printf("tiocsti_fd_%d errno=%d\n", fd, errno);
    }
}

static void try_recv_stdin(void) {
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
    ssize_t n = recvmsg(0, &msg, MSG_DONTWAIT);
    if (n < 0) {
        printf("stdin_recvmsg errno=%d\n", errno);
        return;
    }
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
        printf("stdin_scm_rights ok\n");
    } else {
        printf("stdin_scm_rights none n=%zd\n", n);
    }
}

static void granted_twice(const char *path) {
    try_exec(path, "reexec1");
    try_exec(path, "reexec2");
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "wait";
    printf("hunter mode=%s pid=%d\n", mode, (int)getpid());
    fflush(stdout);

    if (strcmp(mode, "--payload-child") == 0) {
        printf("payload pid=%d\n", (int)getpid());
        return 0;
    }
    if (strcmp(mode, "listfds") == 0) {
        list_fds();
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "granted-twice") == 0) {
        if (argc < 3) {
            printf("granted-twice missing path\n");
            return 2;
        }
        granted_twice(argv[2]);
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "proc-exe") == 0) {
        try_exec("/proc/self/exe", "proc_exe");
        try_execveat(AT_FDCWD, "/proc/self/exe", 0, "proc_exe_execveat");
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "exec-path") == 0) {
        if (argc < 3) {
            printf("exec-path missing path\n");
            return 2;
        }
        try_exec(argv[2], "exec_path");
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "shebang") == 0) {
        if (argc < 3) {
            printf("shebang missing path\n");
            return 2;
        }
        try_exec(argv[2], "shebang");
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "dup2-sock") == 0) {
        int from = argc > 2 ? atoi(argv[2]) : 3;
        try_dup2_inherited(from);
        list_fds();
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "pipe-scm") == 0) {
        char kind[32];
        fd_kind(0, kind, sizeof kind);
        printf("stdin_kind=%s\n", kind);
        try_recv_stdin();
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "tiocsti-high") == 0) {
        for (int fd = 3; fd < 16; fd++) {
            if (fcntl(fd, F_GETFD) < 0) {
                continue;
            }
            try_tiocsti(fd);
        }
        try_tiocsti(3);
        list_fds();
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "wrong-arch") == 0) {
#ifdef __x86_64__
        const char *path = argc > 2 ? argv[2] : "/proc/self/exe";
        pid_t child = fork();
        if (child == 0) {
            try_int80_execve(path);
            try_x32_execve(path);
            try_x32_execveat();
            _exit(0);
        }
        if (child > 0) {
            int status = 0;
            waitpid(child, &status, 0);
            if (WIFSIGNALED(status)) {
                printf("wrong_arch_child signal=%d\n", WTERMSIG(status));
            } else if (WIFEXITED(status)) {
                printf("wrong_arch_child exit=%d\n", WEXITSTATUS(status));
            }
        }
#else
        printf("wrong_arch skipped_not_x86_64\n");
#endif
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "clone3") == 0) {
        try_clone3_cgroup();
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "io-uring") == 0) {
        try_io_uring();
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "ptrace") == 0) {
        try_ptrace_sibling();
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "dumpable") == 0) {
        try_dumpable();
        try_ptrace_sibling();
        fflush(stdout);
        pause_stdin();
        return 0;
    }
    if (strcmp(mode, "combo") == 0) {
        const char *granted = argc > 2 ? argv[2] : "/proc/self/exe";
        list_fds();
        granted_twice(granted);
        try_exec("/proc/self/exe", "proc_exe");
        try_clone3_cgroup();
        try_io_uring();
        try_ptrace_sibling();
        try_dumpable();
#ifdef __x86_64__
        pid_t child = fork();
        if (child == 0) {
            try_int80_execve(granted);
            try_x32_execve(granted);
            _exit(0);
        }
        if (child > 0) {
            int status = 0;
            waitpid(child, &status, 0);
            if (WIFSIGNALED(status)) {
                printf("wrong_arch_child signal=%d\n", WTERMSIG(status));
            } else if (WIFEXITED(status)) {
                printf("wrong_arch_child exit=%d\n", WEXITSTATUS(status));
            }
        }
#endif
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
