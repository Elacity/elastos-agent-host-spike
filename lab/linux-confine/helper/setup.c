/* Applies one Linux confinement policy, then execs the freestanding probe.
 *
 * Order: user namespace, uid/gid map, mount/net/ipc/pid namespaces, Landlock
 * rules, capability bounding set, empty capability sets, no_new_privs,
 * Landlock enforce, seccomp allow-list, exec. A missing primitive writes a
 * refusal and does not exec the probe.
 *
 * Syscall numbers come from <sys/syscall.h>. The audit architecture is
 * selected with the compiler's target macro.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

/* F-LC-STORAGE: eight STORAGE_ROOT rights. The other handled rights stay denied. */
#define LC_STORAGE_RIGHTS (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR)

#if defined(__x86_64__)
#define LC_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define LC_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error linux-confine supports x86_64 and aarch64
#endif

#define LC_EXTRA 12

struct policy {
    int deny_network;
    int provider;
    int read_parent;
    char helper[4096];
    char execute[4096];
    char preload[4096];
    char storage_root[4096];
    char storage[4096];
    char storage2[4096];
    char outside[4096];
    char parent[4096];
    char copy[4096];
    char read_exec[LC_EXTRA][4096];
    int n_read_exec;
    char read_only[LC_EXTRA][4096];
    int n_read_only;
};

static void emit_fd(int fd, const char *s) {
    size_t n = 0;
    while (s[n]) {
        n++;
    }
    syscall(SYS_write, fd, s, n);
}

static void emit(const char *s) {
    emit_fd(1, s);
}

static void refuse(const char *msg) {
    emit(msg);
    emit("\n");
    _exit(2);
}

static void refuse_errno(const char *msg, int err) {
    char buf[512];
    snprintf(buf, sizeof buf, "%s errno=%d\n", msg, err);
    emit(buf);
    _exit(2);
}

const char *abi_refusal(int abi) {
    if (abi < 0) {
        return "linux confinement refused: the kernel has no Landlock";
    }
    if (abi < 3) {
        return "linux confinement refused: the Landlock ABI cannot express the STORAGE_ROOT read and write";
    }
    if (abi < 5) {
        return "linux confinement refused: the Landlock ABI cannot express device ioctl";
    }
    return NULL;
}

static int landlock_abi(void) {
    long n = syscall(SYS_landlock_create_ruleset, NULL, (size_t)0, LANDLOCK_CREATE_RULESET_VERSION);
    if (n < 0) {
        return -1;
    }
    return (int)n;
}

static const char *seccomp_refusal(void) {
    errno = 0;
    int mode = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (mode < 0 && errno == ENOSYS) {
        return "linux confinement refused: the kernel has no seccomp";
    }
    return NULL;
}

static int install_filter(struct sock_filter *filt, unsigned short len) {
    struct sock_fprog prog = {.len = len, .filter = filt};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return -1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        return -1;
    }
    return 0;
}

#ifdef LC_TEST_HOOKS
static void install_block_landlock(void) {
    struct sock_filter filt[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, LC_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_landlock_create_ruleset, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    if (install_filter(filt, sizeof filt / sizeof filt[0]) != 0) {
        refuse_errno("linux confinement refused: the seccomp filter cannot be installed", errno);
    }
}

static void install_block_seccomp_probe(void) {
    /* prctl(PR_GET_SECCOMP) returns ENOSYS. Every other call is allowed. */
    struct sock_filter filt[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, LC_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_GET_SECCOMP, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    if (install_filter(filt, sizeof filt / sizeof filt[0]) != 0) {
        refuse_errno("linux confinement refused: the seccomp filter cannot be installed", errno);
    }
}

static void install_block_unshare(void) {
    struct sock_filter filt[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, LC_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_unshare, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    if (install_filter(filt, sizeof filt / sizeof filt[0]) != 0) {
        refuse_errno("linux confinement refused: the seccomp filter cannot be installed", errno);
    }
}
#endif

static void copy_value(char *dst, size_t dst_len, const char *src) {
    size_t n = 0;
    if (dst_len == 0) {
        refuse("linux confinement refused: the launch path does not fit");
    }
    while (src[n]) {
        if (n + 1 >= dst_len) {
            refuse("linux confinement refused: the launch path does not fit");
        }
        dst[n] = src[n];
        n++;
    }
    dst[n] = 0;
}

static void push_path(char paths[][4096], int *count, const char *src) {
    if (*count >= LC_EXTRA) {
        refuse("linux confinement refused: the launch has too many library paths");
    }
    copy_value(paths[*count], 4096, src);
    *count += 1;
}

static void load_policy(const char *path, struct policy *pol) {
    char buf[65536];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n;
    char *p;
    memset(pol, 0, sizeof *pol);
    pol->deny_network = 1;
    if (fd < 0) {
        refuse_errno("linux confinement refused: the launch policy cannot be read", errno);
    }
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0) {
        refuse_errno("linux confinement refused: the launch policy cannot be read", errno);
    }
    buf[n] = 0;
    p = buf;
    while (*p) {
        char *nl = p;
        char *eq;
        while (*nl && *nl != '\n') {
            nl++;
        }
        *nl = 0;
        eq = p;
        while (*eq && *eq != '=') {
            eq++;
        }
        if (*eq == '=') {
            *eq = 0;
            if (strcmp(p, "deny_network") == 0) {
                pol->deny_network = strcmp(eq + 1, "0") != 0;
            } else if (strcmp(p, "helper") == 0) {
                copy_value(pol->helper, sizeof pol->helper, eq + 1);
            } else if (strcmp(p, "storage_root") == 0) {
                copy_value(pol->storage_root, sizeof pol->storage_root, eq + 1);
            } else if (strcmp(p, "storage") == 0) {
                copy_value(pol->storage, sizeof pol->storage, eq + 1);
            } else if (strcmp(p, "storage2") == 0) {
                copy_value(pol->storage2, sizeof pol->storage2, eq + 1);
            } else if (strcmp(p, "outside") == 0) {
                copy_value(pol->outside, sizeof pol->outside, eq + 1);
            } else if (strcmp(p, "parent") == 0) {
                copy_value(pol->parent, sizeof pol->parent, eq + 1);
            } else if (strcmp(p, "copy") == 0) {
                copy_value(pol->copy, sizeof pol->copy, eq + 1);
            } else if (strcmp(p, "execute") == 0) {
                copy_value(pol->execute, sizeof pol->execute, eq + 1);
            } else if (strcmp(p, "preload") == 0) {
                copy_value(pol->preload, sizeof pol->preload, eq + 1);
            } else if (strcmp(p, "mode") == 0) {
                pol->provider = strcmp(eq + 1, "provider") == 0;
            } else if (strcmp(p, "read_parent") == 0) {
                pol->read_parent = strcmp(eq + 1, "1") == 0;
            } else if (strcmp(p, "read_exec") == 0) {
                push_path(pol->read_exec, &pol->n_read_exec, eq + 1);
            } else if (strcmp(p, "read_only") == 0) {
                push_path(pol->read_only, &pol->n_read_only, eq + 1);
            } else if (p[0] != 0) {
                refuse("linux confinement refused: the launch policy has an unknown field");
            }
        }
        if (nl[1] == 0 && (nl == buf + n || nl[0] == 0)) {
            break;
        }
        p = nl + 1;
        if (p >= buf + n) {
            break;
        }
    }
    if (pol->helper[0] == 0 || pol->storage_root[0] == 0 || pol->storage[0] == 0 || pol->outside[0] == 0 ||
        pol->parent[0] == 0 || pol->copy[0] == 0) {
        refuse("linux confinement refused: the launch policy is incomplete");
    }
    if (pol->storage2[0] == 0) {
        copy_value(pol->storage2, sizeof pol->storage2, "-");
    }
    if (pol->execute[0] == 0) {
        copy_value(pol->execute, sizeof pol->execute, pol->helper);
    }
}

static const char *netns_kind(void) {
    char buf[2048];
    int fd = open("/proc/net/dev", O_RDONLY | O_CLOEXEC);
    ssize_t n;
    char *p;
    int lo = 0;
    int other = 0;
    if (fd < 0) {
        return "unread";
    }
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) {
        return "unread";
    }
    buf[n] = 0;
    p = buf;
    while (*p) {
        char *nl = p;
        int colon = 0;
        char *q;
        while (*nl && *nl != '\n') {
            nl++;
        }
        for (q = p; q < nl; q++) {
            if (*q == ':') {
                colon = 1;
            }
        }
        if (colon) {
            while (p < nl && (*p == ' ' || *p == '\t')) {
                p++;
            }
            if (p + 2 < nl && p[0] == 'l' && p[1] == 'o' && p[2] == ':') {
                lo = 1;
            } else {
                other = 1;
            }
        }
        if (*nl == 0) {
            break;
        }
        p = nl + 1;
    }
    if (lo && !other) {
        return "lo";
    }
    return "host";
}

static void add_rule(int ruleset, const char *path, __u64 access, const char *what) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    struct landlock_path_beneath_attr attr;
    if (fd < 0) {
        refuse_errno(what, errno);
    }
    memset(&attr, 0, sizeof attr);
    attr.allowed_access = access;
    attr.parent_fd = fd;
    if (syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &attr, 0) != 0) {
        int err = errno;
        close(fd);
        refuse_errno("linux confinement refused: the Landlock rule cannot be added", err);
    }
    close(fd);
}

static void install_allow_list(int deny_network) {
    int allow[16];
    int nallow = 0;
    int i;
    struct sock_filter filt[64];
    int n = 0;
    allow[nallow++] = SYS_read;
    allow[nallow++] = SYS_write;
    allow[nallow++] = SYS_close;
    allow[nallow++] = SYS_openat;
    allow[nallow++] = SYS_execve;
    allow[nallow++] = SYS_exit_group;
    allow[nallow++] = SYS_uname;
    allow[nallow++] = SYS_kill;
    if (!deny_network) {
        allow[nallow++] = SYS_socket;
        allow[nallow++] = SYS_socketpair;
    }
    filt[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4);
    filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, LC_AUDIT_ARCH, 1, 0);
    filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    filt[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0);
    for (i = 0; i < nallow; i++) {
        filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)allow[i], 0, 1);
        filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }
    filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    if (install_filter(filt, (unsigned short)n) != 0) {
        refuse_errno("linux confinement refused: the seccomp filter cannot be installed", errno);
    }
}

static void push_nr(int *allow, int *nallow, int nr) {
    if (*nallow >= 96) {
        refuse("linux confinement refused: the seccomp allow-list does not fit");
    }
    allow[*nallow] = nr;
    *nallow += 1;
}

static void install_provider_filter(int deny_network) {
    int allow[96];
    int nallow = 0;
    struct sock_filter filt[320];
    int n = 0;
    int i;
    int denied[] = {
        SYS_socket,   SYS_connect, SYS_bind,      SYS_listen,    SYS_accept,   SYS_accept4,
        SYS_sendto,   SYS_recvfrom, SYS_sendmsg,  SYS_recvmsg,   SYS_sendmmsg, SYS_recvmmsg,
    };
    push_nr(allow, &nallow, SYS_read);
    push_nr(allow, &nallow, SYS_write);
    push_nr(allow, &nallow, SYS_close);
    push_nr(allow, &nallow, SYS_openat);
    push_nr(allow, &nallow, SYS_exit);
    push_nr(allow, &nallow, SYS_exit_group);
    push_nr(allow, &nallow, SYS_mmap);
    push_nr(allow, &nallow, SYS_mprotect);
    push_nr(allow, &nallow, SYS_munmap);
    push_nr(allow, &nallow, SYS_brk);
    push_nr(allow, &nallow, SYS_madvise);
    push_nr(allow, &nallow, SYS_pread64);
    push_nr(allow, &nallow, SYS_pwrite64);
    push_nr(allow, &nallow, SYS_readv);
    push_nr(allow, &nallow, SYS_writev);
    push_nr(allow, &nallow, SYS_lseek);
    push_nr(allow, &nallow, SYS_fstat);
    push_nr(allow, &nallow, SYS_newfstatat);
    push_nr(allow, &nallow, SYS_statx);
    push_nr(allow, &nallow, SYS_getrandom);
    push_nr(allow, &nallow, SYS_getpid);
    push_nr(allow, &nallow, SYS_getuid);
    push_nr(allow, &nallow, SYS_geteuid);
    push_nr(allow, &nallow, SYS_getgid);
    push_nr(allow, &nallow, SYS_getegid);
    push_nr(allow, &nallow, SYS_rt_sigaction);
    push_nr(allow, &nallow, SYS_rt_sigprocmask);
    push_nr(allow, &nallow, SYS_rt_sigreturn);
    push_nr(allow, &nallow, SYS_sigaltstack);
    push_nr(allow, &nallow, SYS_set_tid_address);
    push_nr(allow, &nallow, SYS_set_robust_list);
    push_nr(allow, &nallow, SYS_rseq);
    push_nr(allow, &nallow, SYS_prlimit64);
    push_nr(allow, &nallow, SYS_sched_getaffinity);
    push_nr(allow, &nallow, SYS_sched_yield);
    push_nr(allow, &nallow, SYS_prctl);
    push_nr(allow, &nallow, SYS_futex);
    push_nr(allow, &nallow, SYS_clone);
    push_nr(allow, &nallow, SYS_clone3);
    push_nr(allow, &nallow, SYS_fcntl);
    push_nr(allow, &nallow, SYS_ioctl);
    push_nr(allow, &nallow, SYS_dup);
    push_nr(allow, &nallow, SYS_dup3);
    push_nr(allow, &nallow, SYS_pipe2);
    push_nr(allow, &nallow, SYS_eventfd2);
    push_nr(allow, &nallow, SYS_epoll_create1);
    push_nr(allow, &nallow, SYS_epoll_ctl);
    push_nr(allow, &nallow, SYS_flock);
    push_nr(allow, &nallow, SYS_fsync);
    push_nr(allow, &nallow, SYS_fdatasync);
    push_nr(allow, &nallow, SYS_getdents64);
    push_nr(allow, &nallow, SYS_readlinkat);
    push_nr(allow, &nallow, SYS_clock_gettime);
    push_nr(allow, &nallow, SYS_clock_nanosleep);
    push_nr(allow, &nallow, SYS_nanosleep);
    push_nr(allow, &nallow, SYS_kill);
    push_nr(allow, &nallow, SYS_tgkill);
    push_nr(allow, &nallow, SYS_execve);
    push_nr(allow, &nallow, SYS_execveat);
    push_nr(allow, &nallow, SYS_mkdirat);
    push_nr(allow, &nallow, SYS_unlinkat);
    push_nr(allow, &nallow, SYS_linkat);
    push_nr(allow, &nallow, SYS_renameat);
    push_nr(allow, &nallow, SYS_renameat2);
    push_nr(allow, &nallow, SYS_fchmod);
    push_nr(allow, &nallow, SYS_fchmodat);
    push_nr(allow, &nallow, SYS_faccessat);
    push_nr(allow, &nallow, SYS_faccessat2);
#ifdef SYS_arch_prctl
    push_nr(allow, &nallow, SYS_arch_prctl);
#endif
#ifdef SYS_mkdir
    push_nr(allow, &nallow, SYS_mkdir);
#endif
#ifdef SYS_rename
    push_nr(allow, &nallow, SYS_rename);
#endif
#ifdef SYS_link
    push_nr(allow, &nallow, SYS_link);
#endif
#ifdef SYS_unlink
    push_nr(allow, &nallow, SYS_unlink);
#endif
#ifdef SYS_chmod
    push_nr(allow, &nallow, SYS_chmod);
#endif
#ifdef SYS_access
    push_nr(allow, &nallow, SYS_access);
#endif
#ifdef SYS_poll
    push_nr(allow, &nallow, SYS_poll);
#endif
#ifdef SYS_ppoll
    push_nr(allow, &nallow, SYS_ppoll);
#endif
#ifdef SYS_epoll_wait
    push_nr(allow, &nallow, SYS_epoll_wait);
#endif
#ifdef SYS_epoll_pwait
    push_nr(allow, &nallow, SYS_epoll_pwait);
#endif
#ifdef SYS_gettid
    push_nr(allow, &nallow, SYS_gettid);
#endif
#ifdef SYS_close_range
    push_nr(allow, &nallow, SYS_close_range);
#endif
    if (!deny_network) {
        push_nr(allow, &nallow, SYS_socket);
        push_nr(allow, &nallow, SYS_socketpair);
    }
    filt[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4);
    filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, LC_AUDIT_ARCH, 1, 0);
    filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    filt[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0);
    if (deny_network) {
        for (i = 0; i < (int)(sizeof denied / sizeof denied[0]); i++) {
            filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)denied[i], 0, 1);
            filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
        }
        filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socketpair, 0, 4);
        filt[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16);
        filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 1);
        filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    }
    for (i = 0; i < nallow; i++) {
        filt[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)allow[i], 0, 1);
        filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }
    filt[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    if (n > (int)(sizeof filt / sizeof filt[0])) {
        refuse("linux confinement refused: the seccomp filter cannot be installed");
    }
    if (install_filter(filt, (unsigned short)n) != 0) {
        refuse_errno("linux confinement refused: the seccomp filter cannot be installed", errno);
    }
}

static void hide_parent_siblings(struct policy *pol) {
    char hold[] = "/tmp/lc-hold-XXXXXX";
    const char *slash = strrchr(pol->storage_root, '/');
    char rebound[8192];
    int wrote;
    if (mkdtemp(hold) == NULL) {
        refuse_errno("linux confinement refused: the mount namespace cannot be created", errno);
    }
    if (mount(pol->storage_root, hold, NULL, MS_BIND, NULL) != 0) {
        refuse_errno("linux confinement refused: the mount namespace cannot be created", errno);
    }
    if (mount("tmpfs", pol->parent, "tmpfs", MS_NOSUID | MS_NODEV, "mode=755") != 0) {
        refuse_errno("linux confinement refused: the mount namespace cannot be created", errno);
    }
    if (slash == NULL || slash[1] == 0) {
        refuse("linux confinement refused: the storage root has no directory name");
    }
    wrote = snprintf(rebound, sizeof rebound, "%s/%s", pol->parent, slash + 1);
    if (wrote < 0 || wrote >= (int)sizeof rebound) {
        refuse("linux confinement refused: the storage root has no directory name");
    }
    if (mkdir(rebound, 0755) != 0 && errno != EEXIST) {
        refuse_errno("linux confinement refused: the mount namespace cannot be created", errno);
    }
    if (mount(hold, rebound, NULL, MS_BIND, NULL) != 0) {
        refuse_errno("linux confinement refused: the mount namespace cannot be created", errno);
    }
}

static void close_high_fds(void) {
    int fd;
    for (fd = 3; fd < 256; fd++) {
        close(fd);
    }
}

static void drop_bounding_set(void) {
    int cap;
    int last = -1;
    for (cap = 0; cap < 64; cap++) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0) {
            if (errno == EINVAL) {
                break;
            }
            refuse_errno("linux confinement refused: the capability bounding set cannot be dropped", errno);
        }
        last = cap;
    }
    if (last < 0) {
        refuse("linux confinement refused: the capability bounding set cannot be dropped");
    }
    for (cap = 0; cap <= last; cap++) {
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) != 0) {
            refuse("linux confinement refused: the capability bounding set cannot be dropped");
        }
    }
}

static __u64 handled_fs(void) {
    return LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
           LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
           LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
           LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
           LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE |
           LANDLOCK_ACCESS_FS_IOCTL_DEV;
}

static void confine_and_exec(struct policy *pol, long host_pid) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    char map[64];
    int n;
    int fd;
    int abi;
    const char *land;
    const char *netns;
    struct landlock_ruleset_attr attr;
    int ruleset;
    __u64 storage_rights;
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    struct __user_cap_data_struct got[2];
    int nnp;
    char enforced[256];
    char pidbuf[32];
    char *av[9];

    if (unshare(CLONE_NEWUSER) != 0) {
        refuse_errno("linux confinement refused: user namespaces are turned off", errno);
    }
    fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd < 0 || write(fd, "deny", 4) != 4) {
        refuse_errno("linux confinement refused: user namespaces are turned off", errno);
    }
    close(fd);
    n = snprintf(map, sizeof map, "0 %u 1\n", uid);
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0 || write(fd, map, (size_t)n) != n) {
        refuse_errno("linux confinement refused: user namespaces are turned off", errno);
    }
    close(fd);
    n = snprintf(map, sizeof map, "0 %u 1\n", gid);
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd < 0 || write(fd, map, (size_t)n) != n) {
        refuse_errno("linux confinement refused: user namespaces are turned off", errno);
    }
    close(fd);
    if (geteuid() != 0) {
        refuse("linux confinement refused: the user namespace did not map uid 0");
    }
    if (unshare(CLONE_NEWNS) != 0) {
        refuse_errno("linux confinement refused: the mount namespace cannot be created", errno);
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        refuse_errno("linux confinement refused: the mount namespace cannot be created", errno);
    }
    if (pol->read_parent) {
        hide_parent_siblings(pol);
    }
    if (unshare(CLONE_NEWNET) != 0) {
        refuse_errno("linux confinement refused: the network namespace cannot be created", errno);
    }
    if (unshare(CLONE_NEWIPC) != 0) {
        refuse_errno("linux confinement refused: the IPC namespace cannot be created", errno);
    }
    if (unshare(CLONE_NEWPID) != 0) {
        refuse_errno("linux confinement refused: the PID namespace cannot be created", errno);
    }
    {
        pid_t grand = fork();
        int st = 0;
        if (grand < 0) {
            refuse_errno("linux confinement refused: the PID namespace cannot be created", errno);
        }
        if (grand > 0) {
            if (waitpid(grand, &st, 0) < 0) {
                _exit(2);
            }
            _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 2);
        }
    }

    abi = landlock_abi();
    land = abi_refusal(abi < 0 ? -1 : abi);
    if (land) {
        refuse(land);
    }
    netns = netns_kind();
    memset(&attr, 0, sizeof attr);
    attr.handled_access_fs = handled_fs();
    attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
    ruleset = (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
    if (ruleset < 0) {
        refuse_errno("linux confinement refused: the kernel has no Landlock", errno);
    }
    storage_rights = LC_STORAGE_RIGHTS;
    add_rule(ruleset, pol->storage_root, storage_rights,
             "linux confinement refused: the launch cannot open the storage root");
    add_rule(ruleset, pol->execute, LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
             "linux confinement refused: the launch cannot open PROVIDER_EXECUTABLE");
    if (pol->read_parent) {
        add_rule(ruleset, pol->parent, LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_READ_FILE,
                 "linux confinement refused: the launch cannot open STORAGE_PARENT");
    }
    for (int extra = 0; extra < pol->n_read_exec; extra++) {
        add_rule(ruleset, pol->read_exec[extra], LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
                 "linux confinement refused: the launch cannot open a library");
    }
    for (int extra = 0; extra < pol->n_read_only; extra++) {
        add_rule(ruleset, pol->read_only[extra], LANDLOCK_ACCESS_FS_READ_FILE,
                 "linux confinement refused: the launch cannot open a loader file");
    }

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) {
        refuse_errno("linux confinement refused: the capability set cannot be dropped", errno);
    }
    /* F-LC-CAPBND */
    drop_bounding_set();
    memset(&hdr, 0, sizeof hdr);
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    memset(data, 0, sizeof data);
    if (syscall(SYS_capset, &hdr, data) != 0) {
        refuse_errno("linux confinement refused: the capability set cannot be dropped", errno);
    }
    memset(got, 0, sizeof got);
    if (syscall(SYS_capget, &hdr, got) != 0) {
        refuse_errno("linux confinement refused: the capability set cannot be dropped", errno);
    }
    if ((got[0].effective | got[0].permitted | got[0].inheritable | got[1].effective | got[1].permitted |
         got[1].inheritable) != 0) {
        refuse("linux confinement refused: the capability set cannot be dropped");
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        refuse_errno("linux confinement refused: no_new_privs cannot be set", errno);
    }
    nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if (nnp != 1) {
        refuse("linux confinement refused: no_new_privs cannot be set");
    }
    if (syscall(SYS_landlock_restrict_self, ruleset, 0) != 0) {
        refuse_errno("linux confinement refused: the Landlock ruleset cannot be enforced", errno);
    }
    close(ruleset);
    snprintf(enforced, sizeof enforced,
             "enforced abi=%d uid=%d caps=empty nnp=%d netns=%s storage_rights=0x%llx\n", abi, (int)geteuid(), nnp,
             netns, (unsigned long long)storage_rights);
    snprintf(pidbuf, sizeof pidbuf, "%ld", host_pid);
    close_high_fds();
    if (pol->provider) {
        char preload_env[4200];
        char pid_env[64];
        char copy_env[4200];
        char *envp[4];
        int envn = 0;
        av[0] = pol->helper;
        av[1] = NULL;
        if (pol->preload[0] != 0) {
            snprintf(preload_env, sizeof preload_env, "LD_PRELOAD=%s", pol->preload);
            snprintf(pid_env, sizeof pid_env, "LC_HOST_PID=%s", pidbuf);
            snprintf(copy_env, sizeof copy_env, "LC_UNBOUND=%s", pol->copy);
            envp[envn++] = preload_env;
            envp[envn++] = pid_env;
            envp[envn++] = copy_env;
        }
        envp[envn] = NULL;
        install_provider_filter(pol->deny_network);
        emit_fd(2, enforced);
        syscall(SYS_execve, pol->helper, av, envp);
        {
            char buf[200];
            int err = errno;
            snprintf(buf, sizeof buf,
                     "linux confinement refused: exec of PROVIDER_EXECUTABLE failed errno=%d\n", err);
            emit_fd(2, buf);
        }
        syscall(SYS_exit_group, 2);
    }
    av[0] = pol->helper;
    av[1] = "check";
    av[2] = pol->storage;
    av[3] = pol->outside;
    av[4] = pol->parent;
    av[5] = pol->copy;
    av[6] = pol->storage2;
    av[7] = pidbuf;
    av[8] = NULL;
    install_allow_list(pol->deny_network);
    emit(enforced);
    {
        char *empty_env[] = {NULL};
        syscall(SYS_execve, pol->helper, av, empty_env);
    }
    {
        char buf[160];
        int err = errno;
        snprintf(buf, sizeof buf, "linux confinement refused: exec of PROVIDER_EXECUTABLE failed errno=%d\n", err);
        emit(buf);
    }
    syscall(SYS_exit_group, 2);
}

int main(int argc, char **argv) {
#ifdef LC_TEST_HOOKS
    const char *explain = NULL;
    int block_landlock = 0;
    int block_seccomp = 0;
    int block_userns = 0;
#endif
    const char *policy_path = NULL;
    int i;
    const char *sec;
    int abi;
    const char *land;
    struct policy pol;
    long host_pid;
    pid_t child;
    int st = 0;

    for (i = 1; i < argc; i++) {
#ifdef LC_TEST_HOOKS
        if (strcmp(argv[i], "--explain-abi") == 0 && i + 1 < argc) {
            explain = argv[++i];
            continue;
        } else if (strcmp(argv[i], "--block-landlock") == 0) {
            block_landlock = 1;
            continue;
        } else if (strcmp(argv[i], "--block-seccomp") == 0) {
            block_seccomp = 1;
            continue;
        } else if (strcmp(argv[i], "--block-userns") == 0) {
            block_userns = 1;
            continue;
        }
#endif
        if (argv[i][0] != '-') {
            policy_path = argv[i];
        } else {
            refuse("linux confinement refused: unknown launch argument");
        }
    }
#ifdef LC_TEST_HOOKS
    if (explain) {
        const char *msg = abi_refusal(atoi(explain));
        if (msg) {
            emit(msg);
            emit("\n");
            return 2;
        }
        emit("abi-ok\n");
        return 0;
    }
    if (block_landlock) {
        install_block_landlock();
    }
    if (block_seccomp) {
        install_block_seccomp_probe();
    }
    if (block_userns) {
        install_block_unshare();
    }
#endif
    sec = seccomp_refusal();
    if (sec) {
        emit(sec);
        emit("\n");
        return 2;
    }
    abi = landlock_abi();
    land = abi_refusal(abi < 0 ? -1 : abi);
    if (land) {
        emit(land);
        emit("\n");
        return 2;
    }
    if (!policy_path) {
        refuse("linux confinement refused: the launch has no policy");
    }
    load_policy(policy_path, &pol);
    host_pid = (long)getpid();
    child = fork();
    if (child < 0) {
        refuse_errno("linux confinement refused: the PID namespace cannot be created", errno);
    }
    if (child == 0) {
        confine_and_exec(&pol, host_pid);
        _exit(2);
    }
    if (waitpid(child, &st, 0) < 0) {
        return 2;
    }
    if (WIFEXITED(st)) {
        return WEXITSTATUS(st);
    }
    return 2;
}
