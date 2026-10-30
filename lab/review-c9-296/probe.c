/* Freestanding escape probe for the #296 Linux launcher.
 *
 * Same syscall style as lab/linux-confine/helper/probe.c. The short filter
 * only allows a few numbers, so this file uses raw syscalls and no libc.
 *
 * argv[1] == "check": probe-filter launch (paths on the command line).
 * otherwise: read CFG_PATH (provider-filter launch or an unconfined control).
 */
#include <sys/syscall.h>

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_DIRECTORY 0200000

#define AF_UNIX 1
#define AF_INET 2
#define SOCK_STREAM 1

#define SIGCHLD 17
#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWNS 0x00020000
#define CLONE_NEWNET 0x40000000
#define MS_NOSUID 2
#define MS_NODEV 4

#define PTRACE_TRACEME 0
#define KEYCTL_GET_KEYRING_ID 0
#define KEY_SPEC_USER_KEYRING -4
#define X32_BIT 0x40000000

#ifndef CFG_PATH
#define CFG_PATH "/tmp/lc-review-c9-296/cfg"
#endif

#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
#ifndef SYS_userfaultfd
#define SYS_userfaultfd 323
#endif
#ifndef SYS_open_by_handle_at
#define SYS_open_by_handle_at 304
#endif
#ifndef SYS_process_vm_readv
#define SYS_process_vm_readv 310
#endif

static long sc(long n, long a, long b, long c, long d, long e, long f) {
#if defined(__x86_64__)
    long ret;
    register long r10 asm("r10") = d;
    register long r8 asm("r8") = e;
    register long r9 asm("r9") = f;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                 : "rcx", "r11", "memory");
    return ret;
#else
#error review probes run on x86_64; aarch64 stays NOT RUN
#endif
}

static void wr(const char *s) {
    long n = 0;
    while (s[n]) {
        n++;
    }
    sc(SYS_write, 1, (long)s, n, 0, 0, 0);
}

static void wr_num(long v) {
    char buf[32];
    int i = 31;
    unsigned long u;
    int neg = v < 0;
    buf[i] = 0;
    u = neg ? (unsigned long)(-v) : (unsigned long)v;
    if (u == 0) {
        buf[--i] = '0';
    }
    while (u) {
        buf[--i] = (char)('0' + (u % 10));
        u /= 10;
    }
    if (neg) {
        buf[--i] = '-';
    }
    wr(buf + i);
}

static int streq(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static void copy_str(char *dst, long cap, const char *src) {
    long n = 0;
    if (cap <= 0) {
        return;
    }
    while (src[n] && n + 1 < cap) {
        dst[n] = src[n];
        n++;
    }
    dst[n] = 0;
}

static long parse_pid(const char *s) {
    long v = 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return v;
}

static void line(const char *op, const char *result, long err, const char *reason) {
    wr("op=");
    wr(op);
    wr(" result=");
    wr(result);
    if (err) {
        wr(" errno=");
        wr_num(err < 0 ? -err : err);
    }
    wr(" reason=");
    wr(reason);
    wr("\n");
}

static void rec(const char *op, long rc, const char *ok_why, const char *deny_why) {
    if (rc >= 0) {
        line(op, "ok", 0, ok_why);
    } else {
        line(op, "refused", rc, deny_why);
    }
}

static void rec_close(const char *op, long rc, const char *ok_why, const char *deny_why) {
    if (rc >= 0) {
        sc(SYS_close, rc, 0, 0, 0, 0, 0);
        line(op, "ok", 0, ok_why);
    } else {
        line(op, "refused", rc, deny_why);
    }
}

struct paths {
    char storage[4096];
    char outside[4096];
    char parent[4096];
    char copy[4096];
    long host_pid;
};

static int load_cfg(struct paths *p) {
    char buf[8192];
    long fd = sc(SYS_openat, AT_FDCWD, (long)CFG_PATH, O_RDONLY, 0, 0, 0);
    long n;
    char *cur;
    if (fd < 0) {
        return -1;
    }
    n = sc(SYS_read, fd, (long)buf, (long)sizeof buf - 1, 0, 0, 0);
    sc(SYS_close, fd, 0, 0, 0, 0, 0);
    if (n <= 0) {
        return -1;
    }
    buf[n] = 0;
    cur = buf;
    p->host_pid = 1;
    p->storage[0] = 0;
    p->outside[0] = 0;
    p->parent[0] = 0;
    p->copy[0] = 0;
    while (*cur) {
        char *nl = cur;
        char *eq;
        while (*nl && *nl != '\n') {
            nl++;
        }
        if (*nl) {
            *nl = 0;
        }
        eq = cur;
        while (*eq && *eq != '=') {
            eq++;
        }
        if (*eq == '=') {
            *eq = 0;
            if (streq(cur, "storage")) {
                copy_str(p->storage, sizeof p->storage, eq + 1);
            } else if (streq(cur, "outside")) {
                copy_str(p->outside, sizeof p->outside, eq + 1);
            } else if (streq(cur, "parent")) {
                copy_str(p->parent, sizeof p->parent, eq + 1);
            } else if (streq(cur, "copy")) {
                copy_str(p->copy, sizeof p->copy, eq + 1);
            } else if (streq(cur, "host_pid")) {
                p->host_pid = parse_pid(eq + 1);
            }
        }
        if (*nl == 0 && nl[1] == 0) {
            break;
        }
        cur = nl + 1;
    }
    return p->storage[0] && p->outside[0] ? 0 : -1;
}

static void join(char *dst, long cap, const char *a, const char *b) {
    long n = 0;
    while (a[n] && n + 1 < cap) {
        dst[n] = a[n];
        n++;
    }
    if (n + 1 < cap) {
        dst[n++] = '/';
    }
    while (*b && n + 1 < cap) {
        dst[n++] = *b++;
    }
    dst[n] = 0;
}

static void run_ops(struct paths *p) {
    char path[4200];
    char *empty[] = {0};
    long rc;

    rec_close("socket-inet", sc(SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0),
              "socket(AF_INET) succeeded", "seccomp or kernel refused socket");
    rec_close("socket-unix", sc(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0),
              "socket(AF_UNIX) succeeded", "seccomp or kernel refused AF_UNIX socket");
    {
        int pair[2];
        rc = sc(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long)pair, 0, 0);
        if (rc >= 0) {
            sc(SYS_close, pair[0], 0, 0, 0, 0, 0);
            sc(SYS_close, pair[1], 0, 0, 0, 0, 0);
            line("socketpair", "ok", 0, "socketpair(AF_UNIX) succeeded");
        } else {
            line("socketpair", "refused", rc, "seccomp or kernel refused socketpair");
        }
    }
    rec_close("abstract-unix", sc(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0),
              "abstract unix socket() succeeded (bind not reached)",
              "seccomp refused the AF_UNIX socket used for an abstract name");

    rec("ptrace", sc(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0, 0, 0),
        "ptrace(PTRACE_TRACEME) succeeded", "seccomp or yama refused ptrace");
    rec_close("proc-self-mem",
              sc(SYS_openat, AT_FDCWD, (long)"/proc/self/mem", O_RDWR, 0, 0, 0),
              "opened /proc/self/mem for write", "open of /proc/self/mem failed");
    rec("unshare-user", sc(SYS_unshare, CLONE_NEWUSER, 0, 0, 0, 0, 0),
        "unshare(CLONE_NEWUSER) succeeded", "seccomp or kernel refused unshare");
    rec("unshare-net", sc(SYS_unshare, CLONE_NEWNET, 0, 0, 0, 0, 0),
        "unshare(CLONE_NEWNET) succeeded", "seccomp or kernel refused unshare");
    rec("setns", sc(SYS_setns, -1, 0, 0, 0, 0, 0),
        "setns succeeded", "seccomp or kernel refused setns");
    rec("keyctl",
        sc(SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_USER_KEYRING, 0, 0, 0, 0),
        "keyctl read a keyring id", "seccomp or kernel refused keyctl");
    rec("bpf", sc(SYS_bpf, 0, 0, 0, 0, 0, 0),
        "bpf succeeded", "seccomp or kernel refused bpf");
    rec("io-uring", sc(SYS_io_uring_setup, 2, 0, 0, 0, 0, 0),
        "io_uring_setup succeeded", "seccomp or kernel refused io_uring_setup");
    rec("perf-event-open", sc(SYS_perf_event_open, 0, 0, -1, -1, 0, 0),
        "perf_event_open succeeded", "seccomp or kernel refused perf_event_open");
    rec("userfaultfd", sc(SYS_userfaultfd, 0, 0, 0, 0, 0, 0),
        "userfaultfd succeeded", "seccomp or kernel refused userfaultfd");
    rec("pidfd-open", sc(SYS_pidfd_open, 1, 0, 0, 0, 0, 0),
        "pidfd_open succeeded", "seccomp or kernel refused pidfd_open");
    rec("process-vm-readv", sc(SYS_process_vm_readv, 1, 0, 0, 0, 0, 0),
        "process_vm_readv succeeded", "seccomp or kernel refused process_vm_readv");
    rec("open-by-handle-at", sc(SYS_open_by_handle_at, -1, 0, 0, 0, 0, 0),
        "open_by_handle_at succeeded", "seccomp or kernel refused open_by_handle_at");
    rec("mount",
        sc(SYS_mount, (long)"tmpfs", (long)"/tmp", (long)"tmpfs", MS_NOSUID | MS_NODEV, 0, 0),
        "mount(tmpfs) succeeded", "seccomp or kernel refused mount");

    rec_close("dev-null", sc(SYS_openat, AT_FDCWD, (long)"/dev/null", O_RDWR, 0, 0, 0),
              "opened /dev/null read-write", "open of /dev/null failed");
    rec_close("dev-zero", sc(SYS_openat, AT_FDCWD, (long)"/dev/zero", O_RDWR, 0, 0, 0),
              "opened /dev/zero read-write", "open of /dev/zero failed");
    rec_close("dev-kcore", sc(SYS_openat, AT_FDCWD, (long)"/proc/kcore", O_RDONLY, 0, 0, 0),
              "opened /proc/kcore", "open of /proc/kcore failed");
    rec_close("sys-kernel", sc(SYS_openat, AT_FDCWD, (long)"/sys/kernel", O_RDONLY | O_DIRECTORY, 0, 0, 0),
              "opened /sys/kernel", "open of /sys/kernel failed");

    rec("signal-host", sc(SYS_kill, p->host_pid, 0, 0, 0, 0, 0),
        "kill(host_pid, 0) succeeded", "pid namespace or kernel refused the host pid");

    join(path, sizeof path, p->storage, "escape-link");
    rec("make-sym", sc(SYS_symlinkat, (long)p->outside, AT_FDCWD, (long)path, 0, 0, 0),
        "symlink inside STORAGE_ROOT succeeded", "Landlock or kernel refused MAKE_SYM");
    join(path, sizeof path, p->storage, "escape-fifo");
    rec("make-fifo", sc(SYS_mknodat, AT_FDCWD, (long)path, 010644, 0, 0, 0),
        "mknod fifo inside STORAGE_ROOT succeeded", "Landlock or kernel refused MAKE_FIFO");
    join(path, sizeof path, p->storage, "escape-sock");
    rec("make-sock", sc(SYS_mknodat, AT_FDCWD, (long)path, 0140644, 0, 0, 0),
        "mknod socket inside STORAGE_ROOT succeeded", "Landlock or kernel refused MAKE_SOCK");
    join(path, sizeof path, p->storage, "escape-char");
    rec("make-char", sc(SYS_mknodat, AT_FDCWD, (long)path, 0020644, 1, 0, 0),
        "mknod char inside STORAGE_ROOT succeeded", "Landlock or kernel refused MAKE_CHAR");

    rec_close("dotdot",
              sc(SYS_openat, AT_FDCWD, (long)p->outside, O_RDONLY, 0, 0, 0),
              "read the planted outside file", "Landlock or kernel refused the outside read");
    join(path, sizeof path, p->storage, "../secret-outside");
    rec_close("dotdot-walk",
              sc(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0),
              "opened STORAGE_ROOT/../outside through ..",
              "Landlock or kernel refused the .. walk");

    join(path, sizeof path, p->storage, "inside");
    {
        char dest[4200];
        long fd = sc(SYS_openat, AT_FDCWD, (long)path, O_WRONLY | O_CREAT | O_TRUNC, 0644, 0, 0);
        if (fd >= 0) {
            sc(SYS_write, fd, (long)"in", 2, 0, 0, 0);
            sc(SYS_close, fd, 0, 0, 0, 0, 0);
            line("storage-write", "ok", 0, "wrote under STORAGE_ROOT");
            join(dest, sizeof dest, p->parent, "reparented");
            rec("refer",
                sc(SYS_linkat, AT_FDCWD, (long)path, AT_FDCWD, (long)dest, 0, 0),
                "link across directories succeeded",
                "Landlock or kernel refused REFER");
        } else {
            line("storage-write", "refused", fd, "write under STORAGE_ROOT failed");
            line("refer", "refused", fd, "no inside file to reparent");
        }
    }

    rc = sc(SYS_socket | X32_BIT, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
    rec_close("x32-socket", rc, "x32 socket succeeded", "x32 socket was refused");
    rc = sc(999, 0, 0, 0, 0, 0, 0);
    rec("unknown-syscall", rc, "unknown syscall number succeeded",
        "default seccomp action refused an unlisted number");

    rc = sc(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (rc == 0) {
        sc(SYS_exit_group, 0, 0, 0, 0, 0, 0);
    } else if (rc > 0) {
        line("clone-process", "ok", 0, "clone(SIGCHLD) created a child");
    } else {
        line("clone-process", "refused", rc, "seccomp or kernel refused clone");
    }

    if (p->copy[0]) {
        char *av[] = {p->copy, 0};
        rc = sc(SYS_execve, (long)p->copy, (long)av, (long)empty, 0, 0, 0);
        rec("exec-unbound", rc, "exec of the copy returned",
            "Landlock or kernel refused exec of a file other than the helper");
    }
}

__attribute__((noreturn, noinline, used)) void finish(int code) {
    sc(SYS_exit_group, code, 0, 0, 0, 0, 0);
    for (;;) {
    }
}

int main(int argc, char **argv) {
    struct paths p;
    if (argc >= 8 && streq(argv[1], "check")) {
        copy_str(p.storage, sizeof p.storage, argv[2]);
        copy_str(p.outside, sizeof p.outside, argv[3]);
        copy_str(p.parent, sizeof p.parent, argv[4]);
        copy_str(p.copy, sizeof p.copy, argv[5]);
        p.host_pid = parse_pid(argv[7]);
        run_ops(&p);
        finish(0);
    }
    if (load_cfg(&p) != 0) {
        wr("bad cfg\n");
        finish(2);
    }
    run_ops(&p);
    finish(0);
}

#if defined(__x86_64__)
__asm__(".global _start\n"
        "_start:\n"
        "  xor %rbp, %rbp\n"
        "  mov (%rsp), %rdi\n"
        "  lea 8(%rsp), %rsi\n"
        "  call main\n"
        "  mov %rax, %rdi\n"
        "  call finish\n");
#endif
