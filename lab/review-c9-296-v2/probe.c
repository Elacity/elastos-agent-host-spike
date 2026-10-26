/* Extra process-creation and socketpair probes for the #296 provider filter.
 * Freestanding. Same syscall path as lab/linux-confine/helper/probe.c.
 * Does not edit that tree.
 */
#include <sys/syscall.h>

#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
#define AF_NETLINK 16
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SIGCHLD 17
#define CLONE_VM 0x00000100
#define CLONE_VFORK 0x00004000
#define CLONE_THREAD 0x00010000
#define CLONE_SIGHAND 0x00000800
#define CLONE_FILES 0x00000400
#define CLONE_FS 0x00000200

#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_fork
#define SYS_fork 57
#endif
#ifndef SYS_vfork
#define SYS_vfork 58
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
#error review probe is x86_64 only
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

static void finish(int code) {
    sc(SYS_exit_group, code, 0, 0, 0, 0, 0);
    for (;;) {
    }
}

static void report_sc(const char *op, long r, const char *denied, const char *ok) {
    if (r < 0) {
        line(op, "refused", r, denied);
    } else if (r == 0) {
        /* Child of fork/vfork. Do not continue the probe. */
        sc(SYS_exit_group, 0, 0, 0, 0, 0, 0);
    } else {
        line(op, "ok", 0, ok);
    }
}

static char thread_stack[8192];

static void report_clone(const char *op, long flags) {
    long stack = 0;
    if (flags & CLONE_THREAD) {
        stack = (long)(thread_stack + 8192);
    }
    long r = sc(SYS_clone, flags, stack, 0, 0, 0, 0);
    if (r < 0) {
        line(op, "refused", r, "clone refused");
    } else if (r == 0) {
        if (flags & CLONE_THREAD) {
            sc(SYS_exit, 0, 0, 0, 0, 0, 0);
        }
        sc(SYS_exit_group, 0, 0, 0, 0, 0, 0);
    } else {
        line(op, "ok", 0, "clone created a child");
    }
}

struct clone_args {
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

static void report_clone3(const char *op, unsigned long long flags, unsigned long long exit_signal) {
    struct clone_args args;
    long i;
    char *p = (char *)&args;
    for (i = 0; i < (long)sizeof args; i++) {
        p[i] = 0;
    }
    args.flags = flags;
    args.exit_signal = exit_signal;
    long r = sc(SYS_clone3, (long)&args, (long)sizeof args, 0, 0, 0, 0);
    if (r < 0) {
        line(op, "refused", r, "clone3 refused");
    } else if (r == 0) {
        sc(SYS_exit_group, 0, 0, 0, 0, 0, 0);
    } else {
        line(op, "ok", 0, "clone3 created a child");
    }
}

int main(int argc, char **argv) {
    int pair[2];
    long sp;
    long n;
    char buf[8];
    (void)argc;
    (void)argv;

    report_clone("clone-sigchld", SIGCHLD);
    report_clone("clone-vm-sigchld", CLONE_VM | SIGCHLD);
    report_clone("clone-vfork", CLONE_VFORK | CLONE_VM | SIGCHLD);
    report_clone("clone-thread", CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | CLONE_FILES | CLONE_FS);
    report_sc("fork", sc(SYS_fork, 0, 0, 0, 0, 0, 0), "fork refused", "fork created a child");
    report_sc("vfork", sc(SYS_vfork, 0, 0, 0, 0, 0, 0), "vfork refused", "vfork created a child");
    report_clone3("clone3-sigchld", 0, SIGCHLD);
    report_clone3("clone3-thread", CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | CLONE_FILES | CLONE_FS, 0);

    sp = sc(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long)pair, 0, 0);
    if (sp < 0) {
        line("socketpair-unix", "refused", sp, "socketpair AF_UNIX refused");
    } else {
        line("socketpair-unix", "ok", 0, "socketpair AF_UNIX succeeded");
        n = sc(SYS_write, pair[0], (long)"ping", 4, 0, 0, 0);
        if (n == 4) {
            n = sc(SYS_read, pair[1], (long)buf, 4, 0, 0, 0);
            if (n == 4 && buf[0] == 'p' && buf[1] == 'i' && buf[2] == 'n' && buf[3] == 'g') {
                line("socketpair-unix-io", "ok", 0, "pair carries bytes inside the process");
            } else {
                line("socketpair-unix-io", "refused", n, "pair read failed");
            }
        } else {
            line("socketpair-unix-io", "refused", n, "pair write failed");
        }
        report_sc("socketpair-connect", sc(SYS_connect, pair[0], 0, 0, 0, 0, 0),
                  "connect on the pair refused", "connect on the pair succeeded");
        report_sc("socketpair-bind", sc(SYS_bind, pair[0], 0, 0, 0, 0, 0),
                  "bind on the pair refused", "bind on the pair succeeded");
        report_sc("socketpair-sendmsg", sc(SYS_sendmsg, pair[0], 0, 0, 0, 0, 0),
                  "sendmsg on the pair refused", "sendmsg on the pair succeeded");
        sc(SYS_close, pair[0], 0, 0, 0, 0, 0);
        sc(SYS_close, pair[1], 0, 0, 0, 0, 0);
    }

    report_sc("socketpair-inet", sc(SYS_socketpair, AF_INET, SOCK_STREAM, 0, (long)pair, 0, 0),
              "socketpair AF_INET refused", "socketpair AF_INET succeeded");
    report_sc("socketpair-inet6", sc(SYS_socketpair, AF_INET6, SOCK_STREAM, 0, (long)pair, 0, 0),
              "socketpair AF_INET6 refused", "socketpair AF_INET6 succeeded");
    report_sc("socketpair-netlink", sc(SYS_socketpair, AF_NETLINK, SOCK_DGRAM, 0, (long)pair, 0, 0),
              "socketpair AF_NETLINK refused", "socketpair AF_NETLINK succeeded");
    report_sc("socket-unix", sc(SYS_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0),
              "socket AF_UNIX refused", "socket AF_UNIX succeeded");
    report_sc("socket-inet", sc(SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0),
              "socket AF_INET refused", "socket AF_INET succeeded");

    finish(0);
    return 0;
}

#ifdef __x86_64__
__asm__(".global _start\n"
        "_start:\n"
        "  xor %rbp, %rbp\n"
        "  mov (%rsp), %rdi\n"
        "  lea 8(%rsp), %rsi\n"
        "  call main\n"
        "  mov %rax, %rdi\n"
        "  call finish\n");
#endif
