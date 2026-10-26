/* Freestanding probe. Syscall numbers come from <sys/syscall.h>, so the
 * same source is correct on x86_64 and aarch64. The open flags below are
 * Linux UAPI values shared by both architectures; they are not syscall
 * numbers.
 */
#include <sys/syscall.h>

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_DIRECTORY 0200000

#define AF_UNIX 1
#define AF_INET 2
#define SOCK_STREAM 1

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
#elif defined(__aarch64__)
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a;
    register long x1 asm("x1") = b;
    register long x2 asm("x2") = c;
    register long x3 asm("x3") = d;
    register long x4 asm("x4") = e;
    register long x5 asm("x5") = f;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                 : "memory");
    return x0;
#else
#error linux-confine supports x86_64 and aarch64
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

static int same(const char *buf, long n, const char *want) {
    long i = 0;
    if (n < 0) {
        return 0;
    }
    while (want[i]) {
        if (i >= n || buf[i] != want[i]) {
            return 0;
        }
        i++;
    }
    return i == n;
}

static void write_file(const char *op, const char *path, const char *bytes, long len) {
    long fd = sc(SYS_openat, AT_FDCWD, (long)path, O_WRONLY | O_CREAT | O_TRUNC, 0644, 0, 0);
    if (fd < 0) {
        line(op, "refused", fd, "open for write under STORAGE_ROOT failed");
        return;
    }
    long w = sc(SYS_write, fd, (long)bytes, len, 0, 0, 0);
    sc(SYS_close, fd, 0, 0, 0, 0, 0);
    if (w == len) {
        line(op, "ok", 0, "wrote under STORAGE_ROOT");
    } else {
        line(op, "refused", w, "write under STORAGE_ROOT failed");
    }
}

static void read_file(const char *op, const char *path, const char *bytes, long len) {
    char buf[16];
    long fd = sc(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
    if (fd < 0) {
        line(op, "refused", fd, "open for read under STORAGE_ROOT failed");
        return;
    }
    long r = sc(SYS_read, fd, (long)buf, len, 0, 0, 0);
    sc(SYS_close, fd, 0, 0, 0, 0, 0);
    if (same(buf, r, bytes)) {
        line(op, "ok", 0, "read under STORAGE_ROOT");
    } else {
        line(op, "refused", r < 0 ? r : 0, "read under STORAGE_ROOT returned the wrong bytes");
    }
}

static void open_expect_denied(const char *op, const char *path, long flags, const char *reason) {
    long fd = sc(SYS_openat, AT_FDCWD, (long)path, flags, 0644, 0, 0);
    if (fd < 0) {
        line(op, "refused", fd, reason);
    } else {
        sc(SYS_close, fd, 0, 0, 0, 0, 0);
        line(op, "ok", 0, "open succeeded");
    }
}

__attribute__((noreturn, noinline, used)) void finish(int code) {
    sc(SYS_exit_group, code, 0, 0, 0, 0, 0);
    for (;;) {
    }
}

int main(int argc, char **argv) {
    char *empty_env[] = {0};
    if (argc >= 2 && streq(argv[1], "bound-child")) {
        line("exec-bound", "ok", 0, "process-exec of PROVIDER_EXECUTABLE");
        finish(0);
    }
    if (argc < 8 || !streq(argv[1], "check")) {
        wr("bad args\n");
        finish(2);
    }
    const char *storage = argv[2];
    const char *outside = argv[3];
    const char *parent = argv[4];
    const char *copy = argv[5];
    const char *storage2 = argv[6];
    long host_pid = parse_pid(argv[7]);

    line("in-memory", "ok", 0, "no file and no socket");
    write_file("storage-write", storage, "stored", 6);
    read_file("storage-read", storage, "stored", 6);
    if (!streq(storage2, "-")) {
        write_file("storage2-write", storage2, "persona", 7);
        read_file("storage2-read", storage2, "persona", 7);
    }
    open_expect_denied("outside-read", outside, O_RDONLY,
                       "landlock refused the read outside STORAGE_ROOT");
    open_expect_denied("outside-write", outside, O_WRONLY | O_CREAT | O_TRUNC,
                       "landlock refused the write outside STORAGE_ROOT");
    open_expect_denied("parent-read", parent, O_RDONLY | O_DIRECTORY,
                       "the Landlock ABI cannot express the STORAGE_PARENT read, so the read is refused");
    open_expect_denied("root-read", "/", O_RDONLY | O_DIRECTORY,
                       "no Landlock rule for the root directory read");
    open_expect_denied("kernel-fact", "/proc/kallsyms", O_RDONLY,
                       "landlock refused the read of kernel state");

    char uname_buf[390];
    long un = sc(SYS_uname, (long)uname_buf, 0, 0, 0, 0, 0);
    if (un < 0) {
        line("sysctl", "refused", un, "uname failed");
    } else {
        line("sysctl", "ok", 0, "read kernel identity");
    }

    long sock = sc(SYS_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
    if (sock < 0) {
        line("socket", "refused", sock, "seccomp refused socket");
    } else {
        sc(SYS_close, sock, 0, 0, 0, 0, 0);
        line("socket", "ok", 0, "socket succeeded");
    }
    int pair[2];
    long sp = sc(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long)pair, 0, 0);
    if (sp < 0) {
        line("socketpair", "refused", sp, "seccomp refused socketpair");
    } else {
        sc(SYS_close, pair[0], 0, 0, 0, 0, 0);
        sc(SYS_close, pair[1], 0, 0, 0, 0, 0);
        line("socketpair", "ok", 0, "socketpair succeeded");
    }

    long sig = sc(SYS_kill, host_pid, 0, 0, 0, 0, 0);
    if (sig < 0) {
        line("signal-host", "refused", sig, "the pid namespace has no such host process");
    } else {
        line("signal-host", "ok", 0, "signal succeeded");
    }

    long cl = sc(SYS_clone, 17, 0, 0, 0, 0, 0);
    if (cl < 0) {
        line("clone", "refused", cl, "seccomp refused clone");
    } else {
        line("clone", "ok", 0, "clone succeeded");
    }

    char *copy_argv[] = {(char *)copy, "bound-child", 0};
    long ex = sc(SYS_execve, (long)copy, (long)copy_argv, (long)empty_env, 0, 0, 0);
    if (ex < 0) {
        line("exec-unbound", "refused", ex,
             "landlock refused exec of a file other than PROVIDER_EXECUTABLE");
    } else {
        line("exec-unbound", "ok", 0, "unbound exec returned");
    }

    char *bound_argv[] = {argv[0], "bound-child", 0};
    ex = sc(SYS_execve, (long)argv[0], (long)bound_argv, (long)empty_env, 0, 0, 0);
    line("exec-bound", "refused", ex, "exec of PROVIDER_EXECUTABLE failed");
    finish(1);
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
#elif defined(__aarch64__)
__asm__(".global _start\n"
        "_start:\n"
        "  ldr x0, [sp]\n"
        "  add x1, sp, #8\n"
        "  bl main\n"
        "  bl finish\n");
#endif
