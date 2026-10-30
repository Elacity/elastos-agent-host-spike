/* One i386 syscall. The #296 filter kills a non-native audit architecture.
 * Run last, in its own launch. aarch64 stays NOT RUN.
 */
#include <sys/syscall.h>

static long sc(long n, long a, long b, long c, long d, long e, long f) {
    long ret;
    register long r10 asm("r10") = d;
    register long r8 asm("r8") = e;
    register long r9 asm("r9") = f;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                 : "rcx", "r11", "memory");
    return ret;
}

static void wr(const char *s) {
    long n = 0;
    while (s[n]) {
        n++;
    }
    sc(SYS_write, 1, (long)s, n, 0, 0, 0);
}

static int streq(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

__attribute__((noreturn, noinline, used)) static void finish(int code) {
    sc(SYS_exit_group, code, 0, 0, 0, 0, 0);
    for (;;) {
    }
}

int main(int argc, char **argv) {
    int ret;
    (void)argc;
    (void)argv;
    /* i386 write(1, "i386-ran\n", 9). The filter must kill this process
     * before the write if IA32 emulation is on. */
    asm volatile("int $0x80" : "=a"(ret) : "a"(4), "b"(1), "c"("i386-ran\n"), "d"(9));
    wr("op=i386-int80 result=ok reason=i386 syscall ran\n");
    if (argc >= 2 && streq(argv[1], "check")) {
        finish(0);
    }
    finish(0);
}

__asm__(".global _start\n"
        "_start:\n"
        "  xor %rbp, %rbp\n"
        "  mov (%rsp), %rdi\n"
        "  lea 8(%rsp), %rsi\n"
        "  call main\n"
        "  mov %rax, %rdi\n"
        "  call finish\n");
