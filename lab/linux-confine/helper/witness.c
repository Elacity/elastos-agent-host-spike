/* Attempts the operations the provider protocol does not contain.
 * The constructor runs inside the real provider process, after the
 * launcher has installed Landlock and seccomp and before the provider's
 * own main. It records the errno and returns.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static void line(const char *op, const char *result, int err, const char *reason) {
    if (err) {
        fprintf(stderr, "witness op=%s result=%s errno=%d reason=%s\n", op, result, err, reason);
    } else {
        fprintf(stderr, "witness op=%s result=%s reason=%s\n", op, result, reason);
    }
}

__attribute__((constructor)) static void lc_witness(void) {
    const char *pid_text = getenv("LC_HOST_PID");
    const char *copy = getenv("LC_UNBOUND");
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        line("socket", "refused", errno, "seccomp refused socket");
    } else {
        close(fd);
        line("socket", "ok", 0, "socket succeeded");
    }
    if (pid_text != NULL && pid_text[0] != 0) {
        if (kill((pid_t)atoi(pid_text), 0) < 0) {
            line("signal-host", "refused", errno, "the pid namespace has no such host process");
        } else {
            line("signal-host", "ok", 0, "signal succeeded");
        }
    }
    if (copy != NULL && copy[0] != 0) {
        char *argv[] = {(char *)copy, NULL};
        char *envp[] = {NULL};
        execve(copy, argv, envp);
        line("exec-unbound", "refused", errno,
             "landlock refused exec of a file other than PROVIDER_EXECUTABLE");
    }
}
