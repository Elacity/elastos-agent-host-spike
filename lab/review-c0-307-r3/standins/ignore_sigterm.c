/* Confined stand-in: ignore SIGTERM and stay alive until SIGKILL. */
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    printf("standin=ignore_sigterm pid=%d\n", getpid());
    fflush(stdout);
    for (;;) {
        pause();
    }
}
