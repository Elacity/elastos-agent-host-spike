/* Minimal provider that writes nothing and stays alive. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("standin=sleep_forever pid=%d\n", getpid());
    fflush(stdout);
    for (;;) {
        pause();
    }
}
