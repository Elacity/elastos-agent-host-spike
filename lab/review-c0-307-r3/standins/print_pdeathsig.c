#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_GET_PDEATHSIG
#define PR_GET_PDEATHSIG 2
#endif

int main(void) {
    int sig = 0;
    if (prctl(PR_GET_PDEATHSIG, &sig) != 0) {
        perror("PR_GET_PDEATHSIG");
        return 1;
    }
    printf("pdeathsig=%d pid=%d\n", sig, getpid());
    fflush(stdout);
    return 0;
}
