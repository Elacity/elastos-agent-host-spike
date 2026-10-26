/* Guest Landlock ABI probe. Static. Label-neutral. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

int main(void) {
    long abi = syscall(SYS_landlock_create_ruleset, (void *)0, 0,
                       LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        printf("landlock_abi=unavailable errno=%d\n", errno);
        return 1;
    }
    printf("landlock_abi=%ld\n", abi);
    return 0;
}
