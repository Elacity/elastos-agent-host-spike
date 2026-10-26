/* Prints the three Landlock syscalls. tests/aarch64.rs runs this under
 * qemu-aarch64. qemu-user 8.2.2 returns ENOSYS (unknown syscall 444/445/446).
 * That is not an ARM kernel result and is never Jetson or native aarch64.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/landlock.h>

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

int main(void) {
    long ret;
    int err;

    printf("mode=aarch64-build-plus-qemu-user-host-kernel\n");
    printf("native=0\n");
    printf("jetson=0\n");

    errno = 0;
    ret = syscall(SYS_landlock_create_ruleset, NULL, (size_t)0, LANDLOCK_CREATE_RULESET_VERSION);
    err = errno;
    printf("landlock_create_ruleset nr=%ld ret=%ld errno=%d (%s)\n",
           (long)SYS_landlock_create_ruleset, ret, err, err ? strerror(err) : "ok");

    errno = 0;
    ret = syscall(SYS_landlock_add_rule, (long)-1, 1, NULL, 0);
    err = errno;
    printf("landlock_add_rule nr=%ld ret=%ld errno=%d (%s)\n",
           (long)SYS_landlock_add_rule, ret, err, err ? strerror(err) : "ok");

    errno = 0;
    ret = syscall(SYS_landlock_restrict_self, (long)-1, 0);
    err = errno;
    printf("landlock_restrict_self nr=%ld ret=%ld errno=%d (%s)\n",
           (long)SYS_landlock_restrict_self, ret, err, err ? strerror(err) : "ok");

    printf("SYS_landlock_create_ruleset=%ld SYS_landlock_add_rule=%ld "
           "SYS_landlock_restrict_self=%ld\n",
           (long)SYS_landlock_create_ruleset, (long)SYS_landlock_add_rule,
           (long)SYS_landlock_restrict_self);
    return 0;
}
