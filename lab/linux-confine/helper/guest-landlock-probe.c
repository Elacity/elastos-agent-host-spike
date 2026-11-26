/* Landlock ABI probe for the qemu-system aarch64 guest.
 *
 * Label: aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU).
 * This is never native aarch64 and never Jetson.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <linux/landlock.h>

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

int main(void) {
    long ret;
    int err;
    struct utsname uts;

    printf("mode=aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)\n");
    printf("native=0\n");
    printf("jetson=0\n");
    printf("emulated_cpu=1\n");
    printf("qemu_accel=tcg\n");

    if (uname(&uts) == 0) {
        printf("uname.sysname=%s\n", uts.sysname);
        printf("uname.nodename=%s\n", uts.nodename);
        printf("uname.release=%s\n", uts.release);
        printf("uname.version=%s\n", uts.version);
        printf("uname.machine=%s\n", uts.machine);
    }

    errno = 0;
    ret = syscall(SYS_landlock_create_ruleset, NULL, (size_t)0, LANDLOCK_CREATE_RULESET_VERSION);
    err = errno;
    printf("landlock_create_ruleset nr=%ld ret=%ld errno=%d (%s)\n",
           (long)SYS_landlock_create_ruleset, ret, err, err ? strerror(err) : "ok");
    if (ret >= 0) {
        printf("landlock_abi=%ld\n", ret);
        printf("ioctl_dev_ready=%s\n", ret >= 5 ? "yes" : "no");
    }

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
