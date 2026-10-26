# Linux confinement in this lab (C9)

This file is the lab map for `lab/linux-confine/`. It does not change
`capsules/wallet-provider/CONFINEMENT-LINUX.md`. The seatbelt files stay the
oracle. Native aarch64 and Jetson stay NOT RUN. An aarch64 **build** plus
qemu-user on an x86_64 host is labelled `aarch64 build + qemu-user (host
kernel)` and is not that missing ARM run. qemu-user 8.2.2 returns `ENOSYS`
for `landlock_*`. `lab/linux-confine/run-aarch64-guest.sh` boots
`qemu-system-aarch64` TCG with Alpine virt `6.18.58-0-virt` (Landlock ABI 7)
and runs the C9 suites inside that guest. Label:
`aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)`.
Guest result: confine 25/25, providers 4/4, Landlock ABI 7, IOCTL_DEV
EACCES, six in-guest plants CAUGHT. That guest is still not Jetson and
not native aarch64.

C9 asks for namespaces, capabilities, seccomp and Landlock, with permitted and
denied rows. The Linux map also says the filter refuses a new process and every
`socket` and `socketpair`.

## C9 departure: `socketpair(AF_UNIX)`

`model-provider` starts a Tokio thread that creates one `AF_UNIX` `socketpair`.
The provider filter therefore allows `socketpair` only when the first argument
is `AF_UNIX`. `socket` itself stays refused, including `AF_UNIX`, so an
abstract name cannot be bound. `socketpair(AF_INET)` is refused.

Did and wallet do not call `socketpair`. They run under the same filter. The
freestanding probe filter still refuses every `socket` and `socketpair`.

This pair is a C9 departure: the Linux map refuses every `socketpair` by
number. The lab keeps the Tokio pair because the shipping model binary needs
it, and it proves the inet form is refused.

`provider_filter_refuses_socketpair_inet` is the named test.
`provider_filter_refuses_socket` is the provider-filter socket row.
`F-LC-PROVIDER-SOCKET` plants `provider_deny_socket = 0` and that socket test
fails.

## Process creation

The provider filter allows `clone` only when `CLONE_THREAD` is set. `clone3`
returns `ENOSYS` so a thread call falls back to `clone`. `clone(SIGCHLD)` is
refused. `provider_filter_refuses_clone_process` is the named test. Every
denied row asserts that exact errno. `F-LC-ANY-ERRNO` plants an `expect()`
that accepts any errno plus a clone denial of `ENOSYS`, and that test fails.

## Withheld storage rights

`withheld_storage_rights_are_landlock_eacces` is the named test. Confined
`make-sym`, `make-fifo`, `make-sock`, and `ioctl-dev` return Landlock
`EACCES`. `refer` returns Landlock `EXDEV`. Each of those rows has a
same-test unconfined success. Device ioctl is `RNDGETENTCNT` on `/dev/urandom`.

`make-char` and `make-block` return confined Landlock `EACCES`. Their
unconfined controls stay NOT PROVEN: this uid has no `CAP_MKNOD` in the
initial user namespace, and a user namespace also refuses char/block
`mknod` (`EPERM`).
