# Linux confinement in this lab (C9)

This file is the lab map for `lab/linux-confine/`. It does not change
`capsules/wallet-provider/CONFINEMENT-LINUX.md`. The seatbelt files stay the
oracle. aarch64 and Jetson stay NOT RUN.

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
refused. `provider_filter_refuses_clone_process` is the named test.
