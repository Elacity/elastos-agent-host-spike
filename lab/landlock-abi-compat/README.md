# Landlock ABI compatibility

A decision pack for the Linux confinement guard in draft PRs
[#299](https://github.com/Elacity/elastos-agent-host-spike/pull/299) and
[#307](https://github.com/Elacity/elastos-agent-host-spike/pull/307). Both
drafts refuse to start a provider when the Landlock ABI is below 5. ABI 5
needs Linux 6.10 or later. This folder asks what that floor does to the did,
wallet, and model rows, and which choice stays fail-closed.

The code here is a fresh decision harness. It does not wrap, vendor, or edit
`lab/fail-closed-linux`. The drafts were read at
`ba7608b52990aaf0aea7260fe5106f984564e269` (#299) and
`129fdc98428c9029b328976511478c46ebe765a6` (#307).

The matrix is `MATRIX.md`. The harness is `src/lib.rs`.

## Recommendation for Sash and Anders

Choose **(b): a per-row minimum**. Refuse the start when a required right is
missing, and name that right. Do not keep a bare constant of 5 as the rule,
and do not lower the floor so a provider can start.

For these three providers the per-row minimum is still ABI 5. `TRUNCATE`
(ABI 3) and `IOCTL_DEV` (ABI 5) are unrestricted when the kernel does not
have them, and an unrestricted right is a wider sandbox. `REFER` (ABI 2) is
not part of the minimum: the kernel denies reparenting when that right is
absent. `(deny network*)` is not a Landlock minimum either. Landlock's
network rights are TCP only, and both drafts already deny `socket` with
seccomp.

A kernel whose measured ABI is below 5 still refuses every provider. That is
the same outcome as the hard floor the drafts use today. The difference is
the reason, and the storage mask. Use #307's storage mask: handle device
ioctl, `REFER`, and the special-file create rights, and do not grant them on
`STORAGE_ROOT`. #299 grants those bits on the storage root.

Do not start providers on a host below ABI 5 by deleting the check. Option
(c) is the later route if a measured host is below ABI 5 and the providers
must start there. It is not a change to make inside the two drafts until each
control has a test that fails when that control is removed.

One gap is outside this floor. Neither draft creates a PID namespace or sets
`LANDLOCK_SCOPE_SIGNAL`. A signal to another process stays possible at ABI 5
and at ABI 6. Raising the floor to 6 does not set the bit. The design's
carrier for that row is the PID namespace.

## Options

**(a) Hard floor ABI 5.** Both drafts do this. Below 5 they refuse. At 5 and
above they run. The refusal is fail-closed. The reason in #299 treats a
missing `REFER` as a hole, and the kernel does not. The floor also says
nothing about which storage bits are granted, so #299 can run at ABI 5 with
device ioctl allowed inside the root. Trade-off: simple, and it refuses a
Jetson whose ABI is below 5 even when the only missing piece is one named
right. It does not unlock that machine.

**(b) Per-row minimum.** Refuse only when a required right is missing.
Required here means the absence is wider: filesystem rights (ABI 1),
`TRUNCATE` (ABI 3), `IOCTL_DEV` (ABI 5). A missing `REFER` does not refuse.
TCP bind and connect do not refuse while the seccomp `socket` denial is part
of the same launch; without that denial the network row refuses at every ABI,
because Landlock never covers `(deny network*)` in ABI 1..6. Trade-off: on a
real ABI number the result matches (a), so a host below ABI 5 still refuses.
The gain is a reason that names the right, a storage mask that does not grant
the denial bits, and a test that fails if those bits are dropped and the
start continues.

**(c) Compensating controls.** For a missing `TRUNCATE`, a mount namespace
that hides host files, plus closed inherited descriptors. Path `truncate`
then has no host file to name, and `ftruncate` has no inherited file
descriptor. Seccomp cannot do this job: it cannot see the path, and a denial
of every `truncate` also denies `O_TRUNC` inside the storage root. For a
missing `IOCTL_DEV`, the same mount and the same closed descriptors, plus a
launch check that `STORAGE_ROOT` holds no character or block device. For
`(deny network*)`, the seccomp `socket` denial, at every ABI. If any of those
controls is missing, the start is refused. Trade-off: this is the only option
that can run on ABI 1 without a Landlock hole, and it is the largest new
surface. A mount namespace that still exposes a host path, or a storage root
that still holds a device node, is a weaker sandbox. The harness treats that
as a refusal.

Inherited device descriptors stay unchecked by Landlock even at ABI 5. The
kernel says ioctl control applies to newly opened device files. Closing
inherited descriptors is a launch precondition in the Linux design. Neither
draft does it. Option (c) includes it. Options (a) and (b) do not, and this
pack does not call ABI 5 a fix for that precondition.

## Jetson, to be measured

This pack does not state the kernel or the Landlock ABI of the Jetson Orin
Nano. JetPack R36.4.7 is a release name, not a measurement. Public notes
about that release are not a measurement of the board. Run this on the board
and keep the output:

```bash
uname -r
uname -m
grep -H landlock_create_ruleset /usr/include/asm-generic/unistd.h /usr/include/asm/unistd*.h 2>/dev/null || true
python3 - <<'PY'
import ctypes, errno, os
# aarch64 and x86_64 take the number from asm-generic: 444.
# If the grep above prints a different number, use that number.
SYS_LANDLOCK_CREATE_RULESET = 444
LANDLOCK_CREATE_RULESET_VERSION = 1
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
rc = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
err = ctypes.get_errno()
print("osrelease", os.uname().release)
print("machine", os.uname().machine)
print("syscall", SYS_LANDLOCK_CREATE_RULESET, "ret", rc, "errno", err, errno.errorcode.get(err, ""))
if rc >= 0:
    print("landlock_abi", rc)
elif err == errno.ENOSYS:
    print("landlock_abi absent")
elif err == errno.EOPNOTSUPP:
    print("landlock_abi disabled")
PY
```

A positive `landlock_abi` is the number the guards compare to the floor.
`absent` and `disabled` are refusals under every option in this pack.
`uname -r` alone is not the ABI. The kernel can be new enough and still
leave Landlock out of `CONFIG_LSM`.

## Run

From the repo root, after `cargo test --locked` has filled the crate cache
once (the falsifier builds a scratch copy):

```bash
cargo fmt --manifest-path lab/landlock-abi-compat/Cargo.toml -- --check
cargo test --locked --manifest-path lab/landlock-abi-compat/Cargo.toml -- --test-threads=2
sh lab/landlock-abi-compat/falsify.sh
```

`tests/decisions.rs` feeds simulated ABI levels. `tests/real_kernel.rs` reads
this machine's ABI and creates one ruleset that omits `TRUNCATE` and
`IOCTL_DEV`, then closes it. It does not call `landlock_restrict_self`.

`falsify.sh` copies this crate, drops the missing-right refusal, and expects
`per_row_refuses_below_abi_5` and the silent-weaken check to fail. A compile
error is not a catch. The copy builds in its own target directory, outside
this repo's shared `target-build`, and the script deletes the copy.
