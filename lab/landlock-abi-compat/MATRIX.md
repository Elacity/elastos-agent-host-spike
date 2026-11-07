# Landlock ABI 1..6 and the provider rows

This matrix is the Landlock half of the file-profile contract shared by
`did-provider`, `wallet-provider`, and `model-provider`. The oracle files are
`capsules/did-provider/confine.sb`, `capsules/wallet-provider/confine.sb`, and
`capsules/model-provider/confine.sb`. The Linux mapping is
`capsules/wallet-provider/CONFINEMENT-LINUX.md`. Nothing here is a measurement
of a Jetson kernel.

The three profiles allow the same five rules, with one difference: the model
profile's read of `/` is `file-read-data`, and the did and wallet profiles use
`file-read*`. The denied rows are `(deny default)` and `(deny network*)` on
all three.

A right that is absent from `handled_access_fs` stays allowed. The kernel
states that exception for every filesystem right except `REFER`, which stays
denied. Source: the `handled_access_fs` comment in `include/uapi/linux/landlock.h`,
and [Filesystem flags](https://docs.kernel.org/6.12/userspace-api/landlock.html#filesystem-flags)
in the Linux 6.12 Landlock document. ABI numbers below come from that
document's "Previous limitations" section, from
[landlock(7)](https://man7.org/linux/man-pages/man7/landlock.7.html), and from
the release commits listed by [Landlock news](https://landlock.io/news/).

## Feature matrix

| ABI | Kernel | What it adds | If the ruleset omits it | Provider rows that need it |
| --- | --- | --- | --- | --- |
| 1 | 5.13 | Thirteen filesystem rights: execute, write file, read file, read dir, remove dir, remove file, make char, make dir, make reg, make sock, make fifo, make block, make sym. Commit [`17ae69ab`](https://git.kernel.org/torvalds/c/17ae69aba89dbfa2139b7f8024b757ab3cc42f59). | Wider. Those actions stay allowed. No Landlock at all (`ENOSYS`, or `EOPNOTSUPP` when the LSM is off) is the same kind of hole. | **Permitted, all three:** `process-exec` of `PROVIDER_EXECUTABLE` needs execute and read file. `file-read*` / `file-write*` on `STORAGE_ROOT` needs read file, read dir, write file, make reg, make dir, remove file, remove dir. Did uses that grant for `init` (read `did/nickname.enc`), `set_nickname`, and `get_persona_did`. Wallet uses it for `init` (wallet directory and key) and `create_managed_account`. Model uses it for `init` (`runs/`), `runs_create`, and `runs_get`. **Denied, all three:** an outside read or write, and exec of any other file. Did: `outside_read_denied`, `outside_write_denied`. Wallet: `confined_outside_read_is_denied`, `confined_outside_write_is_denied`. Model: `model_outside_read_denied`, `model_outside_write_denied`. |
| 2 | 5.19 | `LANDLOCK_ACCESS_FS_REFER` (reparent with link or rename). Commit [`cb44e4f0`](https://git.kernel.org/torvalds/c/cb44e4f061e16be65b8a16505e121490c66d30d0). | **Narrower, not wider.** The kernel denies reparenting when the right is absent, including on ABI 1. Quote: "This is the only access right which is denied by default by any ruleset, even if the right is not specified as handled." | No permitted row grants a cross-directory link. A denial is stricter than the oracle. It is not a reason to refuse the start. |
| 3 | 6.2 | `LANDLOCK_ACCESS_FS_TRUNCATE`. Commit [`299e2b19`](https://git.kernel.org/torvalds/c/299e2b1967578b1442128ba8b3e86ed3427d3651). | **Wider.** "File truncation could not be denied before the third Landlock ABI, so it is always allowed when using a kernel that only supports the first or second ABI." `truncate(2)` does not need the write-file right. `open(2)` with `O_RDONLY\|O_TRUNC` truncates too. | **Denied outside write, all three:** did `outside_write_denied`, wallet `confined_outside_write_is_denied`, model `model_outside_write_denied`. Without this right a file outside `STORAGE_ROOT` can be truncated even though write is denied. **Permitted storage write:** `creat(2)` and `O_TRUNC` under the root must be allowed there and nowhere else, so the right has to be handled and granted on the root only. |
| 4 | 6.7 | `LANDLOCK_ACCESS_NET_BIND_TCP` and `LANDLOCK_ACCESS_NET_CONNECT_TCP`. Commit [`136cc1e1`](https://git.kernel.org/torvalds/c/136cc1e1f5be75f57f1e0404b94ee1c8792cb07d). | Wider for TCP only. Other families are untouched. | **Denied `(deny network*)`, all three**, including the model hosted socket (`model_hosted_run_fails_closed_under_profile`). Landlock ABI 4 does not express that row: UDP, Unix, and the other families are outside it. Both drafts carry the row with a seccomp denial of `socket` (and #299 also denies `connect`). |
| 5 | 6.10 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` on a newly opened character or block device. Commit [`2fc0e789`](https://git.kernel.org/torvalds/c/2fc0e7892c10734c1b7c613ef04836d57d4676d5). | **Wider.** "IOCTL operations could not be denied before the fifth Landlock ABI, so ioctl(2) is always allowed when using a kernel that only supports an earlier ABI." A short list of commands stays allowed even after ABI 5 (`FIOCLEX`, `FIONCLEX`, `FIONBIO`, `FIOASYNC`, and the filesystem commands named in the same section). Inherited descriptors, including stdin, stdout, and stderr, are not checked. | **Denied by `(deny default)`.** No permitted row grants device ioctl. The storage grant must not include this bit. A device node created or planted under `STORAGE_ROOT` can otherwise be opened with the read/write grant and then controlled with `ioctl`. |
| 6 | 6.12 | `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` and `LANDLOCK_SCOPE_SIGNAL`. Commit [`e1b061b4`](https://git.kernel.org/torvalds/c/e1b061b444fb01c237838f0d8238653afe6a8094). | Wider for those two actions when the bits are left unset. Unset is the default. | **Denied `(deny network*)`** for an abstract Unix socket, and **denied `(deny default)`** for a signal to another process. The design's carrier for signals is a PID namespace, not this bit (`CONFINEMENT-LINUX.md`, process and signal row). The carrier for the socket is the seccomp `socket` denial. Neither draft sets either scope bit. |

Two oracle allows are not in this table, because no ABI adds them. Landlock
has no literal-directory right, so a read rule on `STORAGE_PARENT` or on `/`
would cover the whole tree. The design maps both allows to no path rule.
That mapping is narrower, and it is the same at every ABI. The did and wallet
read of `/`, the model's `file-read-data` of `/`, and `file-read*` of
`STORAGE_PARENT` are those rows. `sysctl-read` is not a Landlock right either.

`chdir`, `stat`, `flock`, `chmod`, `chown`, `setxattr`, `utime`, `fcntl`, and
`access` stay unrestricted at ABI 6. The 6.12 document says so. This pack does
not treat that list as an ABI floor.

## What each draft does with these rights

Both drafts refuse when the probe returns `ENOSYS` or `EOPNOTSUPP`, and both
refuse when the reported ABI is below 5. The floor cannot be lowered. At ABI
5 or above they start the provider. They do not look at scope.

The rulesets they install are not the same. Sources, read only:
#299 at `ba7608b52990aaf0aea7260fe5106f984564e269` (`src/policy.rs`,
`src/guard.rs`) and #307 at `129fdc98428c9029b328976511478c46ebe765a6`
(`src/lib.rs`).

| | #299 | #307 |
| --- | --- | --- |
| Floor | ABI 5. Reason names the `STORAGE_ROOT` row. | ABI 5. Reason is `Landlock ABI N is below the required 5`. |
| Handled filesystem bits | All sixteen ABI 5 bits. | All sixteen ABI 5 bits. |
| Storage grant | Every handled bit except execute. That includes `REFER`, `IOCTL_DEV`, and make char, sock, fifo, block, and symlink. | Read file, read dir, write file, truncate, make reg, make dir, remove file, remove dir. No `REFER`, no `IOCTL_DEV`, no device, socket, fifo, or symlink create. |
| Executable grant | Execute and read file. | Execute and read file. |
| TCP bind and connect | Not handled. The attribute has no network field. | Handled, and no port rule, so TCP bind and connect are denied. |
| Scope | Not set. | Not set. |
| Seccomp beside Landlock | Denies `socket`, `socketpair`, and `connect`. | Denies `socket` and `socketpair`. Does not deny `connect`. |

#299's own README says a missing `REFER` leaves that right unrestricted. The
kernel says the opposite: a missing `REFER` is a denial. The refusal below
ABI 5 is still right, because `TRUNCATE` and `IOCTL_DEV` are unrestricted
when they are missing. The `REFER` sentence is not.

#307's storage mask matches the oracle's read/write grant more closely.
#299's storage mask grants device creation and device ioctl inside the root.
That is a wider grant on a kernel that is new enough to run. It is not an
ABI downgrade. The two masks are the split already noted in #299's README.

## Decision at each simulated ABI

`Run` means the guard starts the provider under the ruleset above.
`Refuse` means it does not start. `Weaker` means it starts while `TRUNCATE`
or `IOCTL_DEV` (or Landlock itself) is missing. That last column is the
planted best-effort path, not a draft.

| Reported ABI | #299 | #307 | Per-row rule (b) | Best effort |
| --- | --- | --- | --- | --- |
| absent | Refuse. No Landlock. | Refuse. Not available. | Refuse. Names filesystem rights, `TRUNCATE`, and `IOCTL_DEV`. | Weaker. |
| 1 | Refuse. Floor 5. | Refuse. Floor 5. | Refuse. Names `TRUNCATE` and `IOCTL_DEV`. Does not name `REFER`. | Weaker. Drops `TRUNCATE` and `IOCTL_DEV`. |
| 2 | Refuse. Floor 5. | Refuse. Floor 5. | Refuse. Same two rights. | Weaker. |
| 3 | Refuse. Floor 5. | Refuse. Floor 5. | Refuse. Names `IOCTL_DEV` only. Truncate is present. | Weaker. Drops `IOCTL_DEV`. |
| 4 | Refuse. Floor 5. | Refuse. Floor 5. | Refuse. Names `IOCTL_DEV` only. | Weaker. Drops `IOCTL_DEV`. |
| 5 | Run. | Run. | Run. | Run. The hole is gone. |
| 6 | Run. Scope bits stay unset. | Run. Scope bits stay unset. | Run. | Run. |

On the numbers a kernel can report, (a) and (b) both refuse below 5 and both
run at 5 and above. They differ in the reason, and in the fact that (b) does
not treat `REFER` as a hole.

## Signal row

Both drafts run at ABI 6 with `scoped` equal to 0, and neither creates a PID
namespace. A signal to a host process is not confined by Landlock in either
guard. Raising the floor from 5 to 6 does not set the scope bit, so it does
not close that row. The design's carrier is the PID namespace. This pack
leaves the row open and does not hide it inside the ABI floor.
