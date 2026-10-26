# B4 proposed unified baseline

One polarity per right for macOS and both Linux labs. This is a
proposal. The checker scores each platform against `baseline.json`.
It starts no provider and it does not edit a profile.

- Linux x86-64 execution: **NOT RUN**
- Jetson aarch64 execution: **NOT RUN**
- macOS execution: **NOT RUN**

Where a polarity is unsure, this file proposes the tighter side and sets open_decision so Sash and Anders decide.

Owners: Sash, Anders.

## Per-right decision

| Right | Proposed | Decision | macOS | #296 | #307 | Who changes if the proposal is adopted |
| --- | --- | --- | --- | --- | --- | --- |
| `bound-executable` | allow | proposed | CONFORMS | CONFORMS | CONFORMS | none |
| `storage.root` | allow | proposed | CONFORMS | CONFORMS | CONFORMS | none |
| `storage.parent` | deny | OPEN DECISION | OPEN DECISION | OPEN DECISION | OPEN DECISION | macOS profile: drop (allow file-read* (literal (param "STORAGE_PARENT"))) and split STORAGE_PARENT out of the C8 storage right |
| `startup-root-directory` | deny | OPEN DECISION | OPEN DECISION | OPEN DECISION | OPEN DECISION | macOS profile: drop (allow file-read* (literal "/")) and the model file-read-data form |
| `startup-sysctl` | deny | OPEN DECISION | OPEN DECISION | OPEN DECISION | OPEN DECISION | macOS profile: drop (allow sysctl-read) |
| `outside.read` | deny | proposed | CONFORMS | CONFORMS | CONFORMS | none |
| `outside.write` | deny | proposed | CONFORMS | CONFORMS | CONFORMS | none |
| `network` | deny | proposed | CONFORMS | CONFORMS | CONFORMS | none |
| `unix-socketpair` | deny | proposed | CONFORMS | MUST CHANGE | CONFORMS | #296: drop the AF_UNIX socketpair exception so the provider filter denies the pair |
| `exec.other` | deny | proposed | CONFORMS | CONFORMS | CONFORMS | none |
| `signal.host` | deny | proposed | CONFORMS | CONFORMS | MUST CHANGE | #307: unshare CLONE_NEWPID so a host pid cannot be named; SCOPE_SIGNAL at ABI 6 is not a substitute |
| `device.ioctl` | deny | proposed | CONFORMS | CONFORMS | CONFORMS | none |

Scores above are did-provider. wallet and model use the same
proposed polarity. `storage.parent` on #296 is missing for did and
model, and partial (private remount) for wallet.

## Counts

- CONFORMS: **75**
- MUST CHANGE: **6**
- OPEN DECISION: **27**
- Inter-platform mismatch rows: **30**

Counts are provider × right × platform (3 × 12 × 3 = 108).

## Rationale

### `bound-executable` — exec the bound provider binary

Proposed **allow** (proposed).

Every side already grants execute of the one bound provider binary and refuses any other file. The unified model keeps that allow.

- macOS profile: none; #296: none; #307: none

### `storage.root` — read and write under STORAGE_ROOT

Proposed **allow** (proposed).

The approved storage right is the eight-right mask on STORAGE_ROOT (0x41be). macOS uses the subpath write rule. Both Linux labs grant the same eight bits and omit ioctl, refer, and special-file create.

- macOS profile: none; #296: none; #307: none

### `storage.parent` — literal read of STORAGE_PARENT only

Proposed **deny** (OPEN DECISION).

STORAGE_PARENT is its own right here, split out of C8 storage. Landlock cannot name a directory alone: a path rule on the host parent covers siblings. Linux is already the tighter side (missing on did/model; wallet on #296 remounts a private parent). Fail-closed proposes deny of a host-parent grant. C8 still bundles the Seatbelt literal under storage, and macOS init has F-cc1-rm-parent, so this stays an open decision. The keep-the-right path is the #296 wallet remount on every provider, not a host-parent Landlock rule.

- macOS profile: drop (allow file-read* (literal (param "STORAGE_PARENT"))) and split STORAGE_PARENT out of the C8 storage right; #296: none if deny is adopted; if the right is kept, extend hide_parent_siblings to did and model; #307: none if deny is adopted; if the right is kept, add a private-parent mount

### `startup-root-directory` — startup read of /

Proposed **deny** (OPEN DECISION).

One polarity for `/`. A Landlock rule on `/` grants the whole tree, so both Linux labs add none. That is the tighter side. Seatbelt's literal `/` is a macOS loader pin, not a shared grant Linux can copy. Fail-closed proposes deny as the unified right. Open until a named test shows the macOS loader starts without that pin, or Sash and Anders reclassify it as macOS-loader-only and drop it from the shared model.

- macOS profile: drop (allow file-read* (literal "/")) and the model file-read-data form; #296: none; #307: none

### `startup-sysctl` — startup sysctl-read

Proposed **deny** (OPEN DECISION).

One polarity for sysctl-read. Linux has no sysctl right. #307 names none. #296 admits uname and loader syscalls; that is a loader set, not a shared sysctl grant. Fail-closed proposes deny as the unified right. Open until a named test shows the macOS loader starts without sysctl-read, or the C8 baseline names the Linux loader syscalls as Linux-only and drops the shared right.

- macOS profile: drop (allow sysctl-read); #296: none; #307: none

### `outside.read` — read outside STORAGE_ROOT

Proposed **deny** (proposed).

Every side already refuses a read outside STORAGE_ROOT. The unified model keeps that deny.

- macOS profile: none; #296: none; #307: none

### `outside.write` — write outside STORAGE_ROOT

Proposed **deny** (proposed).

Every side already refuses a write outside STORAGE_ROOT. The unified model keeps that deny.

- macOS profile: none; #296: none; #307: none

### `network` — network sockets

Proposed **deny** (proposed).

Providers speak stdin/stdout. macOS denies network*. Both Linux labs deny SYS_socket. The unified model keeps that deny.

- macOS profile: none; #296: none; #307: none

### `unix-socketpair` — AF_UNIX socketpair

Proposed **deny** (proposed).

macOS counts a Unix-domain pair under network* and denies it. #307 denies SYS_socketpair with no AF_UNIX exception. #296 allows AF_UNIX socketpair for Tokio. Fail-closed keeps the tighter deny. A separate fixer is closing the #296 exception. #296 is the side that changes.

- macOS profile: none; #296: drop the AF_UNIX socketpair exception so the provider filter denies the pair; #307: none

### `exec.other` — exec a file other than PROVIDER_EXECUTABLE

Proposed **deny** (proposed).

Every side already grants execute only on the bound binary. The unified model keeps that deny.

- macOS profile: none; #296: none; #307: none

### `signal.host` — signal a host process

Proposed **deny** (proposed).

A provider must not signal a host pid. macOS has no signal-outbound grant. #296 unshares CLONE_NEWPID, so a host pid cannot be named. #307 unshares only CLONE_NEWUSER and sets LANDLOCK_SCOPE_SIGNAL at ABI 6; that is partial, not a deny. The unified model is deny with a PID namespace carrier. #307 is the side that changes.

- macOS profile: none; #296: none; #307: unshare CLONE_NEWPID so a host pid cannot be named; SCOPE_SIGNAL at ABI 6 is not a substitute

### `device.ioctl` — device ioctl

Proposed **deny** (proposed).

IOCTL_DEV is not in the eight-right storage mask. macOS has no file-ioctl grant. Both Linux labs refuse a start that cannot deny ioctl. The unified model keeps that deny.

- macOS profile: none; #296: none; #307: none

## Scores by provider

### did-provider

| Right | macOS | #296 | #307 |
| --- | --- | --- | --- |
| `bound-executable` | CONFORMS | CONFORMS | CONFORMS |
| `storage.root` | CONFORMS | CONFORMS | CONFORMS |
| `storage.parent` | OPEN DECISION | OPEN DECISION | OPEN DECISION |
| `startup-root-directory` | OPEN DECISION | OPEN DECISION | OPEN DECISION |
| `startup-sysctl` | OPEN DECISION | OPEN DECISION | OPEN DECISION |
| `outside.read` | CONFORMS | CONFORMS | CONFORMS |
| `outside.write` | CONFORMS | CONFORMS | CONFORMS |
| `network` | CONFORMS | CONFORMS | CONFORMS |
| `unix-socketpair` | CONFORMS | MUST CHANGE | CONFORMS |
| `exec.other` | CONFORMS | CONFORMS | CONFORMS |
| `signal.host` | CONFORMS | CONFORMS | MUST CHANGE |
| `device.ioctl` | CONFORMS | CONFORMS | CONFORMS |

### wallet-provider

| Right | macOS | #296 | #307 |
| --- | --- | --- | --- |
| `bound-executable` | CONFORMS | CONFORMS | CONFORMS |
| `storage.root` | CONFORMS | CONFORMS | CONFORMS |
| `storage.parent` | OPEN DECISION | OPEN DECISION | OPEN DECISION |
| `startup-root-directory` | OPEN DECISION | OPEN DECISION | OPEN DECISION |
| `startup-sysctl` | OPEN DECISION | OPEN DECISION | OPEN DECISION |
| `outside.read` | CONFORMS | CONFORMS | CONFORMS |
| `outside.write` | CONFORMS | CONFORMS | CONFORMS |
| `network` | CONFORMS | CONFORMS | CONFORMS |
| `unix-socketpair` | CONFORMS | MUST CHANGE | CONFORMS |
| `exec.other` | CONFORMS | CONFORMS | CONFORMS |
| `signal.host` | CONFORMS | CONFORMS | MUST CHANGE |
| `device.ioctl` | CONFORMS | CONFORMS | CONFORMS |

### model-provider

| Right | macOS | #296 | #307 |
| --- | --- | --- | --- |
| `bound-executable` | CONFORMS | CONFORMS | CONFORMS |
| `storage.root` | CONFORMS | CONFORMS | CONFORMS |
| `storage.parent` | OPEN DECISION | OPEN DECISION | OPEN DECISION |
| `startup-root-directory` | OPEN DECISION | OPEN DECISION | OPEN DECISION |
| `startup-sysctl` | OPEN DECISION | OPEN DECISION | OPEN DECISION |
| `outside.read` | CONFORMS | CONFORMS | CONFORMS |
| `outside.write` | CONFORMS | CONFORMS | CONFORMS |
| `network` | CONFORMS | CONFORMS | CONFORMS |
| `unix-socketpair` | CONFORMS | MUST CHANGE | CONFORMS |
| `exec.other` | CONFORMS | CONFORMS | CONFORMS |
| `signal.host` | CONFORMS | CONFORMS | MUST CHANGE |
| `device.ioctl` | CONFORMS | CONFORMS | CONFORMS |

score_ids:

- `did-provider/bound-executable/macos=CONFORMS`
- `did-provider/bound-executable/linux-confine=CONFORMS`
- `did-provider/bound-executable/fail-closed-linux=CONFORMS`
- `did-provider/storage.root/macos=CONFORMS`
- `did-provider/storage.root/linux-confine=CONFORMS`
- `did-provider/storage.root/fail-closed-linux=CONFORMS`
- `did-provider/storage.parent/macos=OPEN DECISION`
- `did-provider/storage.parent/linux-confine=OPEN DECISION`
- `did-provider/storage.parent/fail-closed-linux=OPEN DECISION`
- `did-provider/startup-root-directory/macos=OPEN DECISION`
- `did-provider/startup-root-directory/linux-confine=OPEN DECISION`
- `did-provider/startup-root-directory/fail-closed-linux=OPEN DECISION`
- `did-provider/startup-sysctl/macos=OPEN DECISION`
- `did-provider/startup-sysctl/linux-confine=OPEN DECISION`
- `did-provider/startup-sysctl/fail-closed-linux=OPEN DECISION`
- `did-provider/outside.read/macos=CONFORMS`
- `did-provider/outside.read/linux-confine=CONFORMS`
- `did-provider/outside.read/fail-closed-linux=CONFORMS`
- `did-provider/outside.write/macos=CONFORMS`
- `did-provider/outside.write/linux-confine=CONFORMS`
- `did-provider/outside.write/fail-closed-linux=CONFORMS`
- `did-provider/network/macos=CONFORMS`
- `did-provider/network/linux-confine=CONFORMS`
- `did-provider/network/fail-closed-linux=CONFORMS`
- `did-provider/unix-socketpair/macos=CONFORMS`
- `did-provider/unix-socketpair/linux-confine=MUST CHANGE`
- `did-provider/unix-socketpair/fail-closed-linux=CONFORMS`
- `did-provider/exec.other/macos=CONFORMS`
- `did-provider/exec.other/linux-confine=CONFORMS`
- `did-provider/exec.other/fail-closed-linux=CONFORMS`
- `did-provider/signal.host/macos=CONFORMS`
- `did-provider/signal.host/linux-confine=CONFORMS`
- `did-provider/signal.host/fail-closed-linux=MUST CHANGE`
- `did-provider/device.ioctl/macos=CONFORMS`
- `did-provider/device.ioctl/linux-confine=CONFORMS`
- `did-provider/device.ioctl/fail-closed-linux=CONFORMS`
- `wallet-provider/bound-executable/macos=CONFORMS`
- `wallet-provider/bound-executable/linux-confine=CONFORMS`
- `wallet-provider/bound-executable/fail-closed-linux=CONFORMS`
- `wallet-provider/storage.root/macos=CONFORMS`
- `wallet-provider/storage.root/linux-confine=CONFORMS`
- `wallet-provider/storage.root/fail-closed-linux=CONFORMS`
- `wallet-provider/storage.parent/macos=OPEN DECISION`
- `wallet-provider/storage.parent/linux-confine=OPEN DECISION`
- `wallet-provider/storage.parent/fail-closed-linux=OPEN DECISION`
- `wallet-provider/startup-root-directory/macos=OPEN DECISION`
- `wallet-provider/startup-root-directory/linux-confine=OPEN DECISION`
- `wallet-provider/startup-root-directory/fail-closed-linux=OPEN DECISION`
- `wallet-provider/startup-sysctl/macos=OPEN DECISION`
- `wallet-provider/startup-sysctl/linux-confine=OPEN DECISION`
- `wallet-provider/startup-sysctl/fail-closed-linux=OPEN DECISION`
- `wallet-provider/outside.read/macos=CONFORMS`
- `wallet-provider/outside.read/linux-confine=CONFORMS`
- `wallet-provider/outside.read/fail-closed-linux=CONFORMS`
- `wallet-provider/outside.write/macos=CONFORMS`
- `wallet-provider/outside.write/linux-confine=CONFORMS`
- `wallet-provider/outside.write/fail-closed-linux=CONFORMS`
- `wallet-provider/network/macos=CONFORMS`
- `wallet-provider/network/linux-confine=CONFORMS`
- `wallet-provider/network/fail-closed-linux=CONFORMS`
- `wallet-provider/unix-socketpair/macos=CONFORMS`
- `wallet-provider/unix-socketpair/linux-confine=MUST CHANGE`
- `wallet-provider/unix-socketpair/fail-closed-linux=CONFORMS`
- `wallet-provider/exec.other/macos=CONFORMS`
- `wallet-provider/exec.other/linux-confine=CONFORMS`
- `wallet-provider/exec.other/fail-closed-linux=CONFORMS`
- `wallet-provider/signal.host/macos=CONFORMS`
- `wallet-provider/signal.host/linux-confine=CONFORMS`
- `wallet-provider/signal.host/fail-closed-linux=MUST CHANGE`
- `wallet-provider/device.ioctl/macos=CONFORMS`
- `wallet-provider/device.ioctl/linux-confine=CONFORMS`
- `wallet-provider/device.ioctl/fail-closed-linux=CONFORMS`
- `model-provider/bound-executable/macos=CONFORMS`
- `model-provider/bound-executable/linux-confine=CONFORMS`
- `model-provider/bound-executable/fail-closed-linux=CONFORMS`
- `model-provider/storage.root/macos=CONFORMS`
- `model-provider/storage.root/linux-confine=CONFORMS`
- `model-provider/storage.root/fail-closed-linux=CONFORMS`
- `model-provider/storage.parent/macos=OPEN DECISION`
- `model-provider/storage.parent/linux-confine=OPEN DECISION`
- `model-provider/storage.parent/fail-closed-linux=OPEN DECISION`
- `model-provider/startup-root-directory/macos=OPEN DECISION`
- `model-provider/startup-root-directory/linux-confine=OPEN DECISION`
- `model-provider/startup-root-directory/fail-closed-linux=OPEN DECISION`
- `model-provider/startup-sysctl/macos=OPEN DECISION`
- `model-provider/startup-sysctl/linux-confine=OPEN DECISION`
- `model-provider/startup-sysctl/fail-closed-linux=OPEN DECISION`
- `model-provider/outside.read/macos=CONFORMS`
- `model-provider/outside.read/linux-confine=CONFORMS`
- `model-provider/outside.read/fail-closed-linux=CONFORMS`
- `model-provider/outside.write/macos=CONFORMS`
- `model-provider/outside.write/linux-confine=CONFORMS`
- `model-provider/outside.write/fail-closed-linux=CONFORMS`
- `model-provider/network/macos=CONFORMS`
- `model-provider/network/linux-confine=CONFORMS`
- `model-provider/network/fail-closed-linux=CONFORMS`
- `model-provider/unix-socketpair/macos=CONFORMS`
- `model-provider/unix-socketpair/linux-confine=MUST CHANGE`
- `model-provider/unix-socketpair/fail-closed-linux=CONFORMS`
- `model-provider/exec.other/macos=CONFORMS`
- `model-provider/exec.other/linux-confine=CONFORMS`
- `model-provider/exec.other/fail-closed-linux=CONFORMS`
- `model-provider/signal.host/macos=CONFORMS`
- `model-provider/signal.host/linux-confine=CONFORMS`
- `model-provider/signal.host/fail-closed-linux=MUST CHANGE`
- `model-provider/device.ioctl/macos=CONFORMS`
- `model-provider/device.ioctl/linux-confine=CONFORMS`
- `model-provider/device.ioctl/fail-closed-linux=CONFORMS`
