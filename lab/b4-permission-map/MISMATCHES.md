# B4 permission mismatches

Static source comparison. The checker reads the macOS oracles and the
pinned Linux labs. It starts no provider.

- Linux x86-64 execution: **NOT RUN**
- Jetson aarch64 execution: **NOT RUN**
- macOS execution: **NOT RUN**

Linux sources:

- draft PR #296 `lab/linux-confine` at `2dc3c565c6649d668f1e50efefeea7d964330f9c`
- draft PR #307 `lab/fail-closed-linux` at `2c70a0d845f9acc15144a2afec889370612cca66`

Mismatch rows: **30**.

Suggested fixes stay in this file. This lab does not edit
`capsules/`, `lab/linux-confine/`, or `lab/fail-closed-linux/`.

The proposed unified baseline is `baseline.json`. Scores against
that file (CONFORMS / MUST CHANGE / OPEN DECISION) are `BASELINE.md`.

## did-provider

### `storage.parent` — literal read of STORAGE_PARENT only

Kinds: coverage, coverage.

- allow on macOS, missing on Linux #296
- allow on macOS, missing on Linux #307

- macOS: `capsules/did-provider/confine.sb:18` `(allow file-read* (literal (param "STORAGE_PARENT")))` **allow**
- Linux #296: `lab/linux-confine/helper/setup.c:251` `no Landlock rule on the host STORAGE_PARENT` **missing** — Landlock has no literal-directory rule; did and model get no host-parent grant
- Linux #307: `lab/fail-closed-linux/src/lib.rs:75` `no STORAGE_PARENT path rule` **missing** — the guard unshares only CLONE_NEWUSER and grants the storage root

Suggested fix (not applied): Either drop the STORAGE_PARENT literal read from the C8 storage right once a named test shows each provider starts without it, or teach the Linux labs one private-parent mount for every provider, not only wallet (lab/linux-confine/helper/setup.c:251).

### `startup-root-directory` — startup read of /

Kinds: coverage, coverage.

- allow on macOS, missing on Linux #296
- allow on macOS, missing on Linux #307

- macOS: `capsules/did-provider/confine.sb:13` `(allow file-read* (literal "/"))` **allow**
- Linux #296: `lab/linux-confine/helper/setup.c:38` `no Landlock rule on /` **missing** — a rule on / would grant the whole tree, so the launcher adds none
- Linux #307: `lab/fail-closed-linux/src/lib.rs:75` `no Landlock rule on /` **missing** — the guard does not grant the startup root-directory read

Suggested fix (not applied): Keep the macOS baseline only while a named test needs `/`. If the Linux loader starts without that rule, move the baseline to a Linux-only loader grant and stop claiming one right.

### `startup-sysctl` — startup sysctl-read

Kinds: coverage, coverage.

- allow on macOS, partial on Linux #296
- allow on macOS, missing on Linux #307

- macOS: `capsules/did-provider/confine.sb:15` `(allow sysctl-read)` **allow**
- Linux #296: `lab/linux-confine/helper/setup.c:704` `SYS_uname on the probe filter; no sysctl right` **partial** — Landlock has no sysctl; the provider filter admits the loader syscalls it needs
- Linux #307: `lab/fail-closed-linux/src/real.rs:122` `no sysctl grant` **missing** — the seccomp layer is a deny-list; it does not name sysctl-read

Suggested fix (not applied): Name the Linux syscalls that stand in for sysctl-read (uname and the loader set) in the C8 baseline, or drop the macOS sysctl-read once a named test shows the loader starts without it.

### `unix-socketpair` — AF_UNIX socketpair

Kinds: polarity, linux-split.

- denied on macOS, allowed on Linux #296
- allowed on #296, denied on #307

- macOS: `capsules/did-provider/confine.sb:8` `(deny network*)` **deny** — macOS counts a Unix-domain pair under network*
- Linux #296: `lab/linux-confine/helper/setup.c:373` `provider filter allows socketpair only when arg0 is AF_UNIX` **allow** — model Tokio needs the pair; did and wallet take the same filter; socket itself stays refused
- Linux #307: `lab/fail-closed-linux/src/seccomp.rs:31` `seccomp DENIED includes SYS_socketpair` **deny** — no AF_UNIX exception; this is stricter than the #296 provider filter

Suggested fix (not applied): Pick one declared right for AF_UNIX socketpair. Either add a named macOS network exception that the C8 contract accepts, or drop the #296 AF_UNIX exception so both Linux labs deny the pair like capsules/did-provider/confine.sb:8 and lab/fail-closed-linux/src/seccomp.rs:31.

### `signal.host` — signal a host process

Kinds: coverage, linux-split.

- deny on macOS, partial on Linux #307
- deny on #296, partial on #307

- macOS: `capsules/did-provider/confine.sb:6` `(deny default)` **deny** — no signal-outbound grant
- Linux #296: `lab/linux-confine/helper/setup.c:671` `unshare(CLONE_NEWPID)` **deny** — a host pid cannot be named inside the new PID namespace
- Linux #307: `lab/fail-closed-linux/src/lib.rs:777` `LANDLOCK_SCOPE_SIGNAL at ABI 6; no PID namespace` **partial** — the guard unshares only CLONE_NEWUSER; a host signal is a named gap below ABI 6

Suggested fix (not applied): Give the C0 guard the same carrier #296 already uses: a PID namespace that contains the provider (lab/linux-confine/helper/setup.c:671). LANDLOCK_SCOPE_SIGNAL at ABI 6 is not a substitute for a host pid that still exists in the same namespace.

## wallet-provider

### `storage.parent` — literal read of STORAGE_PARENT only

Kinds: coverage, coverage.

- allow on macOS, partial on Linux #296
- allow on macOS, missing on Linux #307

- macOS: `capsules/wallet-provider/confine.sb:31` `(allow file-read* (literal (param "STORAGE_PARENT")))` **allow**
- Linux #296: `lab/linux-confine/helper/setup.c:251` `hide_parent_siblings + parent read rule` **partial** — wallet launch bind-mounts a private parent that holds only STORAGE_ROOT, then grants read of that parent
- Linux #307: `lab/fail-closed-linux/src/lib.rs:75` `no STORAGE_PARENT path rule` **missing** — the guard unshares only CLONE_NEWUSER and grants the storage root

Suggested fix (not applied): Either drop the STORAGE_PARENT literal read from the C8 storage right once a named test shows each provider starts without it, or teach the Linux labs one private-parent mount for every provider, not only wallet (lab/linux-confine/helper/setup.c:251).

### `startup-root-directory` — startup read of /

Kinds: coverage, coverage.

- allow on macOS, missing on Linux #296
- allow on macOS, missing on Linux #307

- macOS: `capsules/wallet-provider/confine.sb:24` `(allow file-read* (literal "/"))` **allow**
- Linux #296: `lab/linux-confine/helper/setup.c:38` `no Landlock rule on /` **missing** — a rule on / would grant the whole tree, so the launcher adds none
- Linux #307: `lab/fail-closed-linux/src/lib.rs:75` `no Landlock rule on /` **missing** — the guard does not grant the startup root-directory read

Suggested fix (not applied): Keep the macOS baseline only while a named test needs `/`. If the Linux loader starts without that rule, move the baseline to a Linux-only loader grant and stop claiming one right.

### `startup-sysctl` — startup sysctl-read

Kinds: coverage, coverage.

- allow on macOS, partial on Linux #296
- allow on macOS, missing on Linux #307

- macOS: `capsules/wallet-provider/confine.sb:28` `(allow sysctl-read)` **allow**
- Linux #296: `lab/linux-confine/helper/setup.c:704` `SYS_uname on the probe filter; no sysctl right` **partial** — Landlock has no sysctl; the provider filter admits the loader syscalls it needs
- Linux #307: `lab/fail-closed-linux/src/real.rs:122` `no sysctl grant` **missing** — the seccomp layer is a deny-list; it does not name sysctl-read

Suggested fix (not applied): Name the Linux syscalls that stand in for sysctl-read (uname and the loader set) in the C8 baseline, or drop the macOS sysctl-read once a named test shows the loader starts without it.

### `unix-socketpair` — AF_UNIX socketpair

Kinds: polarity, linux-split.

- denied on macOS, allowed on Linux #296
- allowed on #296, denied on #307

- macOS: `capsules/wallet-provider/confine.sb:16` `(deny network*)` **deny** — macOS counts a Unix-domain pair under network*
- Linux #296: `lab/linux-confine/helper/setup.c:373` `provider filter allows socketpair only when arg0 is AF_UNIX` **allow** — model Tokio needs the pair; did and wallet take the same filter; socket itself stays refused
- Linux #307: `lab/fail-closed-linux/src/seccomp.rs:31` `seccomp DENIED includes SYS_socketpair` **deny** — no AF_UNIX exception; this is stricter than the #296 provider filter

Suggested fix (not applied): Pick one declared right for AF_UNIX socketpair. Either add a named macOS network exception that the C8 contract accepts, or drop the #296 AF_UNIX exception so both Linux labs deny the pair like capsules/wallet-provider/confine.sb:16 and lab/fail-closed-linux/src/seccomp.rs:31.

### `signal.host` — signal a host process

Kinds: coverage, linux-split.

- deny on macOS, partial on Linux #307
- deny on #296, partial on #307

- macOS: `capsules/wallet-provider/confine.sb:15` `(deny default)` **deny** — no signal-outbound grant
- Linux #296: `lab/linux-confine/helper/setup.c:671` `unshare(CLONE_NEWPID)` **deny** — a host pid cannot be named inside the new PID namespace
- Linux #307: `lab/fail-closed-linux/src/lib.rs:777` `LANDLOCK_SCOPE_SIGNAL at ABI 6; no PID namespace` **partial** — the guard unshares only CLONE_NEWUSER; a host signal is a named gap below ABI 6

Suggested fix (not applied): Give the C0 guard the same carrier #296 already uses: a PID namespace that contains the provider (lab/linux-confine/helper/setup.c:671). LANDLOCK_SCOPE_SIGNAL at ABI 6 is not a substitute for a host pid that still exists in the same namespace.

## model-provider

### `storage.parent` — literal read of STORAGE_PARENT only

Kinds: coverage, coverage.

- allow on macOS, missing on Linux #296
- allow on macOS, missing on Linux #307

- macOS: `capsules/model-provider/confine.sb:23` `(allow file-read* (literal (param "STORAGE_PARENT")))` **allow**
- Linux #296: `lab/linux-confine/helper/setup.c:251` `no Landlock rule on the host STORAGE_PARENT` **missing** — Landlock has no literal-directory rule; did and model get no host-parent grant
- Linux #307: `lab/fail-closed-linux/src/lib.rs:75` `no STORAGE_PARENT path rule` **missing** — the guard unshares only CLONE_NEWUSER and grants the storage root

Suggested fix (not applied): Either drop the STORAGE_PARENT literal read from the C8 storage right once a named test shows each provider starts without it, or teach the Linux labs one private-parent mount for every provider, not only wallet (lab/linux-confine/helper/setup.c:251).

### `startup-root-directory` — startup read of /

Kinds: coverage, coverage.

- allow on macOS, missing on Linux #296
- allow on macOS, missing on Linux #307

- macOS: `capsules/model-provider/confine.sb:19` `(allow file-read-data (literal "/"))` **allow**
- Linux #296: `lab/linux-confine/helper/setup.c:38` `no Landlock rule on /` **missing** — a rule on / would grant the whole tree, so the launcher adds none
- Linux #307: `lab/fail-closed-linux/src/lib.rs:75` `no Landlock rule on /` **missing** — the guard does not grant the startup root-directory read

Suggested fix (not applied): Keep the macOS baseline only while a named test needs `/`. If the Linux loader starts without that rule, move the baseline to a Linux-only loader grant and stop claiming one right.

### `startup-sysctl` — startup sysctl-read

Kinds: coverage, coverage.

- allow on macOS, partial on Linux #296
- allow on macOS, missing on Linux #307

- macOS: `capsules/model-provider/confine.sb:21` `(allow sysctl-read)` **allow**
- Linux #296: `lab/linux-confine/helper/setup.c:704` `SYS_uname on the probe filter; no sysctl right` **partial** — Landlock has no sysctl; the provider filter admits the loader syscalls it needs
- Linux #307: `lab/fail-closed-linux/src/real.rs:122` `no sysctl grant` **missing** — the seccomp layer is a deny-list; it does not name sysctl-read

Suggested fix (not applied): Name the Linux syscalls that stand in for sysctl-read (uname and the loader set) in the C8 baseline, or drop the macOS sysctl-read once a named test shows the loader starts without it.

### `unix-socketpair` — AF_UNIX socketpair

Kinds: polarity, linux-split.

- denied on macOS, allowed on Linux #296
- allowed on #296, denied on #307

- macOS: `capsules/model-provider/confine.sb:14` `(deny network*)` **deny** — macOS counts a Unix-domain pair under network*
- Linux #296: `lab/linux-confine/helper/setup.c:373` `provider filter allows socketpair only when arg0 is AF_UNIX` **allow** — model Tokio needs the pair; did and wallet take the same filter; socket itself stays refused
- Linux #307: `lab/fail-closed-linux/src/seccomp.rs:31` `seccomp DENIED includes SYS_socketpair` **deny** — no AF_UNIX exception; this is stricter than the #296 provider filter

Suggested fix (not applied): Pick one declared right for AF_UNIX socketpair. Either add a named macOS network exception that the C8 contract accepts, or drop the #296 AF_UNIX exception so both Linux labs deny the pair like capsules/model-provider/confine.sb:14 and lab/fail-closed-linux/src/seccomp.rs:31.

### `signal.host` — signal a host process

Kinds: coverage, linux-split.

- deny on macOS, partial on Linux #307
- deny on #296, partial on #307

- macOS: `capsules/model-provider/confine.sb:12` `(deny default)` **deny** — no signal-outbound grant
- Linux #296: `lab/linux-confine/helper/setup.c:671` `unshare(CLONE_NEWPID)` **deny** — a host pid cannot be named inside the new PID namespace
- Linux #307: `lab/fail-closed-linux/src/lib.rs:777` `LANDLOCK_SCOPE_SIGNAL at ABI 6; no PID namespace` **partial** — the guard unshares only CLONE_NEWUSER; a host signal is a named gap below ABI 6

Suggested fix (not applied): Give the C0 guard the same carrier #296 already uses: a PID namespace that contains the provider (lab/linux-confine/helper/setup.c:671). LANDLOCK_SCOPE_SIGNAL at ABI 6 is not a substitute for a host pid that still exists in the same namespace.

## What matched

These rows match on macOS, #296, and #307: `bound-executable` allow, `storage.root` allow, `outside.read` deny, `outside.write` deny, `network` deny, `exec.other` deny, `device.ioctl` deny.
