# B4 permission map

```text
Slice:        lab/b4-permission-map (M1 check B4, static half)
Branch / PR:  cursor/b4-permission-map-4cfd  (draft, base spike/agent-host)
Commit:       3168b10a6f1a0c58263ad65bde4d64a20e572e57   parent 042cb132371f77ce1b469af059e054bb7ef78295
Develop:      Elacity develop not merged: this PR only adds lab/b4-permission-map/
Machine:      Linux x86_64, kernel 6.12.94+, python3, rustc unused
```

## Invariant

The same declared rights for did, wallet, and model produce one comparison
table on macOS and on Linux. A right allowed on one platform and denied on
the other, or enforced on one and missing on the other, is a named mismatch
with `file:line` on both sides.

## What this lab reads

macOS, on this branch, unread-only:

- `capsules/{did,wallet,model}-provider/confine.sb`
- `capsules/{did,wallet,model}-provider/tests/fixtures/confine/declared-rights.json`
- the operations tables under `## Operations and the rights they need`

Linux, fetched by SHA (those folders are not on `spike/agent-host`):

- draft PR #296 `lab/linux-confine` at `2dc3c565c6649d668f1e50efefeea7d964330f9c`
- draft PR #307 `lab/fail-closed-linux` at `2c70a0d845f9acc15144a2afec889370612cca66`

C8 already owns the bridge-contract template. This lab consumes
`storage`, `bound-executable`, `startup-root-directory`, and
`startup-sysctl` from that template. It does not add a second one. The
other rows are the implicit denials of `(deny default)` and
`(deny network*)`.

## Mismatch list

30 rows, 5 families, on every provider. Full text is `MISMATCHES.md`.

| Right | macOS | Linux #296 | Linux #307 | Kind |
| --- | --- | --- | --- | --- |
| `storage.parent` | allow, `confine.sb` literal parent read | missing (did/model) or partial private remount (wallet) | missing | coverage |
| `startup-root-directory` | allow `/` (model: `file-read-data`) | missing: no Landlock rule on `/` | missing | coverage |
| `startup-sysctl` | allow `sysctl-read` | partial: `uname` and loader syscalls | missing | coverage |
| `unix-socketpair` | deny (`network*`) | allow AF_UNIX `socketpair` | deny `SYS_socketpair` | polarity + linux-split |
| `signal.host` | deny default | deny: `CLONE_NEWPID` | partial: no PID ns, `SCOPE_SIGNAL` at ABI 6 | coverage + linux-split |

Matched on every provider: `bound-executable` allow, `storage.root`
allow (eight-right mask `0x41be`), `outside.read` deny, `outside.write`
deny, `network` deny, `exec.other` deny, `device.ioctl` deny.

## Checker and falsifier

```text
python3 -I lab/b4-permission-map/check.py --write   -> wrote tables and MISMATCHES.md
python3 -I lab/b4-permission-map/check.py --check   -> tables and MISMATCHES.md match the sources
python3 -I -m unittest discover -s lab/b4-permission-map/tests -v
  -> 17 passed
python3 -I lab/b4-permission-map/check.py --plant lab/b4-permission-map/plants/macos-network-allow
  -> F-B4-MACOS-NETWORK-ALLOW CAUGHT (did-provider/network/polarity)
```

Falsifier: `plants/macos-network-allow/confine.sb` is a copy of the did
oracle with `(allow network*)` appended. The checker reports a polarity
mismatch against both Linux labs. A control copy without that line is
not a network CATCH.

## Not run here

- Linux x86-64 execution: **NOT RUN**
- Jetson aarch64 execution: **NOT RUN**
- macOS `sandbox-exec` execution: **NOT RUN**

This checker is static. It does not start a provider, install Landlock,
or run Seatbelt.

## What B4 still needs

B4 is not closed. The map names the gaps. It does not fix them.

1. One declared right for `STORAGE_PARENT`. Landlock cannot name a
   directory alone. #296 remounts a private parent for wallet only.
2. One baseline for `/` and `sysctl-read`, or drop them once a named
   test shows the Linux loader starts without those macOS grants.
3. One decision for AF_UNIX `socketpair`. #296 allows it for Tokio;
   macOS and #307 deny it.
4. One signal carrier. #296 uses a PID namespace. #307 unshares only
   `CLONE_NEWUSER` and sets `LANDLOCK_SCOPE_SIGNAL` at ABI 6.
5. Linux x86-64 and Jetson execution of the #296 / #307 launchers.
   Those stay with those labs and with the Linux matrix.
6. The Runtime generator that emits both profiles from the C8
   declared-rights input. That bridge is still not built.

Fixes belong in the owning folders. This lab does not apply them.

## Principles

- 3 No ambient authority: a right that one platform grants and the
  other omits is listed, not papered over.
- 10 One canonical path: the C8 template stays the one declared-rights
  source.
- 11 Fail closed: a planted network allow is CATCH; a missing pin is a
  read error.
- 12 Docs, code, tests agree: `--check` refuses a stale table.

## DeepSeek

none

## Questions

none
