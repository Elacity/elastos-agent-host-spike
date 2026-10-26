# Adversarial coverage review of PR #296 (C9 / B4)

Draft only. Do not merge. This folder does not edit `lab/linux-confine/`.

```text
Lane:         lab/review-c9-296
Branch:       cursor/review-c9-296-99c1
Base:         spike/agent-host
Reviewed:     Elacity/elastos-agent-host-spike#296
Head:         2dc3c565c6649d668f1e50efefeea7d964330f9c
Branch:       cursor/linux-confine-e156
Machine:      Linux x86_64 cloud VM
Aarch64:      NOT RUN
Jetson:       NOT RUN
```

## C9 wording used here

The M1 check text is not in this repo. The wording this review holds the PR to:

> C9 requires namespaces, capabilities, seccomp and Landlock, with permitted
> and denied rows per platform.

B4 is the permission-model table (permitted and denied operations). C9 is the
Linux enforcement of that table by the four layers.

## How the probes work

`probe.c` is freestanding. `run.py` launches it three ways:

1. Unconfined. Rows that succeed here prove the probe can see a hole.
2. Through #296 `lc-setup` on the short filter (the freestanding probe path).
3. Through #296 `lc-setup` with `mode=provider` (the filter the shipping
   binaries actually get).

`falsify.py` plants an unconfined socket success, a forged `result=ok` on a
must-deny row, and an `aarch64.rs` early `return`. Each plant must be caught.

Aarch64 and the Jetson stay NOT RUN. This runner does not register
`binfmt_misc` or qemu.

## Verdicts

Filled after the probe run on this machine. See the next commit if this file
still says pending.

| Claim | Verdict | Evidence |
| --- | --- | --- |
| Real did, wallet, and model debug binaries run under the Linux profiles | pending | |
| 5–6 permitted and 5 denied rows each | pending | |
| CapBnd of the confined provider is 0 | pending | |
| `--block-*` / `--explain-abi` compile only into `lc-setup-test` | pending | |
| STORAGE_ROOT stays at eight Landlock rights, mask `0x41be` | pending | |
| Denied rows prove denial by the intended layer | pending | |
| A skipped or not-run test is not counted as passed | pending | |
| Seccomp default action and arch filtering (x32 / i386) | pending | |
| Escape attempts listed below are refused | pending | |
| C9 wording (four layers + permitted and denied rows per platform) | pending | |

## Escape probes

ptrace, `/proc/self/mem`, mount, unshare, setns, keyctl, bpf, io_uring,
perf_event_open, symlink and `..` walks into storage, writable `/dev` nodes,
signals to host pids, abstract unix sockets, network, clone of a new process,
x32 sockets, unknown syscall numbers, i386 `int $0x80`.

## Concrete fixes

Filled after the run.

## Next

@irzhyran reviews #296 against this report. This PR stays draft.
