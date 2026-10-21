# Exec exit code from a channel the command cannot write (design note)

Written 21 Oct 2026. Spike-only code: `exec_vm.rs` and its use in `concurrent_launch.rs` came in with spike commit
`bb64eee`; neither is in Elacity develop (`3beb816`). Rules from Sasha, 21 Oct.

## The problem

`elastos-compute/src/exec_vm.rs` (`parse_exec_console`) takes the exit code from any console line that starts with
`elastos-exec-exit `. The command's own stdout and stderr go to the same console.
- A command that prints `elastos-exec-exit 0`, then dies or is killed before init prints the real line, is
  reported as exit 0.
- Two different codes are refused, but a single forged one is accepted.
- The VM test harness (`elastos-vz/tests/concurrent_launch.rs`, `boot_exec_command`) stops the VM at the first such
  console line. So an early forged line also ends the run before the real result exists.

## Rules

1. The exit code comes **only** from a channel the command cannot write to. The console is log, and nothing is ever
   parsed out of it. No nonce in console text: the command could read it.
2. No report on that channel means failure, reason `exit marker missing`. Never fall back to the console.
3. The harness waits for, and stops on, that channel only.

## The channel: a reserved vsock port held by init

- **Guest (init and exec-supervisor in the exec image), in this order:**
  1. As root, before the command starts, bind vsock port `EXEC_EXIT_PORT = 1022`, and check that a second
     bind gets `EADDRINUSE`.
     - Linux reserves vsock ports below 1024 for a process with `CAP_NET_BIND_SERVICE` (`af_vsock.c`,
       `LAST_RESERVED_PORT`).
     - Once init holds the port, nothing else can bind it.
  2. Run the command as an unprivileged user (uid and gid 65534), with no supplementary groups, no capabilities
     (the bounding and ambient sets too) and `no_new_privs`. Each step is checked before the program runs.
     - It cannot bind a reserved port, cannot reach init's socket (`/proc/1/fd` is root's), and cannot signal PID 1.
     - The listening socket is close-on-exec, so the command never holds it.
  3. When the command ends (a command killed by a signal is 128 + the signal number), kill every process still
     running as 65534. Only then listen on the port, so no command process exists while a connection can be made.
     Accept the host's connection (peer CID 2), write the code as decimal ASCII plus `\n` (for example `0\n` or
     `101\n`), and wait for the host to close.
  4. Console output (`hvc0`) stays as it is, as log only.
- **Host (the launcher):**
  - After `start`, connect to the guest's port 1022 with `VzProvider::vsock_connect`, retrying until the deadline,
    because init may not be listening yet.
  - Read at most 16 bytes to end of stream, then stop the VM.
  - The launcher returns the console and these bytes separately (`ExecRun { console, exit_report }`).
- **Why the command cannot fake it:**
  - The host dials the guest, so the command cannot pose as the host.
  - The only socket that can accept that dial is init's, on a port the command can neither bind nor reach.
  - A command that kills the VM or init produces no report, and that is a failure.

## Host-side code in this PR (`exec_vm.rs`)

- `EXEC_EXIT_PORT = 1022`.
- `ExecLauncher::launch` returns `ExecRun { console: String, exit_report: Option<Vec<u8>> }`.
- `parse_exit_report`:
  - `None` gives `exit marker missing`;
  - anything but a canonical decimal `i32` followed by exactly one `\n` gives `exit marker malformed`.
- `exec_result(run)`:
  - takes the code from `parse_exit_report`;
  - the log is the console's non-empty lines, cut to the budget, with host paths refused as before;
  - it never reads a code from the console.
- `parse_exec_console` and `EXEC_EXIT_MARK` are removed.
- Harness (`boot_exec_command`): connects to port 1022 until the report arrives or 45 s pass; never looks at
  console lines to decide anything; stops the VM; builds `ExecRun`.

## Tests and falsifiers

**Cloud (`cargo test -p elastos-compute --lib exec_vm`).**

| Test | Falsifier |
| --- | --- |
| `a_forged_console_line_with_the_vm_killed_fails` (console has `elastos-exec-exit 0`, no report) gives `exit marker missing` | read the code from the console when the report is missing |
| `an_early_forged_line_does_not_end_or_decide_the_run` (console has a forged `0` early, more output after it, report `1\n`) gives exit 1 and keeps the later lines | stop the log at the first marker-looking line, or prefer the console code |
| `the_exit_report_is_exact` (`0\n`, `101\n` accepted; `""`, `0`, `0\n\n`, ` 0\n`, `+0\n`, `00\n`, `0x1\n`, `1\nx` refused) | trim or loosely parse the report |

**Mac (signed VZ test, needs the image change below).**

| Test | Falsifier |
| --- | --- |
| `exec_smoke_image_prints_hello` passes with the report channel | stop on a console line |
| `a_fake_exit_line_does_not_end_the_run`: image command `fake-exit` prints `elastos-exec-exit 0`, sleeps, then exits 1; the run reports 1 and the log holds the line after the fake | stop on the console line |
| `a_killed_vm_after_a_fake_line_fails`: stop the VM right after the fake line appears; the result is `exit marker missing` | fall back to the console |

## The exec image (in this PR since Cursor's review, 21 Oct)

- `examples/exec-image/supervisor`: the static Rust supervisor (aarch64-unknown-linux-musl, `libc` only), and
  `build-linux.sh` to build it on the Mac with Rust's lld.
- `examples/exec-image/init`:
  - loads `virtio_pci_legacy_dev`, `virtio_pci_modern_dev`, `virtio_pci`, `virtio_mmio`, `virtio_console`,
    `vsock`, `vmw_vsock_virtio_transport_common` and `vmw_vsock_virtio_transport`, in that order;
  - runs the `elastos.exec=` command through the supervisor (`true`, `false`, `test-pass`, `test-fail`,
    `test-edited`, `note`, `files`); anything else prints `init: command refused` and reports 1;
  - test fixtures: `fake-exit`, `probe-bind`, `probe-report`, `kill-self`;
  - no console exit line.
- `scripts/build/build-exec-initrd.py`: a newc cpio initramfs.
  - Uid 0 for every entry; `/tmp` mode 1777; the same inputs give the same bytes.
  - Every input is a path argument.
  - It checks that the binaries are static aarch64 ELFs, and each module's vermagic. A module that is built in is
    skipped, and `.ko.xz` is unpacked.
- **In-image falsifiers**, run as the command:
  - `probe-bind` must get `EACCES` on port 1022;
  - `probe-report` tries to write a forged `0` and leaves a process behind that keeps trying, then exits 3, so the
    report must be 3;
  - `kill-self` must report 137.

## Not in this PR

- **crosvm on Linux.** The same port on the crosvm vsock device. Untested here: no KVM in the cloud.
