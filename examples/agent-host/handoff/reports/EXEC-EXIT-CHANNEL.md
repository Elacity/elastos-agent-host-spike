# Exec exit code from a channel the command cannot write

```text
Slice:        exec exit marker fix (spike only; not in Elacity develop). Sasha's rules of 21 Oct.
Branch / PR:  claude/exec-exit-channel  (draft PR in this repo, base spike/agent-host)
Commit:       584c55b8e0e39e6e3b971a7cbda52e6cdb6ca35c (design note, handoff/EXEC-EXIT-CHANNEL.md)
              12b92d9f8b39a9975fa4ade6ffc0ed1e074a36cb (code and tests)
              parent f5396709c286f1b8f8e2ac020b300395dd29999f (spike/agent-host); this report is the next commit
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0. No KVM, no Apple Virtualization.
Changed:      elastos/crates/elastos-compute/src/exec_vm.rs - EXEC_EXIT_PORT (1022), ExecRun, parse_exit_report,
                exec_result; begin_exec takes the code from the report only; parse_exec_console and EXEC_EXIT_MARK
                removed; tests
              elastos/crates/elastos-vz/tests/concurrent_launch.rs - boot_exec_command waits on the exit port, never on
                a console line; a kill_after option for the falsifier; new Mac test a_forged_exit_line_cannot_pass
              examples/agent-host/handoff/EXEC-EXIT-CHANNEL.md - the design note (first commit)
              examples/agent-host/handoff/reports/EXEC-EXIT-CHANNEL.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    An exec run's exit code comes only from the report init writes on vsock port 1022, which the command
              (unprivileged) cannot bind or reach. No report is "exit marker missing". The console is log only, and
              nothing reads a code or a stop signal from it.
Refusals:     no report (VM killed, init crashed, never connected)       -> "exit marker missing"
              a report that is not a canonical decimal i32 plus one "\n" -> "exit marker malformed"
              a host path in the log                                      -> "host path" (as before)
Tests run:    (cd elastos && cargo test -p elastos-compute --lib -- --include-ignored) -> "23 passed" (21 - 1 + 3)
              (cd elastos && cargo test -p elastos-vz --test concurrent_launch) -> "5 passed" (each skips on Linux:
                no Apple Virtualization)
              (cd elastos && cargo clippy -p elastos-compute -p elastos-vz --all-targets -- -D warnings) -> clean
Not run here: the signed VZ tests (exec_smoke_image_prints_hello, a_forged_exit_line_cannot_pass): Mac only, and
              they need the exec image change below.
New tests:    a_forged_console_line_with_the_vm_killed_fails (console has "elastos-exec-exit 0", no report)
              an_early_forged_line_does_not_end_or_decide_the_run (forged 0 early, report 1, later lines kept)
              the_exit_report_is_exact (0, 101, -1 accepted; 13 malformed forms refused)
              a_forged_exit_line_cannot_pass (Mac, needs the fake-exit fixture)
Falsifiers:   XE01 no report falls back to the console      -> a_forged_console_line_with_the_vm_killed_fails FAILED
              XE02 the console code wins over the report    -> both forged-line tests FAILED
              XE03 the log stops at the first marker-looking line -> an_early_forged_line_... FAILED
              XE04 the report is trimmed                     -> the_exit_report_is_exact FAILED
              XE05 a non-canonical number is accepted        -> the_exit_report_is_exact FAILED
              each restored; tree clean
              Mac (for Cursor, after the image change): put the old console stop back in boot_exec_command ->
                a_forged_exit_line_cannot_pass must fail; read the console when the report is missing -> its
                killed-VM half must fail.
Guest hash:   unchanged (no guest change).
Import list:  unchanged.
Principles:   3 and 18: the command proposes nothing about its own result; init, outside its privilege, reports.
              11: no report is a failure, never a fallback. 12: the docs, the code and the tests say the same.
DeepSeek:     none.
Not proven:   The exec image is not in this repo (Sasha's Mac, initrd-debian). Its init must bind vsock port 1022
              as root before the command, run the command as uid/gid 65534 with no capabilities and no_new_privs,
              and write "<code>\n" on one accepted connection. A fake-exit fixture command is needed for the Mac
              falsifier. Until the image changes, the signed test fails closed with "exit marker missing".
              crosvm on Linux is not tested here (no KVM).
Checklist:    no item moves.
Questions:    none.
```

**What is next:** Codex reviews this PR. The image change and the signed runs are on the Mac.
