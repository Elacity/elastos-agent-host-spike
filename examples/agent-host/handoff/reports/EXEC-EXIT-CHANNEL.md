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

## Update: the exec image recipe, after Cursor's review (21 Oct)

Cursor found the gap: the image recipe was only on Sasha's Mac. There, the command ran as root, no vsock modules
were loaded, and BusyBox cannot hold a vsock socket. The image is now in the repo.

```text
Commits:      2a25174 supervisor, init, initramfs builder, Mac fixture test
              690b6e4 supervisor tests wait a bounded time (falsifier SV07 hung the test instead of failing it)
              this section is the next commit
Changed:      examples/exec-image/supervisor/ (Cargo.toml, Cargo.lock, build-linux.sh, src/main.rs, tests/supervisor.rs)
              examples/exec-image/init
              scripts/build/build-exec-initrd.py, scripts/build/test_build_exec_initrd.py
              elastos/crates/elastos-vz/tests/concurrent_launch.rs - the fixture test also boots probe-bind,
                probe-report and kill-self
              examples/agent-host/handoff/EXEC-EXIT-CHANNEL.md - the image section, and the order: bind, run, reap,
                then listen
Supervisor:   as root:
                - bind vsock 1022, and check that a second bind gets EADDRINUSE;
                - fork the command: setsid; stdout and stderr on the console (opened before the drop); stdin
                  /dev/null; ambient set cleared; bounding set dropped; setgroups([]); setresgid and setresuid
                  65534; no_new_privs; capset to zero; then every one of these checked (ids, groups,
                  no_new_privs, capget, bounding and ambient); any miss is code 126 before the program runs;
                  exec failure is 127;
                - wait; a signal is 128 + its number;
                - kill everything still running as 65534 (kill(-1) from a 65534 helper; orphans come back to the
                  supervisor as child subreaper; /proc is checked for live 65534 processes);
                - only then listen, accept peer cid 2, write "<code>\n", and wait for the host to close.
Init:         - modules in Cursor's order (a built-in one is skipped at build time), then wait for /dev/hvc0;
              - elastos.exec= from /proc/cmdline: true, false, test-pass, test-fail, test-edited (vm-smoke
                --exact ... --nocapture), note ("project note <notes.txt>"), files ("project file <name>");
                anything else is "init: command refused" with code 1;
              - fixtures: fake-exit, probe-bind, probe-report, kill-self;
              - no console exit line; poweroff -f at the end.
Builder:      newc cpio, uid/gid 0, mtime 0, /tmp 1777, /root 0700, /dev/console and /dev/null nodes, padded to 512;
              the same inputs give the same bytes. Inputs: --busybox --modules-dir --vm-smoke --supervisor --project
              --output [--init] [--kernel-release 6.1.0-50-arm64].
              Refused: a binary that is not a static aarch64 ELF; a module that is missing (and not built in), in
                a second place, zstd or gzip packed, or built for another release; a project file that is
                missing; an init that prints an exit line (other than the fake-exit fixture).
              It prints the demo digests: a1097f0d... and project-edited 8256365b... (both checked here against the
                vm-smoke formula).
Tests run:    (cd examples/exec-image/supervisor && cargo test --offline) -> "7 passed" (as root here; real vsock
                for the port rules; the report on a Unix socket open to everyone, because vsock loopback does not
                connect in this container)
              (cd examples/exec-image/supervisor && cargo clippy --offline --all-targets -- -D warnings) -> clean
              RUSTFLAGS="-C linker=<sysroot>/lib/rustlib/<host>/bin/gcc-ld/ld.lld" cargo build --locked --release
                --target aarch64-unknown-linux-musl -> "ELF 64-bit LSB executable, ARM aarch64, statically linked",
                443 KB
              python3 -m unittest scripts/build/test_build_exec_initrd.py -> "Ran 8 tests ... OK"
              sh -n examples/exec-image/init -> ok
              (cd elastos && cargo test -p elastos-vz --test concurrent_launch) -> "5 passed" (skip on Linux); clippy
                clean
Supervisor tests (native, root):
              a_command_runs_unprivileged_and_its_code_is_reported (Uid/Gid 65534 x4, Groups empty, CapInh, CapPrm,
                CapEff, CapBnd and CapAmb all 0, NoNewPrivs 1; report 7)
              a_command_killed_by_a_signal_is_not_reported_as_zero (137)
              the_command_cannot_bind_the_exit_port (EACCES; the port is held, a second bind is EADDRINUSE)
              a_forged_report_never_reaches_the_host (report 3; no forged write lands; no process of the command is
                left running)
              no_report_is_served_before_the_command_ends
              a_program_that_cannot_run_reports_127
              nothing_runs_unless_the_exit_port_is_held (the command never runs; no report)
Falsifiers:   SV01 the bounding set is kept (drop and check)  -> a_command_runs_unprivileged_... FAILED
              SV02 the command stays root                     -> same FAILED
              SV03 no_new_privs is not set (set and check)     -> same FAILED
              SV04 a killed command reports 0                  -> a_command_killed_by_a_signal_... FAILED
              SV05 the report does not wait for the command    -> 6 tests FAILED
              SV06 processes left by the command keep running  -> a_forged_report_never_reaches_the_host FAILED
              SV07 the exit port is never bound                -> 7 tests FAILED (after 690b6e4, without hanging)
              BI01 /tmp is not sticky                          -> test_the_image_has_every_piece_owned_by_root FAILED
              BI02 modules load in reverse order               -> test_modules_load_in_the_given_order_... FAILED
              BI03 vermagic is not checked                     -> test_wrong_inputs_stop_the_build FAILED
              BI04 a dynamic ELF is accepted                   -> test_wrong_inputs_stop_the_build FAILED
              BI05 entries are not owned by root               -> test_the_image_has_every_piece_owned_by_root FAILED
              BI06 an init that prints an exit line is accepted -> test_an_init_that_prints_an_exit_line_is_refused
                FAILED
              each restored; tree clean
Not run here: the image itself, and the vsock handshake to the host, the peer CID check, and the fixtures in a
              real VM. They need the Mac (below).
```

### Build and run on the Mac

From the repo root, on the #27 branch.

```sh
IMG=~/code/elastos-exec-image          # where the exec image files live
DEB=$IMG/debian-kernel/linux-image-6.1.0-50-arm64.deb     # 6.1.176-1, sha256 914f75b5...0f06
BUSYBOX=~/.local/share/elastos/cross/aarch64/bin/busybox  # the static aarch64 BusyBox used for rootfs.ext4

# 1. Kernel modules from the Debian package (the same one vmlinux-debian came from).
shasum -a 256 "$DEB"
mkdir -p "$IMG/deb" && (cd "$IMG/deb" && ar x "$DEB" && tar -xf data.tar.*)
MODULES="$IMG/deb/lib/modules/6.1.0-50-arm64"

# 2. The two static aarch64 programs.
rustup target add aarch64-unknown-linux-musl
examples/vm-smoke/build-linux.sh
# Cargo writes to $CARGO_TARGET_DIR (target-build on Sasha's Mac), else examples/vm-smoke/target.
VM_SMOKE=$(ls -t "${CARGO_TARGET_DIR:-examples/vm-smoke/target}"/aarch64-unknown-linux-musl/release/deps/vm_smoke-* | grep -v '\.d$' | head -1)
SUPERVISOR=$(examples/exec-image/supervisor/build-linux.sh | tail -1)
file "$BUSYBOX" "$VM_SMOKE" "$SUPERVISOR"   # all: ELF 64-bit ARM aarch64, statically linked

# 3. The initramfs.
python3 scripts/build/build-exec-initrd.py \
  --busybox "$BUSYBOX" --modules-dir "$MODULES" --vm-smoke "$VM_SMOKE" \
  --supervisor "$SUPERVISOR" --project examples/vm-smoke/project \
  --output "$IMG/initrd-exec"
# It prints the module list and "project demo a1097f0d..." / "project-edited demo 8256365b...".

# 4. The signed VZ tests (from elastos/, so a relative or an absolute test path both work).
cd elastos
cargo test -p elastos-vz --test concurrent_launch --no-run 2>&1 | tee /tmp/vz-build.txt
TEST_BIN=$(sed -n 's/.*Executable tests\/concurrent_launch.rs (\(.*\))/\1/p' /tmp/vz-build.txt)
../scripts/dev/sign-elastos-vz/sign.sh "$TEST_BIN"
ELASTOS_EXEC_KERNEL="$IMG/vmlinux-debian" ELASTOS_EXEC_ROOTFS="$IMG/rootfs.ext4" \
ELASTOS_EXEC_INITRD="$IMG/initrd-exec" ELASTOS_EXEC_FAKE_EXIT=1 \
  "$TEST_BIN" --exact exec_smoke_image_prints_hello a_forged_exit_line_cannot_pass \
  --nocapture --test-threads=1
```

**Mac falsifiers (Cursor)**, each must make a test fail, then revert:
- put the console stop back in `boot_exec_command` -> `a_forged_exit_line_cannot_pass`;
- read the console when the report is missing (`exec_result`) -> the killed-VM half;
- in `init`, run the commands as root: replace `/sbin/exec-supervisor run --` with a direct run that writes the
  code itself -> `probe-bind`;
- drop the peer CID check in `serve_vsock` -> `probe-report`. Expected to survive on hardware: see "Peer CID check:
  defence in depth" below.

## Mac proof (Cursor, 21 Oct, at 088ff76ba): PASS

```text
Build:        modules from the pinned deb (sha256 914f75b5...0f06 checked); supervisor a static aarch64 ELF;
              initrd-exec sha256 aefe8a1a...d198; project digests a1097f0d... and 8256365b..., as printed here.
Signed tests: exec_smoke_image_prints_hello and a_forged_exit_line_cannot_pass -> 2 of 2 pass.
              probe-bind gets EACCES; the probe-report forgery ends with code 3; kill-self reports 137.
Falsifiers:   the supervisor skips the privilege drop         -> caught (concurrent_launch.rs:1023)
              exec_result reads the console without a report  -> caught (:1013)
              the harness stops on a console marker line       -> caught (:998, "exit marker missing")
              the peer CID check in serve_vsock is removed     -> SURVIVES, as expected (below)
              all reverted; a clean rerun passes 2 of 2.
```

### Rerun after the Codex fixes (Cursor, 21 Oct, at 7b9a14a19): PASS

```text
Build:        the new ELF parser accepted the real inputs: the Debian 6.1.0-50 modules, BusyBox, vm-smoke and
              exec-supervisor. initrd-exec sha256 2613f622...212d (new: the supervisor changed). Project digests
              unchanged (a1097f0d... and 8256365b...).
Signed tests: exec_smoke_image_prints_hello and a_forged_exit_line_cannot_pass -> 2 of 2 pass.
              probe-bind gets EACCES; the probe-report forgery ends with code 3.
```

### Peer CID check: defence in depth

`serve_vsock` accepts a report connection only from CID 2 (the host). On the Mac, removing that check fails no test.
That is expected, because the check has nothing to stop there:
- The supervisor listens on port 1022 only after the command has ended and every process left running as 65534
  has been killed.
- So while a connection can be made, no command process exists in the guest to make it.
- The guest also has no vsock loopback transport (`vsock_loopback` is not loaded), so a guest process cannot reach
  its own port in any case.

The check stays as a second line. It covers a future image that loads a loopback transport, or a change that
listens earlier. Its falsifier is recorded as surviving on hardware by design. The order bind, run, reap, then
listen is the primary guard, and three falsifiers pin it:
- SV05: the report does not wait for the command;
- SV10 (was SV06; its code line changed): processes left by the command keep running;
- SV08 and SV09 (below): a cleanup that cannot be confirmed still reports;
- the Mac `probe-report` run, which leaves a process behind that keeps trying.

## Codex review at 4b79c71ab: FAIL, two findings, both fixed

```text
Commits:      7be5df194dfa97e62fb6e9fc72c66c546726ff84 (both fixes and their tests)
              419fa15cdd4168b4b21dc09ce379aac736a1e4ea (one more builder case, after falsifier BI16 survived)
              this section is the next commit
Finding 1:    A cleanup that could not be confirmed still let the supervisor listen and report the command's code.
Fix 1:        kill_everything_unprivileged() returns whether /proc shows no live 65534 process, after at most 5
              rounds. If not: console "exec-supervisor: cleanup failed; no report", no listen, no report, exit 1.
              The host then fails with "exit marker missing".
Test 1:       a_process_that_survives_cleanup_means_no_report: a 65534 process (setpriv) outside the
              supervisor's PID namespace (unshare --pid --fork) survives every kill(-1); /proc still shows it.
              The command exits 0; the report must be None, the console must hold the line, and the supervisor's
              status must not be 0.
Failing first: before the fix: "left: Some("0\n") right: None" (a report of 0 was served).
Finding 2:    The builder took any file with an AArch64 machine field and no PT_INTERP as a program, and any file
              holding "vermagic=<release> " as a module. Codex's probes: a bare ET_REL header as the supervisor; a
              module for another machine; a text file holding the vermagic string.
Fix 2:        ELF parsing, no substring search.
              Programs: ELFCLASS64, little-endian, version 1, EM_AARCH64 (183), ET_EXEC or ET_DYN (static-pie),
                e_entry not 0, whole program headers (56 bytes each, inside the file), at least one PT_LOAD whose
                bytes lie inside the file, no PT_INTERP.
              Modules: the same header checks, ET_REL, section headers inside the file (64 bytes each, shstrndx
                in range), every section inside the file (except NOBITS), the name table a STRTAB, exactly one
                section named ".modinfo", exactly one "vermagic=" entry in it (ASCII); its first word must be the
                kernel release.
Tests 2:      Codex's probes: test_a_bare_relocatable_header_is_not_a_program,
                test_a_module_for_another_architecture_is_refused, test_a_text_file_with_the_vermagic_is_not_a_module
              more: test_a_vermagic_outside_modinfo_does_not_count, test_a_module_must_be_relocatable,
                test_a_module_with_section_headers_past_its_end_is_refused,
                test_a_program_needs_an_entry_a_loadable_segment_and_whole_headers (entry 0; only PT_DYNAMIC;
                cut inside the program headers; cut inside the PT_LOAD; ET_REL; type 4),
                test_a_static_pie_program_is_accepted (ET_DYN with PT_LOAD and PT_DYNAMIC builds)
              The test fixtures are now real ELF: programs with program headers, modules as ET_REL with
                .modinfo, .data and .shstrtab section headers.
Failing first: before the fix: "Ran 16 tests ... FAILED (failures=7)": the 7 refusal tests built.
Real files:   the real exec-supervisor, cross-built here for aarch64-unknown-linux-musl (ET_EXEC, static), is
              accepted; a clang --target=aarch64-linux-gnu object with a .modinfo section gives its vermagic;
              the same object for x86-64 is refused (machine 62); /bin/ls (x86-64) is refused. The real Debian
              modules were not read here (the deb is on the Mac).
Tests run:    (cd examples/exec-image/supervisor && cargo test --offline) -> "8 passed" (root, real vsock)
              (cd examples/exec-image/supervisor && cargo clippy --offline --all-targets -- -D warnings) -> clean;
                cargo fmt --check -> clean
              python3 -m unittest scripts/build/test_build_exec_initrd.py -> "Ran 16 tests ... OK"
Falsifiers:   SV08 a failed cleanup still reports (drop the return)  -> a_process_that_survives_cleanup_... FAILED
              SV09 cleanup is trusted without checking /proc          -> a_process_that_survives_cleanup_... FAILED
              SV10 cleanup is skipped (replaces SV06)                 -> a_forged_report_never_reaches_the_host and
                                                                         a_process_that_survives_cleanup_... FAILED
              BI03 the release is not compared                        -> test_wrong_inputs_stop_the_build FAILED
              BI07 the vermagic substring search is back              -> 6 tests FAILED (Codex's 2 module probes,
                                                                         and 4 more)
              BI08 the machine is not checked                         -> test_a_module_for_another_architecture_...
                                                                         and test_wrong_inputs_stop_the_build FAILED
              BI09 a module need not be relocatable                   -> test_a_module_must_be_relocatable FAILED
              BI10 a program of any type is accepted                  -> test_a_program_needs_... FAILED
              BI11 a program needs no PT_LOAD                         -> test_a_program_needs_... FAILED
              BI12 section headers past the end are not checked       -> test_a_module_with_section_headers_... ERROR
                                                                         (the parse then crashes on struct.error)
              BI13 a program needs no entry point                     -> test_a_program_needs_... FAILED
              BI14 vermagic is read from the whole file, not .modinfo -> test_a_vermagic_outside_modinfo_... FAILED
              BI15 static-pie is refused                              -> test_a_static_pie_program_is_accepted FAILED
              BI16 a PT_LOAD past the file is accepted                -> SURVIVED first; after 419fa15 the
                                                                         cut-inside-the-PT_LOAD case FAILED
              BI17 program headers past the file are not checked      -> test_a_program_needs_... ERROR
              SV01-SV05, SV07, BI01, BI02, BI04-BI06 rerun: each still FAILED; each restored; tree clean
              Codex's bare-header probe is caught by the type check (BI10), and by the entry and PT_LOAD checks.
Guest hash:   unchanged (no guest change).
Principles:   11: a cleanup that is not confirmed is a failure, never a report. 12: the builder checks what it
              says it checks.
DeepSeek:     none.
Mac:          the initrd changes (new supervisor). Rebuilt and rerun by Cursor at 7b9a14a19: PASS, and the real
              Debian modules and static binaries build as before (see "Rerun after the Codex fixes" above).
```

## Codex review at a679e5d3: FAIL, one finding, fixed

```text
Commits:      aec9d37 (the fix and its tests), e7259bc (one more case, after falsifier BI11 survived)
              this section is the next commit
Finding:      The program check accepted a PIE that needs a shared library: a linker-made AArch64 ET_DYN with
              valid PT_LOADs, no PT_INTERP and DT_NEEDED libmissing.so was packed.
Reproduced:   clang --target=aarch64-linux-gnu -fPIE -pie -nostdlib -fuse-ld=lld -Wl,--no-dynamic-linker
              -L. -lmissing -> "ELF 64-bit LSB pie executable, ARM aarch64", NEEDED [libmissing.so], 2.7 KB;
              static_aarch64_elf accepted it.
Fix:          PT_DYNAMIC is parsed. At most one; it must lie inside a PT_LOAD (so inside the file); its 16-byte
              entries are read up to DT_NULL, and a table with no DT_NULL is refused; DT_NEEDED, DT_RPATH and
              DT_RUNPATH are refused. The same rule holds for ET_EXEC. ET_DYN is accepted only as a true
              static-pie.
Tests:        test_a_pie_that_needs_a_library_is_refused (Codex's probe, built by clang and lld when present;
                they are here, so it ran; the same program without the library must still build)
              test_a_program_with_external_dependencies_is_refused (DT_NEEDED, DT_RPATH, DT_RUNPATH, each for
                ET_DYN and ET_EXEC)
              test_a_dynamic_table_must_be_whole_and_loaded (no DT_NULL; cut inside the table; not inside a
                PT_LOAD; two PT_DYNAMIC)
              test_a_static_pie_program_is_accepted now carries a real dynamic table (DT_RELA, DT_NULL)
              the program test gains a PT_NOTE-only case (no PT_LOAD and no PT_DYNAMIC)
Failing first: before the fix: "Ran 19 tests ... FAILED (failures=3)": the three new tests.
Real files:   the real exec-supervisor (aarch64 musl, ET_EXEC) is accepted; the clang static PIE (ET_DYN, no
              NEEDED) is accepted; Codex's probe is refused: "needs a shared library (dynamic tag 1)".
Tests run:    python3 -m unittest scripts/build/test_build_exec_initrd.py -> "Ran 19 tests ... OK" (none skipped)
Falsifiers:   BI18 DT_NEEDED is not refused               -> the probe test and the dependencies test FAILED
              BI19 DT_RPATH and DT_RUNPATH are not refused -> test_a_program_with_external_dependencies_... FAILED
              BI20 the table need not be in a PT_LOAD      -> test_a_dynamic_table_must_be_whole_and_loaded FAILED
              BI21 the table needs no DT_NULL              -> test_a_dynamic_table_must_be_whole_and_loaded FAILED
              BI22 two tables are accepted                 -> test_a_dynamic_table_must_be_whole_and_loaded FAILED
              BI23 PT_DYNAMIC is not read at all           -> 3 tests FAILED
              BI11 (no PT_LOAD needed) SURVIVED after the fix: its fixture had only a PT_DYNAMIC, which the new
                check also refuses. e7259bc adds a PT_NOTE-only case; BI11 then FAILED.
              BI01-BI17 rerun: each FAILED; each restored; tree clean.
              The fix dropped one redundant bound (the table past the end of the file): inside a PT_LOAD is
              already inside the file.
Guest hash:   unchanged (no guest change). The supervisor is unchanged, so the initrd should be the same
              2613f622...212d if the inputs are.
Principles:   12: "static" now means no external dependency, as the docs say.
DeepSeek:     none.
Mac:          rerun the builder on the real inputs (the supervisor and vm-smoke must still pass), then the
              signed tests.
```

**What is next:** Sasha reruns the Mac build and proof, then Codex re-reviews #27. #24 is being fixed in parallel.
