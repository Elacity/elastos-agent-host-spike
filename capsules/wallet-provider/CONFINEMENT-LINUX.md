# The Linux design for the one file-profile contract

The lab contract that `did-provider`, `wallet-provider` and `model-provider`
present is the one file-profile contract: `check_profile_contract`, run over
`FILE_PROFILES` in `tests/confine.rs`, with `(version 1)` first,
`(deny default)` second, an explicit `(deny network*)`, no `(allow default)`,
no network allow, only the `PROVIDER_EXECUTABLE`, `STORAGE_ROOT` and
`STORAGE_PARENT` tokens, and the three shared rules verbatim.
This contract's current Linux behaviour is the seccomp allow list in "The
seccomp allow list" below, and the file-row installer in "The file row". The
seccomp part is a generated allow list and a recorded wallet Linux run in which
the refused calls answer the filter's own marker. The did caller uses the same
path and awaits the policy decision described under "The kernel proof". The
file-row installer is the one Linux launch: it installs the Landlock ruleset
and then the seccomp filter, and the one record carries a Landlock step. The
file row of "The contract on Linux" is GAP. This session recorded no run that
names the host, the kernel and the ABI the kernel reported, so that row is not
written as passing.
`confine.sb` stays each provider's one oracle. The contract is shared, so its
Linux mapping is written once here, beside the one contract check (P10). The
Linux policy that the Runtime would generate from the same approved declared
rights must carry each oracle rule as this file maps it, and no second profile
file exists (P10).

## The seccomp allow list

One part of this design exists today as source for both providers: a seccomp
allow list generated from each provider's own declared rights. Wallet supplies
the recorded Linux proof of the four denied calls; did compares its full
program with wallet's and awaits acceptance of its operation journey.
Namespaces and the capability drop stay unbuilt. The file-row installer is in
the harness, and the contract file row is GAP until a recorded run names the
host, the kernel and the reported ABI. A seccomp filter is the Linux
confinement this lab has recorded.

One function builds the list:
`seccomp_allow_list_from_declared_rights(name, declared)` in
`capsules/wallet-provider/tests/confine.rs` calls `generate_profile`, the one lab
generator, reads the profile text back through `profile_forms`, the one profile
parser, and maps each allow form through one table. It reads no file, holds no
rule text of its own and never reads the declared-rights JSON: `declared_entries`
reaches it only through `generate_profile`, so the JSON has one reader and the
profile one parser (P10). It holds no per-provider branch, so `did-provider` and
`wallet-provider` reach the same builder.

One helper turns a provider name into the list it would launch:
`seccomp_probe_list(name)` reads that provider's committed declared-rights file,
calls the one builder and then `with_launch_essentials`. Both journeys take their
list from it, so there is one file-to-list path and no second one for the second
provider. The named test `seccomp_allow_list_names_the_provider_it_was_built_for`
asks it for both providers, requires each list's `provider` field to be the name
it asked for, and requires it to refuse a name whose file cannot be read with the
reader's own reason. The test starts no process and makes no kernel call, so it
runs on every OS.

The filter is an allow list. Its final decision is the deny marker
`SECCOMP_RET_ERRNO` with `EACCES` (13), and every `SECCOMP_RET_ALLOW` return sits
behind an equality test against a syscall number the list names, so a changed
jump target fails even when the number is right. A call the list does not name is
refused by the default arm. That is what closes the 0710 fault class, in which
every call a list does not name is permitted.

`SECCOMP_RULE_SYSCALLS` is the one mapping table, keyed on the allow-form text.
It holds exactly one row for each of the five allow forms a wallet profile
carries:

| Allow form | Syscalls the row admits |
| --- | --- |
| `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))` | `execve`, `execveat` |
| `(allow file-read* (literal (param "STORAGE_PARENT")))` | `faccessat`, `fstat`, `getdents64`, `lseek`, `newfstatat`, `openat`, `openat2`, `pread64`, `read`, `readlinkat`, `readv`, `statx` |
| `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))` | the file-read row, plus `fchmod`, `fdatasync`, `fsync`, `ftruncate`, `linkat`, `mkdirat`, `pwrite64`, `renameat2`, `unlinkat`, `write`, `writev` |
| `(allow file-read* (literal "/"))` | the file-read row |
| `(allow sysctl-read)` | `uname`, `sysinfo` |

The head forms (`(version 1)`, `(deny default)`) and the deny forms grant
nothing, so they take no row and add no syscall. An allow form with no row is a
refusal that names the provider and the form and builds no filter, symmetrical
to `check_profile_contract`'s refusals. The one recogniser that decides what an
allow form is, `is_allow_form`, reads `(allow)`, `(allow(file-read*))` and
`(allow file-read*)` as allow forms; the three allow predicates and
`allow_forms` call it, so the rule has one spelling.

The table is the only source of the list's declared syscalls, so a declaration
with no allow form yields an empty list and a program whose only decisions are
the two ABI guards and the deny marker. A launch additionally needs the measured
set below, which no declared right covers. That set joins the list in exactly one
place, `SeccompAllowList::with_launch_essentials`, and the launcher and the probe
child both install the result through the one `install_seccomp`, so there is one
list and one install path (P10).

`LAUNCH_ESSENTIALS` is measured, not guessed, on the Linux host the proof ran on:
each entry was dropped alone from the whole list, the probe re-run, and the call
that then failed named it. The set is one table for both providers, and the two
runs measured it separately: wallet's set of seven calls is the table below, and
did's recorded set is the same seven. That did measurement used the wider
`fchmodat` policy described below; it proves no complete did journey under
wallet's preserved policy. Both providers use the same launch table:

| Entry | The call whose refusal named it |
| --- | --- |
| `close` | `close(3)` in the loader, refused before the first mapping |
| `exit_group` | `exit_group(0)`, refused as the provider ended its own run |
| `getrandom` | `getrandom(0xec92ac7c6700, 8, GRND_NONBLOCK)` in the loader |
| `mmap` | `mmap(NULL, 8192, PROT_READ\|PROT_WRITE, MAP_PRIVATE\|MAP_ANONYMOUS, -1, 0)` in the loader, after which the provider took `SIGSEGV` |
| `mprotect` | `mprotect(0xf2640329f000, 65536, PROT_NONE)` in the loader |
| `ppoll` | `ppoll([{fd=0, events=0}, {fd=1, events=0}, {fd=2, events=0}], 3, {tv_sec=0, tv_nsec=0}, NULL, 0)` while the provider waits |
| `rt_sigaction` | `rt_sigaction(SIGPIPE, {sa_handler=SIG_IGN, sa_mask=[PIPE], sa_flags=SA_RESTART}, 0xffffea09ff80, 8)` in the loader |

Four calls are in no row and in no launch entry, so the default decision is the
only answer they receive: `ptrace`, `mount`, `bpf` and `keyctl`. The named test
`seccomp_program_denies_by_default_and_lists_no_undeclared_call` asserts each of
the four is in no list entry and no table row and is tested by no equality in
the program, so adding one to a row turns it red. The filter's marker errno is
`EACCES` rather than `EPERM` on purpose: a host can already answer `EPERM` for a
call an unprivileged process may not make, so a plain `EPERM` assertion would
pass with no filter installed.

`install_seccomp_with(allow, steps)` is the one step sequencer and makes no
kernel call. It checks the audit architecture first, then runs
`NoNewPrivileges` and `Filter` in that order, and stops at the first failure with
that step's own reason and errno. `install_seccomp(allow)` is the one function
that makes the two kernel calls, and it copies the program into a fixed stack
buffer so it allocates nothing after a fork.
`seccomp_launch_refuses_each_reporting_failure` covers the record writer, which
completes a short write and retries on `EINTR`, and gives a failed write and a
zero-byte write distinct reasons and errnos.
`seccomp_launch_record_refuses_missing_or_unknown_report` covers the record
reader: a record that is missing, short, long or names an unknown step is a
refusal with its own reason, never a bare spawn error. It also covers the
launcher's own answer through `seccomp_launch_answers_or_refusal`, the one place
a record becomes a launch result: a child that never wrote a record, because its
own write failed or because it never ran, keeps the record's reason and adds what
the child did instead, so that reason is never lost behind a bare spawn error.

`seccomp_keyctl_probe_supplies_every_argument_without_creation` covers the probe's
`keyctl` request, whose first three arguments are `KEYCTL_GET_KEYRING_ID`
(command `0`), the session keyring, a create flag of `0` that asks for no keyring
to be created, and two unused zeros. One table, `SECCOMP_PROBE_KEYCTL_TABLE`,
holds all five, and the test reads both the table and the call, so a call that
passed fewer arguments than the kernel reads fails even though it compiles.

### The kernel proof

Two named tests, one body. `linux_wallet_journey_runs_under_the_seccomp_allow_list`
and `linux_did_journey_runs_under_the_seccomp_allow_list` are two thin callers of
one function, `seccomp_confined_journey(name, binary, declared, test_name)`: each
passes its own provider name, that provider's own binary, its own committed
declared-rights value and its own test name. There is one journey body, one
launcher, one list helper and one probe, and no copy per provider (P10).

The recorded runs used host `spark1.local`: `aarch64`, Ubuntu 24.04.4, kernel
`6.17.0-1029-nvidia`, 20 cores, unprivileged. The did run used an added syscall
permission, as described below. Each test builds the list from its own
provider's committed declared-rights file through `seccomp_probe_list` and starts
that provider through `standin_spawn_confined_provider` with a `Seccomp` policy,
which reaches `ConfinedProvider::start_under_seccomp` and its one `spawn`.

The wallet run requires `init` `ok`, one read-only wallet call `ok`, a
`wallet-key.hex` of 64 hex digits and a newline under `STORAGE_ROOT`, no profile
written, and the named sibling `seccomp-outside-write` outside `STORAGE_ROOT`
absent after the run. The file evidence is those named fixture paths; a seccomp
filter carries syscall policy, not path policy, so no run claims a general file
boundary.

The did run requires its permitted operations under the filter, through
`did_standin_permitted_operations` and `assert_suite_outcomes` against the
permitted prefix of `DID_SUITE_CASES`: `init` `ok`, `get_did` `ok` with a
`did:key:` value, `resolve` `ok` on that DID, `set_nickname` `ok`, `get_nickname`
returning `Confined`, and `get_persona_did` `ok`. Its `STORAGE_ROOT/seccomp-inside-write`
fixture must equal `b"did seccomp journey fixture\n"`, the encrypted nickname
`did/nickname.enc` must keep the bytes `set_nickname` wrote, and the named sibling
`seccomp-outside-write` outside `STORAGE_ROOT` must be absent. The did suite's
file-denial cases stay in the B3 and C0 journeys, because a seccomp filter cannot
make them fail. Both callers create the fixed-byte fixture before their
operation suites and call `assert_seccomp_journey_files` after shutdown.
`seccomp_journey_file_comparison_catches_corruption_for_each_provider` exercises
that one comparison for both providers with a changed inside file, a changed
fixed-byte fixture and a present outside sibling.

The list each journey asserts about itself: its `provider` field is the name it
asked for, and its `program` equals the program built the same way for wallet.
That equality follows from the two committed declared-rights files declaring the
same two rights and the same two `platform-baseline` ids with identical rule text,
so a difference would be a per-provider widening and the assertion fails on it.

The earlier did run measured `LAUNCH_ESSENTIALS` on its own binary, entry by entry,
by dropping each entry alone from the whole list and reading what then failed. All
seven entries are did's too, so the set is one table and needed no per-provider
row. The failing call was: `close` → `libgcc_s.so.1: cannot close file
descriptor`; `exit_group` → the wait found no clean exit; `getrandom` → a panic
inside `rand`'s thread RNG, which cannot seed; `mmap` → `SIGSEGV`; `mprotect` →
`libgcc_s.so.1: cannot change memory protections`; `ppoll` → `SIGTRAP`;
`rt_sigaction` → `fatal runtime error: assertion failed: signal(libc::SIGPIPE,
handler) != libc::SIG_ERR`.

The did journey is blocked by wallet's preserved syscall policy. The recorded
run failed with `the confined provider must return the stored nickname` and
`{"code":"not_set"}`. Its trace showed
`fchmodat(AT_FDCWD, "<root>/did/nickname.enc", 0600) = -1 EACCES` when
`set_nickname` set the file mode. The earlier successful did run added
`fchmodat` to the shared storage row, which also widened wallet's program.
That addition has been removed. The shared policy owner must resolve this
requirement before a fresh did journey can supply acceptance evidence. The did
test keeps its permitted-operation assertions and full-program equality; its
previous run with the wider policy supplies neither proof for the restored
policy nor acceptance of the did seccomp row.

The current journey also compares the key's final bytes with the bytes captured
immediately after `init`. The key check requires the trailing newline.

The launched child's own `/proc/<pid>/status` reports `Seccomp: 2`
(`SECCOMP_MODE_FILTER`) in the recorded runs. That mode alone also accepts an inherited
filter, so the launcher's record additionally carries the marker call's answer
before and after its own `pre_exec` install, and the two must differ.

The current test runs that journey in a child test process with an inherited
allow-all filter, installed through `install_seccomp`. It checks `Seccomp: 2`
before launching the provider and prints the launcher's before/after answers.
This makes the WP176 skip-install plant reach the before/after assertion even
when the provider already carries an inherited filter. One helper,
`seccomp_journey_runs_beneath_an_inherited_filter(name, test_name)`, does that for
both callers, so the did caller takes the same fixture by its own test name
instead of a second copy of the technique. The parent returns after checking
the child result, so each caller launches its provider once.

Only the wallet journey runs the forked probe child, which records the four calls before the filter, installs
the same filter through `install_seccomp`, and records them again:

| Call | Before the filter | After the filter |
| --- | --- | --- |
| `ptrace(PTRACE_TRACEME)` | returned `0` | `EACCES` (13) |
| `mount` | `ENOENT` (2) | `EACCES` (13) |
| `bpf` (request `0` with a null attribute pointer) | `EINVAL` (22) | `EACCES` (13) |
| `keyctl(KEYCTL_GET_KEYRING_ID, session keyring, create 0)` | a session keyring id, which differs per session | `EACCES` (13) |

Every filtered answer is the deny marker, and the marker differs from the
unfiltered answer the same probe recorded, so a host that already refuses a call
cannot stand in for the filter. The kernel already answers `EPERM` for `bpf`
under `unprivileged_bpf_disabled=2` and `EACCES` is never that answer, which is
why the marker is `EACCES`. The `keyctl` row names the keyring and a create flag
of `0`, because command `0` reads both: a call that passed only its command would
leave the registers behind it to chance, and the probe could select another
keyring or be asked to create one.

The probe child allocates nothing after its fork, and the report proves it. The
test binary counts the probe child's own allocations and the child writes the
count with its report, which is `0` on every kernel-proof child; a child that
allocated reports a count the parser reads and the probe refuses with its own
reason. The report pipe is created with atomic `O_CLOEXEC`. One child ownership
check uses `close_range` before the filter to keep only that child's report
writer, including when another probe or launcher has an open report channel.
The parent owns a bounded, nonblocking reader directly, so a read deadline
closes the descriptor without leaving a reader thread behind. A kernel that
refuses `close_range` ends the probe with its errno before any probe call.

`linux_seccomp_probe_descriptors_stay_with_their_owner` holds the pipe-creation
window open while another thread launches a provider, checks its `/proc` file
descriptors, and runs a fork-only sibling that requires both inherited pipe
ends to be closed. The owner then reaches EOF while the provider stays alive.
A retained parent writer exercises the read deadline and checks descriptor
cleanup on that error.

The reaping test `linux_seccomp_probe_reaps_failures_and_repeated_journeys` starts
children for both failed install steps, an architecture mismatch, missing
reports, stops, timeouts, allocations and repeated kernel proofs. Install
failures use the launcher's fixed-record encoder and decoder, and the test
requires the architecture refusal to name both architectures. A stopped child is
killed and reaped like a timed-out one, because `PTRACE_TRACEME` makes a child's
stops reportable without `WUNTRACED` and a stopped child is still alive. The reap
is asserted on every result before any arm can return, and the whole test is
bounded well inside eight deadlines.

Namespaces and the capability drop stay unbuilt. A seccomp filter reads syscall
numbers and not paths. The file row in "The file row" is GAP, and no sentence
here says a contract file row is enforced on Linux. `linux` stays out of
`DECLARED_CONFINED_OS`. A `linux` host under a `Seatbelt` policy keeps the words
this lab already used, and a `linux` host under a `Seccomp` policy is accepted by
the host rule and starts the provider under the filter; on any other OS the same
seat refuses the start by name instead of starting the provider unconfined.
`standin_host_refusal_decides_each_policy` holds both.

Every Linux-only plant below names exactly one test. The quoted outputs are
from the earlier run on the host above; the repair's new inheritance cases await
a Linux rerun. None is registered in `falsifiers.json`:
the runner runs on the Mac, where these `#[cfg(target_os = "linux")]` tests do not
run, so none can print a CAUGHT line there. Two Mac-runnable rules beside them are
registered instead: WP166's argument rule in
`seccomp_keyctl_probe_supplies_every_argument_without_creation`, WP167's
missing-record reason in `seccomp_launch_record_refuses_missing_or_unknown_report`
and WP178's provider-name rule in
`seccomp_allow_list_names_the_provider_it_was_built_for`. WP178 is the plant that
makes `seccomp_probe_list` ignore its provider argument and read wallet's file:
both lists then answer `wallet-provider` and the did case fails.

- WP168 suppresses the `NoNewPrivileges` install failure, so
  `linux_seccomp_launch_refuses_each_failed_install` fails with
  `wallet-provider start is refused: seccomp install refused: PR_SET_NO_NEW_PRIVS
  failed with errno 1 must refuse the start`.
- WP169 suppresses the `Filter` install failure, so the same test fails with
  `wallet-provider start is refused: seccomp install refused: the filter install
  failed with errno 22 must refuse the start`.
- WP170 substitutes `PROVIDER_BINARY` for the given program, so
  `linux_seccomp_launcher_runs_the_requested_program` fails with
  `left: "/home/spark1/t148/capsules/wallet-provider/target/debug/wallet-provider"`,
  `right: "/tmp/.tmpjY5EWl/requested-program"`.
- WP171 reads a stopped child as an end, so
  `linux_seccomp_probe_reaps_failures_and_repeated_journeys` fails with
  `a stopped child must be reported as stopped and reaped: seccomp probe refused:
  child exit status: 19 wrote no complete report within 10s`.
- WP172 omits the kill and reap for a timed-out probe, so the same test fails with
  `the probe child must already be reaped, and a second wait answered 0`.
- WP173 kills a timed-out probe without reaping it, so the same test fails with
  the same reaped assertion.
- WP174 omits the whole wait, so the same test fails with the same reaped
  assertion.
- WP175 collects the filtered answers into a `Vec` after the fork, so the same
  test fails with `the probe child allocated 1 times after its fork, where only
  async-signal-safe calls are available`.
- WP176 skips only the launcher's `pre_exec` install and leaves the self-filtering
  probe intact. The earlier `linux_wallet_journey_runs_under_the_seccomp_allow_list` run failed
  with `the launched provider must carry SECCOMP_MODE_FILTER in its own /proc
  status`, `left: 0`, `right: 2`. That run did not exercise an inherited filter.
  The current test installs the inherited fixture first. Its required plant
  failure is `an inherited filter alone must not satisfy the launcher's own install`,
  with equal before/after answers. This additional Linux run is NOT RUN in the
  repair session, which runs on macOS. To exercise it, replace
  `install_seccomp(&allow)` in `start_under_linux_policy` with `Ok(())`, then run
  `cargo test --locked --manifest-path capsules/wallet-provider/Cargo.toml --test confine linux_wallet_journey_runs_under_the_seccomp_allow_list -- --exact --nocapture`.
  The inherited fixture's install and the probe's install stay intact.
- WP177 writes the named outside sibling in `status`'s ok arm, so the journey
  finds `ElastOS/SystemServices/seccomp-outside-write` present and fails with
  `the named sibling outside STORAGE_ROOT must stay absent after the run`. That
  plant shows the fixture can fail; a seccomp filter does not stop that write, so
  the assertion is path evidence for the run and not a Linux file boundary.
- WP176 and WP177 on the did caller. `linux_did_journey_runs_under_the_seccomp_allow_list`
  is the second caller of the same journey body, so these are the same two plants
  on the second provider and not new rules, and neither is registered:
  the skip-install plant makes the did run fail on
  `the launched provider must carry SECCOMP_MODE_FILTER in its own /proc status`
  or, with the inherited fixture installed, on
  `an inherited filter alone must not satisfy the launcher's own install`; and the
  outside-write plant makes it find `seccomp-outside-write` beside `STORAGE_PARENT`
  and fail on `the named sibling outside STORAGE_ROOT must stay absent after the
  run`. The earlier did plant results used the wider policy and need a fresh
  run after the shared policy requirement is resolved. Neither Linux plant can
  print a CAUGHT line on the Mac.

The earlier WP166 and WP167 plants were CAUGHT on the Mac, in
`seccomp_keyctl_probe_supplies_every_argument_without_creation` and
`seccomp_launch_record_refuses_missing_or_unknown_report`. WP166 now removes
the call's four trailing arguments. A macOS hand run of that exact edit failed
the named test with `the keyctl call must pass the table's five arguments and
no register it did not set`; the source was then restored byte-for-byte. The
registered runner check remains with the supervisor.

## The Landlock ruleset builder

The file row's ruleset is a decided derivation from the same declared rights.
`landlock_path_rules` in `capsules/wallet-provider/tests/confine.rs` renders the
profile through `generate_profile` and reads it back through `profile_forms`.
It makes no kernel call. The kernel install, the probe and the journey are
"The file row" below. This section claims no row of "The contract on Linux".
Each row that "The file row" does not record keeps its current status and was
not run.

`LANDLOCK_RULE_RIGHTS` is the one table from a top-level allow form to the
rights that form carries. It holds one row for each of the five allow forms a
wallet profile holds:

| Allow form | Rights the row carries |
| --- | --- |
| `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))` | read-file, read-dir, write-file, remove-file, remove-dir, make-dir and make-reg, because `init` creates the wallet directory and its key file inside the root |
| `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))` | `EXECUTE` |
| `(allow file-read* (literal (param "STORAGE_PARENT")))` | none: a directory grant covers the whole tree beneath the parent |
| `(allow file-read* (literal "/"))` | none: a read rule on `/` would grant the whole filesystem |
| `(allow sysctl-read)` | none: Landlock has no sysctl right |

A row that carries none is a written decision and adds no path. A form the
table does not hold is a refusal that names the provider and the form, and no
ruleset is built. A form whose parameter the launch does not bind is a refusal, and no
ruleset is built.

`LANDLOCK_RIGHT_ABI` is the one table from a right to the ABI that introduced
it. `landlock_rights_abi` answers the lowest ABI a set of rights needs. A right
with no table entry is its own refusal. The default denial must be able to
refuse a truncation and a device ioctl, so `TRUNCATE` and `IOCTL_DEV` are
`LANDLOCK_REQUIRED_DENIALS`. A row's rights and those two denials both go
through `landlock_row_abi_refusal`. An ABI below either is refused with
`linux confinement refused: the Landlock ABI cannot express <row>`, naming the
row.

The handled mask is every right that ABI table reports at the version the
ruleset claims, so a right the version knows stays restricted when no path rule
grants it.

`install_landlock_with` runs one order and stops at the first failure: create
the ruleset, add each path rule in ruleset order, set `PR_SET_NO_NEW_PRIVS`,
then the final call. The closure stands in for the kernel call, so the order
is decided here. `install_landlock` is the one kernel caller of that order.

## The file row

The file row is GAP. This session did not reach the spark1 host, so it recorded
no run that names the host, the kernel and the ABI the kernel reported. The
two rows this installer is for — `(deny default)`, files, and
`(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))` — are not
written as passing. Every other row of "The contract on Linux" was not run.
`linux` stays out of `DECLARED_CONFINED_OS`. Nothing here says the Runtime
installed a ruleset. The ruleset test
`landlock_ruleset_follows_the_declared_rights` now derives did's and wallet's
rulesets on the Mac, each on its own storage root, and neither provider's
kernel run exists yet.

What the harness holds, and what a later host run would record:

One Linux launch. `start_under_seccomp` and `start_under_landlock` both call
`start_under_linux_policy`. That function makes one report socket, one
`pre_exec` and one `spawn`. Inside `pre_exec` the order is the file row first,
then `install_seccomp`. `install_landlock` runs `install_landlock_with`: create
the ruleset with the handled mask, add each path rule, set
`PR_SET_NO_NEW_PRIVS`, then `landlock_restrict_self`. `landlock_abi` reads the
version with `LANDLOCK_CREATE_RULESET_VERSION` and returns the create step's
refusal when the kernel answers `ENOSYS` or `EOPNOTSUPP`. The one record's
first field `SECCOMP_LAUNCH_LANDLOCK` carries the failed step, and
`decode_seccomp_launch_record` turns it into that step's words.
`write_seccomp_launch_record` is unchanged.

The nine probe calls, in report order, are `read-inside-storage-root`,
`write-inside-storage-root`, `read-bound-executable`,
`read-beneath-storage-parent`, `write-beside-storage-parent`,
`truncate-beside-storage-parent`, `list-storage-parent`, `list-sibling` and
`list-sibling-private`. This session has no control answer and no confined
errno for any of them. A passing run would show every control call succeeding,
the two inside calls succeeding under the ruleset, and the other seven
answering `EACCES` (13).

`LANDLOCK_LOADER_PATHS` is the aarch64 loader and the three libraries a
dynamically linked wallet maps. Each rule carries `EXECUTE | READ_FILE`. The
failure that named each entry on the earlier host measurement, when that entry
alone was dropped, is:

| Entry | The failure that named it |
| --- | --- |
| `/lib/ld-linux-aarch64.so.1` | `execve` answers `EACCES` (13) before the provider's first instruction without `EXECUTE`; without `READ_FILE` the loader cannot map itself |
| `/lib/aarch64-linux-gnu/libc.so.6` | the loader exits with `error while loading shared libraries: libc.so.6: cannot open shared object file` |
| `/lib/aarch64-linux-gnu/libgcc_s.so.1` | the loader exits with `error while loading shared libraries: libgcc_s.so.1: cannot open shared object file` |
| `/lib/aarch64-linux-gnu/libm.so.6` | the loader exits with `error while loading shared libraries: libm.so.6: cannot open shared object file` |

This session did not drop each entry again against the wallet binary on
spark1. Those four lines are the earlier measurement the constant carries.
They are not this session's recorded run, and they do not name a host, a
kernel and a reported ABI together, so they do not lift the GAP.

Two Linux-only plants are not in `falsifiers.json`. A `#[cfg(target_os = "linux")]`
test cannot print a CAUGHT line on the Mac. Each still needs one red run on
the host. This session did not run either.

- Skip only the launcher's Landlock install: in `start_under_linux_policy`,
  replace `install_landlock(ruleset).map_err(SeccompInstallFailure::Landlock)`
  with `Ok(())`. `linux_wallet_file_row_is_refused_outside_storage_root` must
  fail on the outside `Init`, which would no longer be `storage_error` with
  `Permission denied`. Rerun:
  `~/.cargo/bin/cargo test --locked --manifest-path capsules/wallet-provider/Cargo.toml -- linux_wallet_file_row_is_refused_outside_storage_root --exact --nocapture`.
  This session has no red output to quote.
- Grant `READ_FILE` on the `STORAGE_PARENT` row: change `(SHARED_RULES[1], 0)`
  to `(SHARED_RULES[1], LANDLOCK_ACCESS_FS_READ_FILE)`. The same journey must
  fail because `read-beneath-storage-parent` no longer answers `EACCES` (13).
  The same command reruns it. This session has no red output to quote.

## The frame

The Runtime generates each provider's policy from the provider's approved
declared rights. On Linux the same generator would emit one launch
specification instead of a Seatbelt text: a user namespace, a mount namespace,
a network namespace, a PID namespace and an IPC namespace; every capability
dropped; `no_new_privs` set before any filter; one seccomp filter; and one
Landlock ruleset. The three parameters keep their names and bind to the same
paths as on macOS: `PROVIDER_EXECUTABLE` is the provider binary; for
`did-provider`, `STORAGE_ROOT` is `Init.base_path/did` and `STORAGE_PARENT` is
`Init.base_path`; for `wallet-provider`, `STORAGE_ROOT` is
`base_path/ElastOS/SystemServices/Wallet` and `STORAGE_PARENT` is
`base_path/ElastOS/SystemServices`; the model profile states its own root.

The Linux policy holds no path rule beyond the bound parameters: it adds none
for `/`, `/proc`, `/sys` or a library directory, and `STORAGE_PARENT` carries no
rule, as its row says. The private `/proc` mount the mount namespace provides
is a mount, not a grant. The policy is a second rendering of the same rights,
and the one contract check stays the one check of the oracle.

The Linux policy would be applied before the provider image is entered. Apart
from the seccomp allow list above, this file is a design, and the file row is
GAP as "The file row" records. Each other row names the Linux test that would
prove it. Those rows were not run. No sentence here claims that any provider
is confined on Linux beyond the recorded seccomp filter.

The seccomp allow list's own Linux-test cells are the two journeys:
`linux_wallet_journey_runs_under_the_seccomp_allow_list` and
`linux_did_journey_runs_under_the_seccomp_allow_list`, both in
`capsules/wallet-provider/tests/confine.rs`. Wallet carries the recorded kernel
proof above. Did remains pending the shared policy decision and a fresh run
with the accepted program; its earlier wider-policy run is not row acceptance.

## The contract on Linux

`(deny default)`, files, and
`(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))` are GAP, as
"The file row" records. Every other row below was not run. The cells keep the
design each row already stated.

| Oracle rule | Linux primitive that would carry it | How exact the match is | Linux test that would prove it |
| --- | --- | --- | --- |
| `(version 1)` | The generator's policy version; no kernel primitive carries it. | Exact: the generator emits one version, and the contract check refuses any other head. | `both_file_profiles_bind_one_storage_parameter_contract` |
| `(deny default)`, files | A Landlock ruleset whose only path rules are `PROVIDER_EXECUTABLE` (`EXECUTE`) and `STORAGE_ROOT` (read and write). Every file right the ABI reports and that no rule covers fails. The capability drop removes `CAP_DAC_READ_SEARCH` and `CAP_DAC_OVERRIDE`, so privilege grants no file right. | Exact for every access right the ABI reports. Landlock's [filesystem flags](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags) report no right for `chdir`, `stat`, `flock`, `chmod`, `chown`, `setxattr`, `utime`, `fcntl` and `access`, so the ruleset does not restrict them. No layer of the design refuses `chdir`, `stat`, `access`, `chmod`, `utime` or `setxattr` on a fixture the provider owns with ordinary permissions, in a searchable fixture directory beneath searchable parents, so the mapping is wider than the oracle for those six; the kernel's ordinary permission check still applies, so the design claims no such success for a host-owned file or a file whose permissions deny the call. The capability drop removes `CAP_CHOWN`, so `chown` to a different owner is refused and the mapping is narrower than the oracle inside `STORAGE_ROOT`; an owner that keeps `uid` `-1` may still change its file's group to a group of which it is a member ([chown(2)](https://man7.org/linux/man-pages/man2/chown.2.html)), so the drop does not refuse every `chown`; the probe requires that group call to succeed and the resulting group to be the chosen mapped gid. The policy run checks its own fixture directory's mode and owner before its `chdir`, the same check the positive control makes on its copy, and reports a mismatch as missing evidence with its cause, not as a kernel change. A seccomp rule that refuses every `chown` by syscall number is the group-call falsifier only when the test reports the failing call as the group `chown` itself and every earlier call as a success; a failure at an earlier call is missing evidence. Landlock checks a new data open against the rules for its path, so a data open outside every grant fails; the rules are checked at open time, so a descriptor opened before enforcement is not checked: the [filesystem flags](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags) section states that "Files or directories opened before the sandboxing are not subject to these restrictions", and an `O_PATH` open does not open the file itself for reading or writing ([open(2)](https://man7.org/linux/man-pages/man2/open.2.html)); whether Landlock restricts it is open and unclaimed, and the probe's required success decides the row. The launch precondition is that a provider inherits no descriptor other than its stdin, stdout and stderr protocol streams, which are the harness pipes (`Stdio::piped()` in `ConfinedProvider::spawn` in `capsules/wallet-provider/tests/confine.rs`); future Runtime work proves it, for example by listing `/proc/self/fd` at provider start and allowing exactly 0, 1 and 2, and the design claims no falsifier for it. One raw `fcntl` call with the `F_DUPFD` command duplicates an outside `O_PATH` descriptor that the probe obtains with `openat` ([open(2)](https://man7.org/linux/man-pages/man2/open.2.html)) and gives no content read; the probe issues that raw command itself, not a library duplicate that may use another command such as `F_DUPFD_CLOEXEC`, so the `F_DUPFD`-only falsifier reaches the probe's call. The design claims that one raw call only, not every `fcntl` or `flock`, whose departures stay unclaimed. Falsifier for the duplication: add a seccomp rule that refuses `fcntl` only when its command argument is `F_DUPFD` ([fcntl(2)](https://man7.org/linux/man-pages/man2/fcntl.2.html)); the duplication fails and the test fails. The probe and the Rust runtime make other `fcntl` calls, so a rule that refuses every `fcntl` could stop the probe before its `F_DUPFD` call. Wider also where a rule on a directory covers the tree beneath it, as the next section says. A row that needs a right the ABI lacks departs as the `STORAGE_ROOT` row states, and the start is then refused, never weakened. | `outside_write_denied`, `outside_read_denied`, `confined_outside_write_is_denied`, `confined_outside_read_is_denied`, `linux_file_operations_landlock_cannot_restrict` and `linux_capability_drop_refuses_chown` |
| `(deny default)`, processes and signals | A PID namespace; the empty capability set; a seccomp filter that refuses process creation other than the provider's own threads and every cross-process operation (`ptrace`, `process_vm_*`, `pidfd_getfd`). Landlock `EXECUTE` on `PROVIDER_EXECUTABLE` alone carries exec of any other file. | Exact for signals: a PID namespace contains no PID outside itself, so a signal to a host process cannot be expressed. Narrower for process creation because the provider's threads must start: the filter admits the thread form of `clone` and refuses a new process. The filter adds no exec rule: it sees only the syscall number and cannot read the path behind `execve`'s pointer, so it cannot separate the granted binary from another file, and a refusal by number would also refuse the provider's own launch, which the oracle permits. The Linux test decides the exact flag set. | `confined_provider_denies_process_and_signal_boundaries` |
| `(deny default)`, IPC | An IPC namespace; seccomp refusing every `socket` and `socketpair` call, SysV IPC creation (`msgget` and `shmget` when the key is `IPC_PRIVATE` or the flags carry `IPC_CREAT`, both plain integer arguments the filter can read) and POSIX message queue creation (`mq_open` with `O_CREAT`); Landlock's default denial refusing reads and writes to shared-memory files. | Exact for host IPC objects: a private IPC namespace cannot name them, and the one SysV creation rule refuses every form including the private key. The `mq_open` rule refuses the `O_CREAT` form of the call, and the create also passes through the message queue filesystem ([mq_overview(7)](https://man7.org/linux/man-pages/man7/mq_overview.7.html)). Landlock's default denial would refuse that create only if the ruleset reaches the queue's internal mount; [Landlock's documentation](https://docs.kernel.org/userspace-api/landlock.html) does not settle that reach, and if it does not, no other layer refuses the create. The outcome is open, so the design leaves the `mq_open` falsifier unclaimed: a future isolated probe that drops only the `mq_open` `O_CREAT` refusal and records the outcome would settle it. Wider for a lookup of an existing object: `msgget(key, 0)` and `shmget(key, 0, 0)` are not refused, and inside the namespace they find nothing. Narrower for new objects if the provider needs none. The Linux test decides. | `confined_provider_denies_ipc_boundaries` |
| `(deny default)`, kernel facts | A private, read-only `/proc` mount limited to the provider's own PID namespace and a hidden host `/sys`; Landlock denying reads outside the granted paths, with no `/proc` or `/sys` rule; seccomp refusing syscalls that read host kernel state (`bpf`, `perf_event_open`). | No exact match: the oracle denies every kernel-fact operation except `sysctl-read`, and Linux splits kernel facts across `/proc`, `/sys` and syscalls, so the map is wider in one place and narrower in another. The Linux test decides. | `confined_provider_denies_kernel_fact_boundaries` |
| `(deny network*)`, with no network allow | A network namespace with no interface and no route; the empty capability set; seccomp refusing every `socket` and `socketpair` call by syscall number, with no family list, and refusing `connect`, `sendmsg`, `recvmsg`, `pidfd_getfd` and `process_vm_*` so no descriptor can arrive from outside. | Exact for every family the oracle refuses: the filter refuses the whole call instead of naming families, so no family is left out, Unix-domain included, and the namespace removes every interface. macOS puts a Unix-domain connect under `network*` (cc-model-confine 010, macOS 26.5.2), so this row covers it too. | `profile_denies_network` (the oracle text) and `linux_profile_denies_every_socket_family` (the policy) |
| no `(allow default)` | The generator emits only the rights the oracle grants; the launch adds no permissive rule. | Exact: the Linux policy has no permissive term, and the one contract check refuses one in the oracle. | `both_file_profiles_bind_one_storage_parameter_contract` and `file_profile_contract_rejects_an_allow_default` |
| Only `PROVIDER_EXECUTABLE`, `STORAGE_ROOT` and `STORAGE_PARENT` | The same three parameters, bound to the same paths; the parent takes no path rule, and its row says why. The launch specification accepts no other path. | Exact: no other path enters the policy. | `both_file_profiles_bind_one_storage_parameter_contract` and `file_profile_contract_rejects_a_non_canonical_token` |
| `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))` | Landlock `EXECUTE` on the file named by `PROVIDER_EXECUTABLE`; no other layer carries exec, because a seccomp filter sees only the syscall number and cannot read the path behind `execve`'s pointer. | Exact: a Landlock rule on a file grants only that file, the oracle's `literal` names only that file, and the design gives the whole exec rule to Landlock. | `confined_provider_serves_did_operations_under_its_root` and `confined_provider_serves_wallet_operations_under_its_root` |
| `(allow file-read* (literal "/"))` | No path rule. The nearest rule is a Landlock read rule on `/`, which would grant the whole tree and be a fourth path, so the design does not use it. | No exact match: the nearest rule is wider (all files) and the design's mapping is narrower (no rule). The Linux test decides whether the loader starts without it. | `confined_provider_serves_did_operations_under_its_root` and `confined_provider_serves_wallet_operations_under_its_root` |
| `(allow sysctl-read)` | Seccomp allows the kernel-fact syscalls the loader and the allocator use; no path rule. Landlock has no sysctl right. | No exact match: the oracle grants every sysctl read, and the filter is narrower (named syscalls only). The Linux test decides the set. | `confined_provider_serves_did_operations_under_its_root`, `confined_provider_serves_wallet_operations_under_its_root` and `confined_provider_denies_kernel_fact_boundaries` |
| `(allow file-read* (literal (param "STORAGE_PARENT")))` | No read rule on `STORAGE_PARENT`. Landlock has no rule that names a directory alone: a path rule on a directory covers the whole tree beneath it, so the nearest rule would let a read beneath the parent succeed. | No exact match: the nearest rule is wider than the oracle (the whole tree beneath the parent), so the design's mapping is narrower: no rule. The `STORAGE_PARENT` read test plants a readable file beneath the parent, outside `STORAGE_ROOT`, and requires its read to fail. If the provider needs the directory alone to start, the start is refused with `linux confinement refused: the Landlock ABI cannot express the STORAGE_PARENT read`, and `linux_start_is_refused_when_the_landlock_abi_cannot_express_a_row` requires that reason. | `outside_read_denied` and `confined_outside_read_is_denied` |
| `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))` | Landlock read and write rights on `STORAGE_ROOT`, covering its tree. | Exact for the path: a rule beneath `STORAGE_ROOT` covers the same subtree as the oracle's `subpath`. The rights are exact when the ABI reports every right the oracle's read and write cover. A right the ABI lacks departs the row: `REFER` before ABI 2 refuses every link or rename across directories, which is narrower; `TRUNCATE` before ABI 3 and `IOCTL_DEV` before ABI 5 are not restricted at all, which is wider. Because a wider departure is not confinement, the start is refused when the ABI cannot express this row. | `confined_provider_serves_did_operations_under_its_root`, `confined_provider_serves_wallet_operations_under_its_root`, `outside_write_denied` and `confined_outside_write_is_denied` |
| `(allow file-read-data (literal "/"))` (model profile) | No path rule, for the same reason as the read of `/`. | No exact match: the nearest rule, a read rule on `/`, is wider (data and metadata for all files); the design's mapping is narrower (no rule). The Linux test decides. | `model_provider_ops_under_profile` (the model provider's named test) and `both_file_profiles_bind_one_storage_parameter_contract` |

The five allow rules cover `model-provider` too. The table names the model
profile only where it differs: it presents `(allow file-read-data (literal
"/"))` instead of the shared `(allow file-read* (literal "/"))`, and the model
provider's own document states its storage root.

## Rows with no exact Linux match

Five rows have no exact Linux rule. Each says which way its nearest rule
departs from the oracle, and the Linux test decides the row.

- The file operations Landlock cannot restrict: `chdir`, `stat`, `flock`,
  `chmod`, `chown`, `setxattr`, `utime`, `fcntl` and `access`
  ([filesystem flags](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags)).
  Each departs the oracle in one stated way. No layer of the design refuses
  `chdir`, `stat`, `access`, `chmod`, `utime` or `setxattr` on a fixture the
  provider owns with ordinary permissions, in a searchable fixture directory
  beneath searchable parents, so the mapping is wider than the oracle's
  `(deny default)` for those six; the
  kernel's ordinary permission check still applies, so the design claims no
  such success for a host-owned file or a file whose permissions deny the
  call. `linux_file_operations_landlock_cannot_restrict` probes them on
  isolated file and directory fixtures outside every grant, under the probe's
  mapped uid and gids, with that uid as the fixture owner, the fixture
  directory searchable by that uid (owned by it, mode `0700`), and the search
  bit set on every parent. A positive control under the same uid/gid mappings
  and namespaces, without the proposed Landlock ruleset, capability drop and
  seccomp filter, requires each intended call to succeed first; a fixture the
  host cannot supply or a call the control already refuses is reported with
  its cause as missing evidence. The policy run checks its own fixture
  directory's mode and owner before its `chdir`, the same check the positive
  control makes on its copy, and reports a mismatch as missing evidence with
  its cause, not as a kernel change. Under the policy the probe requires each
  call to succeed, so the widening is recorded rather than claimed as
  confinement; a later kernel that refuses one of them fails the test and the
  row is rewritten. Falsifier for the metadata calls: add a seccomp rule that
  refuses `chmod` and `stat` by syscall number
  ([seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)); a
  filter reads syscall arguments as integers, not paths, so the rule cannot
  select only the probe's calls, and the probe and the Rust runtime make
  other `stat` calls.
  The rule can stop the probe before its own calls, so the design leaves this
  falsifier unclaimed.
  `chown` separates two cases. Changing the owner to a different mapped uid
  is refused because the capability drop removes `CAP_CHOWN`, so the mapping
  is narrower than the oracle inside `STORAGE_ROOT`;
  `linux_capability_drop_refuses_chown` requires `EPERM` with the owner
  unchanged. Falsifier: keep `CAP_CHOWN` in the capability set; the chown
  succeeds and the test fails. Changing only the group of a file the probe
  owns, with `uid` `-1` and a different mapped group of which the probe is a
  member, stays permitted because
  [chown(2)](https://man7.org/linux/man-pages/man2/chown.2.html) lets the
  owner set a group it belongs to; the same probe requires that call to
  succeed and the resulting group to change. Falsifier: add a seccomp rule
  that refuses every `chown` by syscall number; this falsifier counts only
  when the test reports the failing call as the group `chown` itself and every
  earlier call as a success. A failure at an earlier call is reported as
  missing evidence, so the group call is not inferred from it. A fixture
  without the required mapped uid or gid supplies a
  clear reason for missing evidence. `flock` and `fcntl` act only on a
  descriptor, so the descriptor conditions decide them. Landlock refuses a
  new data open outside every grant. A descriptor opened before enforcement
  is not checked: the [filesystem flags](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags)
  section states that "Files or directories opened before the sandboxing are
  not subject to these restrictions".
  The launch precondition is that a provider inherits no descriptor other
  than its stdin, stdout and stderr protocol streams, which are the harness
  pipes (`Stdio::piped()` in `ConfinedProvider::spawn` in
  `capsules/wallet-provider/tests/confine.rs`); future Runtime work proves
  it, for example by listing `/proc/self/fd` at provider start and allowing
  exactly 0, 1 and 2, and the design claims no falsifier for it. An `O_PATH`
  open does not open the file itself for reading or writing
  ([open(2)](https://man7.org/linux/man-pages/man2/open.2.html)); whether
  Landlock restricts it is open and unclaimed, and the probe's required
  success decides the row. The same probe obtains an outside `O_PATH`
  descriptor with `openat` and duplicates it by calling `fcntl` with the raw
  `F_DUPFD` command ([open(2)](https://man7.org/linux/man-pages/man2/open.2.html)),
  not through a library duplicate that may use another command such as
  `F_DUPFD_CLOEXEC`; it requires both descriptors and closes both. The
  duplication gives no proof of a content read, because `open(2)` gives
  `EBADF` for a read on an `O_PATH` descriptor. The design claims this one
  raw `fcntl(F_DUPFD)` call and no other `fcntl` command and no `flock`
  operation, so those departures stay unclaimed. Falsifier for the `O_PATH` open:
  add a seccomp rule that refuses `openat` when its flags carry `O_PATH`; the
  open fails and the test fails. Falsifier for the duplication: add a seccomp
  rule that refuses `fcntl` only when its command argument is `F_DUPFD`
  ([fcntl(2)](https://man7.org/linux/man-pages/man2/fcntl.2.html)); the
  duplication fails and the test fails. The probe and the Rust runtime make
  other `fcntl` calls, so a rule that refuses every `fcntl` could stop the
  probe before its `F_DUPFD` call.
- The literal read of `STORAGE_PARENT` alone. Landlock has no right that names
  a directory without its tree, so the nearest rule is wider than the oracle
  and would let a read beneath the parent succeed. The design's mapping is
  narrower: no rule. The test that decides the row plants a readable file at
  `STORAGE_PARENT/<sibling>/<file>`, outside `STORAGE_ROOT`, and requires the
  read to fail. If the provider needs the directory alone to start, the start
  is refused with `linux confinement refused: the Landlock ABI cannot express
  the STORAGE_PARENT read`, and
  `linux_start_is_refused_when_the_landlock_abi_cannot_express_a_row` requires
  that reason. Falsifier: add the read rule on `STORAGE_PARENT`; the planted
  read succeeds and the test fails.
- The read of `/`. A Landlock read rule on `/` would grant the whole filesystem
  and add a fourth path, so the nearest rule is wider than the oracle. The
  design's mapping is narrower: no rule. The Linux test decides whether the
  loader starts without it.
- `(allow sysctl-read)`. Landlock has no sysctl right. The nearest rule, a
  seccomp allowance of the fact syscalls the loader and the allocator use, is
  narrower than the oracle's grant of every sysctl read. The Linux test decides
  the set.
- The model profile's `file-read-data (literal "/")`. It is the same case as
  the read of `/`, and the nearest read rule on `/` is wider in both path and
  access kind. The Linux test decides.

## Open questions

These are open questions for the Linux tests, not facts:

- Which reads the loader and the allocator need at start on Linux, the
  counterparts of `sysctl-read` and of the read of `/`.
- Whether a dynamically linked provider needs to read its shared libraries. If
  it does, this design admits no fourth path, so the provider would be built to
  need no library read outside `PROVIDER_EXECUTABLE`, or the start would be
  refused.
- The Landlock ABI of a given kernel. The Runtime would read the reported ABI
  and would refuse any row the ABI cannot express.
- Whether the provider's threads need a `clone` form that the process boundary
  must allow.

## When a primitive is missing

The start is refused with a reason that names the missing primitive (item 16's
rule, P11). Each refusal has its own reason and its own Linux test:

- The kernel has no Landlock:
  `linux confinement refused: the kernel has no Landlock`; the test that would
  prove it is `linux_start_is_refused_when_landlock_is_absent`.
- The Landlock ABI cannot express a row:
  `linux confinement refused: the Landlock ABI cannot express <row>`; the test
  that would prove it is
  `linux_start_is_refused_when_the_landlock_abi_cannot_express_a_row`. The test
  presents an ABI that lacks one right per row and requires the reason to name
  that row. For the `STORAGE_PARENT` row the reason names that read, because
  Landlock has no literal-directory right at any ABI.
- User namespaces are turned off:
  `linux confinement refused: user namespaces are turned off`; the test that
  would prove it is
  `linux_start_is_refused_when_user_namespaces_are_turned_off`.
- The mount namespace cannot be created:
  `linux confinement refused: the mount namespace cannot be created`; the test
  that would prove it is
  `linux_start_is_refused_when_the_mount_namespace_cannot_be_created`.
- The network namespace cannot be created:
  `linux confinement refused: the network namespace cannot be created`; the
  test that would prove it is
  `linux_start_is_refused_when_the_network_namespace_cannot_be_created`.
- The PID namespace cannot be created:
  `linux confinement refused: the PID namespace cannot be created`; the test
  that would prove it is
  `linux_start_is_refused_when_the_pid_namespace_cannot_be_created`.
- The IPC namespace cannot be created:
  `linux confinement refused: the IPC namespace cannot be created`; the test
  that would prove it is
  `linux_start_is_refused_when_the_ipc_namespace_cannot_be_created`.
- The capability set cannot be dropped:
  `linux confinement refused: the capability set cannot be dropped`; the test
  that would prove it is
  `linux_start_is_refused_when_the_capability_set_cannot_be_dropped`. The test
  injects a `capset` failure (`ENOMEM` and a refusal by an inherited seccomp
  filter) and requires this exact reason before the provider starts.
- `no_new_privs` cannot be set:
  `linux confinement refused: no_new_privs cannot be set`; the test that would
  prove it is `linux_start_is_refused_when_no_new_privs_cannot_be_set`. The
  test injects a `prctl(PR_SET_NO_NEW_PRIVS)` failure (`EPERM` and a refusal by
  an inherited seccomp filter) and requires this exact reason before the
  provider starts.
- The seccomp filter cannot be installed:
  `linux confinement refused: the seccomp filter cannot be installed`; the test
  that would prove it is
  `linux_start_is_refused_when_the_seccomp_filter_cannot_be_installed`.

Kernel support does not guarantee success: `capset` can return `ENOMEM`, and
an inherited seccomp filter can refuse `capset` or `prctl`, so each failure has
its own reason and test above and no failure starts the provider unconfined.

No row falls back to a weaker rule or to an unconfined start, and no
best-effort mode is used. A refusal leaves nothing under `STORAGE_ROOT`. A
falsifier for these tests is a launch that starts the provider unconfined when a
primitive is missing; the test fails because the provider answers. A second
falsifier returns a fixed reason that names no primitive; the test fails on the
reason.

## The tests

Most of the Linux tests below are future work. Two run today and check the
oracle text rather than the Linux policy:
`both_file_profiles_bind_one_storage_parameter_contract` and
`profile_denies_network`. `linux` joins `DECLARED_CONFINED_OS` only when the
Linux counterparts exist and pass, and the gate then holds Linux to them (027).
Until then, adding `linux` fails the gate on purpose.

Today `sandbox_gate` requires `/usr/bin/sandbox-exec`, and
`sandbox_gate_fails_instead_of_skipping_on_a_declared_os` explicitly expects
`linux` to skip. Before `linux` is declared, both change: `sandbox_gate` gains
a Linux branch that checks the Landlock ABI, user namespaces and seccomp, and
the gate test gains a `linux` case in which each missing primitive is an error
that names it, not a skip.

A Linux counterpart of a named macOS test reuses that test's name; a test with
no macOS counterpart is named here for the first time.

- `both_file_profiles_bind_one_storage_parameter_contract` runs on Linux today.
  It proves the head terms, the three tokens and the three shared rules of the
  oracle, and it needs no Linux counterpart. Falsifier: rename `STORAGE_ROOT`
  (WP22) or add `(allow default)`; the check fails.
- `confined_provider_serves_did_operations_under_its_root` (Linux counterpart)
  drives `Init`, `get_did`, `get_persona_did`, `get_nickname`, `set_nickname`
  and `resolve` under the Linux policy and requires each answer and each file
  under `STORAGE_ROOT`. The test harness places a copy of
  `PROVIDER_EXECUTABLE` in `STORAGE_ROOT`, under a name other than the
  original, before the confined probe starts and outside the policy.
  The harness then checks, outside the policy and before the confined probe
  starts, that the copy can run: either because its mode gives the probe's
  uid an execute bit and the mount that holds `STORAGE_ROOT` carries no
  `noexec` flag, or because the harness starts the copy once outside the
  policy with its own scratch storage root, apart from the probe's
  `STORAGE_ROOT`, and the start succeeds. After that start, and before the
  confined probe starts, the harness lists `STORAGE_ROOT` and requires it to
  hold only the copy; anything else there is reported as missing evidence
  with its cause, never as a result of the confined run: the did and wallet
  probes require files under `STORAGE_ROOT`, so a file the outside start left
  there would stand in for the confined run's write. A copy the harness
  cannot show running is reported as missing evidence with its cause, not as
  the exec rule's refusal. A missing execute bit or a `noexec` mount makes
  that exec fail with `EACCES`, the same error the Landlock refusal gives, so
  without this check the exec-row falsifier would leave the exec failing and
  would not be caught.
  Under the policy the probe first shows the copy is present and readable
  under the `STORAGE_ROOT` grant, and only then requires the exec of the copy
  to fail; a failure before the exec is reported as missing evidence with its
  cause, not as the exec rule's refusal. A copy outside every grant would
  also fail its read, so that probe would not decide the exec rule. It fails
  without the `EXECUTE` rule (the start is refused), without the `STORAGE_ROOT`
  read and write rights (the identity write is denied) and without the rule
  that carries the loader's start reads. Falsifier for the exec row: add a
  Landlock `EXECUTE` rule for the copy under `STORAGE_ROOT`; the copy is
  readable and runs, and the test fails. Dropping the `EXECUTE` rule fails the
  test too, but only through the startup refusal. Falsifier for the state row:
  drop the `STORAGE_ROOT` write right; the test fails on the denied identity
  write. Falsifier for the loader reads: refuse the fact syscalls the loader
  uses; the test fails because the provider cannot start.
- `confined_provider_serves_wallet_operations_under_its_root` (Linux
  counterpart) drives `Init`, `status`, `CreateManagedAccount` and
  `ListAccounts`, and requires the account and the storage key under the wallet
  root. The test harness places a copy of `PROVIDER_EXECUTABLE` in
  `STORAGE_ROOT`, under a name other than the original, before the confined
  probe starts and outside the policy.
  The harness then checks, outside the policy and before the confined probe
  starts, that the copy can run: either because its mode gives the probe's
  uid an execute bit and the mount that holds `STORAGE_ROOT` carries no
  `noexec` flag, or because the harness starts the copy once outside the
  policy with its own scratch storage root, apart from the probe's
  `STORAGE_ROOT`, and the start succeeds. After that start, and before the
  confined probe starts, the harness lists `STORAGE_ROOT` and requires it to
  hold only the copy; anything else there is reported as missing evidence
  with its cause, never as a result of the confined run: the did and wallet
  probes require files under `STORAGE_ROOT`, so a file the outside start left
  there would stand in for the confined run's write. A copy the harness
  cannot show running is reported as missing evidence with its cause, not as
  the exec rule's refusal. A missing execute bit or a `noexec` mount makes
  that exec fail with `EACCES`, the same error the Landlock refusal gives, so
  without this check the exec-row falsifier would leave the exec failing and
  would not be caught.
  Under the policy the probe first shows the copy is present and readable
  under the `STORAGE_ROOT` grant, and only then requires the exec of the copy
  to fail; a failure before the exec is reported as missing evidence with its
  cause, not as the exec rule's refusal. A copy outside every grant would
  also fail its read, so that probe would not decide the exec rule.
  Falsifier for the exec row: add a Landlock `EXECUTE` rule for the copy under
  `STORAGE_ROOT`; the copy is readable and runs, and the test fails. Falsifier
  for the state row: drop the `STORAGE_ROOT` write right; the test fails on
  the denied account write.
- `verify_did_recovery_under_profile` (Linux counterpart) requires
  `invalid_signature` with its reason from the provider under the policy and a
  later `get_did` that proves the service stayed up. Falsifier: make the
  process die in the refusal branch (DID06); the test fails without a response.
- `outside_write_denied` and `confined_outside_write_is_denied` (Linux
  counterparts). As written today, did's `outside_write_denied` writes through
  a link inside the root to two targets, an unrelated directory and a sibling
  of `did/` under `Init.base_path`; wallet's `confined_outside_write_is_denied`
  sends `Init` for three outside bases, an unrelated directory, `base/sibling`
  and `base/ElastOS/SystemServices/Sibling` beneath `STORAGE_PARENT`, and uses
  no link. The Linux counterparts reuse those fixtures: they require
  `storage_error`, no file outside the root, and a later write under the root
  to succeed. Falsifier for either: widen the `STORAGE_ROOT` rule to
  `STORAGE_PARENT`; the sibling write or the beneath-parent `Init` succeeds and
  the test fails.
- `outside_read_denied` and `confined_outside_read_is_denied` (Linux
  counterparts) plant a readable file beneath `STORAGE_PARENT`, outside
  `STORAGE_ROOT`, and reach it through a link from inside the root: did's at
  `STORAGE_PARENT/<sibling>/did/nickname.enc`, wallet's storage key under
  `STORAGE_PARENT/<sibling>/Wallet`. Under the design no read rule covers
  `STORAGE_PARENT`, so the read is refused and the provider stays in service.
  Falsifier: add the `STORAGE_PARENT` read rule; the planted read succeeds and
  the test fails. As written today neither test plants a file beneath
  `STORAGE_PARENT` — did plants it in a separate temporary directory and wallet
  at `base/sibling` — so neither one alone decides the row; the Linux
  counterparts add the fixture. Falsifier for the read of `/` row: add a
  Landlock read rule on `/`; the outside read succeeds, and the test fails, as
  does the model provider's `model_outside_read_denied`.
- `startup_denial_reports_its_reason` (Linux counterpart) starts the provider
  under a policy that denies the exec and requires the failure to name the
  request, the exit status and the policy's reason. Falsifier: drop the reason
  from the failure (DID12); the test fails.
- Each refusal test named in "When a primitive is missing" refuses the start
  for exactly one named failure, requires its own exact reason, and requires
  nothing under `STORAGE_ROOT`. The macOS test
  `startup_is_refused_when_the_profile_cannot_be_applied` covers three
  profile-load failures; the Linux refusals split, so each primitive has one
  name and no test covers two. Falsifiers:
  start the provider unconfined when a primitive is missing (the provider
  answers and the test fails), or return a fixed reason that names no primitive
  (each test fails on the reason).
- `profile_denies_network` runs on Linux today and checks the oracle text.
  `linux_profile_denies_every_socket_family` (new) starts a test probe under the
  same Linux policy and calls `socket(family, type)` for every address family
  number from 0 to `AF_MAX` and every socket type (`SOCK_STREAM`, `SOCK_DGRAM`,
  `SOCK_SEQPACKET`, `SOCK_RAW`, `SOCK_RDM`, `SOCK_DCCP`, `SOCK_PACKET`), and
  `socketpair` for each type, and requires every call to fail with `EPERM`. It
  also requires a `connect` to a Unix-domain stand-in to fail, and the provider
  to stay in service. Falsifier:
  replace the whole-call refusal with a family list that omits `AF_VSOCK`;
  `socket(AF_VSOCK, SOCK_STREAM)` succeeds and the test fails. Because the test
  covers every family number and every type, a list that omits any one of them
  fails.
- `linux_file_operations_landlock_cannot_restrict` (new) uses an isolated
  fixture file and an isolated fixture directory outside every path grant.
  The probe runs under the mapped uid and mapped gids of the policy; the
  fixture file and directory are owned by that uid, the fixture directory
  carries the search bit for that uid (mode `0700`, owned by that uid), every
  parent directory carries the search bit for that uid
  ([chdir(2)](https://man7.org/linux/man-pages/man2/chdir.2.html)), the
  positive control checks its copy of the fixture directory's mode and owner
  before its `chdir`, and the policy run checks its own fixture directory's
  mode and owner before its `chdir`; a mismatch in either copy is reported as
  missing evidence with its cause, not as a kernel change. The file has
  ordinary `0644` permissions so its owner
  may `chmod`, `utime` and `setxattr` it. One mapped supplementary gid
  differs from the file's group and is the target of the group `chown`. The
  file's filesystem supports the chosen `user.*` xattr.
  The calls use the fixture file for `stat`, `chmod`, `access`, `utime`,
  `setxattr` and `chown(path, -1, gid)`, the fixture directory for `chdir`,
  and the fixture file for `openat(AT_FDCWD, path, O_PATH)`, whose descriptor
  the probe duplicates by calling `fcntl(fd, F_DUPFD, 3)` itself with the raw
  `F_DUPFD` command, not through a library duplicate that may use another
  command such as `F_DUPFD_CLOEXEC`, and closes twice. A
  positive control runs the same calls on its own copies of the fixture,
  under the same uid/gid mappings and the same user, mount, PID and IPC
  namespaces without the proposed Landlock ruleset, capability drop or
  seccomp filter, and requires each call to succeed; a fixture the host
  cannot supply, a fixture directory whose mode or owner does not give that
  uid the search bit, a missing uid or gid mapping, a filesystem without the
  xattr, or a call the positive control already refuses is reported with its
  cause as missing evidence, and the probe claims no widening from it. The
  control is a precondition check and claims no policy falsifier. Under the
  policy each call must succeed, the group `chown` must return success and
  the resulting group must be the chosen mapped gid, and the `O_PATH`
  descriptor and its duplicate must both be obtained; a refusal of any of
  these calls under the policy fails the test. The probe reads no file
  content, because `open(2)` gives `EBADF` for a read on an `O_PATH`
  descriptor. Falsifier for the metadata calls: add a seccomp rule that
  refuses `chmod` and `stat` by syscall number
  ([seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)); a
  filter reads syscall arguments as integers, not paths, so the rule cannot
  select only the probe's calls, and the probe and the Rust runtime make
  other `stat` calls.
  The rule can stop the probe before its own calls, so the design leaves this
  falsifier unclaimed. Falsifier for the group case: add a seccomp rule that
  refuses every `chown` by syscall number; the test reports the failing call,
  and the falsifier counts only when that call is the group `chown` itself and
  every earlier call is reported as a success; a failure at an earlier call
  is missing evidence.
  Falsifier for the `O_PATH` open: add a seccomp rule that refuses `openat`
  when its flags carry `O_PATH`; the open fails and the test fails. Falsifier
  for the duplication: add a seccomp rule that refuses `fcntl` only when its
  command argument is `F_DUPFD` ([fcntl(2)](https://man7.org/linux/man-pages/man2/fcntl.2.html));
  the duplication fails and the test fails. The probe and the Rust runtime
  make other `fcntl` calls, so a rule that refuses every `fcntl` could stop
  the probe before its `F_DUPFD` call. A descriptor opened before
  enforcement is not checked: the [filesystem flags](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags)
  section states that "Files or directories opened before the sandboxing are
  not subject to these restrictions".
  The launch precondition is that a provider inherits no descriptor other
  than its stdin, stdout and stderr protocol streams, which are the harness
  pipes (`Stdio::piped()` in `ConfinedProvider::spawn` in
  `capsules/wallet-provider/tests/confine.rs`); future Runtime work proves
  it, for example by listing `/proc/self/fd` at provider start and allowing
  exactly 0, 1 and 2, and this probe claims no falsifier for it.
- `linux_capability_drop_refuses_chown` (new) probes
  `chown(path, other_uid, -1)` on a file under `STORAGE_ROOT` that the probe's
  mapped uid owns, under the same policy, and requires `EPERM` with the owner
  unchanged, so the narrowing of the files row is observed. The fixture maps
  the file's owner and the target as two different uids; a fixture without
  that mapping supplies a clear reason for missing evidence. A positive
  control under the same uid/gid mappings and namespaces uses its own file
  with the same owner, keeps `CAP_CHOWN` in the capability set, and requires
  the same call to succeed, so the fixture is shown to permit it before the
  policy's refusal is attributed to the drop.
  Falsifier: keep `CAP_CHOWN` in the capability set; the chown succeeds and
  the test fails.
- `confined_provider_denies_process_and_signal_boundaries` (new) requires a
  probe under the same policy to fail to exec a copy of `PROVIDER_EXECUTABLE`.
  The test harness places a copy of `PROVIDER_EXECUTABLE` in `STORAGE_ROOT`,
  under a name other than the original, before the confined probe starts and
  outside the policy.
  The harness then checks, outside the policy and before the confined probe
  starts, that the copy can run: either because its mode gives the probe's
  uid an execute bit and the mount that holds `STORAGE_ROOT` carries no
  `noexec` flag, or because the harness starts the copy once outside the
  policy with its own scratch storage root, apart from the probe's
  `STORAGE_ROOT`, and the start succeeds. After that start, and before the
  confined probe starts, the harness lists `STORAGE_ROOT` and requires it to
  hold only the copy; anything else there is reported as missing evidence
  with its cause, never as a result of the confined run: the did and wallet
  probes require files under `STORAGE_ROOT`, so a file the outside start left
  there would stand in for the confined run's write. A copy the harness
  cannot show running is reported as missing evidence with its cause, not as
  the exec rule's refusal. A missing execute bit or a `noexec` mount makes
  that exec fail with `EACCES`, the same error the Landlock refusal gives, so
  without this check the exec-row falsifier would leave the exec failing and
  would not be caught.
  Under the policy the probe first shows the copy is
  present and readable under the `STORAGE_ROOT` grant, and only then requires
  the exec of the copy to fail; a failure before the exec is reported as
  missing evidence with its cause, not as the exec rule's refusal. A copy
  outside every grant would also fail its read, so that probe would not decide
  the exec rule.
  The same probe must fail to fork a new process and to signal a host PID, and
  must fail `ptrace(PTRACE_TRACEME)`, `process_vm_readv` and `pidfd_getfd` on
  its own process; the seccomp rule refuses those three calls by number, so a
  self-target probe observes it without the PID namespace or a Landlock scope.
  Falsifier: remove the PID namespace; the signal to the host PID succeeds and
  the test fails on that assertion. Falsifier for the creation refusal: admit
  the process form of `clone`; the new process starts and the test fails.
  Falsifier for the exec row: add a Landlock `EXECUTE` rule for the copy under
  `STORAGE_ROOT`; the copy is readable and runs, and the test fails. Falsifier
  for the cross-process refusals: allow `ptrace`; the self-trace succeeds and
  the test fails. A host process is not the target here, because the PID
  namespace and Landlock's ptrace restriction would mask that mutation.
- `confined_provider_denies_ipc_boundaries` (new) first creates a SysV queue in
  the host namespace; then a probe under the policy requires
  `msgget(host_key, IPC_CREAT)`, `msgget(IPC_PRIVATE, 0600)` and
  `shmget(IPC_PRIVATE, 4096, 0600)` to fail, `msgget(host_key, 0)` to fail with
  `ENOENT` because the queue is not in the private IPC namespace, a POSIX
  message queue create and a Unix socket pair to fail, and a host shared-memory
  object to fail to open. Falsifier: drop the IPC namespace;
  `msgget(host_key, 0)` returns the host queue and the test fails on that
  assertion, while the seccomp refusals and the Landlock default denial stay in
  place. Falsifier for the `msgget` and `shmget` creation refusals: drop the
  `IPC_PRIVATE` check or the `IPC_CREAT` check; the corresponding create
  succeeds and the test fails on that assertion, because the private IPC
  namespace permits a new object inside itself and Landlock's
  [filesystem flags](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags)
  restrict files and directories, not SysV objects. The POSIX queue create
  also passes through the message queue filesystem
  ([mq_overview(7)](https://man7.org/linux/man-pages/man7/mq_overview.7.html)).
  Landlock's default denial would refuse that create only if the ruleset
  reaches the queue's internal mount; the cited documents do not settle that
  reach, and if it does not, no other layer refuses the create. The outcome is
  open, so the design leaves the `mq_open` falsifier unclaimed: a future
  isolated probe that drops only the `mq_open` `O_CREAT` refusal and records
  the outcome would settle it.
- `confined_provider_denies_kernel_fact_boundaries` (new) requires a probe to
  fail to read `/proc/kallsyms`, host `/proc/sys` entries outside the grant or
  `/sys` kernel state, and to fail `bpf` and `perf_event_open`. The design adds
  no `/proc` or `/sys` path rule, so the
  [Landlock](https://docs.kernel.org/userspace-api/landlock.html) ruleset
  refuses every read under `/proc` and every read of kernel state under a
  mounted host `/sys`; the private `/proc` mount hides host PIDs and the
  hidden host `/sys` hides sysfs, and no assertion observes either mount.
  Falsifier for the `/proc` read: add a `/proc` read rule to the ruleset; the
  read of `/proc/kallsyms` succeeds and the test fails. The `/sys` read has no
  single-rule falsifier: adding a `/sys` read rule alone leaves the read
  refused because the hidden host `/sys` mount still hides sysfs, and mounting
  the host `/sys` alone leaves it refused because Landlock's default denial has
  no `/sys` read rule. The combined edit of mounting the host `/sys` and
  adding a `/sys` read rule makes the read of `/sys` kernel state succeed, so
  it is an experiment that shows the assertion can fail, not proof of either
  rule; the design leaves a falsifier for the `/sys` read unclaimed. It claims
  no falsifier for either mount, because a mount change alone leaves Landlock's
  default denial in place. Falsifier for the `bpf` refusal, read only when
  the host precondition check passes: allow `bpf`; the probe's call succeeds
  and the test fails. This precondition check is a check of the host and the
  probe's launch, read before the mutation, and it passes only when
  `kernel.unprivileged_bpf_disabled` reads 0
  ([unprivileged_bpf_disabled](https://docs.kernel.org/admin-guide/sysctl/kernel.html#unprivileged-bpf-disabled)),
  the probe's `bpf(BPF_MAP_CREATE, ...)` request
  ([bpf(2)](https://man7.org/linux/man-pages/man2/bpf.2.html)) names a map
  type an unprivileged caller may create, and the process holds a memlock or
  memory-cgroup budget for that map; the design found no primary source that
  states which budget the kernel charges that map to, so the design treats
  this condition as an open precondition the check reads, not a settled kernel
  fact. The design's empty capability set leaves the probe without `CAP_BPF`
  or `CAP_SYS_ADMIN`, so the kernel treats it as unprivileged. A value of 1 or
  2 makes the kernel refuse the call with `EPERM` without `CAP_SYS_ADMIN` or
  `CAP_BPF`, and a request outside those other conditions is refused by the
  kernel even when the filter permits it; those cases are masked, so the
  design leaves them unclaimed. The design
  claims no falsifier for `perf_event_open`, because a
  `perf_event_paranoid` value that refuses the probe's event to an unprivileged
  caller can keep the refusal after the filter permits the call
  ([perf_event_paranoid](https://docs.kernel.org/admin-guide/sysctl/kernel.html#perf-event-paranoid)).
- `model_provider_ops_under_profile` (Linux counterpart) drives the model
  provider's named operations and decides the `file-read-data` row. Falsifier
  for the read row: add a Landlock read rule on `/`; the model provider's
  `model_outside_read_denied` fails. Falsifier for its start reads: refuse the
  fact syscalls its loader uses; the provider cannot start.
- `sandbox_gate_fails_instead_of_skipping_on_a_declared_os` (future `linux`
  case) requires a missing Landlock, userns or seccomp on a declared `linux` to
  be an error that names the OS and the primitive. Today the test expects
  `linux` to skip; that expectation changes only with the tests above (027).
