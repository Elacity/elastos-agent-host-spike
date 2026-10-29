# wallet-provider confinement

`confine.sb` is the one oracle for the wallet-provider sandbox profile (one
file, P10): the profile the Runtime generates for this provider must match it.
The oracle starts with `(version 1)` then `(deny default)`. Every operation
that no rule grants fails closed with a reason (P11).

## Profile parameters

The generated profile binds these three parameters, and the tests pass them
with `sandbox-exec -D`:

- `PROVIDER_EXECUTABLE` is the provider binary the launch starts.
- `STORAGE_ROOT` is `base_path/ElastOS/SystemServices/Wallet`.
- `STORAGE_PARENT` is its parent, `base_path/ElastOS/SystemServices`.

`../did-provider/` presents the same contract as this oracle: one profile file,
the same three parameter tokens, literal startup access, one state subtree
grant, and a real stdin/stdout process test.

The tests create the shared ancestors before launch, derive both storage
parameters from the same canonical `Init.base_path` and pass the original base
to `Init` (`start_with_profile`); the Runtime half of the bridge change does
the same and is not built. The provider creates the final
`Wallet` directory. Seatbelt grants recursive state access to that wallet
directory alone. Literal read access to its existing parent lets the provider
inspect and synchronize the directory while it creates Wallet. The parent
receives no recursive grant. The test launch refuses a second binding of a
canonical parameter, so those three paths come only from
`canonical_bindings`; `start_with_profile_refuses_a_canonical_parameter` holds
that rule. The same check reads the binding name before the first `=`, as
`sandbox-exec` does; `start_with_profile_refuses_an_encoded_canonical_parameter`
holds that rule for encoded names.

## What the profile allows

| Rule | Why the provider needs it |
| --- | --- |
| `(allow process-exec (literal PROVIDER_EXECUTABLE))` | Start only the binary the launch named. `unbound_copy_is_refused_under_profile` shows that a byte-identical copy of the binary under `STORAGE_ROOT` is refused with exit 71 and the `execvp()` `Operation not permitted` line, and `bound_copy_serves_under_profile` is its control. |
| `(allow file-read* (literal "/"))` | The kernel resolves every absolute path through the root directory. |
| `(allow sysctl-read)` | The loader and the allocator read kernel facts at startup. |
| `(allow file-read* (literal STORAGE_PARENT))` | Inspect and synchronize the existing parent during wallet directory creation. |
| `(allow file-read* file-write* (subpath STORAGE_ROOT))` | One grant owns all account, key, challenge and approval state under the wallet directory. |

The remaining filesystem and process operations stay under the default denial.

## No network path

Wallet-provider reads line-delimited JSON from stdin and writes one JSON
response per line to stdout. It opens no listener and no socket. The profile
starts from `(deny default)` and adds `(deny network*)`, so every network
operation is refused. `tests/confine.rs` checks that the profile keeps no
network allow rule, so a later change cannot add one without a failing test.

## The Runtime bridge change

The Runtime generates the provider's profile from the provider's approved
declared rights; it does not load a profile that the provider supplies.
`confine.sb` in this folder is the test oracle: the profile the Runtime
generates for this provider must match it, with the same three parameters bound
to the same paths. A lab generator, `generate_profile` in
`capsules/wallet-provider/tests/common/profile_generator.rs`, builds this
profile from the declared-rights file and the contract head, and
`generated_did_and_wallet_profiles_match_their_committed_oracles` requires it
to equal this oracle; the Runtime's own generator and its comparison are not
built and stay in `elastos/`, outside this lane.
This file is the one lab generator for did, wallet and model: each test crate
includes it by `#[path]` and never copies it (P10).
The lab generator and writer are test code only, and
`lab_generator_is_named_only_in_test_code` fails if a file outside test code
names either, so the Runtime keeps one profile generator (P10).
The one contract check, `check_profile_contract`, holds every oracle
to these terms, and the generated profile meets them too: `(version 1)` first,
`(deny default)` second, an explicit `(deny network*)`, no `(allow default)`,
no network allow, exactly one `process-exec` allow, the shared exec rule, only
the `PROVIDER_EXECUTABLE`, `STORAGE_ROOT` and `STORAGE_PARENT` parameter
tokens, and the three shared rules verbatim. An exec added later, such as a
model engine's, is its own named rule with its own falsifier and removal
condition, agreed with Sasha and Rong like the network grant, and never widens
what `PROVIDER_EXECUTABLE` binds.
If the profile cannot be applied, because the file is missing, does not parse
or names a parameter the launch does not bind, `sandbox-exec` exits before the
provider starts and gives its reason on standard error; the Runtime then
refuses the start with that reason and never starts the provider another way
(P11).
The lab writer `write_generated_profile` writes no wallet-provider profile when
the declared-rights file names an id the shared contract does not name, and
`generator_refuses_an_unnamed_right_and_the_start_is_refused` shows that the
start under that path is refused; the Runtime's own refusal is not built.

One generator covers `did-provider`, `wallet-provider` and `model-provider`,
parameterized by the provider's approved declared rights and its storage root,
so the Runtime has one path for a provider's profile (P10). That bridge change
is not built: the Runtime half that generates and enforces the profile is
future work in `elastos/`, outside this lane. The tests launch this provider
under its oracle with `/usr/bin/sandbox-exec -f confine.sb`, and
`startup_is_refused_when_the_profile_cannot_be_applied` proves that a start is
refused when the profile cannot be applied.

`every_did_and_wallet_allow_rule_traces_to_one_declared_right` reads
`capsules/wallet-provider/tests/fixtures/confine/declared-rights.json`. That
file is a lab stand-in for the Runtime generator's input and not a manifest
field. Every top-level allow rule of the wallet profile traces to exactly one
right the shared contract names, or to one platform-baseline rule. In the
wallet profile, each allow rule is claimed by the one id the contract names for
it, and no id or rule is declared twice. The profile rules are evidence for
Anders to review and not accepted rights. Its status label says "Runtime
platform baseline for the wallet-provider executable on macOS, not approved
rights". The model provider's
`capsules/model-provider/tests/fixtures/confine/declared-rights.json` uses the
same template, and `model_declared_rights_read_on_the_did_and_wallet_template`
reads it. The lab generator is test code, and the Runtime's own generator is
not built. Each platform-baseline rule in this provider's
`tests/fixtures/confine/declared-rights.json` gives one
justification that starts with the wallet-provider executable prefix,
`macOS wallet-provider executable bound as PROVIDER_EXECUTABLE:`, and gives a
reason; the `startup-root-directory` justification uses this document's
root-directory sentence, and a justification with another provider's prefix or
no reason is refused.

## Lab stand-in launcher

`standin_spawn_confined_provider` in `tests/confine.rs` is a lab stand-in in
test code, and it is not the Runtime. It copies the inputs of the Runtime's
provider launch entry, `ProviderBridge::spawn(binary_path, config)` with
`ProviderConfig.base_path`, because draft PR #309 names no provider-launch ask
that this stand-in could map to. The stand-in owns the start decision for the
lab proofs: a start it cannot confine is refused with a reason and returns no
provider.

The stand-in refuses in the order of these steps:

1. A host report that `standin_host_refusal` refuses is refused with that one
   reason, before any tool, binary or profile check, so a refused host writes
   no profile and creates no storage root. A host that reports a missing
   primitive is refused whatever its OS, before the `DECLARED_CONFINED_OS`
   lookup, and that is the one host check. The report holds the OS name and
   which of Landlock, user namespaces or the seccomp filter it reports
   unavailable. The reason starts `{name} start on {os} is refused:` and
   carries only its own case's words, as the journey paragraph below states.
2. An absent `sandbox-exec` is refused with a reason that names the OS and the
   path.
3. A present confinement tool that is not `SANDBOX_EXEC` is refused with a
   reason that names the OS, the given path and `SANDBOX_EXEC`, because the
   tool the stand-in checks is the one `start_under` runs.
4. A `binary_path` that is not a file is refused with a reason that names the
   provider and that path, before any profile is written.
5. A refusal of `write_generated_profile` is returned unchanged.
6. A start that `sandbox-exec` refuses is refused with the `try_send`
   failure.
7. An `init` that does not answer `ok` is refused with the answer.

Otherwise the stand-in writes the profile that the lab generator builds from
the declared rights, creates the shared ancestors, and starts the named binary
under that profile through `start_under` with the three canonical bindings. It
sends the provider's `init` config, which holds `base_path` and, for did, the
isolated fixture device key, and is Started only when `init` answers `ok`. The
stand-in never starts the binary outside `sandbox-exec`.

Both file-profile providers start through this one stand-in:
`wallet-provider` here and `did-provider` in the same test file, each with its
own committed declared-rights file, binary and storage-root layout. did's
start binds `<base>/did` as `STORAGE_ROOT` and `<base>` as `STORAGE_PARENT`.
`standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite`
holds M1 check B3 for both: it reads the provider's committed declared-rights
file, starts the binary through the stand-in into a fresh profile directory,
reads the one file the stand-in wrote there, and compares that launched profile
and the provider's permitted and denied suite with the provider's committed
`confine.sb`, case by case.

`standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host` holds the
one C0 journey for did first and then wallet: the macOS start through the
stand-in, one outside write refused with nothing created, the root still
answering, and `shutdown` exiting 0; then every host and process refusal the
stand-in must make. The stand-in's input is one host report, not a bare OS
name: an OS with no confinement design, a host that names one of Landlock, user
namespaces or the seccomp filter as unavailable on any OS, or a simulated
Linux host that reports nothing missing. Each refusal starts
`{name} start on {os} is refused:` and carries only its own case's words: an OS
with no confinement design names that OS and the list where the stand-in
applies confinement; a host with a missing primitive carries the design's
exact words for it from `CONFINEMENT-LINUX.md`, including a simulated `macos`
host whose report leaves Landlock unavailable; and a simulated Linux host that
reports nothing missing says Linux is designed, not enforced, in this lab, so
`linux` is not in `DECLARED_CONFINED_OS`. The Linux rows are simulated host
reports and not a Linux run, so no test here probes a kernel or claims Linux
enforcement.
The B3 journey reads the launched profile, so a stand-in that changes the file
after the writer, in a way the suite does not exercise, fails before the suite
starts. The launched file must pass `check_profile_contract` and
`check_declared_rights`, and it must equal the committed `confine.sb` through
the one comparison body `compare_profile_to_its_oracle`, the same body the
generated-profile test calls. Each case of the suite is pushed with its class,
and every record must hold the cases of that provider's list in order with
their names and classes, so a case that drops out or changes class fails with
the case named. A refusal keeps its answer's `status`, its `code` and the
stable start of its message, so two refusals that differ only in code do not
compare equal. The comparison then requires the two records, from the stand-in
start and from a start under the committed file, to agree entry by entry.
`standin_start_runs_under_the_generated_profile_not_the_committed_file`
requires the stand-in to refuse a start when the generated profile drops the
wallet-root write. The stand-in's start matches the committed `confine.sb` on
the launched profile and the permitted and denied suite in the lab, and this
section makes no claim about a Runtime launch.

Gap (#309, routed to Flint): draft PR #309 at 513988ebd names no provider-launch ask, so this launcher has no RA route to copy, and M1-R for C0 and B3 waits on that ask.

Launcher copy: `standin_spawn_confined_provider` is still a lane copy in `capsules/wallet-provider/tests/confine.rs`. Flint and Rong (2026-10-27 19:25) ruled the copy not acceptable; it is to move under the one shared stand-in, `lab/agent-conformance/standin-runtime/`, owned by cx-agent-conformance. The evidence here runs through the copy, and the move is not done.

## M1 acceptance summary: C0 and B3

This section records the lab evidence for M1 checks C0 and B3 for
`wallet-provider`. It states what the evidence is and gives no verdict;
cc-redteam judges C0 and B3.

Pins: `e31f0f517a3364c6067b1989c1c985c21f823312` is a fixed commit on this lane; every `confine.rs` line number in this section is read with `git show e31f0f517a3364c6067b1989c1c985c21f823312:capsules/wallet-provider/tests/confine.rs`, each wallet `falsifiers.json` entry line in this section is read with `git show e31f0f517a3364c6067b1989c1c985c21f823312:capsules/wallet-provider/falsifiers.json`, and each file pin below is a commit that holds the file, read with `git show <commit>:<path>`.

Gap (#309, routed to Flint): draft PR #309 at 513988ebd names no provider-launch ask, so this launcher has no RA route to copy, and M1-R for C0 and B3 waits on that ask.

Launcher copy: `standin_spawn_confined_provider` is still a lane copy in `capsules/wallet-provider/tests/confine.rs`. Flint and Rong (2026-10-27 19:25) ruled the copy not acceptable; it is to move under the one shared stand-in, `lab/agent-conformance/standin-runtime/`, owned by cx-agent-conformance. The evidence here runs through the copy, and the move is not done.

### C0 part

Written sentence: One C0 journey starts `did-provider` and `wallet-provider`
confined through the lab stand-in on macOS, or the stand-in refuses each host
and process it cannot confine with its own reason and starts no provider.

Counting rule, as `lab/redteam/acceptance/C8.md` words it: a complete journey, a
refusal with a reason, a CAUGHT falsifier, and reviews that pass.

Journey test: `standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host`
in `capsules/wallet-provider/tests/confine.rs` at
`16c4997d20b332d5e5f82999a10a035fcee6a3ab` (line 4165). It runs did first and
then wallet, and this doc records wallet's leg. Its macOS leg is
`standin_confined_journey` (line 3999): it starts the provider under the
stand-in's generated profile, refuses one outside write with nothing created,
keeps the root answering, and exits 0 on `shutdown`. Its refusal rows call
`standin_refusals_for` (line 3657), which reads one host report through
`standin_host_refusal` (line 904) and the launch through
`standin_spawn_confined_provider` (line 971).

Files at their commits:

- `capsules/wallet-provider/tests/confine.rs` at
  `16c4997d20b332d5e5f82999a10a035fcee6a3ab`, the journey test and the stand-in.
- `capsules/wallet-provider/tests/fixtures/confine/declared-rights.json` at
  `9bb0e9ba4debac4a78b512156841f1594d9bb8a4`.
- `capsules/did-provider/tests/fixtures/confine/declared-rights.json` at
  `7c5a31a956bec77db60c9d03c77d05ce6704852a`.
- `capsules/wallet-provider/falsifiers.json` at
  `16c4997d20b332d5e5f82999a10a035fcee6a3ab`.
- `lab/agent-conformance/standin-runtime/README.md` at
  `cccbd8ceb2fde5c2c3eda59ff932d09b33fc1592` answers the stand-in's routes and
  names no provider-launch route.

Refusals, with the reason the code produces and what the journey row checks for
`wallet-provider`. The did leg checks the same strings with `did-provider` in
place of `wallet-provider`. The first eight rows, `standin_refusals_for`'s cases
(a) to (c2), check the `{name} start on {os} is refused: ` prefix and the named
parts, and require the forbidden parts absent (lines 3776-3790); cases (c3),
(e) and (f) check no prefix.

- plan9 row: the code produces `wallet-provider start on plan9 is refused: plan9 has no confinement design, and the lab stand-in applies confinement only on macos`; the row checks the prefix and the parts `plan9`, `has no confinement design` and `macos`, and requires none of `linux is designed, not enforced`, `linux confinement refused: the kernel has no Landlock`, `linux confinement refused: user namespaces are turned off` or `linux confinement refused: the seccomp filter cannot be installed`.
- Linux without Landlock: the code produces `wallet-provider start on linux is refused: linux confinement refused: the kernel has no Landlock`; the row checks the prefix and that part, and requires none of `linux confinement refused: user namespaces are turned off`, `linux confinement refused: the seccomp filter cannot be installed`, `linux is designed, not enforced` or `has no confinement design`.
- Linux without user namespaces: the code produces `wallet-provider start on linux is refused: linux confinement refused: user namespaces are turned off`; the row checks the prefix and that part, and requires none of `linux confinement refused: the kernel has no Landlock`, `linux confinement refused: the seccomp filter cannot be installed`, `linux is designed, not enforced` or `has no confinement design`.
- Linux without the seccomp filter: the code produces `wallet-provider start on linux is refused: linux confinement refused: the seccomp filter cannot be installed`; the row checks the prefix and that part, and requires none of `linux confinement refused: the kernel has no Landlock`, `linux confinement refused: user namespaces are turned off`, `linux is designed, not enforced` or `has no confinement design`.
- Linux with every primitive reported present: the code produces `wallet-provider start on linux is refused: linux is designed, not enforced, in this lab, so linux is not in DECLARED_CONFINED_OS (macos)`; the row checks the prefix and the parts `linux is designed, not enforced` and `not in DECLARED_CONFINED_OS`, and requires none of `linux confinement refused: the kernel has no Landlock`, `linux confinement refused: user namespaces are turned off`, `linux confinement refused: the seccomp filter cannot be installed` or `has no confinement design`.
- macOS whose report leaves Landlock unavailable: the code produces `wallet-provider start on macos is refused: linux confinement refused: the kernel has no Landlock`; the row checks the prefix and the parts `linux confinement refused: the kernel has no Landlock` and `on macos`, and requires none of `linux confinement refused: user namespaces are turned off`, `linux confinement refused: the seccomp filter cannot be installed`, `linux is designed, not enforced` or `has no confinement design`.
- macOS without the tool: the code produces `wallet-provider start on macos is refused: the confinement tool <capsules/wallet-provider/tests/absent-sandbox-exec> is absent`; the row checks the prefix and the parts `on macos`, `is absent` and that path, and requires that the reason holds no `/usr/bin/sandbox-exec`.
- macOS with another tool: the code produces `wallet-provider start on macos is refused: the confinement tool <the test executable path> is not /usr/bin/sandbox-exec, which is the one the stand-in runs`; the row checks the prefix and the parts `on macos`, that path and `/usr/bin/sandbox-exec`.
- A binary path that is not a file: the code produces `wallet-provider start is refused: the provider binary <capsules/wallet-provider/tests/absent-provider-binary> is not a file`; the row checks the provider name and that path in the reason and requires no `must resolve` (lines 3835-3841), and it checks no prefix.
- An unnamed right: the code produces `wallet-provider declares unnamed-right, which the shared contract does not name`; the row compares the whole string exactly (lines 3882-3886).
- A profile the launch cannot apply: the code produces `wallet-provider start is refused: <failure>`; the row checks that the failure carries `exit status:` and `invalid data type of path filter` and requires no `execvp` (lines 3932-3942), and it checks no prefix.
- An `init` answer that is not ok: the code produces `wallet-provider start is refused: init answered <answer>`; the row checks that the reason carries `init answered` and `"status":"error"` (lines 3970-3976), and it checks no prefix.

CAUGHT falsifiers. Each entry is in `capsules/wallet-provider/falsifiers.json`
at `16c4997d20b332d5e5f82999a10a035fcee6a3ab`. The gate logs of PR #561, PR
#607, PR #643, PR #692 and PR #710 are not part of this tree, so this summary
quotes no raw `CAUGHT` line for those runs. One hand run of
`examples/agent-host/falsify.py --from
capsules/wallet-provider/falsifiers.json WP132 WP135 WP136 WP137` at
`606956b3dded92b183c56472b447b96fe0204a61` printed `CAUGHT` for all four; the
other entries were not rerun. The evidence read for each entry is its `expect`
of `caught`, its only named test
`standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host`, and the
plant named on its line.

- `WP112` (entry line 1798, PR #561, not rerun): starts the binary bare in the
  host refusal, so case (a) returns Started.
- `WP113` (entry line 1814, PR #561, not rerun): starts the binary bare after a
  failed `init`, so case (e) returns Started.
- `WP114` (entry line 1830, PR #561, not rerun): starts the binary without the
  generator and `sandbox-exec`, so the macOS leg succeeds at the outside write.
- `WP115` (entry line 1846, PR #561, not rerun): ignores the writer's refusal
  and starts under the committed `confine.sb`, so case (d) returns Started.
- `WP118` (entry line 1894, PR #607, not rerun): removes the check that the
  tool is `SANDBOX_EXEC`, so case (c2) is Started.
- `WP119` (entry line 1910, PR #607, not rerun): removes the binary-file check,
  so case (c3) panics in `resolved`.
- `WP120` (entry line 1926, PR #607, not rerun): answers `Ok(provider)` for an
  `init` that is not `ok`, so case (f) is Started.
- `WP125` (entry line 2006, PR #643, not rerun): makes the absent-tool check
  never fire, so case (c) reads the wrong-tool reason.
- `WP126` (entry line 2022, PR #643, not rerun): drops the OS from the
  wrong-tool reason, so case (c2) loses `on macos`.
- `WP131` (entry line 2102, PR #692, not rerun): starts the binary bare on a
  simulated Linux host that reports a missing primitive, so wallet's Landlock
  row returns Started.
- `WP132` (entry line 2118, PR #692, re-anchored by PR #710, rerun at
  `606956b3d`): returns one fixed reason that names no primitive, so wallet's
  Landlock row loses the design's exact words. The hand run printed
  `WP132  CAUGHT                             2s  the missing-primitive refusal returns one fixed reason that names no primitive`.
- `WP135` (entry line 2166, PR #710, rerun at `606956b3d`): moves the
  `DECLARED_CONFINED_OS` lookup above the missing-primitive check, so wallet's
  `macos` Landlock row returns Started where `sandbox-exec` exists.
- `WP136` (entry line 2182, PR #710, rerun at `606956b3d`): prefixes the
  missing-primitive reason with `linux has no confinement design; `, so wallet's
  Landlock row carries the forbidden words.
- `WP137` (entry line 2198, PR #710, rerun at `606956b3d`): drops the `{name}
  start on {os} is refused: ` prefix, so the plan9 row lacks it.

Reviews. Read with `gh pr view <number> --repo
Elacity/elastos-agent-host-spike --json body,mergeCommit`; each merge commit is
an ancestor of `16c4997d20b332d5e5f82999a10a035fcee6a3ab`. Each PASS line is
the pull request body, which states the reviews as passed; no reviewed SHA is
recorded in it.

- PR #561, https://github.com/Elacity/elastos-agent-host-spike/pull/561, merge
  `fc9cefc40a0d1ac29de5b985d53c54c96972b104`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #607, https://github.com/Elacity/elastos-agent-host-spike/pull/607, merge
  `aca346f10c47812aa8bbed616a7b1b1b7ac2accf`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #643, https://github.com/Elacity/elastos-agent-host-spike/pull/643, merge
  `5d8ba7997d598d952b432f7cd1adf9b0c38bb04e`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #672 (task 102; WP127's records say where it fails), https://github.com/Elacity/elastos-agent-host-spike/pull/672, merge `652cf3bd5c41fd080508662550005ead562512d4`. Body line: `Gates passed on the Mac; reviews PASS: claude,cursor.`
- PR #692, https://github.com/Elacity/elastos-agent-host-spike/pull/692, merge
  `705e4fbbdfaef640a51f5c707069a4a5e7564c5b`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #710, https://github.com/Elacity/elastos-agent-host-spike/pull/710, merge
  `b7ade04219ceb5d5affc567bd745a3a1cbe73006`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #725 (task 109), https://github.com/Elacity/elastos-agent-host-spike/pull/725, merge `606956b3dded92b183c56472b447b96fe0204a61`. Body line: `Gates passed on the Mac; reviews PASS: claude,cursor.`

What this part is not: it is lab stand-in evidence, not the Runtime. The Linux
rows are simulated host reports, not a Linux run. M1-R is not met because #309
has no provider-launch ask.

### B3 part

Written sentence: One B3 journey starts each provider from its committed
declared-rights file through the lab stand-in into a fresh profile directory,
reads the one file the stand-in wrote there, and requires that launched profile
and the provider's permitted and denied suite to match the provider's committed
`confine.sb`, case by case.

Counting rule, as `lab/redteam/acceptance/C8.md` words it: a complete journey, a
refusal with a reason, a CAUGHT falsifier, and reviews that pass.

Journey test: `standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite`
in the same file at `16c4997d20b332d5e5f82999a10a035fcee6a3ab` (line 4875). Its
leg is `standin_b3_journey` (line 4780). The launched-profile checks are
`check_profile_contract` (line 5564), `check_declared_rights` (line 5686) and
`compare_profile_to_its_oracle` (line 6604). The suite comparison is
`assert_suite_outcomes` (line 4676) and `assert_standin_matches_oracle` (line
4716). It runs did first and then wallet, and this doc records wallet's leg.

Files at their commits:

- `capsules/wallet-provider/tests/confine.rs` at
  `16c4997d20b332d5e5f82999a10a035fcee6a3ab`, the journey test and the
  comparison body.
- `capsules/wallet-provider/confine.sb` at
  `959b104022bd0e8ae55636f69f6f06b8eb028e2b`.
- `capsules/did-provider/confine.sb` at
  `959b104022bd0e8ae55636f69f6f06b8eb028e2b`.
- `capsules/wallet-provider/tests/fixtures/confine/declared-rights.json` at
  `9bb0e9ba4debac4a78b512156841f1594d9bb8a4`.
- `capsules/did-provider/tests/fixtures/confine/declared-rights.json` at
  `7c5a31a956bec77db60c9d03c77d05ce6704852a`.
- `capsules/wallet-provider/falsifiers.json` at
  `16c4997d20b332d5e5f82999a10a035fcee6a3ab`.

Refusals, with the message the code writes for `wallet-provider`: each quoted
line is the panic's own message, and the panic prints it with Rust's frame. The
`assert_eq!` rows (order or class, case count, entry, extra entries) print it
after Rust's ``assertion `left == right` failed: `` and before the left/right
lines. `assert_suite_outcomes` checks the record under the committed
`confine.sb` with the label `<name>'s committed confine.sb` first (lines
4826-4830), so a change that breaks both records panics with that label in place
of `<name>'s stand-in launched profile`; the stand-in label (lines 4831-4835),
which the lines below quote, shows when only the launched profile differs. The
did leg asserts the same strings with `did-provider` in place of
`wallet-provider`.

- Launched-profile mismatch, contract check: `wallet-provider B3 journey: the launched profile must pass the contract check: wallet-provider must deny the network explicitly with (deny network*)`.
- Launched-profile mismatch, declared-rights check: `wallet-provider B3 journey: the launched profile must trace to its declared rights: wallet-provider allow rule has no declared right and no platform-baseline rule: <appended allow form>`.
- Launched-profile mismatch, oracle comparison: `wallet-provider B3 journey: the launched profile and its oracle disagree: wallet-provider generated profile differs from its committed oracle: only in generated <forms>, only in committed <forms>`.
- Suite mismatch, case count: `wallet-provider stand-in start must record as many cases as the committed confine.sb: committed <count>, stand-in <count>`.
- Suite mismatch, entry: `wallet-provider stand-in start differs from the committed confine.sb on case "<case>": committed <outcome>, stand-in <outcome>`.
- Suite mismatch, short record: `wallet-provider's stand-in launched profile suite must record case "<case>" as <class>: the record holds N entries`, where N is the record's length (lines 4679-4682).
- Suite mismatch, order or class: `wallet-provider's stand-in launched profile must record case "<case>" as <class>` (lines 4684-4688).
- Suite mismatch, permitted case not `ok`: `wallet-provider's stand-in launched profile must permit case "<case>": <outcome>` (lines 4690-4695).
- Suite mismatch, denied case not refused: `wallet-provider's stand-in launched profile must refuse case "<case>": <outcome>` (lines 4696-4701).
- Suite mismatch, extra entries: `wallet-provider's stand-in launched profile suite must record no case beyond Some("<case>")` (lines 4704-4709), where `cases.last()` is an `Option`, so `{:?}` prints `Some("<case>")`.

CAUGHT falsifiers. Each entry is in `capsules/wallet-provider/falsifiers.json`
at `16c4997d20b332d5e5f82999a10a035fcee6a3ab`. The gate logs of PR #593, PR
#624, PR #635, PR #655, PR #704 and PR #718 are not part of this tree, so this
summary quotes no raw `CAUGHT` line and did not rerun a plant. The evidence read
for each entry is its `expect` of `caught`, its only named test
`standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite`, and
the plant named on its line. Each line cites the check that catches it, as the
merged words of PR #718 say.

- `WP116` (entry line 1862, PR #593, not rerun): binds the stand-in's
  `STORAGE_ROOT` to the base; the widened grant permits did's sibling write, so
  the suite step fails there.
- `WP121` (entry line 1942, PR #624, not rerun): removes the planted-key push,
  so wallet's record holds eight entries where `SUITE_CASES` holds nine.
- `WP124` (entry line 1990, PR #635, not rerun): uses wallet's root layout for a
  did start, so did's first `init` is refused.
- `WP127` (entry line 2038, PR #655, not rerun): appends `(allow file-write* (subpath (param "STORAGE_PARENT")))` to did's launched profile; `check_declared_rights` catches it at did's launched-profile check, and the suite never starts.
- `WP133` (entry line 2134, PR #704, not rerun): appends `(allow file-read* (literal "/private/etc/hosts"))` to the launched profile; `check_declared_rights` catches it at that same check, and no suite case reads that path.
- `WP134` (entry line 2150, PR #704, not rerun): removes `(deny network*)` from the launched profile; `check_profile_contract` catches it at that same check.
- `WP138` (entry line 2214, PR #718, not rerun): appends `(deny file-write* (literal "/private/var/cc-confine-launched"))` after the writer; only `compare_profile_to_its_oracle` catches it, because the head keeps its order and neither contract check reads a deny form.

Reviews. Read with `gh pr view <number> --repo
Elacity/elastos-agent-host-spike --json body,mergeCommit`; each merge commit is
an ancestor of `16c4997d20b332d5e5f82999a10a035fcee6a3ab`. Each PASS line is
the pull request body, which states the reviews as passed; no reviewed SHA is
recorded in it.

- PR #593, https://github.com/Elacity/elastos-agent-host-spike/pull/593, merge
  `693c3681db472d565a2ce07abc9ec2c9a7e0b7e0`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #624, https://github.com/Elacity/elastos-agent-host-spike/pull/624, merge
  `eb92d432778dcdeb5476e35e10f822dd74c6ab9b`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #635, https://github.com/Elacity/elastos-agent-host-spike/pull/635, merge
  `3bfc39b026c86f0bf549fa2b8b53965c955418c2`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #655, https://github.com/Elacity/elastos-agent-host-spike/pull/655, merge
  `62eac8742bb84ec1106159a6c1e5bba988476d9a`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #672 (task 102; WP127's records say where it fails), https://github.com/Elacity/elastos-agent-host-spike/pull/672, merge `652cf3bd5c41fd080508662550005ead562512d4`. Body line: `Gates passed on the Mac; reviews PASS: claude,cursor.`
- PR #704, https://github.com/Elacity/elastos-agent-host-spike/pull/704, merge
  `978873050f6dc3884cef117e39d4345e38d7fb2c`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #718, https://github.com/Elacity/elastos-agent-host-spike/pull/718, merge
  `345697ee3a954e140700033775bad1349587c513`. Body line: `Gates passed on the
  Mac; reviews PASS: claude,cursor.`
- PR #725 (task 109), https://github.com/Elacity/elastos-agent-host-spike/pull/725, merge `606956b3dded92b183c56472b447b96fe0204a61`. Body line: `Gates passed on the Mac; reviews PASS: claude,cursor.`

What this part is not: it is lab stand-in evidence, not the Runtime. The Linux
rows are simulated host reports, not a Linux run. M1-R is not met because #309
has no provider-launch ask.

## The model provider's inline profile

`elastos/crates/elastos-runtime/src/provider/bridge.rs` builds a third,
pre-existing convention for the model provider. Four facts differ from the
contract above: it starts `(allow default)` instead of `(deny default)`; it
interpolates storage paths into `(regex ...)` rules rather than binding a
`(param ...)` token; it grants an explicit
`(allow network-outbound (literal ...))` socket; and it passes its policy
inline with `sandbox-exec -p` rather than `-f confine.sb`. It does not share
the file-profile contract and this document does not claim it does. Aligning
the model provider is future Runtime work in `elastos/`, outside this lane.
The model provider's own file profile, `../model-provider/confine.sb`,
presents this contract as an oracle, and the shared test requires it; the
generated profile for the model provider must match it too.

## Operations and the rights they need

Each operation the provider answers is one row. The inputs are the operation's
top-level JSON names. An ok answer is `status` plus `data`; an ok answer with
no data omits `data`, so `shutdown` answers `{"status":"ok"}` only. An error
answer is `status`, `code` and `message`. The keys of `data` are the keys of
the value the handler returns. Every `wallet_contract` row answers one
`WalletProviderResponseV2` as `data`, which `src/main.rs`
`handle_wallet_contract` serializes for the ok answer. A right, an effect, a
macOS rule or a test is written only where a named test in `tests/confine.rs`
or `src/tests/` shows it.
Where no named test shows one, the cell says "no named test shows this". A
citation is a backtick span that holds a file relative to this folder, two
colons and a function name. The check
`every_operations_table_cites_existing_tests` in `tests/confine.rs` finds
`fn <fn>(` in that file and does not decide whether the function is a
`#[test]`. The check
`every_operations_table_row_matches_its_provider_and_the_contract` holds every
row to four rules: the row set follows the provider's own dispatch, a Right
cell names a declared id or `none: needs no declared right`, a right row cites
both sides, and every Linux cell stays `designed, not enforced`. A refusal
under `(deny default)` is a denial, not a grant, and no
row writes it as a right. A refusal from a `kind` comes back as an outer
`status` `ok` whose `data.result` holds `status` `error`, `code` and `message`;
the outer `status`/`code`/`message` error covers envelope failures only. A
`storage` row cites both sides of its right: `permitted:` names the test that
shows the operation under `STORAGE_ROOT`, and `nearest outside refused:` names
the test that shows the operation on a base beneath `STORAGE_PARENT` refused,
each with its falsifier ids. A row whose Right is "no named test shows this"
or `none: needs no declared right` names no granted resource, so it has no
outside case, and its cell cites only the test that shows the answer and that
test's falsifier. The startup grants stay in "What the profile allows".

M1 check B4 stays open: this table records the macOS half of its permission
model. Linux stays designed, not enforced, and this section claims no current
Linux behaviour. The design is `CONFINEMENT-LINUX.md`; its tests do not exist
yet. A JSON parse failure answers `invalid_request`; it is not an operation
and gets no row.

| Operation | Inputs | Outputs | Right | Effect | macOS rule and test | Linux |
| --- | --- | --- | --- | --- | --- | --- |
| init | `op`, `config` | ok: `status`, `data` (`provider`, `protocol_version`, `storage_configured`, `managed_wallets_configured`, `pre_v2_approvals_rejected`). error: `status`, `code`, `message`. | `storage` | creates the wallet directory and reads or creates `wallet-key.hex` and `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::confined_outside_read_is_denied` shows the key read refused when that path resolves outside. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::confined_provider_serves_wallet_operations_under_its_root` shows this call creating the wallet directory and its key under `STORAGE_ROOT`, and its removal is WP18. nearest outside refused: the read half of `tests/confine.rs::planted_key_beneath_storage_parent_is_not_read` shows a complete key beneath `STORAGE_PARENT` unread, so this call refuses that base, and its removal is WP57; the write half is the `<STORAGE_PARENT>/Fresh` case of `tests/confine.rs::confined_outside_write_is_denied`, whose removal is WP65. | designed, not enforced |
| status | `op` | ok: `status`, `data` (`provider`, `version`, `protocol_version`, `storage_configured`, `managed_wallets_configured`, `active_account_count`, `managed_account_count`, `pending_challenge_count`, `pending_bitcoin_challenge_count`, `pending_approval_count`, `supported_operations`). error: `status`, `code`, `message`. | none: needs no declared right | counts in-memory state; no named test shows a file read or write for this call. | `tests/confine.rs::confined_provider_serves_wallet_operations_under_its_root` shows the answer; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the wallet directory after the setup is the same after this call, and WP139 and WP140, which plant in this call, are its falsifiers. | designed, not enforced |
| shutdown | `op` | ok: `{"status":"ok"}` only. error: `status`, `code`, `message`. | none: needs no declared right | answers and exits; no named test shows a file read or write for this call. | `tests/confine.rs::bound_copy_serves_under_profile` shows the answer and a clean exit; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the wallet directory after the setup is the same after this call, and WP145, which fails the final compare after this call, is its falsifier. | designed, not enforced |
| wallet_contract list_accounts | `op`, `request` (`kind: list_accounts`, `params` (`include_revoked`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | none: needs no declared right | reads the in-memory store loaded at `init`; no named test shows a file read or write for this call. | `tests/confine.rs::confined_provider_serves_wallet_operations_under_its_root` shows the listing after `create_managed_account`; the store read belongs to `init`; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the wallet directory after the setup is the same after this call, and the only registered plants for this test are `WP139` and `WP140` in `status` and `WP145` in `shutdown`, so a regression in this call alone fails the test with no plant of its own. | designed, not enforced |
| wallet_contract create_managed_account | `op`, `request` (`kind: create_managed_account`, `params` (`chain_namespace`, `label`, `create_new`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the account and its encrypted managed key into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::confined_provider_serves_wallet_operations_under_its_root` shows the account in the store under the root. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::confined_provider_serves_wallet_operations_under_its_root` shows this call writing the account and its key under `STORAGE_ROOT`, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract link_verified_account | `op`, `request` (`kind: link_verified_account`, `params` (`proof_binding_id`, `chain_namespace`, `address`, `proof_type`, `label`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the account into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::evm_proofs_and_link_persist_under_storage_root` shows the linked account with its proof binding in `list_accounts` after a restart. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::evm_proofs_and_link_persist_under_storage_root` shows this call writing the account and its proof binding under `STORAGE_ROOT`, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract revoke_account | `op`, `request` (`kind: revoke_account`, `params` (`account_id`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the revoked marker into `wallet-state.json` under `STORAGE_ROOT`; `src/tests/accounts.rs::revoke_account_hides_account_by_default` shows the answer that only a successful write returns. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::account_edits_persist_under_storage_root` shows this call writing the revoked marker under `STORAGE_ROOT`, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract rename_account | `op`, `request` (`kind: rename_account`, `params` (`account_id`, `label`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the label into `wallet-state.json` under `STORAGE_ROOT`; `src/tests/accounts.rs::rename_account_updates_active_label_only` shows the answer that only a successful write returns. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::account_edits_persist_under_storage_root` shows this call writing the new label under `STORAGE_ROOT`, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract set_default_account | `op`, `request` (`kind: set_default_account`, `params` (`chain_namespace`, `intent`, `account_id`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the default entry into `wallet-state.json` under `STORAGE_ROOT`; `src/tests/accounts.rs::default_account_is_principal_scoped_and_drives_explicit_signature_requests` shows the default after a re-init. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::account_edits_persist_under_storage_root` shows the answer that only a successful write returns, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract default_account | `op`, `request` (`kind: default_account`, `params` (`chain_namespace`, `intent`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | none: needs no declared right | looks up the in-memory store loaded at `init`; no named test shows a file read or write for this call. | `tests/confine.rs::account_edits_persist_under_storage_root` shows the answer after `set_default_account`; the store read belongs to `init`; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the wallet directory after the setup is the same after this call, and the only registered plants for this test are `WP139` and `WP140` in `status` and `WP145` in `shutdown`, so a regression in this call alone fails the test with no plant of its own. | designed, not enforced |
| wallet_contract challenge | `op`, `request` (`kind: challenge`, `params` (`domain`, `uri`, `address`, `chain_id`, `resources`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the challenge into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::evm_proofs_and_link_persist_under_storage_root` shows the reloaded `pending_challenge_count` after a restart. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::evm_proofs_and_link_persist_under_storage_root` shows this call writing the challenge under `STORAGE_ROOT`, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract bitcoin_challenge | `op`, `request` (`kind: bitcoin_challenge`, `params` (`domain`, `uri`, `address`, `network`, `resources`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the challenge into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::bitcoin_proofs_persist_under_storage_root` shows the reloaded `pending_bitcoin_challenge_count` after a restart. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::bitcoin_proofs_persist_under_storage_root` shows this call writing the challenge under `STORAGE_ROOT`, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract verify_proof | `op`, `request` (`kind: verify_proof`, `params` (`message`, `signature`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the consumed challenge into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::evm_proofs_and_link_persist_under_storage_root` shows the consumed challenge reloaded. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::evm_proofs_and_link_persist_under_storage_root` shows this call writing the consumed challenge under `STORAGE_ROOT`, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract verify_contract_proof | `op`, `request` (`kind: verify_contract_proof`, `params` (`message`, `signature`, `evidence`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the consumed challenge into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::evm_proofs_and_link_persist_under_storage_root` shows the consumed challenge reloaded. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::evm_proofs_and_link_persist_under_storage_root` shows this call writing the consumed challenge under `STORAGE_ROOT`, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract verify_bip322_proof | `op`, `request` (`kind: verify_bip322_proof`, `params` (`message`, `signature`, `signature_type`, `public_key`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the consumed challenge into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::bitcoin_proofs_persist_under_storage_root` shows the consumed challenge reloaded. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::bitcoin_proofs_persist_under_storage_root` signs the `bitcoin_signed_message` type and shows this call writing the consumed challenge under `STORAGE_ROOT`, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract request_protected_content_rights_signature | `op`, `request` (`kind: request_protected_content_rights_signature`, `params` (`account_id`, `canonical_rights_request_hex`, `reason`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the approval request into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::protected_content_rights_request_persists_under_storage_root` shows the approval request written, reloaded and completed after a restart; `src/tests/approvals/protected_content.rs::protected_content_rights_managed_and_external_sign_identical_canonical_result` shows the answer that only a successful write returns. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::protected_content_rights_request_persists_under_storage_root` shows this call answering with a pending approval request bound to the hex sent and writing it under `STORAGE_ROOT`, then `approve_and_sign_managed` completes it after a restart, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract request_approval | `op`, `request` (`kind: request_approval`, `params` (`account_id`, `chain_namespace`, `intent`, `resource`, `reason`, `payload`, `expires_at`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the approval request into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::managed_approvals_persist_under_storage_root` shows both requests in the store after a restart. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::managed_approvals_persist_under_storage_root` shows this call writing two pending approvals under `STORAGE_ROOT`, then `status` and `list_approvals` after a restart, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract attach_validated_chain_outcome | `op`, `request` (`kind: attach_validated_chain_outcome`, `params` (`outcome`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the projection into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::connector_handoff_and_chain_outcome_persist_under_storage_root` shows the stored outcome reloaded after a restart and a substituted outcome refused. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::connector_handoff_and_chain_outcome_persist_under_storage_root` shows this call writing the outcome under `STORAGE_ROOT`, then a substituted outcome refused after a restart and the `read_store` check showing the stored outcome, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract list_approvals | `op`, `request` (`kind: list_approvals`, `params` (`include_resolved`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | none: needs no declared right | reads the in-memory store loaded at `init`; no named test shows a file read or write for this call. | `tests/confine.rs::managed_approvals_persist_under_storage_root` shows the answer for the pending listing and for the resolved listing; the store read belongs to `init`; `tests/confine.rs::no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` shows the wallet directory after the setup is the same after this call, and the only registered plants for this test are `WP139` and `WP140` in `status` and `WP145` in `shutdown`, so a regression in this call alone fails the test with no plant of its own. | designed, not enforced |
| wallet_contract reject_approval | `op`, `request` (`kind: reject_approval`, `params` (`request_id`, `reason`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the rejection into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::managed_approvals_persist_under_storage_root` shows the rejected status in the store after a restart. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::managed_approvals_persist_under_storage_root` shows this call answering `rejected` and writing that status under `STORAGE_ROOT`, then `list_approvals` with `include_resolved` lists it after a restart, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract approve_and_sign_managed | `op`, `request` (`kind: approve_and_sign_managed`, `params` (`request_id`, `reason`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the completion into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::managed_approvals_persist_under_storage_root` shows the completed status in the store after a restart. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::managed_approvals_persist_under_storage_root` shows this call answering `completed` with a signature and writing that status under `STORAGE_ROOT`, then `list_approvals` with `include_resolved` lists it after a restart, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract approve_connector_handoff | `op`, `request` (`kind: approve_connector_handoff`, `params` (`request_id`, `reason`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the approval into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::connector_handoff_and_chain_outcome_persist_under_storage_root` shows this call answering `approved` with a handoff of intent `transaction_intent`, and that status reloaded by a replayed approve after a restart. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::connector_handoff_and_chain_outcome_persist_under_storage_root` shows this call writing the approved status under `STORAGE_ROOT`, then the replayed approve answers `invalid_request` with `not pending` after a restart, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract complete_connector_handoff | `op`, `request` (`kind: complete_connector_handoff`, `params` (`request_id`, `payload_hash`, `signature`, `signature_type`, `public_key`, `signer`, `transaction_hash`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the completion into `wallet-state.json` under `STORAGE_ROOT`; `tests/confine.rs::connector_handoff_and_chain_outcome_persist_under_storage_root` shows this call answering `completed` with the transaction hash sent, and that status reloaded by a replayed completion after a restart. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::connector_handoff_and_chain_outcome_persist_under_storage_root` shows this call writing the completed status and the transaction hash under `STORAGE_ROOT`, then the replayed completion answers `invalid_request` with `must be approved before completion` after a restart, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract export_managed_recovery_key | `op`, `request` (`kind: export_managed_recovery_key`, `params` (`account_id`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the consumed lifecycle into `wallet-state.json` under `STORAGE_ROOT`; `src/tests/accounts.rs::export_managed_recovery_key_is_available_for_active_managed_account_only` shows the answer that only a successful write returns. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::managed_recovery_writes_persist_under_storage_root` shows this call exporting the active managed account's recovery key and saving that request's consumed lifecycle under `STORAGE_ROOT`, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract import_managed_recovery_key | `op`, `request` (`kind: import_managed_recovery_key`, `params` (`recovery_key`, `label`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the recovered account and key into `wallet-state.json` under `STORAGE_ROOT`; `src/tests/accounts.rs::import_managed_recovery_key_restores_exported_wallet` shows the imported account and its available key in the same process after the re-init that precedes the import. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::managed_recovery_writes_persist_under_storage_root` shows this call importing the exported key into a target wallet under `STORAGE_ROOT` and reloading the account with `managed_key_available`, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract export_managed_recovery_set | `op`, `request` (`kind: export_managed_recovery_set`, `params` (none)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the consumed lifecycle into `wallet-state.json` under `STORAGE_ROOT`; `src/tests/accounts.rs::managed_recovery_set_exports_only_active_managed_accounts_and_restores_labels` shows the exported set that holds only active managed accounts, with their labels. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::managed_recovery_writes_persist_under_storage_root` shows this call exporting the set of active managed accounts and saving that request's consumed lifecycle under `STORAGE_ROOT`, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |
| wallet_contract import_managed_recovery_set | `op`, `request` (`kind: import_managed_recovery_set`, `params` (`recovery_set`)), `_runtime_invocation` | ok: `status`, `data` (`schema`, `protocol_version`, `request_id`, `operation`, `audit_id`, `lifecycle_id`, `session_binding`, `account_binding`, `approval_binding`, `result` from `WalletProviderResponseV2`), names only. error: `status`, `code`, `message`. | `storage` | writes the recovered accounts into `wallet-state.json` under `STORAGE_ROOT`; `src/tests/accounts.rs::managed_recovery_set_exports_only_active_managed_accounts_and_restores_labels` shows the restored labels in the same process that imports them into a target wallet. | The `STORAGE_ROOT` subpath rule is `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))`. permitted: `tests/confine.rs::managed_recovery_writes_persist_under_storage_root` shows this call importing the exported set into a target wallet under `STORAGE_ROOT` and reloading the restored labels, and its removal is WP18. nearest outside refused: `tests/confine.rs::account_operations_beneath_storage_parent_are_refused` shows this call refused with `not_initialized` after `Init` for a base beneath `STORAGE_PARENT` refused, and nothing created beside it, and its removal is WP88. | designed, not enforced |

## Host-OS status

The confinement tests exercise these oracles on macOS through
`/usr/bin/sandbox-exec`. On macOS a test that cannot run because that tool is
missing fails the gate; it never passes by skipping. On any host OS other than
macOS the `sandbox-exec` integration tests print a skip reason and do not run
when that tool is absent. The gate test
`sandbox_gate_fails_instead_of_skipping_on_a_declared_os` checks that rule: a
missing tool on `macos` is an error that names the OS and the path, a missing
one on `linux` is a skip, and a present one on `macos` runs the test.
The one caller, `sandbox_available`, fails the test on that error;
`sandbox_available_fails_for_macos_when_sandbox_exec_is_missing` calls it
with `macos` and a missing path and expects the failure.
The Linux policy stays outside this provider's status. A provider-status claim
needs host-specific test evidence and the Runtime acceptance step, so no status
document records `did-provider` or `wallet-provider` as confined on Linux (P10,
P11). The status change lands when the Runtime side does.

Most Linux enforcement rows are designed in `CONFINEMENT-LINUX.md` and remain
unbuilt. One row exists today as source with a real Linux run behind it: a
seccomp allow list generated from this provider's declared rights, with the one
builder, the one mapping table, the one step sequencer and the one install
function that file names
(`seccomp_allow_list_from_declared_rights`, `SECCOMP_RULE_SYSCALLS`,
`install_seccomp_with`, `install_seccomp`). On a real Linux host the wallet
provider starts under that filter and the four denied calls answer the filter's
own marker there, as `CONFINEMENT-LINUX.md` records with its host, kernel and
per-call answers. That is the whole Linux claim: namespaces, Landlock,
capability dropping and every file row of the contract remain unbuilt, so
`linux` stays out of `DECLARED_CONFINED_OS` and every operations-table cell
reads `designed, not enforced`.
`both_file_profiles_bind_one_storage_parameter_contract` reads the three oracles
and supplies contract evidence, not Linux execution evidence.

## Tests

`tests/confine.rs` builds the provider and runs it under this profile:

- `confined_provider_serves_wallet_operations_under_its_root` drives `Init`,
  `status`, `CreateManagedAccount` and `ListAccounts` over the real protocol and
  checks that the account and storage key land under the wallet root.
- `account_edits_persist_under_storage_root` drives `Init` and
  `create_managed_account`, then `rename_account`, `set_default_account`,
  `default_account` and `revoke_account`, each through `ok_data`. A second
  provider on the same root reloads the new label and the revoked marker
  through `list_accounts` with `include_revoked` and from
  `wallet-state.json` under the wallet directory. Removing the storage-root
  grant (WP18) makes the first `Init` fail.
- `confined_outside_write_is_denied` sends `Init` for an unrelated base,
  `base_path/sibling`, and a sibling service under `ElastOS/SystemServices`.
  The provider answers `storage_error`, answers the next `status`, and can
  reinitialize its allowed root. Each attempted wallet directory stays absent.
  A fourth case sends `Init` for `<STORAGE_PARENT>/Fresh`, where nothing is
  precreated at `Fresh` or beneath it, so the walk reaches the granted parent
  and the first ungranted step is the `mkdir`; the refusal is the create step
  itself, the base stays absent and the next `status` answers ok.
- `confined_outside_read_is_denied` plants a complete key in a sibling wallet.
  It adds literal fixture directory reads and file metadata reads to a copy
  of the single profile source. These grants let `Init` reach the key open;
  the test asserts that this open is the refused operation. The fixture adds
  neither file-content reads nor writes outside the wallet grant.
- `planted_key_beneath_storage_parent_is_not_read` plants a complete key in a
  sibling directory beneath `STORAGE_PARENT` and outside `STORAGE_ROOT`, then
  sends `Init` for that sibling base. Under the real profile the provider
  answers `storage_error`, the planted bytes stay unchanged and no
  `wallet-state.json` appears beside them. The provider then answers `status`
  and serves its own root; the key it writes there differs from the planted
  one, so it never adopted the planted key. The parent read grants the
  directory itself only, so widening it to `subpath` makes this test fail; the
  write half beneath the parent is the `<STORAGE_PARENT>/Fresh` case of
  `confined_outside_write_is_denied`, which is refused at its first write.
- `account_operations_beneath_storage_parent_are_refused` precreates an empty
  wallet directory at `<STORAGE_PARENT>/Sibling`, so the refused step is the
  inspect rather than the `Fresh` `mkdir` or a planted key read. `Init` for
  that sibling base answers `storage_error`; `rename_account`,
  `revoke_account`, `set_default_account`, `default_account`,
  `export_managed_recovery_key`, `import_managed_recovery_key`,
  `export_managed_recovery_set`, `import_managed_recovery_set`, `challenge`,
  `verify_proof`, `verify_contract_proof`, `link_verified_account`,
  `bitcoin_challenge`, `verify_bip322_proof`, `request_approval`,
  `approve_and_sign_managed`, `reject_approval`, `list_approvals`,
  `approve_connector_handoff`, `complete_connector_handoff`,
  `attach_validated_chain_outcome`,
  `request_protected_content_rights_signature`, `create_managed_account` and
  `list_accounts` then answer through `data.result` with `status` `error`,
  `code` `not_initialized` and a reason, and the sibling's wallet directory
  stays empty. The loop checks every call and one assertion fails once,
  naming each call that is not refused. `list_accounts` is sent only to show
  that nothing was created. `Init` for the granted root answers ok, the
  account call lands the account in the store under the root, and the listing
  holds it. Widening the parent grant to read and write (WP88) makes the
  sibling `Init` succeed, so the one assertion names every call that is not
  refused; removing the storage-root grant (WP18) makes the granted `Init`
  fail.
- `profile_denies_network` checks that the profile has `(deny default)` and no
  network allow or `(allow default)` rule, including one appended after denial.
- `startup_denial_reports_its_reason` covers the failure path. It starts the
  provider under a fixture profile that holds `(version 1)` and `(deny default)`,
  so `sandbox-exec` cannot exec it, waits for that child to exit, and sends
  `init`. The one harness failure names the request, the child's exit status and
  `sandbox-exec`'s own `execvp()` denial of the provider binary, `Operation not
  permitted`, from standard error, so another denial cannot stand in for the exec
  denial. A second fixture child reads one request and exits without answering,
  so the response-stream branch reports the same three facts. An answer that is
  not JSON fails with its own message, which names the request, the parse error
  and the answer, and does not say the provider did not answer;
  `invalid_json_answer_names_the_request_and_the_parse_error` checks it. The
  harness drains standard error on its own thread while the child runs, so a
  child that fills the pipe still reaches its own exit.
  `stderr_is_drained_before_wait` writes 128 KiB to standard error and expects
  every byte plus the child's own exit status; it fails when the drainer starts
  only after the wait, because the child then never exits within the deadline.
  The startup case skips with its printed reason when `sandbox-exec` is absent on
  a host OS other than macOS.
- `startup_is_refused_when_the_profile_cannot_be_applied` starts the provider
  under a profile that cannot be applied: a path that does not exist, a copy of
  `confine.sb` with its last `)` removed, and the real profile with every
  parameter bound except `STORAGE_ROOT`. `sandbox-exec` exits with a status
  other than 0 in each case, no wallet directory is created, and the harness
  failure names the request, the exit status and `sandbox-exec`'s own line on
  standard error. That failure also shows that `sandbox-exec` refused the
  profile before any exec.

- The Linux half of `tests/confine.rs` builds nothing on the Mac. Five tests are
  `#[cfg(target_os = "linux")]` and one runs everywhere:
  `linux_wallet_journey_runs_under_the_seccomp_allow_list` starts the provider
  under the generated filter and requires the launched child's own
  `SECCOMP_MODE_FILTER`, the launcher's own install, and one file under
  `STORAGE_ROOT` as its path evidence, then runs one probe child that shows the
  four refused calls answering the filter's marker;
  `linux_did_journey_runs_under_the_seccomp_allow_list` is the second caller of
  the same journey body, with did's own binary, declared rights and permitted
  operations, so the one path carries both providers and neither has a private
  copy of the builder, the installer or the probe;
  `linux_seccomp_launch_refuses_each_failed_install` requires each install
  failure and an architecture refusal to start nothing;
  `linux_seccomp_launcher_runs_the_requested_program` requires the child's own
  `exe` link to name the program the launcher was given;
  `linux_seccomp_probe_reaps_failures_and_repeated_journeys` requires every
  probe child to be reaped and the kernel proof to answer the same twice; and
  `linux_seccomp_journey_is_not_applicable_off_linux` runs on every OS and
  requires the journey's label to say `not applicable` and this OS off Linux.
  `CONFINEMENT-LINUX.md` records the host, kernel, per-call answers and the two
  kernel plants behind the journey, and the two plants on the did caller.
- `seccomp_launch_record_refuses_missing_or_unknown_report` reads the one
  install-record reader and requires a missing, short, long and unknown-step
  record each to give its own reason, and a complete record to carry the
  marker's two answers. It reads no kernel and runs on every OS.

`unbound_copy_is_refused_under_profile` and `bound_copy_serves_under_profile`
split the exec rule into its two halves under the real profile, with no fixture
rule. The first binds the real binary as `PROVIDER_EXECUTABLE` and starts a
byte-identical copy stored under `STORAGE_ROOT`; `sandbox-exec` applies the
profile before the exec, so the copy is refused with exit 71 and the `execvp()`
`Operation not permitted` line, the `init` request gets no answer, and the
storage root keeps only the copy with its bytes unchanged. The second is its
control: the same fixture with `PROVIDER_EXECUTABLE` bound to the copy and the
copy started answers `init` and `status` and exits 0 after `shutdown`, so the
binding is the only difference between the two runs.

- `both_file_profiles_bind_one_storage_parameter_contract` lives in
  `../wallet-provider/tests/confine.rs`. One check function holds the
  contract: `(version 1)` first, `(deny default)` second, an explicit
  `(deny network*)`, no network allow, exactly one `process-exec` allow, the
  shared exec rule, the same `PROVIDER_EXECUTABLE` /
  `STORAGE_ROOT` / `STORAGE_PARENT` parameter tokens, no `(allow default)`
  rule, and the three shared rules verbatim. One list function runs that check over
  `capsules/did-provider/confine.sb`, `capsules/wallet-provider/confine.sb`
  and `capsules/model-provider/confine.sb`. All three profiles are required,
  and a missing or unreadable profile fails the check with a reason that names
  its path. The test runs on every platform because it reads files and starts
  no process.
- `every_did_and_wallet_allow_rule_has_a_registered_removal` runs one removal
  check over the did and wallet profiles and over both of their committed
  falsifier lists. A top-level allow form counts as removed only when an entry
  expects a catch, names that profile's `confine.sb` by the runner's path rule,
  holds the form in its edit `old` and not in its `new`. A form that no entry
  removes fails the test by name, with the instruction to register a removal
  falsifier or delete the rule. The model profile is not read here; its
  allow-rule removals live in `../model-provider/confine-falsifiers.json` under
  that lane's own list. The test reads files and starts no process.
- `every_falsifier_id_is_named_in_its_confinement_document` reads both
  confinement documents and both falsifier lists, and fails when a registered
  id is not named in its own document's `## Falsifiers` section or the section
  names an id that neither list registers. It reads files and starts no
  process.
- `falsifier_section_check_reports_missing_and_stale_ids` builds the section in
  memory. The list holds `DID1`, `DID2` and `DID10`; a section that names
  `DID2`, `DID10` and the unregistered `WP9` returns exactly the missing
  `DID1` and the unregistered `WP9`. A section that names `DID2` and `XDID1`
  returns exactly the missing `DID1`, because a letter directly before a token
  keeps it from naming an id; a section that names `DID2`, `DID1a` and
  `DID1_x` returns that same one problem, because a letter or `_` directly
  after the digits does. A section that names every id whole reports no
  problem. The test reads no file and starts no process.
- `allow_rule_removal_check_reports_an_unremoved_rule` builds a fixture
  profile and fixture entries in the test. An entry whose `new` still holds the
  form, whose `expect` is not `caught`, whose edit names the other provider's
  `confine.sb`, or whose `old` does not hold the form removes nothing, so only
  the process-exec rule comes back; one complete entry for each form leaves
  nothing. The test reads no file.
- `allow_rule_removal_check_rejects_bad_inputs` checks the one source reader.
  A missing profile, a profile that does not parse, a missing list, a list that
  is not JSON, a document without a `falsifiers` list, an entry without an `id`
  and an entry whose `id` is a number each fail with a reason that names that
  path; an entry refusal also holds the words `string id`. There is no skip
  path. The fixtures are built in the test and no process starts.
- `file_profile_contract_rejects_a_profile_without_deny_network` builds a
  minimal profile from the contract's own head forms and shared rules inside
  the test. The check accepts it, then refuses the same profile without
  `(deny network*)` with a reason that names that rule. The test reads no
  file.
- `file_profile_contract_rejects_a_network_allow` builds the same passing
  fixture and appends `(allow network*)`, then
  `(allow network-outbound (remote ip "localhost:*"))`. The check refuses each
  profile with a reason that names `fixture-provider` and the refused form.
  The test reads no file.
- `file_profile_contract_rejects_an_allow_default` builds the same passing
  fixture and appends `(allow default)` after the default denial. The check
  refuses it with a reason that names `fixture-provider` and
  `must reject (allow default)`. The test reads no file.
- `file_profile_contract_rejects_a_second_exec_allow` builds the same passing
  fixture and appends `(allow process-exec (literal "/bin/sh"))`, the shared
  exec rule a second time, `(allow process* (literal "/bin/sh"))`,
  `(allow process-exec)`, `(allow process*)` and
  `(allow file-read* process*)`. The check refuses each profile with a reason
  that names `fixture-provider`, quotes the extra rule and holds
  `more than one process-exec allow`. A fixture that puts
  `(allow process-exec (literal "/bin/sh"))` before the shared exec rule is
  refused with a reason that quotes the `/bin/sh` rule and not the shared one,
  and a fixture with two extra exec rules and no shared exec rule is refused
  with both rules quoted. The profile that appends
  `(allow file-read* (literal "/x") process-exec)` is refused with that rule
  quoted, because an operation name after a filter still names an operation.
  The profile that appends `(allow(literal "/x") process-exec)` is refused the
  same way, because the first filter may sit directly after `allow`. The
  profile that appends `(allow file-read* (literal "a\"b)") process-exec)` is
  refused with that rule quoted, because the escaped quote and the parenthesis
  inside the string leave the operation outside the string.
  `/usr/bin/sandbox-exec` loads `(version 1)(deny default)(allow file-read*
  (literal "/x") process-exec)`; it attempts to start `/usr/bin/true`, whose
  exec fails with `execvp() of '/usr/bin/true' failed: Operation not permitted`
  and exit 71, and the check refuses that form either way. Fixtures that append
  `(allow file-read* (literal "/process-exec"))`,
  `(allow file-read* (process-exec "/x"))`,
  `(allow file-read* (require-all (process*)))`,
  `(allow "process-exec")` and
  `(allow file-read* (literal "a\" process-exec "))` still pass, because a
  token inside a string or a nested filter names text or a filter argument,
  not an operation, and an escaped quote stays inside its string. The
  unfiltered forms put the operation name directly before the closing
  parenthesis, so the predicate reads `)` as a token boundary. The narrower
  exec rule keeps its own removal for the 055 removal check, and the 056 and
  059 copy tests still refuse a copy of the provider binary, so neither sees
  this second exec path. The test reads no file and starts no process.
- `file_profile_contract_rejects_a_non_canonical_token` builds the same
  passing fixture and appends
  `(allow file-read* (literal (param "READ_FIXTURE_KEY")))`. The check refuses
  it with a reason that names `fixture-provider` and
  `non-canonical parameter token READ_FIXTURE_KEY`. The test reads no file.
- `file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does`
  builds the passing fixture and appends
  `(deny file-read* (literal "/x;")) (allow default)` and
  `(deny file-read* (literal "/))"))`. The check refuses it with a reason that
  names `fixture-provider` and `must reject (allow default)`, because the
  parser reads the `;` and the parentheses inside those strings as text. The
  same test checks that the two lines hold three forms with `(allow default)`
  second, that a `;` outside a string comments out the rest of its line, that
  an escaped quote and an escaped backslash stay inside their string, that
  whitespace inside a string is kept and outside it collapses, and that a form
  after a comment's newline still loads. The test reads no file and starts no
  process.
- `a_comment_inside_a_form_keeps_its_tokens_apart` reads a form whose tokens
  a comment splits and expects both tokens back: `(allow;x`, a newline, then
  `default)` gives `(allow default)`, and the network form gives
  `(allow network*)`. The one check refuses the passing fixture with either
  form appended, with the exact `must reject (allow default)` and
  `network allow is refused` reasons. The test reads no file and starts no
  process.
- `a_space_after_the_opening_parenthesis_still_names_its_rule` reads a form
  whose head a space or a comment separates from its first symbol:
  `( allow default)` and `(;x`, a newline, then `allow default)` both give
  `(allow default)`, and the network forms give `(allow network*)`. The one
  check refuses the passing fixture with each of those appended, with the
  exact `must reject (allow default)` and `network allow is refused` reasons.
  The test reads no file and starts no process.
- `a_bare_top_level_value_is_its_own_form` reads a bare value outside every
  form as its own form: `1`, a newline, then `(allow default)` gives `1` and
  `(allow default)`, and so do `1(allow default)` and `"x" (allow default)`; a
  bare value at the end of the profile is a form too. The one check refuses
  the passing fixture with each of those appended, and with
  `1 (allow network*)`, with the exact `must reject (allow default)` and
  `network allow is refused` reasons. The test reads no file and starts no
  process.
- `the_bare_value_fixture_loads_under_sandbox_exec` writes
  `(version 1)(deny default) 1 (allow default)` to a temporary file and runs
  `/usr/bin/sandbox-exec -f <file> /usr/bin/true`, which exits 0. Under
  `(deny default)` alone that program cannot start, so the exit shows that
  `sandbox-exec` reads the `1` as its own form and applies the
  `(allow default)` after it. It checks that test's premise, not a rule, and
  carries no falsifier entry.
- `the_string_fixture_loads_under_sandbox_exec` writes `(version 1)`,
  `(deny default)` and those two lines to a temporary file and runs
  `/usr/bin/sandbox-exec -f <file> /usr/bin/true`, which exits 0. Under
  `(deny default)` alone that program cannot start, so the exit shows that
  `sandbox-exec` reads the `;` and the parentheses as text and applies the
  `(allow default)`. It checks the fixture's premise, not a rule, and carries
  no falsifier entry.
- `profile_forms_rejects_unclosed_string` reads an unclosed string and expects
  the existing "the profile must not end early" reason with `unclosed string`
  in it. The test reads no file and starts no process.
- `profile_forms_rejects_unclosed_form` reads an unclosed form and expects the
  same reason with `unclosed form` in it, and a closed form then loads. The
  test reads no file and starts no process.
- `file_profile_contract_checks_the_model_profile_when_present` runs the same
  list function over a temporary `capsules/` directory that holds the passing
  fixture for all three required profiles. It checks exactly did-provider,
  wallet-provider and model-provider, in that order; a model profile without
  `(deny network*)` fails, naming the model provider and that rule; a removed
  model profile fails, naming model-provider and its path; a model profile
  that is a directory fails as a read error naming its path; and a missing did
  profile fails, naming did-provider.

- `every_did_and_wallet_allow_rule_traces_to_one_declared_right` reads each
  provider's `tests/fixtures/confine/declared-rights.json` and requires every
  top-level allow rule of the did and wallet profiles to trace to exactly one
  declared right or platform-baseline rule.
  `declared_rights_trace_refuses_each_bad_input` builds the same files in a
  temporary `capsules/` directory and proves each refusal. Neither test starts
  a process.
- `model_declared_rights_read_on_the_did_and_wallet_template` reads
  `capsules/model-provider/confine.sb` and the model provider's
  `tests/fixtures/confine/declared-rights.json`, then requires the one
  declared-rights check to accept them unchanged. The model's file uses the
  same rights and platform-baseline template as did and wallet. A missing file
  fails with its path. The test reads files and starts no process.

- `generated_did_and_wallet_profiles_match_their_committed_oracles`
  generates each did and wallet profile with `generate_profile` from its
  `tests/fixtures/confine/declared-rights.json` and the contract head, then
  requires it to equal the committed `confine.sb`: the same three head forms
  in order, and the same remaining forms in any order, because the committed
  profile holds only allow forms after its head. A mismatch names the provider
  and each form that only one profile holds. The test reads files and starts
  no process.

When a request goes unanswered, the harness failure names the request, the
child's exit status or the deadline that ended the wait, and all the child
wrote to standard error.

The tests skip with a printed reason when `/usr/bin/sandbox-exec` is absent on
a host OS other than macOS.

`sandbox_gate_fails_instead_of_skipping_on_a_declared_os` checks the gate
itself without starting a process: a missing `sandbox-exec` on `macos` is an
error that names the OS and the path, a missing one on `linux` is a skip, and
a present one on `macos` runs the test. It runs on every supported build
target.

`sandbox_available_fails_for_macos_when_sandbox_exec_is_missing` checks the
one caller without starting a process: with `macos` and a missing
`sandbox-exec` it fails the test with the gate's reason, and with `macos` and
a present one it returns `true`. It runs on every supported build target.

## Falsifiers

Falsifier procedure (run against a temporary edit, then restore the profile):

- Restore a temp-directory fallback for a missing storage root (WP01):
  `tests::storage_root::missing_storage_root_is_refused` fails.
- Accept an empty storage root instead of refusing it (WP02):
  `tests::storage_root::empty_storage_root_is_refused` fails.
- Accept a relative storage root instead of refusing it (WP03):
  `tests::storage_root::relative_storage_root_is_refused` fails.
- Rename `STORAGE_ROOT` to `WALLET_STORAGE_ROOT` in this profile (WP22):
  `both_file_profiles_bind_one_storage_parameter_contract` fails on the
  non-canonical token.
- Remove the did profile's shared `STORAGE_PARENT` read (WP11, described in
  `../did-provider/CONFINEMENT.md`):
  `both_file_profiles_bind_one_storage_parameter_contract` fails.
- Rename the did profile's `STORAGE_ROOT` to `DID_STORAGE_ROOT` (WP23,
  described in `../did-provider/CONFINEMENT.md`):
  `both_file_profiles_bind_one_storage_parameter_contract` fails.
- `(allow default)` in place of `(deny default)` (WP04) makes the outside
  `Init` succeed, so the outside tests fail.
- Append `(allow file-read* (literal (param "READ_FIXTURE_KEY")))` (WP24):
  `confined_outside_read_is_denied` fails because reading the planted key
  lets `Init` succeed, and
  `both_file_profiles_bind_one_storage_parameter_contract` fails because the
  token is non-canonical.
- `(allow network*)` (WP05) makes `profile_denies_network` and
  `both_file_profiles_bind_one_storage_parameter_contract` fail.
- Append `(allow default)` after `(deny network*)` (WP20):
  `profile_denies_network` fails because `is_default_allow` matches the
  appended rule, `both_file_profiles_bind_one_storage_parameter_contract` fails
  because the one check refuses the rule, and
  `confined_outside_read_is_denied` and `confined_outside_write_is_denied` fail
  because the outside reads and writes then succeed.
- Removing the storage-root write rule (WP18) makes `Init` fail inside the
  root, so the operations and outside-write tests fail, and the shared contract
  check fails.
- Remove `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))` (WP14):
  the operations and outside tests fail because the provider cannot start, and
  the shared contract check fails because the rule is pinned.
- Remove `(allow file-read* (literal "/"))` (WP15): the operations and outside
  tests fail because the provider cannot resolve its program path.
- Remove `(allow sysctl-read)` (WP16): the operations and outside tests fail
  because the loader cannot read the kernel facts it needs.
- Remove `(allow file-read* (literal (param "STORAGE_PARENT")))` (WP17): `Init`
  cannot inspect the parent, so the operations and outside-write tests fail,
  and the shared contract check fails.
- Drop the explicit `(deny network*)` requirement from the shared contract
  check (WP06): `file_profile_contract_rejects_a_profile_without_deny_network`
  and `file_profile_contract_checks_the_model_profile_when_present` fail.
- Drop the model profile from the one required list (WP07):
  `file_profile_contract_checks_the_model_profile_when_present` fails.
- Skip a missing required did profile instead of refusing it (WP09):
  `file_profile_contract_checks_the_model_profile_when_present` fails.
- Remove the network-allow rule from the shared contract check (WP12):
  `file_profile_contract_rejects_a_network_allow` fails.
- Narrow the shared network-allow predicate to the exact form
  `(allow network*)` (WP13):
  `file_profile_contract_rejects_a_network_allow` fails.
- Remove the `(allow default)` refusal from the shared contract check (WP19):
  `file_profile_contract_rejects_an_allow_default` fails.
- Remove the canonical-token refusal from the shared contract check (WP21):
  `file_profile_contract_rejects_a_non_canonical_token` fails.
- Resolve the honesty test's edit paths from the repository root again (WP25):
  `tests::falsifiers::falsifiers_list_is_honest` and
  `tests::falsifiers::falsifiers_list_rejects_a_repository_relative_path` fail.
- Skip a missing model profile again instead of refusing it (WP26):
  `file_profile_contract_checks_the_model_profile_when_present` fails.
- Return `Ok(false)` from the sandbox gate's declared-OS branch (WP27):
  `sandbox_gate_fails_instead_of_skipping_on_a_declared_os` fails.
- Start the provider directly when its profile file is missing (WP28):
  `startup_is_refused_when_the_profile_cannot_be_applied` fails on case (a) at
  the bounded wait, because the provider is still running when the deadline
  kills it.
- Drop the child's standard error from the one harness failure (WP29):
  `startup_is_refused_when_the_profile_cannot_be_applied` fails because every
  failure lacks `sandbox-exec`'s line.
- Return `false` from the error arm of `sandbox_available` instead of failing
  the test (WP30): `sandbox_available_fails_for_macos_when_sandbox_exec_is_missing`
  fails because a missing `sandbox-exec` on `macos` returns instead of failing.
- Cut each line at its first `;` and count parentheses in every token again
  (WP31): `file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does`
  fails because the hidden `(allow default)` then passes the check, and
  `profile_forms_rejects_unclosed_string` fails because the cut reads no
  string to refuse.
- Let an escaped character end its string (WP32):
  `file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does`
  fails because the escaped quote closes the string and the profile ends
  early.
- Drop whitespace that sits inside a string (WP33): the same test fails
  because the spaced in-string form loses its two spaces.
- Keep whitespace outside strings instead of collapsing it (WP34): the same
  test fails because the passing fixture no longer parses into the contract's
  forms.
- Run a comment to the end of the profile instead of its line (WP35): the
  same test fails because the form after the comment's newline is lost.
- Drop the unclosed-string refusal (WP36):
  `profile_forms_rejects_unclosed_string` fails because the profile then ends
  as an unclosed form.
- Drop the unclosed-form refusal (WP37): `profile_forms_rejects_unclosed_form`
  fails because the incomplete profile returns no refusal.
- Drop the newline that ends a comment (WP38):
  `a_comment_inside_a_form_keeps_its_tokens_apart` fails because
  `(allow;x\ndefault)` reads as `(allowdefault)` and passes the check.
- Drop the split outside every form (WP39):
  `a_bare_top_level_value_is_its_own_form` fails because `1`, a newline, then
  `(allow default)` reads as the one form `1 (allow default)` and passes the
  check.
- Add the separator space after an opening parenthesis (WP40):
  `a_space_after_the_opening_parenthesis_still_names_its_rule` fails because
  `( allow default)` reads as its own form and passes the check.
- Start the drainer only after `wait_for_exit` has returned (WP41):
  `stderr_is_drained_before_wait` fails on its exit assertion because the
  child blocks on a full pipe and never exits within the deadline.
- Use a fixed `Operation not permitted` instead of the child's standard error
  in `unanswered` (WP42): `startup_denial_reports_its_reason` fails on its
  `execvp()` assertion because the fixed text names no exec denial.
- Return the shared unanswered message from the invalid-JSON branch (WP43):
  `invalid_json_answer_names_the_request_and_the_parse_error` fails because the
  answer loses its parse error and says the provider did not answer.
- Append `(allow file-read* (literal "/etc"))` to the did profile (WP44):
  `every_did_and_wallet_allow_rule_has_a_registered_removal` fails because no
  entry removes that form.
- Drop the `expect` condition (WP45), the profile-path condition (WP46), the
  `old` condition (WP47) or the `new` condition (WP48) from the removal check:
  `allow_rule_removal_check_reports_an_unremoved_rule` fails because the
  bypassing entry then counts as a removal.
- Turn the unreadable-profile refusal into a skip (WP49), the unparsable-profile
  refusal (WP53), the unreadable-list refusal (WP50), the not-JSON refusal
  (WP51) or the missing-list refusal (WP52):
  `allow_rule_removal_check_rejects_bad_inputs` fails because the refusal does
  not come.
- Drop the canonical-parameter refusal from `start_with_profile` (WP54):
  `start_with_profile_refuses_a_canonical_parameter` fails because the call
  returns a running provider on a Mac, and without `sandbox-exec` it panics
  with the spawn message instead of naming the parameter.
- Check the caller's whole name instead of the name before the first `=`
  (WP55): `start_with_profile_refuses_an_encoded_canonical_parameter` fails
  because the encoded canonical name reaches the launch instead of the
  canonical-binding refusal.
- Append a second, unpinned `(allow process-exec)` after the exec rule (WP56):
  `unbound_copy_is_refused_under_profile` fails on its deadline assertion
  because the copy under `STORAGE_ROOT` starts instead of being refused.
- Widen the parent read from `literal` to `subpath` (WP57):
  `planted_key_beneath_storage_parent_is_not_read` fails on its refusal
  because the planted key loads and `init` answers ok.
- Drop the own-id rule from the section check (WP58):
  `falsifier_section_check_reports_missing_and_stale_ids` fails because the
  missing id reports no problem.
- Drop the unregistered-id rule from the section check (WP59): the same test
  fails because the stale id reports no problem.
- Match an id as a substring instead of a whole token (WP60): the same test
  fails because the longer registered id then names the shorter one.
- Run the section to the end of the file instead of the next `## ` heading
  (WP61): `falsifier_section_check_rejects_a_document_without_its_section`
  fails because an id after the next heading counts as named.
- Bypass the missing-heading refusal (WP62): the same test fails because a
  document without `## Falsifiers` reports no problem.
- Bypass the duplicate-heading refusal (WP63): the same test fails because a
  second `## Falsifiers` heading reports no problem.
- Skip an unreadable `CONFINEMENT.md` instead of refusing it (WP64):
  `falsifier_document_read_rejects_unreadable_source` fails because the
  refusal does not come.
- Append `(allow file-write* (subpath (param "STORAGE_PARENT")))` (WP65):
  `confined_outside_write_is_denied` fails on the new case's absence check
  because the fresh base beneath the parent is created.
- Drop the string-id refusal from the one list reader (WP66):
  `allow_rule_removal_check_rejects_bad_inputs` fails because an entry without
  an id is dropped instead of refused.
- Drop the character-before check from the section check (WP67):
  `falsifier_section_check_reports_missing_and_stale_ids` fails on its `XDID1`
  case because that token then names the missing own id and the missing-id
  problem does not come.
- Drop the character-after check from the section check (WP68): the same test
  fails on its `DID1a` case because that token then names the missing own id
  and the missing-id problem does not come.
- Remove the second-exec-allow refusal from the shared contract check (WP69):
  `file_profile_contract_rejects_a_second_exec_allow` fails because the
  `/bin/sh` fixture passes.
- Read no `)` as a token boundary in the exec predicate (WP70):
  `file_profile_contract_rejects_a_second_exec_allow` fails on its
  `(allow process*)` case because the token reads `process*)` and the profile
  passes the check.
- Quote every exec allow after the first one again (WP71): the same test fails
  on its `/bin/sh`-before-the-shared-rule case because the refusal quotes the
  shared rule and not the extra one.
- Read the exec predicate's operation names only before the first filter
  (WP72): the same test fails on its after-filter `process-exec` case because
  the profile passes the check.
- Quote only the first extra exec rule (WP73): the same test fails on its
  two-extra-rules case because the second quote is missing.
- Count a token inside a nested filter as an operation name (WP74): the same
  test fails because the passing `(allow file-read* (process-exec "/x"))`
  fixture is refused.
- Count text inside a string as an operation name (WP75): the same test fails
  because the passing `(allow "process-exec")` fixture is refused.
- Drop the escape flag in `profile_characters` (WP76):
  `file_profile_contract_rejects_a_second_exec_allow` fails on its
  escaped-string case, and
  `file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does`
  fails on its escaped-quote case.
- Require a space after `allow` (WP77): `file_profile_contract_rejects_a_second_exec_allow`
  fails on its `(allow(literal "/x") process-exec)` case because that profile
  passes the check.
- Rename `outside_write_denied` in `capsules/did-provider/tests/confine.rs`
  (WP78): `every_operations_table_cites_existing_tests` fails because the did
  operations table cites a function that file does not hold.
- Bypass the unresolved-file refusal (WP79):
  `operations_table_check_reports_each_missing_citation` fails because the
  missing-file fixture loses its refusal.
- Bypass the no-citation refusal (WP80): the same test fails because the
  empty-citation fixture loses its refusal.
- Accept an absolute citation path (WP81):
  `operations_table_check_rejects_paths_outside_provider` fails because the
  absolute-path fixture loses its refusal.
- Accept a citation that resolves outside its provider (WP82): the same test
  fails because the sibling-provider fixture loses its containment refusal.
- Rename `confined_outside_write_is_denied` in `tests/confine.rs` (WP83):
  `every_operations_table_cites_existing_tests` fails because the wallet
  operations table cites a function that file does not hold.
- Append `(allow file-read* (literal "/private/var/cc-confine-unnamed"))` to
  the did profile (WP84):
  `every_did_and_wallet_allow_rule_traces_to_one_declared_right` fails because
  no declared right and no platform-baseline rule claims that form.
- Append the same rule to this profile (WP85): the same test fails because the
  wallet form likewise has no claimant.
- Rename the one platform-baseline key the declared-rights check reads to the
  old startup-needs key (WP86):
  `every_did_and_wallet_allow_rule_traces_to_one_declared_right` and
  `model_declared_rights_read_on_the_did_and_wallet_template` fail because the
  did, wallet and model files no longer hold that key.
- Drop the justification refusal (WP87):
  `declared_rights_trace_refuses_each_bad_input` fails because its
  missing-justification case finds no refusal.
- Append `(allow file-read* file-write* (subpath (param "STORAGE_PARENT")))`
  (WP88): `account_operations_beneath_storage_parent_are_refused` fails
  because the sibling `init` and the account call beneath the parent then
  succeed.
- Drop the pin table's two startup rows (WP89):
  `declared_rights_trace_refuses_each_bad_input` fails because the two startup
  rules swapped between their ids and the startup root read claimed by
  `storage` both pass.
- Drop the repeated-id refusal (WP90): the same test fails because the two
  `storage` entries pass the check.
- Drop the repeated-rule refusal (WP91): the same test fails because an entry
  that claims one shared rule twice passes the check.
- Drop the duplicate-form refusal (WP92): the same test fails on its
  `(allow sysctl-read)`-twice case, which then reads "declared rule is not an
  allow rule of its profile".
- Drop the prefix refusal (WP93): the same test fails because a justification
  that names another provider's executable prefix passes the check.
- Drop the empty-reason refusal (WP94): the same test fails because a bare
  provider prefix passes the check.
- Drop the role refusal (WP95): the same test fails because a file that gives
  "approved rights" as its role passes the check, so its role case finds no
  refusal.
- Drop the provider refusal (WP96): the same test fails because the did file
  that names "wallet-provider" passes the check, so its provider case finds no
  refusal.
- Drop the platform-baseline status refusal (WP97): the same test fails
  because a baseline without ", not approved rights" in its status sentence
  passes the check, so its status case finds no refusal.
- Replace the missing rights-list refusal with an empty list (WP98): the same
  test fails because the check goes on and refuses the process-exec form with
  no claimant, so its rights case finds no "must hold a rights list" reason.
- Replace the missing platform-baseline refusal with an empty map (WP99): the
  same test fails because the check goes on and refuses the empty baseline with
  the status reason, so its platform-baseline case finds no "must hold a
  platform baseline" reason.
- Replace the missing baseline rules-list refusal with an empty list (WP100):
  the same test fails because the check goes on and refuses the startup-root
  form with no claimant, so its rules-list case finds no "platform baseline
  must hold a rules list" reason.
- Replace the missing-id refusal with an empty id (WP101): the same test fails
  because the platform-baseline entry without an id reaches the unnamed-id
  refusal, so its case finds none of the list label, `entry 1` or `string id`.
- Replace the missing-rules-list refusal with an empty list (WP102): the same
  test fails because the right without its rules list reaches the "with no
  rules" refusal, so its case finds no "without a rules list" reason.
- Skip a rule that is not a string (WP103): the same test fails because the
  right with the non-string rule passes the check, so its case finds no
  refusal.
- Drop only the pin table's `startup-sysctl` row (WP104): the same test fails
  because the sysctl read moved under `storage` passes the check, so its case
  finds no refusal.
- Make the lab generator emit
  `(allow file-read* (literal "/private/var/cc-confine-generated"))` after
  the contract head (WP105):
  `generated_did_and_wallet_profiles_match_their_committed_oracles` fails
  because neither declared-rights file names that rule.
- Make the declared-rights check's rights-list id refusal never fire (WP106):
  `generator_refuses_an_unnamed_right_and_the_start_is_refused` fails at its
  refusal check because case (a) writes a profile for the unnamed right in the
  did case, and the panic names `did-provider` and the case.
- Make the platform-baseline id refusal never fire (WP107): the same test fails
  at its refusal check because case (b) writes a profile for the unnamed
  baseline rule in the did case.
- Make the lab writer create the profile path before it calls the generator
  (WP108): the same test fails on its no-file assertion because both cases
  create the refused path in the did case.
- Append `(deny file-write* (literal "/private/var/cc-confine-generated"))`
  after the declared rules in `generate_profile` (WP109):
  `generated_did_and_wallet_profiles_match_their_committed_oracles` fails only
  at the sorted-tail comparison, because the head keeps its order and neither
  contract check reads a deny form, so the panic names that form under "only in
  generated".
- Name `generate_profile` in `capsules/wallet-provider/src/main.rs` (WP110):
  `lab_generator_is_named_only_in_test_code` fails because the walk reads the
  provider's non-test file and its refusal names that path.
- Name `generate_profile` in `capsules/did-provider/src/main.rs` (WP111): the
  same test fails because the walk reaches the other crate and its refusal
  names that path.
- Start the binary bare in the stand-in's host refusal (WP112):
  `standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host` fails
  on case (a), which returns Started instead of its reason.
- Start the binary bare after a failed `init` (WP113): the same test fails on
  case (e), which returns Started instead of the reason.
- Replace the stand-in's generated-profile start with a bare start (WP114): the
  same test fails at the outside `init`, which then succeeds.
- Ignore the lab writer's refusal and start under the committed `confine.sb`
  (WP115): the same test fails on case (d), which returns Started instead of
  the unnamed-id reason.
- Bind the stand-in's `STORAGE_ROOT` to the base instead of the wallet
  directory (WP116):
  `standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite`
  fails at did's suite step, where the sibling write beneath the base answers
  `ok` because the widened grant covers it, before the two records are
  compared.
- Write the generated profile but start under the committed `confine.sb`
  (WP117): `standin_start_runs_under_the_generated_profile_not_the_committed_file`
  fails because the start is then Started instead of refused.
- Remove the stand-in's check that the confinement tool is `SANDBOX_EXEC`
  (WP118): `standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host`
  fails on case (c2), which runs the real `sandbox-exec` and returns Started.
- Remove the stand-in's binary-file check (WP119): the same test fails on case
  (c3), which panics in `resolved` with "wallet directory must resolve".
- Return `Ok(provider)` for an `init` answer that is not `ok` (WP120): the same
  test fails on case (f), which returns Started instead of the answer.
- Remove the suite's planted-key push (WP121):
  `standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite`
  fails because wallet's record holds eight entries where `SUITE_CASES` holds
  nine, and the failure names the missing case.
- Drop the refusal `code` from `suite_entry` (WP122):
  `suite_entry_keeps_the_refusal_code` fails because two refusals that differ
  only in `code` then compare equal.
- Record every bound result as `Ok` in `wallet_suite_entry` (WP123):
  `wallet_suite_entry_records_an_inner_refusal_as_refused` fails because the
  inner refusal reads `Ok`.
- Use wallet's root layout for a did start in the stand-in (WP124):
  `standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite`
  fails because the did start is refused at its first `init`.
- Make the stand-in's absent-tool check never fire (WP125):
  `standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host` fails
  on case (c), which then reads the wrong-tool reason and lacks `is absent`.
- Drop the OS from the stand-in's wrong-tool reason (WP126): the same test
  fails on case (c2), whose reason then lacks `on macos`.
- Append a write grant on `STORAGE_PARENT` to the stand-in's generated profile
  for did (WP127):
  `standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite`
  fails at did's launched-profile check, where `check_declared_rights` refuses
  the appended allow form because no declared right names it, and the suite
  never starts.
- Return `did_provider_dir().join("target/debug/did-provider")` from the one
  build-output reader instead of the reported `executable` (WP128):
  `did_binary_is_the_executable_the_build_reports` fails because its fixture
  path sits outside any `target` directory, while
  `standin_launcher_finds_the_built_did_binary` alone still passes because the
  guessed file exists after did's build.
- Return `wallet_dir(base)` for an unknown provider name in
  `provider_storage_root` (WP129):
  `provider_storage_root_refuses_an_unknown_provider_name` fails because no
  refusal comes for `model-provider`.
- Skip the kind check in the one build-output reader (WP130):
  `did_binary_is_the_executable_the_build_reports` fails because the reader
  returns the non-bin artifact's executable, which comes before the bin
  artifact.
- Start the binary bare on a simulated Linux host that reports a missing
  primitive (WP131):
  `standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host` fails
  at did's Landlock row, which returns Started instead of the design's words.
- Return one fixed reason that names no primitive from the missing-primitive
  refusal (WP132): the same test fails on did's Landlock row, whose reason then
  loses the design's exact words for that primitive.
- Append `(allow file-read* (literal "/private/etc/hosts"))` to the file the
  stand-in launches, after the writer (WP133):
  `standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite`
  fails at did's launched-profile check, where `check_declared_rights` refuses
  the appended allow form because no declared right names it, and no suite case
  reads that path.
- Remove `(deny network*)` from the file the stand-in launches, after the
  writer (WP134): the same test fails at that launched-profile check, where
  `check_profile_contract` refuses the profile without its explicit network
  denial, and no suite case opens a socket.
- Append `(deny file-write* (literal "/private/var/cc-confine-launched"))` to
  the file the stand-in launches, after the writer (WP138): the same test fails
  at did's launched-profile check, where `compare_profile_to_its_oracle` alone
  catches it, because the head keeps its order and neither contract check reads
  a deny form, so the panic names that form under "only in generated".
  Removing the comparison call leaves the journey green under this entry's
  plant, so this entry is the one that scores that call.
- Move the `DECLARED_CONFINED_OS` lookup back above the missing-primitive check
  (WP135):
  `standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host` fails
  at did's `macos` Landlock row, which returns Started where `sandbox-exec`
  exists instead of the design's Landlock words.
- Prefix the missing-primitive reason with `linux has no confinement design; `
  (WP136): the same test fails at did's Landlock row, whose reason then
  carries the forbidden words.
- Drop the `{name} start on {os} is refused: ` prefix from the final `Err`
  (WP137): the same test fails at did's first host row, plan9, whose reason
  then lacks the prefix.
- Read `/etc/hosts`, outside every grant, in `status`'s ok arm and answer
  `storage_error` when that read is denied (WP139): the `storage_error`
  refusal replaces the ok answer, so
  `no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged`
  fails on its first answer.
- Append one byte to `wallet-key.hex` in `status`'s ok arm while every answer
  stays ok (WP140): `status` still answers ok, and only the wallet directory
  comparison in
  `no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged`
  catches it, at that call.
- Remove the row-set rule's call from `operations_table_row_problems` (WP141):
  `operations_table_row_check_refuses_each_bad_table` fails on its four row-set
  cases, because a table that omits a row, adds one, follows another order or
  puts a contract row first is then accepted.
- Make the Right-vocabulary refusal return early (WP142): the same test fails on
  its two Right cases, because a Right cell of `bound-net` and one of `no named
  test shows this` are then accepted.
- Make the both-sides refusal return early (WP143): the same test fails on its
  three side cases, because a right row with one side and a `none:` row citing a
  side are then accepted.
- Make the Linux-status refusal return early (WP144): the same test fails on its
  Linux case, because a cell reading `enforced by Landlock` is then accepted.
- Write one file into the wallet directory in `shutdown`'s arm before it answers
  `Response::empty_ok()` (WP145):
  `no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged` fails
  at its final wallet directory compare after `shutdown`, which finds
  `shutdown-falsifier.hex`, a name the setup did not leave.
- Make the allow-list decision the 0710 deny list: refuse `socket`, `connect`
  and `execve` and permit every other call (WP146):
  `seccomp_program_denies_by_default_and_lists_no_undeclared_call` fails on its
  final-decision assertion, which reads `ALLOW` where the deny marker belongs.
- Make the builder return a fixed list and ignore its declared input (WP147):
  `seccomp_allow_list_follows_the_declared_rights` fails because removing the
  `storage` right changes no syscall of the list.
- Skip an allow form the mapping table does not hold instead of refusing it
  (WP148): `seccomp_rejects_unmapped_allow_form` fails on all three spellings,
  because the list is built and no refusal comes.
- Require a space after the operator in the one allow-form recogniser (WP149):
  `seccomp_rejects_unmapped_allow_form` fails on `(allow)` and
  `(allow(file-read*))`, which are then read as head forms instead of refused.
- Admit both branches of the audit-architecture guard (WP150):
  `seccomp_program_denies_by_default_and_lists_no_undeclared_call` fails on its
  guard assertion, because a foreign architecture reaches the number load.
- Make a false equality test fall into its own `ALLOW` (WP151): the same test
  fails on its jump assertions, because an unlisted call is admitted.
- Run the two install steps in the reverse order (WP152):
  `seccomp_install_refuses_each_failed_step` fails on its recorded order,
  because the filter runs before `no_new_privs`.
- Answer both install steps with one fixed reason and errno (WP153): the same
  test fails because the filter step's refusal names the first step.
- Continue after a failed first install step (WP154): the same test fails on its
  recorded order, because the filter runs after a step that failed.
- Stop the write loop at the first short write (WP155):
  `seccomp_launch_refuses_each_reporting_failure` fails on the record it
  expects, because the loop stops early.
- Report an interrupted write instead of retrying it (WP156): the same test
  fails because the `EINTR` case comes back as a failure.
- Answer both reporting failures with one fixed reason (WP157): the same test
  fails because the two reasons are equal.
- Accept a `linux` host under a `Seatbelt` policy (WP158):
  `standin_host_refusal_decides_each_policy` fails because today's exact Linux
  refusal is lost.
- Bypass the launcher's `Seccomp` seat (WP159): the same test fails because the
  `Seccomp` start returns Started instead of its own refusal.
- Add one unconditional syscall beside the rows (WP160):
  `seccomp_allow_list_follows_the_declared_rights` fails on its empty case,
  because a declaration with no allow form still admits that call.
- Test `ptrace`'s number where an admitted syscall's belongs (WP161):
  `seccomp_program_denies_by_default_and_lists_no_undeclared_call` fails on its
  number-set comparison, because the program tests a number no row names.
- Label the Linux journey with a Linux host on a host that is not Linux
  (WP162): `linux_seccomp_journey_is_not_applicable_off_linux` fails on a
  non-Linux host because the label reads `applicable, host` instead of
  `not applicable`, so a Mac run cannot pass a Linux claim on.
- Accept any install-record length (WP163):
  `seccomp_launch_record_refuses_missing_or_unknown_report` fails on its short
  and long cases, because a short record then decodes as an installed filter.
- Decode an unknown record step as an installed filter (WP164): the same test
  fails on its unknown-step case, because the refusal does not come.
- Accept a seccomp allow list generated for another provider (WP165):
  `standin_host_refusal_decides_each_policy` fails because the start is then
  attempted instead of refused for both providers' names.
- Pass only the command to the probe's `keyctl` call (WP166):
  `seccomp_keyctl_probe_supplies_every_argument_without_creation` fails because
  the call omits the keyring, create flag and two unused arguments. The table
  keeps all five values, so the test checks the call's use of them.
- Answer a failed spawn's reason alone when the install record is empty (WP167):
  `seccomp_launch_record_refuses_missing_or_unknown_report` fails because the
  missing-report reason is lost behind that spawn reason.
- Make the one file-to-list helper ignore its provider argument and always read
  wallet's declared-rights file (WP178):
  `seccomp_allow_list_names_the_provider_it_was_built_for` fails on its did
  case, because both lists then answer `wallet-provider`.

Task 148's Linux-only plants are recorded in `CONFINEMENT-LINUX.md`, not here.
Each names a `#[cfg(target_os = "linux")]` test, and the runner runs on the Mac,
so none can produce a CAUGHT line in this list. That file names each of them,
with the red output of its run on the Linux host: the `NoNewPrivileges` and
`Filter` install-failure plants, the requested-program plant, the stopped-child
and timeout-reap plants, the omitted-wait plant, the allocation-guard plant, the
skip-install plant and the outside-write plant.

Task 016 removed these allow forms because no named confinement test needed
them on macOS 26.5.2 arm64:

- `(allow file-read* (literal (param "PROVIDER_EXECUTABLE")))` removed: no
  confinement test needed it on macOS 26.5.2 arm64.
- `(allow file-read* (subpath "/usr/lib"))` removed: no confinement test needed
  it on macOS 26.5.2 arm64.
- `(allow file-read* (subpath "/System/Library"))` removed: no confinement test
  needed it on macOS 26.5.2 arm64.
- `(allow file-read* (subpath "/Library/Apple"))` removed: no confinement test
  needed it on macOS 26.5.2 arm64.
- `(allow file-read* (literal "/dev/urandom"))` removed: no confinement test
  needed it on macOS 26.5.2 arm64.

A host that needs one of the removed grants receives a sandbox denial for the
affected access, so that operation fails closed with a reason. The grant comes
back only together with a named test that needs it.

Run `cargo test --locked --manifest-path capsules/wallet-provider/Cargo.toml`
from the repository root. The existing 102 unit tests remain part of this gate.

The one runner applies and restores each registered falsifier with
`python3 -I examples/agent-host/falsify.py --from capsules/wallet-provider/falsifiers.json`
from the repository root; the list's edit paths are relative to
`examples/agent-host`, and the sandbox entries need `/usr/bin/sandbox-exec`.

A run of the list is evidence only where the sandbox tests run: the runner runs
every chosen named test once on the unmutated tree before its first edit, so on
macOS without `/usr/bin/sandbox-exec` each sandbox test fails at the gate and
its entry reads `NOT RUN` instead of `CAUGHT`, while where the sandbox tests
skip an entry that names one reads `SURVIVED`. A call site that passes a fixed
`"linux"` for the OS is not caught by a run on a Mac where
`/usr/bin/sandbox-exec` exists, because a present tool runs the test before the
OS is read, so that run is no evidence for the OS argument.
