# Adversarial review of #301, #299, and #307

Reviewed this session on Linux 6.12.94+ x86_64, rustc 1.91.0, uid 1000. This host reports Landlock ABI 6 (`landlock_create_ruleset` version query returned 6).

Heads, read only. Nothing under `lab/a1-a8-hardening/` or `lab/fail-closed-linux/` was committed from this review.

| PR | Branch | Head |
| --- | --- | --- |
| #301 | `cursor/a1-a8-hardening-85ce` | `32abea6786340ce2a582af0bd87e097d4a29de66` |
| #299 | `cursor/fail-closed-linux-recover` | `ba7608b52990aaf0aea7260fe5106f984564e269` |
| #307 | `cursor/fail-closed-linux-0b95` | `129fdc98428c9029b328976511478c46ebe765a6` |

Suites and mutations ran from detached checkouts under `/tmp`. Mutations were scratch copies, or a fixture restored to the same SHA-256 before the end of the run (`fde73e381f652d36378a118ef9d84a8d274d8671fe23fc29558c2b670cfd77c9` for the A8 injection).

## Verdicts

| Claim | Verdict |
| --- | --- |
| #301 A1: a `wasi:cli/environment@0.2.0` import is refused at admission with the allowlist sentence, and the same guest without that import is admitted | holds |
| #301 A1: the row is not "every component is refused" | holds |
| #301 A8: the committed injection's refusal sentence is produced by the Runtime, the fake key is unchanged, and the marker is absent | holds |
| #301 A8: `agent_host_host_key_read_is_refused` proves that the Runtime produced the sentence | falsified |
| #301 A8: the injected statement is a fair model of the agent-host with its own guards failed | falsified |
| #301: `shipped_agent_host_bytes_read_host_key` is a pass | holds that it is not. The row is BLOCKED. Cargo exit 0 is the ignored test |
| #299: a failed layer still reaches `exec` in the unmutated guard | holds that it does not |
| #299: the refusal names the failing step | weak |
| #299: real-kernel id-map refusal is unproven | weak. The suite has no such row. The built launcher does refuse a non-dumpable binary, with a three-way reason |
| #299: 26 planted bugs caught, control survives, on this x86-64 host | holds |
| #299: `falsify.py` treats a skipped falsifier as success | falsified as an accounting rule. On this host `F-FC16` did run |
| #307: real-kernel id-map refusal via a mode `0111` launcher, step `uid_map`, os error 13, probe does not run | holds |
| #307: a failed layer still reaches `exec` in the unmutated guard | holds that it does not |
| #307: an empty fault pipe is reported as a start | weak. The README says so. A mutant confirmed the CLI prints `started` and the test does not pass |
| #307: bounding set is dropped before `capset` | holds |
| #307: 17 planted bugs caught, control survives | holds |
| ABI 5 is the minimum honest floor for this guard on JetPack R36.4.7 | falsified as a single floor. See the policy below |
| Which C0 guard to keep | keep #307 |

## #301 A1

Command, after `cargo fetch --locked` of `elastos/tools/componentize` (the first `run.sh` died in componentize with `failed to download anyhow v1.0.103` under `--offline`):

```text
lab/a1-a8-hardening/run.sh
```

Result: cargo exit 0.

```text
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; allowed imports: elastos:bus/types@1.0.0, elastos:bus/runtime@1.0.0, elastos:bus/identity@1.0.0, elastos:bus/capabilities@1.0.0, elastos:bus/providers@1.0.0")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
```

Guest hashes matched the PR log: WASI `a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884`, control `b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f`. The debug `elastos` hash here was `d89a4bab0503570794c87a0cbc0be26f21b0d6a7bd02cb76b391128d90ed9f3c`, not the `97c4cc2e…` in that log.

`python3 lab/a1-a8-hardening/falsify.py F-A1a` staged the control bytes in the refused slot. That run was admitted (`exit:Some(0) refusal_line:None`) and the test failed at the refusal assertion. The file was restored to `ccf9fc61b70f4c0e6a9b7c44de03ecfbac9a76595bdf07ddb55e55a84d34f17a`.

`F-A1-runtime` was not re-run. It rebuilds `elastos`.

## #301 A8

Same `run.sh`:

```text
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports [five elastos:bus interfaces]
a8 injected agent-host: sha256 9cff3664618f2ad65cd2ff4e0b3349568ee1f5b8ab159e78f8548e112eed8a96 imports [the same five]
a8 host key read: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Compute error: Component capsule denied: BusError::Internal(\"capsule manifest does not declare authority for localhost://Public/../../../../.ssh/id_ed25519\")") marker_absent:true unchanged:true
```

Those two guest hashes match the PR log. The core module left in the component target dir does not contain `capsule manifest does not declare authority`. It does contain `localhost://Public/`, `.ssh/id_ed25519`, and `agent-host read the host key`. The sentence in stderr was not in the guest.

The test does not lock that fact. A scratch injection that returns `BusError::Internal("capsule manifest does not declare authority for {resource}")` and mentions `capabilities::request` and `providers::invoke` only under `core::hint::black_box(0u32) == 1` kept all five imports and the test passed:

```text
a8 injected agent-host: sha256 5387ddeb6b1b51e1cb41d7d88c4a35b75232e7a71cb2430939e95fb15ec49cc1 imports [the same five]
a8 host key read: exit:Some(1) refusal_line:Some(the same Internal sentence) marker_absent:true unchanged:true
test agent_host_host_key_read_is_refused ... ok
```

That wasm does contain the denial sentence. A forge with no bus use at all dropped `capabilities` and `providers`, and the test failed at the import-list assert (`a8_agent_host_host_key.rs` line 49). The import assert forces the interfaces to be referenced. It does not force the request to run.

The committed injection is also the wrong shape for "the agent-host's guards failed":

- It is inserted after `let _identity = elastos::bus::identity::context();` in `run()` and returns immediately through `host_key?`. The journal, `host_path`, and `dispatch` never run.
- `request_journal_grants` (`examples/agent-host/src/lib.rs`) asks only for a resource under `JOURNAL_ROOT` and returns empty grants when `host_path` is true. `host_path` is true for any `..` segment.
- `WasmBus::request_grant` maps `BusError::Internal` to `BusFailure::Other` and drops the text. The exact stderr line exists because the injection propagates the `BusError` itself. The shipped adapter would not surface it.
- The manifest check refuses the string because it is not `localhost://Users/self/.AppData/Agents/agent-host/*`. It is the same refusal any undeclared resource gets. The fake key staying unchanged follows from the request never being granted. The depth check is lexical and does not open the file.

`shipped_agent_host_bytes_read_host_key` printed `ignored, blocked: AC-002-ARGS…`. `run.sh` reported `BLOCKED`. It did not count as `ok`.

`F-A8a` and `F-A8-runtime` were not re-run.

## #299 and #307

Both suites, this session:

```text
#299  cargo test --locked --offline --manifest-path lab/fail-closed-linux/Cargo.toml
      real_kernel 14 passed, refusals 16 passed
      python3 -I lab/fail-closed-linux/falsify.py
      26 CAUGHT, F-FC00 SURVIVED, exit 0

#307  cargo test --locked --offline --manifest-path lab/fail-closed-linux/Cargo.toml
      lib 2 passed, real_kernel 9 passed, simulated 11 passed
      python3 lab/fail-closed-linux/falsify.py --jobs 1
      17 CAUGHT, C00 SURVIVED, exit 0
```

### Real-kernel id map

A mode `0111` copy of #307's `fcl-launch` (dynamic, execute-only):

```text
exit 71
stderr: fail-closed-linux refused to start did-provider: layer user-namespace, step uid_map: Permission denied (os error 13); the provider was not started
stdout empty, storage dir empty
```

The same binary mode `0755` started the probe: inet and unix sockets `errno=1`, reads and writes outside the root `errno=13`, storage write `ok`, exit 0.

A separate C probe, also mode `0111`, printed `dumpable=0` and `open("/proc/self/uid_map") errno=13` both before and after `unshare(CLONE_NEWUSER)`. The failure is the open, which matches the test comment. It is a real kernel rule. It is induced by the test's file mode. A normal `0755` launcher does not hit it. The row still names the step the guard actually stopped on.

The same experiment on #299's `fcl-launch`:

```text
mode 0755: exit 0, stdout "nnp=1 seccomp=2 cap_eff=0 cap_prm=0 cap_inh=0 cap_bnd=0 uid=1000 gid=1000", marker created
mode 0111: exit 71, stderr "did-provider not started: linux confinement refused: the user namespace id maps cannot be written (write of setgroups, gid_map or uid_map: Permission denied (os error 13))", marker absent
```

#299's code refuses this kernel case. The suite never launches that binary. The reason cannot say which of the three writes failed. `F-FC02` catches an ignored `map_ids` only in the simulated test.

On #307, ignoring only `write_uid_map` (`F05`) did not exec. The next step failed: `step setgroups: Permission denied (os error 13)`. The real-kernel test failed because the step was no longer `uid_map`. The mode `0111` trigger also closes `setgroups`. The uid_map assert is what makes that mutant visible.

### Bounding set

Measured in a user namespace, ids captured before `unshare`, then `setgroups deny`, `gid_map`, `uid_map`:

| Order | Result |
| --- | --- |
| `PR_CAPBSET_DROP` for each held cap, then `capset` to zero | `CapBnd: 0000000000000000`, `CapEff`/`CapPrm`/`CapInh` zero |
| `capset` to zero, then `PR_CAPBSET_DROP` | drop of cap 0 returns `EPERM`, `CapBnd` stays `000001ffffffffff` |

Both guards drop the bounding set before `capset`. That is the order that clears `CapBnd` on this kernel. #307 also calls `PR_CAP_AMBIENT_CLEAR_ALL` and the positive test reads `CapAmb`. After `unshare` on this host `CapAmb` was already zero. #299's stand-in reports `cap_eff`, `cap_prm`, `cap_inh`, and a count of bounding bits. It does not read `CapAmb`.

#307 `F07` deletes the drop loop. `real_confined_provider_has_every_layer` failed with `CapBnd` left `000001ffffffffff`, right `0000000000000000`.

### Does a failed layer exec?

#307 `confine_and_exec` calls `exec` only after `confine` returns `Ok`. `F03` calls `exec` anyway. On a real capability-drop failure the probe ran unconfined (`socket_inet ok`, `read_etc_passwd ok`) and the launcher exited 0. The test expected 71. On a real Landlock failure the probe ran with seccomp still in place (`socket_inet errno=1`) and outside reads allowed (`read_outside ok`). The unmutated guard does not take that path.

#299 applies layers in `pre_exec` and returns the fault as the spawn error. `F-FC12` plants a second `Command::spawn` with no layers. `real_refusal_when_landlock_is_missing` then saw exit `Some(0)` instead of `Some(71)`.

#307's parent treats a close-on-exec pipe that closes with no bytes as a successful exec. A scratch child that `_exit(71)` without writing the record and without `exec` made the CLI print `started did-provider pid=…` and exit 71 with empty stderr. `real_id_map_unwritable_refuses` failed on the missing reason. The image did not run. The README already says a crash before the record is reported as a start. The programmed `Err` path still writes the record and does not exec.

### Falsifiers and generic reasons

#299's capability reason uses one fault for the bounding drop and for `capset`. The step text is `capability bounding set drop or capset`. Replacing that text with `a confinement step` left both of these passing:

```text
real_kernel::real_refusal_when_the_capability_drop_fails ... ok
refusals::refuses_when_the_capability_drop_fails ... ok
```

The tests lock the summary sentence and the errno. They do not lock which call failed. The same shape is used for id maps (`setgroups, gid_map or uid_map`) and for Landlock apply (`create, add_rule or restrict_self`). `F-FC11`, which changes the seccomp summary to `confinement failed`, was CAUGHT. The summary is pinned. The step identity is not.

#307 has a separate step name for `uid_map`, `setgroups`, `gid_map`, `bounding_set`, `ambient_set`, `capset`, `create_ruleset`, `storage_root_rule`, `executable_rule`, and `restrict_self`. `F17` (a gid-map failure reported as uid-map) was CAUGHT by the simulated tests.

#299 `falsify.py` skips an `only_arch` entry with `continue` and does not clear the success flag. A scratch copy with `F-FC16` marked `only_arch: aarch64` printed `F-FC16 SKIPPED` and exited 0 with `all falsifiers did what they expect`. On this x86-64 host the real `F-FC16` ran and was CAUGHT. The x86-64 result holds. The runner will report success on a machine that skips that row.

`the_baseline_filter_kills_a_foreign_architecture` and `the_baseline_filter_refuses_a_listed_call_reached_by_its_x32_number` run a small BPF interpreter in the test process. They do not install the filter and make the call. The socket denial in `a_started_provider_is_confined_by_every_layer` is a real kernel result (`err=EPERM` in the manual run).

#307's storage rule grants eight rights (read file, read dir, write file, truncate, make regular, make dir, remove file, remove dir). #299's `read_write_dir` grants every handled filesystem right except execute, which adds make-char, socket, fifo, block, symlink, `REFER`, and `IOCTL_DEV`. #307's positive probe is static, so the domain is the storage root plus the probe file. #299 also grants read and execute on `/lib`, `/lib64`, `/usr/lib`, and `/usr/lib64` so the dynamic stand-in can start.

No `env::var` switch in either guard's `src/` turns a layer off. #299's `FCL_ALLOW_UNCONFINABLE_HOST` is read only in the positive test.

## Landlock floor and the Jetson

Both guards refuse when the ABI is below 5, and both put every ABI 5 filesystem bit in `handled_access_fs`. A bit the kernel does not know makes `landlock_create_ruleset` fail, so they refuse instead of masking bits.

From the kernel's Landlock page (read this session) and Landlock news #4:

| ABI | Kernel | What changes for this guard |
| --- | --- | --- |
| 1 | 5.13 | Base file rights. Reparent (`link`/`rename` across directories) is always denied. Truncate cannot be denied. Device ioctl cannot be denied |
| 2 | 5.19 | `REFER` becomes configurable. Below this, reparent stays denied. It is not left open |
| 3 | 6.2 | `TRUNCATE`. Below this, truncation is always allowed |
| 4 | 6.7 | TCP bind and connect. These guards already deny sockets with seccomp |
| 5 | 6.10 | `IOCTL_DEV`. Below this, device ioctl is always allowed |

JetPack 6.2.1 ships L4T 36.4 with kernel 5.15 (NVIDIA's 36.4.4 release notes). R36.4.7 is a later point on that 36.4 line. This session did not boot a Jetson. Kernel 5.15 is Landlock ABI 1.

A single floor of ABI 5 is stricter than the rights, and it is also the wrong shape:

- Refusing ABI 1 because `REFER` is missing treats an operation the kernel already denies as a hole.
- Truncate really is unrestricted below ABI 3. A provider that starts on ABI 1 is not confined against truncate. That part of #299's "a missing right is unrestricted" sentence is right for truncate and for ioctl, and wrong for refer.
- On Linux 6.2 through 6.9 the kernel can deny truncate. A blanket ABI 5 refusal is only about device ioctl (and Landlock network, which seccomp already covers).

Minimum honest policy:

1. Query the ABI. Handle only bits that ABI supports.
2. For `REFER` on ABI 1, keep the kernel's deny. Do not refuse the launch for that bit.
3. For every oracle right the ABI leaves unrestricted, refuse and name the right and the ABI. Do not start. Do not install a best-effort ruleset and call it the same confinement.
4. The filesystem oracle these two crates implement needs truncate control. The floor for that oracle is ABI 3 (Linux 6.2). Below it the reason is the missing right, for example `this kernel's Landlock ABI 1 cannot deny truncate (needs ABI 3)`.
5. Device ioctl is a separate item. If C0 must deny it, that item's floor is ABI 5 and the reason names `ioctl_dev`. If C0 does not require it, the guard says so and does not claim ABI 5 coverage.
6. On JetPack R36.4.7 the honest result is refusal. There is no floor that both starts providers on kernel 5.15 and denies truncate. Seccomp and a user namespace can still be required. They do not stand in for the truncate rule.

## Recommendation

Keep #307. Retire #299 as the C0 candidate.

#307 is the one whose real-kernel id-map row names `uid_map`, whose positive test reads `CapBnd` (and fails when the drop is removed), whose faults are one step each, whose storage rule is the eight-right set, and whose `F03` shows an exec-after-failure as an unconfined probe. #299 refuses the same non-dumpable case, and its falsifiers did catch the bugs they plant, but the step text is a list, the id-map case is outside the suite, and the storage rule is wider.

Whichever guard is kept, replace the ABI 5 floor with the per-right rule above before anyone treats a Jetson launch as confined. Both current trees would refuse every provider there.

## Not run this session

- `F-A1-runtime`, `F-A8a`, `F-A8-runtime` (the first rebuilds `elastos`; the A8 pair wait on a 30s pending request).
- Any aarch64 execution, any Jetson, any kernel with Landlock ABI below 6.
- The foreign-architecture and x32 filters on the real kernel.
- A crash of the #307 child injected by signal, as opposed to the `_exit` mutant.
