# Independent adversarial review r2 of draft PR #351

```text
PR:        #351 A2 e2e resume after a real Runtime process restart
Head:      9e7a85d631aec12de8c1da4fc4958bce18252d21 (measured)
Report:    4c024265b5655a222c4b6cd7d19c1f3068507379
Base:      cursor/a2-journal-load-b1e8 (#341)
Prior:     #368 FALSIFIED A2 at a97a6373
Reviewer:  Cursor Grok (GPT-family)
Date:      26 Oct 2026
Machine:   Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Verdict:   pending measured run
```

This folder is the r2 review only. #351 files were not edited. This
branch was not pushed to `cursor/a2-e2e-resume-27c8`.

Rule used (Anders): a complete journey, refusal evidence, and the
required reviews. A skip is not a pass. Every claim needs a falsifier.

Raw plants: `experiments.py` and `experiments.log`.

## Plain English

#368 said A2 could not be counted. The published journey skipped the
guest on STALE and WRITE2, shipped a public test helper with a known
recovery phrase, believed hardcoded PASS rows, and treated a crash as
STOP PASS.

The author says those holes are closed. This review reruns the journey
from a clean tree, replants every #368 attack, and hunts the new
surfaces: `lab-protection` leaking into a default or workspace build,
the recovery phrase in release artifacts, whether the second process
is truly new, whether the driver writes the journal itself, whether
`guest.sha256` is the bytes Wasmtime loads, and whether STALE is a
Runtime refusal.

Measured rows and plant results land in the next commit after
`lab/a2-e2e-resume/run.sh` and `experiments.py` finish.

## Claims

| # | Claim | Verdict |
| --- | --- | --- |
| 1 | STALE and WRITE2 go through the guest `providers.invoke` hostcall. The driver does not mint a write token or call `handle_component_resource_request`. | pending run; source HOLDS |
| 2 | `store_test_principal_root_protection` is `pub(crate)` under `cfg(test)`, or public only with off-by-default `lab-protection`. Default / workspace / CI / release builds do not enable it. | pending artifact grep; source HOLDS with one residual |
| 3 | Every row is computed. `Proof.row` refuses PASS. STOP requires exit 0. WRITE checks `guest.sha256`. | pending plants |
| 4 | Two real OS processes; store reopened from disk; first process gone before START. | pending pid/strace |
| 5 | STALE proves the Runtime refused, not the guest printing "conflict". | pending audit; source HOLDS |
| 6 | `guest.sha256` is the file Wasmtime loads. | pending hash; source HOLDS |
| — | A2 can be counted under Anders's rule. | pending |

## Source read at 9e7a85d

`4c024265` only changes reports and `evidence.txt`. The measured code is
`9e7a85d`.

### Guest path

`run()` on a first launch (`OpenOutcome::Created`) calls
`probe_stale_write`. That function sends `if_revision=stale-not-current`
through `bus.invoke(..., "write", ...)` and accepts only
`revision_conflict`. On a later launch (`OpenOutcome::Loaded`) it calls
`write_at_loaded_revision`, same hostcall, with the loaded revision.

The driver launches with `run_local_with_principal`. It grants the two
pending journal asks (Home's role). It does not call
`handle_component_resource_request`. That function is `pub(crate)`
again. The old #368 strings `stale_write(&host, ...)` and
`bridge_write(host, ...)` are gone from the driver.

The sentence "driver mints no write token" is a bit wide. The driver
still mints the two journal grant tokens the guest asked for. It does
not mint a token to write as itself.

### Shipping helper

```rust
#[cfg(any(test, feature = "lab-protection"))]
fn store_test_principal_root_protection_inner(...) {
    let recovery_phrase = "aaaa-bbbb-cccc-dddd-eeee-ffff-1111-2222".to_string();
```

`pub(crate)` under `cfg(test)`. `pub` only when `lab-protection` is on
and this is not a test build. `elastos-server` default features are
empty. The only crate that turns the feature on is
`lab/a2-e2e-resume`. That crate is not an `elastos` workspace member.

No CI workflow, `justfile`, or `scripts/` path uses `--all-features`.
`cargo test --workspace` does not pass `--all-features`. Shared
`target-build` does not unify features across separate cargo graphs.

Residual: `cargo build -p elastos-server --features lab-protection`
would compile the phrase into that rlib. Nobody in CI or release
scripts does that. Do not add the lab crate to the elastos workspace.
If you do, one `cargo test --workspace` would turn the feature on for
every member that depends on `elastos-server`.

`resource_bridge` is a public module. `handle_component_resource_request`
inside it is `pub(crate)`, so an outside crate still cannot call it.

### Harness

`Proof.row` exits if the result is PASS. `Proof.accept` is the only
PASS path. WRITE checks journal bytes, format 2, audited `write:ok`,
and `guest.sha256` against the built file. STOP requires return code
0. START requires two different pids, a journal still on disk, and
`PROCESS second`. RESUME requires audited `read:ok` plus a driver
RESUME PASS. WRITE2 requires audited `write:ok` plus a driver WRITE2
PASS.

`invoke_outcome` maps `revision_conflict` to audited `write:conflict`.
A second `create_only` write also becomes `write:conflict`. On the
published guest, STALE is the stale `if_revision` probe. The harness
does not read the write body. It proves a Runtime write conflict, not
the exact stale string, from audit alone.

### Loaded guest bytes

`capsule.json` entrypoint is `agent-host.component.wasm`.
`ComponentProvider::load` does `Component::from_file` on
`path.join(&manifest.entrypoint)`. The pin is that file. The check
is a hash of the file just before launch, not a hash after Wasmtime
decode. Same path.

## What must still run on macOS

The guest hash is per machine. The pinned
`0e868fc1…cbace` is Linux x86_64. A Mac run must rebuild the guest,
re-pin `guest.sha256`, and rerun `lab/a2-e2e-resume/run.sh`. This
review did not do that. `elastos serve` is still not in this lab.

## Next

Finish the clean `run.sh`, then `experiments.py`. Update this file
with exact rows and a yes/no on whether A2 counts.
