# A2 e2e resume

```text
Lane:         lab/a2-e2e-resume
Branch / PR:  cursor/a2-e2e-resume-27c8  https://github.com/Elacity/elastos-agent-host-spike/pull/351
Head:         9e7a85d631aec12de8c1da4fc4958bce18252d21
Base:         cursor/a2-journal-load-b1e8 db8f7510d99f4e1f887801fc642861043d10b474
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Guest:        sha256:0e868fc1b7565f317c06b514992c90e1d75bdeeb1c0e92d2172e4dd4d41cbace
```

Draft PR #368 found A2 could not be counted. This branch fixes those
findings. STALE and WRITE2 go through the guest hostcall. The two
shipping hooks are restored. Every row is computed. The review plants
are in this lab's falsifier.

## Journey (this machine)

`lab/a2-e2e-resume/run.sh` at 2026-10-26T22:36:16Z, exit 0.

| Step | Result | Evidence |
| --- | --- | --- |
| WRITE | PASS | first pid 48301; format-2 journal sha256 `fca6e299…931d30`; `write:ok`; guest `0e868fc1…cbace` |
| STALE | PASS | guest `write:conflict`; stored sha256 unchanged |
| STOP | PASS | first process exited 0; store kept at `lab/a2-e2e-resume/homes/store-48205` |
| START | PASS | second pid 48311 on the same store |
| RESUME | PASS | guest read then write on the stored journal |
| WRITE2 | PASS | new revision `eba4e7eb…271d6f`; journal sha256 `fe13e4b9…e33ea` |
| A2_counted | yes | every row computed PASS; skipped none |

Two real OS processes. One on-disk store. The driver does not mint a
write token and does not call `handle_component_resource_request`.

## Review plants (all CAUGHT)

| Id | Result | What failed |
| --- | --- | --- |
| F-A2-CREATE-ONLY | CAUGHT | RESUME FAIL |
| F-A2-SKIP-LOAD | CAUGHT | RESUME FAIL |
| F-A2-REVISION | CAUGHT | STALE FAIL |
| F-REV-SECOND-STALE-WRITE | CAUGHT | WRITE2 FAIL; RESUME stayed PASS |
| F-REV-OLDER-JOURNAL | CAUGHT | RESUME FAIL |
| F-REV-STORE-WIPE | CAUGHT | second process DRIVER_ERROR; RESUME not PASS |
| F-REV-GUEST-HASH | CAUGHT | WRITE FAIL (`0e868fc1…` -> `07236439…`) |
| F-REV-HARDCODED-HARNESS-PASS | CAUGHT | `Proof.row` refused PASS |
| F-REV-SKIPPED-STALE | CAUGHT | STALE NOT RUN |
| F-REV-STOP-NONZERO | CAUGHT | first exit 1; STOP FAIL |

10 of 10 CAUGHT.

## Shipping hooks

- `handle_component_resource_request` is `pub(crate)` again.
- `store_test_principal_root_protection` is `pub(crate)` under `cfg(test)`.
  The off-by-default `lab-protection` feature exposes it only to this lab
  crate. `cargo build -p elastos-server --release` finished 0. A probe
  crate without the feature printed
  `error[E0425]: cannot find value store_test_principal_root_protection
  in module elastos_server::auth`. `nm` on the release rlib found no
  symbol. The known recovery phrase is absent from that rlib.

Do not merge.
