# Resident instances lane log

## ri-1: harness, SPEC and BLOCKED rows

Base `spike/agent-host` `fe1e1c7e`. Linux 6.12 x86_64 (cloud VM, no KVM),
rustc 1.91.0. This lane changes no file outside `lab/resident-instances/`.

### Gate

```sh
lab/resident-instances/run.sh
```

Exit 0. `cargo fmt --check` clean. Library unit tests 17 passed; gates 4
passed; journeys 18 passed; acceptance 5 ignored, each with its blocker list:

```text
A3 | acceptance_a3_two_resident_instances_in_one_runtime | BLOCKED (RI-1; RI-2; RI-3; RI-4)
A6 | acceptance_a6_instance_grant_does_not_authorise_sibling | BLOCKED (RI-1; RI-2; RI-3; RI-4; RI-7)
A10 | acceptance_a10_cancel_one_instance_sibling_unaffected | BLOCKED (RI-1; RI-2; RI-3; RI-4; RI-5)
A11 | acceptance_a11_failed_instance_request_settled_by_runtime | BLOCKED (RI-1; RI-2; RI-3; RI-4; RI-5; RI-6)
A12 | acceptance_a12_stopped_instances_leave_nothing_behind | BLOCKED (RI-1; RI-2; RI-3; RI-4; RI-7)
resident instances: accepted 0 of 5; failed 0; blocked 5; skipped 0
```

Every gap pin printed `[holds]` with its file and line in this checkout.

```sh
cargo clippy --locked --manifest-path lab/resident-instances/Cargo.toml --all-targets -- -D warnings
```

Clean.

```sh
cargo test --locked --manifest-path lab/resident-instances/Cargo.toml --test acceptance -- --ignored
```

0 passed, 5 failed. Each forced row failed with
`BLOCKED <row>: missing Runtime capabilities <its list>`. No row can pass
without a live journey.

### Falsifiers

26 CAUGHT of 26, on the final source. The shared runner refuses this lane's
command, so a local script applied each entry of `falsifiers.json` by hand:

1. run each named test on the unmutated tree and require it to pass;
2. apply the exact edit, require a clean build, then require each named test
   to run and fail (a build failure would be NOT RUN, never a catch);
3. restore the bytes, check their SHA-256, and require each test to pass.

| Falsifier | Named test that failed |
| --- | --- |
| F-RI-a3-dwell | `a3_refuses_instances_that_leave_after_start` |
| F-RI-a3-processes | `a3_refuses_a_process_per_instance` |
| F-RI-launch-session | `launch_refuses_a_shared_session` |
| F-RI-launch-status | `launch_refuses_an_answer_after_the_run` |
| F-RI-a6-sibling | `a6_refuses_a_grant_shared_across_instances` |
| F-RI-a6-grant | `a6_refuses_a_blind_grant_view` |
| F-RI-a10-sibling | `a10_refuses_a_stop_that_stops_the_sibling` |
| F-RI-a10-settlement | `a10_refuses_a_stop_that_leaves_the_request_pending` |
| F-RI-stop-cause | `a10_refuses_a_stop_without_its_reason` |
| F-RI-a10-watch | `a10_refuses_a_retry_after_stop` |
| F-RI-settler | `a11_refuses_settlement_by_the_shell` |
| F-RI-settlement-reason | `a10_and_a11_refuse_a_settlement_without_its_reason` |
| F-RI-a11-settlement | `a11_refuses_a_request_left_pending_by_failure` |
| F-RI-a12-control | `a12_refuses_a_blind_grant_census` |
| F-RI-a12-grants | `a12_refuses_grants_kept_after_stop` |
| F-RI-census-processes | `census_refuses_a_process_left_after_stop` |
| F-RI-pin | `blocker_evidence_still_holds`, `every_check_reports_blocked_with_its_missing_capabilities` |
| F-RI-gate | `every_check_reports_blocked_with_its_missing_capabilities` (the row graded SKIPPED) |
| F-RI-wit | `wit::tests::imports_comments_and_half_lifecycles_are_not_resident` |
| F-RI-coords | `http::tests::coordinates_name_only_a_loopback_operator` |
| F-RI-scope | `http::tests::live_grants_need_the_global_scope` |
| F-RI-record | `http::tests::a_settlement_record_is_consistent_about_its_settler` |
| F-RI-tree | `http::tests::the_process_census_walks_only_below_the_runtime` |
| F-RI-seed | `http::tests::the_seed_sends_its_bytes_as_a_number_list` |
| F-RI-row | `acceptance_rows_name_exact_blockers` |
| F-RI-spec | `spec_states_the_same_capabilities_and_checks` |

The journey falsifiers remove one check each. The matching reference-double
test then fails, either because the journey passes or because it fails for
another reason than the one that test names. They prove the harness, not the
Runtime.

### Live probe of today's operator

A one-off scratch program (not committed) called this lane's operator adapter
against a real operator built from this checkout:
`elastos` SHA-256 `43db6113…e8e680`, `localhost-provider` SHA-256
`1e82a785…4c8530` (debug builds, `CARGO_PROFILE_DEV_DEBUG=0`). The throwaway
Home sat under this lane's ignored `target/`, with `dev_mode = true`, Carrier
on `127.0.0.1:0`, `ELASTOS_CARRIER_MDNS=0`, and the API on a free loopback
port.

| Call | Result |
| --- | --- |
| `POST /api/auth/attach` (shell) | ok |
| `GET /api/health` | ok |
| `POST /api/provider/localhost/write` (seed) | first refused, then ok after the fix below |
| `GET /api/capability/pending` | ok, 0 pending |
| process census below the operator pid | ok, 1 process (`localhost-provider`, matches `pgrep -P`) |
| `GET /api/capsules` | ok, 0 capsules |
| `GET /api/capability/list?scope=all_sessions_live` | refused by the adapter: no `all_sessions_live` scope (RI-7 gap, live) |
| `GET /api/capability/requests?session=…` | HTTP 405: only `DELETE /api/capability/:id` matches that path (RI-5 gap, live) |

The probe found one adapter bug: the seed sent `content` as a string, and the
localhost provider answered `parse_error` ("expected a sequence"). The adapter
now sends a list of byte values, as agent-conformance does;
`the_seed_sends_its_bytes_as_a_number_list` and F-RI-seed pin it. After
SIGTERM the operator and its provider child exited, no process named the probe
Home, and nothing appeared at `/tmp/elastos`. The probe Home and probe build
were then removed.

No component capsule was launched: RI-1 has no world to build a resident
fixture against. The launch gap (RI-2) and list gap (RI-3) stay source
evidence.

### Not proven

- No check is accepted. All five rows are BLOCKED on RI-1 to RI-4, plus RI-5,
  RI-6 or RI-7 as listed.
- The fixture guests are specified (SPEC.md section 5, `src/contract.rs`) but
  not written: they need the RI-1 world.
- The census's instance-leftover check has no falsifier of its own. Each
  journey's stop waits for `stopped` before the census, so no double fault can
  reach it; it stays as a second line.
- The process census walks the operator's process tree. A worker that leaves
  that tree would escape it.
- The live probe covers today's existing routes only. The journeys have run
  against the reference double, never against a Runtime.
