# A5 binding harness lane log

## a5-1: SPEC, harness and BLOCKED rows

Base `spike/agent-host` `492240a721670beaf8ac45c5e347b8eccaab82a8`. Elacity
`develop` was not merged (this lane changes no Runtime code). Linux x86_64
(cloud VM, no KVM), rustc 1.91.0. This lane changes no file outside
`lab/a5-binding-harness/`.

### Gate

```sh
lab/a5-binding-harness/run.sh
```

Exit 0. `cargo fmt --check` clean. Library 11 passed; gates 6 passed;
journeys 10 passed; acceptance 9 ignored, each with its blocker list:

```text
check | test | grade
A5-ID-POS | acceptance_a5_identity_grant_used_by_bound_agent | BLOCKED (RA-1; RA-5; RA-6)
A5-ID-REPLAY | acceptance_a5_identity_grant_replayed_by_other_agent | BLOCKED (RA-1; RA-5; RA-6)
A5-SESS-POS | acceptance_a5_session_grant_used_in_bound_session | BLOCKED (RA-1; RA-6)
A5-SESS-END | acceptance_a5_session_grant_reused_after_session_end | BLOCKED (RA-1; RA-2; RA-6)
A5-INST-POS | acceptance_a5_instance_grant_used_by_bound_instance | BLOCKED (RA-1; RA-6)
A5-INST-SIB | acceptance_a5_instance_grant_used_by_sibling | BLOCKED (RA-1; RA-6)
A5-STOR-POS | acceptance_a5_owned_storage_grant_used_on_bound_root | BLOCKED (RA-3; RA-5; RA-6)
A5-STOR-OTHER | acceptance_a5_owned_storage_grant_pointed_at_other_root | BLOCKED (RA-3; RA-5; RA-6)
A5-PUB | acceptance_a5_public_storage_read_is_not_binding | BLOCKED (RA-3; RA-5)
A5 binding: accepted 0 of 9; failed 0; blocked 9; skipped 0
```

Every gap pin printed `[holds]` with its file and line in this checkout.

```sh
cargo clippy --locked --manifest-path lab/a5-binding-harness/Cargo.toml --all-targets -- -D warnings
```

Clean.

```sh
cargo test --locked --manifest-path lab/a5-binding-harness/Cargo.toml --test acceptance -- --ignored
```

0 passed, 9 failed. Each forced row failed with `BLOCKED <row>: missing Runtime capabilities …`.

### Falsifiers

5 CAUGHT of 5. Each plant: named test failed, file restored byte-identical
by SHA-256, then the suite passed again.

| Id | Plant | Test that failed |
| --- | --- | --- |
| F-A5-FAKE-REFUSAL | drop the Runtime-speaker check | `fake_refusal_is_rejected`, `fixture_refusal_is_not_runtime_evidence` |
| F-A5-SKIP-AS-PASS | `counts_as_accepted` also matches SKIPPED | `skipped_is_never_accepted` |
| F-A5-PUBLIC-AS-BIND | drop the `read.bound` refusal | `public_read_as_binding_is_rejected` |
| F-A5-SIBLING | drop the sibling use_refused step | `sibling_allowed_is_rejected` |
| F-A5-SESSION-END | drop the post-end use_refused step | `session_survives_end_is_rejected` |

### Not run here

- No live operator. Journeys ran only against the reference double.
- Fixture guests are not written. They wait on RA-6.
- `cx-agent-conformance` was not touched.

### Next

Sasha and Anders review SPEC.md. When RA-1, RA-2, RA-3, RA-5 and RA-6 land,
a later run sets `A5_RUNTIME_COORDS` and the conformance lane can plug in.

## a5-2: review #372 fix list

Review draft #372 (`lab/review-a5-334/REPORT.md`) at `9990c797`. This commit
keeps every row BLOCKED until a guest journey measures the ask. Clearing
`gap()` is not that measurement. The guest presents a handle. The adapter
uses only routes on develop. Empty grant ids are refused. Refusal codes are
whole tokens. The owned-name walk refuses `..`, symlink-shaped segments and
prefix collisions. A5-PUB reads Public. A5-SESS-END requires
`settled_by=runtime`. The four positive rows are different journeys.

### Gate

```sh
lab/a5-binding-harness/run.sh
```

Exit 0. `cargo fmt --check` clean. Library 21 passed; gates 6 passed;
journeys 14 passed; theatre 2 passed; acceptance 9 ignored:

```text
check | test | grade
A5-ID-POS | acceptance_a5_identity_grant_used_by_bound_agent | BLOCKED (RA-1; RA-5; RA-6)
A5-ID-REPLAY | acceptance_a5_identity_grant_replayed_by_other_agent | BLOCKED (RA-1; RA-5; RA-6)
A5-SESS-POS | acceptance_a5_session_grant_used_in_bound_session | BLOCKED (RA-1; RA-6)
A5-SESS-END | acceptance_a5_session_grant_reused_after_session_end | BLOCKED (RA-1; RA-2; RA-6)
A5-INST-POS | acceptance_a5_instance_grant_used_by_bound_instance | BLOCKED (RA-1; RA-6)
A5-INST-SIB | acceptance_a5_instance_grant_used_by_sibling | BLOCKED (RA-1; RA-6)
A5-STOR-POS | acceptance_a5_owned_storage_grant_used_on_bound_root | BLOCKED (RA-1; RA-3; RA-5; RA-6)
A5-STOR-OTHER | acceptance_a5_owned_storage_grant_pointed_at_other_root | BLOCKED (RA-1; RA-3; RA-5; RA-6)
A5-PUB | acceptance_a5_public_storage_read_is_not_binding | BLOCKED (RA-6)
A5 binding: accepted 0 of 9; failed 0; blocked 9; skipped 0
```

```sh
cargo clippy --locked --manifest-path lab/a5-binding-harness/Cargo.toml --all-targets -- -D warnings
```

Clean.

```sh
cargo test --locked --manifest-path lab/a5-binding-harness/Cargo.toml --test acceptance -- --ignored
```

0 passed, 9 failed, each BLOCKED with its named asks.

### Falsifiers

10 CAUGHT of 10. Each plant failed its named test at an assertion, not a
timeout. Files restored byte-identical by SHA-256.

| Id | Plant | Test that failed |
| --- | --- | --- |
| F-A5-FAKE-REFUSAL | drop the Runtime-speaker check | `fake_refusal_is_rejected`, `fixture_refusal_is_not_runtime_evidence` |
| F-A5-SKIP-AS-PASS | `counts_as_accepted` also matches SKIPPED | `skipped_is_never_accepted` |
| F-A5-PUBLIC-AS-BIND | drop the `read.bound` refusal | `public_read_as_binding_is_rejected` |
| F-A5-SIBLING | drop the sibling use_refused step | `sibling_allowed_is_rejected` |
| F-A5-SESSION-END | drop the post-end use_refused step | `session_survives_end_is_rejected` |
| F-A5-THEATRE | drop the guest-handle PASS check | `theatre_without_guest_handle_is_not_accepted` |
| F-A5-EMPTY-ID | drop empty grant id refusal | `empty_grant_id_is_rejected`, `empty_grant_id_is_rejected_on_the_journey` |
| F-A5-REASON-SUB | match reasons with `contains()` | `reason_substring_is_not_a_match` |
| F-A5-PUB-HARDCODE | hardcode Public bound false | `public_read_bound_is_not_hardcoded` |
| F-A5-GAP-CLEAR | `gap()` returns None | `gap_cleared_without_guest_keeps_rows_blocked` |

`theatre_stub_does_not_accept_nine_of_nine` also ran a loopback stub with
blockers skipped: accepted 0 of 9.

### Next

A5 waits on the Runtime asks below. Do not merge this PR.

## a5-3: review #383 r2 — needs() match calls, SPEC not the gate

Review draft #383 (`lab/review-a5-334-r2/REPORT.md`) at `2a6892ff`. This
commit makes every row's `needs()` list every Runtime call its journey
makes. A5-PUB calls `host_record`, so it lists RA-1 and guest-handle use
(#463), not only RA-6. A test derives those calls and fails if `needs()`
omits any. The folder and PR are a SPEC and a BLOCKED table, not the A5
acceptance gate. Landing RA-1/2/3/5/6 + #463 is not enough. SPEC.md
section 9 names the live evidence a later PASS must record.

### Gate

```sh
lab/a5-binding-harness/run.sh
```

Exit 0. `cargo fmt --check` clean. Library 22 passed; gates 7 passed;
journeys 15 passed; theatre 2 passed; acceptance 9 ignored:

```text
check | test | grade
A5-ID-POS | acceptance_a5_identity_grant_used_by_bound_agent | BLOCKED (RA-1; RA-5; RA-6; #463)
A5-ID-REPLAY | acceptance_a5_identity_grant_replayed_by_other_agent | BLOCKED (RA-1; RA-5; RA-6; #463)
A5-SESS-POS | acceptance_a5_session_grant_used_in_bound_session | BLOCKED (RA-1; RA-6; #463)
A5-SESS-END | acceptance_a5_session_grant_reused_after_session_end | BLOCKED (RA-1; RA-2; RA-6; #463)
A5-INST-POS | acceptance_a5_instance_grant_used_by_bound_instance | BLOCKED (RA-1; RA-6; #463)
A5-INST-SIB | acceptance_a5_instance_grant_used_by_sibling | BLOCKED (RA-1; RA-6; #463)
A5-STOR-POS | acceptance_a5_owned_storage_grant_used_on_bound_root | BLOCKED (RA-1; RA-3; RA-5; RA-6; #463)
A5-STOR-OTHER | acceptance_a5_owned_storage_grant_pointed_at_other_root | BLOCKED (RA-1; RA-3; RA-5; RA-6; #463)
A5-PUB | acceptance_a5_public_storage_read_is_not_binding | BLOCKED (RA-1; RA-6; #463)
A5 binding: accepted 0 of 9; failed 0; blocked 9; skipped 0
```

```sh
cargo clippy --locked --manifest-path lab/a5-binding-harness/Cargo.toml --all-targets -- -D warnings
```

Clean.

```sh
cargo test --locked --manifest-path lab/a5-binding-harness/Cargo.toml --test acceptance -- --ignored
```

0 passed, 9 failed, each BLOCKED with its named asks.

### Falsifiers

11 CAUGHT of 11. Each plant failed its named test at an assertion, not a
timeout. Files restored byte-identical by SHA-256.

| Id | Plant | Test that failed |
| --- | --- | --- |
| F-A5-FAKE-REFUSAL | drop the Runtime-speaker check | `fake_refusal_is_rejected`, `fixture_refusal_is_not_runtime_evidence` |
| F-A5-SKIP-AS-PASS | `counts_as_accepted` also matches SKIPPED | `skipped_is_never_accepted` |
| F-A5-PUBLIC-AS-BIND | drop the `read.bound` refusal | `public_read_as_binding_is_rejected` |
| F-A5-SIBLING | drop the sibling use_refused step | `sibling_allowed_is_rejected` |
| F-A5-SESSION-END | drop the post-end use_refused step | `session_survives_end_is_rejected` |
| F-A5-THEATRE | drop the guest-handle PASS check | `theatre_without_guest_handle_is_not_accepted` |
| F-A5-EMPTY-ID | drop empty grant id refusal | `empty_grant_id_is_rejected`, `empty_grant_id_is_rejected_on_the_journey` |
| F-A5-REASON-SUB | match reasons with `contains()` | `reason_substring_is_not_a_match` |
| F-A5-PUB-HARDCODE | hardcode Public bound false | `public_read_bound_is_not_hardcoded` |
| F-A5-GAP-CLEAR | `gap()` returns None | `gap_cleared_without_guest_keeps_rows_blocked` |
| F-A5-NEEDS-OMIT | drop RA-1 from A5-PUB `needs()` | `needs_cover_every_runtime_call_the_journey_makes` |

### Next

Do not merge this PR as the A5 gate. A later lane writes the live
measurement and the missing adapter, and that write is reviewed on its
own.
