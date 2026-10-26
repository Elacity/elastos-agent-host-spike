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
