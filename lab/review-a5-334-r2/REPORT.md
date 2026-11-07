# Independent review r2 of PR #334 (A5 acceptance harness)

Reviewer: Cursor Grok (this draft PR). Author of #334 is Claude-family.
Reviewed head: `2a6892ff5a205d545c2690337b439076352f47d1`
Branch reviewed: `cursor/a5-binding-harness-f635`
Prior review: #372 at `2648b9c1`, verdict `FIX FIRST` (`lab/review-a5-334/REPORT.md`).
This PR: `lab/review-a5-334-r2/` only. #334's branch was not pushed to.
Checkout used for replay: worktree `/tmp/a5-334-wt` at that head.
Mutations ran on a copy under `/tmp/a5-review-r2-copy`. Files restored
byte-identical by SHA-256.
Elacity develop read: `92aeea44d4b258b2965972cbd58aaa203afbab18` (fetch only).
Runtime-asks read: PR #309 head `cursor/runtime-asks-ad52`.

**Verdict: NOT YET.**

The #372 theatre hole is closed. Clearing `gap()`, forging coords, and
talking to a loopback stub now keeps every row BLOCKED. Official plants
are 10 CAUGHT of 10 at assertions. A stub with the blockers skipped is
still accepted 0 of 9.

This folder is still not the A5 acceptance gate. Once RA-1, RA-2, RA-3,
RA-5, RA-6 and guest-handle use land, this harness cannot turn those
asks into PASS. `GuestMeasurement::from_operator` always returns `None`.
The live adapter never records binding evidence. `host_record`,
`use_grant`, `seed`, `read_bytes` and `end_session` are hardcoded
missing. Landing the Runtime asks leaves every row BLOCKED until a
person edits this crate again. That later edit is the next theatre
surface.

Do not merge #334 as the A5 gate.

## Plain English

#372 showed that one edit (`gap()` set to `None`) plus a fake operator
on loopback produced **accepted 9 of 9 PASS**, with no guest and no
real bind. The author said that path is closed.

It is. Today the rows stay BLOCKED until a function named
`guest_measured()` says a guest on a real operator measured each ask.
That function always says no. There is no file and no environment
variable that can change it. A stub that answers HTTP still cannot
reach PASS, because the live adapter refuses to invent a host record
or a guest-handle use, and it never stores the evidence `acceptance()`
needs for PASS.

That is honest for today. It is also why this harness is not yet the
gate. When the Runtime ships the asks, someone still has to write a
real measurement, a host-record lookup, guest-handle use, seed and
read, and a way to record live evidence. Until that write exists and
is reviewed, treat this folder as a BLOCKED table and a SPEC, not as
A5 acceptance.

## Reproduction of #334's counts

Commands run at `2a6892ff` in `/tmp/a5-334-wt`:

```text
lab/a5-binding-harness/run.sh
→ library 21 passed; gates 6 passed; journeys 14 passed; theatre 2 passed;
  acceptance 9 ignored
→ accepted 0 of 9; failed 0; blocked 9; skipped 0
→ exit 0

cargo clippy --locked --manifest-path lab/a5-binding-harness/Cargo.toml --all-targets -- -D warnings
→ clean

cargo test --locked --manifest-path lab/a5-binding-harness/Cargo.toml --test acceptance -- --ignored
→ 0 passed; 9 failed; each BLOCKED with the RA-* list in the PR body
```

The nine BLOCKED lines match the PR table exactly, including A5-PUB on
RA-6 only, and the storage rows on RA-1; RA-3; RA-5; RA-6.

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

Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28).

## Official plants

Ten plants from `falsifiers.json`, applied on the copy. Each named test
failed at an assertion, in under a second. Files restored
SHA-256-identical.

| Id | Named tests failed | Kind | Restore |
| --- | --- | --- | --- |
| F-A5-FAKE-REFUSAL | `fake_refusal_is_rejected`, `fixture_refusal_is_not_runtime_evidence` | ASSERT | IDENTICAL |
| F-A5-SKIP-AS-PASS | `skipped_is_never_accepted` | ASSERT | IDENTICAL |
| F-A5-PUBLIC-AS-BIND | `public_read_as_binding_is_rejected` | ASSERT | IDENTICAL |
| F-A5-SIBLING | `sibling_allowed_is_rejected` | ASSERT | IDENTICAL |
| F-A5-SESSION-END | `session_survives_end_is_rejected` | ASSERT | IDENTICAL |
| F-A5-THEATRE | `theatre_without_guest_handle_is_not_accepted` | ASSERT | IDENTICAL |
| F-A5-EMPTY-ID | `empty_grant_id_is_rejected`, `empty_grant_id_is_rejected_on_the_journey` | ASSERT | IDENTICAL |
| F-A5-REASON-SUB | `reason_substring_is_not_a_match` | ASSERT | IDENTICAL |
| F-A5-PUB-HARDCODE | `public_read_bound_is_not_hardcoded` | ASSERT | IDENTICAL |
| F-A5-GAP-CLEAR | `gap_cleared_without_guest_keeps_rows_blocked` | ASSERT | IDENTICAL |

**10 CAUGHT of 10.** None was a timeout.

These plants prove the harness's own ifs. F-A5-THEATRE only deletes the
guest-handle check inside `grade_pass`. The live 9/9 theatre is covered
by `theatre_stub_does_not_accept_nine_of_nine` and by the attacks below.

## #372 attacks, re-planted

#372's surviving mutants, replayed on `2a6892ff`.

| Id | What we did | Result | Caught? |
| --- | --- | --- | --- |
| M-FORGE-TODAY | forged `A5_RUNTIME_COORDS` + theatre stub, no source edit | accepted 0; blocked 9 | yes |
| M-372-GAP-NONE | `gap()` forced to `None`, no coords | accepted 0; blocked 9 (not SKIPPED) | yes |
| M-372-GAP-NONE-STUB | `gap()` None + forged coords + theatre stub | accepted 0; blocked 9 (not 9/9 PASS) | yes |
| theatre.rs | blockers skipped, `check.run` on the in-crate stub | accepted 0 of 9; failed 9 | yes |

The old 9/9 PASS path is closed. `blocked()` now reads
`guest_measured()`, not `gap()`. Clearing `gap()` leaves every row
BLOCKED.

The old empty-id, reason-substring, allow-all, and Public-bound plants
are caught by the official ten. The live adapter no longer calls
`/api/capability/use` or `/api/sessions/{id}/end`. Those routes are
still absent on develop `92aeea44`.

## New ways to reach ACCEPTED without a guest and a real operator

Each attack tried to make `acceptance()` print PASS. None did.

### Forge a measurement record

`GuestMeasurement::from_operator` reads `A5_RUNTIME_COORDS` and ignores
it. It always returns `None`. We wrote
`guest-measurement.json` / `MEASURED` next to the crate, under `/tmp`,
and in the results dir, with `asks: [RA-1, RA-2, RA-3, RA-5, RA-6]`.
We set `A5_GUEST_MEASURED`, `A5_MEASURED`, `A5_ACCEPT`,
`A5_GUEST_MEASUREMENT`, and `A5_MEASUREMENT_FILE`.

**M-FORGE-MEASUREMENT: accepted 0; blocked 9.** No file is the
measurement. There is nothing to forge today.

### Environment variables the gate trusts

`A5_RUNTIME_COORDS` is the only setup variable. It is used after a row
is already unblocked. It cannot clear a blocker. The measurement
function mentions it and then throws the value away.

### Spoof operator identity or host

`parse_coords` accepts only `http://127.0.0.1:<port>`,
`runtime_kind=operator`, and a nonempty attach secret. A coords file
with `http://10.0.0.1:80` and `runtime_kind=home` is refused if a row
ever reaches attach. Today the rows never get that far.

### Replay a recorded guest transcript

No transcript file exists. We wrote one and pointed `A5_TRANSCRIPT` at
it. **M-REPLAY-TRANSCRIPT: accepted 0; blocked 9.** The harness does
not read a journal or a recorded journey.

### Stub that returns the measured shape

A new stub answers attach, health, `POST /api/capsules` with a
`handle` and `status=running`, grant request/grant with `request_id`,
a live list with identity/session/instance/owned_root, a request
record with `settled_by=runtime`, and raw Public bytes.

With blockers still in place the stub is never asked. With blockers
skipped (below), launch can succeed. The next call is `host_record`,
which is a hardcoded error: `no host-record-for-handle route on
develop`. `use_grant`, `seed`, `read_bytes` and `end_session` are the
same kind of error. A stub cannot complete a journey.

### Flip a single bool or const

`guest_measured()` changed to always `true`:

- no coords: **skipped 9**, accepted 0, exit 4
- #372 theatre stub: **failed 9** (launch handle empty)
- measured stub: **failed 9** (host_record missing)

`from_operator()` changed to `Some(all asks)`: same SKIPPED / FAIL
pattern. `blocked()` changed to always return empty: **failed 9**.

SKIPPED is not ACCEPTED. The bin panics if a non-PASS grade counts as
accepted.

### Delete a blocker from `needs()`

A5-PUB `needs()` emptied: that row SKIPPED without coords, then FAIL
on the measured stub at `host_record`. The other eight stay BLOCKED.
Emptying every `needs()` list: skipped 9, or failed 9 on the stub.
Accepted 0.

### Accept a journey that returns ok without evidence

Two edits: `from_operator()` returns Some(all), and `acceptance()`
treats a missing evidence record as PASS. Measured stub still
**failed 9**. The journeys never return ok. They stop at
`host_record`.

## `needs()` against review #372

#372 item 8 asked: storage rows list RA-1; A5-PUB lists RA-6 and drops
RA-3.

| Row | #372 named | #334 r2 `needs()` | Journey also calls | Gap |
| --- | --- | --- | --- | --- |
| A5-ID-POS / REPLAY | RA-1, RA-5, RA-6 | RA-1, RA-5, RA-6 | `host_record`, `seed`, `read_bytes`, `use_grant` | Matches the table. RA-5 is now used by seed/read. |
| A5-SESS-POS | RA-1, RA-6 | RA-1, RA-6 | `host_record`, `use_grant` | Matches. |
| A5-SESS-END | RA-1, RA-2, RA-6 | RA-1, RA-2, RA-6 | `end_session`, `request_record` (`settled_by=runtime`), `use_grant` | RA-2 is used. |
| A5-INST-POS / SIB | RA-1, RA-6 | RA-1, RA-6 | two launches, `host_record`, prefix walk | Matches. |
| A5-STOR-POS / OTHER | RA-3, RA-5, RA-6; missing RA-1 | RA-1, RA-3, RA-5, RA-6 | `seed`, `read_bytes`, `..` / symlink / prefix | Matches the requested table. |
| A5-PUB | RA-3, RA-5; missing RA-6 | RA-6 only | `public_read`, then `Walk::launch` → `host_record` | RA-3/RA-5 dropped, as asked. Still under-blocked: the journey calls `host_record` (RA-1 / #463). In practice that FAIL keeps the row from PASS. |

SPEC.md §3 still says RA-3 gives each resident instance its own root
under Home. #309 RA-3 is a per-Home directory, not a per-instance
bind. That over-claim is unchanged.

A5-PUB's Public mint is refused inside the adapter
(`is_public_resource`) before the operator is asked. That is a
harness-local refuse, not Runtime evidence.

## Is this the A5 gate once the asks land?

**No.**

When the pins in `capability.rs` move, `gap()` stays `Some` until
`guest_measured()` is true. `guest_measured()` stays false until a
person changes `from_operator()`. The Runtime shipping RA-1/2/3/5/6
does not write that record. The harness has no protocol for writing
it.

After someone does write it, `acceptance()` still cannot PASS:

1. `host_record` is a hardcoded error.
2. `use_grant` is a hardcoded error (guest-handle use, #463).
3. `seed` and `read_bytes` are hardcoded errors.
4. `end_session` is a hardcoded error.
5. `OperatorRuntime.evidence` is never set. A journey that returned ok
   would still FAIL: `journey returned ok without live operator evidence`.

So the folder cannot become the gate by the asks landing. It becomes
the gate only after a later harness rewrite, and that rewrite needs
its own adversarial review. The #372 lesson still applies: if that
rewrite stamps every HTTP 200 as live evidence, a stub can PASS again.

## Runtime asks for Anders

Verbatim from this harness (`SPEC.md` / `Capability::title`) and from
#309. RA-4 and RA-7 are not named here. Guest-handle use is named in
the harness and is not an RA-* number.

1. **RA-1** — "a shell view of every session's live grants"
   (#309: "The shell reads the live grants of every session." The
   harness also uses this id for a host-record-for-handle lookup,
   which #309 does not describe.)
2. **RA-2** — "the Runtime settles an ended requester's pending
   requests, and the shell reads who settled"
   (A5-SESS-END requires `settled_by=runtime` on
   `GET /api/capability/request/:id`. #309's record route is
   `GET /api/capability/requests?session=`.)
3. **RA-3** — "the run launcher takes its storage directory from the
   selected Home"
   (#309: "`elastos run` takes its storage from the selected Home
   (three literals)". Per-Home, not per-instance.)
4. **RA-5** — "a UsersAI alias that resolves to the verified agent
   principal's root"
   (#309: "`UsersAI/self` resolves to the verified agent principal's
   root.")
5. **RA-6** — "resident component instances: world, launch, list, stop"
   (#309: "Resident component instances: world, launch, list, stop
   (RI-1 to RI-4)".)
6. **Guest-handle use** — not on develop; named as #463. The guest
   presents a handle. The host record decides identity, session,
   instance and owned root. The harness does not call a use route
   today.

Open questions in SPEC.md §7 are still open: path layout, Public
grants, RA-1 route form, session-end revoke vs validate, token vs
handle, whole-check vs one combined journey.

## Claims from #334, checked

| Claim | Result |
| --- | --- |
| Rows BLOCKED unless a guest on a real operator measures each ask | HOLDS today. `from_operator()` is hardcoded `None`. |
| 10/10 plants caught at assertions | HOLDS. 10 CAUGHT of 10, restored identical. |
| Loopback stub with blockers skipped still 0/9 | HOLDS. theatre.rs and every skipped-blocker attack: accepted 0. |
| `gap()` is a pin read; clearing it does not unblock | HOLDS. M-372-GAP-NONE stayed blocked 9. |
| Guest presents a handle; identity is not client JSON | HOLDS on the adapter. Journeys still fail at `host_record`. |
| Routes match develop; `/api/capability/use` is not called | HOLDS. develop `92aeea44` has request/grant/list; no use route; no `/api/sessions`. |
| Empty ids refused; reasons are exact | HOLDS in the checker. Coded refusals still win over a lying reason string (documented). |
| Owned-name walk refuses `..`, symlink, prefix | HOLDS in `walk.rs` and the storage journeys. |
| A5-PUB reads Public; `bound` is not hardcoded | HOLDS. Mint refuse is adapter-local. |
| Four positive rows are different journeys | HOLDS against the double. |

## Verdict

**NOT YET.**

The #372 FIX FIRST items that produced fake PASS are closed. This
commit is an honest BLOCKED table plus a double that proves the
harness's own ifs. It is not the A5 acceptance gate, and it will not
become that gate when RA-1/2/3/5/6 and guest-handle use land, until
someone writes a real measurement and the missing live adapter, and
that write is reviewed.

Do not merge #334 as the A5 gate. Keep it as a SPEC draft.

## Next

Sasha and Anders treat #334 as a blocked SPEC, not as A5 acceptance.
A later lane writes `GuestMeasurement` from a guest journey on a real
operator, implements host-record and guest-handle use against routes
that exist, and records evidence only from those answers. This review
PR stays draft.

Principles touched: 3, 7, 10, 11, 12, 18. DeepSeek: none.
