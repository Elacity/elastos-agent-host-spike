# Independent review of PR #334 (A5 acceptance harness)

Reviewer: Cursor Grok (this draft PR). Author of #334 is Claude-family.
Reviewed head: `2648b9c1c514375ff16ea4523af7660538e887a2`
Branch reviewed: `cursor/a5-binding-harness-f635` (also named `lab/a5-binding-harness`)
This PR: `lab/review-a5-334/` only. #334's branch was not pushed to.
Checkout used for replay: worktree `/tmp/a5-334-wt` at that head.
Elacity develop read: `92aeea44d4b258b2965972cbd58aaa203afbab18` (fetch only).
Runtime-asks read: PR #309 head `513988eb`.

**Verdict: FIX FIRST**

The harness is not fit to be the A5 acceptance gate once the RA-* asks land.
Today every row stays BLOCKED unless someone edits `Capability::gap`. After
that one edit, a forged `A5_RUNTIME_COORDS` file and a loopback stub that
answers HTTP 200/403 with the expected JSON fields produced **accepted 9 of 9
PASS**. That stub had no guest, no storage, no host handle, and no verified
principal. The four positive rows are the same journey. Refusal rows accept a
reason substring. The HTTP adapter invents `/api/capability/use` and copies
identity from the harness, not from the Runtime.

## Reproduction of #334's counts

Commands run at `2648b9c1` in `/tmp/a5-334-wt`:

```text
lab/a5-binding-harness/run.sh
→ library 11 passed; gates 6 passed; journeys 10 passed; acceptance 9 ignored
→ accepted 0 of 9; failed 0; blocked 9; skipped 0
→ exit 0

cargo test --locked --manifest-path lab/a5-binding-harness/Cargo.toml --test acceptance -- --ignored
→ 0 passed; 9 failed; each BLOCKED with the RA-* list in the PR body

cargo clippy --locked --manifest-path lab/a5-binding-harness/Cargo.toml --all-targets -- -D warnings
→ clean
```

The nine BLOCKED lines match the PR table exactly, including A5-PUB on RA-3; RA-5 only.

Official plants (copy under `/tmp/a5-review-copy`, files restored byte-identical):

| Id | Named tests failed | Kind | Elapsed | Restore |
| --- | --- | --- | --- | --- |
| F-A5-FAKE-REFUSAL | `fake_refusal_is_rejected`, `fixture_refusal_is_not_runtime_evidence` | ASSERT | 0.62s + 0.04s | IDENTICAL |
| F-A5-SKIP-AS-PASS | `skipped_is_never_accepted` | ASSERT | 0.68s | IDENTICAL |
| F-A5-PUBLIC-AS-BIND | `public_read_as_binding_is_rejected` | ASSERT | 0.63s | IDENTICAL |
| F-A5-SIBLING | `sibling_allowed_is_rejected` | ASSERT | 0.59s | IDENTICAL |
| F-A5-SESSION-END | `session_survives_end_is_rejected` | ASSERT | 0.57s | IDENTICAL |

**5 CAUGHT of 5.** None was a timeout. These plants break harness self-tests
against the in-process double. They do not prove a live Runtime bind.

## Claims

### C1. No row reaches ACCEPTED/PASS without a real Runtime

**FALSIFIED** (after the intended "asks landed" edit). **HOLDS today** only
because `gap()` always returns `Some(...)`.

`acceptance()` returns BLOCKED before it reads `A5_RUNTIME_COORDS` while
`Check::blocked()` is non-empty. `blocked()` is `needs().filter(|c| c.gap().is_some())`.
`Capability::gap` is hardcoded `Some(pins)` for every ask
(`src/capability.rs:173-181` on the reviewed head). There is no env override
and no pin-based auto-clear.

Mutant **M-FORGE-TODAY**: forged coords + theatre stub, `gap()` left as
`Some`. Result: `accepted 0 of 9; blocked 9; skipped 0`. The stub was never
contacted for a journey.

Mutant **M-SKIP-NO-COORDS**: `gap()` forced to `None`, no coords. Result:
`skipped 9`, `accepted 0`, exit 4. SKIPPED is not counted as accepted.

Mutant **M-STUB-theatre**: `gap()` forced to `None`, forged
`A5_RUNTIME_COORDS` pointing at `mutants/stub_operator.py` (mode `theatre`).
Result:

```text
A5-ID-POS     PASS
A5-ID-REPLAY  PASS
A5-SESS-POS   PASS
A5-SESS-END   PASS
A5-INST-POS   PASS
A5-INST-SIB   PASS
A5-STOR-POS   PASS
A5-STOR-OTHER PASS
A5-PUB        PASS
A5 binding: accepted 9 of 9; failed 0; blocked 0; skipped 0
```

The stub printed `{"token":"stub-shell-token"}`. Launch copied the harness
string `agent-a` / `agent-b` as identity. Mint echoed `identity` and
`owned_root`. Use allowed or refused by string compare and returned the
SPEC reason words. No capsule ran. No object was read.

`grade_pass` only checks `EvidenceSource::LiveOperator` and "not a Public
allow" (`src/contract.rs:278-286`). `http.rs` stamps every HTTP answer as
`from_operator` / `Actor::Runtime`. A 200 or a 403 with a substring is
enough.

Hardcoded `Grade::Pass("live operator evidence")` exists in
`tests/gates.rs:139`. That test is not an acceptance row. `from_double` is
`pub` (`src/contract.rs:144`); `grade_pass` rejects it. Those are not the
path that produced 9/9.

### C2. Each BLOCKED row names the missing Runtime capability

**WEAK.** The names match SPEC.md and #309's RA-* titles. The lists do not
match what the journeys call, and RA-3 is not a per-instance bind.

| Row | Named | Journey also needs | Gap |
| --- | --- | --- | --- |
| A5-PUB | RA-3, RA-5 | `launch` (RA-6) and `/api/capability/use` | Under-blocked on RA-6. Over-blocked on RA-3/RA-5: a Public read works on today's localhost provider. |
| A5-STOR-* | RA-3, RA-5, RA-6 | `live_grants` (RA-1) via `assert_live_binding` | Under-blocked on RA-1. |
| A5-SESS-END | RA-1, RA-2, RA-6 | SPEC asks `settled_by=runtime` on `GET /api/capability/requests` | Journey never reads that route. RA-2 is named and unused. |
| A5-ID-POS | RA-1, RA-5, RA-6 | Two launches and a live list | RA-5 is unused: identity is the harness argument to `launch`. |

#309 RA-3 (`03-launcher-storage-under-home.md`) says the three
`/tmp/elastos/storage` literals are a **per-Home** directory, not a
per-instance owned root, and that the edit "does not by itself make agent
A's read of B's file return a reason". SPEC.md §3 still writes "Each
resident instance then has its own root under that Home." That is more
than RA-3.

When pins move, `blocker_evidence_still_holds` fails. `acceptance()` still
returns BLOCKED until a person changes `gap()` to `None`. That is
conservative for today's table. It is also how the theatre stub becomes
the gate.

### C3. The harness would fail a Runtime that is present but does not bind

**FALSIFIED** for the positive rows and for any speaker that returns the
reason words. **HOLDS** for a speaker that allows the forbidden use
without those words.

Mutant **M-STUB-allow-all** (every use HTTP 200):

```text
A5-ID-POS PASS    A5-ID-REPLAY FAIL
A5-SESS-POS PASS  A5-SESS-END FAIL
A5-INST-POS PASS  A5-INST-SIB FAIL
A5-STOR-POS PASS  A5-STOR-OTHER FAIL
A5-PUB FAIL
accepted 4 of 9
```

The four positive rows ACCEPTED with no identity, session, instance, or
root check. They are one journey: launch, mint, echo live list, use_ok.

Mutant **M-STUB-reason-sub** (refuse with `no identity check`,
`instance-1-evil accepted`, `owned root via ..`):

```text
A5-ID-REPLAY PASS   reason "no identity check" contains "identity"
A5-INST-SIB PASS    reason "instance-1-evil accepted" contains "instance"
A5-STOR-OTHER PASS  reason "owned root via .." contains "owned root"
accepted 7 of 9
```

`require_runtime_refusal` uses `evidence.reason.contains(expected)`
(`src/contract.rs:258`).

Mutant **M-STUB-empty-id** (mint `request_id: ""`):

```text
A5-ID-POS PASS request=Some("")
… eight rows PASS; A5-SESS-END FAIL (live list still has the empty id)
accepted 8 of 9
```

`mint_grant` rejects `id.is_none()` and empty `owned_root` / `identity`.
It accepts an empty string id (`src/http.rs:311-314`).

Mutant **M-STUB-hide-end** (drop grant from the live list, still allow
use): A5-SESS-END FAIL on `use_refused`. The leftover list check is not
enough by itself; the use step is. SPEC's `settled_by=runtime` is still
untested.

Prefix instance ids: the journeys compare `x.id == y.id` exactly. They
never send `instance-1` versus `instance-1-evil`. A Runtime that
prefix-matches internally and still returns 403 containing `instance`
PASSes A5-INST-SIB. `ResourceId::matches` on develop already prefix-matches
`/*` (`elastos/crates/elastos-runtime/src/capability/token.rs:91-105` at
`92aeea44`).

Owned-root walk: `lab/grant-binding` refuses `\`, `/`, `.`, `..`,
symlink-shaped segments, and a name that is not the root or a child
(`src/lib.rs:260-294`). This harness never sends `..`, a symlink, or a
renamed root. `A5-STOR-OTHER` only tries the sibling notes path. SPEC
says "A's root is unchanged"; no read-back exists.

### C4. A Public-storage read is not counted as binding

**WEAK.** The double and `grade_pass` refuse a Public allow. The live
adapter cannot report a Public bind.

`OperatorRuntime::public_read` POSTs a write, ignores status, returns
hardcoded bytes and `bound: false` (`src/http.rs:418-437`). A5-PUB's
`if read.bound` (`src/journey.rs:301`) never fires on the live path.
The row then forges `Grant { id: "public-claim", owned_root: "Public/a5-binding", ... }`
and asks `use_refused` for the phrase `public storage read does not bind`.
A stub that 403s that phrase PASSes A5-PUB (theatre). A real Runtime that
403s `unknown grant` FAILS the row even if Public is not a bound grant.

F-A5-PUBLIC-AS-BIND only deletes the `if read.bound` check. On the live
path that check is dead.

### C5. The HTTP adapter talks to the operator as the shell, not as a guest

**FALSIFIED** as A5 evidence if A5 means the grant-binding rule (guest
presents a handle; host record decides). The SPEC says the harness talks
to the operator API. That API, as written here, is not the Runtime of
`92aeea44`.

On develop `92aeea44`:

- `POST /api/capability/grant` grants a **pending request by
  `request_id`**. Input is `request_id`, `duration`, `rationale`
  (`elastos/crates/elastos-server/src/api/handlers/capability.rs:270-278,
  294-359`). Output is `{success, token}`. There is no `owned_root` or
  `identity` field.
- The harness POSTs `{session_id, resource, action}` and reads
  `request_id` / `owned_root` / `identity` (`src/http.rs:301-326`).
- `POST /api/capability/use` does not exist (`server.rs` capability
  routes: 243-266). The harness sends
  `{grant_id, identity, session, instance, path}`.
- `POST /api/sessions/{id}/end` does not exist.
- `LaunchResponse` is `{id, name, status}` with no `session_id`
  (`elastos/crates/elastos-server/src/api/routes.rs:74-78`).
- `launch` in the harness sets `identity` from the function argument, not
  from the response (`src/http.rs:266-270`).
- `mint_grant` copies `session` and `instance` from the launch struct, not
  from the grant response (`src/http.rs:322-323`).

`lab/grant-binding` reads only a handle. Forged identity/session/instance
on the guest request have no effect (`src/lib.rs:42-48`). This harness
sends those claims in the body and believes the echo.

### C6. The five official falsifiers are real

**HOLDS** as self-tests. **WEAK** as proof of the acceptance gate.

Each plant failed its named test at an assertion, in under a second, and
restored SHA-256-identical bytes. They do not run `acceptance()` against
an operator. F-A5-SESSION-END only deletes `use_refused`; the leftover
list check remains. Combined with a stub that hides the grant and never
calls `use_grant`, the planted journey returned ok and `acceptance`
graded FAIL for missing live evidence, not PASS.

## Surviving mutants

These produced ACCEPTED/PASS for at least one A5 row without a Runtime
that binds.

| Id | What we did | Survived as PASS |
| --- | --- | --- |
| M-STUB-theatre | `gap() = None` + forged coords + echo stub | **9/9** |
| M-STUB-empty-id | mint empty `request_id` | **8/9** (SESS-END failed) |
| M-STUB-reason-sub | reason contains the dimension word | **7/9** |
| M-STUB-allow-all | every use 200 | **4/9** (all four positive rows) |
| M-STUB-public-ok | Public use 200; other rows theatre | **7/9**; A5-PUB failed (good) |
| M-FORGE-TODAY | forged coords, `gap()` still Some | 0/9 BLOCKED (did not survive) |
| M-SKIP-NO-COORDS | `gap() = None`, no coords | 0/9 SKIPPED (did not survive) |

Untested by this harness, so they survive as gaps: `..` under an owned
root, symlink-shaped or renamed roots, `instance-1` vs `instance-1-evil`
as issued ids, grant-id prefix, and a Public read that actually returns
bytes.

Logs: `lab/review-a5-334/mutants/results/M-STUB-*.txt`.

## Six questions for Anders, checked on develop `92aeea44`

The questions are real open choices. Line numbers below are that develop
commit, `elastos/` prefix.

1. **Path layout.** Accurate. `docs/AGENT_ARCHITECTURE.md:341-343` does
   not freeze the layout under `UsersAI`. `UsersAI` is a file-backed
   owner-only root (`elastos/crates/elastos-common/src/localhost.rs:9-16,
   118`). The journal contract (spike
   `examples/agent-host/handoff/USERSAI-JOURNAL.md:23-24`) names
   `UsersAI/self`. A15 in #284 names `UsersAI/<agent>/notes`. #290 / this
   SPEC name `UsersAI/<identity>/<session>/<instance>`.
   `scope_current_user_alias` on develop still rewrites only `Users/self`
   and then `Ok(rooted)` (`elastos/crates/elastos-server/src/resource_bridge.rs:677-714`).
   `principal_localhost_root` still maps to `localhost://Users/<hash>`
   (`elastos/crates/elastos-server/src/auth.rs:7090-7092`). On the #334
   checkout those pins sat at `resource_bridge.rs:835` and `auth.rs:7039`.
   The text still holds; the lines moved.

2. **Public grants.** Accurate as a question. `lab/grant-binding` refuses
   a Public name at bind (`Refuse::PublicRead`, `src/lib.rs:91, 274-275`).
   Develop lists `Public` as a canonical root
   (`localhost.rs:14, 104`). Capability mint has no Public-as-bound-grant
   rule. The harness only refuses to count a Public allow; A5-PUB's live
   path forges a grant id.

3. **RA-1 route form.** Accurate. Develop serves plain
   `GET /api/capability/list` (`server.rs:247`) and
   `list_session_granted(&session_id)` (`capability.rs:425-434`). The
   string `all_sessions_live` is absent. #309 already records the two
   callers (plain list vs `?scope=all_sessions_live`). This harness uses
   the query form (`src/http.rs:393`).

4. **Session end.** Accurate. `invalidate_session` removes the session
   and emits `reason: "invalidated"`; it revokes no grant
   (`elastos/crates/elastos-runtime/src/session/registry.rs:113-135`).
   `validate` compares `token.capsule` to `caller_capsule_id`
   (`manager.rs:409-414`). There is no live-session check and no
   `/api/capability/requests` route. SPEC A5-SESS-END asks `settled_by`
   `runtime`; the journey does not read it.

5. **Token or handle.** Accurate. `CapabilityToken` has `capsule`,
   resource, action, constraints; no identity, session, or owned root
   (`token.rs:194-214`). `grant_request` comments "Use session ID as
   capsule ID for now" (`capability.rs:339-346`).
   `lab/bus-v2-proposal/CORE-CALLS-PROPOSAL.md:492` states there is no
   handle table and that `CapabilityGrant.id` is the token string. #463
   is named in `lab/grant-binding/README.md:12` as Runtime work. This
   harness never presents a handle.

6. **Whole-check / A4/A7.** Accurate as a process question. Anders
   already ordered A5 before A4/A7. Whether every row must PASS, or one
   combined journey is enough, is still open. The four positive rows here
   are not four journeys.

## Verdict

**FIX FIRST.**

Do not treat this folder as the A5 gate after RA-1/2/3/5/6 land. Today
the table is an honest BLOCKED list plus a double that proves the
harness's own ifs. The live path is a shell JSON theatre that a stub can
PASS.

## Fix list

1. Keep rows BLOCKED until a **guest** journey on a real operator
   measures the ask. Clearing `gap()` by deleting `Some(...)` is not a
   measurement.
2. Stop sending identity, session, and instance as client JSON. The
   guest presents a handle (or the host session of the instance). The
   host record decides.
3. Talk to routes that exist, or label new routes as asks. Today's
   `POST /api/capability/grant` wants `request_id`. `/api/capability/use`
   and `/api/sessions/{id}/end` are not on develop.
4. Reject empty grant ids. Match refusal reasons as whole tokens, not
   `contains("identity")` / `contains("instance")`.
5. Walk owned names the way `lab/grant-binding` does: no `..`, no
   symlink-shaped segment, no prefix `instance-1` / `instance-1-evil`,
   child only under the root plus `/`.
6. A5-PUB: read Public through the operator; do not hardcode
   `bound: false`; do not forge `public-claim`. Decide (Anders Q2)
   whether mint on `Public/` is refused.
7. A5-SESS-END: read `settled_by=runtime` from the request record. A
   403 whose reason contains `session` is not enough.
8. Fix `needs()`: A5-PUB lists RA-6 if it launches; storage rows list
   RA-1 if they call the live-grant view; drop RA-3 from A5-PUB unless
   the journey uses Home storage.
9. Make the four positive rows different. Identity must show bytes from
   A's root and a refusal for B. Session must show the session id on the
   host record. Instance must show two activations. Storage must show a
   child allowed and `..` / sibling refused, with A's object unchanged.
10. Add plants for: theatre stub 9/9, empty grant id, reason substring,
    hardcoded `public_read.bound = false`, and `gap()` cleared without a
    live guest.

## Next

Sasha and Anders treat #334 as a SPEC draft, not as the A5 gate. A later
lane rewrites the live adapter against the real grant and launch routes
and adds the plants above. This review PR stays draft.
