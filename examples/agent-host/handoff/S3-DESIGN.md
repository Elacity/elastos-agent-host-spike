# S3 design: the Runtime stores the journal

Written 20 Oct 2026 (overnight 1, item 4). No code in this item. S3 itself starts only after Sasha says yes (HANDOFF section 8) and after the open security finding at the end is answered.

Goal (HANDOFF S3): the guest proposes a journal append. The Runtime checks the grant and writes the S2 bytes (`USERSAI-JOURNAL.md`) through Runtime storage as a compare-and-swap. The guest never sees a host path.

Every line reference below is at branch `claude/overnight-1`, checked by reading the code. Paths start at the repo root.

## 1. What the code does today

### 1a. The component host's `invoke` path

- **WIT.** `elastos/wit/elastos-bus-v1.wit`:
  - `invoke-request { resource, operation, body: list<u8>, grant: option<grant-id> }` (lines 37-42)
  - `bus-error` = denied | not-found | invalid | unavailable | timeout | internal (lines 50-57)
  - `providers.invoke` (lines 78-82)
  - The world `product-capsule-v1` (lines 91-97) offers `providers` and `capabilities`, but the guest imports neither today.
- **Host.** `elastos/crates/elastos-compute/src/providers/component.rs`:
  - `fn invoke` (lines 384-421) returns `Denied("resource invoke requires a capability grant")` for a missing or empty grant before it touches the bridge (lines 389-393).
  - It parses the body as JSON (`json_body`, lines 294-303).
  - It sends a `ResourceInvoke` envelope. The grant becomes the envelope's `token`.
  - `call_bridge` (lines 306-324) passes `(line, capsule_id, principal_id)` to the hostcall.
  - `bus_error` (lines 268-282) maps `missing_token`, `invalid_token` and `capability_denied` to `Denied`. Any other code becomes `Internal`.
- **Principal.** `ComponentState { hostcall, capsule_id, principal_id, limits }` (lines 38-43). `set_bridge_principal` (lines 69-74) is called by `elastos/crates/elastos-server/src/runtime.rs:304-310` before start and cleared after (lines 315-317).
- **Proof today.** `provider_invoke_without_a_grant_is_denied_before_the_bridge` (`component.rs:541`).

### 1b. How a grant reaches it

- **In-Runtime hostcall.** `Runtime::set_provider_registry` (`runtime.rs:98-140`) installs a closure that calls `resource_bridge::handle_component_resource_request` (`elastos/crates/elastos-server/src/resource_bridge.rs:738`).
- **Order of checks** in `authorize_and_dispatch_resource_invoke` (`resource_bridge.rs:333-456`):
  1. `resource_invoke_dispatch` (line 183) scopes `Users/self` and drops a token found in the body.
  2. `manifest_allows_resource` (line 253): the capsule manifest's upper bound.
  3. An empty token gives `missing_token` (line 371).
  4. An unparsable token gives `invalid_token` (line 385).
  5. `capability_manager.validate(token, capsule_id, action, resource)`; failure gives `capability_denied` (line 407).
  6. Then dispatch to protected principal-root storage, or to the provider registry.
- **Attached Runtime.** `Runtime::set_bridge_hostcall` (`runtime.rs:145`) is used by `elastos run` (`run_cmd.rs:243-260`). It refuses principal-root storage outright: `principal_context_required` (`resource_bridge.rs:1075-1083`).
- **Token minting.** One resource and one action per token: `CapabilityManager::grant` and `validate` (`elastos/crates/elastos-runtime/src/capability/manager.rs`, about lines 309-505; read by a helper, spot-checked by me only at the call site).
- **Proofs today:**
  - `resource_invoke_localhost_rejects_missing_envelope_token_even_with_body_token` (`resource_bridge.rs:2398`, asserts `missing_token` at line 2423)
  - `resource_invoke_dispatch_rejects_foreign_principal_root` (line 1633)

### 1c. Object versions and compare-and-swap

- **Atomic, the one to use:** `write_principal_root_object_if_revision` (`elastos/crates/elastos-server/src/auth.rs:5632`).
  - Preconditions are `Absent` or `Revision(..)` (lines 5602-5605). A conflict is `PrincipalRootObjectWriteConflict`, "principal-root object write precondition failed" (lines 5607-5614).
  - The revision is `"hex(sha256(principal \0 uri \0 plaintext))"` (`principal_root_object_revision`, lines 5618-5630).
  - It is checked under `principal_root_object_mutation_lock` (line 355).
  - It accepts only roots under `localhost://Users/` (lines 7081-7083).
- **Not atomic, do not use:** library `Write { if_revision }` runs `check_revision` (`library.rs:3704`, function at 6646-6660) before the locked write (line 3718). A blank `if_revision` skips the check (lines 6652-6654).
- **Pattern to copy:** Assistant workspace v2 (`api/gateway_assistant_workspace_v2.rs`) uses a `u64 revision`, `if_revision`, one global mutation lock (lines 37-42), conflict code `assistant_workspace_revision_conflict` (line 13), and an 8 MiB cap (line 8).

### 1d. How `UsersAI` is named and owned today

- `UsersAI` is a file-backed, owner-only root (`elastos/crates/elastos-common/src/localhost.rs:9-30`, line 118).
- **No principal mapping.**
  - `principal_localhost_root` always gives `localhost://Users/<hex(sha256(principal)[..12])>` (`auth.rs:7036-7039`).
  - `scope_current_user_alias` (`resource_bridge.rs:671-709`) rewrites and checks `Users/...`, but returns any other rooted path unchanged, so `UsersAI/<anything>` passes through (line 708).
  - `principal_root_read_write_uri` matches only `localhost://Users/`.
- So a `UsersAI` request goes to the generic localhost provider. Its `validate_token` is a placeholder that returns `Ok(())` (`elastos/capsules/localhost-provider/src/main.rs:394-400`). The only gates are the manifest bound and the token's resource pattern.
- There are no tests for `UsersAI` ownership.

### 1e. Where `settlement_unknown` already exists

- **Model runs only.**
  - `RunStatus::SettlementUnknown` and `ErrorClass::SettlementUnknown` (`capsules/model-provider/src/contract.rs:127, 134, 153`)
  - The Runtime's run index: "settlement_unknown when this Runtime never saw the run settle" (`api/gateway_model_service.rs`, about line 141)
  - Test: `prepared_run_becomes_settlement_unknown_after_restart` (model-provider `state.rs`, about line 3210; read by a helper)
- **In the guest:** `StepState::SettlementUnknown` (`examples/agent-host/src/lib.rs`, `note_crash`)
- Nothing in storage uses it yet.

### 1f. Size limits on the path

- A Runtime resource frame is at most 1 MiB (`resource_bridge.rs:32`), checked on the envelope line.
- The S2 journal cap is 256 KiB, which is about 342 KiB in base64, so it fits.
- Wasmtime: 128 MiB memory and 100 M fuel (`component.rs:28-29`).

## 2. Proposed design (smallest diff)

**Changes from the PR #3 review (20 Oct). These win over the list below.**

- **Where the journal lives (answer 1).** `localhost://Users/self/.AppData/Agents/<agent-id>/tasks/<task-id>/journal`. The bridge already scopes `Users/self` to the launching principal (`resource_bridge.rs:671-709`), and the atomic compare-and-swap already accepts `Users/` roots (`auth.rs:7081`). So items 3 and 4 below need no new scoping rule. **The journal moves to `UsersAI` once the Runtime scopes `UsersAI`** the way it scopes `Users/self`.
- **Owner (answer 2).** The launching person principal owns the journal. `<agent-id>` is a name under that person's space: ASCII letters, digits and `-`, at most 64 bytes. No new principal type in the spike.
- **Grant (answer 3).** The Runtime gives the guest a grant at launch, scoped to that one journal path and the write action. No `capabilities` import.
- **Writes.** Only through `write_principal_root_object_if_revision`. Never the library `Write` path, whose revision check is not atomic (section 1c).
- **Round trip (answer 4).** `decode(encode(j)) == without_grants(j)` is confirmed.
- **Open: the import list.** Answer 3 also says the import list stays identity, runtime, types. But those three interfaces offer only `runtime.info()` and `identity.context()` (`elastos/wit/elastos-bus-v1.wit:63-73`). With them, the guest has no call that can hand bytes to the Runtime. Proposing an append needs `elastos:bus/providers@1.0.0` (item 1 below, and HANDOFF S3), or a WIT change, which the plan forbids. See question 5.

1. **Imports (a security change, needs the adversarial review).** The guest adds `elastos:bus/providers@1.0.0`, and `elastos:bus/capabilities@1.0.0` only if the guest must ask for its own grant. The ignored Wasmtime test's expected list changes in the same commit.
2. **Guest.**
   - A new step kind, `ProposalKind::JournalAppend`.
   - `propose_journal_append(journal, task_id, seen_revision)` records a Prepared step whose resource is `localhost://UsersAI/self/.AppData/ElastOS/AgentHost/tasks/<task-id>/journal`. The task id is ASCII letters, digits and `-`, at most 64 bytes.
   - The body is JSON `{ "data": base64(encode_journal(j, prev_head)), "if_revision": seen_revision | null }`.
   - Dispatch calls `providers.invoke` with operation `journal_append` and the Runtime's grant.
   - Existing rules stay: dispatch only with a grant (now pinned by G1), cancel before dispatch, and crash after dispatch is `SettlementUnknown`, with no second dispatch.
3. **Runtime scoping.**
   - In `scope_current_user_alias`, add the `UsersAI` twin of the `Users` rule. `UsersAI/self` becomes the agent principal's root `localhost://UsersAI/<hex(sha256(agent principal)[..12])>`.
   - Any other `UsersAI/<root>` is refused, so another principal's journal is refused before the token check.
   - The resource must be rooted (`rooted_localhost_uri`) and free of `..`. The guest already refuses host paths with `host_path`.
4. **Runtime storage.**
   - A `journal_append` operation in the in-Runtime protected-storage branch. It does not go to the localhost provider.
   - It decodes base64 and refuses more than 256 KiB.
   - It calls the S2 `decode_journal` logic, or a Runtime copy of it, so it never stores bytes it cannot read back.
   - It writes with `write_principal_root_object_if_revision`, widened to accept the agent's `UsersAI` root: `Absent` for the first append, `Revision(seen)` after that.
   - A conflict returns a typed `journal_revision_conflict` mapped to `Invalid`, not `Internal`.
   - The response returns the new revision.
   - The attached Runtime (`elastos run`) keeps refusing it with `principal_context_required`.
5. **Resume.** Read back the object. If its head hash equals the guest's last head, the append settled. If it equals the parent, the append did not happen; propose again with a new step. If it is anything else, the state is `settlement_unknown` until a person decides.

## 3. Tests (from HANDOFF S3, plus where to model each)

- `journal_append_without_a_grant_is_denied_before_the_provider`: like `component.rs:541` and `resource_bridge.rs:2398`. The provider sees no request.
- `a_stale_journal_revision_is_refused_and_nothing_is_written`: like the workspace v2 conflict test (`gateway_tests/assistant_workspace_v2.rs`, about line 237).
- `a_crash_between_append_and_result_is_settlement_unknown_and_not_retried`: the guest step state after `note_crash`; the Runtime gets no second invoke.
- `resume_reads_back_the_same_bytes`: the stored bytes decode to the journal that was sent (S2 round trip).
- `another_principals_journal_is_refused`: like `resource_invoke_dispatch_rejects_foreign_principal_root` (`resource_bridge.rs:1633`), but for `UsersAI`.
- Import list: the ignored Wasmtime test expects the new list. Removing `providers` from the guest fails it.

## 4. Attack list (each needs a test and a falsifier)

| Attack | Where it must stop | Expected result |
| --- | --- | --- |
| Another principal's journal: `UsersAI/<other>/...` | `scope_current_user_alias` (new UsersAI rule) | refused before the token check, no provider call |
| A replayed old version: an old revision as `if_revision`, or an old encoding | compare-and-swap under the lock; `prev_head` mismatch | `journal_revision_conflict`, nothing written |
| A grant for a different resource or action (for example a read token, or another task's journal) | `capability_manager.validate` on the scoped resource and the write action | `capability_denied` |
| A crash between the write and the result | guest `note_crash` after dispatch | `SettlementUnknown`, no second dispatch; resume uses the head hash |
| An oversized append: more than 256 KiB decoded, or more than 1 MiB frame | guest `encode_journal`; Runtime decode; `MAX_RESOURCE_FRAME_BYTES` | refused, nothing written |
| A host path or `..` in the resource | guest `host_path`; Runtime `rooted_localhost_uri` | refused, no step, no provider call |
| Bytes that are re-linked but malformed | Runtime decode (S2 canonical checks) | refused, nothing written |
| An attached Runtime trying to write | `resource_bridge.rs:1075-1083` | `principal_context_required` |

## 5. Open questions for Sasha (S3 must not start until they are answered)

1. **Security finding, details for Sasha.** Two things in shipping code, not spike code. Today they matter only for paths under `UsersAI` and for capability approval, but S3 would build on both.
   - (a) `UsersAI` paths are not scoped to a principal anywhere in the Runtime. The shell capsule's agent mode, with no policy file, auto-allows `localhost://UsersAI/*` (`elastos/capsules/shell/src/main.rs:227-240`).
   - (b) Two Runtime launch paths default the shell's decision mode to `auto` when `ELASTOS_SHELL_MODE` is unset (`elastos/crates/elastos-server/src/main.rs:1912`, `serve_cmd.rs:333`). The managed path sets `agent` (`runtime_control.rs:1320`).
   I did not test what either means on an installed Home. Please decide whether this goes to the team, and whether S3 waits for it.
   Note added after review: `UsersAI` is `0700` on disk, so only the operating-system owner can read it (`localhost.rs:118-136`). But the Runtime has no principal mapping for it like `Users/self`.
   **Answer (20 Oct):** on Sasha's Mac the installed Home runs the shell in agent mode with policy `home-auto.json`. That allows peer, did, `Users/*` and one shared Home folder. No `UsersAI`, no auto-grant, so this is not live today. Sasha raises it with the team privately. S3 does not wait: the journal goes under `Users/self` (section 2).
2. **Which principal owns the journal?** `docs/AGENT_ARCHITECTURE.md` says the agent principal. Today only `person:` and `device:` principals exist, and the bridge principal is the launching person. S3 needs a rule for the agent principal id, and who may create one.
3. **Does the guest ask for its own grant (`capabilities` import), or does the Runtime hand it one at launch?** The first adds a second import and an approval card. The second needs a launch-time grant scoped to one task journal.
4. **Confirm the S2 choice** that grant strings are not stored in the journal.

Answers (20 Oct): 2, the launching person principal; 3, a grant at launch, no `capabilities` import; 4, confirmed.

5. **(new, open)** Answer 3 keeps the import list at identity, runtime, types, but the guest needs `providers.invoke` to propose an append (section 2, "Open: the import list"). Is adding `elastos:bus/providers@1.0.0` allowed for S3, with the adversarial review HANDOFF S3 already asks for?
