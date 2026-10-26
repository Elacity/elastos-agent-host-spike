# Runtime asks that keep A15 rows BLOCKED

This file is the A15 half of the Runtime work. It changes no ElastOS source.
Draft PR #309 (`lab/runtime-asks/`) holds the same two asks as RA-4 and RA-5
for Anders after 0.8.0. This copy stays with the lab so a reader of #284 can
see why a row is BLOCKED or NEEDS RUNTIME.

A15 stays open until a stored journal is asserted and the notes read is a
live probe. Lab evidence for a library call stays evidence.

## RA-4 Protected storage bridge entry

**Why A15 needs it.** The Host sends an approved journal write through
`handle_remote_request_with_audit_dir`. That public entry refuses a
principal-root write with `principal_context_required` /
`principal-root storage requires an in-runtime protected storage bridge`
before it validates the token. `handle_component_resource_request` is the
in-runtime store, and it is `pub(crate)`.

**Rows that stay BLOCKED until this lands.**

- Altered journal resource on the public bus entry (today the storage
  refusal wins; the lab `CapabilityManager` already returns `wrong resource`).
- Second use on the public bus entry (today the storage refusal wins; the lab
  manager already returns `use limit exceeded`).
- Approved journal write stored (nothing is stored).

**Smallest Runtime change.** Make the in-runtime entry reachable for this
journey, with a principal the Runtime verified, and with principal-root
protection active. Form and review class are in #309
`lab/runtime-asks/04-protected-storage-bridge-entry.md`.

**Lab signal today.** `public_bridge_blocks_journal_storage_before_token_checks`
and `approved_plan_records_blocked_in_process_bridge_effects` assert the
BLOCKED text. After RA-4 they fail. Replace them with a stored journal, a
`wrong resource` on the bridge, and `use limit exceeded` on the bridge.

## RA-5 `UsersAI` alias

**Why A15 needs it.** Step 1 reads `localhost://UsersAI/ada/notes`.
`scope_current_user_alias` leaves a `UsersAI` path unchanged.
`runtime_gap` records BLOCKED without a bus call.

**Row that stays BLOCKED (STATIC) until this lands.** Notes read.

**Smallest Runtime change.** Resolve `UsersAI/self` to the verified agent
principal's root, as `Users/self` already resolves for a person. Refuse
another agent's `UsersAI` root. The path layout is not frozen
(`docs/AGENT_ARCHITECTURE.md`). Details are in #309
`lab/runtime-asks/05-usersai-principal-root-alias.md`.

**Lab signal today.** The notes step is STATIC. When RA-5 lands, nothing in
this crate turns red until the lab adds a live notes probe. That probe is
not written.

## Spawned `elastos` process over the bus

**Class: NEEDS RUNTIME.**

This lab links `elastos-server` and calls
`handle_remote_request_with_audit_dir` in-process. It does not build or
spawn the `elastos` binary from this checkout. A cold workspace build of
that binary is a Runtime-tree job. Even after a spawn, the public entry
still refuses principal-root storage (RA-4), so the write would stay
BLOCKED.

The row that would count: start `elastos` from this checkout, send the
approved journal write over that process's bus, and assert a stored
journal (or a named BLOCKED reason from that process). That row is not in
this crate.
