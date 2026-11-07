# How the guest gets its journal grant: options

**Decided 20 Oct: option B.** Sasha chose the `capabilities` import, reversing answer 3. The guest asks for exactly two grants, read and write, on its own journal; the manifest declares only `.AppData/Agents/<agent-id>/*`. Built on `claude/s3-guest-journal` (PR #9). The grant type is now `JournalGrant`.

Written 20 Oct 2026 for PR #9, questions 1 and 2. No code. Sasha decides.

## The problem in three lines

- The answer to PR #3 said: the Runtime gives the guest a grant at launch, and there is no `capabilities` import.
- But the guest has no way to receive one. `lifecycle.run` takes no argument, and `identity` and `runtime` return only fixed records (`elastos/wit/elastos-bus-v1.wit`).
- Resume also needs a **read** grant, because one token is one resource and one action (`CapabilityManager::grant`, `elastos-runtime/src/capability/manager.rs:309`).

## What exists today (checked in the code)

- `capabilities.request` is already in the WIT world and in the Runtime's allowed imports (`elastos-server/src/component.rs:6-12`). The component host already forwards it (`elastos-compute/src/providers/component.rs`, `capabilities::Host::request`).
- In the Runtime, a component's `request_capability` goes through the normal path (`resource_bridge.rs`, the `"request_capability"` arm):
  1. it scopes `Users/self` to the person;
  2. it checks the manifest bound;
  3. it creates a pending request with the reason, which emits a `CapabilityRequested` audit event (`elastos-runtime/src/capability/pending.rs:338`);
  4. it waits up to 30 s (300 × 100 ms) for the shell to grant or deny;
  5. it returns one token for one resource and one action.
- On Sasha's installed Home, the shell runs agent mode with `home-auto.json`, which allows `Users/*`. So a request for the journal path would be auto-granted there. Elsewhere it is an approval card.

## Options

| | A. WIT launch context | B. `capabilities` import | C. Host attaches the grant | D. Reuse `identity.session` |
| --- | --- | --- | --- | --- |
| Change | New WIT field or interface; every component capsule's `wit_world_sha256` changes (4 manifests plus `components.json`) | Guest adds one import and asks twice (write, read) for its one journal | Runtime mints two tokens at launch; component host adds them when the guest names its own journal with no grant | Put the token in `session` |
| Shipping code | WIT, bindgen, allowed imports, every capsule | None (Runtime path exists) | `runtime.rs` launch, `component.rs` invoke, a new rule | `component.rs` |
| Who decides the grant | Runtime at launch | Shell policy or a person, per request (audited) | Runtime at launch | Runtime at launch |
| Import list | identity, providers, runtime, types (+ new) | identity, **capabilities**, providers, runtime, types | identity, providers, runtime, types | unchanged |
| Changes earlier answers | "no WIT change" (the plan) | answer 3 ("no capabilities import") | answer 1 ("sent in invoke-request.grant") and the guest's no-grant rule | none on paper, but a token in a field named `session` |
| Principles | 10 one path: a second way to get a grant | 10: uses the one existing path; 7 humans and agents share it; 16 the card is not the grant, the Runtime is | 3: the host adds authority the guest did not name; a special case in `invoke` | 12 breaks: the docs say session, the code means grant |
| Size | Largest | Smallest | Medium | Small but wrong |

## My recommendation: B

- It is the only option with **no shipping Runtime change**. Every check already runs: the `Users/self` scoping, the manifest bound, the pending request, the shell decision, the audit event, and the one-resource-one-action token.
- The guest asks for exactly two tokens: `write` and `read` on `localhost://Users/self/.AppData/Agents/<agent-id>/tasks/<task-id>/journal`. A token for anything else is useless to it, because the bridge checks the token's resource on every call.
- It keeps the guest rules: a grant in memory, sent in `invoke-request.grant`, never journaled. Only where the grant comes from changes.
- Cost: the import list gains `capabilities`, which reverses answer 3. That is why this is your call.

If you prefer the plan's original shape (a grant at launch, no new import), **C** is next best, but it needs a launch-time mint in `runtime.rs`, the agent and task ids at launch (launch args), and a host rule in `component.rs` that adds a grant the guest did not send.

## If you pick B, the next slice is

1. Guest: `request_journal_grants(agent_id, task_id)` calls `capabilities.request` twice, then puts the results in two `LaunchGrant`s. A refusal means no grant, and nothing is sent (the existing guest tests cover that).
2. Wasmtime test: the expected import list adds `capabilities`. With no Runtime, the request gets `unavailable`, so the guest still sends nothing.
3. A Runtime test in `resource_bridge.rs`: a component request for the journal path in a test Runtime is granted, then a write with that token stores the journal. Another task's path is refused by the manifest bound or by the token check.
4. Falsifiers: drop the read request, so resume is denied; ask for the parent folder instead of the journal; send without asking.

## If you pick C, the next slice is

1. `runtime.rs`: at component launch, mint write and read tokens for the journal named by launch args, held host side only.
2. `component.rs`: when the guest invokes its own journal with no grant, attach the launch token. Every other resource keeps "requires a capability grant".
3. Guest: send `grant: None` for the journal only, which reverses the guest's no-grant rule for this one call.
4. Tests and falsifiers: another resource with no grant is still denied; a token never reaches the guest.
