# Human and agent architecture

This document defines how human and AI actors fit the same ElastOS authority
model. It is an architecture contract, not a claim that the complete agent
product is implemented. [GitHub issues](https://github.com/elastos/elastos-runtime/issues) own implementation status and proof.

The governing rule is:

> Humans and agents use the same Runtime resources, capability checks, session
> boundaries, and audit path. They may use different proofs and interaction
> flows, but neither receives ambient authority.

This follows [Principle 7](../PRINCIPLES.md#7-humans-and-agents-share-one-authority-model),
[Principle 13](../PRINCIPLES.md#13-objects-capsules-and-spaces-must-stay-distinct),
and [Principle 18](../PRINCIPLES.md#18-executable-capsules-are-isolated-execution-environments).

## Decision summary

- A human and an agent are both represented by Runtime principals.
- In the current collaboration model, a human's portable product identity is a
  signed Profile document with a stable Profile DID, controlled from a
  principal-owned protected `ProfileAuthority` bundle.
- A Profile is signed principal-owned data. It is not normally a capsule.
- Executable agent software is a capsule, separate from the agent principal
  and profile.
- A capsule instance acts only in the context of its capsule identity,
  principal, session, granted capabilities, resources, and lifecycle.
- A model or harness may propose an effect. Runtime alone authorizes and routes
  that effect.
- Human approval and agent delegation must resolve to the same underlying
  capability-scoped provider operation.
- A Profile may be exported as a signed data package, but importing or viewing
  it does not grant authority.

## Terms and ownership

In this document, **Profile** means the canonical signed public identity
document. It does not mean an installation profile selected by `elastos setup`,
a Browser profile disk, an execution profile, or a container for private agent
configuration. A future agent identity document and private agent persona state
are target architecture and remain separate objects.

| Concept | Meaning | Owner | What it is not |
| --- | --- | --- | --- |
| Principal | Runtime authority subject representing a human, agent, device, capsule, or provider | Runtime | A display name, passkey, DID, or capsule package |
| ProfileAuthority | Protected principal-root bundle containing the Profile signing secret, current signed public Profile, and retained revisions | Runtime-owned principal state | A public document, App, or ambient signing service |
| Profile | Signed public identity document containing a stable Profile DID, display data, monotonic revision, previous-profile hash, and authorized delivery-device bindings | Principal through ProfileAuthority | The local principal, passkey, device DID, or executable code |
| Profile DID | Stable person/contact identity named by signed People, discovery, contacts, and conversations | Signed Profile document | A local authorization principal or transport endpoint |
| Proof binding | Evidence accepted by Runtime as control of a principal, such as a human passkey or an agent proof | Runtime identity boundary | The principal itself |
| Session | Short-lived active context binding a principal, proof, lifecycle, and permitted operations | Runtime | A durable identity or profile |
| Capsule artifact | Immutable signed software or packaged-data artifact | Publisher and Runtime admission policy | A running agent or human account |
| Capsule instance | One isolated activation of a capsule under a session and capability set | Runtime lifecycle | The principal that uses it |
| Capability grant | Narrow Runtime authority over a resource, action, and operation | Runtime | A UI state, route, profile field, or model suggestion |
| Mandate (target) | Higher-level delegated policy that may constrain duration, scope, rate, or budget before Runtime grants an operation | Consent or mandate service; enforced by Runtime capabilities | Identity or ambient access |
| Agent private state (target) | Persona, model policy, memory roots, and selected skills or Apps | Agent principal through typed Runtime resources | A public Profile, signing authority, or executable capsule |

The canonical definition of a principal is in the
[Glossary](GLOSSARY.md#principal). Wallet addresses, passkeys, and DIDs are
proof bindings or linked identities; they do not replace the Runtime
principal. The current collaboration contract further distinguishes the local
principal from the signed [Profile DID](GLOSSARY.md#profile-did) that other
people name.

## Human and agent parity

Parity means equal enforcement, not identical embodiment.

| Concern | Human | Agent |
| --- | --- | --- |
| Authority subject | Human principal | Agent principal |
| Rooted state | `Users/...` | `UsersAI/...` |
| Typical proof | Passkey-backed session | Agent key or another Runtime-accepted proof |
| Product identity | Signed Profile DID | Verified agent identity document; target, not currently shipped |
| Identity authority and document | Protected ProfileAuthority and signed public Profile | Protected authority and signed agent identity document; target, not currently shipped |
| Private preferences and memory | Principal-owned application state | Principal-owned persona, model policy, memory, and skill selection |
| Executable actor | Home or another app capsule | Agent Host or task capsule |
| Immediate authority | Interactive approval or existing grant | Existing grant or interactive approval |
| Standing authority | Explicit user-configured policy | Explicit mandate scoped to the agent |
| Effects | Typed Runtime resources and providers | The same typed Runtime resources and providers |
| Audit | Runtime audit | Runtime audit |

The parallel shape is:

```text
Human principal                         Agent principal
  +-- protected ProfileAuthority          +-- signed agent identity (target)
  +-- signed public Profile DID           +-- private persona/model state
  +-- passkey proof                       +-- agent proof binding
  +-- active session                      +-- active session
  +-- Home/app capsule instance           +-- Agent Host capsule instance
             |                                        |
             +--------------+  +----------------------+
                            v  v
                   Runtime capability check
                            |
                            v
                    provider operation
                            |
                            v
                      audited result
```

The pointer, keyboard, API, and agent-message paths may begin differently, but
they must converge before the effect occurs. If a person and an agent request
the same operation on the same resource, Runtime must evaluate both through
the same authority and provider boundary.

Automation is therefore not a privileged bypass. It is the same operation with
more explicit delegation, expiry, revocation, and accounting.

## Why a profile is not normally a capsule

A Profile is a signed public identity object, and its protected
ProfileAuthority changes independently of executable software. The current
Profile schema contains display data, revision history, and explicit delivery
endpoint and application-signer bindings. ProfileAuthority contains the signing
secret, current signed head, and retained signed revisions.

Private preferences, persona, model policy, memory roots, and selected skills or
Apps belong in separate principal-owned objects. They may influence how an agent
acts, but they are not public identity fields and must not expand
ProfileAuthority into a general private-state bundle. A later Profile schema may
add explicitly public presentation or credential fields through a reviewed
versioned contract.

Making that live object an executable capsule would collapse four boundaries:

1. **Identity and code.** Changing public display data or private preferences
   should not replace the executable agent package.
2. **Mutable and immutable state.** Profile updates should not require a new
   capsule artifact and signature.
3. **Principal and actor.** Authority belongs to the principal and session,
   not to whichever profile viewer happens to be open.
4. **Shared implementation and individual identity.** Many principals should
   be able to use the same admitted Home, People/Profile App, or Agent Host
   capsule while retaining separate state and authority.

The current product uses the `people` App capsule as the Profile and contacts
surface, backed by Runtime-owned ProfileAuthority. A future dedicated Profile
App may also be a capsule. In either case, the capsule only views or requests
edits to Profile objects through Runtime-mediated operations. It does not
become the Profile, hold the Profile signing secret, or inherit the principal's
authority from being displayed in Home.

A Profile snapshot may later be packaged as a signed data capsule when
portability or provenance requires it. That packaging is optional target
architecture, not a current implementation claim. The exported artifact must
not become a bearer credential, and installing it must not silently recreate
sessions, capabilities, or mandates.

## Agent composition

An ElastOS agent is a composition rather than one package:

```text
agent principal
  +-- signed agent identity document (target)
  +-- private persona and model policy
  +-- principal-owned memory and conversation state
  +-- proof binding
  +-- selected Agent Host capsule
  +-- active sessions
  +-- capability grants and mandates
```

The **Agent Host capsule** owns ordinary harness behavior such as conversation
state, context construction, model selection, planning, compaction, and
interpreting model tool requests. Different harness implementations may fill
this role without changing the Runtime authority model.

The Agent Host is not trusted to authorize its own effects. It starts without
ambient filesystem, network, wallet, provider-credential, or control
authority. Every external effect crosses a typed Runtime resource.

One admitted Agent Host artifact may serve many agent principals. Each running
instance must be bound independently to its agent principal, session, state,
capabilities, resources, and lifecycle. Updating the harness must not rewrite
the agent's public identity, private persona, or memory.

## One live run

One Home process: one agent has one live run. A second `elastos serve` or `elastos gateway` on that data root is refused by the exclusive host lock (`elastos/crates/elastos-server/src/host_lock.rs:120`, called from `serve_cmd.rs:46` and `gateway_cmd.rs:71`). A process started with `ELASTOS_ALLOW_SUBORDINATE_RUNTIME_HOST=1` does not take that lock (`serve_cmd.rs:39`).

The gateway sets that variable on a managed child (`runtime_control.rs:1497`). `require_home_runtime` (`agent_admission.rs:65`) admits an agent launch only when the sign-in store is this process's data folder (`agent_admission.rs:66`, called from `agent_admission.rs:192`). The managed child's sign-in store is the parent data folder (`runtime_control.rs:1504`, read at `gateway_home_token.rs:1787`) and its data folder is the nested home (`runtime_control.rs:1510`), so the child does not start agents.

A hand-started subordinate host on the Home's own root keeps running. Its live-run token is its own. The journal revision lock is also its own (`auth.rs:495`, one mutex in the process at `auth.rs:446`). That host can hold a live run of an agent the first process also holds, and each process can write the journal.

A second Start while that run is live is refused, and the refusal says "this agent is already running", including when that Start presents the same grant. A Start while a Stop still holds its token is refused, and the refusal says "this agent is stopping". A Stop that has not finished answers "stopping" (`routes.rs:580`) and leaves the run live.

The run ends when that Stop finishes, when the guest fails, when the guest crashes, when that run is cancelled, or when the Home process starts again, and a later Start can then begin. An effect already in flight keeps the live-run token after that end is decided. A later Start stays refused until that effect is settled or its record is unknown, and is then allowed. When an end cannot run (`OwedEnd::Lost`, `runtime.rs:969`), the live-run token is released while the registry row may still show the run as live.

Retire refuses a later Start because the agent is retired. The launch answers "the caller owns no agent with that id" (`a_retired_or_unknown_agent_refuses_its_launch`).

Two different agents may run at the same time, and two Starts of one agent at the same moment produce one run.

A journal under `.AppData/Agents` is written as a whole object. The write carries `create_only` when the object is new, or `if_revision` with the revision last read. Append is refused (`an_append_to_a_journal_is_refused`, `resource_bridge.rs:1441`). An ended run cannot write that journal: its manifest ceiling is gone, so the bridge answers `manifest_capability_denied` (`an_ended_run_cannot_write_after_the_next_run_starts`). A write whose revision is not the stored revision is a `revision_conflict`, the second check (`auth.rs:7626`). Journals keep the revision check. An ended run's plan step that was claimed before the end may still write (`resource_bridge.rs:477`). Outside `.AppData/Agents`, on a protected root, a plain write replaces an existing file and an append of a file that is not there creates it (`resource_bridge.rs:1476`); an append extends a file that is already there (`resource_bridge.rs:1468`). On a root with no principal-root protection, a plain write or an append is handled by the provider (`resource_bridge.rs:1387`). One live run does not change those writes.

## Runtime and provider architecture

The minimal agent path on ElastOS is:

```text
Home
  | start, resume, cancel, or present approval
  v
Runtime
  | bind principal, proof, session, capsule, grants, and lifecycle
  v
Agent Host capsule
  | harness, context, conversation, and planning
  |
  +-- model request --> Runtime --> model provider --> configured backend
  |
  +-- proposed effect --> Runtime capability check --> owning provider
                                                        |
                                                        v
                                                   audited result
```

The boundaries are:

- **Home** presents sessions, activity, approvals, results, and receipts. A UI
  card is not an authority grant.
- **Runtime** verifies the principal and session, enforces capabilities, owns
  lifecycle and audit, and routes the operation.
- **Agent Host** owns agent-loop behavior but cannot mint authority.
- **Runtime** stores hosted model credentials and brokers exact approved HTTPS
  destinations. **Model provider** owns protocol adaptation, model
  availability, and inference semantics. The Agent Host does not receive
  upstream credentials or endpoints.
- **Effect providers** own operation semantics for resources such as content,
  messaging, Browser, wallet, chain, rights, or storage. They do not decide
  that an unverified caller is authorized.
- **Carrier** may transport an off-box operation selected by Runtime. It is not
  the agent API or authority system.

## Request flow

A conforming agent action follows this sequence:

1. Home asks Runtime to start or resume an agent session.
2. Runtime resolves and binds the human principal, agent principal, proof,
   Agent Host capsule identity, session, and launch authority.
3. Runtime launches the isolated Agent Host instance with only its initial
   scoped resources.
4. The Agent Host requests inference through the model provider.
5. The model may return text or propose a typed operation. A proposal carries
   no authority.
6. The Agent Host submits the proposed operation to Runtime as the active agent
   principal and session.
7. Runtime verifies the exact resource, action, operation, principal, session,
   capsule, grant, expiry, and revocation state.
8. If additional consent is required, Runtime records a pending request and
   Home or Inbox presents it. The UI does not mint the grant itself.
9. Runtime dispatches an approved operation to the owning provider and records
   the result in the same audit path used for a human action.
10. The result returns to the Agent Host and Home without exposing provider
    credentials or broader authority.

## Session and interaction contract

An agent task is durable Runtime-owned state, not a short-lived Runtime session
or the lifetime of one terminal, web page, model stream, or Agent Host process.
It has a stable task ID and may span renewed session IDs. Model requests,
proposed effects, approvals, effect settlement, and presentation events record
both the task and the session that authorized them.

The minimum lifecycle is:

```text
created -> running -> completed
                   -> failed
                   -> cancelled
                   -> interrupted -> resumable -> running
        -> waiting_for_approval -> running
                                -> cancelled
                                -> interrupted -> resumable
```

`interrupted` means execution stopped before the system could establish a
terminal result. `resumable` means Runtime has enough durable state to continue
without recreating already settled work. A UI disconnect does not change the
task state by itself.

The interaction contract requires:

- one durable identity for the task, session, model request, approval request,
  and external effect;
- visible current state, progress, selected provider and model, and last durable
  event;
- an explicit interrupt or cancel operation that reports its settlement;
- approval requests that remain pending across UI, Agent Host, or Runtime
  restart until approved, denied, expired, revoked, or cancelled;
- resume from the last durable event after UI, Agent Host, or Runtime restart;
- one terminal state for every model request and external effect;
- deduplication by effect ID so presentation recovery cannot repeat a settled
  operation; and
- an explicit unknown-settlement state when Runtime cannot prove whether a
  remote or provider effect completed.

The UI must not remain in `responding` after the model provider has emitted a
terminal event. It must also not hide an approval because the view changed or a
stream disconnected. Reconnecting presentation reads durable state; it does
not rerun inference or submit the proposed effect again.

The [model provider contract](MODEL_PROVIDER.md) defines inference selection,
stream events, cancellation, and terminal outcomes. Provider-specific stream
formats remain behind that boundary.

## Harness conformance

Agent Host implementations may differ in prompts, context policy, planning,
memory, compaction, subtask execution, and user experience. To fit ElastOS,
each harness must:

- run as an admitted capsule instance without ambient filesystem, network,
  wallet, provider-credential, or control authority;
- bind every model request and effect proposal to the active agent principal,
  Runtime session, and durable task;
- use typed Runtime resources instead of direct host tools or provider
  endpoints;
- treat model output and tool calls as untrusted proposals;
- preserve cancellation and durable correlation IDs across its internal loop;
- keep private persona, memory, and conversation state in principal-owned
  resources; and
- accept Runtime denial, expiry, revocation, and unknown settlement as
  authoritative outcomes.

These constraints allow a harness to be replaced without creating another
authority system or changing the agent's identity.

## Delegation and mandates

Interactive and automated authority should differ only in delegation scope:

- **Allow once** authorizes one exact operation.
- **Allow for this session** authorizes a bounded operation set until the
  session ends or the grant is revoked.
- **Standing mandate** delegates a bounded operation set to an agent principal
  with explicit scope, expiry, revocation, and optional rate or spend limits.

A mandate is policy above the Runtime capability primitive. Runtime remains the
enforcement point for every resulting effect. A mandate service must not hand
the agent a user's unrestricted credentials or create a second authority
system beside Runtime.

## State ownership

- Human state is rooted under the human principal's `Users/...` space.
- Agent state is rooted under the agent principal's `UsersAI/...` space.
- Public Profile documents and private memory, conversation, and task state are
  mutable objects, separate from immutable capsule artifacts.
- Model credentials and provider topology remain provider-owned state.
- Runtime owns sessions, grants, revocation, lifecycle, and authoritative
  audit records.
- A public profile projection exposes only fields the principal explicitly
  publishes; a route or visible page does not grant access to private state.

### Agent storage protection

The wrap key seals an agent's data key. Runtime derives that wrap key from
the owner's data key. The derivation inputs are the owner, the agent id, and
the agent's root. The same derivation binds the agent's data key id.
`a_new_agent_protection_opens_under_its_own_derived_key_only` shows that a
key derived for another id, another root, or another data key id does not
open the wrap. A rename keeps the agent id, the root, and the wrap, and
changes the display name. Opening the same Home again reads that same
record, and the stored note opens under the same wrap. Owner recovery on
the same Home, with the same owner key, reopens every agent of that owner.
Another person's agents stay closed to the recovered owner, and those agents
still open for their own owner.

These limits are part of the property:

- A new Home has no agents.
- Storing a replaced protection does not re-wrap. A replaced owner data key
  makes existing agent data unopenable on this Home. The row covers an active
  agent and a retired agent.
- A replaced, rolled-back or deleted agent file is not detected on load yet.
- The sealed file holds none of the object's content in plaintext. This
  protection makes no claim against a process of the same operating-system
  user outside the agent's sandbox.

`the_wrap_key_binds_each_input`, `the_wrap_key_binds_the_owner_id`, and
`the_wrap_key_is_the_owners_alone` show the wrap key's inputs.
`a_new_agent_protection_opens_under_its_own_derived_key_only` is named in
the paragraph above. `rename_changes_display_name_only` shows a
rename leaves the wrap in place. `stable_id_after_rename_and_reopen` shows
the id, the root, and the note after a rename and a reopen.
`owner_recovery_reopens_agent_data` shows one agent's note after recovery on
this Home with the same owner key.
`owner_recovery_reopens_every_agents_data_and_no_other_persons` shows every
agent of that owner, and the other person's agent.
`a_missing_file_means_no_agents` shows a new Home has no agents.
`a_replaced_owner_data_key_does_not_rewrap_agent_data` shows that storing a
replaced protection does not re-wrap, and that the replaced key leaves an
active agent's data and a retired agent's data unopenable on this Home.
`the_sealed_file_holds_none_of_the_objects_content_in_plaintext` shows the
sealed file holds none of the object's content in plaintext. The doc comment
on `the_wrap_key_binds_each_input` names the same tests.

### Instance access to agent storage

Each running instance gets fresh, limited access to its agent's storage, and
that access ends when the instance stops. A step whose dispatch hasn't reached
its effect is refused; an effect already begun is tracked, and Stop says
stopping until it ends. When settlement records that effect as unknown, the
effect is resolved for Stop: the instance is reaped, Stop answers stopped and
names the step, and the record stays unknown. A late landing can still store
the bytes that effect had already begun. That store is the same effect, not a
new action, and the record is not changed to done or refused. A journal write
still has to pass its revision check.

Stop says stopped only when that session has ended and nothing of it is still landing. A refusal (409) stays a refusal when an earlier step is unknown, and a session that is stopping is not also listed as stopped. A Start during a landing effect answers "this agent is stopping", and that mark stays until the effect is settled or its record is unknown. The plan instance is bound before the guest runs. Unknown steps are capped per agent and dropped when that session's row is evicted. A provider stop that fails leaves the run able to act. Unknown steps are carried through the Runtime hop to the owner. A one-use grant is counted only after the plan admit. A one-use grant the effect spent is settled in the pending store, so a later Stop can still save that session's revocations. A settlement record write is retried a bounded number of times; if it still fails, the flight resolves as unknown and the stored record is not updated to a stronger status. Plans approved in the gateway process while the guest runs in a separate managed Runtime process are outside this branch.

This document does not freeze the exact path layout below `Users/...` or
`UsersAI/...`. Those paths require their own versioned object contract before
applications may depend on them.

## Current implementation status

The repository already establishes several parts of this model:

- `Users` and `UsersAI` are canonical local roots.
- Runtime principals may represent humans, agents, devices, capsules, or
  providers.
- Human collaboration uses a protected ProfileAuthority and signed Profile DID
  distinct from the local principal, passkey, and device DID.
- The `people` App is the current Profile and contacts surface; Profile
  authority remains Runtime-owned rather than becoming a Profile capsule.
- Capability and audit policy already applies to typed model-provider
  resources.
- The old terminal `chat`, `agent`, and `home-agent` source capsules are retired.
  Product Chat is the `chat-room` App. The installed `assistant` capsule is the
  Home-integrated conversational surface and uses typed Runtime model and
  workspace operations. It is not the future general autonomous Agent Host.
- The architecture already separates mutable capsule state from immutable
  capsule artifacts.

No product-readiness claim should be inferred from this architecture document.
A conforming implementation must prove the exact installed Runtime, capsule,
provider, principal, grant, session, restart, and audit path that a user runs.

## Non-negotiable boundaries

- A human profile is not a capability.
- A signed agent identity or private persona is not executable authority.
- A capsule signature admits code; it does not authorize user-scoped effects.
- A model response or tool call is a proposal, not permission.
- A harness is not the security boundary.
- A visible approval card is not the grant authority.
- A provider implements an operation; Runtime authorizes the caller.
- A passkey, DID, or wallet address proves or links identity under its stated
  contract; none grants ambient administrator authority.
- Human and agent actions must not use hidden alternate provider or transport
  paths.
- ElastOS must have one enforcing Runtime authority path, not parallel
  capability systems whose decisions can disagree.

## Related documents

- [Principles](../PRINCIPLES.md)
- [Architecture](ARCHITECTURE.md)
- [Glossary](GLOSSARY.md)
- [Capsule model](CAPSULE_MODEL.md)
- [Home shell host contract](HOME_SHELL_HOST_CONTRACT.md)
- [People and conversations](PEOPLE_CONVERSATIONS.md)
- [Model provider contract](MODEL_PROVIDER.md)
- [Private network contract](PRIVATE_NETWORK.md)
