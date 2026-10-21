# Runtime budget fields on capability grants

**For Anders, after 0.8.0.** Written 21 Oct 2026 as a short design note; no code. It is the Runtime side of OMP idea
2 (OMP2-DESIGN.md): the guest's own limits become a second check, and the Runtime enforces the real ones.

## What exists today (spike/agent-host f5396709c)

- A capability token already carries what a budget needs (`elastos-runtime/src/capability/token.rs`, `manager.rs`):
  - `max_uses`, refused with `UseLimitExceeded`, and counted atomically (`try_use_token`);
  - `expiry` (a `SecureTimestamp`), refused with `TokenExpired`;
  - `delegatable`: whether the token can be passed on;
  - one-by-one revocation (`CapabilityManager::revoke`), refused with `TokenRevoked`.
- The grant handler offers only `once` (`max_uses = 1`) and `session` (no limit, no expiry)
  (`elastos-server/src/api/handlers/capability.rs`, `grant_request`).

## Proposal

1. **Grant with a budget.** The grant request and the shell's grant accept `max_uses` and `expires_in_seconds` as
   well as `once` and `session`.
   - The person sees the budget on the card and can raise it.
   - The top task's default budget is written into its grant by the host. The guest never chooses its own.
2. **One counter for model calls.** Hosted and local model calls should go through one model grant, so its
   `max_uses` counts both.
3. **A child's grant is never wider than its parent's.**
   - Its `max_uses` is at most what the parent has left.
   - Its expiry is no later than the parent's.
   - At the depth limit it is not delegatable.
   - This is the same rule as resources, and the delegation code already copies `max_uses` from the parent.
4. **The guest learns its limits as data.** The reply to a granted request includes the granted `max_uses` and
   expiry, so the guest can record them and check a child's budget against them.
5. **Cancel revokes the tree.** Cancelling a task revokes every model grant in its subtree, so a call already on its
   way is refused.
6. **Codes the guest can tell apart.** The bridge and `elastos-compute` map `use_limit_exceeded`, `token_expired` and
   `token_revoked` to distinct results, like PR #19 did for the S3 codes. The guest then records `requests`, `time`
   or `cancelled`.

## Tests to write when it is built

| Test | Falsifier |
| --- | --- |
| a use-limited model grant refuses the n+1th call | leave `max_uses` unset |
| an expired child grant is refused | skip the expiry check |
| a child grant asked for wider than the parent's is refused | copy the asked value |
| a non-delegatable grant cannot be delegated | ignore the flag |
| revoking a tree refuses a call already on its way | revoke only the top grant |
| the three refusal codes reach the guest as three different results | map them to one |

## Not decided

- Whether `expires_in_seconds` is measured from the grant or from the first use.
- Where the person raises a running task's budget, and whether raising it issues a new grant.
