STATUS: GREEN (package SR-0-recovery; under cap; draft PR)

Base: `4b55d14a2683c849c0ac24aaba565f2317b03c6d`
Branch: ultrafast/a5-s1-sr-0-recovery-onspike
Worktree: /Users/sash/uf-omp-review/wt/A5-store-root-s1a

## Scope (causal package 1 of S1-SR-0 split)

Per Rong `rong-ruling-S1-SR-0-recovery-2315.md` + addendum:

1. `ResolvedPrincipalRoot::from_verified_human_recovery_kit` — verify kit material; `kit.localhost_root == principal_localhost_root(&kit.principal_id)`; Human Users root only.
2. Recovery mint tokens via that root + `HomeLaunchTokenContext::resolved` + `issue_home_launch_token_with_context` **before** commit (not resolve/issue_for_auth_grant).
3. Shared D1 primitive `device_local_root_for_did` used by `resolve` device arm (`PrincipalId::device_did` + `principal_localhost_root`).
4. Agent importer / replaced Agent record refused in `ensure_recovered_root_reassignable_in_state` (pre-mint + commit). No Agent recovery; commit preserves importer kind.
5. Production reexport of `issue_home_launch_token_with_context` from `gateway.rs`.

**Not in this package:** L1–L4 resolve-before-mint, `verified_device_signer` (site 4), L5–L7, private root field, STORE-ROOT lift.

## Size

| File | + | - |
|---|---:|---:|
| auth.rs | 40 | 2 |
| auth_gateway.rs | 28 | 6 |
| gateway.rs | 8 | 8 |
| **total** | **76** | **16** | (=92, cap 120)

## Gates

- fmt --check PASS
- clippy -D warnings PASS
- recovery journey + reassignment suite targeted PASS
- Full assembly with later SR-0a/0b still required before STORE-ROOT lift

## Follow-on (saved full tree at /tmp/sr0-aside/full-tree)

- SR-0a: gateway_home_token L1–L4 + verified_device_signer + rightful-store test repairs
- SR-0b: auth_gateway L5–L7 + preparation seeds
