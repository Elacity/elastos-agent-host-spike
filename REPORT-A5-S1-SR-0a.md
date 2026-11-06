STATUS: GREEN (package SR-0a; under cap; draft PR; depends on #1540)

Base of branch: `11fb884a` (SR-0-recovery). Tip of spike still `4b55d14a` until #1540 merges.

## Scope

Closes gateway_home_token production literals L1–L4 onto `resolved()` / Wallet root / launch-auth resolve / `verified_device_signer` (D1 after signature + exact device checks; does not call resolve).

Rightful-store test repairs: parent-store seed, proof-bound seed, p2a_ii_0b expect refuse-at-issue.

## Size

gateway_home_token 66/44 + auth verified_device_signer 8/0 = **74+/44-** (118, cap 120).

## Gates

fmt/clippy PASS; proof_bound, parent-store, p2a_ii_0b, full recovery, parent-signer PASS.
