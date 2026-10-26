# RA-6 — two resident capsule instances in one Runtime

This is the Runtime ask for A6. The lab journey is written and ready. It
reports **BLOCKED**, never PASS, until the Runtime meets this ask.

## What the Runtime must host

One running Runtime / Home process must host two independent **resident**
capsule instances at the same time (`instance-1` and `instance-2`).

String capsule ids on one in-process `CapabilityManager` are not this.
Two throwaway Homes are not this. Fixture deny across process-isolation
clients is not this.

## Required journey

1. Start one Runtime / Home.
2. Launch `instance-1` and `instance-2` as resident capsules in that
   Runtime.
3. Grant `instance-1` a real session token through
   `CapabilityManager::grant`.
4. `instance-1` presents that token to `validate` and is accepted.
5. `instance-2` presents instance-1's token to `validate` and is refused
   `WrongCapsule { expected: instance-1, got: instance-2 }` (both fields
   compared).
6. Removing validate step 4 (`token.capsule != caller`) from the Runtime
   binary this journey loaded makes step 5 fail: the sibling is accepted.

## Current status

The Runtime does not host two resident capsule instances in one process.
Resident lifecycle is still RT4 / Bus v2. Owner A6 rows
(`two_instances_overlap_with_separate_grants`,
`instance_grant_does_not_authorise_sibling`) refuse the sibling by
fixture deny, not by presenting a session token.

The lab function `resident_two_instance_token_journey` mints a real
token and checks step 5 against the Runtime this process loaded. That
readiness check FAIL if step 4 is removed. Hosting the pair still
returns BLOCKED (`RA-6`).
