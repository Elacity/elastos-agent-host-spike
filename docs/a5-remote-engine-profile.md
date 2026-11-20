# A5 R4 note: the remote Engine profile path

A5 runtime design v2, slice R4, swaps every Browser profile lookup to the
principal's stored, kind-aware root. One Browser path has no stored principal:
a Runtime serving a Browser Engine for a remote peer. This note records the
rule that path follows (R4, PR #1573, commits e4709535 and b1f75f95).

## Rule

The serving Runtime puts the remote owner's Engine profile at

    localhost://Users/remote-engine-<hex sha256("<endpoint>\n<requester>")>/BrowserProfiles/default/profile.ext4

- `endpoint` is the requester's authenticated Carrier endpoint (its iroh key).
- `requester` is the principal id the granted request names.
- Code: `RemoteEngineOwner::storage_principal_for` in `carrier_engine_binding.rs`;
  `remote_engine_profile` in `api/gateway_browser_remote.rs`.
- Pinned by `remote_engine_profile_uri_names_authenticated_owner` and the
  preparation row in `api/gateway_tests/remote_engine.rs`, against a literal URI.

## Why the requester is in the hash

The requester id comes from the peer and is not a principal in this Runtime's
auth store, so it cannot own a path alone: any peer could name it and borrow
that profile. The endpoint alone would merge every principal of one peer
Runtime into one profile. Hashing both keeps each profile bound to one
authenticated endpoint and one named requester. The hash also keeps
peer-supplied bytes out of the path.

## No id-rule root is derived

The remote owner has no auth record, so the R4 resolver
(`ResolvedPrincipalRoot::resolve`) would refuse it, and R4 forbids the
`principal_localhost_root` fallback. The path above does not use that rule:
`remote-engine-<64 hex>` is a storage name, not `Users/<24 hex of sha256(id)>`.
No `Users/` or `UsersAI/` principal root is derived for the remote owner.

Open: profiles stored before R4 at the old id-derived path are not migrated;
the owner gets a fresh profile [Inference; no deployment checked].
