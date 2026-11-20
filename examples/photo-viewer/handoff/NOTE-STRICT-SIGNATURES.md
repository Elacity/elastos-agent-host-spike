# Note for Anders: verify Ed25519 signatures strictly in the Runtime

This is a small principles fix of its own (Sasha, P4b review). It is **not** part of P4b and not built.
The P4b bundle tool verifies with `verify_strict`. When that code moves into the Runtime, the Runtime should
be brought up to the same standard, not the tool loosened.

## What differs

ed25519-dalek 2.x has two checks:
- `verify`, the RFC 8032 cofactorless equation;
- `verify_strict`, which also refuses a signature whose `R` point is of small order, and a public key of
  small order.

The Runtime already refuses small-order and non-canonical **keys** when it decodes a did:key
(`elastos-identity/src/store.rs:123-145`, `validate_canonical_ed25519_verifying_key_bytes`). So where the key
comes from `decode_did_key`, the gap is the small-order `R` check only. Where a `VerifyingKey` comes from
elsewhere, the key check is missing too.

I have not shown that any of the call sites below can be attacked. The point is one rule: a signature the
Runtime accepts is one `verify_strict` accepts.

## Runtime call sites using `verify` (found with grep; production code only)

| Site | Key from |
|---|---|
| `elastos-server/src/crypto.rs:76` (`verify_signature_digest_with_cache_capacity`, behind `verify_domain_separated_signature`, launch tokens, receipts) | `decode_did_key` |
| `elastos-server/src/shares.rs:717` (provenance) and `:840` | `decode_did_key` at `:711`; `:840` not traced |
| `elastos-runtime/src/capability/token.rs:390` (`verify_signature`) | the caller's `VerifyingKey`, not traced |

`crypto.rs:472` is a test. ed25519-dalek 3 (Iroh transport, `elastos-server/Cargo.toml:94`) is out of scope.

## Proposed change

1. Replace `verify` with `verify_strict` at those sites. The signature cache in `crypto.rs` stores only
   verified results, so it is unaffected.
2. Add one test per site with a signature that `verify` accepts and `verify_strict` refuses. The published
   edge-case vectors for Ed25519 ("Taming the many EdDSAs", Chalkias, Garillot and Nikolaenko, 2020) include
   small-order `R` cases with a valid key; one of those suits the `decode_did_key` sites. I have not picked or
   checked a vector yet.
3. Add a falsifier that puts `verify` back and sees the test fail.

It is a shipping Runtime change, so it needs Sasha's yes.
