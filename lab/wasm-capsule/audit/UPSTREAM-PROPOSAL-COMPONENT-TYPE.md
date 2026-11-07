# Upstream proposal: one component-type allowlist

Status: lab proposal only, not sent. The Runtime keeps the one validator.

The lab audit already has to read the same `component-type` section twice: once
on the signed core module and once on the componentized artifact. One reader
owns the rule (P10). When the Runtime is ready, this allowlist can move there
unchanged.

## The rule

- One signed artifact carries exactly one custom section whose name starts with
  `component-type`. A second such section is refused with
  `code in custom section`.
- That section is accepted only when its data bytes equal the pinned
  `product-capsule-v1` encoding, or when every type-level import name inside it
  equals one of these five strings and at least one name is present:

  ```text
  elastos:bus/types@1.0.0
  elastos:bus/runtime@1.0.0
  elastos:bus/identity@1.0.0
  elastos:bus/capabilities@1.0.0
  elastos:bus/providers@1.0.0
  ```

  The same five strings are in the Runtime's read-only
  `elastos/crates/elastos-server/src/component.rs` (`ALLOWED_BUS_IMPORTS`).
- Type-level names are read from `ComponentType::Component` import
  declarations, including names one or more nested `Type(...)` declarations
  down. Equality is exact: a prefix of a listed string, or a name that only
  starts with `elastos:bus`, is refused.
- Type-only data with no type-level import and no byte match is refused.
- `audit` on the core module is a pre-check. The claim that counts is the
  componentized artifact passing `audit_component`.

## The pin

The committed fixture `tests/fixtures/wit-bindgen-0.57.1-component-type.bin`
holds the `product-capsule-v1` world encoded by wit-bindgen 0.57.1. It is
1,382 bytes with SHA-256
`439929eb565421a1de4791c7e5b278ae105687eb0f12d4a965d6a6adabce24a8`. The lab
crate pins it with `include_bytes!`; byte identity is the pin, so no second
hash function exists.
