# Proposal: one `component-type` section in a capsule artifact

Lab proposal for one later validator. This crate makes no admission or launch
decision; the Runtime owns enforcement. Here `audit` on a core module is the
pre-check and `audit_component` on the componentized artifact is the lab claim.

## Rule

A signed artifact carries exactly one custom section whose name starts with
`component-type`. A second such section returns `CodeInCustomSection` with the
string `code in custom section`; its bytes are not read.

That one section is accepted in one of two ways:

- its data equals the committed fixture
  `tests/fixtures/wit-bindgen-0.57.1-component-type.bin`, 1,382 bytes, SHA-256
  `439929eb565421a1de4791c7e5b278ae105687eb0f12d4a965d6a6adabce24a8`; or
- its walk finds at least one type-level import and every such name equals one
  of the five Bus interfaces below.

A type-level name is `ComponentImport.name.name`. The walk covers
`ComponentTypeDeclaration::Type` and `ComponentType::Instance`, so a name one
level down is still collected. A name that is a prefix of a listed string, a
section with no type-level import, and a `component-type` name inside type-only
data all return `CodeInCustomSection` with the same string.

## Allowed Bus interfaces

```
elastos:bus/types@1.0.0
elastos:bus/runtime@1.0.0
elastos:bus/identity@1.0.0
elastos:bus/capabilities@1.0.0
elastos:bus/providers@1.0.0
```

Copied read-only from `ALLOWED_BUS_IMPORTS` in
`elastos/crates/elastos-server/src/component.rs`. `elastos:bus/lifecycle@1.0.0`
stays off the list.
