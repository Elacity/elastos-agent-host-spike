# Import audit API v1

`wasm-capsule-audit` is a static lab pre-check. It lists imports and refuses
imports outside the caller's declaration. It makes no admission, launch or
trust decision. The Runtime owns enforcement. No admission or launch path
calls this crate.

## Public API

```rust
pub const AUDIT_API: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredImport {
    pub module: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    Undeclared { module: String, name: String },
    Malformed,
    CodeInCustomSection,
}

pub fn audit(wasm: &[u8], declared: &[DeclaredImport]) -> Result<Vec<DeclaredImport>, Refusal>;
```

`Refusal` implements `std::fmt::Display` and `std::error::Error`.
These exact Display strings are part of v1 and never change:

| Variant | Display string |
| --- | --- |
| `Undeclared { module, name }` | `undeclared import {module}.{name}` |
| `Malformed` | `malformed module` |
| `CodeInCustomSection` | `code in custom section` |

The `Undeclared` string joins module and name with a dot for people to read.
Either part can contain dots, for example `wasi:cli/environment@0.2.0`.
Callers match the variant's fields; they never parse the Display string.

## Rules

- On success, the result lists exactly the imports read from the module, in
  import-section order, including repeated imports. It covers single imports
  and both compact forms (`Compact1` and `Compact2`). An unused `declared`
  entry stays out of the result, and declaration order does not change it.
- An import is declared only when its module and name both equal the fields
  of one entry in `declared`. v1 does not compare the import kind.
- The pinned `wasmparser` parses and validates the bytes with its default
  features (`Validator::new()`). The crate never executes or instantiates a
  module. Post-MVP instructions that rustc emits by default, such as sign
  extension and bulk memory, are valid under this contract.
- `Malformed` covers any bytes that fail to parse and validate as a core
  module, including unknown sections and Component bytes. The core header
  check and full validation run before the import and custom-section checks.
- `CodeInCustomSection` covers a custom section whose payload contains the
  Wasm magic bytes `00 61 73 6D` at any offset, including an embedded module
  or component. A custom section without these bytes is allowed. This check
  scans payload bytes; it does not decode compressed or encoded content.
- After validation and custom-section checks, the first undeclared import
  in section order returns `Undeclared` with its module and name.

## Additive under v1 (cwa-002)

`AUDIT_API` stays 1. The items and strings above keep their v1 meaning.

```rust
pub fn audit_component(wasm: &[u8], declared_interfaces: &[&str]) -> Result<Vec<String>, Refusal>;
```

The non-exhaustive `Refusal` enum gains two variants with these exact strings:

| Variant | Display string |
| --- | --- |
| `UndeclaredInterface { name: String }` | `undeclared interface {name}` |
| `NotAComponent` | `not a component` |

- On success, the result contains exactly the top-level import names read
  from the Component, in section order. An unused declared interface stays
  out of the result. Declaration order does not change the result order.
- An import passes only when its full name equals one `declared_interfaces`
  entry as a string, including its exact version. Prefixes, version ranges
  and unversioned declarations cannot match a versioned import. Under the
  pinned validator's default features, the full name is `ComponentExternName.name`;
  the validator refuses `implements`, `version_suffix` and `external_id` fields.
- The shared parse-and-validate step uses the pinned `wasmparser` with its
  default features. `NotAComponent` covers all bytes that fail to parse and
  validate as a Component, including core-module bytes. The encoding check
  and full validation run before import and custom-section checks.
- Only the outermost Component's imports are outside imports. Embedded core
  modules and nested components get their imports from inside the Component;
  the audit does not apply the core-module import rules to them.
- The shared v1 custom-section rule applies at every depth: the Component's
  own sections, embedded core modules and nested components. A payload that
  contains Wasm magic `00 61 73 6D` at any offset returns `CodeInCustomSection`
  with v1's string `code in custom section`. Plain-text payloads pass this check.
- After validation and custom-section checks, the first undeclared interface
  in section order returns `UndeclaredInterface` with its full name. Callers
  match the variant's field and use its Display string for people to read.
