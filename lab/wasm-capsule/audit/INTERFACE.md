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
