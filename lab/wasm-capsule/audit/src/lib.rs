//! Static lab import pre-check. The Runtime owns enforcement.

use std::fmt;
use wasmparser::{Parser, Payload, Validator};

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

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undeclared { module, name } => write!(f, "undeclared import {module}.{name}"),
            Self::Malformed => f.write_str("malformed module"),
            Self::CodeInCustomSection => f.write_str("code in custom section"),
        }
    }
}

impl std::error::Error for Refusal {}

pub fn audit(wasm: &[u8], declared: &[DeclaredImport]) -> Result<Vec<DeclaredImport>, Refusal> {
    let mut imports = Vec::new();
    if !wasm.starts_with(b"\0asm\x01\0\0\0") || Validator::new().validate_all(wasm).is_err() {
        return Err(Refusal::Malformed);
    }

    for payload in Parser::new(0).parse_all(wasm) {
        match payload.map_err(|_| Refusal::Malformed)? {
            Payload::ImportSection(section) => {
                for import in section.into_imports() {
                    let import = import.map_err(|_| Refusal::Malformed)?;
                    imports.push(DeclaredImport {
                        module: import.module.to_owned(),
                        name: import.name.to_owned(),
                    });
                }
            }
            Payload::CustomSection(section) => {
                if section.data().windows(4).any(|bytes| bytes == b"\0asm") {
                    return Err(Refusal::CodeInCustomSection);
                }
            }
            _ => {}
        }
    }

    for import in &imports {
        if !declared.contains(import) {
            return Err(Refusal::Undeclared {
                module: import.module.clone(),
                name: import.name.clone(),
            });
        }
    }
    Ok(imports)
}
