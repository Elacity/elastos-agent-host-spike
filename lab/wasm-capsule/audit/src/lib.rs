//! Static lab import pre-check. The Runtime owns enforcement.

use std::fmt;
use wasmparser::{Encoding, MemoryType, Parser, Payload, Validator};

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
    UndeclaredInterface { name: String },
    NotAComponent,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undeclared { module, name } => write!(f, "undeclared import {module}.{name}"),
            Self::Malformed => f.write_str("malformed module"),
            Self::CodeInCustomSection => f.write_str("code in custom section"),
            Self::UndeclaredInterface { name } => write!(f, "undeclared interface {name}"),
            Self::NotAComponent => f.write_str("not a component"),
        }
    }
}

impl std::error::Error for Refusal {}

pub fn audit(wasm: &[u8], declared: &[DeclaredImport]) -> Result<Vec<DeclaredImport>, Refusal> {
    let mut imports = Vec::new();
    inspect(wasm, Encoding::Module, |payload| {
        if let Payload::ImportSection(section) = payload {
            for import in section.into_imports() {
                let import = import.map_err(|_| Refusal::Malformed)?;
                imports.push(DeclaredImport {
                    module: import.module.to_owned(),
                    name: import.name.to_owned(),
                });
            }
        }
        Ok(())
    })?;

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

pub fn audit_component(wasm: &[u8], declared_interfaces: &[&str]) -> Result<Vec<String>, Refusal> {
    let mut interfaces = Vec::new();
    inspect(wasm, Encoding::Component, |payload| {
        if let Payload::ComponentImportSection(section) = payload {
            for import in section {
                let import = import.map_err(|_| Refusal::NotAComponent)?;
                interfaces.push(import.name.name.to_owned());
            }
        }
        Ok(())
    })?;

    for name in &interfaces {
        if !declared_interfaces.contains(&name.as_str()) {
            return Err(Refusal::UndeclaredInterface { name: name.clone() });
        }
    }
    Ok(interfaces)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryLimits {
    pub minimum: u64,
    pub maximum: Option<u64>,
    pub memory64: bool,
    pub shared: bool,
}

pub fn memories(wasm: &[u8]) -> Result<Vec<MemoryLimits>, Refusal> {
    let mut defined = Vec::new();
    inspect(wasm, Encoding::Module, |payload| {
        if let Payload::MemorySection(section) = payload {
            for memory in section {
                let ty = memory.map_err(|_| Refusal::Malformed)?;
                defined.push(memory_limits(ty));
            }
        }
        Ok(())
    })?;
    Ok(defined)
}

fn memory_limits(ty: MemoryType) -> MemoryLimits {
    MemoryLimits {
        minimum: ty.initial,
        maximum: ty.maximum,
        memory64: ty.memory64,
        shared: ty.shared,
    }
}

// Validate the full input first. Imports describe outside authority only at
// depth 1; custom payloads carry bytes and receive the same check at every depth.
fn inspect(
    wasm: &[u8],
    encoding: Encoding,
    mut read_imports: impl FnMut(Payload<'_>) -> Result<(), Refusal>,
) -> Result<(), Refusal> {
    let (right_encoding, invalid) = match encoding {
        Encoding::Module => (wasm.starts_with(b"\0asm\x01\0\0\0"), Refusal::Malformed),
        Encoding::Component => (Parser::is_component(wasm), Refusal::NotAComponent),
    };
    if !right_encoding || Validator::new().validate_all(wasm).is_err() {
        return Err(invalid);
    }

    let mut depth = 0;
    for payload in Parser::new(0).parse_all(wasm) {
        match payload.map_err(|_| invalid.clone())? {
            Payload::Version { .. } => depth += 1,
            Payload::End(_) => depth -= 1,
            Payload::CustomSection(section) => {
                let range = section.range();
                let start = usize::try_from(range.start).map_err(|_| invalid.clone())?;
                let start = start.checked_sub(1).ok_or_else(|| invalid.clone())?;
                let end = usize::try_from(range.end).map_err(|_| invalid.clone())?;
                let content = wasm.get(start..end).ok_or_else(|| invalid.clone())?;
                if content.windows(4).any(|bytes| bytes == b"\0asm") {
                    return Err(Refusal::CodeInCustomSection);
                }
            }
            payload if depth == 1 => read_imports(payload)?,
            _ => {}
        }
    }
    Ok(())
}
