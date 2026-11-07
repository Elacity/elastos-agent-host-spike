//! Static lab import pre-check. The Runtime owns enforcement.

use std::fmt;
use wasmparser::{
    ComponentExternalKind, ComponentType, ComponentTypeDeclaration, Encoding, Import,
    ImportSectionReader, InstanceTypeDeclaration, MemoryType, Parser, Payload, TypeRef, Validator,
};

pub const AUDIT_API: u32 = 1;

// The five interfaces the Runtime grants to a first-party capsule. Copied
// read-only from `elastos/crates/elastos-server/src/component.rs`; this crate
// does not import the Runtime and adds no sixth name.
const ALLOWED_BUS_IMPORTS: [&str; 5] = [
    "elastos:bus/types@1.0.0",
    "elastos:bus/runtime@1.0.0",
    "elastos:bus/identity@1.0.0",
    "elastos:bus/capabilities@1.0.0",
    "elastos:bus/providers@1.0.0",
];

// The pinned wit-bindgen 0.57.1 encoding of the `product-capsule-v1` world:
// 1,382 bytes, SHA-256
// 439929eb565421a1de4791c7e5b278ae105687eb0f12d4a965d6a6adabce24a8.
const PRODUCT_CAPSULE_V1_COMPONENT_TYPE: &[u8] =
    include_bytes!("../tests/fixtures/wit-bindgen-0.57.1-component-type.bin");

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
            for import in module_imports(section)? {
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
    let mut limits = Vec::new();
    inspect(wasm, Encoding::Module, |payload| {
        if let Payload::ImportSection(section) = payload {
            for import in module_imports(section)? {
                if let TypeRef::Memory(ty) = import.ty {
                    limits.push(memory_limits(ty));
                }
            }
        } else if let Payload::MemorySection(section) = payload {
            for memory in section {
                let ty = memory.map_err(|_| Refusal::Malformed)?;
                limits.push(memory_limits(ty));
            }
        }
        Ok(())
    })?;
    Ok(limits)
}

fn module_imports<'a>(section: ImportSectionReader<'a>) -> Result<Vec<Import<'a>>, Refusal> {
    let mut read = Vec::new();
    for import in section.into_imports() {
        let import = import.map_err(|_| Refusal::Malformed)?;
        read.push(import);
    }
    Ok(read)
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
    read_imports: impl FnMut(Payload<'_>) -> Result<(), Refusal>,
) -> Result<(), Refusal> {
    let mut validator = new_validator();
    inspect_with_validator(wasm, encoding, &mut validator, false, read_imports)
}

// The crate's one validator constructor. Nested type-only data gets its own
// validator, so its reset cannot use up the outer one.
fn new_validator() -> Validator {
    Validator::new()
}

// The crate's one parse. A `component-type` section reuses it on its own data.
fn payloads(
    wasm: &[u8],
) -> impl Iterator<Item = Result<Payload<'_>, wasmparser::BinaryReaderError>> + '_ {
    Parser::new(0).parse_all(wasm)
}

fn inspect_with_validator(
    wasm: &[u8],
    encoding: Encoding,
    validator: &mut Validator,
    nested: bool,
    mut read_imports: impl FnMut(Payload<'_>) -> Result<(), Refusal>,
) -> Result<(), Refusal> {
    let (right_encoding, invalid) = match encoding {
        Encoding::Module => (wasm.starts_with(b"\0asm\x01\0\0\0"), Refusal::Malformed),
        Encoding::Component => (Parser::is_component(wasm), Refusal::NotAComponent),
    };
    validator.reset();
    if !right_encoding || validator.validate_all(wasm).is_err() {
        return Err(invalid);
    }

    let mut depth = 0;
    let mut component_type_sections = 0;
    for payload in payloads(wasm) {
        match payload.map_err(|_| invalid.clone())? {
            Payload::Version { .. } => depth += 1,
            Payload::End(_) => depth -= 1,
            Payload::CustomSection(section) => {
                let component_type = section.name().starts_with("component-type");
                // One level only: the encoded world never nests its own
                // section, and a hostile chain would exhaust the stack.
                if nested && component_type {
                    return Err(Refusal::CodeInCustomSection);
                }
                if component_type {
                    // One signed artifact carries exactly one such section.
                    component_type_sections += 1;
                    if component_type_sections > 1 {
                        return Err(Refusal::CodeInCustomSection);
                    }
                    type_only_component(section.data())?;
                } else {
                    let range = section.range();
                    let start = usize::try_from(range.start).map_err(|_| invalid.clone())?;
                    let start = start.checked_sub(1).ok_or_else(|| invalid.clone())?;
                    let end = usize::try_from(range.end).map_err(|_| invalid.clone())?;
                    let content = wasm.get(start..end).ok_or_else(|| invalid.clone())?;
                    if content.windows(4).any(|bytes| bytes == b"\0asm") {
                        return Err(Refusal::CodeInCustomSection);
                    }
                }
            }
            payload if depth == 1 => read_imports(payload)?,
            _ => {}
        }
    }
    Ok(())
}

// wit-bindgen names its encoded world `component-type:...`. That data is a
// component of type definitions and type exports, never code. The committed
// product-capsule-v1 world passes by byte identity; any other type-only data
// carries only type-level imports from the five granted Bus interfaces.
fn type_only_component(data: &[u8]) -> Result<(), Refusal> {
    if data == PRODUCT_CAPSULE_V1_COMPONENT_TYPE {
        return Ok(());
    }
    let mut validator = new_validator();
    let mut type_imports = Vec::new();
    inspect_with_validator(data, Encoding::Component, &mut validator, true, |payload| {
        type_only_payload(payload, &mut type_imports)
    })
    .map_err(|_| Refusal::CodeInCustomSection)?;
    if type_imports.is_empty()
        || type_imports
            .iter()
            .any(|name| !ALLOWED_BUS_IMPORTS.contains(&name.as_str()))
    {
        return Err(Refusal::CodeInCustomSection);
    }
    Ok(())
}

fn type_only_payload(payload: Payload<'_>, type_imports: &mut Vec<String>) -> Result<(), Refusal> {
    match payload {
        Payload::ComponentTypeSection(section) => {
            for ty in section {
                let ty = ty.map_err(|_| Refusal::CodeInCustomSection)?;
                type_import_names(&ty, type_imports);
            }
            Ok(())
        }
        Payload::ComponentExportSection(section) => {
            // Defence in depth: a non-type export needs a definition section
            // (module, instance, component, function or value), and the final
            // arm refuses every such section before this export is read.
            for export in section {
                let export = export.map_err(|_| Refusal::CodeInCustomSection)?;
                if export.kind != ComponentExternalKind::Type {
                    return Err(Refusal::CodeInCustomSection);
                }
            }
            Ok(())
        }
        _ => Err(Refusal::CodeInCustomSection),
    }
}

// A type-level import can sit one or more nested `Type(...)` declarations
// down. Every name is checked, not only the first level.
fn type_import_names(ty: &ComponentType<'_>, names: &mut Vec<String>) {
    match ty {
        ComponentType::Component(declarations) => {
            for declaration in declarations.iter() {
                match declaration {
                    ComponentTypeDeclaration::Import(import) => {
                        names.push(import.name.name.to_owned());
                    }
                    ComponentTypeDeclaration::Type(nested) => type_import_names(nested, names),
                    _ => {}
                }
            }
        }
        ComponentType::Instance(declarations) => {
            for declaration in declarations.iter() {
                if let InstanceTypeDeclaration::Type(nested) = declaration {
                    type_import_names(nested, names);
                }
            }
        }
        _ => {}
    }
}
