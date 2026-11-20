//! Admission-like check, before anything is compiled or instantiated: a guest
//! may import only `elastos:bus/<interface>@2.0.0` for the interfaces of the
//! `product-capsule-v2` world. Anything else is refused with a named reason.

use wasmparser::{ComponentTypeRef, Encoding, Parser, Payload};
use wasmtime::component::Component;
use wasmtime::Engine;

pub const BUS_V2: &str = "2.0.0";
/// The interfaces a v2 guest may import (the world's imports, and `types`,
/// which they use).
pub const V2_INTERFACES: [&str; 9] = [
    "types",
    "runtime",
    "identity",
    "capabilities",
    "providers",
    "clock",
    "random",
    "ui",
    "credentials",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Not a component (for example a core module).
    NotAComponent,
    /// The bytes do not parse or do not validate.
    Malformed(String),
    /// A top-level import of a core module.
    CoreModuleImport(String),
    /// Any `wasi:*` import.
    WasiImport(String),
    /// An import outside `elastos:bus/*@2.0.0` (another package, a plain
    /// name, or another version of the bus).
    OutsideBusV2(String),
    /// Imports from both Bus v1 and Bus v2.
    MixedBusVersions { v1: String, v2: String },
    /// An `elastos:bus/*@2.0.0` interface that is not in the world.
    UnknownBusInterface(String),
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::NotAComponent => "not_a_component",
            Refusal::Malformed(_) => "malformed",
            Refusal::CoreModuleImport(_) => "core_module_import",
            Refusal::WasiImport(_) => "wasi_import",
            Refusal::OutsideBusV2(_) => "outside_bus_v2",
            Refusal::MixedBusVersions { .. } => "mixed_bus_versions",
            Refusal::UnknownBusInterface(_) => "unknown_bus_interface",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NotAComponent => write!(
                f,
                "{}: expected a component, not a core module",
                self.code()
            ),
            Refusal::Malformed(why) => write!(f, "{}: {why}", self.code()),
            Refusal::CoreModuleImport(name) => {
                write!(
                    f,
                    "{}: imports the core module {name:?}; a guest imports only bus interfaces",
                    self.code()
                )
            }
            Refusal::WasiImport(name) | Refusal::OutsideBusV2(name) => {
                write!(
                    f,
                    "{}: imports {name:?}; only elastos:bus/*@{BUS_V2} is allowed",
                    self.code()
                )
            }
            Refusal::MixedBusVersions { v1, v2 } => {
                write!(
                    f,
                    "{}: imports both {v1:?} and {v2:?}; a guest uses one bus version",
                    self.code()
                )
            }
            Refusal::UnknownBusInterface(name) => {
                write!(
                    f,
                    "{}: {name:?} is not an interface of product-capsule-v2",
                    self.code()
                )
            }
        }
    }
}

/// `elastos:bus/<interface>@<version>`, split.
fn bus_import(name: &str) -> Option<(&str, &str)> {
    name.strip_prefix("elastos:bus/")?.split_once('@')
}

/// The component's top-level import names, if every one is allowed.
pub fn check_imports(bytes: &[u8]) -> Result<Vec<String>, Refusal> {
    let mut depth = 0usize;
    let mut imports = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|err| Refusal::Malformed(err.to_string()))?;
        match payload {
            Payload::Version { encoding, .. } if depth == 0 && encoding != Encoding::Component => {
                return Err(Refusal::NotAComponent);
            }
            Payload::ModuleSection { .. } | Payload::ComponentSection { .. } => depth += 1,
            Payload::End(_) => depth = depth.saturating_sub(1),
            Payload::ComponentImportSection(reader) if depth == 0 => {
                for import in reader {
                    let import = import.map_err(|err| Refusal::Malformed(err.to_string()))?;
                    let name = import.name.name.to_string();
                    if matches!(import.ty, ComponentTypeRef::Module(_)) {
                        return Err(Refusal::CoreModuleImport(name));
                    }
                    imports.push(name);
                }
            }
            _ => {}
        }
    }

    let v1 = imports
        .iter()
        .find(|name| bus_import(name).is_some_and(|(_, version)| version.starts_with("1.")));
    let v2 = imports
        .iter()
        .find(|name| bus_import(name).is_some_and(|(_, version)| version == BUS_V2));
    if let (Some(v1), Some(v2)) = (v1, v2) {
        return Err(Refusal::MixedBusVersions {
            v1: v1.clone(),
            v2: v2.clone(),
        });
    }
    for name in &imports {
        if name.starts_with("wasi:") {
            return Err(Refusal::WasiImport(name.clone()));
        }
        match bus_import(name) {
            Some((interface, BUS_V2)) => {
                if !V2_INTERFACES.contains(&interface) {
                    return Err(Refusal::UnknownBusInterface(name.clone()));
                }
            }
            _ => return Err(Refusal::OutsideBusV2(name.clone())),
        }
    }
    Ok(imports)
}

/// Checks the imports, then compiles. Nothing is instantiated here.
pub fn admit(engine: &Engine, bytes: &[u8]) -> Result<Component, Refusal> {
    check_imports(bytes)?;
    Component::new(engine, bytes).map_err(|err| Refusal::Malformed(format!("{err:#}")))
}
