use std::path::Path;

use elastos_common::{CapsuleManifest, ElastosError, Result};
use wasmparser::{ComponentTypeRef, Encoding, Parser, Payload};

const ALLOWED_BUS_IMPORTS: &[&str] = &[
    "elastos:bus/types@1.0.0",
    "elastos:bus/runtime@1.0.0",
    "elastos:bus/identity@1.0.0",
    "elastos:bus/capabilities@1.0.0",
    "elastos:bus/providers@1.0.0",
];

/// Parse caps: bounds on the work the compiler is asked to do, checked in the
/// same pass as the imports. The largest component in this repository
/// (agent-host) has 896 functions and a largest body of 88,523 bytes.
const MAX_COMPONENT_FUNCTIONS: u32 = 20_000;
const MAX_FUNCTION_BODY_BYTES: usize = 512 * 1024;

const FORBIDDEN_AUTHORITY_MARKERS: &[&str] = &[
    "wasi",
    "env",
    "preopen",
    "socket",
    "sock",
    "fifo",
    "fd_",
    "path_",
    "http",
    "tcp",
    "udp",
    "ELASTOS_API",
    "ELASTOS_TOKEN",
    "ELASTOS_CARRIER_FIFOS",
    "_carrier",
];

/// Reads a component capsule's entrypoint once, under the size cap. The
/// signature check, the import check and the compiler all use these bytes.
pub(crate) async fn read_admitted_entrypoint(
    capsule_dir: &Path,
    manifest: &CapsuleManifest,
) -> Result<Vec<u8>> {
    let entrypoint = capsule_dir.join(&manifest.entrypoint);
    let bytes = elastos_compute::providers::ComponentProvider::read_component(&entrypoint)
        .await
        .map_err(|err| {
            ElastosError::InvalidManifest(format!(
                "failed to read component entrypoint {}: {}",
                manifest.entrypoint, err
            ))
        })?;
    #[cfg(test)]
    AFTER_ENTRYPOINT_READ.with(|hook| hook.borrow().iter().for_each(|hook| hook(&entrypoint)));
    Ok(bytes)
}

#[cfg(test)]
type EntrypointHook = Option<Box<dyn Fn(&Path)>>;

#[cfg(test)]
thread_local! {
    /// Test hook: runs right after the one read of a component entrypoint, so a
    /// test can replace the file and show that nothing reads it again.
    pub(crate) static AFTER_ENTRYPOINT_READ: std::cell::RefCell<EntrypointHook> =
        const { std::cell::RefCell::new(None) };
}

pub(crate) fn validate_component_imports(bytes: &[u8]) -> std::result::Result<(), String> {
    let mut saw_root_header = false;
    let mut functions: u32 = 0;

    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|err| format!("failed to parse component entrypoint: {err}"))? {
            Payload::Version { encoding, .. } if !saw_root_header => {
                saw_root_header = true;
                if encoding != Encoding::Component {
                    return Err("component entrypoint must be a WebAssembly component".to_string());
                }
            }
            Payload::ComponentImportSection(section) => {
                for import in section {
                    let import = import.map_err(|err| {
                        format!("failed to parse component import section: {err}")
                    })?;
                    let name = import.name.name;
                    if name.starts_with("import-type-") {
                        if !matches!(import.ty, ComponentTypeRef::Type(_)) {
                            return Err(format!(
                                "component generated type import \"{}\" must be a type import",
                                name
                            ));
                        }
                        continue;
                    }
                    if name == "import-func-run" {
                        if !matches!(import.ty, ComponentTypeRef::Func(_)) {
                            return Err("component generated run import must be a function import"
                                .to_string());
                        }
                        continue;
                    }
                    if !ALLOWED_BUS_IMPORTS.contains(&name) {
                        return Err(format!(
                            "component import \"{}\" is not allowed; allowed imports: {}",
                            name,
                            ALLOWED_BUS_IMPORTS.join(", ")
                        ));
                    }
                    if !matches!(import.ty, ComponentTypeRef::Instance(_)) {
                        return Err(format!(
                            "component import \"{}\" must be an interface instance import",
                            name
                        ));
                    }
                }
            }
            Payload::CodeSectionStart { count, .. } => {
                functions = functions.saturating_add(count);
                if functions > MAX_COMPONENT_FUNCTIONS {
                    return Err(format!(
                        "component has more than {MAX_COMPONENT_FUNCTIONS} functions"
                    ));
                }
            }
            Payload::CodeSectionEntry(body) => {
                let len = body.range().len();
                if len > MAX_FUNCTION_BODY_BYTES {
                    return Err(format!(
                        "component function body of {len} bytes is over the {MAX_FUNCTION_BODY_BYTES} byte limit"
                    ));
                }
            }
            Payload::ImportSection(section) => {
                // Flattens wasmparser's grouped (compact) imports into one per item.
                for import in section.into_imports() {
                    let import = import.map_err(|err| {
                        format!("failed to parse component core import section: {err}")
                    })?;
                    validate_core_import(import.module, import.name)?;
                }
            }
            _ => {}
        }
    }

    if !saw_root_header {
        return Err("component entrypoint is empty".to_string());
    }

    Ok(())
}

fn validate_core_import(module: &str, name: &str) -> std::result::Result<(), String> {
    let lower = format!("{module}::{name}").to_ascii_lowercase();
    if FORBIDDEN_AUTHORITY_MARKERS
        .iter()
        .any(|marker| lower.contains(&marker.to_ascii_lowercase()))
    {
        return Err(format!(
            "component core module import \"{module}::{name}\" is forbidden"
        ));
    }

    if ALLOWED_BUS_IMPORTS.contains(&module) {
        return Ok(());
    }
    if module.is_empty() && (name == "$imports" || name.bytes().all(|byte| byte.is_ascii_digit())) {
        return Ok(());
    }

    Err(format!(
        "component core module import \"{module}::{name}\" is not allowed; use elastos:bus component imports only"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_encoder::{
        Component, ComponentImportSection, ComponentTypeRef as EncodedComponentTypeRef,
        ComponentTypeSection, InstanceType, PrimitiveValType,
    };

    fn component_with_imports(imports: &[(&str, EncodedComponentTypeRef)]) -> Vec<u8> {
        let mut types = ComponentTypeSection::new();
        types.instance(&InstanceType::new());

        let mut import_section = ComponentImportSection::new();
        for (name, ty) in imports {
            import_section.import(*name, *ty);
        }

        let mut component = Component::new();
        component.section(&types);
        component.section(&import_section);
        component.finish()
    }

    #[test]
    fn accepts_allowed_component_imports() {
        let bytes = component_with_imports(&[
            (
                "elastos:bus/runtime@1.0.0",
                EncodedComponentTypeRef::Instance(0),
            ),
            (
                "elastos:bus/providers@1.0.0",
                EncodedComponentTypeRef::Instance(0),
            ),
        ]);

        validate_component_imports(&bytes).unwrap();
    }

    #[test]
    fn rejects_core_wasm_module() {
        let err = validate_component_imports(b"\0asm\x01\0\0\0").unwrap_err();
        assert!(err.contains("must be a WebAssembly component"));
    }

    #[test]
    fn rejects_extra_component_import() {
        let bytes = component_with_imports(&[(
            "wasi:filesystem/types@0.2.0",
            EncodedComponentTypeRef::Instance(0),
        )]);

        let err = validate_component_imports(&bytes).unwrap_err();
        assert!(err.contains("not allowed"));
        assert!(err.contains("elastos:bus/runtime@1.0.0"));
    }

    #[test]
    fn rejects_unimplemented_bus_import() {
        let bytes = component_with_imports(&[(
            "elastos:bus/streams@1.0.0",
            EncodedComponentTypeRef::Instance(0),
        )]);

        let err = validate_component_imports(&bytes).unwrap_err();
        assert!(err.contains("not allowed"));
        assert!(err.contains("elastos:bus/streams@1.0.0"));
    }

    #[test]
    fn rejects_nested_core_module_imports() {
        let mut module = wasm_encoder::Module::new();
        let mut types = wasm_encoder::TypeSection::new();
        types.ty().function([], []);
        module.section(&types);
        let mut imports = wasm_encoder::ImportSection::new();
        imports.import(
            "wasi_snapshot_preview1",
            "fd_write",
            wasm_encoder::EntityType::Function(0),
        );
        module.section(&imports);

        let mut component = Component::new();
        component.section(&wasm_encoder::ModuleSection(&module));

        let err = validate_component_imports(&component.finish()).unwrap_err();
        assert!(err.contains("core module import"));
        assert!(err.contains("wasi_snapshot_preview1::fd_write"));
    }

    /// A component holding core modules, one per entry of `modules`; each
    /// module has that many functions, each a body of `body_len` bytes.
    fn component_with_functions(modules: &[u32], body_len: usize) -> Vec<u8> {
        let mut component = Component::new();
        for count in modules {
            let mut module = wasm_encoder::Module::new();
            let mut types = wasm_encoder::TypeSection::new();
            types.ty().function([], []);
            module.section(&types);
            let mut functions = wasm_encoder::FunctionSection::new();
            let mut code = wasm_encoder::CodeSection::new();
            // A body is its locals count (one byte), its instructions, and `end`.
            let mut body = wasm_encoder::Function::new([]);
            for _ in 0..body_len - 2 {
                body.instruction(&wasm_encoder::Instruction::Nop);
            }
            body.instruction(&wasm_encoder::Instruction::End);
            for _ in 0..*count {
                functions.function(0);
                code.function(&body);
            }
            module.section(&functions);
            module.section(&code);
            component.section(&wasm_encoder::ModuleSection(&module));
        }
        component.finish()
    }

    #[test]
    fn a_component_may_hold_twenty_thousand_functions_and_no_more() {
        // The count is over every core module of the component together.
        validate_component_imports(&component_with_functions(&[12_000, 8_000], 2)).unwrap();
        let err =
            validate_component_imports(&component_with_functions(&[12_000, 8_001], 2)).unwrap_err();
        assert_eq!(err, "component has more than 20000 functions");
    }

    #[test]
    fn a_function_body_may_be_512_kib_and_no_more() {
        validate_component_imports(&component_with_functions(&[1], 512 * 1024)).unwrap();
        let err = validate_component_imports(&component_with_functions(&[1], 512 * 1024 + 1))
            .unwrap_err();
        assert_eq!(
            err,
            "component function body of 524289 bytes is over the 524288 byte limit"
        );
    }

    #[test]
    fn the_repository_fixture_is_far_under_the_parse_caps() {
        let bytes = include_bytes!(
            "../../../tests/fixtures/components/bus-v1/bus-v1-conformance.component.wasm"
        );
        validate_component_imports(bytes).unwrap();
    }

    #[test]
    fn rejects_allowed_name_with_wrong_import_kind() {
        let mut types = ComponentTypeSection::new();
        types
            .function()
            .params(std::iter::empty::<(&str, PrimitiveValType)>())
            .result(None);

        let mut imports = ComponentImportSection::new();
        imports.import(
            "elastos:bus/runtime@1.0.0",
            EncodedComponentTypeRef::Func(0),
        );

        let mut component = Component::new();
        component.section(&types);
        component.section(&imports);

        let err = validate_component_imports(&component.finish()).unwrap_err();
        assert!(err.contains("must be an interface instance import"));
    }
}
