//! A minimal reader for the shape facts this lane pins that the audit API
//! does not give: that the artifact is a core Wasm module, that its `digest`
//! export has the signature `(param i32) -> (result i64)`, and (task 068) that
//! its `elastos:bus/lifecycle@1.0.0#run` export has `() -> (result i32)`.
//!
//! It reads no imports (task 053). The capsule's zero-import claim (P3) is read
//! only through `wasm_capsule_audit::audit`, the lab's one module reader (P10),
//! and a module with an import section is refused here with one exact reason,
//! so this reader never maps an export index past imports it did not read.
//!
//! It is deliberately tiny and dependency-free, and it is NOT a validator: it
//! reads only the sections those facts need and fails closed with a named
//! reason (PRINCIPLES P11) on anything it cannot read. Keeping it in the lane's
//! own tooling, with no external crate, keeps the surface minimal (P18) and
//! adds nothing to the lane's Cargo.lock.

/// The one reason a module with an import section is refused (task 053).
pub const IMPORT_SECTION_REFUSED: &str =
    "the shape reader reads no imports: a module's imports are read only through wasm_capsule_audit::audit";

/// The core export of the world's `lifecycle.run` interface (task 068): the
/// name `wit-bindgen` writes for `export lifecycle;` of `product-capsule-v1`.
pub const LIFECYCLE_RUN_EXPORT: &[u8] = b"elastos:bus/lifecycle@1.0.0#run";

/// A Wasm value type, as far as wc-001 needs to tell them apart.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
    /// Any other encoding (reference types, v128, ...). Kept exact so a changed
    /// signature cannot pass as a match.
    Other(u8),
}

/// A function type: the parameters and results of one Wasm function.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

/// The shape facts read from one module.
#[derive(Debug, PartialEq, Eq)]
pub struct Shape {
    /// True only when the file begins with the core Wasm magic and version 1.
    /// A Component (or anything else) is not core Wasm.
    pub is_core_wasm: bool,
    /// The signature of the exported function named `digest`, if present.
    pub digest: Option<FuncType>,
    /// The signature of the exported function named `LIFECYCLE_RUN_EXPORT`, if
    /// present (task 068).
    pub lifecycle_run: Option<FuncType>,
}

impl Shape {
    /// The shape facts this lane requires from the capsule: core Wasm, a
    /// `digest` export of `(param i32) -> (result i64)`, and (task 068) a
    /// `elastos:bus/lifecycle@1.0.0#run` export of `() -> (result i32)`. The
    /// last is `func() -> result<_, bus-error>`, lowered as measured for
    /// `product-capsule-v1`. Imports are not one of these facts:
    /// `wasm_capsule_audit::audit` reads those (task 053).
    pub fn is_the_required_capsule_shape(&self) -> bool {
        self.is_core_wasm
            && self.digest
                == Some(FuncType {
                    params: vec![ValType::I32],
                    results: vec![ValType::I64],
                })
            && self.lifecycle_run
                == Some(FuncType {
                    params: vec![],
                    results: vec![ValType::I32],
                })
    }
}

/// A byte cursor that never reads past the end: every helper fails closed.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn byte(&mut self) -> Result<u8, String> {
        let b = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| "unexpected end of module".to_string())?;
        self.at += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.remaining() < n {
            return Err("unexpected end of module".to_string());
        }
        let slice = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(slice)
    }

    /// An unsigned LEB128, capped at 32 bits (every count and index wc-001 reads
    /// fits there). A run-on encoding fails closed rather than wrapping.
    fn uleb(&mut self) -> Result<u32, String> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            let byte = self.byte()?;
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 35 {
                return Err("LEB128 value is too long".to_string());
            }
        }
        if result > u64::from(u32::MAX) {
            return Err("LEB128 value does not fit in 32 bits".to_string());
        }
        Ok(result as u32)
    }

    fn val_type(&mut self) -> Result<ValType, String> {
        Ok(match self.byte()? {
            0x7f => ValType::I32,
            0x7e => ValType::I64,
            0x7d => ValType::F32,
            0x7c => ValType::F64,
            other => ValType::Other(other),
        })
    }

    fn val_type_vec(&mut self) -> Result<Vec<ValType>, String> {
        let count = self.uleb()? as usize;
        let mut types = Vec::with_capacity(count);
        for _ in 0..count {
            types.push(self.val_type()?);
        }
        Ok(types)
    }
}

/// Read the shape facts from a Wasm module's bytes.
pub fn read(bytes: &[u8]) -> Result<Shape, String> {
    // Magic (`\0asm`) and version 1 mark core Wasm. A Component shares the
    // magic but carries a different version, so both bytes are checked.
    let is_core_wasm =
        bytes.len() >= 8 && &bytes[0..4] == b"\0asm" && bytes[4..8] == [0x01, 0x00, 0x00, 0x00];
    if !is_core_wasm {
        return Ok(Shape {
            is_core_wasm: false,
            digest: None,
            lifecycle_run: None,
        });
    }

    let mut func_types: Vec<FuncType> = Vec::new();
    // Type index for each defined function. With no import section, the
    // function index space holds only these.
    let mut function_type_indices: Vec<u32> = Vec::new();
    // (export name, is a function, index in the function index space)
    let mut exports: Vec<(Vec<u8>, bool, u32)> = Vec::new();

    let mut cursor = Cursor::new(bytes);
    cursor.at = 8;
    while cursor.remaining() > 0 {
        let section_id = cursor.byte()?;
        let section_len = cursor.uleb()? as usize;
        let body = cursor.take(section_len)?;
        let mut sec = Cursor::new(body);
        match section_id {
            // Type section: the function types, in order.
            1 => {
                let count = sec.uleb()?;
                for _ in 0..count {
                    match sec.byte()? {
                        0x60 => {
                            let params = sec.val_type_vec()?;
                            let results = sec.val_type_vec()?;
                            func_types.push(FuncType { params, results });
                        }
                        other => {
                            return Err(format!("unexpected type form 0x{other:02x}"));
                        }
                    }
                }
            }
            // Import section: never read here (task 053). Refused whole, so
            // no import is counted, walked or skipped past.
            2 => return Err(IMPORT_SECTION_REFUSED.to_string()),
            // Function section: the type index of each defined function.
            3 => {
                let count = sec.uleb()?;
                for _ in 0..count {
                    function_type_indices.push(sec.uleb()?);
                }
            }
            // Export section: name, kind, index.
            7 => {
                let count = sec.uleb()?;
                for _ in 0..count {
                    let name_len = sec.uleb()? as usize;
                    let name = sec.take(name_len)?.to_vec();
                    let kind = sec.byte()?;
                    let index = sec.uleb()?;
                    exports.push((name, kind == 0x00, index));
                }
            }
            // Every other section is skipped whole.
            _ => {}
        }
    }

    let digest = resolve_export(
        b"digest",
        "digest",
        &exports,
        &function_type_indices,
        &func_types,
    )?;
    let lifecycle_run = resolve_export(
        LIFECYCLE_RUN_EXPORT,
        "elastos:bus/lifecycle@1.0.0#run",
        &exports,
        &function_type_indices,
        &func_types,
    )?;

    Ok(Shape {
        is_core_wasm: true,
        digest,
        lifecycle_run,
    })
}

/// Find the function export named `name` and return its signature, or `None`
/// when there is no such function export. `label` is the export's name as a
/// refusal names it. A module read here imports nothing, so a function index
/// is a defined function's index; one that points past the known functions
/// fails closed.
fn resolve_export(
    name: &[u8],
    label: &str,
    exports: &[(Vec<u8>, bool, u32)],
    function_type_indices: &[u32],
    func_types: &[FuncType],
) -> Result<Option<FuncType>, String> {
    for (export_name, is_function, index) in exports {
        if export_name != name {
            continue;
        }
        if !is_function {
            return Err(format!("the `{label}` export is not a function"));
        }
        let type_index = *function_type_indices
            .get(*index as usize)
            .ok_or_else(|| format!("the `{label}` function index is out of range"))?
            as usize;
        let sig = func_types
            .get(type_index)
            .ok_or_else(|| format!("the `{label}` type index is out of range"))?;
        return Ok(Some(sig.clone()));
    }
    Ok(None)
}
