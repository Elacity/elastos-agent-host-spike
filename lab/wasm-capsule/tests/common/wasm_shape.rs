//! A minimal reader for the three shape facts wc-001 pins: that the artifact is
//! a core Wasm module, that it imports nothing, and that its `digest` export has
//! the signature `(param i32) -> (result i64)`.
//!
//! It is deliberately tiny and dependency-free, and it is NOT a validator: it
//! reads only the sections those facts need and fails closed with a named
//! reason (PRINCIPLES P11) on anything it cannot read. Keeping it in the lane's
//! own tooling, with no external crate, keeps the surface minimal (P18) and the
//! lane's Cargo.lock free of the network.

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
    /// The number of entries in the import section (0 when it is absent).
    pub import_count: usize,
    /// The signature of the exported function named `digest`, if present.
    pub digest: Option<FuncType>,
}

impl Shape {
    /// The exact shape wc-001 requires: core Wasm, nothing imported, and a
    /// `digest` export of `(param i32) -> (result i64)`.
    pub fn is_the_required_capsule_shape(&self) -> bool {
        self.is_core_wasm
            && self.import_count == 0
            && self.digest
                == Some(FuncType {
                    params: vec![ValType::I32],
                    results: vec![ValType::I64],
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
            import_count: 0,
            digest: None,
        });
    }

    let mut func_types: Vec<FuncType> = Vec::new();
    // Type index for each function, imported functions first, then defined.
    let mut function_type_indices: Vec<u32> = Vec::new();
    let mut imported_function_count: u32 = 0;
    let mut import_count: usize = 0;
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
            // Import section: count them, and track imported functions so a
            // later export index maps to the right function.
            2 => {
                let count = sec.uleb()?;
                import_count = count as usize;
                for _ in 0..count {
                    let module_len = sec.uleb()? as usize;
                    sec.take(module_len)?;
                    let name_len = sec.uleb()? as usize;
                    sec.take(name_len)?;
                    match sec.byte()? {
                        0x00 => {
                            // Imported function: it carries a type index.
                            sec.uleb()?;
                            imported_function_count += 1;
                        }
                        0x01 => {
                            // Table: element type then limits.
                            sec.val_type()?;
                            read_limits(&mut sec)?;
                        }
                        0x02 => {
                            // Memory: limits.
                            read_limits(&mut sec)?;
                        }
                        0x03 => {
                            // Global: value type then a mutability flag.
                            sec.val_type()?;
                            sec.byte()?;
                        }
                        other => {
                            return Err(format!("unexpected import kind 0x{other:02x}"));
                        }
                    }
                }
            }
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

    let digest = resolve_digest(
        &exports,
        &function_type_indices,
        &func_types,
        imported_function_count,
    )?;

    Ok(Shape {
        is_core_wasm: true,
        import_count,
        digest,
    })
}

/// Limits are a flag byte then one or two LEB128 values. wc-001 only needs to
/// step over them.
fn read_limits(sec: &mut Cursor) -> Result<(), String> {
    let flag = sec.byte()?;
    sec.uleb()?; // minimum
    if flag & 0x01 != 0 {
        sec.uleb()?; // maximum
    }
    Ok(())
}

/// Find the `digest` function export and return its signature, or `None` when
/// there is no such function export. A function index that points past the
/// known functions fails closed.
fn resolve_digest(
    exports: &[(Vec<u8>, bool, u32)],
    function_type_indices: &[u32],
    func_types: &[FuncType],
    imported_function_count: u32,
) -> Result<Option<FuncType>, String> {
    for (name, is_function, index) in exports {
        if name != b"digest" {
            continue;
        }
        if !is_function {
            return Err("the `digest` export is not a function".to_string());
        }
        if *index < imported_function_count {
            return Err("the `digest` export is an imported function".to_string());
        }
        let defined = (*index - imported_function_count) as usize;
        let type_index = *function_type_indices
            .get(defined)
            .ok_or_else(|| "the `digest` function index is out of range".to_string())?
            as usize;
        let sig = func_types
            .get(type_index)
            .ok_or_else(|| "the `digest` type index is out of range".to_string())?;
        return Ok(Some(sig.clone()));
    }
    Ok(None)
}
