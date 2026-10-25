//! A strict reader for the small JSON subset the wc-003 lab manifest uses:
//! objects, arrays, strings of printable ASCII with no escapes, and whole
//! numbers. It is test-side only, so `bundle_manifest_matches_lab_schema` can
//! check the manifest `tools/bundle` writes without a JSON crate.
//!
//! It fails closed with a named reason (PRINCIPLES P11) on anything outside the
//! subset, and on a duplicate key, which would let two readers see two
//! different manifests in the same bytes.

/// A JSON value from the subset. An object keeps its members in byte order.
#[derive(Debug, PartialEq, Eq)]
pub enum Value {
    Object(Vec<(String, Value)>),
    Array(Vec<Value>),
    String(String),
    Integer(u64),
}

/// Read one JSON value that is the whole of `bytes`, apart from whitespace.
pub fn parse(bytes: &[u8]) -> Result<Value, String> {
    let mut reader = Reader { bytes, at: 0 };
    let value = reader.value(0)?;
    reader.skip_space();
    if reader.at != bytes.len() {
        return Err(format!(
            "unexpected bytes after the value at offset {}",
            reader.at
        ));
    }
    Ok(value)
}

/// Nesting deeper than this is refused; the lab manifest needs three levels.
const MAX_DEPTH: usize = 16;

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at += 1;
        Some(byte)
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return Err("the value nests too deeply".to_string());
        }
        self.skip_space();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::String),
            Some(b'0'..=b'9') => self.integer().map(Value::Integer),
            _ => Err(format!("unsupported value at offset {}", self.at)),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, String> {
        self.bump(); // `{`
        let mut members: Vec<(String, Value)> = Vec::new();
        self.skip_space();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_space();
            let key = self.string()?;
            if members.iter().any(|(seen, _)| *seen == key) {
                return Err(format!("duplicate key `{key}`"));
            }
            self.skip_space();
            if self.bump() != Some(b':') {
                return Err(format!("expected `:` after key `{key}`"));
            }
            let value = self.value(depth + 1)?;
            members.push((key, value));
            self.skip_space();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => return Ok(Value::Object(members)),
                _ => return Err(format!("expected `,` or `}}` at offset {}", self.at)),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, String> {
        self.bump(); // `[`
        let mut items = Vec::new();
        self.skip_space();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_space();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => return Ok(Value::Array(items)),
                _ => return Err(format!("expected `,` or `]` at offset {}", self.at)),
            }
        }
    }

    /// Printable ASCII between quotes. An escape, a control byte or a
    /// non-ASCII byte is outside the subset and refused.
    fn string(&mut self) -> Result<String, String> {
        if self.bump() != Some(b'"') {
            return Err(format!("expected a string at offset {}", self.at));
        }
        let start = self.at;
        loop {
            match self.bump() {
                Some(b'"') => break,
                Some(b'\\') => return Err("string escapes are outside the subset".to_string()),
                Some(0x20..=0x7e) => {}
                _ => {
                    return Err(format!(
                        "a string byte is not printable ASCII at offset {}",
                        self.at
                    ))
                }
            }
        }
        let text = &self.bytes[start..self.at - 1];
        Ok(String::from_utf8(text.to_vec()).expect("printable ASCII is UTF-8"))
    }

    /// Digits only: no sign, fraction, exponent or leading zero.
    fn integer(&mut self) -> Result<u64, String> {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        let digits = std::str::from_utf8(&self.bytes[start..self.at]).expect("digits are ASCII");
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(format!("the number {digits} has a leading zero"));
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(format!(
                "the number at offset {start} is not a whole number"
            ));
        }
        digits
            .parse()
            .map_err(|_| format!("the number {digits} does not fit in 64 bits"))
    }
}
