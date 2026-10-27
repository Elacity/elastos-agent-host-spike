# Minimal patches for r5 survivors

These edit `lab/a1-a8-hardening/src/lib.rs` only. They are review
advice. This PR does not apply them to #455.

## 1. Time / pid / zero session (`H-session-from-time`, `H-session-from-pid`, `H-session-all-zeros`)

`is_session_id` accepts any 32 lowercase hex. `format!("{:032x}", pid)`,
`format!("{:032x}", unix_nanos)`, and 32 zeros all later-PASS.

```rust
pub fn is_session_id(word: &str) -> bool {
    let hex = word.strip_prefix("session-").unwrap_or(word);
    if hex.len() != 32 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return false;
    }
    let Ok(value) = u128::from_str_radix(hex, 16) else {
        return false;
    };
    // Refuse pid, unix-nanos, counters, and the zero id. A host CSPRNG
    // 128-bit value is almost always >= 2^64.
    value >= (1u128 << 64)
}
```

The Runtime must still mint from `OsRng`. This only closes the lab hole.

## 2. Session reused across runs (`H-session-reused`)

`authorship_gaps` is stateless. Two complete binds with the same session
both later-PASS.

On `Home`, keep a host-held set and refuse a second insert:

```rust
// Home
used_sessions: Mutex<HashSet<String>>,

pub fn record_session(&self, session: &str) -> Result<(), String> {
    let mut used = self.used_sessions.lock().unwrap_or_else(|e| e.into_inner());
    if !used.insert(session.to_string()) {
        return Err(format!("session_id reused across runs: {session}"));
    }
    Ok(())
}
```

Call it from the A8 test when `session_id` is present. Unit tests that
reuse the fixture `SESSION` stay on `authorship_gaps` only.

## 3. seq wrap (`H-seq-overflow-wrap`)

`pair[0] + 1` panics in debug and wraps in release. `u64::MAX` then `0`
would later-PASS in release.

```rust
for pair in nums.windows(2) {
    match pair[0].checked_add(1) {
        Some(next) if pair[1] == next => {}
        _ => {
            return Err(format!(
                "receipt seq must be strictly increasing without gaps, repeats, or wrap; host records: {records:?}"
            ));
        }
    }
}
```

## 4. Rename TOCTOU (`H-toctou-rename`)

`executed_bytes_hash` compares two slices. A rename-swap between hash
and `load`, then a swap back, keeps both hashes honest.

```rust
pub struct StagedSeal {
    pub path: PathBuf,
    pub inode: u64,
    pub size: u64,
    pub hash: String,
}

pub fn seal_staged_bytes(path: &Path) -> Result<StagedSeal, String> {
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.file_type().is_symlink() {
        return Err("staged component must not be a symlink".into());
    }
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    Ok(StagedSeal {
        path: path.to_path_buf(),
        inode: meta.ino(),
        size: meta.len(),
        hash: sha256(&bytes),
    })
}

pub fn executed_bytes_still_sealed(seal: &StagedSeal) -> Result<String, String> {
    let meta = fs::metadata(&seal.path).map_err(|e| e.to_string())?;
    let bytes = fs::read(&seal.path).map_err(|e| e.to_string())?;
    if meta.ino() != seal.inode || meta.len() != seal.size || sha256(&bytes) != seal.hash {
        return Err("module_hash must be of the exact bytes executed".into());
    }
    Ok(seal.hash.clone())
}
```

Seal before `elastos run`. Check again after `run_until`, and refuse if
the inode changed during the window.

## 5. Dangling symlink journal (`H-symlink-journal`)

`path.exists()` is false for a dangling symlink. The test treats that
as absent. Receipts then land on the target, which later-PASSes.

```rust
pub fn assert_receipts_absent(&self) {
    let path = self.receipts_path();
    match fs::symlink_metadata(&path) {
        Ok(_) => panic!(
            "capability-requests.jsonl must not exist before the guest is launched ({})",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("capability-requests.jsonl: {error}"),
    }
}
```

## 6. BOM and truncated final line (`H-bom`, `H-truncated-final-line`)

A UTF-8 BOM makes the first line fail parse and be dropped. A missing
final newline drops the last line. One remaining complete line
later-PASSes `authorship_gaps`.

```rust
if text.as_bytes().starts_with(&[0xEF, 0xBB, 0xBF]) {
    return Err(Some("capability-requests.jsonl must not start with a BOM".into()));
}
```

And do not bind a single line as a complete write-then-read:

```rust
if records.len() != 2 {
    missing.push("write-then-read pair");
}
```

Silent drop of a non-seq parse error stays a hole. Fail closed on any
parse error except a missing final newline on an otherwise empty tail.
