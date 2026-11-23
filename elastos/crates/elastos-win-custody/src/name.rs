use std::ffi::OsStr;

/// One path component: not empty, not `.` or `..`, and no separator, stream, or NUL.
pub fn one_component_name(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    !bytes.is_empty()
        && bytes != b"."
        && bytes != b".."
        && !bytes
            .iter()
            .any(|unit| matches!(unit, 0 | b'/' | b'\\' | b':'))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::one_component_name;

    #[test]
    fn one_component_name_rejects_empty_dot_and_separators() {
        for name in ["", ".", "..", "a/b", r"a\b", "a:b", "a\0b"] {
            assert!(!one_component_name(OsStr::new(name)), "{name:?}");
        }
        assert!(one_component_name(OsStr::new("device.key")));
        assert!(one_component_name(OsStr::new("identity")));
    }
}
