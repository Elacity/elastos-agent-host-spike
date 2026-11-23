use std::ffi::OsStr;
#[cfg(any(windows, test))]
use std::ffi::OsString;

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

#[cfg(any(windows, test))]
const NOT_ABSOLUTE: &str = "absolute local disk path required";
#[cfg(any(windows, test))]
const DRIVE_RELATIVE: &str = "drive-relative path";
#[cfg(any(windows, test))]
const INVALID_COMPONENT: &str = "invalid path component";
#[cfg(any(windows, test))]
const NO_NAME: &str = "path has no file or directory name";

/// Absolute Windows local-disk path: `C:\a\b` or `\\?\C:\a\b`.
///
/// A relative path is refused. This does not read the current directory and
/// does not collapse `.` or `..`.
#[cfg(any(windows, test))]
pub(crate) fn absolute_local_disk(path: &OsStr) -> Result<(u8, Vec<OsString>), &'static str> {
    let bytes = path.as_encoded_bytes();
    let (drive, rest, verbatim) = disk_prefix(bytes)?;
    let mut names = Vec::new();
    let mut start = 0usize;
    for (index, byte) in rest.iter().enumerate() {
        if !is_component_sep(*byte, verbatim) {
            continue;
        }
        push_component(&mut names, &rest[start..index])?;
        start = index + 1;
    }
    push_component(&mut names, &rest[start..])?;
    if names.is_empty() {
        return Err(NO_NAME);
    }
    Ok((drive, names))
}

#[cfg(any(windows, test))]
fn push_component(names: &mut Vec<OsString>, part: &[u8]) -> Result<(), &'static str> {
    if part.is_empty() {
        return Ok(());
    }
    // SAFETY: `part` is a subslice of an `OsStr`'s encoded bytes, cut only on
    // ASCII separators. Those cuts stay on encoded-character boundaries, so
    // `part` is valid OsStr bytes on Unix and valid WTF-8 on Windows.
    let name = unsafe { OsStr::from_encoded_bytes_unchecked(part) };
    if !one_component_name(name) {
        return Err(INVALID_COMPONENT);
    }
    names.push(name.to_os_string());
    Ok(())
}

#[cfg(any(windows, test))]
fn disk_prefix(bytes: &[u8]) -> Result<(u8, &[u8], bool), &'static str> {
    if let Some(rest) = bytes.strip_prefix(b"\\\\?\\") {
        let (drive, tail) = drive_root(rest)?;
        return Ok((drive, tail, true));
    }
    if let Some(rest) = bytes.strip_prefix(b"//?/") {
        let (drive, tail) = drive_root(rest)?;
        return Ok((drive, tail, true));
    }
    if matches!(bytes, [a, b, ..] if is_sep(*a) && is_sep(*b)) {
        return Err(NOT_ABSOLUTE);
    }
    let (drive, tail) = drive_root(bytes)?;
    Ok((drive, tail, false))
}

#[cfg(any(windows, test))]
fn drive_root(bytes: &[u8]) -> Result<(u8, &[u8]), &'static str> {
    let Some((letter, rest)) = bytes.split_first() else {
        return Err(NOT_ABSOLUTE);
    };
    if !letter.is_ascii_alphabetic() {
        return Err(NOT_ABSOLUTE);
    }
    let Some((colon, rest)) = rest.split_first() else {
        return Err(NOT_ABSOLUTE);
    };
    if *colon != b':' {
        return Err(NOT_ABSOLUTE);
    }
    let Some((sep, rest)) = rest.split_first() else {
        return Err(DRIVE_RELATIVE);
    };
    if !is_sep(*sep) {
        return Err(DRIVE_RELATIVE);
    }
    Ok((*letter, rest))
}

#[cfg(any(windows, test))]
fn is_sep(byte: u8) -> bool {
    byte == b'\\' || byte == b'/'
}

#[cfg(any(windows, test))]
fn is_component_sep(byte: u8, verbatim: bool) -> bool {
    byte == b'\\' || (!verbatim && byte == b'/')
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::{absolute_local_disk, one_component_name};

    #[test]
    fn one_component_name_rejects_empty_dot_and_separators() {
        for name in ["", ".", "..", "a/b", r"a\b", "a:b", "a\0b"] {
            assert!(!one_component_name(OsStr::new(name)), "{name:?}");
        }
        assert!(one_component_name(OsStr::new("device.key")));
        assert!(one_component_name(OsStr::new("identity")));
    }

    fn parsed(path: &str) -> Result<(char, Vec<String>), &'static str> {
        absolute_local_disk(OsStr::new(path)).map(|(drive, names)| {
            (
                drive as char,
                names
                    .into_iter()
                    .map(|name| name.to_string_lossy().into_owned())
                    .collect(),
            )
        })
    }

    #[test]
    fn absolute_local_disk_accepts_drive_paths_and_refuses_relative_ones() {
        assert_eq!(parsed(r"C:\k").unwrap(), ('C', vec!["k".to_owned()]));
        assert_eq!(
            parsed(r"C:\k\child").unwrap(),
            ('C', vec!["k".to_owned(), "child".to_owned()])
        );
        assert_eq!(
            parsed(r"c:/k/child").unwrap(),
            ('c', vec!["k".to_owned(), "child".to_owned()])
        );
        assert_eq!(
            parsed(r"C:\k\\child\").unwrap(),
            ('C', vec!["k".to_owned(), "child".to_owned()])
        );
        assert_eq!(
            parsed(r"C:\k/child").unwrap(),
            ('C', vec!["k".to_owned(), "child".to_owned()])
        );
        assert_eq!(
            parsed(r"\\?\D:\k\child").unwrap(),
            ('D', vec!["k".to_owned(), "child".to_owned()])
        );
        assert_eq!(parsed("//?/D:/k").unwrap(), ('D', vec!["k".to_owned()]));

        for (path, reason) in [
            ("child", "absolute local disk path required"),
            (r"k\child", "absolute local disk path required"),
            (r".\k", "absolute local disk path required"),
            (r"..\k", "absolute local disk path required"),
            (r"\k", "absolute local disk path required"),
            (r"\\server\share\k", "absolute local disk path required"),
            (r"\\.\C:\k", "absolute local disk path required"),
            (
                r"\\?\UNC\server\share\k",
                "absolute local disk path required",
            ),
            ("", "absolute local disk path required"),
            (r"C:k", "drive-relative path"),
            ("C:", "drive-relative path"),
            (r"C:\", "path has no file or directory name"),
            (r"\\?\C:\", "path has no file or directory name"),
            (r"C:\k\..\child", "invalid path component"),
            (r"C:\k\.\child", "invalid path component"),
            (r"C:\k:stream", "invalid path component"),
            ("C:\\k\\a\0b", "invalid path component"),
            (r"\\?\D:\k/child", "invalid path component"),
        ] {
            assert_eq!(parsed(path).unwrap_err(), reason, "{path}");
        }
    }
}
