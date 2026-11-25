//! `DT_NEEDED` sonames from an open ELF.
//!
//! The caller reads the bytes. A file that is not an ELF has no sonames. A
//! dynamic section that is not a bounded table ending in `DT_NULL`, or a
//! string that does not sit in a load, is refused by `label`.

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

/// `loader` is always required. A name in `needed` is required. With no
/// program descriptor, `libc.so.6` and `libgcc_s.so.1` stay required.
pub fn library_required(name: &str, loader: &str, needed: Option<&[String]>) -> bool {
    name == loader
        || needed.is_some_and(|list| list.iter().any(|item| item == name))
        || needed.is_none() && matches!(name, "libc.so.6" | "libgcc_s.so.1")
}

/// A program-header offset that does not fit in `u64`. The sentence names the executable.
pub const UNUSABLE_PROGRAM_HEADERS: &str =
    "provider start is refused: the executable program headers are not usable";

fn checked_offset(base: u64, index: u64, step: u64) -> Option<u64> {
    index
        .checked_mul(step)
        .and_then(|scaled| base.checked_add(scaled))
}

/// File offset of one program header. Overflow is `UNUSABLE_PROGRAM_HEADERS`.
pub fn ph_at(base: u64, index: u64, step: u64) -> Result<u64, String> {
    checked_offset(base, index, step).ok_or_else(|| UNUSABLE_PROGRAM_HEADERS.to_string())
}

/// Read `DT_NEEDED` through `read`. `read` fills the buffer from the file
/// offset and returns false when the bytes are not there.
pub fn dt_needed(
    mut read: impl FnMut(&mut [u8], u64) -> bool,
    label: &str,
) -> Result<Vec<String>, String> {
    let bad = || format!("provider start is refused: {label} dynamic section is malformed");
    let mut magic = [0u8; 4];
    if !read(&mut magic, 0) {
        return Err(bad());
    }
    if &magic != b"\x7fELF" {
        return Ok(Vec::new());
    }
    let mut header = [0u8; 64];
    header[..4].copy_from_slice(&magic);
    if !read(&mut header[4..], 4) || header[4] != 2 || header[5] != 1 {
        return Err(bad());
    }
    let (phoff, entsize, phnum) = (
        le_u64(&header[32..40]),
        u16::from_le_bytes(header[54..56].try_into().unwrap()) as u64,
        u16::from_le_bytes(header[56..58].try_into().unwrap()) as u64,
    );
    if entsize < 56 || phnum > 128 {
        return Err(bad());
    }
    let mut loads = Vec::new();
    let mut dynamic = None;
    for index in 0..phnum {
        let mut ph = [0u8; 56];
        let at = checked_offset(phoff, index, entsize).ok_or_else(bad)?;
        if !read(&mut ph, at) {
            return Err(bad());
        }
        let (kind, off, addr, filesz) = (
            u32::from_le_bytes(ph[..4].try_into().unwrap()),
            le_u64(&ph[8..16]),
            le_u64(&ph[16..24]),
            le_u64(&ph[32..40]),
        );
        if kind == 1 {
            loads.push((off, addr, filesz));
        } else if kind == 2 {
            dynamic = Some((off, filesz));
        }
    }
    let Some((off, filesz)) = dynamic else {
        return Ok(Vec::new());
    };
    if filesz == 0 || filesz > 65536 || filesz % 16 != 0 {
        return Err(bad());
    }
    let mut table = vec![0u8; filesz as usize];
    if !read(&mut table, off) {
        return Err(bad());
    }
    let (mut strtab, mut strsz, mut rels, mut saw_null) = (None, None, Vec::new(), false);
    for entry in table.chunks_exact(16) {
        match i64::from_le_bytes(entry[..8].try_into().unwrap()) {
            0 => {
                saw_null = true;
                break;
            }
            1 => rels.push(le_u64(&entry[8..16])),
            5 => strtab = Some(le_u64(&entry[8..16])),
            10 => strsz = Some(le_u64(&entry[8..16])),
            _ => {}
        }
    }
    if !saw_null {
        return Err(bad());
    }
    if rels.is_empty() {
        return Ok(Vec::new());
    }
    let (Some(strtab), Some(strsz)) = (strtab, strsz) else {
        return Err(bad());
    };
    if strsz == 0 || strsz > (1 << 20) {
        return Err(bad());
    }
    let Some((load_off, load_addr, _load_len)) = loads.into_iter().find(|(_, addr, len)| {
        strtab >= *addr && strtab - addr < *len && strsz <= *len - (strtab - addr)
    }) else {
        return Err(bad());
    };
    let mut strings = vec![0u8; strsz as usize];
    let at = load_off.checked_add(strtab - load_addr).ok_or_else(bad)?;
    if !read(&mut strings, at) {
        return Err(bad());
    }
    rels.into_iter()
        .map(|rel| {
            if rel >= strsz {
                return Err(bad());
            }
            let start = rel as usize;
            let end = strings[start..]
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(bad)?;
            if end == 0 || end > 4096 {
                return Err(bad());
            }
            std::str::from_utf8(&strings[start..start + end])
                .map(|name| name.to_string())
                .map_err(|_| bad())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::dt_needed;

    fn read_from(bytes: &[u8]) -> impl FnMut(&mut [u8], u64) -> bool + '_ {
        move |buf, off| {
            let start = off as usize;
            let end = start + buf.len();
            if end > bytes.len() {
                return false;
            }
            buf.copy_from_slice(&bytes[start..end]);
            true
        }
    }

    fn elf_with_needed(needed: &[&str]) -> Vec<u8> {
        let mut strings = vec![0u8];
        let mut rels = Vec::new();
        for name in needed {
            rels.push(strings.len() as u64);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let dyn_off = 64 + 56 * 2;
        let dyn_len = (3 + rels.len()) * 16;
        let str_off = dyn_off + dyn_len;
        let mut buf = vec![0u8; str_off + strings.len()];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2;
        buf[5] = 1;
        buf[32..40].copy_from_slice(&64u64.to_le_bytes());
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        buf[56..58].copy_from_slice(&2u16.to_le_bytes());
        let write_ph = |buf: &mut [u8], at: usize, kind: u32, off: u64, size: u64| {
            buf[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            buf[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
            buf[at + 16..at + 24].copy_from_slice(&off.to_le_bytes());
            buf[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
        };
        let load_len = buf.len() as u64;
        write_ph(&mut buf, 64, 1, 0, load_len);
        write_ph(&mut buf, 64 + 56, 2, dyn_off as u64, dyn_len as u64);
        let mut at = dyn_off;
        let write_dyn = |buf: &mut [u8], at: &mut usize, tag: i64, val: u64| {
            buf[*at..*at + 8].copy_from_slice(&tag.to_le_bytes());
            buf[*at + 8..*at + 16].copy_from_slice(&val.to_le_bytes());
            *at += 16;
        };
        write_dyn(&mut buf, &mut at, 5, str_off as u64);
        write_dyn(&mut buf, &mut at, 10, strings.len() as u64);
        for rel in rels {
            write_dyn(&mut buf, &mut at, 1, rel);
        }
        write_dyn(&mut buf, &mut at, 0, 0);
        buf[str_off..].copy_from_slice(&strings);
        buf
    }

    #[test]
    fn needed_names_come_back_and_a_bad_table_is_refused() {
        let image = elf_with_needed(&["libc.so.6", "libgcc_s.so.1"]);
        let names = dt_needed(read_from(&image), "the executable").unwrap();
        assert_eq!(names, ["libc.so.6", "libgcc_s.so.1"]);
        assert!(dt_needed(read_from(b"library"), "libc.so.6")
            .unwrap()
            .is_empty());
        let mut bad = vec![0u8; 64 + 56];
        bad[0..4].copy_from_slice(b"\x7fELF");
        bad[4] = 2;
        bad[5] = 1;
        bad[32..40].copy_from_slice(&64u64.to_le_bytes());
        bad[54..56].copy_from_slice(&56u16.to_le_bytes());
        bad[56..58].copy_from_slice(&1u16.to_le_bytes());
        bad[64..68].copy_from_slice(&2u32.to_le_bytes());
        bad[96..104].copy_from_slice(&8u64.to_le_bytes());
        let err = dt_needed(read_from(&bad), "the executable").unwrap_err();
        assert!(
            err.contains("the executable dynamic section is malformed"),
            "{err}"
        );
    }

    #[test]
    fn a_wrapping_offset_is_refused_by_name() {
        let mut image = elf_with_needed(&["libgcc_s.so.1"]);
        image[64 + 8..64 + 16].copy_from_slice(&(u64::MAX - 5).to_le_bytes());
        let err = dt_needed(read_from(&image), "libgcc_s.so.1").unwrap_err();
        assert!(
            err.contains("libgcc_s.so.1 dynamic section is malformed"),
            "{err}"
        );

        let header = {
            let mut image = elf_with_needed(&["libc.so.6"]);
            image[32..40].copy_from_slice(&(u64::MAX - 20).to_le_bytes());
            image
        };
        let read = |buf: &mut [u8], off: u64| {
            let Some(start) = usize::try_from(off).ok() else {
                buf.fill(0);
                return true;
            };
            let Some(end) = start.checked_add(buf.len()) else {
                buf.fill(0);
                return true;
            };
            if end > header.len() {
                buf.fill(0);
                return true;
            }
            buf.copy_from_slice(&header[start..end]);
            true
        };
        let err = dt_needed(read, "the executable").unwrap_err();
        assert!(
            err.contains("the executable dynamic section is malformed"),
            "{err}"
        );
        let err = super::ph_at(u64::MAX - 20, 1, 56).unwrap_err();
        assert!(
            err.contains("the executable program headers are not usable"),
            "{err}"
        );
    }
}
