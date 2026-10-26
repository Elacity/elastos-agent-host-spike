use std::fs;
use std::path::Path;

const ELF_MAGIC: &[u8] = b"\x7fELF";
const AR_MAGIC: &[u8] = b"!<arch>\n";
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
const E_MACHINE_OFF: usize = 18;
const AR_HEADER: usize = 60;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

fn expected_elf_machine(target: &str) -> u16 {
    if target.contains("aarch64") {
        EM_AARCH64
    } else if target.contains("x86_64") {
        EM_X86_64
    } else {
        panic!(
            "linux-confine: no ELF e_machine for TARGET={target}. \
             Real aarch64 execution is NOT RUN."
        );
    }
}

fn elf_machine_name(machine: u16) -> String {
    match machine {
        EM_AARCH64 => "EM_AARCH64=183".to_string(),
        EM_X86_64 => "EM_X86_64=62".to_string(),
        other => format!("e_machine={other}"),
    }
}

fn read_u16(bytes: &[u8], offset: usize, little: bool) -> Result<u16, String> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "ELF header is truncated".to_string())?;
    if little {
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
    } else {
        Ok(u16::from_be_bytes([slice[0], slice[1]]))
    }
}

fn elf_machine_from_bytes(bytes: &[u8]) -> Result<u16, String> {
    if bytes.len() < E_MACHINE_OFF + 2 || !bytes.starts_with(ELF_MAGIC) {
        return Err("not an ELF file".to_string());
    }
    let class = bytes[EI_CLASS];
    if class != ELFCLASS32 && class != ELFCLASS64 {
        return Err(format!("unknown ELF class {class}"));
    }
    let little = match bytes[EI_DATA] {
        ELFDATA2LSB => true,
        ELFDATA2MSB => false,
        other => return Err(format!("unknown ELF data encoding {other}")),
    };
    read_u16(bytes, E_MACHINE_OFF, little)
}

fn archive_payload<'a>(name: &str, data: &'a [u8]) -> &'a [u8] {
    let name = name.trim();
    let rest = name
        .strip_prefix("#1/")
        .map(|rest| rest.trim_end_matches('/').trim());
    if let Some(rest) = rest {
        if let Ok(n) = rest.parse::<usize>() {
            if n <= data.len() {
                return &data[n..];
            }
        }
    }
    data
}

fn elf_machine_from_archive(bytes: &[u8]) -> Result<u16, String> {
    if !bytes.starts_with(AR_MAGIC) {
        return Err("not an archive".to_string());
    }
    let mut off = AR_MAGIC.len();
    let mut found = None;
    while off + AR_HEADER <= bytes.len() {
        let header = &bytes[off..off + AR_HEADER];
        if &header[58..60] != b"`\n" {
            return Err("archive member header is truncated".to_string());
        }
        let name = std::str::from_utf8(&header[..16])
            .map_err(|_| "archive member name is not utf-8".to_string())?;
        let size_field = std::str::from_utf8(&header[48..58])
            .map_err(|_| "archive member size is not utf-8".to_string())?
            .trim();
        let size: usize = size_field
            .parse()
            .map_err(|_| format!("archive member size is not a number: {size_field}"))?;
        let data_off = off + AR_HEADER;
        let data_end = data_off
            .checked_add(size)
            .ok_or_else(|| "archive member size overflows".to_string())?;
        if data_end > bytes.len() {
            return Err("archive member runs past the file".to_string());
        }
        let payload = archive_payload(name, &bytes[data_off..data_end]);
        if payload.starts_with(ELF_MAGIC) {
            let machine = elf_machine_from_bytes(payload)?;
            match found {
                None => found = Some(machine),
                Some(prev) if prev != machine => {
                    return Err(format!(
                        "archive mixes {} and {}",
                        elf_machine_name(prev),
                        elf_machine_name(machine)
                    ));
                }
                Some(_) => {}
            }
        }
        off = data_end + (size % 2);
    }
    found.ok_or_else(|| "archive has no ELF member".to_string())
}

fn read_elf_machine(path: &Path) -> Result<u16, String> {
    let bytes = fs::read(path).map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    if bytes.starts_with(ELF_MAGIC) {
        elf_machine_from_bytes(&bytes)
    } else if bytes.starts_with(AR_MAGIC) {
        elf_machine_from_archive(&bytes)
    } else {
        Err(format!(
            "{} is not an ELF object or archive",
            path.display()
        ))
    }
}

fn assert_target_elf(path: &Path, target: &str) {
    let got = read_elf_machine(path).unwrap_or_else(|err| {
        panic!(
            "linux-confine: cannot read ELF e_machine of {}: {err}. \
             Real aarch64 execution is NOT RUN.",
            path.display()
        );
    });
    let want = expected_elf_machine(target);
    if got != want {
        panic!(
            "linux-confine: {} is {}, TARGET={target} needs {}. \
             TARGET_CC / CC_<target> produced the wrong architecture. \
             Real aarch64 execution is NOT RUN.",
            path.display(),
            elf_machine_name(got),
            elf_machine_name(want)
        );
    }
}
