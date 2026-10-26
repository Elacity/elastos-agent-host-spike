//! ELF e_machine reader used by build.rs after a foreign-target compile.
use std::path::PathBuf;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/elf_machine.rs"));

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tmp() -> Tmp {
    let path = std::env::temp_dir().join(format!("linux-confine-elf-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    Tmp(path)
}

fn elf64_le(machine: u16) -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes
}

fn elf64_be(machine: u16) -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 2;
    bytes[6] = 1;
    bytes[18..20].copy_from_slice(&machine.to_be_bytes());
    bytes
}

fn elf32_le(machine: u16) -> Vec<u8> {
    let mut bytes = vec![0u8; 52];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes
}

fn write_ar(path: &Path, members: &[(&str, &[u8])]) {
    let mut out = Vec::from(&b"!<arch>\n"[..]);
    for (name, member) in members {
        let mut header = [b' '; 60];
        let field = format!("{name}/");
        header[..field.len()].copy_from_slice(field.as_bytes());
        let size = member.len().to_string();
        header[48..48 + size.len()].copy_from_slice(size.as_bytes());
        header[58] = b'`';
        header[59] = b'\n';
        out.extend_from_slice(&header);
        out.extend_from_slice(member);
        if member.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    fs::write(path, out).unwrap();
}

fn host_machine() -> u16 {
    if cfg!(target_arch = "x86_64") {
        EM_X86_64
    } else if cfg!(target_arch = "aarch64") {
        EM_AARCH64
    } else {
        panic!("this test names only x86_64 and aarch64");
    }
}

fn other_target() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "aarch64-unknown-linux-gnu"
    } else if cfg!(target_arch = "aarch64") {
        "x86_64-unknown-linux-gnu"
    } else {
        panic!("this test names only x86_64 and aarch64");
    }
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else {
        String::new()
    }
}

#[test]
fn expected_machine_maps_aarch64_and_x86_64() {
    assert_eq!(
        expected_elf_machine("aarch64-unknown-linux-gnu"),
        EM_AARCH64
    );
    assert_eq!(expected_elf_machine("x86_64-unknown-linux-gnu"), EM_X86_64);
}

#[test]
fn reads_elf64_le_be_and_elf32_le() {
    let dir = tmp();
    let a64 = dir.0.join("a64");
    let x64be = dir.0.join("x64be");
    let a32 = dir.0.join("a32");
    fs::write(&a64, elf64_le(EM_AARCH64)).unwrap();
    fs::write(&x64be, elf64_be(EM_X86_64)).unwrap();
    fs::write(&a32, elf32_le(EM_AARCH64)).unwrap();
    assert_eq!(read_elf_machine(&a64).unwrap(), EM_AARCH64);
    assert_eq!(read_elf_machine(&x64be).unwrap(), EM_X86_64);
    assert_eq!(read_elf_machine(&a32).unwrap(), EM_AARCH64);
}

#[test]
fn reads_archive_member_and_refuses_a_mixed_archive() {
    let dir = tmp();
    let ok = dir.0.join("ok.a");
    let mixed = dir.0.join("mixed.a");
    let a64 = elf64_le(EM_AARCH64);
    let x64 = elf64_le(EM_X86_64);
    write_ar(&ok, &[("/", b"sym"), ("probe.o", &a64)]);
    write_ar(&mixed, &[("a.o", &a64), ("b.o", &x64)]);
    assert_eq!(read_elf_machine(&ok).unwrap(), EM_AARCH64);
    let err = read_elf_machine(&mixed).unwrap_err();
    assert!(err.contains("archive mixes"), "{err}");
}

#[test]
fn host_helpers_match_host_elf_machine() {
    let want = host_machine();
    for path in [
        env!("LC_PROBE"),
        env!("LC_SETUP"),
        env!("LC_SETUP_TEST"),
        env!("LC_WITNESS"),
    ] {
        assert_eq!(read_elf_machine(Path::new(path)).unwrap(), want, "{path}");
    }
}

#[test]
fn host_helper_is_refused_for_the_other_arch() {
    let err = std::panic::catch_unwind(|| {
        assert_target_elf(Path::new(env!("LC_PROBE")), other_target());
    })
    .expect_err("a host-arch helper must not pass the other TARGET");
    let text = panic_text(err);
    assert!(
        text.contains("wrong architecture"),
        "missing refusal: {text}"
    );
}

#[test]
fn matching_object_is_accepted() {
    let dir = tmp();
    let path = dir.0.join("ok");
    fs::write(&path, elf64_le(EM_AARCH64)).unwrap();
    assert_target_elf(&path, "aarch64-unknown-linux-gnu");
}
