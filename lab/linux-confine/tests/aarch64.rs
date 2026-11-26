//! aarch64 build + qemu-user (host kernel).
//!
//! This test is never native aarch64 and never Jetson. qemu-user translates
//! guest instructions and forwards implemented syscalls to the x86_64 host
//! kernel. qemu 8.2.2 does not implement landlock_* (unknown syscall
//! 444/445/446, ENOSYS). `--explain-abi` only checks a compiled table and
//! does not call Landlock.
use std::path::{Path, PathBuf};
use std::process::Command;

const MODE: &str = "aarch64 build + qemu-user (host kernel)";
const EM_AARCH64: u16 = 183;
const ENOSYS: i32 = 38;

fn compiler() -> Option<String> {
    let name = "aarch64-linux-gnu-gcc";
    if Command::new(name).arg("--version").output().is_ok() {
        Some(name.to_string())
    } else {
        None
    }
}

fn qemu_user() -> Option<String> {
    if Command::new("qemu-aarch64")
        .arg("--version")
        .output()
        .is_ok()
    {
        Some("qemu-aarch64".to_string())
    } else {
        None
    }
}

fn elf_machine(path: &Path) -> u16 {
    let bytes = std::fs::read(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    assert!(
        bytes.len() > 20 && bytes.starts_with(b"\x7fELF"),
        "{} is not ELF",
        path.display()
    );
    u16::from_le_bytes([bytes[18], bytes[19]])
}

fn qemu_cmd(qemu: &str, bin: &Path) -> Command {
    let mut cmd = Command::new(qemu);
    if !bin
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.contains("lc-probe"))
    {
        cmd.args(["-L", "/usr/aarch64-linux-gnu"]);
    }
    cmd.arg(bin);
    cmd
}

fn compile(cc: &str, args: &[&str]) -> bool {
    let output = Command::new(cc).args(args).output().unwrap();
    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
    output.status.success()
}

fn parse_errno_line(text: &str, name: &str) -> (i64, i32) {
    for line in text.lines() {
        if !line.starts_with(name) {
            continue;
        }
        let mut ret = None;
        let mut errno = None;
        for part in line.split_whitespace() {
            if let Some(v) = part.strip_prefix("ret=") {
                ret = v.parse().ok();
            }
            if let Some(v) = part.strip_prefix("errno=") {
                errno = v.parse().ok();
            }
        }
        return (ret.expect(line), errno.expect(line));
    }
    panic!("missing {name} in:\n{text}");
}

#[test]
fn qemu_user_mode_label_is_not_native_or_jetson() {
    assert_eq!(MODE, "aarch64 build + qemu-user (host kernel)");
    let lower = MODE.to_ascii_lowercase();
    assert!(MODE.contains("qemu-user"), "{MODE}");
    assert!(MODE.contains("host kernel"), "{MODE}");
    assert!(!lower.contains("jetson"), "{MODE}");
    assert!(!lower.contains("native"), "{MODE}");
}

#[test]
fn parse_errno_line_reads_ret_and_errno() {
    let text = "landlock_create_ruleset nr=444 ret=-1 errno=38 (Function not implemented)\n";
    assert_eq!(
        parse_errno_line(text, "landlock_create_ruleset"),
        (-1, ENOSYS)
    );
}

#[test]
#[ignore = "needs aarch64-linux-gnu-gcc and qemu-aarch64; aarch64 build + qemu-user (host kernel); never native/Jetson"]
fn aarch64_qemu_user_host_kernel() {
    let Some(cc) = compiler() else {
        panic!(
            "{MODE}: aarch64 cross compiler is absent. NOT RUN. \
             This ignored test must not count as a pass."
        );
    };
    let Some(qemu) = qemu_user() else {
        panic!(
            "{MODE}: qemu-aarch64 is absent. NOT RUN. \
             This ignored test must not count as a pass."
        );
    };
    let dir = std::env::temp_dir().join(format!("linux-confine-aarch64-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("helper");
    let setup = dir.join("lc-setup");
    let setup_test = dir.join("lc-setup-test");
    let probe = dir.join("lc-probe");
    let witness = dir.join("lc-witness.so");
    let landlock = dir.join("landlock-probe");
    assert!(compile(
        &cc,
        &[
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o",
            setup.to_str().unwrap(),
            src.join("setup.c").to_str().unwrap(),
        ],
    ));
    assert!(compile(
        &cc,
        &[
            "-DLC_TEST_HOOKS",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o",
            setup_test.to_str().unwrap(),
            src.join("setup.c").to_str().unwrap(),
        ],
    ));
    assert!(compile(
        &cc,
        &[
            "-static",
            "-nostdlib",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o",
            probe.to_str().unwrap(),
            src.join("probe.c").to_str().unwrap(),
        ],
    ));
    assert!(compile(
        &cc,
        &[
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o",
            witness.to_str().unwrap(),
            src.join("witness.c").to_str().unwrap(),
        ],
    ));
    assert!(compile(
        &cc,
        &[
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-o",
            landlock.to_str().unwrap(),
            src.join("landlock-probe.c").to_str().unwrap(),
        ],
    ));
    for path in [&setup, &setup_test, &probe, &witness, &landlock] {
        let machine = elf_machine(path);
        assert_eq!(
            machine,
            EM_AARCH64,
            "{MODE}: {} e_machine={machine}, want EM_AARCH64=183",
            path.display()
        );
    }

    // Real Landlock syscalls. qemu-user 8.2.2 does not implement them.
    let probe_out = qemu_cmd(&qemu, &landlock).output().unwrap();
    let probe_text = format!(
        "{}{}",
        String::from_utf8_lossy(&probe_out.stdout),
        String::from_utf8_lossy(&probe_out.stderr)
    );
    assert!(
        probe_out.status.success(),
        "{MODE}: landlock-probe failed: {probe_text}"
    );
    assert!(
        probe_text.contains("mode=aarch64-build-plus-qemu-user-host-kernel")
            && probe_text.contains("native=0")
            && probe_text.contains("jetson=0"),
        "{MODE}: probe lost its label:\n{probe_text}"
    );
    for name in [
        "landlock_create_ruleset",
        "landlock_add_rule",
        "landlock_restrict_self",
    ] {
        let (ret, errno) = parse_errno_line(&probe_text, name);
        assert_eq!(
            (ret, errno),
            (-1, ENOSYS),
            "{MODE}: {name} under qemu-user must be ENOSYS (qemu 8.2.2 \
             unknown syscall). This is not an ARM kernel and not Jetson. \
             got ret={ret} errno={errno}\n{probe_text}"
        );
    }
    eprintln!("{MODE}: landlock_* = ENOSYS (qemu-user 8.2.2 does not implement 444/445/446)");

    // Launcher calls landlock_abi() unless --explain-abi is used.
    let real_abi = qemu_cmd(&qemu, &setup_test).output().unwrap();
    let real_text = format!(
        "{}{}",
        String::from_utf8_lossy(&real_abi.stdout),
        String::from_utf8_lossy(&real_abi.stderr)
    );
    assert!(
        !real_abi.status.success() && real_text.contains("the kernel has no Landlock"),
        "{MODE}: launcher must fail closed when qemu-user returns ENOSYS:\n{real_text}"
    );

    // --explain-abi is a compiled table. It does not call Landlock.
    let explain = qemu_cmd(&qemu, &setup_test)
        .args(["--explain-abi", "6"])
        .output()
        .unwrap();
    assert!(
        explain.status.success(),
        "{MODE}: {}",
        String::from_utf8_lossy(&explain.stderr)
    );
    assert!(
        String::from_utf8_lossy(&explain.stdout).contains("abi-ok"),
        "{MODE}: --explain-abi 6 is a table check, not a kernel probe"
    );
    let low = qemu_cmd(&qemu, &setup_test)
        .args(["--explain-abi", "4"])
        .output()
        .unwrap();
    assert!(!low.status.success());
    assert!(String::from_utf8_lossy(&low.stdout).contains("device ioctl"));

    let blocked = qemu_cmd(&qemu, &setup)
        .arg("--block-landlock")
        .output()
        .unwrap();
    let blocked_text = format!(
        "{}{}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert!(
        !blocked.status.success() && blocked_text.contains("unknown launch argument"),
        "{MODE}: {blocked_text}"
    );
    assert!(
        !blocked_text.contains("the kernel has no Landlock"),
        "{MODE}: production --block-landlock must stay unknown, not a Landlock probe: {blocked_text}"
    );

    let probe_run = qemu_cmd(&qemu, &probe).arg("bound-child").output().unwrap();
    assert!(
        probe_run.status.success(),
        "{MODE}: {}",
        String::from_utf8_lossy(&probe_run.stderr)
    );
    assert!(String::from_utf8_lossy(&probe_run.stdout).contains("exec-bound"));
    eprintln!(
        "{MODE}: helpers are EM_AARCH64; landlock_* ENOSYS; launcher fail-closed. \
         Never native aarch64. Never Jetson."
    );
    let _ = std::fs::remove_dir_all(&dir);
}
