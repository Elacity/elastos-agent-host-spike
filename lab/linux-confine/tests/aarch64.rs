//! Cross build of the launcher. Jetson execution is not this machine.
use std::process::Command;

fn compiler() -> Option<String> {
    let name = "aarch64-linux-gnu-gcc";
    if Command::new(name).arg("--version").output().is_ok() {
        Some(name.to_string())
    } else {
        None
    }
}

#[test]
fn aarch64_launcher_compiles() {
    let Some(cc) = compiler() else {
        eprintln!("aarch64 cross compiler is absent. NOT RUN");
        return;
    };
    let dir = std::env::temp_dir().join(format!("linux-confine-aarch64-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("helper");
    let setup = dir.join("lc-setup");
    let setup_test = dir.join("lc-setup-test");
    let probe = dir.join("lc-probe");
    let witness = dir.join("lc-witness.so");
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
    if Command::new("qemu-aarch64")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("qemu-aarch64 is absent. The aarch64 binaries compiled. Execution under qemu is NOT RUN. Jetson execution is NOT RUN.");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let explain = Command::new("qemu-aarch64")
        .args(["-L", "/usr/aarch64-linux-gnu"])
        .arg(&setup_test)
        .args(["--explain-abi", "6"])
        .output()
        .unwrap();
    assert!(
        explain.status.success(),
        "{}",
        String::from_utf8_lossy(&explain.stderr)
    );
    assert!(String::from_utf8_lossy(&explain.stdout).contains("abi-ok"));
    let low = Command::new("qemu-aarch64")
        .args(["-L", "/usr/aarch64-linux-gnu"])
        .arg(&setup_test)
        .args(["--explain-abi", "4"])
        .output()
        .unwrap();
    assert!(!low.status.success());
    assert!(String::from_utf8_lossy(&low.stdout).contains("device ioctl"));
    let blocked = Command::new("qemu-aarch64")
        .args(["-L", "/usr/aarch64-linux-gnu"])
        .arg(&setup)
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
        "{blocked_text}"
    );
    assert!(
        !blocked_text.contains("the kernel has no Landlock"),
        "{blocked_text}"
    );
    let probe_run = Command::new("qemu-aarch64")
        .arg(&probe)
        .arg("bound-child")
        .output()
        .unwrap();
    assert!(
        probe_run.status.success(),
        "{}",
        String::from_utf8_lossy(&probe_run.stderr)
    );
    assert!(String::from_utf8_lossy(&probe_run.stdout).contains("exec-bound"));
    eprintln!("aarch64 cross build and qemu-user check passed. Jetson execution is NOT RUN.");
    let _ = std::fs::remove_dir_all(&dir);
}

fn compile(cc: &str, args: &[&str]) -> bool {
    let output = Command::new(cc).args(args).output().unwrap();
    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
    output.status.success()
}
