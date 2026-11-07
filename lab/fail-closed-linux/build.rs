//! Builds `probe/main.rs` and `probe/silent.rs` as fully static executables
//! and exposes their paths as `FCL_PROBE` and `FCL_SILENT`. A static probe
//! needs no dynamic loader, so the Landlock layer can grant only the storage
//! root and the probe file itself.
//!
//! When TARGET equals HOST the probes are built with the host rustc. When
//! TARGET differs, they are built only if a cross linker is set
//! (`CARGO_TARGET_*_LINKER` or `CC_<target>`), so `cargo check --target`
//! without a cross compiler still works and nothing for that target is
//! executed.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=probe/main.rs");
    println!("cargo:rerun-if-changed=probe/silent.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let target = env::var("TARGET").expect("cargo sets TARGET");
    let host = env::var("HOST").expect("cargo sets HOST");
    let linker = cross_linker(&target);
    if target != host && linker.is_none() {
        println!("cargo:rustc-env=FCL_PROBE=");
        println!("cargo:rustc-env=FCL_SILENT=");
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    build_static(
        &rustc,
        &target,
        linker.as_deref(),
        "fcl_probe",
        "probe/main.rs",
        out_dir.join("fcl-probe"),
        "FCL_PROBE",
    );
    build_static(
        &rustc,
        &target,
        linker.as_deref(),
        "fcl_silent",
        "probe/silent.rs",
        out_dir.join("fcl-silent"),
        "FCL_SILENT",
    );
}

fn env_target_key(target: &str) -> String {
    target.to_uppercase().replace('-', "_")
}

fn cross_linker(target: &str) -> Option<String> {
    let key = env_target_key(target);
    env::var(format!("CARGO_TARGET_{key}_LINKER"))
        .or_else(|_| env::var(format!("CC_{key}")))
        .ok()
        .filter(|value| !value.is_empty())
}

fn build_static(
    rustc: &str,
    target: &str,
    linker: Option<&str>,
    crate_name: &str,
    src: &str,
    out: PathBuf,
    env_name: &str,
) {
    let mut cmd = Command::new(rustc);
    cmd.args([
        "--edition",
        "2021",
        "--crate-name",
        crate_name,
        "--crate-type",
        "bin",
    ])
    .args(["-C", "opt-level=1", "-C", "panic=abort"])
    .args(["-C", "target-feature=+crt-static"])
    .args(["--target", target]);
    if let Some(linker) = linker {
        cmd.args(["-C", &format!("linker={linker}")]);
    }
    let status = cmd
        .arg(src)
        .arg("-o")
        .arg(&out)
        .status()
        .unwrap_or_else(|_| panic!("cannot start rustc for {crate_name}"));
    assert!(
        status.success(),
        "the static {crate_name} did not build: {status}"
    );
    println!("cargo:rustc-env={env_name}={}", out.display());
}
