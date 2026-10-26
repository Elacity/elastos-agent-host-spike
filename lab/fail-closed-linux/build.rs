//! Builds `probe/main.rs` as a fully static executable and exposes its path
//! as `FCL_PROBE`. A static probe needs no dynamic loader, so the Landlock
//! layer can grant only the storage root and the probe file itself.
//!
//! The probe is built only when the target is the build host. For any other
//! target `FCL_PROBE` is empty, so `cargo check --target ...` still works and
//! nothing for that target is executed.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=probe/main.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let target = env::var("TARGET").expect("cargo sets TARGET");
    let host = env::var("HOST").expect("cargo sets HOST");
    if target != host {
        println!("cargo:rustc-env=FCL_PROBE=");
        return;
    }

    let out = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR")).join("fcl-probe");
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let status = Command::new(rustc)
        .args([
            "--edition",
            "2021",
            "--crate-name",
            "fcl_probe",
            "--crate-type",
            "bin",
        ])
        .args(["-C", "opt-level=1", "-C", "panic=abort"])
        .args(["-C", "target-feature=+crt-static"])
        .args(["--target", &target])
        .arg("probe/main.rs")
        .arg("-o")
        .arg(&out)
        .status()
        .expect("cannot start rustc for the probe");
    assert!(status.success(), "the static probe did not build: {status}");
    println!("cargo:rustc-env=FCL_PROBE={}", out.display());
}
