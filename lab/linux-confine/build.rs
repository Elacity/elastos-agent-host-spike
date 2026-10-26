use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let probe = out.join("lc-probe");
    let setup = out.join("lc-setup");
    compile(
        &cc,
        &probe,
        &manifest.join("helper/probe.c"),
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
        ],
    );
    compile(
        &cc,
        &setup,
        &manifest.join("helper/setup.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
    );
    println!("cargo:rustc-env=LC_PROBE={}", probe.display());
    println!("cargo:rustc-env=LC_SETUP={}", setup.display());
    println!("cargo:rerun-if-changed=helper/probe.c");
    println!("cargo:rerun-if-changed=helper/setup.c");
    println!("cargo:rerun-if-changed=build.rs");
}

fn compile(cc: &str, out: &PathBuf, src: &PathBuf, flags: &[&str]) {
    let output = Command::new(cc)
        .args(flags)
        .arg("-o")
        .arg(out)
        .arg(src)
        .output()
        .unwrap_or_else(|err| panic!("cannot run {cc}: {err}"));
    if !output.status.success() {
        panic!(
            "{cc} failed for {}\n{}",
            src.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
