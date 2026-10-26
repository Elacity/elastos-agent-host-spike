use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let (cc, target, host) = target_cc();
    let foreign = target != host;
    if foreign {
        eprintln!(
            "linux-confine: C helpers use {cc} for TARGET={target}. Real aarch64 execution is NOT RUN."
        );
    }
    let probe = out.join("lc-probe");
    let setup = out.join("lc-setup");
    let setup_test = out.join("lc-setup-test");
    let witness = out.join("lc-witness.so");
    compile(
        &cc,
        &target,
        foreign,
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
    // F-LC-BLOCK: the shipped launcher is this binary. It has no test hooks.
    let production_flags: &[&str] = &["-O2", "-Wall", "-Wextra", "-Werror"];
    compile(
        &cc,
        &target,
        foreign,
        &setup,
        &manifest.join("helper/setup.c"),
        production_flags,
    );
    compile(
        &cc,
        &target,
        foreign,
        &setup_test,
        &manifest.join("helper/setup.c"),
        &["-DLC_TEST_HOOKS", "-O2", "-Wall", "-Wextra", "-Werror"],
    );
    compile(
        &cc,
        &target,
        foreign,
        &witness,
        &manifest.join("helper/witness.c"),
        &["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"],
    );
    println!("cargo:rustc-env=LC_PROBE={}", probe.display());
    println!("cargo:rustc-env=LC_SETUP={}", setup.display());
    println!("cargo:rustc-env=LC_SETUP_TEST={}", setup_test.display());
    println!("cargo:rustc-env=LC_WITNESS={}", witness.display());
    println!("cargo:rerun-if-changed=helper/probe.c");
    println!("cargo:rerun-if-changed=helper/setup.c");
    println!("cargo:rerun-if-changed=helper/witness.c");
    println!("cargo:rerun-if-changed=build.rs");
}

/// Same lookup as the `cc` crate: `CC_<target>` with `-` → `_`, then
/// `TARGET_CC`, then a target-prefixed gcc. Host `CC` / `cc` is used only
/// when TARGET == HOST. A foreign target never falls back to the host
/// compiler. Real aarch64 execution is NOT RUN.
fn target_cc() -> (String, String, String) {
    let target = env::var("TARGET").expect("TARGET is set by cargo");
    let host = env::var("HOST").unwrap_or_default();
    let underscored = target.replace('-', "_");
    println!("cargo:rerun-if-env-changed=CC_{underscored}");
    println!("cargo:rerun-if-env-changed=CC_{target}");
    println!("cargo:rerun-if-env-changed=TARGET_CC");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=HOST");
    println!("cargo:rerun-if-env-changed=TARGET");
    if let Ok(cc) = env::var(format!("CC_{underscored}")) {
        if !cc.is_empty() {
            return (cc, target, host);
        }
    }
    if let Ok(cc) = env::var(format!("CC_{target}")) {
        if !cc.is_empty() {
            return (cc, target, host);
        }
    }
    if let Ok(cc) = env::var("TARGET_CC") {
        if !cc.is_empty() {
            return (cc, target, host);
        }
    }
    if target != host {
        if target.contains("aarch64") && target.contains("linux") {
            return ("aarch64-linux-gnu-gcc".to_string(), target, host);
        }
        panic!(
            "linux-confine: no C compiler for TARGET={target}. Set CC_{underscored}. \
             Host cc is not used for a foreign target. Real aarch64 execution is NOT RUN."
        );
    }
    (
        env::var("CC").unwrap_or_else(|_| "cc".to_string()),
        target,
        host,
    )
}

fn compile(cc: &str, target: &str, foreign: bool, out: &PathBuf, src: &PathBuf, flags: &[&str]) {
    let output = Command::new(cc)
        .args(flags)
        .arg("-o")
        .arg(out)
        .arg(src)
        .output()
        .unwrap_or_else(|err| {
            if foreign {
                panic!(
                    "cannot run {cc} for TARGET={target}: {err}. \
                     Set CC_{}. Host cc is not used for a foreign target. \
                     Real aarch64 execution is NOT RUN.",
                    target.replace('-', "_")
                );
            }
            panic!("cannot run {cc}: {err}")
        });
    if !output.status.success() {
        if foreign {
            panic!(
                "{cc} failed for {} TARGET={target}\n{}\n\
                 Host cc is not used for a foreign target. Real aarch64 execution is NOT RUN.",
                src.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        panic!(
            "{cc} failed for {}\n{}",
            src.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
