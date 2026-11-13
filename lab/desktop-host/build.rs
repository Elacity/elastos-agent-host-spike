use std::path::PathBuf;
use std::process::Command;

fn xcrun(args: &[&str]) -> String {
    let output = Command::new("xcrun").args(args).output().expect("xcrun");
    assert!(output.status.success(), "xcrun {args:?} failed");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn main() {
    println!("cargo:rerun-if-changed=src/enclave.swift");
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() != "macos" {
        return;
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        other => panic!("unsupported architecture {other}"),
    };
    let status = Command::new("xcrun")
        .args([
            "swiftc",
            "-O",
            "-parse-as-library",
            "-emit-library",
            "-static",
        ])
        .args(["-module-name", "ElastosEnclave", "-target"])
        .arg(format!("{arch}-apple-macos13.0"))
        .arg("src/enclave.swift")
        .arg("-o")
        .arg(out.join("libelastos_enclave.a"))
        .status()
        .expect("swiftc");
    assert!(status.success(), "swiftc failed");
    let swiftc = PathBuf::from(xcrun(&["-f", "swiftc"]));
    let toolchain = swiftc.parent().unwrap().join("../lib/swift/macosx");
    let sdk = xcrun(&["--show-sdk-path"]);
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-search=native={}", toolchain.display());
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    println!("cargo:rustc-link-lib=static=elastos_enclave");
    for framework in ["CryptoKit", "LocalAuthentication", "Security", "Foundation"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
