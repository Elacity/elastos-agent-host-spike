//! The receipt binds the artifact to the exact toolchain and inputs, so a
//! rebuild can be checked against it (PRINCIPLES P13).

mod common;

use common::build::{lane_dir, run_build, rustc_version, sha256_file, Receipt, TempDir};

#[test]
fn the_receipt_names_the_exact_toolchain() {
    let lane = lane_dir();
    let tmp = TempDir::new("receipt-toolchain");
    let out = tmp.path().join("out");
    run_build(&lane, &out);
    let receipt = Receipt::read(&out);

    assert_eq!(
        receipt.get("rustc_version"),
        rustc_version(&lane),
        "the receipt must name the exact compiler tools/build used"
    );
    assert_eq!(
        receipt.get("target"),
        "wasm32-unknown-unknown",
        "the receipt must name the build target"
    );
}

/// An explicit `RUSTC` override must reach the receipt: the compiler Cargo is
/// told to build with is the one the receipt names, not a different `rustc` on
/// PATH. The stand-in reports a marker version and delegates every real task to
/// the true rustc, so the build still compiles. Unix-only: it writes an
/// executable shell stand-in, and the lane's tooling is Mac/Linux.
#[cfg(unix)]
#[test]
fn the_receipt_names_an_overridden_compiler() {
    use common::build::run_build_with_env;
    use std::os::unix::fs::PermissionsExt;

    const MARKER: &str = "rustc 1.91.0 (wc001-override-marker)";

    let lane = lane_dir();
    let tmp = TempDir::new("receipt-override");

    // A stand-in rustc: report MARKER for --version, delegate all else (-vV,
    // --print sysroot, real compiles) to the true rustc so the build succeeds.
    let fake_rustc = tmp.path().join("fake-rustc");
    std::fs::write(
        &fake_rustc,
        format!(
            "#!/usr/bin/env bash\n\
             if [ \"$1\" = \"--version\" ]; then\n\
             echo '{MARKER}'\n\
             exit 0\n\
             fi\n\
             exec rustc \"$@\"\n"
        ),
    )
    .expect("write fake rustc");
    std::fs::set_permissions(&fake_rustc, std::fs::Permissions::from_mode(0o755))
        .expect("chmod fake rustc");

    let out = tmp.path().join("out");
    run_build_with_env(
        &lane,
        &out,
        &[("RUSTC", fake_rustc.to_str().expect("utf8 temp path"))],
    );
    let receipt = Receipt::read(&out);

    assert_eq!(
        receipt.get("rustc_version"),
        MARKER,
        "the receipt must name the compiler RUSTC selected, not a PATH rustc"
    );
    assert_ne!(
        receipt.get("rustc_version"),
        rustc_version(&lane),
        "the override must actually differ from the default PATH compiler"
    );
}

#[test]
fn receipt_hashes_match_artifact_and_lockfile() {
    let lane = lane_dir();
    let tmp = TempDir::new("receipt-hashes");
    let out = tmp.path().join("out");
    run_build(&lane, &out);
    let receipt = Receipt::read(&out);

    assert_eq!(
        receipt.get("artifact_sha256"),
        sha256_file(&out.join("capsule.wasm")),
        "the receipt's artifact hash must match the built capsule"
    );
    assert_eq!(
        receipt.get("lockfile_sha256"),
        sha256_file(&lane.join("Cargo.lock")),
        "the receipt's lockfile hash must match Cargo.lock"
    );
}
