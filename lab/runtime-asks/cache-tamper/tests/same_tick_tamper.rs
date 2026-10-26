//! Reproduction for `lab/runtime-asks/cache-tamper.md`.
//!
//! Two Runtime caches treat a file as unchanged while its dev, inode, size,
//! mode, mtime and ctime stay the same. Before multigrain timestamps, Linux
//! stamps mtime and ctime from `CLOCK_REALTIME_COARSE`, so every change inside
//! one clock tick gets the same stamp.
//!
//! Each attempt waits for a fresh tick, makes the last legitimate change, lets
//! the Runtime record the file, and rewrites the same number of bytes, all in
//! that tick. The publication test also restores mtime with utimensat, so only
//! ctime can show the change. Each attempt then checks the precondition: every
//! stat field the Runtime compares is equal and the bytes differ. An attempt
//! that crosses a tick is discarded. The result never rests on timing luck.
//!
//! These tests assert today's Runtime behaviour. They must fail once Runtime
//! re-verifies an entry whose ctime is not safely older than its record time.
#![cfg(target_os = "linux")]

use elastos_server::release_publication::Publication;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const ATTEMPTS: usize = 200;

fn coarse_now() -> (libc::time_t, libc::c_long) {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &mut now) },
        0
    );
    (now.tv_sec, now.tv_nsec)
}

fn wait_for_fresh_tick() {
    let start = coarse_now();
    while coarse_now() == start {
        std::hint::spin_loop();
    }
}

/// The union of the fields both Runtime caches compare.
#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    size: u64,
    mode: u32,
    nlink: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

fn stamp(path: &Path) -> Stamp {
    let m = fs::symlink_metadata(path).unwrap();
    assert!(m.is_file());
    Stamp {
        dev: m.dev(),
        ino: m.ino(),
        size: m.len(),
        mode: m.mode(),
        nlink: m.nlink(),
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn rewrite_in_place(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .write_all_at(bytes, 0)
        .unwrap();
}

/// Restore mtime only. ctime is the remaining stamp; utimensat cannot set it.
fn restore_mtime(path: &Path, mtime: (i64, i64)) {
    let c_path = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()))
        .unwrap();
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: mtime.0,
            tv_nsec: mtime.1,
        },
    ];
    assert_eq!(
        unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) },
        0
    );
}

fn no_attempt_kept_the_stamp() -> ! {
    panic!(
        "no attempt kept the stat identity across a same-size rewrite in {ATTEMPTS} tries: \
         this filesystem gives every write a new timestamp, so the gap does not reproduce here"
    )
}

/// A source-Home image set at the Linux paths `verify_legacy_or_missing_release` reads.
fn write_image_set(data: &Path, rootfs: &[u8]) -> [PathBuf; 4] {
    let guest = if cfg!(target_arch = "aarch64") {
        "linux-arm64"
    } else {
        "linux-amd64"
    };
    let mut receipt = json!({
        "schema":"elastos.browser.vm-rootfs-build/v1", "ok":true, "target_platform":guest,
        "size":rootfs.len(), "sha256":sha256(rootfs),
        "kernel":{"size":6,"sha256":sha256(b"kernel")},
        "initrd":{"size":6,"sha256":sha256(b"initrd")},
        "preflight":{"ok":true,"audio_default_ready":true,"missing":[],"manifest_errors":[],"script_errors":[],
            "manifest":{"schema":"elastos.browser.vm-target/v1","engine":"chromium_microvm","network_mode":"runtime_net_only","direct_network":false,"wallet_injection":false,"media_transport":"runtime_relay","display_mode":"webrtc_remote_display","guarantee_level":"mechanism_microvm","control_transport":"vsock_relay","control_port":19092,"runtime_exit_transport":"vsock_relay","display_backend":"vm_selkies_gstreamer_webrtc"}}
    });
    for (group, names) in [
        ("required", "manifest init native_proxy runtime_relay guest_control_bridge control_service selkies_start node chromium xvfb python3 gst_inspect"),
        ("optional_audio", "pipewire pipewire_pulse wireplumber pw_cli"),
    ] {
        receipt["preflight"][group] = names
            .split_whitespace()
            .map(|name| (name.to_owned(), json!({"ok":true})))
            .collect::<serde_json::Map<_, _>>()
            .into();
    }
    let dir = data.join("browser-vm");
    fs::create_dir_all(&dir).unwrap();
    let paths = [
        "browser-vm-rootfs-manifest.json",
        "rootfs.ext4",
        "vmlinux",
        "initrd",
    ]
    .map(|name| dir.join(name));
    let bytes = [
        serde_json::to_vec(&receipt).unwrap(),
        rootfs.to_vec(),
        b"kernel".to_vec(),
        b"initrd".to_vec(),
    ];
    for (path, bytes) in paths.iter().zip(bytes) {
        fs::write(path, bytes).unwrap();
    }
    paths
}

#[test]
fn browser_image_check_admits_a_same_size_rootfs_rewrite_from_the_same_tick() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let ensure = |data: &Path| {
        runtime.block_on(elastos_server::setup::ensure_browser_vm_image_for_local_engine(data))
    };
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let warm = base.join("warm");
    write_image_set(&warm, b"working-image");
    ensure(&warm).expect("a valid image set verifies");

    for attempt in 1..=ATTEMPTS {
        let data = base.join(attempt.to_string());
        fs::create_dir_all(data.join("browser-vm")).unwrap();
        wait_for_fresh_tick();
        let paths = write_image_set(&data, b"working-image");
        ensure(&data).expect("a valid image set verifies");
        let recorded: Vec<Stamp> = paths.iter().map(|path| stamp(path)).collect();
        rewrite_in_place(&paths[1], b"changed-image");
        restore_mtime(&paths[1], recorded[1].mtime);
        if paths.iter().map(|path| stamp(path)).collect::<Vec<_>>() != recorded {
            continue;
        }
        let receipt: Value = serde_json::from_slice(&fs::read(&paths[0]).unwrap()).unwrap();
        let on_disk = sha256(&fs::read(&paths[1]).unwrap());
        assert_ne!(on_disk, receipt["sha256"].as_str().unwrap());
        println!(
            "attempt {attempt}: stamp unchanged, receipt sha256 {}, rootfs sha256 {on_disk}",
            receipt["sha256"]
        );

        ensure(&data).expect("the cached result admits a rootfs that differs from its receipt");

        let cold = base.join(format!("cold-{attempt}"));
        let cold_paths = write_image_set(&cold, b"working-image");
        fs::write(&cold_paths[1], b"changed-image").unwrap();
        let refused = format!("{:#}", ensure(&cold).unwrap_err());
        assert!(
            refused.contains("rootfs.ext4 checksum mismatch"),
            "{refused}"
        );
        return;
    }
    no_attempt_kept_the_stamp()
}

fn raw_cid(bytes: &[u8]) -> String {
    let hash = cid::multihash::Multihash::<64>::wrap(0x12, &Sha256::digest(bytes)).unwrap();
    cid::Cid::new_v1(0x55, hash).to_string()
}

fn descriptor(bytes: &[u8]) -> Value {
    json!({"cid":raw_cid(bytes),"sha256":sha256(bytes),"size":bytes.len()})
}

fn envelope(key: &ed25519_dalek::SigningKey, domain: &str, payload: &Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(payload).unwrap();
    let (signature, signer_did) =
        elastos_server::crypto::domain_separated_sign(key, domain, &bytes);
    serde_json::to_vec(&json!({"payload":payload,"signature":signature,"signer_did":signer_did}))
        .unwrap()
}

/// A public signed set shaped like the Runtime's `PublicPublicationFixture`.
fn write_signed_set(input: &Path, key: &ed25519_dalek::SigningKey, did: &str) {
    fs::create_dir(input).unwrap();
    let binary = b"#!/bin/sh\nexit 0\n";
    let support = b"public qualified support archive";
    let catalog = br#"{"payload":{"entries":[],"schema":"elastos.model.catalog/v1"}}"#;
    let mut support_ref = descriptor(support);
    support_ref["release_path"] = json!("home.tar.gz");
    support_ref["checksum"] = json!(format!("sha256:{}", sha256(support)));
    support_ref.as_object_mut().unwrap().remove("sha256");
    let components = serde_json::to_vec(&json!({
        "schema":"elastos.components/v1", "capsules":{}, "profiles":{},
        "external":{"home":{"platforms":{"*":support_ref}}},
        "model_catalog":{"head_cid":raw_cid(catalog),"publisher_dids":[did]}
    }))
    .unwrap();
    let installer = b"#!/bin/sh\n# public frozen installer\n";
    for (name, data) in [
        ("elastos-aarch64-darwin", &binary[..]),
        ("components-aarch64-darwin.json", &components[..]),
        ("home.tar.gz", &support[..]),
        ("model-catalog.json", &catalog[..]),
        ("install.sh", &installer[..]),
    ] {
        fs::write(input.join(name), data).unwrap();
    }
    let release = json!({"schema":"elastos.release/v1","version":"0.7.1","channel":"canary",
        "source":{"commit":"a".repeat(40),"tree":"b".repeat(40)},
        "released_at":1,"prev_release_cid":null,"installer_sha256":sha256(installer),
        "platforms":{"aarch64-darwin":{"binary":descriptor(binary),"components":descriptor(&components)}}});
    let release = envelope(key, "elastos.release.v1", &release);
    let head = json!({"schema":"elastos.release.head/v1","version":"0.7.1","channel":"canary",
        "signer_did":did,"updated_at":2,"prev_head_cid":null,
        "latest_release_cid":raw_cid(&release),"release_sha256":sha256(&release)});
    fs::write(input.join("release.json"), release).unwrap();
    fs::write(
        input.join("release-head.json"),
        envelope(key, "elastos.release.head.v1", &head),
    )
    .unwrap();
}

#[test]
fn published_release_check_reports_a_same_size_artifact_rewrite_from_the_same_tick_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().canonicalize().unwrap();
    let input = parent.join("input");
    // A memory-only disposable key; it signs only the public fixture above.
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let did = elastos_server::crypto::encode_signing_key_did(&key);
    write_signed_set(&input, &key, &did);
    let flat = Publication::open_flat(&input, &did).expect("the signed set admits");

    for attempt in 1..=ATTEMPTS {
        let output = parent.join(format!("published-{attempt}"));
        flat.snapshot_into(&output).unwrap();
        let path = output.join("artifacts/home.tar.gz");
        let original = fs::read(&path).unwrap();
        wait_for_fresh_tick();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let publication = Publication::open_published(&output, &did).expect("the snapshot admits");
        let recorded = stamp(&path);
        rewrite_in_place(&path, &[original[0] ^ 1]);
        // Any writer can restore mtime (utimensat). Only ctime still guards.
        restore_mtime(&path, recorded.mtime);
        if stamp(&path) != recorded {
            continue;
        }
        assert_ne!(fs::read(&path).unwrap(), original);
        println!("attempt {attempt}: stamp unchanged with restored mtime, artifact bytes differ");

        publication
            .unchanged_published()
            .expect("the identity check reports a rewritten artifact unchanged");

        assert!(publication.read_verified_artifact("home.tar.gz").is_err());
        return;
    }
    no_attempt_kept_the_stamp()
}
