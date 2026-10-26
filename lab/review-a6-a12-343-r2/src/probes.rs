//! Extra r2 probes, compiled only inside the #343 worktree for one run.
//! Not part of draft PR #343. Restored after the review compile.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::Arc;

use elastos_runtime::capability::manager::{CapabilityManager, ValidationError};
use elastos_runtime::capability::token::{Action, CapabilityToken, ResourceId, TokenConstraints};
use elastos_runtime::capability::CapabilityStore;
use elastos_runtime::primitives::metrics::MetricsManager;
use elastos_runtime::primitives::time::SecureTimestamp;
use elastos_runtime::primitives::AuditLog;

use crate::a12;
use crate::a6;

const INSTANCE_1: &str = "instance-1";
const INSTANCE_2: &str = "instance-2";
const RESOURCE_A: &str = "localhost://Users/self/Documents/a6-lab/file.txt";
const RESOURCE_B: &str = "localhost://Users/self/Documents/a6-lab/other.txt";

fn manager() -> CapabilityManager {
    CapabilityManager::new(
        Arc::new(CapabilityStore::new()),
        Arc::new(AuditLog::new()),
        Arc::new(MetricsManager::new()),
    )
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

fn grant(
    manager: &CapabilityManager,
    capsule: &str,
    resource: &str,
    action: Action,
    expiry: Option<SecureTimestamp>,
) -> CapabilityToken {
    manager.grant(
        capsule,
        ResourceId::new(resource),
        action,
        TokenConstraints::default(),
        expiry,
    )
}

fn validate(
    manager: &CapabilityManager,
    token: &CapabilityToken,
    caller: &str,
    action: Action,
    resource: &str,
) -> Result<(), ValidationError> {
    let wire = CapabilityToken::from_base64(&token.to_base64().expect("encode"))
        .expect("round-trip unless the probe is testing tamper");
    block_on(manager.validate(&wire, caller, action, &ResourceId::new(resource), None))
}

#[test]
fn r2_token_for_other_resource_sibling_is_still_wrong_capsule() {
    let mgr = manager();
    let token = grant(&mgr, INSTANCE_1, RESOURCE_B, Action::Read, None);
    match validate(&mgr, &token, INSTANCE_2, Action::Read, RESOURCE_A) {
        Err(ValidationError::WrongCapsule { expected, got })
            if expected == INSTANCE_1 && got == INSTANCE_2 =>
        {
            println!("r2 other-resource sibling: WrongCapsule {{ expected:{expected} got:{got} }}");
        }
        other => panic!("expected WrongCapsule first, got {other:?}"),
    }
}

#[test]
fn r2_token_for_other_action_sibling_is_still_wrong_capsule() {
    let mgr = manager();
    let token = grant(&mgr, INSTANCE_1, RESOURCE_A, Action::Write, None);
    match validate(&mgr, &token, INSTANCE_2, Action::Read, RESOURCE_A) {
        Err(ValidationError::WrongCapsule { expected, got })
            if expected == INSTANCE_1 && got == INSTANCE_2 =>
        {
            println!("r2 other-action sibling: WrongCapsule {{ expected:{expected} got:{got} }}");
        }
        other => panic!("expected WrongCapsule before WrongAction, got {other:?}"),
    }
}

#[test]
fn r2_owner_other_resource_is_wrong_resource() {
    let mgr = manager();
    let token = grant(&mgr, INSTANCE_1, RESOURCE_A, Action::Read, None);
    match validate(&mgr, &token, INSTANCE_1, Action::Read, RESOURCE_B) {
        Err(ValidationError::WrongResource { .. }) => {
            println!("r2 owner other-resource: WrongResource");
        }
        other => panic!("expected WrongResource, got {other:?}"),
    }
}

#[test]
fn r2_expired_token_is_refused() {
    let mgr = manager();
    let token = grant(
        &mgr,
        INSTANCE_1,
        RESOURCE_A,
        Action::Read,
        Some(SecureTimestamp::at(1)),
    );
    match validate(&mgr, &token, INSTANCE_1, Action::Read, RESOURCE_A) {
        Err(ValidationError::TokenExpired) => println!("r2 expired token: TokenExpired"),
        other => panic!("expected TokenExpired, got {other:?}"),
    }
}

#[test]
fn r2_revoked_token_is_refused() {
    let mgr = manager();
    let token = grant(&mgr, INSTANCE_1, RESOURCE_A, Action::Read, None);
    block_on(mgr.revoke(*token.id(), "r2 review"));
    match validate(&mgr, &token, INSTANCE_1, Action::Read, RESOURCE_A) {
        Err(ValidationError::TokenRevoked) => println!("r2 revoked token: TokenRevoked"),
        other => panic!("expected TokenRevoked, got {other:?}"),
    }
}

#[test]
fn r2_tampered_base64_is_refused() {
    let mgr = manager();
    let token = grant(&mgr, INSTANCE_1, RESOURCE_A, Action::Read, None);
    let encoded = token.to_base64().expect("encode");
    assert!(encoded.len() > 8, "token too short to tamper: {encoded}");
    let bytes = encoded.as_bytes();
    let mut tampered = encoded.clone();
    let mid = encoded.len() / 2;
    let ch = bytes[mid];
    let replacement = if ch == b'A' { 'B' } else { 'A' };
    tampered.replace_range(mid..mid + 1, &replacement.to_string());
    assert_ne!(tampered, encoded);
    match CapabilityToken::from_base64(&tampered) {
        Err(reason) => {
            println!("r2 tampered base64: from_base64 refused ({reason})");
        }
        Ok(decoded) => {
            let result = block_on(mgr.validate(
                &decoded,
                INSTANCE_1,
                Action::Read,
                &ResourceId::new(RESOURCE_A),
                None,
            ));
            assert!(
                result.is_err(),
                "tampered token decoded and validated as owner: {result:?}"
            );
            println!("r2 tampered base64: decoded then validate refused {result:?}");
        }
    }
}

#[test]
fn r2_capsule_id_case_variant_is_refused() {
    let session = a6::Session::mint_instance1();
    match session.validate_as("INSTANCE-1") {
        Err(ValidationError::WrongCapsule { expected, got })
            if expected == INSTANCE_1 && got == "INSTANCE-1" =>
        {
            println!("r2 case variant: WrongCapsule {{ expected:{expected} got:{got} }}");
        }
        other => panic!("expected exact-case WrongCapsule, got {other:?}"),
    }
}

#[test]
fn r2_capsule_id_unicode_zwsp_is_refused() {
    let session = a6::Session::mint_instance1();
    let sneaky = format!("instance-1{}", '\u{200b}');
    match session.validate_as(&sneaky) {
        Err(ValidationError::WrongCapsule { expected, got })
            if expected == INSTANCE_1 && got == sneaky =>
        {
            println!("r2 unicode zwsp: WrongCapsule got_len={}", got.len());
        }
        other => panic!("expected WrongCapsule for zero-width sibling, got {other:?}"),
    }
}

#[test]
fn r2_renamed_tree_without_marker_is_hidden() {
    let parent = a12::isolated_dir("r2-nomarker");
    let named = parent.join("named-root");
    fs::create_dir_all(named.join("storage")).unwrap();
    fs::write(named.join("storage").join("plain.txt"), b"not-the-lab-marker\n").unwrap();
    let bak = parent.join("named-root.bak");
    fs::rename(&named, &bak).unwrap();
    let leftovers = a12::leftovers_under(&[named.clone()]).expect("walk missing root");
    let saw_plain = leftovers.iter().any(|path| {
        path.ends_with("plain.txt")
            || fs::read(path)
                .ok()
                .as_deref()
                .is_some_and(|bytes| bytes == b"not-the-lab-marker\n")
    });
    a12::remove_isolated(&parent);
    println!("r2 marker-absent rename leftovers={leftovers:?} saw_plain={saw_plain}");
    assert!(
        !saw_plain,
        "unexpected: census found a renamed tree that had no leftover marker"
    );
}

#[test]
fn r2_rename_to_unrelated_name_hides_marker() {
    let parent = a12::isolated_dir("r2-unrelated");
    let named = parent.join("named-root");
    fs::create_dir_all(&named).unwrap();
    let leftover = a12::create_runtime_storage_leftover(&named).expect("marker leftover");
    let moved = parent.join("moved-away");
    fs::rename(&named, &moved).unwrap();
    fs::create_dir_all(&named).unwrap();
    let leftovers = a12::leftovers_under(&[named.clone()]).expect("walk");
    let saw_marker = leftovers.iter().any(|path| {
        fs::read(path).ok().as_deref() == Some(a12::LEFTOVER_MARKER)
            || path.ends_with(leftover.file_name().unwrap())
    });
    a12::remove_isolated(&parent);
    println!("r2 unrelated rename leftovers={leftovers:?} saw_marker={saw_marker}");
    assert!(
        !saw_marker,
        "unexpected: prefix-free rename was still found by marker scan"
    );
}

#[test]
fn r2_symlink_loop_does_not_pass_as_clean() {
    let dir = a12::isolated_dir("r2-loop");
    let link = dir.join("loop-root");
    symlink(&link, &link).unwrap();
    let result = a12::leftovers_under(&[link.clone()]);
    a12::remove_isolated(&dir);
    match result {
        Ok(paths) => {
            println!("r2 symlink loop listed {paths:?}");
            panic!("symlink loop must not look like a clean empty walk");
        }
        Err(reason) => {
            println!("r2 symlink loop refused: {reason}");
            assert!(
                reason.contains("resolve") || reason.contains("loop") || reason.contains("inspect"),
                "{reason}"
            );
        }
    }
}

#[test]
fn r2_elastos_tmp_root_relative_is_accepted() {
    let isolated = a12::isolated_dir("r2-rel-parent");
    let rel = PathBuf::from("r2-relative-tmp");
    let _ = fs::remove_dir_all(&rel);
    a12::with_tmp_root(&rel, || {
        let got = a12::elastos_tmp_root();
        assert_eq!(got, rel, "relative ELASTOS_TMP_ROOT must be kept as given");
        let leftover = a12::create_runtime_storage_leftover(&got).expect("create relative leftover");
        assert!(
            leftover.starts_with(&rel),
            "relative leftover path {}",
            leftover.display()
        );
        println!(
            "r2 relative ELASTOS_TMP_ROOT accepted: {} leftover {}",
            got.display(),
            leftover.display()
        );
        drop(leftover);
    });
    let _ = fs::remove_dir_all(&rel);
    a12::remove_isolated(&isolated);
}

#[test]
fn r2_elastos_tmp_root_slash_has_no_guard() {
    a12::with_tmp_root(std::path::Path::new("/"), || {
        let roots = a12::runtime_owned_temp_roots();
        println!("r2 ELASTOS_TMP_ROOT=/ roots={roots:?}");
        assert!(
            roots.iter().any(|root| root == std::path::Path::new("/")),
            "slash root must appear in the census list: {roots:?}"
        );
        assert!(
            roots
                .iter()
                .any(|root| root == std::path::Path::new("/storage")),
            "slash storage child must appear: {roots:?}"
        );
    });
}

#[test]
fn r2_elastos_tmp_root_unset_defaults_to_shared_tmp() {
    let _lock = a12::lock_real_root();
    let previous = std::env::var_os("ELASTOS_TMP_ROOT");
    std::env::remove_var("ELASTOS_TMP_ROOT");
    let tmp = a12::elastos_tmp_root();
    let storage = a12::storage_root();
    match previous {
        Some(value) => std::env::set_var("ELASTOS_TMP_ROOT", value),
        None => std::env::remove_var("ELASTOS_TMP_ROOT"),
    }
    assert_eq!(tmp, std::path::PathBuf::from("/tmp/elastos"));
    assert_eq!(storage, std::path::PathBuf::from("/tmp/elastos/storage"));
    println!("r2 unset ELASTOS_TMP_ROOT defaults to /tmp/elastos (shared Runtime temp)");
}

#[test]
fn r2_subject_does_not_claim_resident_instances() {
    let a6 = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/a6.rs"));
    let findings = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/FINDINGS.md"));
    assert!(
        a6.contains("not two resident capsule instances"),
        "a6.rs dropped the resident-instance disclaimer"
    );
    assert!(
        findings.contains("not two independent resident capsule instances"),
        "FINDINGS.md dropped the resident-instance disclaimer"
    );
    println!("r2: #343 does not claim Anders resident-instance A6");
}
