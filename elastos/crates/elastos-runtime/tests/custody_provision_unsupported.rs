#![cfg(all(unix, elastos_unsupported_os_check))]

use elastos_runtime::provider::{CheckedExecutable, ProviderBridge};

#[tokio::test]
async fn custody_provision_os_refusal_names_the_helper_before_start() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("custody-provider-must-stay-absent");
    let checked =
        CheckedExecutable::pinned(&binary, &format!("sha256:{}", "00".repeat(32))).unwrap();
    let error = ProviderBridge::spawn_custody_provision(
        &checked,
        temp.path(),
        "0x00",
        8192,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(
        error.contains("custody-provider provisioning refused"),
        "{error}"
    );
    assert!(
        error.contains("this operating system has no confinement"),
        "{error}"
    );
    assert!(!binary.exists());
}
