use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use linux_confine::{
    allow_rules, block_landlock, block_seccomp, block_userns, deny_network_by_default, explain_abi,
    launch, op, parse_profile, read_profile, Launch, Report, ABI_IOCTL, ABI_STORAGE, NO_LANDLOCK,
    NO_SECCOMP, NO_USERNS, STORAGE_ROOT_RIGHTS,
};

const EPERM: i32 = 1;
const ESRCH: i32 = 3;
const EACCES: i32 = 13;

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Built {
    launch: Launch,
    _tmp: Tmp,
    secret: Vec<u8>,
    copy_bytes: Vec<u8>,
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn build(name: &str, kind: &str) -> Built {
    let base = std::env::temp_dir().join(format!(
        "linux-confine-{}-{}-{}",
        std::process::id(),
        name,
        kind
    ));
    let _ = fs::remove_dir_all(&base);
    let (parent, root, storage, storage2, outside) = match kind {
        "did" => {
            let parent = base.join("base");
            let root = parent.join("did");
            fs::create_dir_all(root.join("personas")).unwrap();
            fs::create_dir_all(parent.join("sibling")).unwrap();
            (
                parent.clone(),
                root.clone(),
                root.join("nickname.enc"),
                Some(root.join("personas").join("fixture.enc")),
                parent.join("sibling").join("secret"),
            )
        }
        "wallet" => {
            let parent = base.join("base").join("ElastOS").join("SystemServices");
            let root = parent.join("Wallet");
            fs::create_dir_all(&root).unwrap();
            fs::create_dir_all(parent.join("sibling")).unwrap();
            (
                parent.clone(),
                root.clone(),
                root.join("wallet-state.json"),
                None,
                parent.join("sibling").join("secret"),
            )
        }
        "model" => {
            let parent = base.join("base").join("providers");
            let root = parent.join("model-provider");
            fs::create_dir_all(root.join("runs")).unwrap();
            fs::create_dir_all(parent.join("sibling")).unwrap();
            (
                parent.clone(),
                root.clone(),
                root.join("runs").join("record"),
                None,
                parent.join("sibling").join("secret"),
            )
        }
        _ => panic!("unknown layout {kind}"),
    };
    let secret = b"secret-bytes\n".to_vec();
    fs::write(&outside, &secret).unwrap();
    let copy = root.join("copy");
    fs::copy(env!("LC_PROBE"), &copy).unwrap();
    let mut perms = fs::metadata(&copy).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&copy, perms).unwrap();
    let copy_bytes = fs::read(&copy).unwrap();
    let positive = Command::new(&copy)
        .arg("bound-child")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        positive.status.success(),
        "missing evidence: the copy cannot run outside the policy\n{}",
        String::from_utf8_lossy(&positive.stderr)
    );
    let positive_out = String::from_utf8_lossy(&positive.stdout);
    assert!(
        positive_out.contains("op=exec-bound result=ok"),
        "missing evidence: {positive_out}"
    );
    assert!(!storage.exists());
    if let Some(path) = &storage2 {
        assert!(!path.exists());
    }
    Built {
        launch: Launch {
            deny_network: deny_network_by_default(),
            storage_root: root,
            storage,
            storage2,
            outside,
            parent,
            copy,
        },
        _tmp: Tmp(base),
        secret,
        copy_bytes,
    }
}

fn expect(report: &Report, name: &str, result: &str, errno: Option<i32>, reason: &str) {
    let found = op(report, name).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(found.result, result, "{name}\n{}", report.raw);
    assert_eq!(found.errno, errno, "{name}\n{}", report.raw);
    assert_eq!(found.reason, reason, "{name}\n{}", report.raw);
}

fn print_table(profile: &str, rows: &[(&str, &str, &str, &str)]) {
    println!("### {profile}");
    println!();
    println!("| side | operation | result | reason |");
    println!("| --- | --- | --- | --- |");
    for (side, operation, result, reason) in rows {
        println!("| {side} | {operation} | {result} | {reason} |");
    }
    println!();
}

fn profile_rows(
    storage: &[&str],
    persona: &[&str],
    memory: &[&str],
) -> Vec<(String, String, String, String)> {
    let mut rows = Vec::new();
    for name in storage {
        rows.push((
            "permitted".to_string(),
            (*name).to_string(),
            "ok".to_string(),
            "wrote and read a file under STORAGE_ROOT".to_string(),
        ));
    }
    for name in persona {
        rows.push((
            "permitted".to_string(),
            (*name).to_string(),
            "ok".to_string(),
            "wrote and read personas/fixture.enc under STORAGE_ROOT".to_string(),
        ));
    }
    for name in memory {
        rows.push((
            "permitted".to_string(),
            (*name).to_string(),
            "ok".to_string(),
            "no file and no socket; the confined process ran".to_string(),
        ));
    }
    rows.push((
        "permitted".to_string(),
        "process-exec PROVIDER_EXECUTABLE".to_string(),
        "ok".to_string(),
        "process-exec of PROVIDER_EXECUTABLE".to_string(),
    ));
    rows.push((
        "permitted".to_string(),
        "sysctl-read".to_string(),
        "ok".to_string(),
        "read kernel identity".to_string(),
    ));
    let denied = [
        (
            "read outside STORAGE_ROOT",
            "landlock refused the read outside STORAGE_ROOT",
        ),
        (
            "write outside STORAGE_ROOT",
            "landlock refused the write outside STORAGE_ROOT",
        ),
        (
            "read STORAGE_PARENT",
            "the Landlock ABI cannot express the STORAGE_PARENT read, so the read is refused",
        ),
        ("read /", "no Landlock rule for the root directory read"),
        (
            "read /proc/kallsyms",
            "landlock refused the read of kernel state",
        ),
        ("socket", "seccomp refused socket"),
        ("socketpair", "seccomp refused socketpair"),
        (
            "exec a copy under STORAGE_ROOT",
            "landlock refused exec of a file other than PROVIDER_EXECUTABLE",
        ),
        (
            "signal a host pid",
            "the pid namespace has no such host process",
        ),
        ("clone a process", "seccomp refused clone"),
    ];
    for (operation, reason) in denied {
        rows.push((
            "denied".to_string(),
            operation.to_string(),
            "refused".to_string(),
            reason.to_string(),
        ));
    }
    rows
}

fn prove(name: &str, kind: &str, storage: &[&str], persona: &[&str], memory: &[&str], note: &str) {
    let built = build(name, kind);
    let report = launch(&built.launch).unwrap_or_else(|err| panic!("{name}: {err}"));
    assert_eq!(
        report.enforced.storage_rights, STORAGE_ROOT_RIGHTS,
        "storage root rights drifted"
    );
    assert_eq!(report.enforced.uid, 0, "{}", report.raw);
    assert_eq!(report.enforced.caps, "empty", "{}", report.raw);
    assert_eq!(report.enforced.nnp, 1, "{}", report.raw);
    assert_eq!(report.enforced.netns, "lo", "{}", report.raw);
    assert!(report.enforced.abi >= 5, "{}", report.raw);
    expect(&report, "in-memory", "ok", None, "no file and no socket");
    expect(
        &report,
        "storage-write",
        "ok",
        None,
        "wrote under STORAGE_ROOT",
    );
    expect(
        &report,
        "storage-read",
        "ok",
        None,
        "read under STORAGE_ROOT",
    );
    assert_eq!(fs::read(&built.launch.storage).unwrap(), b"stored");
    if built.launch.storage2.is_some() {
        expect(
            &report,
            "storage2-write",
            "ok",
            None,
            "wrote under STORAGE_ROOT",
        );
        expect(
            &report,
            "storage2-read",
            "ok",
            None,
            "read under STORAGE_ROOT",
        );
        assert_eq!(
            fs::read(built.launch.storage2.as_ref().unwrap()).unwrap(),
            b"persona"
        );
    }
    expect(
        &report,
        "outside-read",
        "refused",
        Some(EACCES),
        "landlock refused the read outside STORAGE_ROOT",
    );
    expect(
        &report,
        "outside-write",
        "refused",
        Some(EACCES),
        "landlock refused the write outside STORAGE_ROOT",
    );
    expect(
        &report,
        "parent-read",
        "refused",
        Some(EACCES),
        "the Landlock ABI cannot express the STORAGE_PARENT read, so the read is refused",
    );
    expect(
        &report,
        "root-read",
        "refused",
        Some(EACCES),
        "no Landlock rule for the root directory read",
    );
    expect(
        &report,
        "kernel-fact",
        "refused",
        Some(EACCES),
        "landlock refused the read of kernel state",
    );
    expect(&report, "sysctl", "ok", None, "read kernel identity");
    let socket = op(&report, "socket").unwrap();
    assert!(
        socket.result == "refused"
            && socket.errno == Some(EPERM)
            && socket.reason == "seccomp refused socket",
        "socket denial did not hold: {}",
        report.raw
    );
    expect(
        &report,
        "socketpair",
        "refused",
        Some(EPERM),
        "seccomp refused socketpair",
    );
    expect(
        &report,
        "exec-unbound",
        "refused",
        Some(EACCES),
        "landlock refused exec of a file other than PROVIDER_EXECUTABLE",
    );
    expect(
        &report,
        "exec-bound",
        "ok",
        None,
        "process-exec of PROVIDER_EXECUTABLE",
    );
    expect(
        &report,
        "signal-host",
        "refused",
        Some(ESRCH),
        "the pid namespace has no such host process",
    );
    expect(
        &report,
        "clone",
        "refused",
        Some(EPERM),
        "seccomp refused clone",
    );
    assert_eq!(fs::read(&built.launch.outside).unwrap(), built.secret);
    assert_eq!(fs::read(&built.launch.copy).unwrap(), built.copy_bytes);
    let rows = profile_rows(storage, persona, memory);
    let borrowed: Vec<(&str, &str, &str, &str)> = rows
        .iter()
        .map(|row| {
            (
                row.0.as_str(),
                row.1.as_str(),
                row.2.as_str(),
                row.3.as_str(),
            )
        })
        .collect();
    println!(
        "enforced abi={} uid={} caps={} nnp={} netns={} storage_rights=0x{:x}",
        report.enforced.abi,
        report.enforced.uid,
        report.enforced.caps,
        report.enforced.nnp,
        report.enforced.netns,
        report.enforced.storage_rights
    );
    print_table(name, &borrowed);
    if !note.is_empty() {
        println!("{note}");
        println!();
    }
}

#[test]
fn profiles_match_their_declared_rights() {
    let root = repo();
    let cases = [
        (
            "capsules/did-provider/confine.sb",
            "capsules/did-provider/tests/fixtures/confine/declared-rights.json",
            false,
        ),
        (
            "capsules/wallet-provider/confine.sb",
            "capsules/wallet-provider/tests/fixtures/confine/declared-rights.json",
            false,
        ),
        (
            "capsules/model-provider/confine.sb",
            "capsules/model-provider/tests/fixtures/confine/declared-rights.json",
            true,
        ),
    ];
    for (sb, rights, data_only) in cases {
        let sb_text = fs::read_to_string(root.join(sb)).unwrap();
        let json = fs::read_to_string(root.join(rights))
            .unwrap()
            .replace("\\\"", "\"");
        let profile = parse_profile(&sb_text).unwrap();
        let mut from_profile = profile.allow_lines.clone();
        let mut from_rights = allow_rules(&json);
        from_profile.sort();
        from_rights.sort();
        assert_eq!(from_profile, from_rights, "{sb}");
        let root_read = profile.allows.iter().find_map(|allow| match allow {
            linux_confine::Allow::RootRead { data_only } => Some(*data_only),
            _ => None,
        });
        assert_eq!(root_read, Some(data_only), "{sb}");
        let _ = read_profile(Path::new(&root.join(sb))).unwrap();
    }
}

#[test]
fn unknown_allow_is_refused() {
    let text =
        "(version 1)\n(deny default)\n(deny network*)\n(allow file-read* (literal \"/etc\"))\n";
    let err = parse_profile(text).unwrap_err();
    assert!(err.contains("unknown allow"), "{err}");
}

#[test]
fn a_wider_root_read_is_refused() {
    let text =
        "(version 1)\n(deny default)\n(deny network*)\n(allow file-write* (literal \"/\"))\n";
    let err = parse_profile(text).unwrap_err();
    assert!(err.contains("wider") || err.contains("must name"), "{err}");
}

#[test]
fn did_profile_permits_its_operations_and_refuses_the_rest() {
    prove(
        "did-provider",
        "did",
        &["init", "set_nickname"],
        &["get_persona_did"],
        &[
            "get_did",
            "resolve",
            "sign_chat_message",
            "verify",
            "verify_did_recovery",
            "get_nickname",
            "shutdown",
        ],
        "",
    );
}

#[test]
fn wallet_profile_permits_its_operations_and_refuses_the_rest() {
    prove(
        "wallet-provider",
        "wallet",
        &[
            "init",
            "wallet_contract create_managed_account",
            "wallet_contract link_verified_account",
            "wallet_contract revoke_account",
            "wallet_contract rename_account",
            "wallet_contract set_default_account",
            "wallet_contract challenge",
            "wallet_contract bitcoin_challenge",
            "wallet_contract verify_proof",
            "wallet_contract verify_contract_proof",
            "wallet_contract verify_bip322_proof",
            "wallet_contract request_protected_content_rights_signature",
            "wallet_contract request_approval",
            "wallet_contract reject_approval",
            "wallet_contract approve_and_sign_managed",
            "wallet_contract approve_connector_handoff",
            "wallet_contract complete_connector_handoff",
            "wallet_contract attach_validated_chain_outcome",
            "wallet_contract export_managed_recovery_key",
            "wallet_contract import_managed_recovery_key",
            "wallet_contract export_managed_recovery_set",
            "wallet_contract import_managed_recovery_set",
        ],
        &[],
        &["status", "shutdown", "wallet_contract list_accounts"],
        "default_account and list_approvals have no named macOS test. This run does not claim them.",
    );
}

#[test]
fn model_profile_permits_its_operations_and_refuses_the_rest() {
    prove(
        "model-provider",
        "model",
        &["init", "runs_create", "runs_get"],
        &[],
        &["status", "shutdown", "offers_list"],
        "runs_events and runs_cancel have no named macOS test. This run does not claim them. The model root read is file-read-data of / on macOS. Linux grants no rule for that path, and the read of / is refused.",
    );
}

#[test]
fn removing_the_socket_denial_lets_the_call_succeed() {
    let mut built = build("socket-rule", "did");
    built.launch.deny_network = false;
    let report = launch(&built.launch).unwrap_or_else(|err| panic!("{err}"));
    let socket = op(&report, "socket").unwrap();
    assert_eq!(socket.result, "ok", "{}", report.raw);
    assert_eq!(socket.reason, "socket succeeded", "{}", report.raw);
    expect(
        &report,
        "outside-read",
        "refused",
        Some(EACCES),
        "landlock refused the read outside STORAGE_ROOT",
    );
    println!("F-LC-SOCKET CAUGHT");
}

#[test]
fn landlock_absence_refuses_the_start() {
    let err = block_landlock().unwrap_err();
    assert!(err.contains(NO_LANDLOCK), "{err}");
    assert!(!err.contains("op="), "{err}");
}

#[test]
fn seccomp_absence_refuses_the_start() {
    let err = block_seccomp().unwrap_err();
    assert!(err.contains(NO_SECCOMP), "{err}");
    assert!(!err.contains("op="), "{err}");
}

#[test]
fn user_namespace_absence_refuses_the_start() {
    let built = build("userns", "did");
    let err = block_userns(&built.launch).unwrap_err();
    assert!(err.contains(NO_USERNS), "{err}");
    assert!(!err.contains("op="), "{err}");
    assert!(
        !built.launch.storage.exists(),
        "a refusal wrote under STORAGE_ROOT"
    );
}

#[test]
fn production_launcher_rejects_block_switches() {
    for arg in [
        "--block-landlock",
        "--block-seccomp",
        "--block-userns",
        "--explain-abi",
    ] {
        let output = Command::new(env!("LC_SETUP"))
            .arg(arg)
            .output()
            .unwrap_or_else(|err| panic!("{arg}: {err}"));
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !output.status.success()
                && text.contains("unknown launch argument")
                && !text.contains(NO_LANDLOCK)
                && !text.contains(NO_SECCOMP)
                && !text.contains(NO_USERNS),
            "the production launcher accepted a block switch: {arg}: {text}"
        );
    }
}

#[test]
fn a_low_landlock_abi_refuses_the_start() {
    let storage = explain_abi(2).unwrap_err();
    assert!(storage.contains(ABI_STORAGE), "{storage}");
    let ioctl = explain_abi(4).unwrap_err();
    assert!(ioctl.contains(ABI_IOCTL), "{ioctl}");
    let missing = explain_abi(-1).unwrap_err();
    assert!(missing.contains(NO_LANDLOCK), "{missing}");
    let ready = explain_abi(6).unwrap();
    assert!(ready.contains("abi-ok"), "{ready}");
}
