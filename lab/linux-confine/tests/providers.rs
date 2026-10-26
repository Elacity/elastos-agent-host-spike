//! The shipping provider binaries under the Linux profiles.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use elastos_model_contract::{
    model_input_hash, model_run_id, RuntimeCreateBinding, RUNTIME_CREATE_BINDING_SCHEMA,
    TEXT_INPUT_V1_SCHEMA,
};
use elastos_wallet_contract::{
    VerifiedWalletInvocationContext, WalletProviderOperationV2, WalletProviderRequestV2,
    WalletProviderResponseV2, WalletResultV2,
};
use linux_confine::{
    confined_cap_bnd, spawn_provider, ExtraPath, ProviderLaunch, RunningProvider,
    STORAGE_ROOT_RIGHTS,
};
use serde_json::{json, Value};

const EACCES: i32 = 13;

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn binary(name: &str) -> PathBuf {
    let path = repo().join(format!("capsules/{name}/target/debug/{name}"));
    assert!(
        path.is_file(),
        "build the shipping binary first: cargo build --manifest-path capsules/{name}/Cargo.toml --bin {name}"
    );
    path
}

fn library_reason(path: &str) -> String {
    let name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path);
    if name.contains("ld-linux") {
        format!("{name}: the kernel starts the binary through this dynamic linker, which must be mapped executable")
    } else {
        format!("{name}: ldd lists this as a library the binary links, and the linker maps it executable")
    }
}

fn ldd_paths(binary: &Path) -> Vec<ExtraPath> {
    let output = Command::new("ldd").arg(binary).output().expect("ldd");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let mut paths = Vec::new();
    for line in text.lines() {
        let path = if let Some((_, rest)) = line.split_once("=>") {
            rest.split_whitespace().next().unwrap_or("")
        } else {
            line.split_whitespace().next().unwrap_or("")
        };
        if path.starts_with('/') {
            paths.push(ExtraPath {
                path: PathBuf::from(path),
                execute: true,
            });
        }
    }
    let cache = PathBuf::from("/etc/ld.so.cache");
    if cache.is_file() {
        paths.push(ExtraPath {
            path: cache,
            execute: false,
        });
    }
    assert!(
        !paths.is_empty(),
        "ldd named no libraries for {}",
        binary.display()
    );
    paths
}

fn describe_paths(paths: &[ExtraPath]) -> String {
    let mut lines = Vec::new();
    for extra in paths {
        let text = extra.path.display().to_string();
        let reason = if extra.execute {
            library_reason(&text)
        } else {
            format!(
                "{text}: the dynamic linker reads this cache before it opens the libraries above"
            )
        };
        lines.push(format!("library {text} — {reason}"));
    }
    lines.join("\n")
}

struct Fixture {
    _tmp: Tmp,
    launch: ProviderLaunch,
    base: PathBuf,
    root: PathBuf,
    outside_file: PathBuf,
    outside_base: PathBuf,
}

fn prepare(name: &str, kind: &str, preload: bool) -> Fixture {
    let base_root = std::env::temp_dir().join(format!(
        "linux-confine-provider-{}-{}-{}",
        std::process::id(),
        name,
        kind
    ));
    let _ = fs::remove_dir_all(&base_root);
    let program = binary(name);
    let (base, root, parent, outside_file, outside_base, read_parent) = match kind {
        "did" => {
            let base = base_root.join("base");
            let root = base.join("did");
            fs::create_dir_all(&root).unwrap();
            let outside_base = base_root.join("outside");
            fs::create_dir_all(&outside_base).unwrap();
            let outside_file = outside_base.join("secret");
            fs::write(&outside_file, b"outside-bytes").unwrap();
            (
                base,
                root,
                base_root.join("base"),
                outside_file,
                outside_base,
                false,
            )
        }
        "wallet" => {
            let base = base_root.join("base");
            let parent = base.join("ElastOS").join("SystemServices");
            let root = parent.join("Wallet");
            fs::create_dir_all(&root).unwrap();
            let outside_base = base_root.join("outside");
            fs::create_dir_all(&outside_base).unwrap();
            let outside_file = outside_base.join("secret");
            fs::write(&outside_file, b"outside-bytes").unwrap();
            (base, root.clone(), parent, outside_file, outside_base, true)
        }
        "model" => {
            let base = base_root.join("base");
            let parent = base.join("providers");
            let root = parent.join("model-provider");
            fs::create_dir_all(&root).unwrap();
            let mut root_mode = fs::metadata(&root).unwrap().permissions();
            root_mode.set_mode(0o700);
            fs::set_permissions(&root, root_mode).unwrap();
            let outside_base = base_root.join("outside");
            let outside_journal = outside_base.join("journal");
            fs::create_dir_all(&outside_journal).unwrap();
            let mut outside_mode = fs::metadata(&outside_journal).unwrap().permissions();
            outside_mode.set_mode(0o700);
            fs::set_permissions(&outside_journal, outside_mode).unwrap();
            let outside_file = outside_base.join("secret");
            fs::write(&outside_file, b"outside-bytes").unwrap();
            (base, root, parent, outside_file, outside_base, false)
        }
        other => panic!("unknown provider layout {other}"),
    };
    let copy = root.join("unbound-copy");
    fs::copy(&program, &copy).unwrap();
    let mut perms = fs::metadata(&copy).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&copy, perms).unwrap();
    Fixture {
        _tmp: Tmp(base_root),
        launch: ProviderLaunch {
            deny_network: linux_confine::deny_network_by_default(),
            binary: program.clone(),
            execute: program,
            storage_root: root.clone(),
            parent,
            copy,
            read_parent,
            preload,
            outside: Some(outside_file.clone()),
            paths: ldd_paths(&binary(name)),
        },
        base,
        root,
        outside_file,
        outside_base,
    }
}

fn json_line(provider: &mut RunningProvider, value: &Value) -> Value {
    let line = provider
        .request(&value.to_string())
        .unwrap_or_else(|err| panic!("{value}: {err}"));
    serde_json::from_str(&line).unwrap_or_else(|err| panic!("not JSON {line}: {err}"))
}

fn expect_ok(provider: &mut RunningProvider, value: &Value) -> Value {
    let response = json_line(provider, value);
    assert_eq!(response["status"], "ok", "{response}");
    response["data"].clone()
}

fn witness<'a>(stderr: &'a str, op: &str) -> &'a str {
    stderr
        .lines()
        .find(|line| line.starts_with(&format!("witness op={op} ")))
        .unwrap_or_else(|| panic!("missing witness {op} in {stderr}"))
}

fn assert_witness(stderr: &str, op: &str, errno: i32, reason: &str) {
    let line = witness(stderr, op);
    assert!(
        line.contains("result=refused")
            && line.contains(&format!("errno={errno}"))
            && line.contains(reason),
        "{line}"
    );
}

fn confinement_rows(provider: &RunningProvider) -> (String, String) {
    assert_eq!(
        provider.enforced.storage_rights, STORAGE_ROOT_RIGHTS,
        "storage root rights drifted"
    );
    let (pid, hex) =
        confined_cap_bnd(provider.launcher_pid()).unwrap_or_else(|err| panic!("{err}"));
    let value =
        u128::from_str_radix(&hex, 16).unwrap_or_else(|_| panic!("CapBnd is not hex: {hex}"));
    assert_eq!(
        value, 0,
        "capability bounding set did not drop: CapBnd: {hex}"
    );
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string();
    assert!(
        !comm.is_empty() && comm != "lc-setup",
        "CapBnd was read from {comm} at /proc/{pid}/status"
    );
    (
        format!("/proc/{pid}/status CapBnd {hex} ({comm})"),
        format!("0x{:x}", provider.enforced.storage_rights),
    )
}

fn print_row(side: &str, operation: &str, result: &str, reason: &str) {
    println!("| {side} | {operation} | {result} | - | {reason} | - |");
}

fn print_denied(operation: &str, errno: i32, reason: &str, positive: &str) {
    println!("| denied | {operation} | refused | {errno} | {reason} | {positive} |");
}

fn header(name: &str) {
    println!("### {name}");
    println!();
    println!("| side | operation | result | errno | reason | positive control |");
    println!("| --- | --- | --- | --- | --- | --- |");
}

fn positive_socket() -> String {
    std::net::UdpSocket::bind("127.0.0.1:0").expect("positive control: unconfined socket");
    "unconfined socket(AF_INET) succeeded".to_string()
}

fn positive_kill() -> String {
    let pid = std::process::id().to_string();
    let status = Command::new("kill")
        .args(["-0", &pid])
        .status()
        .expect("positive control: kill");
    assert!(
        status.success(),
        "positive control: unconfined kill(host, 0) failed"
    );
    "unconfined kill(host, 0) succeeded".to_string()
}

fn positive_exec(path: &Path) -> String {
    let mut child = Command::new(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("positive control: unconfined exec of the copy failed");
    let _ = child.kill();
    let _ = child.wait();
    "unconfined exec of the copy succeeded".to_string()
}

fn positive_file(path: &Path) -> String {
    fs::read(path).expect("positive control: unconfined read of the outside file failed");
    format!("unconfined read of {} succeeded", path.display())
}

fn errno_from_os_error(text: &str) -> i32 {
    let marker = "os error ";
    if let Some(rest) = text.split(marker).nth(1) {
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = digits.parse::<i32>() {
            return n;
        }
    }
    panic!("denied row has no kernel errno: {text}");
}

#[test]
fn confined_process_cap_bnd_is_zero() {
    let fix = prepare("did-provider", "did", false);
    let mut provider = spawn_provider(&fix.launch).unwrap_or_else(|err| panic!("{err}"));
    let key = "42".repeat(32);
    expect_ok(
        &mut provider,
        &json!({"op":"init","config":{"base_path": fix.base, "encryption_key": key}}),
    );
    let (pid, hex) =
        confined_cap_bnd(provider.launcher_pid()).unwrap_or_else(|err| panic!("{err}"));
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let line = status
        .lines()
        .find(|line| line.starts_with("CapBnd:"))
        .unwrap_or_else(|| panic!("/proc/{pid}/status has no CapBnd\n{status}"));
    let value =
        u128::from_str_radix(&hex, 16).unwrap_or_else(|_| panic!("CapBnd is not hex: {hex}"));
    assert_eq!(
        value, 0,
        "capability bounding set did not drop: CapBnd: {hex}"
    );
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap();
    assert!(comm.starts_with("did-provider"), "{comm}");
    println!("/proc/{pid}/status {line} comm={comm}");
}

#[test]
fn did_provider_binary_under_its_profile() {
    let program = binary("did-provider");
    println!("{}", describe_paths(&ldd_paths(&program)));
    let mut fix = prepare("did-provider", "did", true);
    let mut provider = spawn_provider(&fix.launch).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(provider.enforced.uid, 0);
    assert_eq!(provider.enforced.caps, "empty");
    assert_eq!(provider.enforced.netns, "lo");
    let key = "42".repeat(32);
    let init = expect_ok(
        &mut provider,
        &json!({"op":"init","config":{"base_path": fix.base, "encryption_key": key}}),
    );
    assert_eq!(init["provider"], "did");
    let did = expect_ok(&mut provider, &json!({"op":"get_did"}));
    let nickname = expect_ok(
        &mut provider,
        &json!({"op":"set_nickname","nickname":"Confined"}),
    );
    assert_eq!(nickname["nickname"], "Confined");
    let read_back = expect_ok(&mut provider, &json!({"op":"get_nickname"}));
    assert_eq!(read_back["nickname"], "Confined");
    let persona = expect_ok(
        &mut provider,
        &json!({"op":"get_persona_did","name":"fixture"}),
    );
    assert_eq!(persona["owner_did"], did["did"]);
    assert!(!fs::read(fix.root.join("nickname.enc")).unwrap().is_empty());
    assert!(!fs::read(fix.root.join("personas").join("fixture.enc"))
        .unwrap()
        .is_empty());

    let granted = fix.root.join("nickname.enc");
    fs::remove_file(&granted).unwrap();
    std::os::unix::fs::symlink(&fix.outside_file, &granted).unwrap();
    let denied = json_line(
        &mut provider,
        &json!({"op":"set_nickname","nickname":"Outside"}),
    );
    assert_eq!(denied["status"], "error", "{denied}");
    assert_eq!(denied["code"], "storage_error");
    let write_reason = denied["message"].as_str().unwrap().to_string();
    assert!(
        write_reason.starts_with("did-provider: failed to save nickname:"),
        "{write_reason}"
    );
    assert_eq!(fs::read(&fix.outside_file).unwrap(), b"outside-bytes");
    let (cap_row, rights_row) = confinement_rows(&provider);
    expect_ok(&mut provider, &json!({"op":"shutdown"}));
    let stderr = provider.stderr();
    let status = provider.wait().unwrap();
    assert!(status.success(), "{status} {stderr}");
    assert_witness(&stderr, "socket", 1, "seccomp refused socket");
    assert_witness(
        &stderr,
        "signal-host",
        3,
        "the pid namespace has no such host process",
    );
    assert_witness(
        &stderr,
        "exec-unbound",
        EACCES,
        "landlock refused exec of a file other than PROVIDER_EXECUTABLE",
    );
    assert_witness(
        &stderr,
        "outside-read",
        EACCES,
        "landlock refused the read outside STORAGE_ROOT",
    );
    assert_witness(
        &stderr,
        "outside-write",
        EACCES,
        "landlock refused the write outside STORAGE_ROOT",
    );

    let exec_reason = unbound_exec_reason(&mut fix.launch);
    let read_fix = prepare("did-provider", "did", false);
    fs::remove_file(read_fix.root.join("nickname.enc")).ok();
    std::os::unix::fs::symlink(&read_fix.outside_file, read_fix.root.join("nickname.enc")).unwrap();
    let mut reader = spawn_provider(&read_fix.launch).unwrap();
    let denied = json_line(
        &mut reader,
        &json!({"op":"init","config":{"base_path": read_fix.base, "encryption_key": key}}),
    );
    assert_eq!(denied["code"], "storage_error", "{denied}");
    let read_reason = denied["message"].as_str().unwrap().to_string();
    assert!(
        read_reason.starts_with("did-provider: failed to read nickname:"),
        "{read_reason}"
    );
    assert_eq!(fs::read(&read_fix.outside_file).unwrap(), b"outside-bytes");

    let write_errno = errno_from_os_error(&write_reason);
    let read_errno = errno_from_os_error(&read_reason);
    header("did-provider");
    print_row(
        "permitted",
        "init",
        "ok",
        "wrote nickname state under STORAGE_ROOT",
    );
    print_row(
        "permitted",
        "get_did",
        "ok",
        "answered from the device key in memory",
    );
    print_row(
        "permitted",
        "set_nickname",
        "ok",
        "wrote nickname.enc under STORAGE_ROOT",
    );
    print_row("permitted", "get_nickname", "ok", "read nickname.enc back");
    print_row(
        "permitted",
        "get_persona_did",
        "ok",
        "wrote personas/fixture.enc under STORAGE_ROOT",
    );
    print_row("permitted", "shutdown", "ok", "answered and exited");
    print_denied(
        "write outside STORAGE_ROOT",
        write_errno,
        &write_reason,
        &positive_file(&fix.outside_file),
    );
    print_denied(
        "read outside STORAGE_ROOT",
        read_errno,
        &read_reason,
        &positive_file(&read_fix.outside_file),
    );
    print_denied("socket", 1, "seccomp refused socket", &positive_socket());
    print_denied(
        "exec a copy of the provider",
        EACCES,
        &exec_reason,
        &positive_exec(&fix.launch.copy),
    );
    print_denied(
        "signal a host pid",
        3,
        "the pid namespace has no such host process",
        &positive_kill(),
    );
    print_row("confined", "/proc/self/status CapBnd", "0", &cap_row);
    print_row(
        "confined",
        "STORAGE_ROOT rights",
        &rights_row,
        "read file, read directory, write file, truncate, make regular file, make directory, remove file, remove directory",
    );
    println!();
}

fn unbound_exec_reason(launch: &mut ProviderLaunch) -> String {
    let real = launch.execute.clone();
    launch.binary = launch.copy.clone();
    launch.execute = real;
    launch.preload = false;
    let err = match spawn_provider(launch) {
        Ok(running) => running.stderr(),
        Err(err) => err,
    };
    assert!(
        err.contains("errno=13"),
        "unbound exec of the real binary was not refused: {err}"
    );
    "linux confinement refused: exec of PROVIDER_EXECUTABLE failed errno=13".to_string()
}

#[test]
fn wallet_provider_binary_under_its_profile() {
    let program = binary("wallet-provider");
    println!("{}", describe_paths(&ldd_paths(&program)));
    let mut fix = prepare("wallet-provider", "wallet", true);
    let mut provider = spawn_provider(&fix.launch).unwrap_or_else(|err| panic!("{err}"));
    let init = json_line(
        &mut provider,
        &json!({"op":"init","config":{"base_path": fix.base.display().to_string()}}),
    );
    assert_eq!(init["status"], "ok", "{init}");
    assert_eq!(init["data"]["storage_configured"], true, "{init}");
    let status = json_line(&mut provider, &json!({"op":"status"}));
    assert_eq!(status["status"], "ok", "{status}");
    let created = wallet(
        &mut provider,
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Confined".to_string()),
            create_new: false,
        },
    );
    let account_id = created["account"]["account_id"]
        .as_str()
        .unwrap()
        .to_string();
    let listed = wallet(
        &mut provider,
        WalletProviderOperationV2::ListAccounts {
            include_revoked: false,
        },
    );
    assert!(listed["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["account_id"] == account_id));
    let store = fs::read_to_string(fix.root.join("wallet-state.json")).unwrap();
    assert!(store.contains(&account_id), "{store}");
    assert!(fs::metadata(fix.root.join("wallet-key.hex")).unwrap().len() > 0);
    let (cap_row, rights_row) = confinement_rows(&provider);
    let shutdown = json_line(&mut provider, &json!({"op":"shutdown"}));
    assert_eq!(shutdown["status"], "ok", "{shutdown}");
    let stderr = provider.stderr();
    assert!(provider.wait().unwrap().success(), "{stderr}");
    assert_witness(&stderr, "socket", 1, "seccomp refused socket");
    assert_witness(
        &stderr,
        "signal-host",
        3,
        "the pid namespace has no such host process",
    );
    assert_witness(
        &stderr,
        "exec-unbound",
        EACCES,
        "landlock refused exec of a file other than PROVIDER_EXECUTABLE",
    );
    assert_witness(
        &stderr,
        "outside-read",
        EACCES,
        "landlock refused the read outside STORAGE_ROOT",
    );
    assert_witness(
        &stderr,
        "outside-write",
        EACCES,
        "landlock refused the write outside STORAGE_ROOT",
    );
    let exec_reason = unbound_exec_reason(&mut fix.launch);

    let outside = prepare("wallet-provider", "wallet", false);
    let mut denied_provider = spawn_provider(&outside.launch).unwrap();
    // The outside base is not the granted tree. Init for it must fail.
    let denied = json_line(
        &mut denied_provider,
        &json!({"op":"init","config":{"base_path": outside.outside_base.display().to_string()}}),
    );
    // First init the granted root so the process is up, then the outside init.
    // The call above was the first init. If the launcher's storage is the granted
    // root, an outside base is a different path.
    assert_eq!(denied["status"], "error", "{denied}");
    assert_eq!(denied["code"], "storage_error", "{denied}");
    let outside_reason = denied["message"].as_str().unwrap().to_string();
    assert!(
        outside_reason.contains("wallet storage"),
        "{outside_reason}"
    );
    assert!(!outside.outside_base.join("ElastOS").exists());
    let read_fix = prepare("wallet-provider", "wallet", false);
    let outside_wallet = read_fix
        .outside_base
        .join("ElastOS")
        .join("SystemServices")
        .join("Wallet");
    fs::create_dir_all(&outside_wallet).unwrap();
    for dir in [
        read_fix.outside_base.join("ElastOS"),
        read_fix.outside_base.join("ElastOS").join("SystemServices"),
        outside_wallet.clone(),
    ] {
        let mut mode = fs::metadata(&dir).unwrap().permissions();
        mode.set_mode(0o700);
        fs::set_permissions(&dir, mode).unwrap();
    }
    fs::write(
        outside_wallet.join("wallet-key.hex"),
        b"not-the-granted-key",
    )
    .unwrap();
    let mut reader = spawn_provider(&read_fix.launch).unwrap();
    let denied_read = json_line(
        &mut reader,
        &json!({"op":"init","config":{"base_path": read_fix.outside_base.display().to_string()}}),
    );
    assert_eq!(denied_read["status"], "error", "{denied_read}");
    assert_eq!(denied_read["code"], "storage_error", "{denied_read}");
    let read_reason = denied_read["message"].as_str().unwrap().to_string();
    assert_eq!(fs::read(&read_fix.outside_file).unwrap(), b"outside-bytes");

    let write_errno = errno_from_os_error(&outside_reason);
    let read_errno = errno_from_os_error(&read_reason);
    header("wallet-provider");
    print_row(
        "permitted",
        "init",
        "ok",
        "created the wallet directory and key under STORAGE_ROOT",
    );
    print_row("permitted", "status", "ok", "answered from memory");
    print_row(
        "permitted",
        "wallet_contract create_managed_account",
        "ok",
        "wrote the account under STORAGE_ROOT",
    );
    print_row(
        "permitted",
        "wallet_contract list_accounts",
        "ok",
        "listed the account stored under STORAGE_ROOT",
    );
    print_row("permitted", "shutdown", "ok", "answered and exited");
    print_denied(
        "write outside STORAGE_ROOT",
        write_errno,
        &outside_reason,
        &positive_file(&outside.outside_file),
    );
    print_denied(
        "read outside STORAGE_ROOT",
        read_errno,
        &read_reason,
        &positive_file(&read_fix.outside_file),
    );
    print_denied("socket", 1, "seccomp refused socket", &positive_socket());
    print_denied(
        "exec a copy of the provider",
        EACCES,
        &exec_reason,
        &positive_exec(&fix.launch.copy),
    );
    print_denied(
        "signal a host pid",
        3,
        "the pid namespace has no such host process",
        &positive_kill(),
    );
    print_row("confined", "/proc/self/status CapBnd", "0", &cap_row);
    print_row(
        "confined",
        "STORAGE_ROOT rights",
        &rights_row,
        "read file, read directory, write file, truncate, make regular file, make directory, remove file, remove directory",
    );
    println!();
}

fn wallet(provider: &mut RunningProvider, operation: WalletProviderOperationV2) -> Value {
    let context = VerifiedWalletInvocationContext::new(
        "person:local:alice",
        "session:confine",
        Some("proof:confine".to_string()),
        "grant:confine",
        "wallet",
        "launch:confine",
    )
    .unwrap();
    let issued = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let request = WalletProviderRequestV2::new(
        &context,
        format!("wallet-request:{:032x}", issued),
        issued,
        issued.saturating_add(120),
        operation,
    )
    .unwrap();
    let response = json_line(
        provider,
        &json!({
            "op": "wallet_contract",
            "request": request,
            "_runtime_invocation": {
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": "wallet",
                "op": "wallet_contract",
                "capability": "provider:runtime->wallet:wallet_contract",
                "transport": "runtime-local-provider-plane",
                "carrier": null,
                "transfer": "json",
                "range": null,
                "progress": null,
                "abi": {
                    "schema": "elastos.provider.transfer-abi/v1",
                    "transfer": "json",
                    "transport": "runtime-local-provider-plane",
                    "range_supported": false,
                    "progress_supported": false,
                    "progress_mode": "none",
                    "transport_native_stream": false,
                    "backpressure": "not_applicable",
                    "cancel_supported": false
                }
            }
        }),
    );
    assert_eq!(response["status"], "ok", "{response}");
    let bytes = serde_json::to_vec(&response["data"]).unwrap();
    match WalletProviderResponseV2::decode_for_request(&bytes, &request)
        .unwrap()
        .result
    {
        WalletResultV2::Ok { data } => data,
        WalletResultV2::Error { code, message } => panic!("{code}: {message}"),
    }
}

#[test]
fn model_provider_binary_under_its_profile() {
    let program = binary("model-provider");
    println!("{}", describe_paths(&ldd_paths(&program)));
    let mut fix = prepare("model-provider", "model", true);
    let mut provider = spawn_provider(&fix.launch).unwrap_or_else(|err| panic!("{err}"));
    let init = expect_ok(&mut provider, &model_init(&fix.base, None));
    assert_eq!(init["provider"], "model-provider");
    assert_eq!(init["offers_ready"], 1);
    let status = expect_ok(&mut provider, &json!({"op":"status"}));
    assert_eq!(status["offers_ready"], 1);
    let offers = expect_ok(&mut provider, &json!({"op":"offers_list"}));
    assert!(offers["offers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|o| o["id"] == "confine-hosted-text"));
    let input = json!({"schema": TEXT_INPUT_V1_SCHEMA, "prompt": "confined read"});
    let issued = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let request_id = format!("model-v1:{issued}:fixture-linux-confine");
    let binding = RuntimeCreateBinding {
        schema: RUNTIME_CREATE_BINDING_SCHEMA.to_string(),
        principal_id: "person:local:confine".into(),
        session_id: "session:confine".into(),
        capsule_id: "assistant".into(),
        grant_id: "grant:confine".into(),
        request_id: request_id.clone(),
        offer_id: "confine-hosted-text".into(),
        operation: "text.generate".into(),
        input_hash: model_input_hash(&input).unwrap(),
    };
    let run_id = model_run_id(&binding);
    let created = expect_ok(
        &mut provider,
        &json!({
            "op": "runs_create",
            "offer_id": "confine-hosted-text",
            "operation": "text.generate",
            "input": input,
            "runtime_binding": binding
        }),
    );
    assert_eq!(
        created["terminal"]["error"]["message"],
        "Hosted external HTTPS is paused."
    );
    let runs = fix.root.join("runs");
    assert!(
        fs::read_dir(&runs).unwrap().next().is_some(),
        "a run file must land under STORAGE_ROOT"
    );
    let fetched = expect_ok(
        &mut provider,
        &json!({
            "op": "runs_get",
            "run_id": run_id,
            "runtime_binding": {
                "schema": elastos_model_contract::RUNTIME_ACCESS_BINDING_SCHEMA,
                "principal_id": "person:local:confine",
                "session_id": "session:confine",
                "capsule_id": "assistant",
                "grant_id": "grant:confine",
                "request_id": request_id.clone(),
                "run_id": run_id.clone()
            }
        }),
    );
    assert_eq!(fetched["run_id"], created["run_id"]);
    let (cap_row, rights_row) = confinement_rows(&provider);
    let shutdown = expect_ok(&mut provider, &json!({"op":"shutdown"}));
    assert_eq!(shutdown["shutdown"], true);
    let stderr = provider.stderr();
    assert!(provider.wait().unwrap().success(), "{stderr}");
    assert_witness(&stderr, "socket", 1, "seccomp refused socket");
    assert_witness(
        &stderr,
        "signal-host",
        3,
        "the pid namespace has no such host process",
    );
    assert_witness(
        &stderr,
        "exec-unbound",
        EACCES,
        "landlock refused exec of a file other than PROVIDER_EXECUTABLE",
    );
    assert_witness(
        &stderr,
        "outside-read",
        EACCES,
        "landlock refused the read outside STORAGE_ROOT",
    );
    assert_witness(
        &stderr,
        "outside-write",
        EACCES,
        "landlock refused the write outside STORAGE_ROOT",
    );
    let runs = fix.root.join("runs");
    let moved = fix.outside_base.join("moved-runs");
    fs::rename(&runs, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &runs).unwrap();
    let mut reader = spawn_provider(&fix.launch).unwrap();
    let reread = json_line(&mut reader, &model_init(&fix.base, None));
    let read_reason = if reread["status"] == "error" {
        format!(
            "{}: {}",
            reread["code"].as_str().unwrap_or("error"),
            reread["message"].as_str().unwrap_or("")
        )
    } else {
        let denied_read = json_line(
            &mut reader,
            &json!({
                "op": "runs_get",
                "run_id": run_id,
                "runtime_binding": {
                    "schema": elastos_model_contract::RUNTIME_ACCESS_BINDING_SCHEMA,
                    "principal_id": "person:local:confine",
                    "session_id": "session:confine",
                    "capsule_id": "assistant",
                    "grant_id": "grant:confine",
                    "request_id": request_id,
                    "run_id": run_id
                }
            }),
        );
        assert_eq!(denied_read["status"], "error", "{denied_read}");
        format!(
            "{}: {}",
            denied_read["code"].as_str().unwrap_or("error"),
            denied_read["message"].as_str().unwrap_or("")
        )
    };
    assert_eq!(fs::read(&fix.outside_file).unwrap(), b"outside-bytes");
    let exec_reason = unbound_exec_reason(&mut fix.launch);

    let outside = prepare("model-provider", "model", false);
    let mut denied_provider = spawn_provider(&outside.launch).unwrap();
    let denied = json_line(
        &mut denied_provider,
        &model_init(&outside.base, Some(&outside.outside_base.join("journal"))),
    );
    assert_eq!(denied["status"], "error", "{denied}");
    let outside_reason = format!(
        "{}: {}",
        denied["code"].as_str().unwrap_or("error"),
        denied["message"].as_str().unwrap_or("")
    );
    assert!(!outside_reason.is_empty(), "{denied}");
    assert_eq!(fs::read(&outside.outside_file).unwrap(), b"outside-bytes");

    header("model-provider");
    print_row(
        "permitted",
        "init",
        "ok",
        "created runs/ under STORAGE_ROOT",
    );
    print_row("permitted", "status", "ok", "answered from memory");
    print_row(
        "permitted",
        "offers_list",
        "ok",
        "listed the hosted offer from memory",
    );
    print_row(
        "permitted",
        "runs_create",
        "ok",
        "wrote the run record under STORAGE_ROOT",
    );
    print_row(
        "permitted",
        "runs_get",
        "ok",
        "read the run record back from STORAGE_ROOT",
    );
    print_row("permitted", "shutdown", "ok", "answered and exited");
    assert!(
        outside_reason.contains("journal_access_denied") || outside_reason.contains("not writable"),
        "model outside write mapping drifted: {outside_reason}"
    );
    print_denied(
        "write outside STORAGE_ROOT",
        EACCES,
        "landlock refused the write outside STORAGE_ROOT",
        &positive_file(&outside.outside_file),
    );
    print_denied(
        "read outside STORAGE_ROOT",
        EACCES,
        "landlock refused the read outside STORAGE_ROOT",
        &positive_file(&fix.outside_file),
    );
    print_denied("socket", 1, "seccomp refused socket", &positive_socket());
    print_denied(
        "exec a copy of the provider",
        EACCES,
        &exec_reason,
        &positive_exec(&fix.launch.copy),
    );
    print_denied(
        "signal a host pid",
        3,
        "the pid namespace has no such host process",
        &positive_kill(),
    );
    println!(
        "provider mapping for the denied outside journal read stays {read_reason}. That string is not the Landlock-read row."
    );
    print_row("confined", "/proc/self/status CapBnd", "0", &cap_row);
    print_row(
        "confined",
        "STORAGE_ROOT rights",
        &rights_row,
        "read file, read directory, write file, truncate, make regular file, make directory, remove file, remove directory",
    );
    println!("runs_events and runs_cancel have no named macOS test. This run does not claim them.");
    println!("Hosted dispatch stops in the binary before a socket, with \"Hosted external HTTPS is paused.\" The socket row is the kernel refusal from the same process.");
    println!();
}

fn model_init(base: &Path, journal: Option<&Path>) -> Value {
    let mut extra = json!({
        "provider_id": "model-provider",
        "offers": [{
            "id": "confine-hosted-text",
            "title": "Confined Hosted Text",
            "operation": "text.generate",
            "input_modalities": ["text/plain"],
            "output_modalities": ["text/plain"],
            "policy": {
                "concurrency_limit": 1,
                "input_bytes_limit": 4096,
                "inline_output_bytes_limit": 4096,
                "event_bytes_limit": 4096,
                "runtime_ms_limit": 10000,
                "retention_secs": 60,
                "cancel_settlement_timeout_ms": 100
            },
            "adapter": {
                "kind": "open_ai_compatible_text",
                "api_url": "https://hosted.invalid/v1/chat/completions",
                "model": "confine/text",
                "hosted": {
                    "backend_provider_label": "Confine Fixture",
                    "selection_mode": "pinned",
                    "privacy_policy_ref": "fixture:privacy:confine",
                    "terms_ref": "fixture:terms:confine",
                    "upstream_routing_fallback_assertion": "operator_asserted_disabled"
                }
            },
            "enabled": true
        }]
    });
    if let Some(journal) = journal {
        extra["journal_dir"] = json!(journal);
    }
    json!({
        "op": "init",
        "config": {
            "base_path": base,
            "allowed_paths": [],
            "read_only": false,
            "encryption_key": "",
            "extra": extra
        }
    })
}
