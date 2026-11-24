//! Production Linux start of llama-server b10516. Ignored unless
//! `ELASTOS_TEST_LLAMA_SERVER`, `ELASTOS_TEST_LLAMA_LIBS`, and
//! `ELASTOS_TEST_GGUF` are set. The Runtime admit path is
//! `libexec/llama.cpp/<build>/<platform>` and
//! `model-preparation/admitted-<64 hex>/`, so this row copies those env files
//! into that layout. The copy of the weights is mode 0600, one link, owned by
//! the Runtime user.

use super::*;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[tokio::test]
#[ignore = "set ELASTOS_TEST_LLAMA_SERVER, ELASTOS_TEST_LLAMA_LIBS, and ELASTOS_TEST_GGUF"]
async fn linux_local_model_completes_inside_the_fence() {
    let Ok(server) = std::env::var("ELASTOS_TEST_LLAMA_SERVER") else {
        return;
    };
    let Ok(libs) = std::env::var("ELASTOS_TEST_LLAMA_LIBS") else {
        return;
    };
    let Ok(gguf) = std::env::var("ELASTOS_TEST_GGUF") else {
        return;
    };
    if server.is_empty() || libs.is_empty() || gguf.is_empty() {
        return;
    }
    let server = std::fs::canonicalize(&server).expect("ELASTOS_TEST_LLAMA_SERVER");
    let libs = std::fs::canonicalize(&libs).expect("ELASTOS_TEST_LLAMA_LIBS");
    let gguf = std::fs::canonicalize(&gguf).expect("ELASTOS_TEST_GGUF");
    let binary = if server.is_file() {
        server
    } else {
        let nested = server.join("llama-server");
        assert!(
            nested.is_file(),
            "ELASTOS_TEST_LLAMA_SERVER has no llama-server"
        );
        nested
    };
    assert!(libs.is_dir(), "ELASTOS_TEST_LLAMA_LIBS is a directory");
    assert!(gguf.is_file(), "ELASTOS_TEST_GGUF is a file");

    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let base = temp.path().join("base");
    std::fs::create_dir(&base).unwrap();
    let base = std::fs::canonicalize(&base).unwrap();
    let bundle = base.join("libexec/llama.cpp/b10516/linux");
    std::fs::create_dir_all(&bundle).unwrap();
    copy_library_tree(&libs, &bundle);
    let engine = bundle.join("llama-server");
    std::fs::copy(&binary, &engine).unwrap();
    std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
    write_engine_receipt(&bundle);
    let digest = file_sha256(&gguf);
    let admitted = base.join(format!("model-preparation/admitted-{digest}"));
    std::fs::create_dir_all(&admitted).unwrap();
    let model = admitted.join("weights.gguf");
    std::fs::copy(&gguf, &model).unwrap();
    std::fs::set_permissions(&model, std::fs::Permissions::from_mode(0o600)).unwrap();
    let outside = temp.path().join("outside-proof");
    std::fs::write(&outside, b"outside").unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o644)).unwrap();
    let outside = std::fs::canonicalize(&outside).unwrap();
    let journal = base.join("providers/model-provider/journal");
    std::fs::create_dir_all(&journal).unwrap();
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o700)).unwrap();

    let provider = build_model_provider(temp.path());
    let engine_sha = format!("sha256:{}", file_sha256(&engine));
    let model_sha = format!("sha256:{digest}");
    let mut config = ProviderConfig {
        base_path: base.to_string_lossy().into_owned(),
        ..ProviderConfig::default()
    };
    config.extra = serde_json::json!({
        "journal_dir": journal,
        "offers": [{
            "id": "local",
            "title": "Local",
            "operation": "text.generate",
            "input_modalities": ["text/plain"],
            "output_modalities": ["text/plain"],
            "enabled": true,
            "policy": {
                "concurrency_limit": 1,
                "input_bytes_limit": 4096,
                "inline_output_bytes_limit": 4096,
                "event_bytes_limit": 4096,
                "runtime_ms_limit": 600000,
                "retention_secs": 60,
                "cancel_settlement_timeout_ms": 2000
            },
            "adapter": {
                "kind": "local_llama_cpp_text",
                "engine": {"path": engine, "sha256": engine_sha},
                "model": {"path": model, "sha256": model_sha},
                "settings": {
                    "context_size": 512,
                    "parallel": 1,
                    "threads": 2,
                    "batch_threads": 2,
                    "gpu_layers": 0,
                    "health_timeout_ms": 180000,
                    "shutdown_timeout_ms": 5000,
                    "enable_thinking": false
                }
            }
        }]
    });
    let (confined, sockets, vacant, _) = ProviderBridge::spawn_confined_model_from_rights(
        &committed_authority("model"),
        &CheckedExecutable::for_test(&provider),
        &journal,
        config,
    )
    .await
    .unwrap_or_else(|error| panic!("production model start: {error}"));
    let mut stop = KillTree(fork_pid(confined.bridge()) as u32);
    assert!(vacant.is_empty(), "one offer binds one broker");
    let broker = sockets["local"].clone();
    assert!(broker.ends_with("/0.sock"), "{broker}");
    let other = broker.replace("/0.sock", "/1.listen/engine.sock");
    let input = serde_json::json!({
        "schema": elastos_model_contract::TEXT_INPUT_V2_SCHEMA,
        "messages": [{"role": "user", "content": "Say hello in one word."}],
        "max_output_tokens": 16
    });
    let issued = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let request_id = format!("model-v1:{issued}:b3m6");
    let binding = elastos_model_contract::RuntimeCreateBinding {
        schema: elastos_model_contract::RUNTIME_CREATE_BINDING_SCHEMA.into(),
        principal_id: "principal".into(),
        session_id: "session".into(),
        capsule_id: "model-provider".into(),
        grant_id: "grant".into(),
        request_id,
        offer_id: "local".into(),
        operation: "text.generate".into(),
        input_hash: elastos_model_contract::model_input_hash(&input).unwrap(),
    };
    let created = confined
        .bridge()
        .send_raw(&serde_json::json!({
            "op": "runs_create",
            "offer_id": "local",
            "operation": "text.generate",
            "input": input,
            "runtime_binding": binding
        }))
        .await
        .unwrap_or_else(|error| panic!("runs_create: {error}"));
    assert_eq!(created["status"], "ok", "{created}");
    let listen = PathBuf::from(broker.replace("/0.sock", "/0.listen/engine.sock"));
    assert!(
        std::fs::symlink_metadata(&listen)
            .unwrap()
            .file_type()
            .is_socket(),
        "the engine bound the listen inode"
    );
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": "Say hi."}],
        "max_tokens": 8
    })
    .to_string();
    let completion = unix_http(
        Path::new(&broker),
        &format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .expect("completion through the broker");
    assert!(completion.contains("200"), "{completion}");
    assert!(completion.contains("content"), "{completion}");
    assert!(
        UnixStream::connect(&other).is_err(),
        "another offer has no listener"
    );
    for pid in descendants(stop.0) {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let field = |name: &str| {
            status.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key == name).then(|| value.trim().to_string())
            })
        };
        assert_eq!(field("NoNewPrivs").as_deref(), Some("1"), "{pid} {status}");
        assert_eq!(field("Seccomp").as_deref(), Some("2"), "{pid} {status}");
    }
    let errno = confined_open_errno(stop.0, &outside);
    assert_eq!(
        errno,
        libc::EACCES as i64,
        "outside file in this process tree"
    );
    confined.bridge().shutdown().await.ok();
    stop.0 = 0;
}

struct KillTree(u32);

impl Drop for KillTree {
    fn drop(&mut self) {
        if self.0 != 0 {
            for pid in descendants(self.0) {
                unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            }
        }
    }
}

fn descendants(root: u32) -> Vec<u32> {
    let mut all = vec![root];
    loop {
        let before = all.len();
        let entries = std::fs::read_dir("/proc").unwrap();
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if all.contains(&pid) {
                continue;
            }
            let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
                continue;
            };
            let parent = status.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key == "PPid").then(|| value.trim().parse::<u32>().ok())?
            });
            if parent.is_some_and(|parent| all.contains(&parent)) {
                all.push(pid);
            }
        }
        if all.len() == before {
            return all;
        }
    }
}

fn copy_library_tree(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let name = entry.file_name();
        if name == ".elastos-engine.json" {
            continue;
        }
        let dest = to.join(&name);
        let meta = std::fs::symlink_metadata(entry.path()).unwrap();
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(entry.path()).unwrap();
            std::os::unix::fs::symlink(&target, &dest).unwrap();
        } else if meta.is_dir() {
            std::fs::create_dir(&dest).unwrap();
            copy_library_tree(&entry.path(), &dest);
        } else if meta.is_file() {
            std::fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

fn write_engine_receipt(bundle: &Path) {
    let mut entries = Vec::new();
    let mut stack = vec![bundle.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            let relative = path.strip_prefix(bundle).unwrap();
            if relative == Path::new("llama-server") {
                continue;
            }
            let text = relative.to_str().unwrap();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                entries.push(serde_json::json!({
                    "path": text,
                    "type": "symlink",
                    "target": target
                }));
            } else if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                entries.push(serde_json::json!({
                    "path": text,
                    "type": "file",
                    "sha256": format!("sha256:{}", file_sha256(&path))
                }));
            }
        }
    }
    let receipt = bundle.join(".elastos-engine.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&receipt)
        .unwrap();
    file.write_all(
        serde_json::to_string(&serde_json::json!({
            "schema": "elastos.local-model-engine/v2",
            "entries": entries
        }))
        .unwrap()
        .as_bytes(),
    )
    .unwrap();
}

fn file_sha256(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path).unwrap();
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    format!("{:x}", hasher.finalize())
}

fn build_model_provider(dir: &Path) -> PathBuf {
    let manifest = format!(
        "{}/../../../capsules/model-provider/Cargo.toml",
        env!("CARGO_MANIFEST_DIR")
    );
    let target = dir.join("provider-target");
    let built = std::process::Command::new("cargo")
        .args([
            "build",
            "--manifest-path",
            &manifest,
            "--bin",
            "model-provider",
        ])
        .env("CARGO_TARGET_DIR", &target)
        .env_remove("CARGO_BUILD_BUILD_DIR")
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "model-provider build: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    target.join("debug/model-provider")
}

fn unix_http(socket: &Path, request: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(180)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    stream.write_all(request.as_bytes())?;
    let mut body = String::new();
    stream.read_to_string(&mut body)?;
    Ok(body)
}

fn confined_open_errno(pid: u32, path: &Path) -> i64 {
    let mut bytes = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()).to_vec();
    bytes.push(0);
    let pid = pid as libc::pid_t;
    unsafe {
        if libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) != 0 {
            panic!("ptrace attach: {}", std::io::Error::last_os_error());
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, libc::PTRACE_O_TRACESYSGOOD);
        let mut saved: libc::user_regs_struct = std::mem::zeroed();
        libc::ptrace(libc::PTRACE_GETREGS, pid, 0, &mut saved);
        let insn = syscall_address(pid);
        let slot = stack_pointer(&saved) - 256;
        poke_bytes(pid, slot, &bytes);
        let mut regs = saved;
        set_openat(&mut regs, insn, slot);
        libc::ptrace(libc::PTRACE_SETREGS, pid, 0, &regs);
        libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0);
        libc::waitpid(pid, &mut status, 0);
        libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0);
        libc::waitpid(pid, &mut status, 0);
        let mut after: libc::user_regs_struct = std::mem::zeroed();
        libc::ptrace(libc::PTRACE_GETREGS, pid, 0, &mut after);
        let result = syscall_result(&after);
        libc::ptrace(libc::PTRACE_SETREGS, pid, 0, &saved);
        libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
        if result < 0 {
            -result
        } else {
            result
        }
    }
}

fn poke_bytes(pid: libc::pid_t, addr: u64, bytes: &[u8]) {
    let mut offset = 0;
    while offset < bytes.len() {
        let mut word = [0u8; 8];
        let count = (bytes.len() - offset).min(8);
        word[..count].copy_from_slice(&bytes[offset..offset + count]);
        let value = u64::from_ne_bytes(word);
        let wrote = unsafe {
            libc::ptrace(
                libc::PTRACE_POKEDATA,
                pid,
                (addr + offset as u64) as *mut libc::c_void,
                value as *mut libc::c_void,
            )
        };
        assert_eq!(wrote, 0, "ptrace poke: {}", std::io::Error::last_os_error());
        offset += 8;
    }
}

fn syscall_address(pid: libc::pid_t) -> u64 {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else { continue };
        let Some(perms) = parts.next() else { continue };
        if !perms.starts_with("r-x") {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let start = u64::from_str_radix(start, 16).unwrap();
        let end = u64::from_str_radix(end, 16)
            .unwrap()
            .min(start + 256 * 1024);
        let mut addr = start;
        while addr + 8 <= end {
            let word = peek(pid, addr);
            let bytes = word.to_ne_bytes();
            if let Some(found) = find_syscall(&bytes) {
                return addr + found;
            }
            addr += 8;
        }
    }
    panic!("the provider text has no syscall instruction");
}

fn peek(pid: libc::pid_t, addr: u64) -> u64 {
    unsafe {
        *libc::__errno_location() = 0;
        let word = libc::ptrace(libc::PTRACE_PEEKDATA, pid, addr as *mut libc::c_void, 0);
        assert_eq!(*libc::__errno_location(), 0, "ptrace peek");
        word as u64
    }
}

#[cfg(target_arch = "x86_64")]
fn find_syscall(bytes: &[u8; 8]) -> Option<u64> {
    (0..7)
        .find(|index| bytes[*index] == 0x0f && bytes[*index + 1] == 0x05)
        .map(|index| index as u64)
}

#[cfg(target_arch = "aarch64")]
fn find_syscall(bytes: &[u8; 8]) -> Option<u64> {
    (0..2)
        .find(|index| {
            let start = index * 4;
            u32::from_ne_bytes(bytes[start..start + 4].try_into().unwrap()) == 0xd400_0001
        })
        .map(|index| index as u64 * 4)
}

#[cfg(target_arch = "x86_64")]
fn stack_pointer(regs: &libc::user_regs_struct) -> u64 {
    regs.rsp
}

#[cfg(target_arch = "aarch64")]
fn stack_pointer(regs: &libc::user_regs_struct) -> u64 {
    regs.sp
}

#[cfg(target_arch = "x86_64")]
fn set_openat(regs: &mut libc::user_regs_struct, insn: u64, path: u64) {
    regs.rip = insn;
    regs.orig_rax = 257;
    regs.rax = 257;
    regs.rdi = (-100i64) as u64;
    regs.rsi = path;
    regs.rdx = libc::O_RDONLY as u64;
    regs.r10 = 0;
}

#[cfg(target_arch = "aarch64")]
fn set_openat(regs: &mut libc::user_regs_struct, insn: u64, path: u64) {
    regs.pc = insn;
    regs.regs[8] = 56;
    regs.regs[0] = (-100i64) as u64;
    regs.regs[1] = path;
    regs.regs[2] = libc::O_RDONLY as u64;
    regs.regs[3] = 0;
}

#[cfg(target_arch = "x86_64")]
fn syscall_result(regs: &libc::user_regs_struct) -> i64 {
    regs.rax as i64
}

#[cfg(target_arch = "aarch64")]
fn syscall_result(regs: &libc::user_regs_struct) -> i64 {
    regs.regs[0] as i64
}
