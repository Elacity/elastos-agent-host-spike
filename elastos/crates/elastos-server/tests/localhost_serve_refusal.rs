//! One unreadable file under Users/ must leave the real `elastos serve` up.
//!
//! This is an integration test because `CARGO_BIN_EXE_elastos` is set only
//! here. A `#[test]` inside the binary runs the test harness, not `serve`.
//! Restoring the old `?` — the Refuse arm returns an error from
//! `setup_server_infrastructure` — makes this test fail: the process exits
//! and no storage route answers 503.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const STUB: &[u8] = b"localhost-provider-stub\n";
const STUB_SHA256: &str = "fe4d4ae6392aba6ebd7b7b954f970c4f96b28335d86da2aa1eff3dfa1bfe0dcf";

struct Serve {
    child: Child,
    output: Arc<Mutex<String>>,
    addr: String,
    data: PathBuf,
}

impl Drop for Serve {
    fn drop(&mut self) {
        let pid = self.child.id() as i32;
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        let _ = self.child.wait();
    }
}

#[test]
fn unreadable_users_file_keeps_serve_up_and_storage_answers_503() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    #[cfg(target_os = "macos")]
    let data = home.join("Library/Application Support/elastos");
    #[cfg(not(target_os = "macos"))]
    let data = home.join(".local/share/elastos");
    let storage = data.join("storage");
    std::fs::create_dir_all(&storage).unwrap();
    std::fs::create_dir_all(data.join("bin")).unwrap();
    std::fs::write(data.join("bin/localhost-provider"), STUB).unwrap();
    write_manifest(&data);
    let secret = data.join("Users/secret.bin");
    std::fs::create_dir_all(secret.parent().unwrap()).unwrap();
    std::fs::write(&secret, b"private").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let addr = format!("127.0.0.1:{port}");

    let mut child = Command::new(env!("CARGO_BIN_EXE_elastos"))
        .args(["serve", "-a", &addr, "--storage", storage.to_str().unwrap()])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let output = Arc::new(Mutex::new(String::new()));
    pump(child.stdout.take().unwrap(), Arc::clone(&output));
    pump(child.stderr.take().unwrap(), Arc::clone(&output));
    let mut serve = Serve {
        child,
        output,
        addr: addr.clone(),
        data: data.clone(),
    };

    let deadline = Instant::now() + Duration::from_secs(180);
    let mut health = 0;
    while Instant::now() < deadline {
        if let Some(status) = serve.child.try_wait().unwrap() {
            panic!(
                "serve exited {status} before it was ready\n{}",
                serve.output.lock().unwrap()
            );
        }
        if let Some((status, _)) = http(
            &addr,
            &format!("GET /api/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
        ) {
            health = status;
            if status == 200 && sentence_from(&serve.output.lock().unwrap()).is_some() {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let logged = serve.output.lock().unwrap().clone();
    let Some(sentence) = sentence_from(&logged) else {
        panic!("health {health}; serve did not print the sentence\n{logged}");
    };
    let sentence = sentence.to_string();
    assert!(serve.child.try_wait().unwrap().is_none(), "serve left");
    assert!(sentence.contains("Users/secret.bin"), "{sentence}");
    assert!(sentence.contains("not readable"), "{sentence}");
    assert_eq!(health, 200, "{logged}");

    let coords = std::fs::read_to_string(serve.data.join("runtime-coords.json")).unwrap();
    let secret = json_string(&coords, "attach_secret").expect("attach secret");
    let attach_body = format!(r#"{{"secret":"{secret}","scope":"shell"}}"#);
    let (status, body) = http(
        &addr,
        &format!(
            "POST /api/auth/attach HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{attach_body}",
            attach_body.len()
        ),
    )
    .unwrap_or_else(|| panic!("attach did not answer\n{logged}"));
    assert_eq!(status, 200, "{body}");
    let token = json_string(&body, "token").expect("token");
    let (status, body) = http(
        &addr,
        &format!(
            "GET /api/localhost/MyWebSite/index.html HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        ),
    )
    .unwrap_or_else(|| panic!("storage did not answer\n{logged}"));
    assert_eq!(status, 503, "{body}");
    assert_eq!(body, sentence);
    assert!(
        serve.child.try_wait().unwrap().is_none(),
        "serve left after 503"
    );
}

fn sentence_from(output: &str) -> Option<&str> {
    let line = output
        .lines()
        .find(|line| line.contains("Local apps are off. "))?;
    Some(line.split_once("Local apps are off. ").unwrap().1.trim())
}

fn write_manifest(data: &Path) {
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-amd64",
        ("linux", "aarch64") => "linux-arm64",
        ("macos", "aarch64") => "darwin-arm64",
        (os, arch) => panic!("unsupported test platform {os}-{arch}"),
    };
    let manifest = format!(
        r#"{{
  "external": {{
    "localhost-provider": {{
      "install_path": "bin/localhost-provider",
      "platforms": {{
        "{platform}": {{
          "checksum": "sha256:{STUB_SHA256}",
          "install_path": "bin/localhost-provider"
        }}
      }},
      "provider_runtime": {{
        "role": "provider",
        "substrate": "native",
        "runtime_abi": "elastos.provider-stdio/v1",
        "execution": "native-provider",
        "provides": "localhost://"
      }}
    }}
  }},
  "capsules": {{}},
  "profiles": {{}}
}}
"#
    );
    std::fs::write(data.join("components.json"), manifest).unwrap();
}

fn pump(mut pipe: impl Read + Send + 'static, slot: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    slot.lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            }
        }
    });
}

fn http(addr: &str, request: &str) -> Option<(u16, String)> {
    let mut stream =
        std::net::TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_secs(2)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok()?;
    stream.write_all(request.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(parsed) = split_http(&buf) {
                    return Some(parsed);
                }
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => return None,
        }
    }
    split_http(&buf)
}

fn split_http(buf: &[u8]) -> Option<(u16, String)> {
    let text = String::from_utf8_lossy(buf);
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    });
    match length {
        Some(length) if body.len() >= length => Some((status, body[..length].to_string())),
        Some(_) => None,
        None => Some((status, body.to_string())),
    }
}

fn json_string<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let after = text
        .split_once(&needle)?
        .1
        .trim_start()
        .strip_prefix(':')?
        .trim_start();
    let value = after.strip_prefix('"')?;
    Some(&value[..value.find('"')?])
}
