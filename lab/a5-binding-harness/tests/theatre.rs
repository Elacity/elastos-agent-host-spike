//! Theatre 9/9 plant: blockers treated as cleared, forged coords, loopback
//! stub that echoes identity and the expected reason words. A real assertion
//! must catch PASS. Timeouts do not count.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use a5_binding_harness::capability::Check;
use a5_binding_harness::contract::grade_pass;
use a5_binding_harness::http::{parse_coords, OperatorRuntime, Setup};
use a5_binding_harness::{acceptance, counts_as_accepted, Grade};

fn write_http(stream: &mut TcpStream, status: u16, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn handle_client(mut stream: TcpStream) {
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let line = req.lines().next().unwrap_or("");
    if line.starts_with("POST /api/auth/attach") {
        write_http(&mut stream, 200, br#"{"token":"stub-shell-token"}"#);
        return;
    }
    if line.starts_with("GET /api/health") {
        write_http(&mut stream, 200, br#"{"status":"ok"}"#);
        return;
    }
    if line.starts_with("POST /api/capsules") {
        write_http(
            &mut stream,
            200,
            br#"{"id":"instance-1","session_id":"sess-1","status":"running","identity":"agent-a"}"#,
        );
        return;
    }
    if line.starts_with("POST /api/capability/grant") {
        write_http(
            &mut stream,
            200,
            br#"{"request_id":"g1","id":"g1","success":true,"identity":"agent-a","owned_root":"UsersAI/agent-a/sess-1/instance-1"}"#,
        );
        return;
    }
    if line.starts_with("POST /api/capability/request") {
        write_http(
            &mut stream,
            200,
            br#"{"status":"pending","request_id":"g1"}"#,
        );
        return;
    }
    if line.starts_with("GET /api/capability/list") {
        write_http(
            &mut stream,
            200,
            br#"{"scope":"all_sessions_live","capabilities":[{"request_id":"g1","identity":"agent-a","session_id":"sess-1","instance_id":"instance-1","resource":"localhost://UsersAI/agent-a/sess-1/instance-1/notes","owned_root":"UsersAI/agent-a/sess-1/instance-1"}]}"#,
        );
        return;
    }
    if line.starts_with("POST /api/capability/use")
        || line.starts_with("POST /api/sessions/")
        || line.starts_with("POST /api/provider/localhost/write")
    {
        write_http(
            &mut stream,
            200,
            br#"{"status":"ok","reason":"identity does not match the grant","code":"identity"}"#,
        );
        return;
    }
    if line.starts_with("GET /api/localhost/") {
        write_http(&mut stream, 200, b"a5-binding public fixture bytes\n");
        return;
    }
    if line.starts_with("PUT /api/localhost/") {
        write_http(&mut stream, 200, br#"{"ok":true}"#);
        return;
    }
    if line.starts_with("DELETE /api/capsules/") {
        write_http(&mut stream, 200, br#"{"ok":true}"#);
        return;
    }
    write_http(&mut stream, 404, br#"{"error":"missing"}"#);
}

fn start_stub() -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind theatre stub");
    listener
        .set_nonblocking(true)
        .expect("nonblocking theatre stub");
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let handle = thread::spawn(move || {
        while !flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => handle_client(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (port, stop, handle)
}

#[test]
fn theatre_stub_does_not_accept_nine_of_nine() {
    let (port, stop, handle) = start_stub();
    let coords = std::env::temp_dir().join(format!("a5-theatre-coords-{port}.json"));
    std::fs::write(
        &coords,
        format!(
            r#"{{"api_url":"http://127.0.0.1:{port}","runtime_kind":"operator","attach_secret":"forged-attach-secret"}}"#
        ),
    )
    .unwrap();
    assert!(parse_coords(&std::fs::read(&coords).unwrap()).is_ok());

    let setup = Setup::from_lookup(|_| Some(coords.clone())).expect("forged coords");
    let mut runtime = OperatorRuntime::attach(&setup).expect("theatre stub attach");
    let mut accepted = 0usize;
    let mut failed = 0usize;
    for check in Check::ALL {
        match check.run(&mut runtime) {
            Ok(_) => match runtime.take_binding_evidence() {
                Some(evidence) => match grade_pass(evidence) {
                    Ok(_) => accepted += 1,
                    Err(_) => failed += 1,
                },
                None => failed += 1,
            },
            Err(_) => failed += 1,
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    let _ = std::fs::remove_file(&coords);
    assert_eq!(
        accepted, 0,
        "theatre stub accepted {accepted} of 9; failed {failed}. gap-cleared + forged coords + loopback stub must not PASS"
    );
    assert_eq!(
        failed, 9,
        "theatre stub must fail every row at an assertion"
    );
}

#[test]
fn forged_coords_without_guest_keep_acceptance_blocked() {
    for check in Check::ALL {
        let grade = acceptance(check);
        assert!(
            matches!(grade, Grade::Blocked(_)),
            "{} should stay BLOCKED without a guest measurement, got {} {}",
            check.id(),
            grade.label(),
            grade.detail()
        );
        assert!(!counts_as_accepted(&grade));
    }
}
