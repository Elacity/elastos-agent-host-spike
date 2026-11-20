use std::io::{BufRead, Write};
use std::os::raw::c_char;

const ROOT: &str = "@@ROOT@@";

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn readlinkat(dirfd: i32, path: *const c_char, buf: *mut c_char, bufsiz: usize) -> isize;
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let _ = std::fs::write(format!("{ROOT}/probe.error"), info.to_string());
    }));
    // Linux reads its PID through the seccomp-admitted readlinkat call.
    #[cfg(target_os = "linux")]
    let pid = {
    let mut target = [0u8; 32];
    let count = unsafe {
        readlinkat(
            -100, // AT_FDCWD
            c"/proc/self".as_ptr(),
            target.as_mut_ptr().cast(),
            target.len(),
        )
    };
    if count < 0 {
        panic!("readlinkat /proc/self: {}", std::io::Error::last_os_error());
    }
    std::str::from_utf8(&target[..count as usize]).unwrap().to_string()
    };
    #[cfg(target_os = "macos")]
    let pid = std::process::id().to_string();
    assert!(pid.bytes().all(|byte| byte.is_ascii_digit()));
    std::fs::write(format!("{ROOT}/child.pid"), pid).unwrap();
    let mut output = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        if line.contains("\"op\":\"init\"") {
            if !line.contains(&format!(
                "\"base_path\":\"{}\"",
                ROOT.trim_end_matches("/did")
            )) {
                writeln!(
                    output,
                    "{{\"status\":\"error\",\"code\":\"path\",\"message\":\"wrong base\"}}"
                )
                .unwrap();
            } else {
                writeln!(output, "{{\"status\":\"ok\"}}").unwrap();
            }
        } else if line.contains("\"op\":\"get_did\"") {
            writeln!(
                output,
                "{{\"status\":\"ok\",\"data\":{{\"did\":\"did:key:zFixture\"}}}}"
            )
            .unwrap();
        } else if line.contains("\"op\":\"set_nickname\"") {
            std::fs::write(format!("{ROOT}/nickname"), b"Ada").unwrap();
            writeln!(output, "{{\"status\":\"ok\"}}").unwrap();
        } else if line.contains("\"op\":\"probe_outside_write\"") {
            let refused = std::fs::write(
                format!("{}/outside", ROOT.trim_end_matches("/did")),
                b"outside",
            )
            .is_err();
            writeln!(
                output,
                "{{\"status\":\"ok\",\"data\":{{\"outside_write_refused\":{refused}}}}}"
            )
            .unwrap();
        } else if line.contains("\"op\":\"shutdown\"") {
            std::fs::write(format!("{ROOT}/shutdown"), b"yes").unwrap();
            writeln!(output, "{{\"status\":\"ok\"}}").unwrap();
            output.flush().unwrap();
            return;
        }
        output.flush().unwrap();
    }
}
