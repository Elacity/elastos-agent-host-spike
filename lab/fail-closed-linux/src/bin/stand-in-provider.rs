//! A stand-in provider for the guard's tests. It is not a real provider.
//!
//! With `--marker PATH` it creates PATH on start, which shows that the provider
//! image ran. Then it answers one line per request on stdout:
//!
//! - `status`: `nnp`, `seccomp`, `cap_eff`, `cap_prm`, `cap_inh`, `cap_bnd`
//!   (the number of held bounding capabilities), `uid`, `gid`.
//! - `write PATH`, `truncate PATH`, `socket`: `ok` or `err=<errno>`.
//! - `exit`: leave.

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::io::{self, BufRead, Write};

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    fn errno_of(error: &io::Error) -> i32 {
        error.raw_os_error().unwrap_or(-1)
    }

    fn outcome(result: io::Result<()>) -> String {
        match result {
            Ok(()) => "ok".to_string(),
            Err(error) => format!("err={}", errno_of(&error)),
        }
    }

    fn c_path(path: &str) -> io::Result<CString> {
        CString::new(path).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    }

    fn status() -> String {
        // SAFETY: read-only queries with live structures.
        unsafe {
            let nnp = libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
            let seccomp = libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0);
            let header = CapHeader {
                version: 0x2008_0522,
                pid: 0,
            };
            let mut data = [CapData::default(); 2];
            let rc = libc::syscall(
                libc::SYS_capget,
                &header as *const CapHeader,
                data.as_mut_ptr(),
            );
            let word = |pick: fn(&CapData) -> u32| {
                (u64::from(pick(&data[1])) << 32) | u64::from(pick(&data[0]))
            };
            let (eff, prm, inh) = if rc == 0 {
                (
                    word(|d| d.effective),
                    word(|d| d.permitted),
                    word(|d| d.inheritable),
                )
            } else {
                (u64::MAX, u64::MAX, u64::MAX)
            };
            let mut bounding = 0;
            for cap in 0..64 as libc::c_ulong {
                match libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) {
                    1 => bounding += 1,
                    0 => {}
                    _ => break,
                }
            }
            format!(
                "nnp={nnp} seccomp={seccomp} cap_eff={eff:x} cap_prm={prm:x} cap_inh={inh:x} cap_bnd={bounding} uid={} gid={}",
                libc::getuid(),
                libc::getgid()
            )
        }
    }

    fn answer(request: &str) -> Option<String> {
        let (op, rest) = request.split_once(' ').unwrap_or((request, ""));
        Some(match op {
            "status" => status(),
            "write" => outcome(std::fs::write(rest, b"x")),
            "truncate" => outcome(c_path(rest).and_then(|path| {
                // SAFETY: `path` is NUL-terminated and outlives the call.
                if unsafe { libc::truncate(path.as_ptr(), 0) } < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            })),
            "socket" => {
                // SAFETY: `socket` takes integers; a descriptor is closed at once.
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
                if fd < 0 {
                    format!("err={}", errno_of(&io::Error::last_os_error()))
                } else {
                    unsafe { libc::close(fd) };
                    "ok".to_string()
                }
            }
            "exit" => return None,
            _ => "err=unknown-request".to_string(),
        })
    }

    pub fn run() {
        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--marker" {
                let Some(path) = args.next() else {
                    std::process::exit(2)
                };
                if let Err(error) = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    eprintln!("stand-in-provider: marker {path}: {error}");
                    std::process::exit(3);
                }
            }
        }
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            match answer(line.trim()) {
                Some(reply) => {
                    if writeln!(stdout, "{reply}")
                        .and_then(|()| stdout.flush())
                        .is_err()
                    {
                        break;
                    }
                }
                None => break,
            }
        }
    }
}
