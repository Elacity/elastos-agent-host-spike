//! Ready operator and socket census through the lane's single launch primitive.

pub use agent_conformance::census::loopback_socket_count;
use agent_conformance::harness::{RunningChild, ThrowawayHome};
use agent_conformance::runtime::runtime_under_test;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

pub struct Operator<'a> {
    pub child: RunningChild<'a>,
    home: &'a ThrowawayHome,
    pub port: u16,
}

impl<'a> Operator<'a> {
    pub fn start(home: &'a ThrowawayHome) -> Result<Self, Box<dyn std::error::Error>> {
        let runtime = runtime_under_test()?;
        super::write_operator_home(home)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let host = include_str!("../../fixtures/operator-api-host.txt").trim();
        // The wildcard is solely the F-ac1j listener mutation. All requests still
        // connect to loopback; the census, rather than this selector, rejects it.
        if !matches!(host, "127.0.0.1" | "0.0.0.0") {
            return Err("unknown operator API fixture host".into());
        }
        let child = home.start(
            &runtime.binary,
            &[
                "serve",
                "--addr",
                &format!("{host}:{port}"),
                "--storage-path",
                home.root()
                    .join("storage")
                    .to_str()
                    .ok_or("storage path is not UTF-8")?,
            ],
        )?;
        Ok(Self { child, home, port })
    }

    pub fn ready(&mut self) -> Result<(), &'static str> {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(60) {
            self.require_alive()?;
            // Check existence only. Runtime owns the attach data in this file.
            let coords = self.home.data().join("runtime-coords.json");
            let exists = coords
                .try_exists()
                .map_err(|_| "could not check coordinates existence")?;
            if exists && health_is_ok(self.port) {
                self.require_alive()?;
                if started.elapsed() < Duration::from_secs(60) {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err("operator readiness exceeded 60 seconds: coordinates and HTTP 200 required")
    }

    pub fn begin_check(&mut self) -> Result<(usize, Instant), String> {
        self.ready()?;
        Ok((self.census()?, Instant::now()))
    }

    /// All effect journeys share the same two samples and group-drain stop.
    pub fn finish_check(mut self, (first, sampled): (usize, Instant)) -> Result<String, String> {
        while sampled.elapsed() < Duration::from_secs(3) {
            self.require_alive()?;
            std::thread::sleep(Duration::from_millis(50));
        }
        let second = self.census()?;
        self.child.stop()?;
        let cleanup =
            drain_capture_holders(|| agent_conformance::census::cleanup(self.home, self.port))?;
        Ok(format!("operator census: {first} then {second} loopback sockets, API listener present in both; samples at least 3 seconds apart; group stopped\n{cleanup}"))
    }

    pub fn require_alive(&mut self) -> Result<(), &'static str> {
        if !self.child.is_alive()? {
            return Err("operator exited before the check completed");
        }
        Ok(())
    }

    pub fn census(&mut self) -> Result<usize, String> {
        let result = self.sample();
        if result.is_err() {
            // Refuse immediately and stop even when the listing cannot be read.
            self.child
                .stop()
                .map_err(|reason| format!("socket census failed; {reason}"))?;
        }
        result
    }

    fn sample(&mut self) -> Result<usize, String> {
        self.require_alive()?;
        let listing = agent_conformance::census::listing(
            self.home,
            &[
                "-nP",
                "-a",
                "-g",
                &self.child.pgid().to_string(),
                "-i",
                "-FpfPtnT",
                "-Ts",
            ],
            false,
        )?;
        self.require_alive()?;
        loopback_socket_count(&listing, self.port)
    }
}

const CAPTURE_DRAIN_ATTEMPTS: u8 = 4;

/// One census. A holder of only `stdout-N` or `stderr-N` can still be exiting
/// after pgrep has dropped the group. A later look must be empty. Any other
/// path, including a key file or the home directory, is a refusal on the first look.
fn drain_capture_holders(
    mut census: impl FnMut() -> Result<String, String>,
) -> Result<String, String> {
    let mut attempts = 0;
    loop {
        match census() {
            Ok(line) => return Ok(line),
            Err(line) if capture_holder_only(&line) && attempts < CAPTURE_DRAIN_ATTEMPTS => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(line) => return Err(line),
        }
    }
}

fn capture_holder_only(line: &str) -> bool {
    if !line.contains("; process leftover;") {
        return false;
    }
    if line.contains("API socket leftover") || line.contains("temp leftover") {
        return false;
    }
    let Some(start) = line.find(" paths:") else {
        return false;
    };
    let rest = &line[start + " paths:".len()..];
    let Some(end) = rest.find(" API sockets:") else {
        return false;
    };
    let list = &rest[..end];
    let Some(inner) = list
        .strip_prefix('[')
        .and_then(|body| body.strip_suffix(']'))
    else {
        return false;
    };
    if inner.is_empty() {
        return false;
    }
    inner.split(", ").all(capture_path)
}

fn capture_path(item: &str) -> bool {
    let Some(name) = item
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
    else {
        return false;
    };
    let Some(digits) = name
        .strip_prefix("stdout-")
        .or_else(|| name.strip_prefix("stderr-"))
    else {
        return false;
    };
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn health_is_ok(port: u16) -> bool {
    let bound = Duration::from_millis(200);
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, bound) else {
        return false;
    };
    if stream.set_read_timeout(Some(bound)).is_err()
        || stream.set_write_timeout(Some(bound)).is_err()
        || stream
            .write_all(b"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .is_err()
    {
        return false;
    }
    let mut response = [0; 128];
    match stream.read(&mut response) {
        Ok(len) => {
            response[..len].starts_with(b"HTTP/1.1 200 ")
                || response[..len].starts_with(b"HTTP/1.0 200 ")
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{drain_capture_holders, CAPTURE_DRAIN_ATTEMPTS};

    const STDOUT_LEFTOVER: &str = "cleanup census: FAIL retained:target/home-1; process leftover; processes:1 paths:[\"stdout-217\"] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)";
    const PASS_LINE: &str = "cleanup census: root checks PASS; processes:0 paths:[] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)";

    #[test]
    fn capture_holder_drain_retries_a_stdout_leftover() {
        let mut calls = 0;
        let line = drain_capture_holders(|| {
            calls += 1;
            if calls < 3 {
                Err(STDOUT_LEFTOVER.to_owned())
            } else {
                Ok(PASS_LINE.to_owned())
            }
        })
        .expect("the drain accepts a capture holder that the next look releases");
        assert!(
            line.contains("root checks PASS"),
            "the drain returns the clean census: {line}"
        );
        assert_eq!(
            calls, 3,
            "the drain looks again after a capture-only leftover"
        );

        let mut pair_calls = 0;
        let pair = "cleanup census: FAIL retained:target/home-1; process leftover; processes:1 paths:[\"stderr-4\", \"stdout-9\"] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)";
        let line = drain_capture_holders(|| {
            pair_calls += 1;
            if pair_calls == 1 {
                Err(pair.to_owned())
            } else {
                Ok(PASS_LINE.to_owned())
            }
        })
        .expect("the drain accepts stdout and stderr holders that the next look releases");
        assert!(line.contains("root checks PASS"), "{line}");
        assert_eq!(pair_calls, 2, "the drain looks again for both captures");
    }

    #[test]
    fn capture_holder_drain_keeps_other_leftovers() {
        for line in [
            "cleanup census: FAIL retained:target/home-1; process leftover; processes:1 paths:[\".\"] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)",
            "cleanup census: FAIL retained:target/home-1; process leftover; processes:1 paths:[\"ca.key\", \"device.key\", \"tls.key\"] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)",
            "cleanup census: FAIL retained:target/home-1; process leftover; processes:1 paths:[\"home/Library/Application Support/elastos/host-process.lock\"] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)",
            "cleanup census: FAIL retained:target/home-1; process leftover; processes:1 paths:[\"stdout-217\", \"home/Library/Application Support/elastos/host-process.lock\"] API sockets:0 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)",
            "cleanup census: FAIL retained:target/home-1; API socket leftover; processes:0 paths:[] API sockets:1 temp:0 paths:[]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)",
            "cleanup census: FAIL retained:target/home-1; temp leftover; processes:0 paths:[] API sockets:0 temp:1 paths:[\"tmp/planted\"]; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)",
        ] {
            let mut calls = 0;
            let result = drain_capture_holders(|| {
                calls += 1;
                Err(line.to_owned())
            });
            assert_eq!(
                result,
                Err(line.to_owned()),
                "the drain refuses this leftover"
            );
            assert_eq!(
                calls, 1,
                "the drain refuses this leftover on the first look: {line}"
            );
        }
    }

    #[test]
    fn capture_holder_drain_stops_when_the_capture_stays() {
        let mut calls = 0;
        let result = drain_capture_holders(|| {
            calls += 1;
            Err(STDOUT_LEFTOVER.to_owned())
        });
        assert_eq!(
            result,
            Err(STDOUT_LEFTOVER.to_owned()),
            "the drain still refuses a capture holder that stays"
        );
        assert_eq!(calls, usize::from(CAPTURE_DRAIN_ATTEMPTS) + 1);
    }
}
