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
            runtime.verified_path()?,
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
        let cleanup = agent_conformance::census::cleanup(self.home, self.port)?;
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
        if let Err(reason) = &result {
            // Refuse immediately and stop even when the listing cannot be read.
            self.child.stop().map_err(|stop_reason| {
                format!("socket census failed: {reason}; operator stop failed: {stop_reason}")
            })?;
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
    use super::*;
    use std::fs;
    use std::path::Path;

    const SAMPLE_REASON: &str = "census tool failed or returned a warning";
    const STOP_REASON: &str = "managed child or its group exceeded the 10 second stop bound";

    fn socket_free_operator(home: &ThrowawayHome, ignore_term: bool) -> Operator<'_> {
        let script = if ignore_term {
            "trap '' TERM; printf '%s\\n' \"$$\" > \"$HOME/census-ready\"; exec /bin/sleep 120"
        } else {
            "printf '%s\\n' \"$$\" > \"$HOME/census-ready\"; exec /bin/sleep 120"
        };
        let child = home
            .start(Path::new("/bin/sh"), &["-c", script])
            .expect("fixture setup failed: start socket-free child");
        let mut operator = Operator {
            child,
            home,
            port: 0,
        };
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            operator
                .require_alive()
                .expect("fixture setup failed: child must stay alive");
            if fs::read_to_string(home.home().join("census-ready"))
                .is_ok_and(|pid| pid.trim() == operator.child.pgid().to_string())
            {
                return operator;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("fixture setup failed: child must write its ready marker within two seconds");
    }

    #[test]
    fn census_refusal_preserves_reason_after_clean_stop() {
        let home = ThrowawayHome::new().expect("fixture setup failed: fresh Home required");
        let root = home.root().to_path_buf();
        let mut operator = socket_free_operator(&home, false);
        let pgid = operator.child.pgid();
        let result = operator.census();
        // Observe before Drop so emergency cleanup cannot hide an omitted stop.
        let leader_alive = operator.child.is_alive();
        let group_alive = home.group_is_alive(pgid);
        assert_eq!(
            leader_alive,
            Ok(false),
            "census refusal must reap the leader before Drop"
        );
        assert_eq!(
            group_alive,
            Ok(false),
            "census refusal must empty the group before Drop"
        );
        assert_eq!(
            result,
            Err(SAMPLE_REASON.into()),
            "clean stop must preserve the exact census refusal"
        );
        drop(operator);
        home.finish().expect("clean stop must allow Home removal");
        assert!(!root.exists(), "clean stop Home must be removed");
    }

    #[test]
    fn census_refusal_preserves_reason_after_failed_stop() {
        let home = ThrowawayHome::new().expect("fixture setup failed: fresh Home required");
        let root = home.root().to_path_buf();
        let mut operator = socket_free_operator(&home, true);
        let pgid = operator.child.pgid();
        let started = Instant::now();
        let result = operator.census();
        let elapsed = started.elapsed();
        let leader_alive = operator.child.is_alive();
        let group_alive = home.group_is_alive(pgid);
        eprintln!("census stop observed: result={result:?} elapsed={elapsed:?} leader_alive={leader_alive:?} group_alive={group_alive:?}");
        let reason = result.expect_err("failed stop must keep the census refusal");
        assert_eq!(
            reason.matches(SAMPLE_REASON).count(),
            1,
            "failed stop must preserve the complete census cause exactly once"
        );
        assert_eq!(
            reason.matches(STOP_REASON).count(),
            1,
            "failed stop must preserve the complete operator-stop cause exactly once"
        );
        assert_eq!(
            reason,
            format!("socket census failed: {SAMPLE_REASON}; operator stop failed: {STOP_REASON}"),
            "census cause must precede the labelled operator-stop cause"
        );
        assert!(
            elapsed >= Duration::from_secs(10),
            "census stop must reach the ten-second bound: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(15),
            "census stop must finish within fifteen seconds: {elapsed:?}"
        );
        assert_eq!(
            leader_alive,
            Ok(false),
            "failed census stop must reap the leader before Drop"
        );
        assert_eq!(
            group_alive,
            Ok(false),
            "failed census stop must empty the group before Drop"
        );
        assert!(root.is_dir(), "failed stop Home must remain before Drop");
        drop(operator);
        assert_eq!(
            home.finish(),
            Err("keep the root after an unstopped child or failed stop"),
            "failed census stop must retain its Home"
        );
        assert!(root.is_dir(), "failed stop Home must remain after finish");
        // Retention and the empty group are proven; remove only this fixture.
        fs::remove_dir_all(root).unwrap();
    }
}
