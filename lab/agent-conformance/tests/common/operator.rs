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
