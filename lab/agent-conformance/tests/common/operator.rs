//! Ready operator and socket census through the lane's single launch primitive.

use agent_conformance::harness::{RunningChild, ThrowawayHome};
use agent_conformance::runtime::runtime_under_test;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
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
        let output = self.home.launch(
            Path::new("/usr/sbin/lsof"),
            &[
                "-nP",
                "-a",
                "-g",
                &self.child.pgid().to_string(),
                "-i",
                "-FpfPtnT",
                "-Ts",
            ],
            Duration::from_secs(5),
        )?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err("socket census tool failed or returned a warning".into());
        }
        self.require_alive()?;
        let listing =
            std::str::from_utf8(&output.stdout).map_err(|_| "socket census is not UTF-8")?;
        loopback_socket_count(listing, self.port)
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

#[derive(Default)]
struct Socket<'a> {
    family: Option<&'a str>,
    protocol: Option<&'a str>,
    name: Option<&'a str>,
    state: Option<&'a str>,
}

fn set_once<'a>(field: &mut Option<&'a str>, value: &'a str) -> Result<(), String> {
    if field.replace(value).is_some() {
        return Err("socket census repeats a field".into());
    }
    Ok(())
}

impl Socket<'_> {
    fn check(&self, api_port: u16) -> Result<bool, String> {
        let family = self.family.ok_or("socket census lacks an address family")?;
        let protocol = self.protocol.ok_or("socket census lacks a protocol")?;
        if !matches!(family, "IPv4" | "IPv6") || !matches!(protocol, "TCP" | "UDP") {
            return Err("socket census has an unknown socket kind or family".into());
        }
        let name = self.name.ok_or("socket census lacks an address")?;
        let ends: Vec<_> = name.split("->").collect();
        if ends.is_empty() || ends.len() > 2 {
            return Err("socket census has an unparseable connection".into());
        }
        let mut addresses = Vec::new();
        for end in ends {
            if end.starts_with("*:") {
                return Err(format!(
                    "socket census refused {protocol} {family} non-loopback address"
                ));
            }
            let address: SocketAddr = end
                .parse()
                .map_err(|_| "socket census has an unparseable address")?;
            if !matches!(address.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST)
                && !matches!(address.ip(), IpAddr::V6(ip) if ip == Ipv6Addr::LOCALHOST)
            {
                return Err(format!(
                    "socket census refused {protocol} {family} non-loopback address"
                ));
            }
            if (address.is_ipv4() != (family == "IPv4")) || address.port() == 0 {
                return Err(
                    "socket census address disagrees with its family or has zero port".into(),
                );
            }
            addresses.push(address);
        }
        Ok(protocol == "TCP"
            && self.state == Some("ST=LISTEN")
            && addresses == [SocketAddr::from((Ipv4Addr::LOCALHOST, api_port))])
    }
}

/// Parse lsof's selected field format; every socket and both connection ends
/// must be readable. The API listener is the census visibility control.
pub fn loopback_socket_count(listing: &str, api_port: u16) -> Result<usize, String> {
    let mut process = false;
    let mut socket: Option<Socket<'_>> = None;
    let mut count = 0;
    let mut api_seen = false;
    for line in listing.lines() {
        let (tag, value) = line
            .split_at_checked(1)
            .ok_or("socket census has an empty field")?;
        if matches!(tag, "p" | "f") {
            if let Some(previous) = socket.take() {
                api_seen |= previous.check(api_port)?;
                count += 1;
            }
        }
        match tag {
            "p" if value.parse::<u32>().is_ok_and(|pid| pid > 0) => process = true,
            "f" if process && value.parse::<u32>().is_ok() => socket = Some(Socket::default()),
            _ => {
                let current = socket
                    .as_mut()
                    .ok_or("socket census has a field outside a socket")?;
                match tag {
                    "t" => set_once(&mut current.family, value)?,
                    "P" => set_once(&mut current.protocol, value)?,
                    "n" => set_once(&mut current.name, value)?,
                    "T" if value.starts_with("ST=") => set_once(&mut current.state, value)?,
                    _ => return Err("socket census has an unknown or misplaced field".into()),
                }
            }
        }
    }
    if let Some(previous) = socket {
        api_seen |= previous.check(api_port)?;
        count += 1;
    }
    if count == 0 || !api_seen {
        return Err("socket census requires the loopback API listener positive control".into());
    }
    Ok(count)
}
