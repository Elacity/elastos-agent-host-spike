//! The operator's one lsof path and parser, shared with the pre-test root check.
use crate::harness::ThrowawayHome;
use std::collections::BTreeSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn listing(
    home: &ThrowawayHome,
    args: &[&str],
    root_selection: bool,
) -> Result<String, String> {
    let output = home.launch(Path::new("/usr/sbin/lsof"), args, Duration::from_secs(5))?;
    // macOS lsof returns 1 if ANY +D entry has no open handle, including a
    // partly matched tree. That is a selection result, not tool failure.
    // Warnings, other statuses and malformed output still fail closed.
    let selection_exit = root_selection && output.status.code() == Some(1);
    if (!output.status.success() && !selection_exit) || !output.stderr.is_empty() {
        return Err("census tool failed or returned a warning".into());
    }
    String::from_utf8(output.stdout).map_err(|_| "census is not UTF-8".into())
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Holder {
    pub pid: u32,
    pub root: String,
    pub path: String,
}

pub fn root_holders(home: &ThrowawayHome, roots: &[PathBuf]) -> Result<Vec<Holder>, String> {
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let mut args = vec!["-nP", "-FpfPtnT", "-Ts"];
    for root in roots {
        args.extend(["+D", root.to_str().ok_or("census root is not UTF-8")?]);
    }
    // lsof and its stat helper inherit cwd and captures. Keep those outside
    // the inspected roots so only the caller PID needs an exemption.
    let tool_home = ThrowawayHome::new()?;
    let result = listing(&tool_home, &args, true);
    home.collect_captures_from(&tool_home)?;
    tool_home.finish()?;
    let text = result?;
    let mut holders = BTreeSet::new();
    for file in parse_listing(&text)? {
        // The test owns capture handles during lsof. Only its own PID is exempt.
        if file.pid == std::process::id() {
            continue;
        }
        let path = Path::new(file.name.ok_or("census file lacks a name")?);
        let root = roots
            .iter()
            .find(|root| path.starts_with(root))
            .ok_or("census file lies outside the selected roots")?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "census path escaped its root")?;
        holders.insert(Holder {
            pid: file.pid,
            root: root
                .file_name()
                .ok_or("census root lacks a name")?
                .to_string_lossy()
                .into(),
            path: if relative.as_os_str().is_empty() {
                ".".into()
            } else {
                relative.to_string_lossy().into()
            },
        });
    }
    Ok(holders.into_iter().collect())
}

/// Snapshot after all run clients and the operator group have been collected.
pub fn cleanup(home: &ThrowawayHome, port: u16) -> Result<String, String> {
    let root = home.root().file_name().unwrap().to_string_lossy();
    let checked = || -> Result<(usize, Vec<String>, usize, Vec<String>), String> {
        home.guard(home.home(), home.data())?;
        let holders = root_holders(home, &[home.root().to_owned()])?;
        let processes = holders.iter().map(|h| h.pid).collect::<BTreeSet<_>>().len();
        let paths = holders
            .into_iter()
            .map(|h| h.path)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let sockets = match TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            Duration::from_millis(200),
        ) {
            Ok(_) => 1,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => 0,
            Err(_) => return Err("API port check failed without a connection refusal".into()),
        };
        let mut temp = Vec::new();
        for entry in fs::read_dir(home.temp()).map_err(|_| "could not inspect TMPDIR")? {
            let entry = entry.map_err(|_| "could not inspect TMPDIR entry")?;
            temp.push(format!("tmp/{}", entry.file_name().to_string_lossy()));
        }
        temp.sort();
        Ok((processes, paths, sockets, temp))
    };
    let (processes, paths, sockets, temp) = checked()
        .map_err(|reason| format!("cleanup census: FAIL retained:target/{root}; {reason}"))?;
    let mut reasons = Vec::new();
    if processes > 0 {
        reasons.push("process leftover");
    }
    if sockets > 0 {
        reasons.push("API socket leftover");
    }
    if !temp.is_empty() {
        reasons.push("temp leftover");
    }
    let status = if reasons.is_empty() {
        "root checks PASS".into()
    } else {
        format!("FAIL retained:target/{root}; {}", reasons.join(", "))
    };
    let line = format!("cleanup census: {status}; processes:{processes} paths:{paths:?} API sockets:{sockets} temp:{} paths:{temp:?}; excludes only test PID; outside-root:BLOCKED(AC-006-STORAGE)", temp.len());
    if reasons.is_empty() {
        Ok(line)
    } else {
        Err(line)
    }
}

/// Inspect only existing home-* trees, never the build tree or file contents.
/// Each bounded lsof snapshot covers all roots and never signals their owners.
pub fn earlier_runs() -> Result<Vec<Holder>, String> {
    let started = Instant::now();
    let home = ThrowawayHome::new()?;
    let mut roots = Vec::new();
    for entry in
        fs::read_dir(home.root().parent().unwrap()).map_err(|_| "could not list lane target")?
    {
        if started.elapsed() >= Duration::from_secs(2) {
            return Err("earlier-run root selection exceeded 2 seconds".into());
        }
        let entry = entry.map_err(|_| "could not inspect lane target entry")?;
        if entry.path() == home.root() || !entry.file_name().to_string_lossy().starts_with("home-")
        {
            continue;
        }
        let kind = entry
            .file_type()
            .map_err(|_| "could not inspect earlier-run root")?;
        if !kind.is_dir() || kind.is_symlink() {
            return Err("earlier-run root must be a directory without symlinks".into());
        }
        roots.push(entry.path());
    }
    let holders = root_holders(&home, &roots)?;
    home.finish()?;
    Ok(holders)
}

#[derive(Default)]
struct OpenFile<'a> {
    pid: u32,
    descriptor: &'a str,
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

impl OpenFile<'_> {
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
    let files = parse_listing(listing)?;
    let mut api_seen = false;
    for file in &files {
        if file.descriptor.parse::<u32>().is_err() {
            return Err("socket census requires a numeric descriptor".into());
        }
        api_seen |= file.check(api_port)?;
    }
    if files.is_empty() || !api_seen {
        return Err("socket census requires the loopback API listener positive control".into());
    }
    Ok(files.len())
}

// Both the operator socket sample and root census use this one field parser.
fn parse_listing(listing: &str) -> Result<Vec<OpenFile<'_>>, String> {
    let mut pid = None;
    let mut file: Option<OpenFile<'_>> = None;
    let mut files = Vec::new();
    for line in listing.lines() {
        let (tag, value) = line
            .split_at_checked(1)
            .ok_or("census has an empty field")?;
        if tag == "p" && pid.is_some() && file.is_none() {
            return Err("census process has no files".into());
        }
        if matches!(tag, "p" | "f") {
            if let Some(previous) = file.take() {
                if previous.name.is_none() || previous.family.is_none() {
                    return Err("census has an incomplete file record".into());
                }
                files.push(previous);
            }
        }
        match tag {
            "p" => {
                pid = Some(
                    value
                        .parse::<u32>()
                        .ok()
                        .filter(|pid| *pid > 0)
                        .ok_or("census has an invalid PID")?,
                );
            }
            "f" if !value.is_empty() => {
                file = Some(OpenFile {
                    pid: pid.ok_or("census file lacks a PID")?,
                    descriptor: value,
                    ..OpenFile::default()
                });
            }
            _ => {
                let current = file.as_mut().ok_or("census has a field outside a file")?;
                match tag {
                    "t" => set_once(&mut current.family, value)?,
                    "P" => set_once(&mut current.protocol, value)?,
                    "n" => set_once(&mut current.name, value)?,
                    "T" if value.starts_with("ST=") => set_once(&mut current.state, value)?,
                    _ => return Err("census has an unknown or misplaced field".into()),
                }
            }
        }
    }
    if let Some(last) = file {
        if last.name.is_none() || last.family.is_none() {
            return Err("census has an incomplete file record".into());
        }
        files.push(last);
    } else if pid.is_some() {
        return Err("census process has no files".into());
    }
    Ok(files)
}
