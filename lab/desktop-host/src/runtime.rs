//! Everything this app knows about ElastOS. With the real home folder it runs no
//! Runtime command: it only looks for the installed binary and asks Home whether it
//! answers. Only with `ELASTOS_LAB_HOME` (experiments) does it start Home.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::time::Duration;

/// Passkeys belong to `localhost`; `127.0.0.1` is a different site to WebKit.
pub const HOME_URL: &str = "http://localhost:8090/home/";
const HOME_ADDR: &str = "localhost:8090";
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

pub fn home_dir() -> Option<PathBuf> {
    lab_home().or_else(|| std::env::var_os("HOME").map(PathBuf::from))
}

/// A throwaway folder that stands in for the user's home folder in experiments.
/// On Windows, where a shortcut cannot set it, `%LOCALAPPDATA%\ElastOS Lab`.
pub fn lab_home() -> Option<PathBuf> {
    let lab = std::env::var_os("ELASTOS_LAB_HOME").map(PathBuf::from);
    #[cfg(windows)]
    let lab = lab.or_else(|| {
        std::env::var_os("LOCALAPPDATA").map(|dir| PathBuf::from(dir).join("ElastOS Lab"))
    });
    lab
}

#[cfg(windows)]
pub use crate::wsl::{installed, start_home};

/// LAB DRAFT of `elastos service start`: `ELASTOS_SERVICE=1` keeps the lab Runtime
/// from opening a browser, because this app shows Home itself. Home gets its own
/// process group, so it keeps running when this app quits.
#[cfg(unix)]
pub fn start_home(home: &Path) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    let log = std::fs::File::options()
        .create(true)
        .append(true)
        .open(home.join("home.log"))?;
    Command::new(home.join(".local/bin/elastos"))
        .args(["home", "--browser"])
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("ELASTOS_SERVICE", "1")
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .process_group(0)
        .spawn()?;
    Ok(())
}

#[cfg(unix)]
pub fn installed() -> bool {
    home_dir().is_some_and(|home| home.join(".local/bin/elastos").is_file())
}

/// Any Home on port 8090 counts; P2 replaces this with `elastos service status`,
/// which only reports this data folder's Home.
pub fn home_answers() -> bool {
    let Ok(addrs) = HOME_ADDR.to_socket_addrs() else {
        return false;
    };
    addrs.into_iter().any(|addr| probe(addr).unwrap_or(false))
}

fn probe(addr: SocketAddr) -> std::io::Result<bool> {
    let mut stream = TcpStream::connect_timeout(&addr, PROBE_TIMEOUT)?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT))?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT))?;
    stream
        .write_all(b"GET /home/ HTTP/1.1\r\nHost: localhost:8090\r\nConnection: close\r\n\r\n")?;
    let mut status_line = [0u8; 12];
    stream.read_exact(&mut status_line)?;
    Ok(status_line.starts_with(b"HTTP/1.1 2") || status_line.starts_with(b"HTTP/1.1 3"))
}
