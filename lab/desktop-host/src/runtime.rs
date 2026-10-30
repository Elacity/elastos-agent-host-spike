//! Everything this app knows about ElastOS. P1 runs no Runtime command: it only
//! looks for the installed binary, asks Home whether it answers, and opens Home.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Passkeys belong to `localhost`; `127.0.0.1` is a different site to the browser.
pub const HOME_URL: &str = "http://localhost:8090/home/";
const HOME_ADDR: &str = "localhost:8090";
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

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

/// Chromium browsers that can show Home as its own window (app mode). They keep the
/// browser's passkeys, which an embedded web view cannot use at `localhost`.
const APP_MODE_BROWSERS: &[&str] = &[
    "/Applications/Brave Browser.app",
    "/Applications/Google Chrome.app",
    "/Applications/Microsoft Edge.app",
    "/Applications/Chromium.app",
];

/// Opens Home in its own window when an app-mode browser is installed, otherwise in a
/// tab of the default browser. Launch Services starts the browser, so macOS privacy
/// prompts name the browser, not this app; a running browser takes over the request.
pub fn open_home() -> std::io::Result<()> {
    let app_mode = APP_MODE_BROWSERS.iter().find(|app| Path::new(app).is_dir());
    let status = match app_mode {
        Some(app) => Command::new("open")
            .args(["-n", "-a", app, "--args"])
            .arg(format!("--app={HOME_URL}"))
            .status()?,
        None => Command::new("open").arg(HOME_URL).status()?,
    };
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("open exited with {status}")))
    }
}
