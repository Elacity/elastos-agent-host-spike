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

/// Opens Home, in order of preference: the Home app the person installed from the
/// browser (opening it brings its window forward), a new app-mode window, or a tab of
/// the default browser. Launch Services starts the browser, so macOS privacy prompts
/// name the browser, not this app; a running browser takes over the request.
pub fn open_home() -> std::io::Result<()> {
    let status = if let Some(app) = installed_home_app() {
        Command::new("open").arg(app).status()?
    } else if let Some(app) = APP_MODE_BROWSERS.iter().find(|app| Path::new(app).is_dir()) {
        Command::new("open")
            .args(["-n", "-a", app, "--args"])
            .arg(format!("--app={HOME_URL}"))
            .status()?
    } else {
        Command::new("open").arg(HOME_URL).status()?
    };
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("open exited with {status}")))
    }
}

/// Chromium browsers put installed web apps in `~/Applications/<Browser> Apps.localized`
/// and record the start address as `CrAppModeShortcutURL`. Only an app installed from
/// exactly `HOME_URL` counts, so a Home installed from `127.0.0.1` is never used.
fn installed_home_app() -> Option<PathBuf> {
    let applications = home_dir()?.join("Applications");
    for folder in std::fs::read_dir(applications).ok()?.flatten() {
        if !folder
            .file_name()
            .to_string_lossy()
            .ends_with("Apps.localized")
        {
            continue;
        }
        let Ok(apps) = std::fs::read_dir(folder.path()) else {
            continue;
        };
        for app in apps.flatten() {
            let plist = app.path().join("Contents/Info.plist");
            let Ok(out) = Command::new("plutil")
                .args(["-extract", "CrAppModeShortcutURL", "raw", "-o", "-"])
                .arg(&plist)
                .output()
            else {
                continue;
            };
            if out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == HOME_URL {
                return Some(app.path());
            }
        }
    }
    None
}
