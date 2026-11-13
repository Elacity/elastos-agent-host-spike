//! Windows (ELASTOS-DESKTOP-APP P9 W1, LAB DRAFT). ElastOS is a Linux Runtime: on
//! Windows it runs in its own WSL 2 system, imported for this user from the Ubuntu
//! image packed in this app and checked against the SHA-256 built into it. That
//! system cannot see Windows drives or start Windows programs. Home runs there as an
//! ordinary user, and WSL forwards `localhost:8090` to this window.

use std::io::{self, Read, Write};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

const DISTRO: &str = "ElastOS-Lab";
const USER: &str = "elastos";
const HOME: &str = "/home/elastos";
const PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// No Windows drives and no Windows programs inside the ElastOS system.
const WSL_CONF: &str = "printf '%s\\n' '[automount]' 'enabled=false' 'mountFsTab=false' '[interop]' 'enabled=false' 'appendWindowsPath=false' > /etc/wsl.conf";

/// Runs the release's own Runtime only after its SHA-256 matches the pin built into
/// this app.
const INSTALL: &str = r#"umask 077
cd /home/elastos || exit 3
rm -f .elastos-installer
cp "release/$1" .elastos-installer || exit 3
echo "$2  .elastos-installer" | sha256sum -c --quiet || exit 4
chmod 700 .elastos-installer
env -i HOME=/home/elastos PATH=/usr/bin:/bin:/usr/sbin:/sbin ./.elastos-installer install --from /home/elastos/release --publisher "$3" --head "$4" --sources-sha256 "$5"
status=$?
rm -f .elastos-installer
exit $status"#;

fn wsl() -> Command {
    let system = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let mut command = Command::new(system.join(r"System32\wsl.exe"));
    command
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// `args` run directly (no shell) as `user` in the ElastOS system.
fn inside(user: &str, args: &[&str]) -> Command {
    let mut command = wsl();
    command
        .args(["-d", DISTRO, "-u", user, "--cd", "/", "-e"])
        .args(args);
    command
}

fn succeeds(command: &mut Command) -> bool {
    command.status().is_ok_and(|status| status.success())
}

fn logged(command: &mut Command, log: &std::fs::File, what: &str) -> io::Result<()> {
    let status = command
        .stdout(log.try_clone()?)
        .stderr(log.try_clone()?)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{what} failed ({status})")))
    }
}

pub fn installed() -> bool {
    crate::runtime::lab_home().is_some_and(|lab| ours(&lab) == Some(true))
        && succeeds(&mut inside(USER, &["test", "-x", "/home/elastos/.local/bin/elastos"]))
}

/// Whether the WSL system named `DISTRO` is the one this app made in `lab`; None
/// when there is none.
fn ours(lab: &Path) -> Option<bool> {
    let base = registered()?;
    let same = std::fs::canonicalize(base)
        .ok()
        .zip(std::fs::canonicalize(lab.join("wsl")).ok())
        .is_some_and(|(base, system)| base == system);
    Some(same)
}

/// The folder of the WSL system named `DISTRO`, from WSL's own list in the registry.
fn registered() -> Option<PathBuf> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY_CURRENT_USER, KEY_READ,
        RRF_RT_REG_SZ,
    };
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }
    let mut lxss = std::ptr::null_mut();
    let path = wide(r"Software\Microsoft\Windows\CurrentVersion\Lxss");
    if unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_READ, &mut lxss) }
        != ERROR_SUCCESS
    {
        return None;
    }
    let read = |key: &[u16], value: &str| -> Option<String> {
        let mut buffer = vec![0u16; 4096];
        let mut size = (buffer.len() * 2) as u32;
        let status = unsafe {
            RegGetValueW(
                lxss,
                key.as_ptr(),
                wide(value).as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        let chars = (size as usize / 2).saturating_sub(1).min(buffer.len());
        (status == ERROR_SUCCESS).then(|| String::from_utf16_lossy(&buffer[..chars]))
    };
    let mut found = None;
    for index in 0.. {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                lxss,
                index,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            break;
        }
        let key: Vec<u16> = name[..len as usize].iter().copied().chain(Some(0)).collect();
        if read(&key, "DistributionName").is_some_and(|name| name.eq_ignore_ascii_case(DISTRO)) {
            found = read(&key, "BasePath").map(PathBuf::from);
            break;
        }
    }
    unsafe { RegCloseKey(lxss) };
    found
}

/// First open: the ElastOS system, its user, and ElastOS from the signed release.
pub fn install(release: &Path, lab: &Path) -> io::Result<()> {
    let (
        Some(head),
        Some(publisher),
        Some(runtime),
        Some(runtime_sha256),
        Some(sources_sha256),
        Some(image_sha256),
    ) = (
        option_env!("ELASTOS_RELEASE_HEAD"),
        option_env!("ELASTOS_RELEASE_PUBLISHER"),
        option_env!("ELASTOS_RELEASE_RUNTIME"),
        option_env!("ELASTOS_RELEASE_RUNTIME_SHA256"),
        option_env!("ELASTOS_RELEASE_SOURCES_SHA256"),
        option_env!("ELASTOS_WSL_IMAGE_SHA256"),
    )
    else {
        return Err(io::Error::other(
            "this app was built without a release to install",
        ));
    };
    if !succeeds(wsl().arg("--version")) {
        return Err(io::Error::other(
            "Windows Subsystem for Linux (WSL) is not turned on. Open PowerShell as administrator, run: wsl --install --no-distribution, restart Windows, then open ElastOS Lab again.",
        ));
    }
    std::fs::create_dir_all(lab)?;
    let log = std::fs::File::options()
        .create(true)
        .append(true)
        .open(lab.join("install.log"))?;

    match ours(lab) {
        Some(true) => {}
        Some(false) => {
            return Err(io::Error::other(
                "Another WSL system is already called ElastOS-Lab, and ElastOS Lab uses only the one it made. Remove it (wsl --unregister ElastOS-Lab) if it is a leftover, then open ElastOS Lab again.",
            ))
        }
        None => {
            let image = release
                .parent()
                .ok_or_else(|| io::Error::other("the app has no Resources folder"))?
                .join(r"wsl\ubuntu-22.04.tar.gz");
            let staged = lab.join(format!("ubuntu-22.04-{}.tar.gz", std::process::id()));
            stage_image(&image, image_sha256, &staged)?;
            let system = lab.join("wsl");
            let imported = std::fs::create_dir_all(&system).and_then(|()| {
                logged(
                    wsl()
                        .args(["--import", DISTRO])
                        .arg(&system)
                        .arg(&staged)
                        .args(["--version", "2"]),
                    &log,
                    "importing the ElastOS system into WSL",
                )
            });
            let _ = std::fs::remove_file(&staged);
            imported?;
        }
    }
    logged(
        &mut inside("root", &["sh", "-c", WSL_CONF]),
        &log,
        "closing the ElastOS system to Windows drives and programs",
    )?;
    logged(
        wsl().args(["--terminate", DISTRO]),
        &log,
        "restarting the ElastOS system",
    )?;
    logged(
        &mut inside(
            "root",
            &[
                "sh",
                "-c",
                "id elastos >/dev/null 2>&1 || useradd -m -s /bin/sh elastos",
            ],
        ),
        &log,
        "creating the ElastOS user",
    )?;

    copy_release(release, &log)?;
    logged(
        &mut inside(
            USER,
            &[
                "sh",
                "-c",
                INSTALL,
                "sh",
                runtime,
                runtime_sha256,
                publisher,
                head,
                sources_sha256,
            ],
        ),
        &log,
        "installing ElastOS from the signed release",
    )
    .map_err(|error| {
        io::Error::other(format!("{error}; see {}", lab.join("install.log").display()))
    })
}

/// LAB DRAFT of `elastos service start`, as on macOS and Linux. Home keeps running
/// in WSL when this app quits.
pub fn start_home(lab: &Path) -> io::Result<()> {
    let log = std::fs::File::options()
        .create(true)
        .append(true)
        .open(lab.join("home.log"))?;
    inside(
        USER,
        &[
            "env",
            "-i",
            &format!("HOME={HOME}"),
            &format!("PATH={PATH}"),
            "ELASTOS_SERVICE=1",
            "/home/elastos/.local/bin/elastos",
            "home",
            "--browser",
        ],
    )
    .stdout(log.try_clone()?)
    .stderr(log)
    .spawn()?;
    Ok(())
}

/// The signed release, file by file, into `~/release` of the ElastOS user; the
/// Runtime then checks every file against the signed release.
fn copy_release(release: &Path, log: &std::fs::File) -> io::Result<()> {
    logged(
        &mut inside(
            USER,
            &["sh", "-c", "umask 077 && cd /home/elastos && rm -rf release && mkdir release"],
        ),
        log,
        "preparing the release folder",
    )?;
    for entry in std::fs::read_dir(release)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::other("the release has a file with an unreadable name"))?;
        let plain = !name.starts_with('.')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !plain || !entry.file_type()?.is_file() {
            return Err(io::Error::other(format!(
                "the release has an unexpected entry {name:?}"
            )));
        }
        logged(
            inside(
                USER,
                &["sh", "-c", "umask 077 && cat > \"/home/elastos/release/$1\"", "sh", &name],
            )
            .stdin(std::fs::File::open(entry.path())?),
            log,
            "copying the release",
        )?;
    }
    Ok(())
}

/// Copies `source` to a new `staged` file, and keeps it only if those bytes have
/// `sha256`; WSL then imports the copy, not the file in the app folder.
fn stage_image(source: &Path, sha256: &str, staged: &Path) -> io::Result<()> {
    let mut input = std::fs::File::open(source)?;
    let mut output = std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(staged)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let copied = loop {
        let read = match input.read(&mut buffer) {
            Ok(read) => read,
            Err(error) => break Err(error),
        };
        if read == 0 {
            break output.flush();
        }
        hasher.update(&buffer[..read]);
        if let Err(error) = output.write_all(&buffer[..read]) {
            break Err(error);
        }
    };
    drop(output);
    if copied.is_err() || format!("{:x}", hasher.finalize()) != sha256 {
        let _ = std::fs::remove_file(staged);
        copied?;
        return Err(io::Error::other(
            "the Linux image in this app is not the one it was built with",
        ));
    }
    Ok(())
}
