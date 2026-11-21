//! Keep the verified executable bytes selected until process creation.

use anyhow::{Context, Result};
use sha2::Digest;
#[cfg(target_os = "macos")]
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Read;
#[cfg(target_os = "macos")]
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct VerifiedExecutable {
    #[cfg(target_os = "linux")]
    file: File,
    #[cfg(target_os = "macos")]
    _private_dir: tempfile::TempDir,
    exec_path: PathBuf,
    /// The signed release digest these held bytes matched (none for a source
    /// Home's `dev_mode = true` start). A native provider start pins its
    /// spawn-time check to this same digest.
    checksum: Option<String>,
}

impl VerifiedExecutable {
    pub fn prepare(path: &Path, checksum: &str) -> Result<Self> {
        Self::hold(path, Some(checksum))
    }

    /// A source Home's `dev_mode = true` start: the same held bytes, no digest.
    pub(crate) fn unchecked(path: &Path) -> Result<Self> {
        Self::hold(path, None)
    }

    fn hold(path: &Path, checksum: Option<&str>) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("cannot open installed executable {}", path.display()))?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "installed executable is not a regular file"
        );
        anyhow::ensure!(
            checksum.map_or(Ok(true), |checksum| matches_checksum(&mut file, checksum))?,
            "installed executable differs from signed release digest"
        );

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            // Standard I/O setup owns descriptors 0..2 in the child.
            let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("cannot hold installed executable");
            }
            Ok(Self {
                file: unsafe { File::from_raw_fd(fd) },
                exec_path: format!("/proc/self/fd/{fd}").into(),
                checksum: checksum.map(str::to_owned),
            })
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::PermissionsExt;
            let private_dir = tempfile::Builder::new().prefix("elastos-exec-").tempdir()?;
            let exec_path = private_dir.path().join("executable");
            let mut copy = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&exec_path)?;
            file.seek(SeekFrom::Start(0))?;
            std::io::copy(&mut file, &mut copy)?;
            copy.sync_all()?;
            copy.set_permissions(fs::Permissions::from_mode(0o500))?;
            drop(copy);
            let mut copy = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&exec_path)?;
            anyhow::ensure!(
                checksum.map_or(Ok(true), |checksum| matches_checksum(&mut copy, checksum))?,
                "private executable copy differs from signed release digest"
            );
            Ok(Self {
                _private_dir: private_dir,
                exec_path,
                checksum: checksum.map(str::to_owned),
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        anyhow::bail!("installed executable launch is unsupported on this platform")
    }

    pub fn exec_path(&self) -> &Path {
        &self.exec_path
    }

    /// Native providers require a signed digest even in a source Home's
    /// `dev_mode`; refuse an unchecked executable before process creation.
    pub fn signed_checksum(&self) -> Result<&str> {
        self.checksum.as_deref().ok_or_else(|| {
            anyhow::anyhow!("no signed release digest (dev_mode start is unchecked)")
        })
    }

    /// Attach after the caller has set all arguments and environment changes.
    /// Linux executes the held descriptor; the visible command path is only a
    /// fallback for std's command construction and is never the exec target.
    pub fn attach_std(&self, command: &mut std::process::Command, clear_env: bool) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::collections::BTreeMap;
            use std::ffi::{CString, OsString};
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::process::CommandExt;

            let mut argv = Vec::new();
            argv.push(CString::new(command.get_program().as_bytes())?);
            for arg in command.get_args() {
                argv.push(CString::new(arg.as_bytes())?);
            }
            let mut env: BTreeMap<OsString, OsString> = if clear_env {
                BTreeMap::new()
            } else {
                std::env::vars_os().collect()
            };
            for (key, value) in command.get_envs() {
                match value {
                    Some(value) => {
                        env.insert(key.to_os_string(), value.to_os_string());
                    }
                    None => {
                        env.remove(key);
                    }
                }
            }
            let env: Vec<CString> = env
                .into_iter()
                .map(|(key, value)| {
                    let mut bytes = key.as_bytes().to_vec();
                    bytes.push(b'=');
                    bytes.extend_from_slice(value.as_bytes());
                    CString::new(bytes)
                })
                .collect::<std::result::Result<_, _>>()?;
            let mut argv_ptrs: Vec<usize> =
                argv.iter().map(|value| value.as_ptr() as usize).collect();
            argv_ptrs.push(0);
            let mut env_ptrs: Vec<usize> =
                env.iter().map(|value| value.as_ptr() as usize).collect();
            env_ptrs.push(0);
            let fd = self.file.as_raw_fd();
            unsafe {
                command.pre_exec(move || {
                    // Script interpreters reopen the descriptor after exec.
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    libc::fexecve(fd, argv_ptrs.as_ptr().cast(), env_ptrs.as_ptr().cast());
                    let _keep_alive = (&argv, &env);
                    Err(std::io::Error::last_os_error())
                });
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (command, clear_env);
        }
        Ok(())
    }

    pub fn attach_tokio(
        &self,
        command: &mut tokio::process::Command,
        clear_env: bool,
    ) -> Result<()> {
        self.attach_std(command.as_std_mut(), clear_env)
    }
}

fn matches_checksum(file: &mut File, checksum: &str) -> Result<bool> {
    let (algorithm, expected) = checksum
        .split_once(':')
        .context("signed executable digest is malformed")?;
    let mut buffer = [0u8; 8192];
    match algorithm {
        "sha256" if expected.len() == 64 => {
            let mut digest = sha2::Sha256::new();
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                digest.update(&buffer[..n]);
            }
            Ok(hex::encode(digest.finalize()) == expected.to_ascii_lowercase())
        }
        "sha512" if expected.len() == 128 => {
            let mut digest = sha2::Sha512::new();
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                digest.update(&buffer[..n]);
            }
            Ok(hex::encode(digest.finalize()) == expected.to_ascii_lowercase())
        }
        _ => anyhow::bail!("signed executable digest is unsupported"),
    }
}
