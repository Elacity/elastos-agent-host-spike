//! Running VM lifecycle management (crosvm)

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Stdio;

use elastos_common::{CapsuleManifest, CapsuleStatus, ElastosError, Result};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tokio::process::{Child, Command};

use crate::config::VmConfig;

/// A running crosvm VM instance
pub struct RunningVm {
    /// VM configuration
    pub config: VmConfig,

    /// Capsule manifest
    pub manifest: CapsuleManifest,

    /// Current status
    pub status: CapsuleStatus,

    /// crosvm control socket path (for `crosvm stop`)
    pub socket_path: PathBuf,

    /// crosvm process handle
    process: Option<Child>,

    /// Process ID (for signal sending)
    pid: Option<u32>,

    /// Path to crosvm binary (for `crosvm stop`)
    crosvm_bin: Option<PathBuf>,

    verified_rootfs: Option<File>,
}

impl RunningVm {
    /// Create a new VM (not yet started)
    pub fn new(
        config: VmConfig,
        manifest: CapsuleManifest,
        socket_path: PathBuf,
        verified_rootfs: Option<File>,
    ) -> Self {
        Self {
            config,
            manifest,
            status: CapsuleStatus::Loading,
            socket_path,
            process: None,
            pid: None,
            crosvm_bin: None,
            verified_rootfs,
        }
    }

    /// Start the VM using crosvm
    pub async fn start(&mut self, crosvm_bin: &std::path::Path) -> Result<()> {
        if self.process.is_some() {
            return Err(ElastosError::Compute("VM already started".into()));
        }
        let rootfs = self
            .verified_rootfs
            .as_ref()
            .ok_or_else(|| ElastosError::Compute("Unverified VM rootfs refused".into()))?;
        let rootfs_fd = rootfs.as_raw_fd();

        if !cfg!(target_os = "linux") || !std::path::Path::new("/dev/kvm").exists() {
            return Err(ElastosError::Compute(
                "/dev/kvm not available — verified crosvm disk requires Linux KVM".into(),
            ));
        }

        // Guest networking is explicit compatibility mode only.
        // Ordinary app capsules use the serial Carrier bridge and no guest NIC.

        // Ensure socket directory exists
        if let Some(parent) = self.socket_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                ElastosError::Compute(format!("Failed to create socket dir: {}", e))
            })?;
        }

        // Ensure crosvm pivot-root directory exists (avoids host /var/empty dependency).
        if let Some(ref pivot_root) = self.config.pivot_root_dir {
            tokio::fs::create_dir_all(pivot_root).await.map_err(|e| {
                ElastosError::Compute(format!(
                    "Failed to create crosvm pivot-root dir '{}': {}",
                    pivot_root.display(),
                    e
                ))
            })?;
        }

        if let Some(ref network) = self.config.network {
            tracing::info!(
                "Setting up guest-network TAP for VM '{}': tap={} host={} guest={}",
                self.manifest.name,
                network.tap_name,
                network.host_ip,
                network.guest_ip
            );
            network.setup().map_err(|e| {
                ElastosError::Compute(format!(
                    "guest-network TAP setup failed for '{}': {}",
                    self.manifest.name, e
                ))
            })?;
        }

        let _ = tokio::fs::remove_file(&self.socket_path).await;

        // Build crosvm run command
        let mut checked = self.config.clone();
        checked.rootfs_path = format!("/proc/self/fd/{rootfs_fd}").into();
        let crosvm_args = checked.to_crosvm_args();

        tracing::info!(
            "Starting crosvm VM '{}': {} run --socket {} {}",
            self.manifest.name,
            crosvm_bin.display(),
            self.socket_path.display(),
            crosvm_args.join(" ")
        );

        // Spawn: crosvm run --socket <path> [vm args...]
        let mut command = Command::new(crosvm_bin);
        command
            .arg("run")
            .arg("--socket")
            .arg(&self.socket_path)
            .args(&crosvm_args)
            .kill_on_drop(true);
        unsafe {
            command.as_std_mut().pre_exec(move || {
                if libc::fcntl(rootfs_fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        if self.config.interactive_stdio {
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        } else {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }

        let mut child = command.spawn().map_err(|e| {
            if let Some(ref network) = self.config.network {
                let _ = network.teardown();
            }
            ElastosError::Compute(format!("Failed to start crosvm: {}", e))
        })?;
        self.verified_rootfs.take();

        // Forward VM serial output through tracing.
        if !self.config.interactive_stdio {
            if let Some(stdout) = child.stdout.take() {
                tokio::spawn(async move {
                    use tokio::io::AsyncBufReadExt;
                    let reader = tokio::io::BufReader::new(stdout);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        tracing::info!(target: "vm_console", "{}", line);
                    }
                });
            }
            if let Some(stderr) = child.stderr.take() {
                tokio::spawn(async move {
                    use tokio::io::AsyncBufReadExt;
                    let reader = tokio::io::BufReader::new(stderr);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        tracing::warn!(target: "vm_console", "{}", line);
                    }
                });
            }
        }

        self.pid = child.id();
        self.process = Some(child);
        self.status = CapsuleStatus::Running;
        self.crosvm_bin = Some(crosvm_bin.to_path_buf());

        tracing::info!(
            "crosvm VM '{}' started (pid: {:?})",
            self.manifest.name,
            self.pid,
        );

        Ok(())
    }

    /// Stop the VM gracefully (via `crosvm stop` or SIGTERM)
    pub async fn stop(&mut self) -> Result<()> {
        // Try `crosvm stop` via control socket first
        let crosvm = self
            .crosvm_bin
            .as_deref()
            .unwrap_or_else(|| std::path::Path::new("crosvm"));
        if self.socket_path.exists() {
            let output = tokio::process::Command::new(crosvm)
                .arg("stop")
                .arg(&self.socket_path)
                .output()
                .await;

            match output {
                Ok(o) if o.status.success() => {
                    tracing::info!(
                        "crosvm VM '{}' stopped via control socket",
                        self.manifest.name
                    );
                }
                _ => {
                    // Fallback to SIGTERM
                    if let Some(pid) = self.pid {
                        let nix_pid = Pid::from_raw(pid as i32);
                        if let Err(e) = signal::kill(nix_pid, Signal::SIGTERM) {
                            tracing::warn!("Failed to send SIGTERM to VM: {}", e);
                        }
                    }
                }
            }
        } else if let Some(pid) = self.pid {
            let nix_pid = Pid::from_raw(pid as i32);
            if let Err(e) = signal::kill(nix_pid, Signal::SIGTERM) {
                tracing::warn!("Failed to send SIGTERM to VM: {}", e);
            }
        }

        // Wait for process to exit
        if let Some(ref mut child) = self.process {
            match tokio::time::timeout(std::time::Duration::from_secs(10), child.wait()).await {
                Ok(Ok(status)) => {
                    tracing::info!(
                        "crosvm VM '{}' exited with status: {}",
                        self.manifest.name,
                        status
                    );
                }
                Ok(Err(e)) => {
                    tracing::warn!("Error waiting for VM to exit: {}", e);
                }
                Err(_) => {
                    tracing::warn!("VM did not exit within timeout, killing");
                    self.kill().await?;
                }
            }
        }

        self.process = None;
        self.pid = None;
        self.status = CapsuleStatus::Stopped;
        self.verified_rootfs.take();

        // Clean up socket
        let _ = tokio::fs::remove_file(&self.socket_path).await;
        if let Some(ref network) = self.config.network {
            let _ = network.teardown();
        }

        Ok(())
    }

    /// Force kill the VM
    pub async fn kill(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            let nix_pid = Pid::from_raw(pid as i32);
            if let Err(e) = signal::kill(nix_pid, Signal::SIGKILL) {
                tracing::warn!("Failed to send SIGKILL to VM: {}", e);
            }
        }

        if let Some(ref mut child) = self.process {
            let _ = child.wait().await;
        }

        self.process = None;
        self.pid = None;
        self.status = CapsuleStatus::Stopped;
        self.verified_rootfs.take();

        // Clean up socket
        let _ = tokio::fs::remove_file(&self.socket_path).await;
        if let Some(ref network) = self.config.network {
            let _ = network.teardown();
        }

        Ok(())
    }

    /// Check if the VM is running
    /// Wait for the VM process to exit. Returns the exit status.
    pub async fn wait_for_exit(&mut self) -> Result<std::process::ExitStatus> {
        match self.process.as_mut() {
            Some(child) => child
                .wait()
                .await
                .map_err(|e| ElastosError::Compute(format!("wait failed: {}", e))),
            None => Err(ElastosError::Compute("no VM process to wait on".into())),
        }
    }

    pub fn is_running(&self) -> bool {
        if let Some(pid) = self.pid {
            let nix_pid = Pid::from_raw(pid as i32);
            signal::kill(nix_pid, None).is_ok()
        } else {
            false
        }
    }

    /// Get the VM's HTTP port (if configured)
    pub fn http_port(&self) -> Option<u16> {
        self.config.http_port
    }

    /// Get the VM's process ID
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }
}

impl Drop for RunningVm {
    fn drop(&mut self) {
        // Try to clean up the VM if it's still running
        if let Some(pid) = self.pid {
            let nix_pid = Pid::from_raw(pid as i32);
            let _ = signal::kill(nix_pid, Signal::SIGKILL);
        }
        if let Some(ref network) = self.config.network {
            let _ = network.teardown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn start_without_checked_rootfs_refuses_before_kvm() {
        let temp = tempfile::tempdir().unwrap();
        let manifest: CapsuleManifest = serde_json::from_value(serde_json::json!({
            "schema": "elastos.capsule/v1",
            "version": "0.1.0",
            "name": "test-vm",
            "role": "app",
            "type": "microvm",
            "entrypoint": "rootfs.ext4"
        }))
        .unwrap();
        let config = VmConfig::from_manifest(&manifest, temp.path(), &temp.path().join("vmlinux"));
        let mut vm = RunningVm::new(config, manifest, temp.path().join("vm.sock"), None);
        let error = vm.start(&temp.path().join("crosvm")).await.unwrap_err();
        assert!(error.to_string().contains("Unverified VM rootfs refused"));
        assert!(!temp.path().join("vm.sock").exists());
    }
}
