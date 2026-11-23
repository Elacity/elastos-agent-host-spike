//! Update children require an owned process tree and parent-loss fence.
//! Windows waits for an equivalent job-object implementation.

use std::io;
use std::process::ExitStatus;

use anyhow::Result;
use tokio::process::Command;

pub(crate) struct OwnedChild {
    _private: (),
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "update child process ownership is unsupported on Windows",
    )
}

impl OwnedChild {
    pub(crate) fn spawn(_command: &mut Command) -> Result<Self> {
        Err(unsupported().into())
    }

    pub(crate) fn pid(&self) -> u32 {
        unreachable!("Windows cannot construct an owned update child")
    }

    pub(crate) fn observed_exit(&self) -> Result<Option<ExitStatus>> {
        Err(unsupported().into())
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        Err(unsupported().into())
    }
}

pub(crate) fn process_start(_pid: u32) -> Option<String> {
    // Unknown identity is never evidence that a process is the claimed one.
    None
}

pub(crate) fn generation_gone(_pid: u32, _start: &str) -> Result<bool> {
    Err(unsupported().into())
}

/// Same name as `elastos_common::process_lifetime::PARENT_PIPE_ENV`, which is Unix-only.
const PARENT_PIPE_ENV: &str = "ELASTOS_UPDATE_PARENT_PIPE";

/// Windows refuses whenever the parent-pipe marker is present, because it has no owned
/// parent pipe yet. Unix goes further than marker presence: it also checks the marker's
/// pipe fd identity, so a stale or reused descriptor runs without a watcher instead of
/// refusing.
pub(crate) fn watch_parent() -> Result<()> {
    if std::env::var_os(PARENT_PIPE_ENV).is_none() {
        return Ok(());
    }
    Err(unsupported().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_start_without_the_update_child_marker_and_an_update_child_still_refuses() {
        // One test so the process environment is changed in one place only.
        std::env::remove_var(PARENT_PIPE_ENV);
        assert!(watch_parent().is_ok());
        std::env::set_var(PARENT_PIPE_ENV, "1:2:3");
        let error = watch_parent().unwrap_err();
        std::env::remove_var(PARENT_PIPE_ENV);
        assert_eq!(
            error.to_string(),
            "update child process ownership is unsupported on Windows"
        );
    }
}
