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

pub(crate) fn watch_parent() -> Result<()> {
    Err(unsupported().into())
}
