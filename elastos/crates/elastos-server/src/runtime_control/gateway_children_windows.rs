//! Managed gateway children wait for Windows process-tree ownership.

use std::path::Path;
use std::process::{Child, Command, ExitStatus};

use anyhow::Result;

#[derive(Clone)]
pub(crate) struct Owner {
    _private: (),
}

fn unsupported() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "managed gateway process groups are unsupported on Windows",
    )
}

impl Owner {
    pub(crate) fn read(_data_dir: &Path) -> Result<Self> {
        Err(unsupported().into())
    }

    pub(crate) fn read_for_generation(
        _data_dir: &Path,
        _pid: u32,
        _update_generation: &str,
    ) -> Result<Option<Self>> {
        Err(unsupported().into())
    }

    pub(crate) fn configure(&self, _command: &mut Command) -> Result<()> {
        Err(unsupported().into())
    }

    pub(crate) fn lock_start(&self) -> Result<crate::host_lock::FileLock> {
        Err(unsupported().into())
    }
}

pub(crate) struct StartingChild {
    pub child: Child,
}

impl StartingChild {
    pub(crate) fn new(
        mut child: Child,
        _owner: Option<&Owner>,
        _coords_path: &Path,
    ) -> Result<Self> {
        let _ = child.kill();
        let _ = child.wait();
        Err(unsupported().into())
    }

    pub(crate) fn ready(&mut self) {
        unreachable!("Windows cannot construct a managed gateway child")
    }

    pub(crate) fn observed_exit(&self) -> std::io::Result<Option<ExitStatus>> {
        Err(unsupported())
    }
}

pub(crate) async fn shutdown(owner: Option<Owner>) -> Result<()> {
    if owner.is_some() {
        Err(unsupported().into())
    } else {
        Ok(())
    }
}

pub(crate) fn refuse_unreconciled_groups(_data_dir: &Path) -> Result<()> {
    Err(unsupported().into())
}

pub fn watch_gateway_owner() -> Result<()> {
    Err(unsupported().into())
}
