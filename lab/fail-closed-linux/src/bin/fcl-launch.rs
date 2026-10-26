//! Starts one provider under the fail-closed guard.
//!
//! usage: fcl-launch --provider NAME --storage-root DIR [--require-landlock-abi N] -- EXECUTABLE [ARG...]
//!
//! Exit codes: 71 when the guard refuses (the provider was not started), 64
//! for a usage error, otherwise the provider's own exit code (128 + signal
//! when a signal ended it).

use fail_closed_linux::real::RealKernel;
use fail_closed_linux::{launch, ProviderSpec, REFUSAL_EXIT_CODE};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::exit;

const USAGE_EXIT_CODE: i32 = 64;
const WAIT_FAILED_EXIT_CODE: i32 = 70;
const USAGE: &str = "usage: fcl-launch --provider NAME --storage-root DIR [--require-landlock-abi N] -- EXECUTABLE [ARG...]";

fn main() {
    let spec = match parse(std::env::args_os().skip(1).collect()) {
        Ok(spec) => spec,
        Err(message) => {
            eprintln!("fcl-launch: {message}\n{USAGE}");
            exit(USAGE_EXIT_CODE);
        }
    };
    match launch(&mut RealKernel::new(), &spec) {
        Ok(started) => {
            println!("started {} pid={}", started.provider, started.pid);
            exit(wait(started.pid));
        }
        Err(refusal) => {
            eprintln!("{refusal}");
            exit(REFUSAL_EXIT_CODE);
        }
    }
}

fn parse(args: Vec<OsString>) -> Result<ProviderSpec, String> {
    let mut provider = None;
    let mut storage_root = None;
    let mut landlock_abi = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.to_str() {
            Some("--provider") => {
                provider = Some(
                    value("--provider")?
                        .into_string()
                        .map_err(|_| "--provider must be UTF-8".to_string())?,
                )
            }
            Some("--storage-root") => storage_root = Some(PathBuf::from(value("--storage-root")?)),
            Some("--require-landlock-abi") => {
                let text = value("--require-landlock-abi")?;
                landlock_abi = Some(
                    text.to_str()
                        .and_then(|text| text.parse::<u32>().ok())
                        .ok_or_else(|| "--require-landlock-abi needs a number".to_string())?,
                );
            }
            Some("--") => {
                let executable = PathBuf::from(args.next().ok_or("no EXECUTABLE after --")?);
                let provider = provider
                    .filter(|name| !name.is_empty())
                    .ok_or("--provider is required")?;
                let storage_root = storage_root.ok_or("--storage-root is required")?;
                let mut spec = ProviderSpec::new(provider, executable, storage_root);
                if let Some(abi) = landlock_abi {
                    spec = spec.require_landlock_abi(abi);
                }
                for arg in args {
                    spec = spec.arg(arg);
                }
                return Ok(spec);
            }
            _ => return Err(format!("unknown argument {arg:?}")),
        }
    }
    Err("no -- EXECUTABLE".to_string())
}

fn wait(pid: u32) -> i32 {
    let mut status = 0;
    loop {
        // SAFETY: `status` is a valid out pointer.
        let ret = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
        if ret >= 0 {
            break;
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return WAIT_FAILED_EXIT_CODE;
        }
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        WAIT_FAILED_EXIT_CODE
    }
}
