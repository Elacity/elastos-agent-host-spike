//! Standalone launcher guard.
//!
//! ```text
//! fcl-launch --provider did-provider --storage-root DIR [--read-exec DIR]... -- PROGRAM [ARG...]
//! ```
//!
//! It starts PROGRAM with every confinement layer applied, or refuses and
//! prints the reason. Exit status: the provider's own status after a start;
//! 71 when the guard refuses (the status `sandbox-exec` gives when it cannot
//! start a provider); 70 for another start failure; 64 for a usage error.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("provider not started: linux confinement refused: this host is not Linux");
    std::process::exit(71);
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::Command;

    use fail_closed_linux::{FsRules, Guard, LaunchError, Policy, ProviderKind};

    const EXIT_USAGE: i32 = 64;
    const EXIT_FAILED: i32 = 70;
    const EXIT_REFUSED: i32 = 71;

    const USAGE: &str =
        "usage: fcl-launch --provider <did-provider|wallet-provider|model-provider> \
--storage-root DIR [--read-exec DIR]... -- PROGRAM [ARG...]";

    struct Args {
        provider: ProviderKind,
        storage_root: PathBuf,
        read_exec: Vec<PathBuf>,
        program: PathBuf,
        program_args: Vec<String>,
    }

    fn parse(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
        let mut provider = None;
        let mut storage_root = None;
        let mut read_exec = Vec::new();
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--provider" => {
                    let name = args.next().ok_or("--provider needs a name")?;
                    provider = Some(
                        ProviderKind::from_name(&name).ok_or(format!("unknown provider {name}"))?,
                    );
                }
                "--storage-root" => {
                    storage_root = Some(PathBuf::from(
                        args.next().ok_or("--storage-root needs a path")?,
                    ))
                }
                "--read-exec" => read_exec.push(PathBuf::from(
                    args.next().ok_or("--read-exec needs a path")?,
                )),
                "--" => {
                    let program = args.next().ok_or("no provider program after --")?;
                    return Ok(Args {
                        provider: provider.ok_or("--provider is required")?,
                        storage_root: storage_root.ok_or("--storage-root is required")?,
                        read_exec,
                        program: PathBuf::from(program),
                        program_args: args.collect(),
                    });
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        Err("no -- before the provider program".to_string())
    }

    pub fn run() -> i32 {
        let args = match parse(std::env::args().skip(1)) {
            Ok(args) => args,
            Err(message) => {
                eprintln!("fcl-launch: {message}\n{USAGE}");
                return EXIT_USAGE;
            }
        };
        let policy = (|| {
            let mut fs = FsRules::new()
                .exec_file(&args.program)?
                .read_write_dir(&args.storage_root)?;
            for dir in &args.read_exec {
                fs = fs.read_exec_dir(dir)?;
            }
            Policy::baseline(fs)
        })();
        let policy = match policy {
            Ok(policy) => policy,
            Err(error) => {
                eprintln!(
                    "{} not started: policy rejected: {error}",
                    args.provider.name()
                );
                return EXIT_FAILED;
            }
        };
        let mut command = Command::new(&args.program);
        command.args(&args.program_args);
        match Guard::host(policy).launch(args.provider, command) {
            Ok(mut child) => match child.wait() {
                Ok(status) => status
                    .code()
                    .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
                Err(error) => {
                    eprintln!("{} wait failed: {error}", args.provider.name());
                    EXIT_FAILED
                }
            },
            Err(LaunchError::Refused(refusal)) => {
                eprintln!("{refusal}");
                EXIT_REFUSED
            }
            Err(error @ LaunchError::Spawn(_)) => {
                eprintln!("{} {error}", args.provider.name());
                EXIT_FAILED
            }
        }
    }
}
