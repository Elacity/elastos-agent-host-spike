//! The `tools/bundle` command's rules, as library functions the named tests
//! call in-process. The `bundle` binary (`src/bin/bundle.rs`) only parses,
//! runs, prints and sets the exit status.
//!
//! ```text
//! tools/bundle OUT_DIR             build with tools/build, write OUT_DIR/bundle/, print its lab CID
//! tools/bundle --name BUNDLE_DIR   print the lab CID of an existing bundle
//! ```
//!
//! Both modes name a bundle only with [`crate::bundle_identity`], and pass its
//! refusals through unchanged. The build mode makes a new OUT_DIR, and inside
//! it a new `bundle/` holding exactly `capsule.json` (this capsule's manifest,
//! [`crate::CAPSULE_MANIFEST`]) and `capsule.wasm` (the module `tools/build`
//! wrote and receipted, moved in unchanged). Each entry is made new, so
//! nothing is ever written into or through what was already at its path, a
//! link included. Links in OUT_DIR's own parent folders are not checked, and
//! another process changing OUT_DIR during the run is not covered: that needs
//! folder-relative opens.

use crate::{bundle_identity, CAPSULE_MANIFEST};
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

/// The usage line, printed after every argument refusal.
pub const USAGE: &str = "usage: tools/bundle OUT_DIR | tools/bundle --name BUNDLE_DIR";

/// The one option.
const NAME_OPTION: &str = "--name";

/// The bundle folder `tools/bundle` makes inside OUT_DIR.
const BUNDLE_DIR: &str = "bundle";

/// The manifest's file name in a bundle.
const MANIFEST_FILE: &str = "capsule.json";

/// The module's file name, in OUT_DIR (where `tools/build` writes it) and in a
/// bundle.
const MODULE_FILE: &str = "capsule.wasm";

/// What the command was asked to do. Paths stay `OsString`s, so a path that is
/// not UTF-8 keeps every byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Build the capsule and write a new bundle in the new folder `out_dir`.
    Build { out_dir: PathBuf },
    /// Name the existing bundle at `bundle_dir`.
    Name { bundle_dir: PathBuf },
}

/// Why the arguments were refused. Each rule has its own reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgRefusal {
    /// No argument at all.
    NoArgument,
    /// An argument that starts with `-` and is not `--name`.
    UnknownOption(OsString),
    /// `--name` with no directory after it.
    NameWithoutDir,
    /// An argument after OUT_DIR, or after `--name BUNDLE_DIR`.
    ExtraArgument(OsString),
    /// An empty OUT_DIR or BUNDLE_DIR.
    EmptyPath,
}

impl fmt::Display for ArgRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArgRefusal::NoArgument => write!(f, "no argument: give OUT_DIR, or --name BUNDLE_DIR"),
            ArgRefusal::UnknownOption(arg) => write!(
                f,
                "unknown option {:?}: the only option is --name",
                arg.to_string_lossy()
            ),
            ArgRefusal::NameWithoutDir => write!(f, "--name needs a BUNDLE_DIR after it"),
            ArgRefusal::ExtraArgument(arg) => write!(
                f,
                "extra argument {:?}: give one OUT_DIR, or --name and one BUNDLE_DIR",
                arg.to_string_lossy()
            ),
            ArgRefusal::EmptyPath => write!(f, "an empty path names no directory"),
        }
    }
}

impl Error for ArgRefusal {}

/// Read the command's arguments (without the program name).
///
/// Any argument that starts with `-` and is not `--name` is refused first,
/// wherever it is. Then `--name` must be first and take one BUNDLE_DIR, or
/// the one argument is OUT_DIR. An empty path is refused. Nothing is
/// converted to UTF-8.
pub fn parse_args(args: &[OsString]) -> Result<Mode, ArgRefusal> {
    if let Some(option) = args
        .iter()
        .find(|arg| arg.as_bytes().starts_with(b"-") && *arg != NAME_OPTION)
    {
        return Err(ArgRefusal::UnknownOption(option.clone()));
    }
    let (path, rest) = match args {
        [] => return Err(ArgRefusal::NoArgument),
        [option, rest @ ..] if option == NAME_OPTION => match rest {
            [] => return Err(ArgRefusal::NameWithoutDir),
            [dir, ..] if dir == NAME_OPTION => return Err(ArgRefusal::NameWithoutDir),
            [dir, rest @ ..] => (dir, rest),
        },
        [out_dir, rest @ ..] => (out_dir, rest),
    };
    if path.is_empty() {
        return Err(ArgRefusal::EmptyPath);
    }
    if let Some(extra) = rest.first() {
        return Err(ArgRefusal::ExtraArgument(extra.clone()));
    }
    let path = PathBuf::from(path);
    if args[0] == NAME_OPTION {
        Ok(Mode::Name { bundle_dir: path })
    } else {
        Ok(Mode::Build { out_dir: path })
    }
}

/// Why a run was refused, at which path. Each step has its own reason.
#[derive(Debug)]
pub enum Reason {
    /// Something (a folder, a file or a link) is already at OUT_DIR.
    OutDirExists,
    /// OUT_DIR could not be made.
    OutDirNotCreated(io::Error),
    /// `tools/build` could not be started.
    BuildDidNotStart(io::Error),
    /// `tools/build` ran and failed.
    BuildFailed(ExitStatus),
    /// Something was put at `OUT_DIR/bundle` during the build.
    BundleDirExists,
    /// `OUT_DIR/bundle` could not be made.
    BundleDirNotCreated(io::Error),
    /// `bundle/capsule.json` could not be made new.
    ManifestNotCreated(io::Error),
    /// `bundle/capsule.json` was made, but its bytes could not be written.
    ManifestNotWritten(io::Error),
    /// The module could not be moved into the bundle.
    ModuleNotMoved(io::Error),
    /// [`crate::bundle_identity`] refused the bundle: its own refusal,
    /// unchanged.
    Identity(Box<dyn Error + Send + Sync>),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::OutDirExists => write!(
                f,
                "OUT_DIR already exists: tools/bundle makes a new OUT_DIR and never writes into or through what is already there"
            ),
            Reason::OutDirNotCreated(error) => write!(f, "OUT_DIR cannot be created: {error}"),
            Reason::BuildDidNotStart(error) => write!(f, "tools/build did not start: {error}"),
            Reason::BuildFailed(status) => write!(f, "tools/build failed ({status})"),
            Reason::BundleDirExists => write!(
                f,
                "bundle/ already exists: it appeared during the build, and tools/bundle never writes into or through it"
            ),
            Reason::BundleDirNotCreated(error) => write!(f, "bundle/ cannot be created: {error}"),
            Reason::ManifestNotCreated(error) => {
                write!(f, "capsule.json cannot be created: {error}")
            }
            Reason::ManifestNotWritten(error) => {
                write!(f, "capsule.json cannot be written: {error}")
            }
            Reason::ModuleNotMoved(error) => {
                write!(f, "capsule.wasm cannot be moved into the bundle: {error}")
            }
            Reason::Identity(refusal) => write!(f, "{refusal}"),
        }
    }
}

/// A refused run: the path it stopped at, and why.
#[derive(Debug)]
pub struct RunRefusal {
    pub path: PathBuf,
    pub reason: Reason,
}

impl RunRefusal {
    fn new(path: &Path, reason: Reason) -> RunRefusal {
        RunRefusal {
            path: path.to_path_buf(),
            reason,
        }
    }
}

impl fmt::Display for RunRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.reason)
    }
}

impl Error for RunRefusal {}

/// Run `mode`. `build_script` is the `tools/build` to run, by its path; the
/// binary passes the lane's own, and tests pass small scripts of their own.
/// Success returns the bundle's lab CID as [`crate::bundle_identity`] prints
/// it.
pub fn run(mode: &Mode, build_script: &Path) -> Result<String, RunRefusal> {
    match mode {
        Mode::Build { out_dir } => build_bundle(out_dir, build_script),
        Mode::Name { bundle_dir } => identify(bundle_dir),
    }
}

/// The one naming step of both modes: [`crate::bundle_identity`] of `dir`,
/// printed, or its refusal unchanged.
fn identify(dir: &Path) -> Result<String, RunRefusal> {
    bundle_identity(dir)
        .map(|name| name.to_string())
        .map_err(|refusal| RunRefusal::new(dir, Reason::Identity(Box::new(refusal))))
}

/// Make the new OUT_DIR, build into it, make the new bundle, and name it.
fn build_bundle(out_dir: &Path, build_script: &Path) -> Result<String, RunRefusal> {
    // `create_dir` refuses anything already at OUT_DIR, a link included.
    fs::create_dir(out_dir).map_err(|error| match error.kind() {
        io::ErrorKind::AlreadyExists => RunRefusal::new(out_dir, Reason::OutDirExists),
        _ => RunRefusal::new(out_dir, Reason::OutDirNotCreated(error)),
    })?;
    run_build(build_script, out_dir)?;

    // Made only after the build, so anything put here during it is refused.
    let bundle = out_dir.join(BUNDLE_DIR);
    fs::create_dir(&bundle).map_err(|error| match error.kind() {
        io::ErrorKind::AlreadyExists => RunRefusal::new(&bundle, Reason::BundleDirExists),
        _ => RunRefusal::new(&bundle, Reason::BundleDirNotCreated(error)),
    })?;
    write_new_file(&bundle.join(MANIFEST_FILE), CAPSULE_MANIFEST)?;
    move_module(&out_dir.join(MODULE_FILE), &bundle.join(MODULE_FILE))?;
    identify(&bundle)
}

/// Run `build_script OUT_DIR` by its path, never through a PATH lookup. Its
/// stderr passes through, and its stdout goes to stderr, so the command's
/// stdout carries only the name.
fn run_build(build_script: &Path, out_dir: &Path) -> Result<(), RunRefusal> {
    let status = Command::new(path_to_run(build_script))
        .arg(out_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(io::stderr()))
        .status()
        .map_err(|error| RunRefusal::new(build_script, Reason::BuildDidNotStart(error)))?;
    if !status.success() {
        return Err(RunRefusal::new(build_script, Reason::BuildFailed(status)));
    }
    Ok(())
}

/// `path` as a program to run by its path: a bare name gets `./`, so the
/// system never looks it up on PATH. The two-engine runner starts each engine
/// through it too.
pub(crate) fn path_to_run(path: &Path) -> PathBuf {
    if path.as_os_str().as_bytes().contains(&b'/') {
        path.to_path_buf()
    } else {
        Path::new(".").join(path)
    }
}

/// Make the new file `path` and write `bytes` into it. `create_new` refuses
/// any entry already at `path`, a link included, so nothing is written into
/// or through it.
pub fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), RunRefusal> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| RunRefusal::new(path, Reason::ManifestNotCreated(error)))?;
    write_all_to(path, &mut file, bytes)
}

/// Write `bytes` to `out`, the new file at `path`.
pub fn write_all_to(path: &Path, out: &mut impl Write, bytes: &[u8]) -> Result<(), RunRefusal> {
    out.write_all(bytes)
        .and_then(|()| out.flush())
        .map_err(|error| RunRefusal::new(path, Reason::ManifestNotWritten(error)))
}

/// Move the module from `from` to `to` with `rename`. A rename moves a
/// folder entry: it reads and writes no file content and never follows a
/// link, so a link at `from` moves as a link and the naming step refuses it.
fn move_module(from: &Path, to: &Path) -> Result<(), RunRefusal> {
    fs::rename(from, to).map_err(|error| RunRefusal::new(from, Reason::ModuleNotMoved(error)))
}
