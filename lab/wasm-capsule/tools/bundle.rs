//! The wc-003 lab bundle tool, run as `tools/bundle`:
//!
//!   bundle [OUT_DIR]            build with tools/build, write OUT_DIR/bundle/, print its lab name
//!   bundle --name BUNDLE_DIR    print the lab name of an existing bundle
//!
//! OUT_DIR defaults to the lane root. OUT_DIR/bundle/ holds exactly the
//! closure: `capsule.json` (the lab manifest) and `capsule.wasm` (the module
//! tools/build made). tools/build's own `capsule.wasm` and `receipt.txt` stay in
//! OUT_DIR, outside the closure. stdout carries only the name; a refusal goes to
//! stderr with its path and reason, and the exit status is 1.
//!
//! The build mode writes a new bundle only: anything already at OUT_DIR/bundle,
//! a link included, is refused before a byte is written, so no write ever goes
//! through a link. To bundle again into the same OUT_DIR, remove its bundle/.
//!
//! This is host-side lab tooling. tools/build compiles only the library, so
//! none of this is ever compiled into the capsule.

mod lab_name;

use lab_name::{
    name_bundle, no_seam, open_regular, read_file, ClosureFile, Refusal, MANIFEST_PATH, MODULE_PATH,
};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The schema id that marks `capsule.json` as a lab manifest, not a Runtime
/// capsule manifest.
const MANIFEST_SCHEMA: &str = "wc-003.lab-manifest/v1";

/// The capsule's linear-memory ceiling in Wasm pages of 65,536 bytes. 16 pages
/// (1 MiB) is the initial memory the wc-001 module declares; it never grows.
/// Declared only: nothing in wc-003 enforces it.
const MAX_MEMORY_PAGES: u32 = 16;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let named = match args.as_slice() {
        [] => build_bundle(&lane_dir()),
        [flag, dir] if flag == "--name" => name_bundle(Path::new(dir)),
        [out_dir] if !out_dir.starts_with('-') => build_bundle(Path::new(out_dir)),
        _ => {
            eprintln!("usage: tools/bundle [OUT_DIR] | tools/bundle --name BUNDLE_DIR");
            std::process::exit(2);
        }
    };
    match named {
        Ok(name) => println!("{name}"),
        Err(refusal) => {
            eprintln!("bundle: refused: {refusal}");
            std::process::exit(1);
        }
    }
}

/// The lane root, where tools/build lives.
fn lane_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Build the capsule with tools/build, write the closure as a new
/// OUT_DIR/bundle/, and name what is on disk exactly as `--name` would.
fn build_bundle(out_dir: &Path) -> Result<String, Refusal> {
    // The lane's one reproducible build (wc-001). Its progress line goes to
    // stderr, so stdout carries only the name.
    let status = Command::new("bash")
        .arg(lane_dir().join("tools").join("build"))
        .arg(out_dir)
        .stdout(Stdio::from(io::stderr()))
        .status()
        .map_err(|err| Refusal::new(out_dir, format!("tools/build did not start ({err})")))?;
    if !status.success() {
        return Err(Refusal::new(
            out_dir,
            format!("tools/build did not build the capsule ({status})"),
        ));
    }

    // The module tools/build wrote, read through the lab's one check.
    let module = read_file(&out_dir.join(MODULE_PATH), &mut no_seam)?;
    let bundle = out_dir.join("bundle");
    write_new_bundle(
        &bundle,
        &[
            ClosureFile {
                path: MANIFEST_PATH.to_string(),
                bytes: capsule_manifest().into_bytes(),
            },
            ClosureFile {
                path: MODULE_PATH.to_string(),
                bytes: module,
            },
        ],
    )?;

    name_bundle(&bundle)
}

/// Write `files` as a new bundle directory at `bundle`. The directory is
/// created new, and `mkdir` never follows a link, so anything already at
/// `bundle` (a link, a file or a directory) is refused before a byte is
/// written. Each file is then created new through the lab's one check,
/// `open_regular`, so nothing is ever written into or through a file that was
/// there before.
fn write_new_bundle(bundle: &Path, files: &[ClosureFile]) -> Result<(), Refusal> {
    fs::create_dir(bundle).map_err(|err| {
        if err.kind() == io::ErrorKind::AlreadyExists {
            Refusal::new(
                bundle,
                "already exists (tools/bundle writes a new bundle, never into or through what is already there)",
            )
        } else {
            Refusal::new(bundle, format!("cannot be created ({err})"))
        }
    })?;
    for file in files {
        let path = bundle.join(&file.path);
        open_regular(&path, OpenOptions::new().write(true).create_new(true))?
            .write_all(&file.bytes)
            .map_err(|err| Refusal::new(&path, format!("cannot be written ({err})")))?;
    }
    Ok(())
}

/// The lab manifest of this lane's capsule, in its one byte layout (fixed key
/// order, two-space indent, LF line ends), so the same capsule always gives the
/// same manifest bytes. README.md defines each field. `name` and `version` are
/// the Cargo package's, so they have one source.
fn capsule_manifest() -> String {
    format!(
        concat!(
            "{{\n",
            "  \"schema\": \"{schema}\",\n",
            "  \"name\": \"{name}\",\n",
            "  \"version\": \"{version}\",\n",
            "  \"entrypoint\": \"{entrypoint}\",\n",
            "  \"imports\": [],\n",
            "  \"resources\": {{ \"max_memory_pages\": {pages} }}\n",
            "}}\n",
        ),
        schema = MANIFEST_SCHEMA,
        name = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION"),
        entrypoint = MODULE_PATH,
        pages = MAX_MEMORY_PAGES,
    )
}
