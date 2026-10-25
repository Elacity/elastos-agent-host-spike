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
//! This is host-side lab tooling. tools/build compiles only the library, so
//! none of this is ever compiled into the capsule.

mod lab_name;

use lab_name::{name_bundle, Refusal, MANIFEST_PATH, MODULE_PATH};
use std::fs;
use std::io;
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

/// Build the capsule with tools/build, write the closure into OUT_DIR/bundle/,
/// and name what is on disk exactly as `--name` would.
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

    let bundle = out_dir.join("bundle");
    fs::create_dir_all(&bundle)
        .map_err(|err| Refusal::new(&bundle, format!("cannot be created ({err})")))?;
    let module = bundle.join(MODULE_PATH);
    fs::copy(out_dir.join(MODULE_PATH), &module)
        .map_err(|err| Refusal::new(&module, format!("cannot be written ({err})")))?;
    let manifest = bundle.join(MANIFEST_PATH);
    fs::write(&manifest, capsule_manifest())
        .map_err(|err| Refusal::new(&manifest, format!("cannot be written ({err})")))?;

    name_bundle(&bundle)
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
