//! The `tools/bundle` command. It only parses, runs, prints and sets the exit
//! status; the rules are in `wasm_capsule_tools::bundle`.
//!
//! - success: the lab CID and a newline on stdout, exit status 0;
//! - an argument refusal: `bundle: <reason>` and the usage line on stderr,
//!   exit status 2;
//! - a run refusal: `bundle: refused: <path>: <reason>` on stderr, exit
//!   status 1.
//!
//! A refusal prints nothing to stdout.

use std::path::Path;
use std::process::ExitCode;
use wasm_capsule_tools::bundle::{parse_args, run, USAGE};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mode = match parse_args(&args) {
        Ok(mode) => mode,
        Err(refusal) => {
            eprintln!("bundle: {refusal}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    // The lane's own tools/build, beside this crate's manifest.
    let build_script = Path::new(env!("CARGO_MANIFEST_DIR")).join("build");
    match run(&mode, &build_script) {
        Ok(name) => {
            println!("{name}");
            ExitCode::SUCCESS
        }
        Err(refusal) => {
            eprintln!("bundle: refused: {refusal}");
            ExitCode::from(1)
        }
    }
}
