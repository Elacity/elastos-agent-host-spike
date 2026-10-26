use agent_conformance::{build, report};
use std::{env, fs, path::Path, process};

fn main() {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 5 {
        eprintln!(
            "versions receipt failure: expected inventory, results, Cargo status and receipt path"
        );
        process::exit(1);
    }
    let mut inputs_ok = true;
    let mut read = |path, label| {
        fs::read_to_string(path).unwrap_or_else(|_| {
            eprintln!("versions receipt failure: could not read Cargo {label}");
            inputs_ok = false;
            String::new()
        })
    };
    let listed = read(&args[1], "inventory");
    let output = read(&args[2], "results");
    let receipt = Path::new(&args[4]);
    let result = report::write_run(
        &listed,
        &output,
        inputs_ok && args[3] == "0",
        report::GitIdentity::read(&build::repository()),
        receipt,
    );
    print!("{}", result.table);
    if result.receipt_written {
        match receipt.strip_prefix(build::lane()) {
            Ok(relative) => println!("versions receipt: {}", relative.display()),
            Err(_) => println!("versions receipt: {}", receipt.display()),
        }
    }
    for reason in &result.failures {
        eprintln!("versions receipt failure: {reason}");
    }
    if !result.passed {
        process::exit(1);
    }
}
