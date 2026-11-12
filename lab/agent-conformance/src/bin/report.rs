use agent_conformance::{build, report};
use std::{env, fs, path::Path, process};

fn main() {
    let args: Vec<_> = env::args_os().collect();
    if args.len() == 2 && args[1] == "--check-earlier-runs" {
        match agent_conformance::census::earlier_runs() {
            Ok(holders) if holders.is_empty() => return,
            Ok(holders) => {
                let owners: std::collections::BTreeSet<_> = holders
                    .iter()
                    .map(|holder| (holder.pid, &holder.root))
                    .collect();
                for (pid, root) in owners {
                    eprintln!("earlier run: PID {pid} root {root:?}");
                }
                eprintln!("earlier-run check: FAIL; live processes hold earlier Homes; inspect and stop their owners by hand before retrying");
            }
            Err(reason) => eprintln!("earlier-run check: FAIL; {reason}"),
        }
        process::exit(1);
    }
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
    let gaps = fs::read_to_string(build::lane().join("GAPS.md")).ok();
    let receipt = Path::new(&args[4]);
    // Reviews name the commit they read, so they live outside that commit.
    let reviews = match env::var_os("AGENT_CONFORMANCE_REVIEWS") {
        None => None,
        Some(path) => match fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Vec<report::Review>>(&bytes).ok())
        {
            Some(reviews) => Some(reviews),
            None => {
                eprintln!("versions receipt failure: could not read reviews");
                process::exit(1);
            }
        },
    };
    // An installed Runtime is named by its binary and its data folder, because
    // the installer can put the binary elsewhere. Neither given means no
    // installed Runtime; there is no default, so a test never reads a real one.
    let installed = match (
        env::var_os("AGENT_CONFORMANCE_INSTALLED_BINARY"),
        env::var_os("AGENT_CONFORMANCE_INSTALLED_DATA"),
    ) {
        (None, None) => None,
        (Some(binary), Some(data)) => Some(report::read_installed_runtime(
            Path::new(&binary),
            Path::new(&data),
            report::release_platform(),
        )),
        _ => {
            eprintln!("versions receipt failure: an installed Runtime needs both its binary and its data folder");
            process::exit(1);
        }
    };
    let result = report::write_bound_run(
        &listed,
        &output,
        inputs_ok && args[3] == "0",
        report::GitIdentity::read(&build::repository()),
        report::Bound {
            reviews: reviews.as_deref(),
            installed,
        },
        receipt,
        gaps.as_deref(),
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

#[test]
fn earlier_run_check_refuses_live_owner() {
    use agent_conformance::{census::earlier_runs, harness::ThrowawayHome};
    let home = ThrowawayHome::new().unwrap();
    let mut child = home.start(Path::new("/bin/sleep"), &["20"]).unwrap();
    let started = std::time::Instant::now();
    let holders = earlier_runs().unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert!(holders
        .iter()
        .any(|h| h.pid == child.pgid()
            && h.root == home.root().file_name().unwrap().to_str().unwrap()));
    assert!(
        child.is_alive().unwrap(),
        "the earlier-run check only observes"
    );
    child.stop().unwrap();
    drop(child);
    let holders = earlier_runs().unwrap();
    assert!(holders
        .iter()
        .all(|h| h.root != home.root().file_name().unwrap().to_str().unwrap()));
    home.finish().unwrap();
}
