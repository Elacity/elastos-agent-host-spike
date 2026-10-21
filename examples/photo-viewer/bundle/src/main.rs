//! `capsule-bundle cid <dir>` prints the closure CID.
//! `capsule-bundle listing <dir>` prints the canonical listing it names.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, dir) = match args.as_slice() {
        [command, dir] => (command.as_str(), std::path::Path::new(dir)),
        _ => usage(),
    };
    let result = match command {
        "cid" => capsule_bundle::closure_cid(dir).map(|(cid, _)| cid),
        "listing" => capsule_bundle::list_closure(dir)
            .map(|entries| String::from_utf8(capsule_bundle::listing_bytes(&entries)).unwrap()),
        _ => usage(),
    };
    match result {
        Ok(out) => println!("{out}"),
        Err(refusal) => {
            eprintln!("refused: {refusal}");
            std::process::exit(1);
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: capsule-bundle cid|listing <capsule-dir>");
    std::process::exit(2);
}
