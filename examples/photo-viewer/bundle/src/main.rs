//! `capsule-bundle cid <dir>` prints the closure CID.
//! `capsule-bundle listing <dir>` prints the canonical listing it names.
//! `capsule-bundle pack <source> <into> [--require <name>=<cid> ...]` packs the
//! closure a capsule ships into a new folder, and prints its CID.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [command, dir] if command == "cid" => {
            capsule_bundle::closure_cid(std::path::Path::new(dir)).map(|(cid, _)| cid)
        }
        [command, dir] if command == "listing" => {
            capsule_bundle::list_closure(std::path::Path::new(dir))
                .map(|entries| String::from_utf8(capsule_bundle::listing_bytes(&entries)).unwrap())
        }
        [command, source, into, rest @ ..] if command == "pack" => {
            let mut requires = Vec::new();
            let mut rest = rest.iter();
            while let Some(flag) = rest.next() {
                match (
                    flag.as_str(),
                    rest.next().and_then(|value| value.split_once('=')),
                ) {
                    ("--require", Some((name, cid))) => {
                        requires.push((name.to_string(), cid.to_string()))
                    }
                    _ => usage(),
                }
            }
            capsule_bundle::pack(
                std::path::Path::new(source),
                std::path::Path::new(into),
                &requires,
            )
            .map(|(cid, _)| cid)
        }
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
    eprintln!("       capsule-bundle pack <source> <into> [--require <name>=<cid> ...]");
    std::process::exit(2);
}
