//! Plant grammar and the one falsifier runner.
//!
//! One file under `plants/` replaces exact text once. Every named test must
//! fail on that mutated source. The original bytes are written back before
//! the next plant and on drop.

use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
struct Plant {
    id: String,
    file: PathBuf,
    tests: Vec<String>,
    old: String,
    new: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Header,
    Old,
    New,
    End,
}

impl Plant {
    fn parse(source: &str, path: &Path) -> Self {
        let mut id = None;
        let mut file = None;
        let mut tests = Vec::new();
        let mut old = Vec::new();
        let mut new = Vec::new();
        let mut section = Section::Header;
        for line in source.lines() {
            match section {
                Section::Header => {
                    if line == "--- old" {
                        section = Section::Old;
                    } else if let Some(value) = line.strip_prefix("id: ") {
                        id = Some(value.trim().to_owned());
                    } else if let Some(value) = line.strip_prefix("file: ") {
                        file = Some(value.trim().to_owned());
                    } else if let Some(value) = line.strip_prefix("test: ") {
                        tests.push(value.trim().to_owned());
                    } else if !line.trim().is_empty() {
                        panic!("plant {}: unexpected header line {line:?}", path.display());
                    }
                }
                Section::Old => {
                    if line == "--- new" {
                        section = Section::New;
                    } else {
                        old.push(line);
                    }
                }
                Section::New => {
                    if line == "--- end" {
                        section = Section::End;
                    } else {
                        new.push(line);
                    }
                }
                Section::End => {
                    if !line.trim().is_empty() {
                        panic!("plant {}: text after --- end", path.display());
                    }
                }
            }
        }

        let id = id.unwrap_or_else(|| panic!("plant {}: missing id", path.display()));
        assert!(
            !id.is_empty() && !id.chars().any(char::is_whitespace),
            "plant {id}: id must be one token"
        );
        let file = file.unwrap_or_else(|| panic!("plant {id}: missing file"));
        assert!(
            Path::new(&file)
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
            "plant {id}: file must be a plain relative path without .."
        );
        assert!(!tests.is_empty(), "plant {id}: missing test");
        assert!(
            tests.iter().all(|test| !test.is_empty()),
            "plant {id}: empty test name"
        );
        assert_eq!(section, Section::End, "plant {id}: missing --- end");

        Self {
            id,
            file: PathBuf::from(file),
            tests,
            old: old.join("\n"),
            new: new.join("\n"),
        }
    }
}

/// Serialises source reads with the plant runner, which rewrites a source file.
pub(crate) fn source_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Runs every plant in file-name order. A catch is a compiled child run whose
/// output line for the named test ends with `FAILED`.
pub(crate) fn run_all() {
    if std::env::var_os("INTENT_PLANNER_PLANT_CHILD").is_some() {
        return;
    }
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let plants_dir = crate_dir.join("plants");
    let mut plants: Vec<PathBuf> = fs::read_dir(&plants_dir)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", plants_dir.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("cannot read a plant entry: {error}"))
                .path()
        })
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("txt"))
        .collect();
    plants.sort();
    assert!(
        !plants.is_empty(),
        "no plants under {}",
        plants_dir.display()
    );

    for path in plants {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let plant = Plant::parse(&source, &path);
        let target = crate_dir.join(&plant.file);
        let original = fs::read_to_string(&target).unwrap_or_else(|error| {
            panic!(
                "plant {}: cannot read {}: {error}",
                plant.id,
                target.display()
            )
        });
        assert_eq!(
            original.matches(&plant.old).count(),
            1,
            "plant {}: old text must occur exactly once in {}",
            plant.id,
            target.display()
        );
        let mut restore = Restore::new(target.clone(), original.clone());
        fs::write(&target, original.replacen(&plant.old, &plant.new, 1)).unwrap_or_else(|error| {
            panic!(
                "plant {}: cannot write {}: {error}",
                plant.id,
                target.display()
            )
        });
        for test in &plant.tests {
            let output = run_test(&crate_dir, &plant.id, test);
            let proof = output.lines().find(|line| {
                let line = line.trim_end();
                line.starts_with("test ")
                    && line.contains(&format!("{test} ... "))
                    && line.ends_with("FAILED")
            });
            assert!(
                proof.is_some(),
                "plant {} was not caught by {test}:\n{output}",
                plant.id
            );
            eprintln!("plant {} caught {}", plant.id, proof.unwrap().trim_end());
        }
        restore.restore();
    }
}

fn run_test(crate_dir: &Path, plant_id: &str, test: &str) -> String {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let manifest = crate_dir.join("Cargo.toml");
    // Reuse this crate's build directory. A private one would compile
    // elastos-server again for every named test.
    let output = Command::new(cargo)
        .current_dir(crate_dir)
        .args(["test", "--lib", "--locked", "--offline", "--manifest-path"])
        .arg(&manifest)
        .arg(test)
        .arg("--")
        .arg("--exact")
        .arg(test)
        .env("INTENT_PLANNER_PLANT_CHILD", "1")
        .env("CARGO_TERM_COLOR", "never")
        .output()
        .unwrap_or_else(|error| panic!("plant {plant_id}: cannot run cargo for {test}: {error}"));
    assert!(
        output.status.code().is_some(),
        "plant {plant_id}: cargo for {test} was killed by a signal"
    );
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

/// Restores the planted file between plants and on drop.
struct Restore {
    path: PathBuf,
    original: String,
    armed: bool,
}

impl Restore {
    fn new(path: PathBuf, original: String) -> Self {
        Self {
            path,
            original,
            armed: true,
        }
    }

    fn restore(&mut self) {
        if self.armed {
            fs::write(&self.path, &self.original)
                .unwrap_or_else(|error| panic!("cannot restore {}: {error}", self.path.display()));
            self.armed = false;
        }
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::write(&self.path, &self.original);
        }
    }
}
