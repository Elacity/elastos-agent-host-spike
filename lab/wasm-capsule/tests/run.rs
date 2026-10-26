//! wc-005a: the runner, `wasm_capsule_tools::run::run_engine` (PRINCIPLES P3,
//! P10, P11, P18). It runs one host engine on a verified bundle's entrypoint
//! bytes, written from memory into a new private folder, with a fixed argv.
//!
//! The stand-in engines are small shell scripts written into each test's own
//! temp dir. One test starts the real `wasmtime` and `wasmer`; an engine it
//! cannot find is reported SKIPPED, never PASS. Every test key is made fresh in
//! memory inside its test and never written. The tests share one process, so
//! none changes process-wide state (env, working folder, limits).

mod common;

use capsule::{FIXED_INPUT, FIXED_OUTPUT};
use capsule_identity::sign_bundle;
use common::build::{lane_dir, run_build, TempDir};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use wasm_capsule_tools::bundle::{Reason as WriteReason, RunRefusal as WriteRefusal};
use wasm_capsule_tools::run::{
    module_refusal, run_engine, Engine, Reason, Refusal, DIGEST_ARGUMENT, DIGEST_EXPORT,
};
use wasm_capsule_tools::verify::{verify_bundle, VerifiedBundle};
use wasm_capsule_tools::CAPSULE_MANIFEST;

/// The smallest core Wasm module: the magic and version 1, no sections.
const MODULE: &[u8] = b"\0asm\x01\0\0\0";

/// Other bytes put at the bundle's `capsule.wasm` after verification.
const CHANGED_MODULE: &[u8] = b"\0asm\x01\0\0\0\0\x01\x00";

/// Both engines, in a fixed order.
const ENGINES: [Engine; 2] = [Engine::Wasmtime, Engine::Wasmer];

/// A stand-in engine that prints the bytes of the module it was given (its
/// fourth argument).
const CAT_MODULE: &str = "#!/bin/sh\ncat \"$4\"\n";

/// A stand-in engine that prints each argument on its own line.
const PRINT_ARGS: &str = "#!/bin/sh\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\"; done\n";

/// A stand-in engine that prints whether `HOME` reached it.
const PRINT_HOME: &str = "#!/bin/sh\nprintf '%s' \"${HOME-unset}\"\n";

/// A stand-in engine that fails with a message on stderr.
const FAILING: &str = "#!/bin/sh\nprintf 'boom: bad module\\n' >&2\nexit 3\n";

/// The macOS texts of the OS errors the tests meet.
const NOT_FOUND: &str = "No such file or directory (os error 2)";
const DENIED: &str = "Permission denied (os error 13)";

fn fresh_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// The test's temp dir by its canonical path: on macOS the temp dir sits under
/// the `/var` link, which the runner refuses.
fn canonical(tmp: &TempDir) -> PathBuf {
    fs::canonicalize(tmp.path()).expect("canonicalize the temp dir")
}

/// A new folder `name` in `root` holding this capsule's manifest and `module`
/// as `capsule.wasm`, signed with a fresh key and verified.
fn verified_bundle(root: &Path, name: &str, module: &[u8]) -> (PathBuf, VerifiedBundle) {
    let bundle = root.join(name);
    fs::create_dir(&bundle).expect("create the bundle folder");
    fs::write(bundle.join("capsule.json"), CAPSULE_MANIFEST).expect("write capsule.json");
    fs::write(bundle.join("capsule.wasm"), module).expect("write capsule.wasm");
    let key = fresh_key();
    let sig = sign_bundle(&key, &bundle).expect("sign the bundle");
    let accepted = [elastos_identity::encode_signing_key_did(&key)];
    let value = verify_bundle(&bundle, Some(&sig), &accepted, &[])
        .unwrap_or_else(|refusal| panic!("the verifier refused: {refusal}"));
    (bundle, value)
}

/// The fixture bundle in its own temp dir, outside every work root.
fn fixture() -> (TempDir, VerifiedBundle) {
    let tmp = TempDir::new("run-fixture");
    let (_, value) = verified_bundle(&canonical(&tmp), "bundle", MODULE);
    (tmp, value)
}

/// Write the stand-in engine `name` into `folder` and make it runnable.
fn stand_in(folder: &Path, name: &str, script: &str) -> PathBuf {
    let path = folder.join(name);
    fs::write(&path, script).expect("write a stand-in engine");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("make it runnable");
    path
}

/// A stand-in engine that leaves `marker` behind if it is ever started.
fn marking(folder: &Path, marker: &Path) -> PathBuf {
    let script = format!("#!/bin/sh\n: > '{}'\n", marker.display());
    stand_in(folder, "marking", &script)
}

/// The names in `folder`, sorted.
fn names(folder: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(folder)
        .expect("list a folder")
        .map(|entry| {
            entry
                .expect("read an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn ran(result: Result<Vec<u8>, Refusal>) -> Vec<u8> {
    result.unwrap_or_else(|refusal| panic!("the runner refused: {refusal}"))
}

fn refused(result: Result<Vec<u8>, Refusal>) -> Refusal {
    match result {
        Ok(stdout) => panic!(
            "the runner ran, stdout {:?}, not a refusal",
            String::from_utf8_lossy(&stdout)
        ),
        Err(refusal) => refusal,
    }
}

/// `text` without its whole-line `//` comments.
fn without_comments(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The runner's module, without its whole-line comments.
fn runner_code() -> String {
    without_comments(include_str!("../tools/src/run.rs"))
}

#[test]
fn run_writes_only_the_verified_entrypoint_bytes() {
    let engines = TempDir::new("run-bytes-engines");
    let engine = stand_in(&canonical(&engines), "cat", CAT_MODULE);
    let tmp = TempDir::new("run-bytes");
    let root = canonical(&tmp);
    let (bundle, value) = verified_bundle(&root, "bundle", MODULE);
    assert_eq!(value.entrypoint().content, MODULE);
    fs::write(bundle.join("capsule.wasm"), CHANGED_MODULE).expect("change capsule.wasm");

    let stdout = ran(run_engine(&value, Engine::Wasmtime, &engine, &root));
    assert_eq!(
        stdout, MODULE,
        "the engine did not get the verified entrypoint bytes"
    );
    let run_dir = root.join("wasmtime");
    assert_eq!(names(&run_dir), ["module.wasm"], "the run folder");
    assert_eq!(
        fs::read(run_dir.join("module.wasm")).expect("read the module"),
        MODULE
    );
    assert_eq!(
        names(&root),
        ["bundle", "wasmtime"],
        "something was written outside the run folder"
    );
    assert_eq!(names(&bundle), ["capsule.json", "capsule.wasm"]);
}

#[test]
fn engine_path_must_be_absolute() {
    let (_bundle, value) = fixture();
    let tmp = TempDir::new("run-relative-engine");
    let root = canonical(&tmp);
    for program in ["./wasmtime", "wasmtime", "engines/wasmtime"] {
        let refusal = refused(run_engine(
            &value,
            Engine::Wasmtime,
            Path::new(program),
            &root,
        ));
        assert!(
            matches!(refusal.reason, Reason::EngineNotAbsolute),
            "{program}: {refusal}"
        );
        assert_eq!(
            refusal.to_string(),
            format!(
                "{program}: the engine program path is not absolute: an engine is started only by an absolute path"
            )
        );
        assert!(names(&root).is_empty(), "{program}: something was written");
    }
}

#[test]
fn work_root_must_be_absolute_and_canonical() {
    let (_bundle, value) = fixture();
    let tmp = TempDir::new("run-work-root");
    let base = canonical(&tmp);
    let marker = base.join("started");
    let engine = marking(&base, &marker);
    let real = base.join("real");
    fs::create_dir(&real).expect("create a folder");
    let link = base.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("plant a folder link");

    for root in ["work", "--env=X", "./work"] {
        let refusal = refused(run_engine(&value, Engine::Wasmer, &engine, Path::new(root)));
        assert!(
            matches!(refusal.reason, Reason::WorkRootNotAbsolute),
            "{root}: {refusal}"
        );
        assert_eq!(
            refusal.to_string(),
            format!("{root}: the work root is not an absolute path")
        );
        assert!(!lane_dir().join(root).exists(), "{root} was made");
    }
    assert!(!lane_dir().join("wasmer").exists(), "a run folder was made");

    let not_canonical = [
        (link.clone(), "a folder link"),
        (link.join("."), "a link and a dot"),
        (base.join("real").join("..").join("real"), "a dot-dot"),
        (
            PathBuf::from(format!("{}/", real.display())),
            "a trailing /",
        ),
    ];
    for (root, kind) in not_canonical {
        let refusal = refused(run_engine(&value, Engine::Wasmer, &engine, &root));
        match &refusal.reason {
            Reason::WorkRootNotCanonical { canonical } => assert_eq!(canonical, &real, "{kind}"),
            _ => panic!("{kind}: {refusal}"),
        }
        assert_eq!(
            refusal.to_string(),
            format!(
                "{}: the work root is not canonical: it resolves to {}",
                root.display(),
                real.display()
            ),
            "{kind}"
        );
        assert!(names(&real).is_empty(), "{kind}: something was written");
    }
    assert!(!marker.exists(), "an engine was started");
    assert_eq!(names(&base), ["link", "marking", "real"]);
}

#[test]
fn run_directory_is_private_and_new() {
    let (_bundle, value) = fixture();
    let engines = TempDir::new("run-private-engines");
    let engines = canonical(&engines);
    let cat = stand_in(&engines, "cat", CAT_MODULE);
    let tmp = TempDir::new("run-private");
    let root = canonical(&tmp);

    ran(run_engine(&value, Engine::Wasmtime, &cat, &root));
    let mode = fs::metadata(root.join("wasmtime"))
        .expect("the run folder")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "the run folder is not private");

    // A second run in the same root, and a folder planted at a run folder's
    // name: each is refused, the folder is never reused, no engine starts.
    let marker = engines.join("started");
    let engine = marking(&engines, &marker);
    let planted = root.join("wasmer");
    fs::create_dir(&planted).expect("plant a folder");
    for (engine_kind, run_dir) in [
        (Engine::Wasmtime, root.join("wasmtime")),
        (Engine::Wasmer, planted.clone()),
    ] {
        let before = names(&run_dir);
        let refusal = refused(run_engine(&value, engine_kind, &engine, &root));
        assert!(
            matches!(refusal.reason, Reason::RunDirExists),
            "{engine_kind}: {refusal}"
        );
        assert_eq!(
            refusal.to_string(),
            format!(
                "{}: the run folder already exists: the runner makes a new one and never reuses it",
                run_dir.display()
            )
        );
        assert_eq!(names(&run_dir), before, "{engine_kind}: the folder changed");
    }
    assert!(!marker.exists(), "an engine was started");
}

#[test]
fn runner_io_refusals_keep_path_and_cause() {
    let (_bundle, value) = fixture();
    let tmp = TempDir::new("run-io");
    let base = canonical(&tmp);
    let marker = base.join("started");
    let engine = marking(&base, &marker);

    // The work root cannot be resolved.
    let missing = base.join("missing");
    let refusal = refused(run_engine(&value, Engine::Wasmtime, &engine, &missing));
    match &refusal.reason {
        Reason::WorkRootUnresolved(error) => assert_eq!(error.kind(), io::ErrorKind::NotFound),
        _ => panic!("{refusal}"),
    }
    assert_eq!(refusal.path, missing);
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: the work root cannot be resolved: {NOT_FOUND}",
            missing.display()
        )
    );

    // The work root is a file.
    let file = base.join("file");
    fs::write(&file, b"not a folder").expect("write a file");
    let refusal = refused(run_engine(&value, Engine::Wasmtime, &engine, &file));
    assert!(
        matches!(refusal.reason, Reason::WorkRootNotAFolder),
        "{refusal}"
    );
    assert_eq!(
        refusal.to_string(),
        format!("{}: the work root is not a folder", file.display())
    );

    // The run folder cannot be made in a work root the user may not write.
    let locked = base.join("locked");
    fs::create_dir(&locked).expect("create a folder");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).expect("lock it");
    let result = run_engine(&value, Engine::Wasmtime, &engine, &locked);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).expect("unlock it");
    let refusal = refused(result);
    let run_dir = locked.join("wasmtime");
    match &refusal.reason {
        Reason::RunDirNotCreated(error) => {
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied)
        }
        _ => panic!("{refusal}"),
    }
    assert_eq!(refusal.path, run_dir);
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: the run folder cannot be created: {DENIED}",
            run_dir.display()
        )
    );
    assert!(names(&locked).is_empty());
    assert!(!marker.exists(), "an engine was started");

    // The shared writer's refusals, as the runner's own: the module file
    // cannot be made new, or cannot be written, each with its path and cause;
    // any other writer reason is carried unchanged.
    let module = base.join("wasmtime").join("module.wasm");
    let writer = |reason| WriteRefusal {
        path: module.clone(),
        reason,
    };
    let created = module_refusal(writer(WriteReason::ManifestNotCreated(
        io::Error::from_raw_os_error(17),
    )));
    assert!(
        matches!(&created.reason, Reason::ModuleNotCreated(error) if error.raw_os_error() == Some(17)),
        "{created}"
    );
    assert_eq!(created.path, module);
    assert_eq!(
        created.to_string(),
        format!(
            "{}: the verified entrypoint cannot be created: File exists (os error 17)",
            module.display()
        )
    );
    let written = module_refusal(writer(WriteReason::ManifestNotWritten(
        io::Error::from_raw_os_error(28),
    )));
    assert!(
        matches!(&written.reason, Reason::ModuleNotWritten(error) if error.raw_os_error() == Some(28)),
        "{written}"
    );
    assert_eq!(written.path, module);
    assert_eq!(
        written.to_string(),
        format!(
            "{}: the verified entrypoint cannot be written: No space left on device (os error 28)",
            module.display()
        )
    );
    let other = module_refusal(writer(WriteReason::OutDirExists));
    assert!(
        matches!(&other.reason, Reason::Writer(WriteReason::OutDirExists)),
        "{other}"
    );
    assert_eq!(
        other.to_string(),
        format!(
            "{}: the shared writer refused: {}",
            module.display(),
            WriteReason::OutDirExists
        )
    );
}

/// An **argv proof**, not a behaviour proof: it shows the exact command line
/// each engine gets, and that it carries no folder, env or network flag.
#[test]
fn runner_passes_no_directory_env_or_network_flags() {
    let (_bundle, value) = fixture();
    let engines = TempDir::new("run-argv-engines");
    let engine = stand_in(&canonical(&engines), "print-args", PRINT_ARGS);
    let tmp = TempDir::new("run-argv");
    let root = canonical(&tmp);
    assert_eq!(DIGEST_EXPORT, "digest");
    assert_eq!(DIGEST_ARGUMENT, FIXED_INPUT.to_string());
    assert_eq!(DIGEST_ARGUMENT, "1592590337");

    for engine_kind in ENGINES {
        let stdout = ran(run_engine(&value, engine_kind, &engine, &root));
        let module = root.join(engine_kind.name()).join("module.wasm");
        let argv = String::from_utf8(stdout).expect("the argv is UTF-8");
        assert_eq!(
            argv,
            format!("run\n--invoke\ndigest\n{}\n1592590337\n", module.display()),
            "{engine_kind}: the argv"
        );
        let module_argument = argv.lines().nth(3).expect("the module argument");
        assert!(
            module_argument.starts_with('/'),
            "{engine_kind}: the module argument could be read as an option"
        );
        for flag in ["--dir", "--mapdir", "--env", "--net", "-e", "--volume"] {
            assert!(
                !argv.lines().any(|arg| arg.starts_with(flag)),
                "{engine_kind}: the argv carries {flag}"
            );
        }
    }
}

#[test]
fn engine_starts_with_an_empty_environment() {
    let (_bundle, value) = fixture();
    let engines = TempDir::new("run-env-engines");
    let engine = stand_in(&canonical(&engines), "print-home", PRINT_HOME);
    let tmp = TempDir::new("run-env");
    let root = canonical(&tmp);
    assert!(
        std::env::var_os("HOME").is_some(),
        "the test process has no HOME, so this test proves nothing"
    );

    let stdout = ran(run_engine(&value, Engine::Wasmer, &engine, &root));
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        "unset",
        "the engine got the test process's environment"
    );
}

#[test]
fn engine_failures_keep_their_cause() {
    let (_bundle, value) = fixture();
    let engines = TempDir::new("run-fail-engines");
    let engines = canonical(&engines);
    let failing = stand_in(&engines, "failing", FAILING);

    for engine_kind in ENGINES {
        let tmp = TempDir::new("run-fail");
        let root = canonical(&tmp);
        let refusal = refused(run_engine(&value, engine_kind, &failing, &root));
        match &refusal.reason {
            Reason::EngineFailed {
                engine,
                status,
                stderr,
            } => {
                assert_eq!(*engine, engine_kind);
                assert_eq!(status.code(), Some(3));
                assert_eq!(stderr, "boom: bad module\n");
            }
            _ => panic!("{engine_kind}: {refusal}"),
        }
        assert_eq!(refusal.path, failing);
        assert_eq!(
            refusal.to_string(),
            format!(
                "{}: {engine_kind} failed (exit status: 3): boom: bad module",
                failing.display()
            )
        );
    }

    let missing = engines.join("no-such-engine");
    for engine_kind in ENGINES {
        let tmp = TempDir::new("run-missing-engine");
        let root = canonical(&tmp);
        let refusal = refused(run_engine(&value, engine_kind, &missing, &root));
        match &refusal.reason {
            Reason::EngineDidNotStart { engine, error } => {
                assert_eq!(*engine, engine_kind);
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
            }
            _ => panic!("{engine_kind}: {refusal}"),
        }
        assert_eq!(refusal.path, missing);
        assert_eq!(
            refusal.to_string(),
            format!(
                "{}: {engine_kind} did not start: {NOT_FOUND}",
                missing.display()
            )
        );
    }
}

/// The first `name` on the test process's PATH, by an absolute path.
fn find_engine(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|folder| folder.is_absolute())
        .map(|folder| folder.join(name))
        .find(|candidate| candidate.is_file())
}

#[test]
fn each_engine_prints_the_fixed_output() {
    let tmp = TempDir::new("run-real");
    let root = canonical(&tmp);
    let out = root.join("out");
    fs::create_dir(&out).expect("create OUT_DIR");
    run_build(&lane_dir(), &out);
    let built = fs::read(out.join("capsule.wasm")).expect("read the built capsule.wasm");
    let (_, value) = verified_bundle(&root, "bundle", &built);
    let work = root.join("work");
    fs::create_dir(&work).expect("create the work root");

    let mut ran_any = false;
    for engine_kind in ENGINES {
        let Some(program) = find_engine(engine_kind.name()) else {
            eprintln!("SKIPPED: {engine_kind} not found on PATH (no result, not a PASS)");
            continue;
        };
        let stdout = ran(run_engine(&value, engine_kind, &program, &work));
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            format!("{FIXED_OUTPUT}\n"),
            "{engine_kind} ({}) did not print FIXED_OUTPUT for FIXED_INPUT",
            program.display()
        );
        eprintln!("PASS: {engine_kind} printed {FIXED_OUTPUT} for {FIXED_INPUT}");
        ran_any = true;
    }
    if !ran_any {
        eprintln!("SKIPPED: no engine found; this test proves nothing here");
    }
}

#[test]
fn runner_uses_only_explicit_inputs() {
    let code = runner_code();
    // Built at run time, so this file does not match itself.
    let forbidden = [
        ["env", "::var"].concat(),
        ["var", "_os"].concat(),
        ["env", "!("].concat(),
        ["std::", "env"].concat(),
        ["current", "_dir"].concat(),
        ["home", "_dir"].concat(),
        ["fs::", "read"].concat(),
        ["File::", "open"].concat(),
        ["read_to", "_end"].concat(),
        ["read_to", "_string"].concat(),
        ["include", "_bytes"].concat(),
        ["serde", "_json"].concat(),
        ["Capsule", "Manifest"].concat(),
        ["from", "_slice"].concat(),
        ["wasm_capsule", "_audit"].concat(),
        ["checked", "_bundle"].concat(),
        ["verify", "_bundle("].concat(),
        ["verify", "_checked("].concat(),
        ["entries", "()"].concat(),
    ];
    for needle in &forbidden {
        assert!(
            !code.contains(needle.as_str()),
            "the runner reaches past its explicit inputs: {needle}"
        );
    }
    assert_eq!(
        code.matches(".entrypoint()").count(),
        1,
        "the runner takes the module bytes from entrypoint() once"
    );
}

#[test]
fn runner_reuses_shared_writer() {
    let code = runner_code();
    assert_eq!(
        code.matches("write_new_file(").count(),
        1,
        "the runner writes the module through the shared writer once"
    );
    assert!(code.contains("use crate::bundle::{write_new_file,"));
    // Built at run time, so this file does not match itself.
    let writers = [
        ["Open", "Options"].concat(),
        ["File::", "create"].concat(),
        ["fs::", "write"].concat(),
        ["create", "_new"].concat(),
        ["write", "_all"].concat(),
        ["fs::", "copy"].concat(),
        ["fs::", "rename"].concat(),
        ["hard", "_link"].concat(),
        ["sym", "link"].concat(),
    ];
    for writer in &writers {
        assert!(
            !code.contains(writer.as_str()),
            "the runner writes a file without the shared writer: {writer}"
        );
    }
}
