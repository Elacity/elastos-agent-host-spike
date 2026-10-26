//! wc-005a: the runner, `wasm_capsule_tools::run::run_engine` (PRINCIPLES P3,
//! P10, P11, P18). It runs one host engine on a verified bundle's entrypoint
//! bytes, written from memory into a new private folder, with a fixed argv.
//!
//! wc-005b: the two-engine runner, `wasm_capsule_tools::run::run`. It calls
//! `verify_bundle` once, then `run_engine` for `wasmtime` and then for
//! `wasmer`, and requires both to succeed with byte-identical stdout.
//!
//! wc-005c: before the module runs, `run` asks each engine `--version` and
//! keeps the first line it printed; `wasm_capsule_tools::receipt` renders the
//! run's receipt and writes it only through the shared new-file writer.
//!
//! The stand-in engines are small shell scripts written into each test's own
//! temp dir. Every stand-in the two-engine runner starts answers `--version`
//! on its own branch, apart from its module run. The real-engine tests start
//! the real `wasmtime` and `wasmer`; an engine they cannot find is reported
//! SKIPPED, never PASS. Every test key is made fresh in
//! memory inside its test and never written. The tests share one process, so
//! none changes process-wide state (env, working folder, limits).

mod common;

use capsule::{FIXED_INPUT, FIXED_OUTPUT};
use capsule_identity::{sign_bundle, LabCid, NameSignature};
use common::build::{lane_dir, run_build, TempDir};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use wasm_capsule_tools::bundle::{
    write_new_file, Reason as WriteReason, RunRefusal as WriteRefusal,
};
use wasm_capsule_tools::receipt::{render, write_receipt, RECEIPT_SCHEMA};
use wasm_capsule_tools::run::{
    module_refusal, run, run_engine, work_root_folder, Engine, EngineRun, Reason, Refusal,
    RunInput, TwoEngineRefusal, TwoEngineRun, DIGEST_ARGUMENT, DIGEST_EXPORT,
};
use wasm_capsule_tools::verify::{verify_bundle, VerifiedBundle, VerifyRefusal};
use wasm_capsule_tools::{bundle_identity, CAPSULE_MANIFEST};

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

/// A stand-in engine that prints whether its stdin is `/dev/null`.
const PRINT_STDIN: &str =
    "#!/bin/sh\nif [ /dev/stdin -ef /dev/null ]; then printf null; else printf other; fi\n";

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

fn did(key: &SigningKey) -> String {
    elastos_identity::encode_signing_key_did(key)
}

/// A new folder `name` in `root` holding this capsule's manifest and `module`
/// as `capsule.wasm`, signed in memory with `key`.
fn signed_bundle(
    root: &Path,
    name: &str,
    module: &[u8],
    key: &SigningKey,
) -> (PathBuf, NameSignature) {
    let bundle = root.join(name);
    fs::create_dir(&bundle).expect("create the bundle folder");
    fs::write(bundle.join("capsule.json"), CAPSULE_MANIFEST).expect("write capsule.json");
    fs::write(bundle.join("capsule.wasm"), module).expect("write capsule.wasm");
    let sig = sign_bundle(key, &bundle).expect("sign the bundle");
    (bundle, sig)
}

/// A new folder `name` in `root` holding this capsule's manifest and `module`
/// as `capsule.wasm`, signed with a fresh key and verified.
fn verified_bundle(root: &Path, name: &str, module: &[u8]) -> (PathBuf, VerifiedBundle) {
    let key = fresh_key();
    let (bundle, sig) = signed_bundle(root, name, module, &key);
    let value = verify_bundle(&bundle, Some(&sig), &[did(&key)], &[])
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

/// A run's stdout; it exited 0, the only status `run_engine` returns.
fn ran(result: Result<EngineRun, Refusal>) -> Vec<u8> {
    let run = result.unwrap_or_else(|refusal| panic!("the runner refused: {refusal}"));
    assert_eq!(run.status.code(), Some(0), "a run that did not exit 0");
    run.stdout
}

fn refused(result: Result<EngineRun, Refusal>) -> Refusal {
    match result {
        Ok(run) => panic!(
            "the runner ran, stdout {:?}, not a refusal",
            String::from_utf8_lossy(&run.stdout)
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

    // The work root resolved, then its metadata could not be read: the OS
    // cause is kept, never reported as "not a folder". A real lookup cannot be
    // made to fail between the two calls without a race, so the step is called
    // on a failed lookup directly, and the runner is checked to call it on the
    // canonical path's own metadata, with no second folder check.
    let refusal = work_root_folder(&base, Err(io::Error::from_raw_os_error(13)))
        .expect_err("a failed metadata read was accepted");
    match &refusal.reason {
        Reason::WorkRootMetadataFailed(error) => assert_eq!(error.raw_os_error(), Some(13)),
        _ => panic!("{refusal}"),
    }
    assert_eq!(refusal.path, base);
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: the work root's metadata cannot be read: {DENIED}",
            base.display()
        )
    );
    assert!(work_root_folder(&base, fs::metadata(&base)).is_ok());
    let code = runner_code();
    assert_eq!(
        code.matches("work_root_folder(work_root, fs::metadata(&canonical))")
            .count(),
        1,
        "the runner does not check the work root's own metadata through work_root_folder"
    );
    assert_eq!(
        code.matches("is_dir()").count(),
        1,
        "the runner checks for a folder outside work_root_folder"
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
fn engine_stdin_is_null() {
    let (_bundle, value) = fixture();
    let engines = TempDir::new("run-stdin-engines");
    let engine = stand_in(&canonical(&engines), "print-stdin", PRINT_STDIN);

    for engine_kind in ENGINES {
        let tmp = TempDir::new("run-stdin");
        let root = canonical(&tmp);
        let stdout = ran(run_engine(&value, engine_kind, &engine, &root));
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "null",
            "{engine_kind}: the engine's stdin is not /dev/null"
        );
    }
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
        ["verify", "_checked("].concat(),
        ["entries", "()"].concat(),
    ];
    for needle in &forbidden {
        assert!(
            !code.contains(needle.as_str()),
            "the runner reaches past its explicit inputs: {needle}"
        );
    }
    // wc-005b: the two-engine runner verifies once, through wc-004's one
    // verify path, with no grants. Nothing else in the module verifies.
    assert_eq!(
        code.matches(["verify", "_bundle("].concat().as_str())
            .count(),
        1,
        "the runner calls the verifier more or less than once"
    );
    assert_eq!(
        code.matches(
            [
                "verify",
                "_bundle(input.bundle, input.signature, input.accepted, &[])"
            ]
            .concat()
            .as_str()
        )
        .count(),
        1,
        "the runner does not verify its own inputs with no grants"
    );
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

/// A signed fixture bundle in its own temp dir, outside every work root, and
/// the signer list that accepts it.
struct Signed {
    _tmp: TempDir,
    bundle: PathBuf,
    sig: NameSignature,
    accepted: Vec<String>,
}

fn signed_fixture() -> Signed {
    let tmp = TempDir::new("run2-fixture");
    let key = fresh_key();
    let (bundle, sig) = signed_bundle(&canonical(&tmp), "bundle", MODULE, &key);
    Signed {
        _tmp: tmp,
        bundle,
        sig,
        accepted: vec![did(&key)],
    }
}

/// The two-engine runner's input for `signed`, with both engine programs and
/// the work root.
fn input<'a>(
    signed: &'a Signed,
    wasmtime: &'a Path,
    wasmer: &'a Path,
    work_root: &'a Path,
) -> RunInput<'a> {
    RunInput {
        bundle: &signed.bundle,
        signature: Some(&signed.sig),
        accepted: &signed.accepted,
        wasmtime,
        wasmer,
        work_root,
    }
}

/// A new, empty work root `name` in `root`.
fn work_root(root: &Path, name: &str) -> PathBuf {
    let work = root.join(name);
    fs::create_dir(&work).expect("create a work root");
    work
}

/// A stand-in engine `name` for the two-engine runner. Asked `--version`, it
/// runs the shell `version` and exits 0 unless that exits first; started any
/// other way, it runs the shell `body`.
fn engine(folder: &Path, name: &str, version: &str, body: &str) -> PathBuf {
    let script = format!("#!/bin/sh\nif [ \"$1\" = --version ]; then\n{version}exit 0\nfi\n{body}");
    stand_in(folder, name, &script)
}

/// The version a stand-in made by [`marked`] prints.
fn stand_in_version(name: &str) -> String {
    format!("{name} 0.0.0-stand-in")
}

/// A stand-in engine `name` that, asked `--version`, leaves `<name>.version`
/// in `folder` and prints [`stand_in_version`]; started for a module run, it
/// leaves `<name>.started` in `folder`, then runs the shell `body`.
fn marked(folder: &Path, name: &str, body: &str) -> PathBuf {
    let version = format!("printf '%s\\n' '{}'\n", stand_in_version(name));
    marked_with(folder, name, &version, body)
}

/// As [`marked`], but asked `--version` it runs the shell `version` after
/// leaving its marker.
fn marked_with(folder: &Path, name: &str, version: &str, body: &str) -> PathBuf {
    let version_marker = folder.join(format!("{name}.version"));
    let marker = folder.join(format!("{name}.started"));
    engine(
        folder,
        name,
        &format!(": > '{}'\n{version}", version_marker.display()),
        &format!(": > '{}'\n{body}", marker.display()),
    )
}

/// Whether the stand-in `name` made by [`marked`] in `folder` was started for
/// a module run.
fn started(folder: &Path, name: &str) -> bool {
    folder.join(format!("{name}.started")).exists()
}

/// Whether the stand-in `name` made by [`marked`] in `folder` was asked
/// `--version`.
fn queried(folder: &Path, name: &str) -> bool {
    folder.join(format!("{name}.version")).exists()
}

/// The shell body of a stand-in engine that fails as [`FAILING`] does.
const FAILING_BODY: &str = "printf 'boom: bad module\\n' >&2\nexit 3\n";

/// A stand-in engine `name` that, asked `--version`, records `version <name>`
/// in `log`; started for a module run, it records that it started, with the
/// module path it was given, waits, records that it ended, then prints
/// `output`. Two engines that overlap leave their lines interleaved.
fn recording(folder: &Path, name: &str, log: &Path, output: &str) -> PathBuf {
    let version = format!(
        "printf 'version {name}\\n' >> '{log}'\nprintf '{name} 0.0.0-stand-in\\n'\n",
        log = log.display()
    );
    let body = format!(
        "printf 'start {name} %s\\n' \"$4\" >> '{log}'\n/bin/sleep 0.5\nprintf 'end {name}\\n' >> '{log}'\nprintf '{output}'\n",
        log = log.display()
    );
    engine(folder, name, &version, &body)
}

fn two_ran(result: Result<TwoEngineRun, TwoEngineRefusal>) -> TwoEngineRun {
    result.unwrap_or_else(|refusal| panic!("the two-engine runner refused: {refusal}"))
}

fn two_refused(result: Result<TwoEngineRun, TwoEngineRefusal>) -> TwoEngineRefusal {
    match result {
        Ok(passed) => panic!("the two-engine runner passed, {passed:?}, not a refusal"),
        Err(refusal) => refusal,
    }
}

#[test]
fn same_name_same_output_on_wasmtime_and_wasmer() {
    let mut missing = Vec::new();
    let mut programs = Vec::new();
    for engine_kind in ENGINES {
        match find_engine(engine_kind.name()) {
            Some(program) => programs.push(program),
            None => missing.push(engine_kind.name()),
        }
    }
    if !missing.is_empty() {
        eprintln!(
            "SKIPPED: {} not found on PATH; the two-engine proof needs both (no result, not a PASS)",
            missing.join(" and ")
        );
        return;
    }
    let tmp = TempDir::new("run2-real");
    let root = canonical(&tmp);
    let out = root.join("out");
    fs::create_dir(&out).expect("create OUT_DIR");
    run_build(&lane_dir(), &out);
    let built = fs::read(out.join("capsule.wasm")).expect("read the built capsule.wasm");
    let key = fresh_key();
    let (bundle, sig) = signed_bundle(&root, "bundle", &built, &key);
    let accepted = [did(&key)];
    let name = bundle_identity(&bundle).expect("name the bundle");
    let work = work_root(&root, "work");

    let passed = two_ran(run(&RunInput {
        bundle: &bundle,
        signature: Some(&sig),
        accepted: &accepted,
        wasmtime: &programs[0],
        wasmer: &programs[1],
        work_root: &work,
    }));
    let expected = format!("{FIXED_OUTPUT}\n");
    assert_eq!(
        passed.wasmtime(),
        expected.as_bytes(),
        "wasmtime ({}) did not print FIXED_OUTPUT for FIXED_INPUT",
        programs[0].display()
    );
    assert_eq!(
        passed.wasmer(),
        expected.as_bytes(),
        "wasmer ({}) did not print FIXED_OUTPUT for FIXED_INPUT",
        programs[1].display()
    );
    assert_eq!(
        passed.cid(),
        name,
        "the run does not hold the verified name"
    );
    assert_eq!(names(&work), ["wasmer", "wasmtime"]);
    eprintln!("PASS: wasmtime and wasmer both printed {FIXED_OUTPUT} for {FIXED_INPUT}, {name}");
}

#[test]
fn runner_refuses_an_unverified_bundle() {
    let tmp = TempDir::new("run2-unverified");
    let root = canonical(&tmp);
    let engines = work_root(&root, "engines");
    let wasmtime = marked(&engines, "wasmtime", "printf same\n");
    let wasmer = marked(&engines, "wasmer", "printf same\n");
    let key = fresh_key();
    let (bundle, sig) = signed_bundle(&root, "bundle", MODULE, &key);
    let signer = [did(&key)];
    let other = [did(&fresh_key())];
    let work = work_root(&root, "work");

    let cases: [(&str, Option<&NameSignature>, &[String]); 2] = [
        ("unsigned", None, &signer),
        ("wrong signer", Some(&sig), &other),
    ];
    for (kind, signature, accepted) in cases {
        let expected = verify_bundle(&bundle, signature, accepted, &[])
            .expect_err("the verifier passed a bundle this test means to be refused");
        let refusal = two_refused(run(&RunInput {
            bundle: &bundle,
            signature,
            accepted,
            wasmtime: &wasmtime,
            wasmer: &wasmer,
            work_root: &work,
        }));
        assert_eq!(refusal.to_string(), expected.to_string(), "{kind}");
        match refusal {
            TwoEngineRefusal::Verify(reason) => assert_eq!(reason, expected, "{kind}"),
            other => panic!("{kind}: {other}"),
        }
        match (kind, &expected) {
            ("unsigned", VerifyRefusal::Unsigned) => assert_eq!(
                expected.to_string(),
                "the bundle has no signature: an unsigned bundle is refused"
            ),
            ("wrong signer", VerifyRefusal::Identity(_)) => {}
            _ => panic!("{kind}: an unexpected verifier refusal: {expected}"),
        }
        assert!(names(&work).is_empty(), "{kind}: something was written");
        for engine_kind in ENGINES {
            assert!(
                !queried(&engines, engine_kind.name()),
                "{kind}: {engine_kind} was asked its version before verification"
            );
            assert!(
                !started(&engines, engine_kind.name()),
                "{kind}: {engine_kind} was started"
            );
        }
    }
    assert_eq!(names(&engines), ["wasmer", "wasmtime"]);
}

#[test]
fn differing_engine_outputs_are_reported_as_a_failure() {
    let signed = signed_fixture();
    let tmp = TempDir::new("run2-differ");
    let root = canonical(&tmp);
    let engines = work_root(&root, "engines");

    // Different digits, and the same digit with and without its newline:
    // stdout is compared byte for byte, never trimmed.
    for (case, wasmtime_out, wasmer_out) in [("digits", "1\n", "2\n"), ("newline", "7\n", "7")] {
        let wasmtime = marked(
            &engines,
            &format!("wasmtime-{case}"),
            &format!("printf '{}'\n", wasmtime_out.replace('\n', "\\n")),
        );
        let wasmer = marked(
            &engines,
            &format!("wasmer-{case}"),
            &format!("printf '{}'\n", wasmer_out.replace('\n', "\\n")),
        );
        let work = work_root(&root, case);
        let refusal = two_refused(run(&input(&signed, &wasmtime, &wasmer, &work)));
        assert_eq!(
            refusal.to_string(),
            format!(
                "the engines' outputs differ: wasmtime printed {wasmtime_out:?}, wasmer printed {wasmer_out:?}"
            ),
            "{case}"
        );
        match refusal {
            TwoEngineRefusal::OutputsDiffer { wasmtime, wasmer } => {
                assert_eq!(wasmtime, wasmtime_out.as_bytes(), "{case}");
                assert_eq!(wasmer, wasmer_out.as_bytes(), "{case}");
            }
            other => panic!("{case}: {other}"),
        }
        assert_eq!(names(&work), ["wasmer", "wasmtime"], "{case}");
    }
}

#[test]
fn matching_engine_failures_are_refused() {
    let signed = signed_fixture();
    let tmp = TempDir::new("run2-equal-failures");
    let root = canonical(&tmp);
    let engines = work_root(&root, "engines");
    let wasmtime = marked(&engines, "wasmtime", FAILING_BODY);
    let wasmer = marked(&engines, "wasmer", FAILING_BODY);
    let work = work_root(&root, "work");

    // Both would fail the same way, with the same empty stdout. That is
    // refused with the first failure's own reason, never as equal outputs,
    // and wasmer is not started after wasmtime is refused.
    let refusal = two_refused(run(&input(&signed, &wasmtime, &wasmer, &work)));
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: wasmtime failed (exit status: 3): boom: bad module",
            wasmtime.display()
        )
    );
    match refusal {
        TwoEngineRefusal::Engine(Refusal {
            path,
            reason:
                Reason::EngineFailed {
                    engine,
                    status,
                    stderr,
                },
        }) => {
            assert_eq!(path, wasmtime);
            assert_eq!(engine, Engine::Wasmtime);
            assert_eq!(status.code(), Some(3));
            assert_eq!(stderr, "boom: bad module\n");
        }
        other => panic!("{other}"),
    }
    assert!(started(&engines, "wasmtime"), "wasmtime was not started");
    assert!(
        !started(&engines, "wasmer"),
        "wasmer was started after wasmtime failed"
    );
    assert_eq!(names(&work), ["wasmtime"]);
}

#[test]
fn runner_preserves_engine_refusals() {
    let signed = signed_fixture();
    let tmp = TempDir::new("run2-engine-refusals");
    let root = canonical(&tmp);

    // Either engine's module run failing: 014's refusal comes back unchanged,
    // with its own path and cause, and nothing starts after it. A program that
    // does not start is refused at its version query, before any module run
    // (`version_query_failures_keep_their_cause`).
    for failing_engine in ENGINES {
        let case = format!("{failing_engine}-fails");
        let engines = work_root(&root, &format!("engines-{case}"));
        let mut programs = Vec::new();
        for engine_kind in ENGINES {
            let program = if engine_kind != failing_engine {
                marked(&engines, engine_kind.name(), "printf same\n")
            } else {
                marked(&engines, engine_kind.name(), FAILING_BODY)
            };
            programs.push(program);
        }
        let failing = &programs[if failing_engine == Engine::Wasmtime {
            0
        } else {
            1
        }];
        let work = work_root(&root, &format!("work-{case}"));
        let refusal = two_refused(run(&input(&signed, &programs[0], &programs[1], &work)));
        let text = format!(
            "{}: {failing_engine} failed (exit status: 3): boom: bad module",
            failing.display()
        );
        assert_eq!(refusal.to_string(), text, "{case}");
        let refusal = match refusal {
            TwoEngineRefusal::Engine(refusal) => refusal,
            other => panic!("{case}: {other}"),
        };
        assert_eq!(&refusal.path, failing, "{case}");
        match refusal.reason {
            Reason::EngineFailed {
                engine,
                status,
                stderr,
            } => {
                assert_eq!(engine, failing_engine, "{case}");
                assert_eq!(status.code(), Some(3), "{case}");
                assert_eq!(stderr, "boom: bad module\n", "{case}");
            }
            other => panic!("{case}: {other}"),
        }
        if failing_engine == Engine::Wasmtime {
            assert!(
                !started(&engines, "wasmer"),
                "{case}: wasmer was started after wasmtime was refused"
            );
            assert_eq!(names(&work), ["wasmtime"], "{case}");
        } else {
            assert!(
                started(&engines, "wasmtime"),
                "{case}: wasmtime did not run"
            );
            assert_eq!(names(&work), ["wasmer", "wasmtime"], "{case}");
        }
    }

    // A run folder already at wasmer's name: wasmtime runs, then 014's
    // refusal for the planted folder comes back unchanged.
    let engines = work_root(&root, "engines-planted");
    let wasmtime = marked(&engines, "wasmtime", "printf same\n");
    let wasmer = marked(&engines, "wasmer", "printf same\n");
    let work = work_root(&root, "work-planted");
    let planted = work_root(&work, "wasmer");
    let refusal = two_refused(run(&input(&signed, &wasmtime, &wasmer, &work)));
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: the run folder already exists: the runner makes a new one and never reuses it",
            planted.display()
        )
    );
    match refusal {
        TwoEngineRefusal::Engine(Refusal {
            path,
            reason: Reason::RunDirExists,
        }) => assert_eq!(path, planted),
        other => panic!("{other}"),
    }
    assert!(started(&engines, "wasmtime"), "wasmtime did not run");
    assert!(!started(&engines, "wasmer"), "wasmer was started");
    assert!(names(&planted).is_empty(), "the planted folder was used");
}

#[test]
fn runner_calls_engines_in_order() {
    let signed = signed_fixture();
    let tmp = TempDir::new("run2-order");
    let root = canonical(&tmp);
    let engines = work_root(&root, "engines");
    let log = engines.join("log");
    let wasmtime = recording(&engines, "wasmtime", &log, "same");
    let wasmer = recording(&engines, "wasmer", &log, "same");
    let work = work_root(&root, "work");

    let passed = two_ran(run(&input(&signed, &wasmtime, &wasmer, &work)));
    // Both are asked their version first, wasmtime then wasmer; then wasmtime
    // starts and ends, then wasmer starts and ends: one after the other, never
    // overlapping, each through run_engine's own run folder.
    assert_eq!(
        fs::read_to_string(&log).expect("read the start log"),
        format!(
            "version wasmtime\nversion wasmer\nstart wasmtime {}\nend wasmtime\nstart wasmer {}\nend wasmer\n",
            work.join("wasmtime").join("module.wasm").display(),
            work.join("wasmer").join("module.wasm").display()
        ),
        "the engines did not run one after the other through run_engine"
    );
    assert_eq!(passed.wasmtime(), b"same");
    assert_eq!(passed.wasmer(), b"same");
    assert_eq!(names(&work), ["wasmer", "wasmtime"]);
    for engine_kind in ENGINES {
        assert_eq!(
            fs::read(work.join(engine_kind.name()).join("module.wasm")).expect("read a module"),
            MODULE,
            "{engine_kind}: the run folder does not hold the verified bytes"
        );
    }
}

#[test]
fn run_returns_the_verified_name_and_both_outputs() {
    let signed = signed_fixture();
    let name = bundle_identity(&signed.bundle).expect("name the bundle");
    let tmp = TempDir::new("run2-name");
    let root = canonical(&tmp);
    let engines = work_root(&root, "engines");
    // wasmtime changes the bundle on disk while it runs, so a name taken from
    // the folder after verification would differ from the verified one.
    let wasmtime = marked(
        &engines,
        "wasmtime",
        &format!(
            "printf x >> '{}'\nprintf 'same\\n'\n",
            signed.bundle.join("capsule.wasm").display()
        ),
    );
    let wasmer = marked(&engines, "wasmer", "printf 'same\\n'\n");
    let work = work_root(&root, "work");

    let passed = two_ran(run(&input(&signed, &wasmtime, &wasmer, &work)));
    assert_ne!(
        bundle_identity(&signed.bundle).expect("name the changed bundle"),
        name,
        "the stand-in did not change the bundle, so this test proves nothing"
    );
    assert_eq!(
        passed.cid(),
        name,
        "the run does not hold the verified name"
    );
    assert_eq!(passed.wasmtime(), b"same\n");
    assert_eq!(passed.wasmer(), b"same\n");
}

/// A stand-in engine `name` that records each start in `<its own path>.starts`,
/// found from its own `$0`, never from an environment variable (the engine
/// runs with none): `version` for a `--version` query, which prints a version,
/// and `module <module path>` for a module run, which prints `same`.
fn counting(folder: &Path, name: &str) -> PathBuf {
    engine(
        folder,
        name,
        &format!("printf 'version\\n' >> \"$0.starts\"\nprintf '{name} 0.0.0-stand-in\\n'\n"),
        "printf 'module %s\\n' \"$4\" >> \"$0.starts\"\nprintf 'same\\n'\n",
    )
}

/// How many starts of `kind` (`version` or `module`) the stand-in made by
/// [`counting`] at `program` recorded; none if it was never started.
fn starts(program: &Path, kind: &str) -> usize {
    let record = PathBuf::from(format!("{}.starts", program.display()));
    match fs::read_to_string(&record) {
        Ok(text) => text
            .lines()
            .filter(|line| line.split(' ').next() == Some(kind))
            .count(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => panic!("read {}: {error}", record.display()),
    }
}

/// One `run_engine` call starts its engine for exactly one module run; one
/// `run` call starts each engine for exactly one module run, two in all. Its
/// `--version` queries (task 016) are counted apart. The counts are exact,
/// never "at least one" (wc-005: one process per engine; P3, P10).
#[test]
fn run_engine_starts_its_engine_exactly_once() {
    let (_bundle, value) = fixture();
    let tmp = TempDir::new("run-starts");
    let root = canonical(&tmp);
    for engine_kind in ENGINES {
        let engines = work_root(&root, &format!("{engine_kind}-engines"));
        let program = counting(&engines, engine_kind.name());
        let work = work_root(&root, &format!("{engine_kind}-work"));

        assert_eq!(
            ran(run_engine(&value, engine_kind, &program, &work)),
            b"same\n"
        );
        let module_runs = starts(&program, "module");
        assert_eq!(
            module_runs, 1,
            "{engine_kind}: one run_engine call started the engine {module_runs} times"
        );
        assert_eq!(
            starts(&program, "version"),
            0,
            "{engine_kind}: run_engine asked --version"
        );
    }

    let signed = signed_fixture();
    let engines = work_root(&root, "two-engines");
    let wasmtime = counting(&engines, "wasmtime");
    let wasmer = counting(&engines, "wasmer");
    let work = work_root(&root, "two-work");

    let passed = two_ran(run(&input(&signed, &wasmtime, &wasmer, &work)));
    assert_eq!(passed.wasmtime(), b"same\n");
    assert_eq!(passed.wasmer(), b"same\n");
    let module_runs = [starts(&wasmtime, "module"), starts(&wasmer, "module")];
    assert_eq!(
        module_runs,
        [1, 1],
        "one run call started wasmtime and wasmer {module_runs:?} times"
    );
    assert_eq!(
        module_runs.iter().sum::<usize>(),
        2,
        "two module runs in all"
    );
    let version_queries = [starts(&wasmtime, "version"), starts(&wasmer, "version")];
    assert_eq!(
        version_queries,
        [1, 1],
        "one run call asked wasmtime and wasmer --version {version_queries:?} times"
    );
}

/// The two-engine runner's version refusal, and nothing else.
fn version_refused(result: Result<TwoEngineRun, TwoEngineRefusal>) -> Refusal {
    match two_refused(result) {
        TwoEngineRefusal::Version(refusal) => refusal,
        other => panic!("not a version refusal: {other}"),
    }
}

#[test]
fn receipt_records_observed_engine_versions() {
    let signed = signed_fixture();
    let name = bundle_identity(&signed.bundle).expect("name the bundle");
    let tmp = TempDir::new("run3-receipt");
    let root = canonical(&tmp);
    assert_eq!(RECEIPT_SCHEMA, "wc-005.run-receipt/v1");

    // Two runs of the same bundle, by stand-ins that print made-up versions,
    // each followed by a second line that is not kept.
    let mut runs = Vec::new();
    for (case, wasmtime_version, wasmer_version) in [
        (
            "first",
            "wasmtime 99.0.0-made-up (abc1234 2099-01-01)",
            "wasmer 0.0.1-made-up",
        ),
        ("second", "wasmtime 1.2.3-other", "wasmer 4.5.6-other"),
    ] {
        let engines = work_root(&root, &format!("engines-{case}"));
        let wasmtime = engine(
            &engines,
            "wasmtime",
            &format!("printf '%s\\nsecond line\\n' '{wasmtime_version}'\n"),
            "printf '4242\\n'\n",
        );
        let wasmer = engine(
            &engines,
            "wasmer",
            &format!("printf '%s\\nsecond line\\n' '{wasmer_version}'\n"),
            "printf '4242\\n'\n",
        );
        let work = work_root(&root, &format!("work-{case}"));
        let passed = two_ran(run(&input(&signed, &wasmtime, &wasmer, &work)));
        assert_eq!(
            passed.version(Engine::Wasmtime),
            wasmtime_version.as_bytes(),
            "{case}"
        );
        assert_eq!(
            passed.version(Engine::Wasmer),
            wasmer_version.as_bytes(),
            "{case}"
        );
        for engine_kind in ENGINES {
            assert_eq!(passed.status(engine_kind).code(), Some(0), "{case}");
            assert_eq!(passed.stdout(engine_kind), b"4242\n", "{case}");
        }
        assert_eq!(passed.cid(), name, "{case}: not the verified name");

        let receipt = render(&passed);
        assert_eq!(
            receipt,
            format!(
                "schema: wc-005.run-receipt/v1\n\
                 bundle: {name}\n\
                 function: digest\n\
                 argument: 1592590337\n\
                 wasmtime_version: \"{wasmtime_version}\"\n\
                 wasmtime_status: exit status: 0\n\
                 wasmtime_stdout: \"4242\\n\"\n\
                 wasmer_version: \"{wasmer_version}\"\n\
                 wasmer_status: exit status: 0\n\
                 wasmer_stdout: \"4242\\n\"\n"
            ),
            "{case}: the receipt"
        );
        for installed in ["45.0.1", "7.5.0", "second line"] {
            assert!(
                !receipt.contains(installed),
                "{case}: the receipt holds {installed:?}, which no stand-in printed as its version"
            );
        }
        runs.push((passed, [wasmtime_version, wasmer_version]));
    }

    // The engine versions are beside the lab CID, never in it: other versions
    // on the same bundle give the same name.
    assert_eq!(runs[0].0.cid(), runs[1].0.cid());
    let cid = name.to_string();
    // The printed form is cc-capsule-identity's to check: its one parse.
    let parsed: LabCid = cid
        .parse()
        .unwrap_or_else(|refusal| panic!("{cid} does not parse as a lab CID: {refusal}"));
    assert_eq!(
        parsed.to_string(),
        cid,
        "the parse does not print back {cid}"
    );
    for (_, versions) in &runs {
        for version in versions {
            let number = version.split(' ').nth(1).expect("a version number");
            assert!(!cid.contains(number), "the lab CID holds {number}");
        }
    }
}

#[test]
fn version_query_failures_keep_their_cause() {
    let signed = signed_fixture();
    let tmp = TempDir::new("run3-version-fail");
    let root = canonical(&tmp);

    // A version query that exits nonzero, prints nothing, prints an empty
    // first line, or whose program is missing: each is refused with its own
    // reason, engine and cause, and no module run starts.
    let cases = [
        ("nonzero", Some("printf 'no version here\\n' >&2\nexit 4\n")),
        ("empty", Some("")),
        ("blank-first-line", Some("printf '\\nwasmtime 1.0\\n'\n")),
        ("missing", None),
    ];
    for failing_engine in ENGINES {
        for (kind, version) in cases {
            let case = format!("{failing_engine}-{kind}");
            let engines = work_root(&root, &format!("engines-{case}"));
            let mut programs = Vec::new();
            for engine_kind in ENGINES {
                let name = engine_kind.name();
                let program = match version {
                    _ if engine_kind != failing_engine => marked(&engines, name, "printf same\n"),
                    Some(version) => marked_with(&engines, name, version, "printf same\n"),
                    None => engines.join(name),
                };
                programs.push(program);
            }
            let failing = &programs[if failing_engine == Engine::Wasmtime {
                0
            } else {
                1
            }];
            let work = work_root(&root, &format!("work-{case}"));
            let refusal = version_refused(run(&input(&signed, &programs[0], &programs[1], &work)));
            assert_eq!(&refusal.path, failing, "{case}");
            let text = match (kind, &refusal.reason) {
                (
                    "nonzero",
                    Reason::VersionFailed {
                        engine,
                        status,
                        stderr,
                    },
                ) => {
                    assert_eq!(*engine, failing_engine, "{case}");
                    assert_eq!(status.code(), Some(4), "{case}");
                    assert_eq!(stderr, "no version here\n", "{case}");
                    format!("{failing_engine} --version failed (exit status: 4): no version here")
                }
                ("empty" | "blank-first-line", Reason::VersionEmpty { engine }) => {
                    assert_eq!(*engine, failing_engine, "{case}");
                    format!(
                        "{failing_engine} --version printed no version: its first stdout line is empty"
                    )
                }
                ("missing", Reason::VersionDidNotStart { engine, error }) => {
                    assert_eq!(*engine, failing_engine, "{case}");
                    assert_eq!(error.kind(), io::ErrorKind::NotFound, "{case}");
                    format!("{failing_engine} --version did not start: {NOT_FOUND}")
                }
                (_, other) => panic!("{case}: {other}"),
            };
            assert_eq!(
                refusal.to_string(),
                format!("{}: {text}", failing.display()),
                "{case}"
            );

            // No module run started, and nothing was written.
            for engine_kind in ENGINES {
                assert!(
                    !started(&engines, engine_kind.name()),
                    "{case}: {engine_kind}'s module run started"
                );
            }
            assert!(names(&work).is_empty(), "{case}: something was written");
            // wasmtime is asked first; wasmer is not asked after it is refused.
            if failing_engine == Engine::Wasmtime {
                assert!(!queried(&engines, "wasmer"), "{case}: wasmer was asked");
            } else {
                assert!(
                    queried(&engines, "wasmtime"),
                    "{case}: wasmtime was not asked"
                );
            }
        }
    }
}

#[test]
fn version_queries_use_explicit_inputs() {
    let signed = signed_fixture();
    let tmp = TempDir::new("run3-version-inputs");
    let root = canonical(&tmp);
    assert!(
        std::env::var_os("HOME").is_some(),
        "the test process has no HOME, so this test proves nothing"
    );

    // Each version answer is the program path the stand-in was started by,
    // HOME as it saw it, and whether its stdin is /dev/null.
    let report = "if [ /dev/stdin -ef /dev/null ]; then stdin=null; else stdin=other; fi\n\
                  printf '%s %s %s\\n' \"$0\" \"${HOME-unset}\" \"$stdin\"\n";
    let engines = work_root(&root, "engines");
    let wasmtime = engine(&engines, "wasmtime", report, "printf same\n");
    let wasmer = engine(&engines, "wasmer", report, "printf same\n");
    let work = work_root(&root, "work");
    let passed = two_ran(run(&input(&signed, &wasmtime, &wasmer, &work)));
    for (engine_kind, program) in [(Engine::Wasmtime, &wasmtime), (Engine::Wasmer, &wasmer)] {
        assert_eq!(
            String::from_utf8_lossy(passed.version(engine_kind)),
            format!("{} unset null", program.display()),
            "{engine_kind}: the version query was not started by its absolute path with an empty environment and stdin null"
        );
    }

    // A relative program path, for either engine, is refused before it is
    // started; nothing is looked up against the working folder, and no
    // module run starts.
    for relative_engine in ENGINES {
        let engines = work_root(&root, &format!("engines-{relative_engine}-relative"));
        let relative = PathBuf::from(format!("engines/{relative_engine}"));
        assert!(
            !relative.exists(),
            "{relative_engine}: the relative path names a file here, so this test proves nothing"
        );
        let mut programs = Vec::new();
        for engine_kind in ENGINES {
            programs.push(if engine_kind == relative_engine {
                relative.clone()
            } else {
                marked(&engines, engine_kind.name(), "printf same\n")
            });
        }
        let work = work_root(&root, &format!("work-{relative_engine}-relative"));
        let refusal = version_refused(run(&input(&signed, &programs[0], &programs[1], &work)));
        assert!(
            matches!(refusal.reason, Reason::EngineNotAbsolute),
            "{relative_engine}: {refusal}"
        );
        assert_eq!(refusal.path, relative, "{relative_engine}");
        assert_eq!(
            refusal.to_string(),
            format!(
                "engines/{relative_engine}: the engine program path is not absolute: an engine is started only by an absolute path"
            )
        );
        for engine_kind in ENGINES {
            assert!(
                !started(&engines, engine_kind.name()),
                "{relative_engine}: {engine_kind}'s module run started"
            );
        }
        assert!(
            names(&work).is_empty(),
            "{relative_engine}: something was written"
        );
    }
}

#[test]
fn receipt_write_refuses_an_existing_path() {
    let signed = signed_fixture();
    let tmp = TempDir::new("run3-receipt-write");
    let root = canonical(&tmp);
    let engines = work_root(&root, "engines");
    let wasmtime = marked(&engines, "wasmtime", "printf same\n");
    let wasmer = marked(&engines, "wasmer", "printf same\n");
    let work = work_root(&root, "work");
    let passed = two_ran(run(&input(&signed, &wasmtime, &wasmer, &work)));

    // A new path: the receipt is written, byte for byte.
    let receipts = work_root(&root, "receipts");
    let written = receipts.join("receipt.txt");
    write_receipt(&passed, &written)
        .unwrap_or_else(|refusal| panic!("the receipt was refused: {refusal}"));
    assert_eq!(
        fs::read_to_string(&written).expect("read the receipt"),
        render(&passed)
    );

    // The receipt just written, a planted file, a live link to a file and a
    // dangling link: each is refused with the shared writer's own reason and
    // cause, and nothing at or behind the path changes.
    let planted = receipts.join("planted.txt");
    fs::write(&planted, b"planted receipt\n").expect("plant a file");
    let target = receipts.join("target.txt");
    fs::write(&target, b"link target\n").expect("write a link target");
    let live = receipts.join("live-link.txt");
    std::os::unix::fs::symlink(&target, &live).expect("plant a live link");
    let nowhere = receipts.join("nowhere.txt");
    let dangling = receipts.join("dangling-link.txt");
    std::os::unix::fs::symlink(&nowhere, &dangling).expect("plant a dangling link");

    for (kind, path) in [
        ("the receipt already written", &written),
        ("a planted file", &planted),
        ("a live link", &live),
        ("a dangling link", &dangling),
    ] {
        let link_before = fs::read_link(path).ok();
        let bytes_before = fs::read(path).ok();
        let refusal = write_receipt(&passed, path)
            .err()
            .unwrap_or_else(|| panic!("{kind}: the receipt was written over an existing path"));
        assert_eq!(&refusal.path, path, "{kind}");
        match &refusal.reason {
            WriteReason::ManifestNotCreated(error) => {
                assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{kind}");
                assert_eq!(error.raw_os_error(), Some(17), "{kind}");
            }
            other => panic!("{kind}: {other}"),
        }
        let own = write_new_file(path, b"other bytes")
            .err()
            .unwrap_or_else(|| panic!("{kind}: the shared writer wrote over an existing path"));
        assert_eq!(refusal.to_string(), own.to_string(), "{kind}");
        assert_eq!(
            refusal.to_string(),
            format!(
                "{}: capsule.json cannot be created: File exists (os error 17)",
                path.display()
            ),
            "{kind}"
        );
        assert_eq!(
            fs::read_link(path).ok(),
            link_before,
            "{kind}: the link changed"
        );
        assert_eq!(
            fs::read(path).ok(),
            bytes_before,
            "{kind}: the bytes changed"
        );
    }
    assert_eq!(
        fs::read_to_string(&written).expect("read the receipt"),
        render(&passed),
        "the first receipt changed"
    );
    assert_eq!(fs::read(&planted).expect("read"), b"planted receipt\n");
    assert_eq!(fs::read(&target).expect("read"), b"link target\n");
    assert!(
        !nowhere.exists(),
        "a receipt was written through the dangling link"
    );
    assert_eq!(
        names(&receipts),
        [
            "dangling-link.txt",
            "live-link.txt",
            "planted.txt",
            "receipt.txt",
            "target.txt"
        ]
    );
}

#[test]
fn real_receipt_names_both_installed_engines() {
    let mut missing = Vec::new();
    let mut programs = Vec::new();
    for engine_kind in ENGINES {
        match find_engine(engine_kind.name()) {
            Some(program) => programs.push(program),
            None => missing.push(engine_kind.name()),
        }
    }
    if !missing.is_empty() {
        eprintln!(
            "SKIPPED: {} not found on PATH; the real receipt needs both (no result, not a PASS)",
            missing.join(" and ")
        );
        return;
    }
    let tmp = TempDir::new("run3-real");
    let root = canonical(&tmp);
    let out = root.join("out");
    fs::create_dir(&out).expect("create OUT_DIR");
    run_build(&lane_dir(), &out);
    let built = fs::read(out.join("capsule.wasm")).expect("read the built capsule.wasm");
    let key = fresh_key();
    let (bundle, sig) = signed_bundle(&root, "bundle", &built, &key);
    let accepted = [did(&key)];
    let name = bundle_identity(&bundle).expect("name the bundle");
    let work = work_root(&root, "work");

    let passed = two_ran(run(&RunInput {
        bundle: &bundle,
        signature: Some(&sig),
        accepted: &accepted,
        wasmtime: &programs[0],
        wasmer: &programs[1],
        work_root: &work,
    }));
    let expected = format!("{FIXED_OUTPUT}\n");
    for (engine_kind, program) in ENGINES.iter().zip(&programs) {
        let version = passed.version(*engine_kind);
        assert!(
            version.starts_with(format!("{engine_kind} ").as_bytes()),
            "{engine_kind} ({}) printed the version {:?}",
            program.display(),
            String::from_utf8_lossy(version)
        );
        // What the engine prints for --version here, asked the same way.
        let printed = std::process::Command::new(program)
            .arg("--version")
            .env_clear()
            .stdin(std::process::Stdio::null())
            .output()
            .expect("ask the engine its version");
        assert_eq!(
            printed.stdout.split(|&byte| byte == b'\n').next(),
            Some(version),
            "{engine_kind}: the receipt's version is not the line the engine prints"
        );
        assert_eq!(passed.stdout(*engine_kind), expected.as_bytes());
        assert_eq!(passed.status(*engine_kind).code(), Some(0));
    }
    assert_eq!(
        passed.cid(),
        name,
        "the run does not hold the verified name"
    );

    let receipt = render(&passed);
    let path = root.join("receipt.txt");
    write_receipt(&passed, &path)
        .unwrap_or_else(|refusal| panic!("the receipt was refused: {refusal}"));
    assert_eq!(
        fs::read_to_string(&path).expect("read the receipt"),
        receipt
    );
    let lines: Vec<&str> = receipt.lines().collect();
    assert_eq!(
        lines[..4],
        [
            "schema: wc-005.run-receipt/v1".to_string(),
            format!("bundle: {name}"),
            "function: digest".to_string(),
            format!("argument: {FIXED_INPUT}"),
        ]
    );
    eprintln!("RECEIPT (this machine):\n{receipt}");
    eprintln!("PASS: the receipt names both installed engines' versions as they printed them");
}
