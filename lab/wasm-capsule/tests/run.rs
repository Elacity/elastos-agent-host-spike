//! wc-005a: the runner, `wasm_capsule_tools::run::run_engine` (PRINCIPLES P3,
//! P10, P11, P18). It runs one host engine on a verified bundle's entrypoint
//! bytes, written from memory into a new private folder, with a fixed argv.
//!
//! wc-005b: the two-engine runner, `wasm_capsule_tools::run::run`. It calls
//! `verify_bundle` once, then `run_engine` for `wasmtime` and then for
//! `wasmer`, and requires both to succeed with byte-identical stdout.
//!
//! The stand-in engines are small shell scripts written into each test's own
//! temp dir. One test starts the real `wasmtime` and `wasmer`; an engine it
//! cannot find is reported SKIPPED, never PASS. Every test key is made fresh in
//! memory inside its test and never written. The tests share one process, so
//! none changes process-wide state (env, working folder, limits).

mod common;

use capsule::{FIXED_INPUT, FIXED_OUTPUT};
use capsule_identity::{sign_bundle, NameSignature};
use common::build::{lane_dir, run_build, TempDir};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use wasm_capsule_tools::bundle::{Reason as WriteReason, RunRefusal as WriteRefusal};
use wasm_capsule_tools::run::{
    module_refusal, run, run_engine, work_root_folder, Engine, Reason, Refusal, RunInput,
    TwoEngineRefusal, TwoEngineRun, DIGEST_ARGUMENT, DIGEST_EXPORT,
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

/// A stand-in engine `name` that leaves `<name>.started` in `folder` when it
/// is started, then runs the shell `body`.
fn marked(folder: &Path, name: &str, body: &str) -> PathBuf {
    let marker = folder.join(format!("{name}.started"));
    let script = format!("#!/bin/sh\n: > '{}'\n{body}", marker.display());
    stand_in(folder, name, &script)
}

/// Whether the stand-in `name` made by [`marked`] in `folder` was started.
fn started(folder: &Path, name: &str) -> bool {
    folder.join(format!("{name}.started")).exists()
}

/// The shell body of a stand-in engine that fails as [`FAILING`] does.
const FAILING_BODY: &str = "printf 'boom: bad module\\n' >&2\nexit 3\n";

/// A stand-in engine `name` that records in `log` that it started, with the
/// module path it was given, waits, records that it ended, then prints
/// `output`. Two engines that overlap leave their lines interleaved.
fn recording(folder: &Path, name: &str, log: &Path, output: &str) -> PathBuf {
    let script = format!(
        "#!/bin/sh\nprintf 'start {name} %s\\n' \"$4\" >> '{log}'\n/bin/sleep 0.5\nprintf 'end {name}\\n' >> '{log}'\nprintf '{output}'\n",
        log = log.display()
    );
    stand_in(folder, name, &script)
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
        let wasmtime = stand_in(
            &engines,
            &format!("wasmtime-{case}"),
            &format!(
                "#!/bin/sh\nprintf '{}'\n",
                wasmtime_out.replace('\n', "\\n")
            ),
        );
        let wasmer = stand_in(
            &engines,
            &format!("wasmer-{case}"),
            &format!("#!/bin/sh\nprintf '{}'\n", wasmer_out.replace('\n', "\\n")),
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

    // Either engine failing, or not starting: 014's refusal comes back
    // unchanged, with its own path and cause, and nothing starts after it.
    for (failing_engine, start) in [
        (Engine::Wasmtime, true),
        (Engine::Wasmtime, false),
        (Engine::Wasmer, true),
        (Engine::Wasmer, false),
    ] {
        let case = format!(
            "{failing_engine}-{}",
            if start { "fails" } else { "missing" }
        );
        let engines = work_root(&root, &format!("engines-{case}"));
        let mut programs = Vec::new();
        for engine_kind in ENGINES {
            let program = if engine_kind != failing_engine {
                marked(&engines, engine_kind.name(), "printf same\n")
            } else if start {
                marked(&engines, engine_kind.name(), FAILING_BODY)
            } else {
                engines.join(engine_kind.name())
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
        let text = if start {
            format!(
                "{}: {failing_engine} failed (exit status: 3): boom: bad module",
                failing.display()
            )
        } else {
            format!(
                "{}: {failing_engine} did not start: {NOT_FOUND}",
                failing.display()
            )
        };
        assert_eq!(refusal.to_string(), text, "{case}");
        let refusal = match refusal {
            TwoEngineRefusal::Engine(refusal) => refusal,
            other => panic!("{case}: {other}"),
        };
        assert_eq!(&refusal.path, failing, "{case}");
        match (refusal.reason, start) {
            (
                Reason::EngineFailed {
                    engine,
                    status,
                    stderr,
                },
                true,
            ) => {
                assert_eq!(engine, failing_engine, "{case}");
                assert_eq!(status.code(), Some(3), "{case}");
                assert_eq!(stderr, "boom: bad module\n", "{case}");
            }
            (Reason::EngineDidNotStart { engine, error }, false) => {
                assert_eq!(engine, failing_engine, "{case}");
                assert_eq!(error.kind(), io::ErrorKind::NotFound, "{case}");
            }
            (other, _) => panic!("{case}: {other}"),
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
    // wasmtime starts and ends, then wasmer starts and ends: one after the
    // other, never overlapping, each through run_engine's own run folder.
    assert_eq!(
        fs::read_to_string(&log).expect("read the start log"),
        format!(
            "start wasmtime {}\nend wasmtime\nstart wasmer {}\nend wasmer\n",
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
    let wasmtime = stand_in(
        &engines,
        "wasmtime",
        &format!(
            "#!/bin/sh\nprintf x >> '{}'\nprintf 'same\\n'\n",
            signed.bundle.join("capsule.wasm").display()
        ),
    );
    let wasmer = stand_in(&engines, "wasmer", "#!/bin/sh\nprintf 'same\\n'\n");
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
