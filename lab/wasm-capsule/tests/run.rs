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
//! wc-009a: `run` passes the caller's granted imports, read from a lab grants
//! file by `read_grants`, to its one `verify_bundle` call, and reports the
//! linked imports and the unused grants. A module with an import that is not
//! granted never reaches an engine.
//!
//! Task 031: a module that imports, granted, an import with no typed lab
//! operation (`LAB_OPERATIONS`) never reaches an engine either.
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
use common::grants::{env_f, grants_file, importing, importing_env, IMPORTING_MODULE};
use common::wasm_shape;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use wasm_capsule_audit::Refusal as AuditRefusal;
use wasm_capsule_tools::bundle::{
    write_new_file, Reason as WriteReason, RunRefusal as WriteRefusal,
};
use wasm_capsule_tools::receipt::{
    render, render_refused, write_receipt, write_refused_receipt, RECEIPT_SCHEMA,
};
use wasm_capsule_tools::run::{
    module_refusal, run, run_engine, work_root_folder, Engine, EngineRun, Reason, Refusal,
    RunControl, RunInput, TwoEngineRefusal, TwoEngineRun, DIGEST_ARGUMENT, DIGEST_EXPORT,
    WASMER_VERSION, WASMTIME_VERSION,
};
use wasm_capsule_tools::verify::{read_grants, verify_bundle, VerifiedBundle, VerifyRefusal};
use wasm_capsule_tools::{bundle_identity, CAPSULE_MANIFEST};

/// The smallest core Wasm module: the magic and version 1, no sections.
const MODULE: &[u8] = b"\0asm\x01\0\0\0";

/// Other bytes put at the bundle's `capsule.wasm` after verification.
const CHANGED_MODULE: &[u8] = b"\0asm\x01\0\0\0\0\x01\x00";

/// Both engines, in a fixed order.
const ENGINES: [Engine; 2] = [Engine::Wasmtime, Engine::Wasmer];

/// Task 043: the run budget of every test run that is not about the budget:
/// far above any run here, so it never decides a result.
const TEST_BUDGET: Duration = Duration::from_secs(30);

/// The one run control those runs pass: `TEST_BUDGET`, explicit at each call
/// (the runner has no default).
static TEST_CONTROL: RunControl = RunControl::new(TEST_BUDGET);

/// The shell line that sets `module` to a stand-in's second-to-last
/// argument: the module path, which comes just before the fixed argument
/// whatever memory cap arguments come before it (wc-010b).
macro_rules! module_argument {
    () => {
        "for arg in \"$@\"; do module=\"$last\"; last=\"$arg\"; done\n"
    };
}
const MODULE_ARGUMENT: &str = module_argument!();

/// The shell lines, after [`MODULE_ARGUMENT`], with which a stand-in records
/// its run folder as it saw it during its run (task 039: the runner removes
/// the folder once the engine exits). Each record sits beside the stand-in's
/// own path, `$0`, in the test's own stand-in folder, outside the work root:
/// a copy of the module in `$0.module`, the folder's mode in `$0.mode` and
/// its entries in `$0.entries`. A later run of the same stand-in writes over
/// them. Every command is named by its absolute path (the engine has no
/// environment).
macro_rules! record_run_folder {
    () => {
        concat!(
            "/bin/cp \"$module\" \"$0.module\"\n",
            "/usr/bin/stat -f %Lp \"${module%/*}\" > \"$0.mode\"\n",
            "/bin/ls -A \"${module%/*}\" > \"$0.entries\"\n",
        )
    };
}
const RECORD_RUN_FOLDER: &str = record_run_folder!();

/// A stand-in engine that prints the bytes of the module it was given (its
/// second-to-last argument), after recording its run folder.
const CAT_MODULE: &str = concat!(
    "#!/bin/sh\n",
    module_argument!(),
    record_run_folder!(),
    "cat \"$module\"\n"
);

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

/// What the stand-in at `program` recorded as `kind` (`module`, `mode` or
/// `entries`) through [`RECORD_RUN_FOLDER`] during its last run.
fn recorded(program: &Path, kind: &str) -> Vec<u8> {
    let record = PathBuf::from(format!("{}.{kind}", program.display()));
    fs::read(&record).unwrap_or_else(|error| panic!("read {}: {error}", record.display()))
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

    let stdout = ran(run_engine(
        &value,
        Engine::Wasmtime,
        &engine,
        &root,
        &TEST_CONTROL,
    ));
    assert_eq!(
        stdout, MODULE,
        "the engine did not get the verified entrypoint bytes"
    );
    // As the engine saw its run folder: exactly the module file, holding the
    // verified bytes. Task 039: once it exited, the folder was removed.
    assert_eq!(
        recorded(&engine, "entries"),
        b"module.wasm\n",
        "the run folder"
    );
    assert_eq!(recorded(&engine, "module"), MODULE);
    assert_eq!(
        names(&root),
        ["bundle"],
        "something was written outside the run folder, or the run folder was left"
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
            &TEST_CONTROL,
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
        let refusal = refused(run_engine(
            &value,
            Engine::Wasmer,
            &engine,
            Path::new(root),
            &TEST_CONTROL,
        ));
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
        let refusal = refused(run_engine(
            &value,
            Engine::Wasmer,
            &engine,
            &root,
            &TEST_CONTROL,
        ));
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

    // The run folder's mode as the engine saw it, during its run. Task 039: a
    // second run in the same root finds no folder (the first was removed) and
    // makes a new one, private too; each leaves the root empty.
    for run in ["first", "second"] {
        assert_eq!(
            ran(run_engine(
                &value,
                Engine::Wasmtime,
                &cat,
                &root,
                &TEST_CONTROL
            )),
            MODULE,
            "{run} run"
        );
        assert_eq!(
            recorded(&cat, "mode"),
            b"700\n",
            "{run} run: the run folder is not private"
        );
        assert!(
            names(&root).is_empty(),
            "{run} run: the run folder was left"
        );
    }

    // A folder planted at a run folder's name is refused, never reused or
    // removed, and no engine starts.
    let marker = engines.join("started");
    let engine = marking(&engines, &marker);
    let planted = root.join("wasmer");
    fs::create_dir(&planted).expect("plant a folder");
    let refusal = refused(run_engine(
        &value,
        Engine::Wasmer,
        &engine,
        &root,
        &TEST_CONTROL,
    ));
    assert!(matches!(refusal.reason, Reason::RunDirExists), "{refusal}");
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: the run folder already exists: the runner makes a new one and never reuses it",
            planted.display()
        )
    );
    assert_eq!(names(&root), ["wasmer"], "the planted folder was removed");
    assert!(names(&planted).is_empty(), "the planted folder changed");
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
    let refusal = refused(run_engine(
        &value,
        Engine::Wasmtime,
        &engine,
        &missing,
        &TEST_CONTROL,
    ));
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
    let refusal = refused(run_engine(
        &value,
        Engine::Wasmtime,
        &engine,
        &file,
        &TEST_CONTROL,
    ));
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
    let result = run_engine(&value, Engine::Wasmtime, &engine, &locked, &TEST_CONTROL);
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
/// wc-010b: `wasmtime` also gets the memory cap for this capsule's manifest,
/// which declares no `resources`, so the Runtime's default 64 MB = 64 × 2^20
/// = 67108864 bytes; `wasmer`'s argv is unchanged (its CLI has no cap flag).
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

    assert_eq!(value.memory_mb(), 64, "this capsule's declared memory_mb");

    for engine_kind in ENGINES {
        let stdout = ran(run_engine(
            &value,
            engine_kind,
            &engine,
            &root,
            &TEST_CONTROL,
        ));
        let module = root.join(engine_kind.name()).join("module.wasm");
        let argv = String::from_utf8(stdout).expect("the argv is UTF-8");
        let cap = match engine_kind {
            Engine::Wasmtime => {
                "-W\nmax-memory-size=67108864,max-memories=1,trap-on-grow-failure=y\n"
            }
            Engine::Wasmer => "",
        };
        assert_eq!(
            argv,
            format!(
                "run\n--invoke\ndigest\n{cap}{}\n1592590337\n",
                module.display()
            ),
            "{engine_kind}: the argv"
        );
        let module_argument = argv.lines().rev().nth(1).expect("the module argument");
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
        assert!(
            names(&root).is_empty(),
            "{engine_kind}: the run folder was left"
        );
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

    let stdout = ran(run_engine(
        &value,
        Engine::Wasmer,
        &engine,
        &root,
        &TEST_CONTROL,
    ));
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
        let stdout = ran(run_engine(
            &value,
            engine_kind,
            &engine,
            &root,
            &TEST_CONTROL,
        ));
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
        let refusal = refused(run_engine(
            &value,
            engine_kind,
            &failing,
            &root,
            &TEST_CONTROL,
        ));
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
        let refusal = refused(run_engine(
            &value,
            engine_kind,
            &missing,
            &root,
            &TEST_CONTROL,
        ));
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

/// Task 039: `run_engine` removes its module file and its run folder once
/// the engine has exited, on every outcome after the folder was made: a
/// success, an engine that fails (`FAILING`, the shell `FAILING_BODY`) and an
/// absolute engine path that does not exist (the folder is made before the
/// start). Each leaves the work root empty, and each outcome's own result or
/// reason is unchanged.
#[test]
fn run_engine_removes_its_run_folder_after_every_outcome() {
    let (_bundle, value) = fixture();
    let engines = TempDir::new("run039-every-engines");
    let engines = canonical(&engines);
    let cat = stand_in(&engines, "cat", CAT_MODULE);
    let failing = stand_in(&engines, "failing", FAILING);
    assert!(FAILING.ends_with(FAILING_BODY), "FAILING runs FAILING_BODY");
    let missing = engines.join("no-such-engine");

    for engine_kind in ENGINES {
        let tmp = TempDir::new("run039-every");
        let root = canonical(&tmp);

        assert_eq!(
            ran(run_engine(&value, engine_kind, &cat, &root, &TEST_CONTROL)),
            MODULE,
            "{engine_kind}: the success"
        );
        assert_eq!(
            recorded(&cat, "entries"),
            b"module.wasm\n",
            "{engine_kind}: the engine did not run in its run folder"
        );
        assert!(
            names(&root).is_empty(),
            "{engine_kind}: a success left {:?}",
            names(&root)
        );

        let refusal = refused(run_engine(
            &value,
            engine_kind,
            &failing,
            &root,
            &TEST_CONTROL,
        ));
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
        assert!(
            names(&root).is_empty(),
            "{engine_kind}: a failed engine left {:?}",
            names(&root)
        );

        let refusal = refused(run_engine(
            &value,
            engine_kind,
            &missing,
            &root,
            &TEST_CONTROL,
        ));
        match &refusal.reason {
            Reason::EngineDidNotStart { engine, error } => {
                assert_eq!(*engine, engine_kind);
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
            }
            _ => panic!("{engine_kind}: {refusal}"),
        }
        assert_eq!(
            refusal.to_string(),
            format!(
                "{}: {engine_kind} did not start: {NOT_FOUND}",
                missing.display()
            )
        );
        assert!(
            names(&root).is_empty(),
            "{engine_kind}: an engine that did not start left {:?}",
            names(&root)
        );
    }
}

/// Task 039: a stand-in that, during its run, writes one extra file into its
/// own run folder. After a success the run is refused with the removal reason
/// and the run folder's path; only the runner's own module file is deleted,
/// and the extra file and the folder stay. A stand-in that puts a folder at
/// the module file's path is refused at that path, and the folder it put
/// there stays. After an engine failure the failure stays the answer and the
/// failed removal is not reported (README's known limit).
#[test]
fn run_folder_that_cannot_be_removed_is_refused() {
    let (_bundle, value) = fixture();
    let engines = TempDir::new("run039-kept-engines");
    let engines = canonical(&engines);
    let extra = stand_in(
        &engines,
        "extra",
        &format!("#!/bin/sh\n{MODULE_ARGUMENT}: > \"${{module%/*}}/extra\"\nprintf same\n"),
    );
    let swapped = stand_in(
        &engines,
        "swapped",
        &format!("#!/bin/sh\n{MODULE_ARGUMENT}/bin/rm \"$module\"\n/bin/mkdir \"$module\"\nprintf same\n"),
    );
    let extra_failing = stand_in(
        &engines,
        "extra-failing",
        &format!("#!/bin/sh\n{MODULE_ARGUMENT}: > \"${{module%/*}}/extra\"\n{FAILING_BODY}"),
    );

    for engine_kind in ENGINES {
        let tmp = TempDir::new("run039-kept");
        let root = canonical(&tmp);
        let run_dir = root.join(engine_kind.name());
        let refusal = refused(run_engine(
            &value,
            engine_kind,
            &extra,
            &root,
            &TEST_CONTROL,
        ));
        match &refusal.reason {
            Reason::RunDirNotRemoved(error) => assert_eq!(error.raw_os_error(), Some(66)),
            _ => panic!("{engine_kind}: not the removal reason: {refusal}"),
        }
        assert_eq!(refusal.path, run_dir, "{engine_kind}");
        assert_eq!(
            refusal.to_string(),
            format!(
                "{}: the run folder cannot be removed after the engine exited: Directory not empty (os error 66)",
                run_dir.display()
            )
        );
        assert_eq!(
            names(&run_dir),
            ["extra"],
            "{engine_kind}: the extra file was deleted, or the module file was left"
        );
        assert_eq!(names(&root), [engine_kind.name()], "{engine_kind}");

        let tmp = TempDir::new("run039-swapped");
        let root = canonical(&tmp);
        let module = root.join(engine_kind.name()).join("module.wasm");
        let refusal = refused(run_engine(
            &value,
            engine_kind,
            &swapped,
            &root,
            &TEST_CONTROL,
        ));
        match &refusal.reason {
            Reason::RunDirNotRemoved(error) => assert_eq!(error.raw_os_error(), Some(1)),
            _ => panic!("{engine_kind}: not the removal reason: {refusal}"),
        }
        assert_eq!(refusal.path, module, "{engine_kind}");
        assert!(
            module.is_dir() && names(&module).is_empty(),
            "{engine_kind}: the folder at the module file's path was not left as it was"
        );

        let tmp = TempDir::new("run039-kept-failing");
        let root = canonical(&tmp);
        let run_dir = root.join(engine_kind.name());
        let refusal = refused(run_engine(
            &value,
            engine_kind,
            &extra_failing,
            &root,
            &TEST_CONTROL,
        ));
        assert!(
            matches!(refusal.reason, Reason::EngineFailed { .. }),
            "{engine_kind}: the failure is not the answer: {refusal}"
        );
        assert_eq!(refusal.path, extra_failing, "{engine_kind}");
        assert_eq!(names(&run_dir), ["extra"], "{engine_kind}");
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
        let stdout = ran(run_engine(
            &value,
            engine_kind,
            &program,
            &work,
            &TEST_CONTROL,
        ));
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
        ["wasm_capsule_audit", "::audit"].concat(),
        ["audit", "_component"].concat(),
        ["audit", "("].concat(),
        ["checked", "_bundle"].concat(),
        ["verify", "_checked("].concat(),
        ["entries", "()"].concat(),
        ["read", "_grants"].concat(),
        ["parse", "_grants"].concat(),
    ];
    for needle in &forbidden {
        assert!(
            !code.contains(needle.as_str()),
            "the runner reaches past its explicit inputs: {needle}"
        );
    }
    // wc-005b: the two-engine runner verifies once, through wc-004's one
    // verify path. wc-009a: it passes the caller's granted imports unchanged,
    // never an empty list of its own, and reads no grants itself.
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
                "_bundle(input.bundle, input.signature, input.accepted, input.granted)"
            ]
            .concat()
            .as_str()
        )
        .count(),
        1,
        "the runner does not verify its own inputs with the caller's grants"
    );
    assert_eq!(
        code.matches("input.granted").count(),
        1,
        "the runner uses the granted imports somewhere other than its verify call"
    );
    // Task 033: the module's bytes come from entrypoint() twice, the module
    // write and the memory check, and nowhere else.
    assert_eq!(
        code.matches(".entrypoint()").count(),
        2,
        "the runner takes the module bytes from entrypoint() other than for its write and its memory check"
    );
    // Task 033: the runner reads the module's memory limits only through the
    // audit crate's `memories`, the lab's one module reader, imported once and
    // called once; it uses nothing else of that crate.
    let audit_crate = ["wasm_capsule", "_audit"].concat();
    assert_eq!(
        code.matches(audit_crate.as_str()).count(),
        1,
        "the runner names the audit crate other than in its one import"
    );
    assert!(
        code.contains(&format!(
            "use {audit_crate}::{{memories, Refusal as AuditRefusal}};"
        )),
        "the runner imports more or less of the audit crate than memories and its refusal"
    );
    assert_eq!(
        code.matches(["memories", "("].concat().as_str()).count(),
        1,
        "the runner reads the module's memory limits more or less than once"
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
        granted: &[],
        wasmtime,
        wasmer,
        work_root,
        control: &TEST_CONTROL,
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

/// The version a stand-in made by [`marked`], [`recording`] or [`counting`]
/// prints: its engine's pinned version, from the tools crate's constants, with
/// a ` (stand-in)` tail, so it passes the pin check (task 038) and is never a
/// real engine's line. `name` is the engine's name, or `<engine>-<case>`.
fn stand_in_version(name: &str) -> String {
    let engine_name = name.split('-').next().unwrap_or(name);
    let pinned = match engine_name {
        "wasmtime" => WASMTIME_VERSION,
        "wasmer" => WASMER_VERSION,
        _ => panic!("the stand-in {name} names no engine"),
    };
    format!("{engine_name} {pinned} (stand-in)")
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
/// in `log`; started for a module run, it writes every argument it was given,
/// one per line, to `<name>.argv` in `folder` (see [`logged_argv`]), records
/// its run folder ([`RECORD_RUN_FOLDER`]), records in `log` that it started,
/// with the module path it was given, waits, records that it ended, then
/// prints `output`. Two engines that overlap leave their lines interleaved in
/// `log`.
fn recording(folder: &Path, name: &str, log: &Path, output: &str) -> PathBuf {
    let version = format!(
        "printf 'version {name}\\n' >> '{log}'\nprintf '%s\\n' '{version}'\n",
        log = log.display(),
        version = stand_in_version(name)
    );
    let body = format!(
        "printf '%s\\n' \"$@\" > '{argv}'\n{MODULE_ARGUMENT}{RECORD_RUN_FOLDER}printf 'start {name} %s\\n' \"$module\" >> '{log}'\n/bin/sleep 0.5\nprintf 'end {name}\\n' >> '{log}'\nprintf '{output}'\n",
        argv = folder.join(format!("{name}.argv")).display(),
        log = log.display()
    );
    engine(folder, name, &version, &body)
}

/// The argv the stand-in `name` made by [`recording`] in `folder` was given
/// for its module run, one argument per entry.
fn logged_argv(folder: &Path, name: &str) -> Vec<String> {
    let path = folder.join(format!("{name}.argv"));
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .lines()
        .map(str::to_owned)
        .collect()
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
        granted: &[],
        wasmtime: &programs[0],
        wasmer: &programs[1],
        work_root: &work,
        control: &TEST_CONTROL,
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
    assert!(
        names(&work).is_empty(),
        "task 039: the run folders were left: {:?}",
        names(&work)
    );
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
            granted: &[],
            wasmtime: &wasmtime,
            wasmer: &wasmer,
            work_root: &work,
            control: &TEST_CONTROL,
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
        assert!(names(&work).is_empty(), "{case}: a run folder was left");
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
    assert!(names(&work).is_empty(), "a run folder was left");
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
        } else {
            assert!(
                started(&engines, "wasmtime"),
                "{case}: wasmtime did not run"
            );
        }
        assert!(names(&work).is_empty(), "{case}: a run folder was left");
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
    assert_eq!(
        names(&work),
        ["wasmer"],
        "wasmtime's run folder was left, or the planted folder was removed"
    );
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
    // Each run folder as its engine saw it; task 039: both are removed.
    for (engine_kind, program) in [(Engine::Wasmtime, &wasmtime), (Engine::Wasmer, &wasmer)] {
        assert_eq!(
            recorded(program, "module"),
            MODULE,
            "{engine_kind}: the run folder did not hold the verified bytes"
        );
    }
    assert!(names(&work).is_empty(), "a run folder was left");
}

/// Task 039: a two-engine `run` on stand-ins that succeeds, and one refused
/// because `wasmer` fails after `wasmtime` ran, each leave the work root
/// empty: both engines ran in their own run folder, and neither folder is
/// left.
#[test]
fn run_leaves_an_empty_work_root() {
    let signed = signed_fixture();
    let tmp = TempDir::new("run039-empty-root");
    let root = canonical(&tmp);
    for (case, wasmer_body) in [("passes", "printf same\n"), ("wasmer-fails", FAILING_BODY)] {
        let engines = work_root(&root, &format!("engines-{case}"));
        let wasmtime = marked(&engines, "wasmtime", "printf same\n");
        let wasmer = marked(&engines, "wasmer", wasmer_body);
        let work = work_root(&root, &format!("work-{case}"));

        let result = run(&input(&signed, &wasmtime, &wasmer, &work));
        match (case, &result) {
            ("passes", Ok(passed)) => assert_eq!(passed.stdout(Engine::Wasmer), b"same"),
            (
                "wasmer-fails",
                Err(TwoEngineRefusal::Engine(Refusal {
                    reason: Reason::EngineFailed { engine, .. },
                    ..
                })),
            ) => assert_eq!(*engine, Engine::Wasmer),
            _ => panic!("{case}: not the expected answer: {result:?}"),
        }
        for engine_kind in ENGINES {
            assert!(
                started(&engines, engine_kind.name()),
                "{case}: {engine_kind} did not run"
            );
        }
        assert!(
            names(&work).is_empty(),
            "{case}: the work root holds {:?}",
            names(&work)
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
/// and `module <module path>` for a module run, which records its run folder
/// ([`RECORD_RUN_FOLDER`]) and prints `same`.
fn counting(folder: &Path, name: &str) -> PathBuf {
    engine(
        folder,
        name,
        &format!(
            "printf 'version\\n' >> \"$0.starts\"\nprintf '%s\\n' '{}'\n",
            stand_in_version(name)
        ),
        &format!("{MODULE_ARGUMENT}{RECORD_RUN_FOLDER}printf 'module %s\\n' \"$module\" >> \"$0.starts\"\nprintf 'same\\n'\n"),
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
            ran(run_engine(
                &value,
                engine_kind,
                &program,
                &work,
                &TEST_CONTROL
            )),
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
    assert_eq!(RECEIPT_SCHEMA, "wc-005.run-receipt/v2");

    // Two runs of the same bundle, by stand-ins that print the pinned versions
    // with made-up tails (task 038: only the pinned versions run), each
    // followed by a second line that is not kept. No tail is a real engine's.
    let mut runs = Vec::new();
    for (case, wasmtime_version, wasmer_version) in [
        (
            "first",
            "wasmtime 45.0.1 (abc1234 2099-01-01)",
            "wasmer 7.5.0 (made-up)",
        ),
        ("second", "wasmtime 45.0.1 other", "wasmer 7.5.0 other"),
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
                "schema: wc-005.run-receipt/v2\n\
                 bundle: {name}\n\
                 function: digest\n\
                 argument: 1592590337\n\
                 wasmtime_version: \"{wasmtime_version}\"\n\
                 wasmtime_status: exit status: 0\n\
                 wasmtime_stdout: \"4242\\n\"\n\
                 wasmer_version: \"{wasmer_version}\"\n\
                 wasmer_status: exit status: 0\n\
                 wasmer_stdout: \"4242\\n\"\n\
                 memory_mb: 64\n\
                 memory_cap_bytes: 67108864\n\
                 wasmtime_memory_cap: ENFORCED max-memory-size=67108864,max-memories=1,trap-on-grow-failure=y\n\
                 {WASMER_SKIPPED}\n"
            ),
            "{case}: the receipt"
        );
        // This Mac's installed engines' lines, each as the receipt would quote
        // it, and the second line: no stand-in printed any as its version.
        for installed in [
            "\"wasmtime 45.0.1 (83166ba31 2026-06-05)\"",
            "\"wasmer 7.5.0\"",
            "second line",
        ] {
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

    // Each version answer is the stand-in's pinned version (task 038), then
    // the program path it was started by, HOME as it saw it, and whether its
    // stdin is /dev/null.
    let report = |engine_kind: Engine| {
        format!(
            "if [ /dev/stdin -ef /dev/null ]; then stdin=null; else stdin=other; fi\n\
             printf '{} %s %s %s\\n' \"$0\" \"${{HOME-unset}}\" \"$stdin\"\n",
            stand_in_version(engine_kind.name())
        )
    };
    let engines = work_root(&root, "engines");
    let wasmtime = engine(
        &engines,
        "wasmtime",
        &report(Engine::Wasmtime),
        "printf same\n",
    );
    let wasmer = engine(&engines, "wasmer", &report(Engine::Wasmer), "printf same\n");
    let work = work_root(&root, "work");
    let passed = two_ran(run(&input(&signed, &wasmtime, &wasmer, &work)));
    for (engine_kind, program) in [(Engine::Wasmtime, &wasmtime), (Engine::Wasmer, &wasmer)] {
        assert_eq!(
            String::from_utf8_lossy(passed.version(engine_kind)),
            format!(
                "{} {} unset null",
                stand_in_version(engine_kind.name()),
                program.display()
            ),
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
        granted: &[],
        wasmtime: &programs[0],
        wasmer: &programs[1],
        work_root: &work,
        control: &TEST_CONTROL,
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
            "schema: wc-005.run-receipt/v2".to_string(),
            format!("bundle: {name}"),
            "function: digest".to_string(),
            format!("argument: {FIXED_INPUT}"),
        ]
    );
    // wc-010c: this capsule declares no `resources`, so the Runtime's default
    // 64 MB = 67108864 bytes; the real wasmtime ran under that cap, wasmer
    // under none.
    assert_eq!(
        lines[10..],
        [
            "memory_mb: 64",
            "memory_cap_bytes: 67108864",
            "wasmtime_memory_cap: ENFORCED max-memory-size=67108864,max-memories=1,trap-on-grow-failure=y",
            WASMER_SKIPPED,
        ]
    );
    eprintln!("RECEIPT (this machine):\n{receipt}");
    eprintln!("PASS: the receipt names both installed engines' versions as they printed them");
}

/// The folders of one wc-009a run made by [`run_with_grants`]: both
/// [`counting`] stand-ins and the work root.
struct GrantsRun {
    wasmtime: PathBuf,
    wasmer: PathBuf,
    work: PathBuf,
}

/// One wc-009a run: `module`, bundled with this capsule's manifest in `root`,
/// signed with a fresh key, run through `run` with the grants that
/// `read_grants` reads from a new lab grants file beside the bundle, never
/// inside it, on [`counting`] stand-ins. Each `case` gets its own folders.
fn run_with_grants(
    root: &Path,
    case: &str,
    module: &[u8],
    grants: &[(&str, &str, &str)],
) -> (Result<TwoEngineRun, TwoEngineRefusal>, GrantsRun) {
    let key = fresh_key();
    let (bundle, sig) = signed_bundle(root, &format!("bundle-{case}"), module, &key);
    let accepted = [did(&key)];
    let grants_path = grants_file(root, &format!("grants-{case}.json"), grants);
    let granted = read_grants(&grants_path)
        .unwrap_or_else(|refusal| panic!("{case}: the grants file was refused: {refusal}"));
    let engines = work_root(root, &format!("engines-{case}"));
    let folders = GrantsRun {
        wasmtime: counting(&engines, "wasmtime"),
        wasmer: counting(&engines, "wasmer"),
        work: work_root(root, &format!("work-{case}")),
    };
    let result = run(&RunInput {
        bundle: &bundle,
        signature: Some(&sig),
        accepted: &accepted,
        granted: &granted,
        wasmtime: &folders.wasmtime,
        wasmer: &folders.wasmer,
        work_root: &folders.work,
        control: &TEST_CONTROL,
    });
    (result, folders)
}

/// Each engine of `ran` was asked `--version` `count` times and started for a
/// module run `count` times: one of each per engine when the run passed, none
/// of either when it was refused.
fn assert_engine_starts(ran: &GrantsRun, count: usize, case: &str) {
    for (engine_kind, program) in [
        (Engine::Wasmtime, &ran.wasmtime),
        (Engine::Wasmer, &ran.wasmer),
    ] {
        assert_eq!(
            starts(program, "version"),
            count,
            "{case}: {engine_kind}'s --version queries"
        );
        assert_eq!(
            starts(program, "module"),
            count,
            "{case}: {engine_kind}'s module runs"
        );
    }
}

/// The capsule `tools/build` makes, built into a new OUT_DIR under `root`.
fn built_capsule(root: &Path) -> Vec<u8> {
    let out = root.join("out");
    fs::create_dir(&out).expect("create OUT_DIR");
    run_build(&lane_dir(), &out);
    fs::read(out.join("capsule.wasm")).expect("read the built capsule.wasm")
}

/// wc-009a, Rong's test: the capsule `tools/build` makes, signed, with an
/// empty grants file: each engine is asked its version once and runs the
/// module once, nothing is linked and no grant is unused.
#[test]
fn zero_grants_zero_imports_runs() {
    let tmp = TempDir::new("run9-zero");
    let root = canonical(&tmp);
    let built = built_capsule(&root);

    let (result, ran) = run_with_grants(&root, "zero", &built, &[]);
    let passed = two_ran(result);
    assert!(passed.linked().is_empty(), "linked: {:?}", passed.linked());
    assert!(
        passed.unused_grants().is_empty(),
        "unused: {:?}",
        passed.unused_grants()
    );
    assert_engine_starts(&ran, 1, "zero");
    assert!(names(&ran.work).is_empty(), "a run folder was left");
}

/// wc-009a, the real-engine variant of `zero_grants_zero_imports_runs`: the
/// real `wasmtime` and `wasmer` on PATH print `FIXED_OUTPUT`, with nothing
/// linked. An engine not found prints SKIPPED and gives no result.
#[test]
fn zero_grants_zero_imports_runs_on_both_real_engines() {
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
            "SKIPPED: {} not found on PATH; the zero-grants real run needs both (no result, not a PASS)",
            missing.join(" and ")
        );
        return;
    }
    let tmp = TempDir::new("run9-zero-real");
    let root = canonical(&tmp);
    let built = built_capsule(&root);
    let key = fresh_key();
    let (bundle, sig) = signed_bundle(&root, "bundle", &built, &key);
    let accepted = [did(&key)];
    let grants = grants_file(&root, "grants.json", &[]);
    let granted = read_grants(&grants).expect("read the empty grants file");
    let work = work_root(&root, "work");

    let passed = two_ran(run(&RunInput {
        bundle: &bundle,
        signature: Some(&sig),
        accepted: &accepted,
        granted: &granted,
        wasmtime: &programs[0],
        wasmer: &programs[1],
        work_root: &work,
        control: &TEST_CONTROL,
    }));
    let expected = format!("{FIXED_OUTPUT}\n");
    for engine_kind in ENGINES {
        assert_eq!(
            passed.stdout(engine_kind),
            expected.as_bytes(),
            "{engine_kind}"
        );
    }
    assert!(passed.linked().is_empty(), "linked: {:?}", passed.linked());
    assert!(passed.unused_grants().is_empty());
    eprintln!("PASS: zero grants, zero imports: both engines printed {FIXED_OUTPUT}");
}

/// wc-009a, Rong's test: the signed module that imports `env.f`, with an
/// empty grants file, is refused by the verifier by the import's name; no run
/// folder is made and no engine is started, not even for `--version`.
#[test]
fn declared_not_granted_import_refuses_instantiation_by_name() {
    let tmp = TempDir::new("run9-not-granted");
    let root = canonical(&tmp);

    let (result, ran) = run_with_grants(&root, "not-granted", IMPORTING_MODULE, &[]);
    let refusal = two_refused(result);
    assert_eq!(refusal.to_string(), "undeclared import env.f");
    match refusal {
        TwoEngineRefusal::Verify(reason) => assert_eq!(
            reason,
            VerifyRefusal::Audit(AuditRefusal::Undeclared {
                module: "env".into(),
                name: "f".into(),
            })
        ),
        other => panic!("not a verifier refusal: {other}"),
    }
    assert!(names(&ran.work).is_empty(), "a run folder was made");
    assert_engine_starts(&ran, 0, "not-granted");
}

/// wc-009a, Rong's test: a validly signed zero-import bundle with an empty
/// grants file links nothing.
#[test]
fn valid_signature_with_empty_grants_file_links_nothing() {
    let tmp = TempDir::new("run9-empty");
    let root = canonical(&tmp);

    let (result, ran) = run_with_grants(&root, "empty", MODULE, &[]);
    let passed = two_ran(result);
    assert!(passed.linked().is_empty(), "linked: {:?}", passed.linked());
    assert!(passed.unused_grants().is_empty());
    assert_engine_starts(&ran, 1, "empty");
}

/// wc-009a, Rong's rename of `granted_but_undeclared_is_refused`: a grant for
/// an import the module does not have links nothing and is reported.
#[test]
fn grant_for_an_import_the_module_does_not_have_links_nothing_and_is_reported() {
    let tmp = TempDir::new("run9-unused");
    let root = canonical(&tmp);

    let (result, ran) = run_with_grants(&root, "unused", MODULE, &[("env", "f", "call")]);
    let passed = two_ran(result);
    assert_eq!(passed.linked(), [], "a grant was linked with no import");
    assert_eq!(passed.unused_grants(), [env_f()], "the unused grant");
    assert_engine_starts(&ran, 1, "unused");
}

/// wc-009a: the signed module that imports `env.f`, with `env.f` granted,
/// passes verification and `env.f` is linked; each engine is asked its
/// version once and runs the module once. The stand-ins host nothing: the
/// runner gives no engine a host function yet (wc-009b).
#[test]
fn granted_import_is_linked() {
    let tmp = TempDir::new("run9-linked");
    let root = canonical(&tmp);

    let (result, ran) = run_with_grants(&root, "linked", IMPORTING_MODULE, &[("env", "f", "call")]);
    let passed = two_ran(result);
    assert_eq!(passed.linked(), [env_f()], "the linked imports");
    assert!(passed.unused_grants().is_empty());
    assert_engine_starts(&ran, 1, "linked");
    // Each run folder as its engine saw it; task 039: both are removed.
    for (engine_kind, program) in [
        (Engine::Wasmtime, &ran.wasmtime),
        (Engine::Wasmer, &ran.wasmer),
    ] {
        assert_eq!(
            recorded(program, "module"),
            IMPORTING_MODULE,
            "{engine_kind}: not the verified importing module"
        );
    }
    assert!(names(&ran.work).is_empty(), "a run folder was left");
}

/// Task 031: the signed module that imports `env.g`, which has no typed lab
/// operation, is refused by the verifier with `env.g` granted, by the import's
/// name; with no grant, the audit still refuses it as undeclared. Either way no
/// run folder is made and no engine is started, not even for `--version`.
#[test]
fn module_import_with_no_typed_operation_is_refused() {
    let tmp = TempDir::new("run31-untyped");
    let root = canonical(&tmp);
    let module = importing_env(b'g');

    let (result, ran) = run_with_grants(&root, "untyped", &module, &[("env", "g", "call")]);
    let refusal = two_refused(result);
    assert_eq!(
        refusal.to_string(),
        "no typed lab operation for import env.g"
    );
    match refusal {
        TwoEngineRefusal::Verify(reason) => assert_eq!(
            reason,
            VerifyRefusal::UntypedImport {
                module: "env".into(),
                name: "g".into(),
            }
        ),
        other => panic!("not a verifier refusal: {other}"),
    }
    assert!(names(&ran.work).is_empty(), "a run folder was made");
    assert_engine_starts(&ran, 0, "untyped");

    let (result, ran) = run_with_grants(&root, "untyped-not-granted", &module, &[]);
    let refusal = two_refused(result);
    assert_eq!(refusal.to_string(), "undeclared import env.g");
    match refusal {
        TwoEngineRefusal::Verify(reason) => assert_eq!(
            reason,
            VerifyRefusal::Audit(AuditRefusal::Undeclared {
                module: "env".into(),
                name: "g".into(),
            })
        ),
        other => panic!("not a verifier refusal: {other}"),
    }
    assert!(names(&ran.work).is_empty(), "a run folder was made");
    assert_engine_starts(&ran, 0, "untyped-not-granted");
}

/// wc-010b, task 033: a hand-written core module, as bytes: one memory of 1
/// page with a maximum of 1024 pages, 64 MB, this capsule's declared size, no
/// import, and one export, `digest (i32) -> i32`, that ignores its argument
/// and runs `memory.grow` by the constant `delta` (two signed LEB128 bytes),
/// returning what `memory.grow` returns: the old size in pages, 1, on
/// success, or -1 on failure.
fn grow_module(delta: [u8; 2]) -> Vec<u8> {
    memory_module(&MAXIMUM_1024, delta)
}

/// [`grow_module`]'s module with one memory whose limits are `limits`, as
/// encoded: the limits flag (0x00 minimum only, 0x01 minimum and maximum),
/// then the minimum and any maximum in pages, each LEB128.
fn memory_module(limits: &[u8], delta: [u8; 2]) -> Vec<u8> {
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    // Type section: one type, (i32) -> (i32).
    module.extend_from_slice(&[0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f]);
    // Function section: one function, of type 0.
    module.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    // Memory section: one memory, with `limits`.
    let size = u8::try_from(1 + limits.len()).expect("a one-byte section size");
    module.extend_from_slice(&[0x05, size, 0x01]);
    module.extend_from_slice(limits);
    // Export section: "digest", function 0.
    module.extend_from_slice(&[0x07, 0x0a, 0x01, 0x06]);
    module.extend_from_slice(b"digest");
    module.extend_from_slice(&[0x00, 0x00]);
    // Code section: no locals; i32.const delta; memory.grow 0; end.
    module.extend_from_slice(&[0x0a, 0x09, 0x01, 0x07, 0x00, 0x41]);
    module.extend_from_slice(&delta);
    module.extend_from_slice(&[0x40, 0x00, 0x0b]);
    module
}

/// Task 033: memory limits for [`memory_module`]: minimum 1 page, maximum
/// 1024 pages (64 MB, the default declared size).
const MAXIMUM_1024: [u8; 4] = [0x01, 0x01, 0x80, 0x08];

/// Minimum 1 page, maximum 1025 pages: one page over the default 64 MB.
const MAXIMUM_1025: [u8; 4] = [0x01, 0x01, 0x81, 0x08];

/// Minimum 1 page, maximum 32 pages: exactly a declared 2 MB.
const MAXIMUM_32: [u8; 3] = [0x01, 0x01, 0x20];

/// Minimum 1 page, maximum 33 pages: one page over a declared 2 MB.
const MAXIMUM_33: [u8; 3] = [0x01, 0x01, 0x21];

/// Minimum 1 page and no maximum.
const NO_MAXIMUM: [u8; 2] = [0x00, 0x01];

/// 1023 pages as signed LEB128: from 1 page to exactly 1024 pages, 64 MB, the
/// declared cap.
const GROW_TO_THE_CAP: [u8; 2] = [0xff, 0x07];

/// 1024 pages as signed LEB128: from 1 page to 1025 pages, 67174400 bytes, one
/// page past the declared cap.
const GROW_PAST_THE_CAP: [u8; 2] = [0x80, 0x08];

/// This capsule's manifest with `"resources": {"memory_mb": <memory_mb>}`
/// added, the Runtime's own field; nothing else changes.
fn manifest_with_memory_mb(memory_mb: u32) -> Vec<u8> {
    let manifest = std::str::from_utf8(CAPSULE_MANIFEST).expect("the manifest is UTF-8");
    let end = "\"entrypoint\": \"capsule.wasm\"\n}";
    assert_eq!(manifest.matches(end).count(), 1, "the manifest's last key");
    manifest
        .replace(
            end,
            &format!(
                "\"entrypoint\": \"capsule.wasm\",\n  \"resources\": {{\"memory_mb\": {memory_mb}}}\n}}"
            ),
        )
        .into_bytes()
}

/// A new folder `name` in `root` holding [`manifest_with_memory_mb`] and
/// `module` as `capsule.wasm`, signed in memory with a fresh key: its folder,
/// signature and accepted signer, as a `run` needs them.
fn signed_bundle_declaring(root: &Path, name: &str, module: &[u8], memory_mb: u32) -> Declared {
    let bundle = root.join(name);
    fs::create_dir(&bundle).expect("create the bundle folder");
    fs::write(
        bundle.join("capsule.json"),
        manifest_with_memory_mb(memory_mb),
    )
    .expect("write capsule.json");
    fs::write(bundle.join("capsule.wasm"), module).expect("write capsule.wasm");
    let key = fresh_key();
    let sig = sign_bundle(&key, &bundle).expect("sign the bundle");
    Declared {
        bundle,
        sig,
        accepted: vec![did(&key)],
    }
}

/// [`signed_bundle_declaring`]'s bundle, verified; the verified value keeps
/// the declared `memory_mb`.
fn verified_bundle_declaring(
    root: &Path,
    name: &str,
    module: &[u8],
    memory_mb: u32,
) -> VerifiedBundle {
    let signed = signed_bundle_declaring(root, name, module, memory_mb);
    let value = verify_bundle(&signed.bundle, Some(&signed.sig), &signed.accepted, &[])
        .unwrap_or_else(|refusal| panic!("the verifier refused: {refusal}"));
    assert_eq!(value.memory_mb(), memory_mb, "the declared memory_mb");
    value
}

/// A bundle made by [`signed_bundle_declaring`]: its folder, its in-memory
/// name signature and the signer list that accepts it.
struct Declared {
    bundle: PathBuf,
    sig: NameSignature,
    accepted: Vec<String>,
}

impl Declared {
    /// The two-engine runner's input for this bundle, no grants.
    fn input<'a>(
        &'a self,
        wasmtime: &'a Path,
        wasmer: &'a Path,
        work_root: &'a Path,
    ) -> RunInput<'a> {
        RunInput {
            bundle: &self.bundle,
            signature: Some(&self.sig),
            accepted: &self.accepted,
            granted: &[],
            wasmtime,
            wasmer,
            work_root,
            control: &TEST_CONTROL,
        }
    }
}

/// wc-010b: the cap on `wasmtime`'s argv is the manifest's declared
/// `resources.memory_mb` × 2^20, read, not fixed: a bundle that declares 2 MB
/// gives `max-memory-size=2097152`, and one that declares `u32::MAX` gives
/// 4503599626321920 bytes, which only a `u64` product holds. `wasmer`'s argv
/// gets no cap. Stand-in engines; an argv proof.
#[test]
fn declared_memory_cap_comes_from_the_manifest() {
    let engines = TempDir::new("run10-cap-engines");
    let engine = stand_in(&canonical(&engines), "print-args", PRINT_ARGS);
    let tmp = TempDir::new("run10-cap");
    let root = canonical(&tmp);

    for (memory_mb, bytes) in [(2, "2097152"), (u32::MAX, "4503599626321920")] {
        let value =
            verified_bundle_declaring(&root, &format!("bundle-{memory_mb}"), MODULE, memory_mb);

        let work = work_root(&root, &format!("work-{memory_mb}"));
        for engine_kind in ENGINES {
            let stdout = ran(run_engine(
                &value,
                engine_kind,
                &engine,
                &work,
                &TEST_CONTROL,
            ));
            let module = work.join(engine_kind.name()).join("module.wasm");
            let cap = match engine_kind {
                Engine::Wasmtime => {
                    format!("-W\nmax-memory-size={bytes},max-memories=1,trap-on-grow-failure=y\n")
                }
                Engine::Wasmer => String::new(),
            };
            assert_eq!(
                String::from_utf8(stdout).expect("the argv is UTF-8"),
                format!(
                    "run\n--invoke\ndigest\n{cap}{}\n1592590337\n",
                    module.display()
                ),
                "{engine_kind}, memory_mb {memory_mb}: the argv"
            );
        }
    }
}

/// The real `wasmtime` on PATH, by an absolute path, or `None` after a
/// SKIPPED line: an engine not found gives no result, never a PASS.
fn real_wasmtime(test: &str) -> Option<PathBuf> {
    let program = find_engine(Engine::Wasmtime.name());
    if program.is_none() {
        eprintln!("SKIPPED: wasmtime not found on PATH; {test} needs it (no result, not a PASS)");
    }
    program
}

/// wc-010b, real engine: a signed, verified module that grows its memory by
/// 1023 pages, to exactly the declared 64 MB, runs under the cap on
/// `wasmtime`, and `memory.grow` returns the old size, 1.
#[test]
fn capsule_grows_within_the_declared_cap_on_wasmtime() {
    let Some(program) = real_wasmtime("the within-cap run") else {
        return;
    };
    let tmp = TempDir::new("run10-within");
    let root = canonical(&tmp);
    let (_, value) = verified_bundle(&root, "bundle", &grow_module(GROW_TO_THE_CAP));
    assert_eq!(value.memory_mb(), 64);
    let work = work_root(&root, "work");

    let stdout = ran(run_engine(
        &value,
        Engine::Wasmtime,
        &program,
        &work,
        &TEST_CONTROL,
    ));
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        "1\n",
        "wasmtime ({}): the grow to the cap did not succeed",
        program.display()
    );
    eprintln!("PASS: wasmtime grew to the declared 64 MB cap and printed 1");
}

/// wc-010b, real engine: a signed, verified module that grows its memory by
/// 1024 pages, one page past the declared 64 MB, is refused on `wasmtime`: the
/// grow traps, so the engine fails with its trap on stderr.
#[test]
fn memory_grow_past_the_declared_cap_traps_on_wasmtime() {
    let Some(program) = real_wasmtime("the past-cap run") else {
        return;
    };
    let tmp = TempDir::new("run10-past");
    let root = canonical(&tmp);
    let (_, value) = verified_bundle(&root, "bundle", &grow_module(GROW_PAST_THE_CAP));
    assert_eq!(value.memory_mb(), 64);
    let work = work_root(&root, "work");

    let refusal = refused(run_engine(
        &value,
        Engine::Wasmtime,
        &program,
        &work,
        &TEST_CONTROL,
    ));
    match &refusal.reason {
        Reason::EngineFailed {
            engine,
            status,
            stderr,
        } => {
            assert_eq!(*engine, Engine::Wasmtime);
            assert!(!status.success(), "a failed run exited 0");
            assert!(
                stderr.contains("forcing trap when growing memory to 67174400 bytes"),
                "wasmtime ({}) did not trap on the grow past the cap: {stderr}",
                program.display()
            );
        }
        _ => panic!("not an engine failure: {refusal}"),
    }
    eprintln!("PASS: wasmtime trapped on the grow past the declared 64 MB cap");
}

/// wc-010b, task 033: a hand-written core module, as bytes: two memories of
/// 32 pages (2 MB) each with a maximum of 32 pages, no import, and one export,
/// `digest (i32) -> i32`, that ignores its argument and returns `memory.size
/// 0 + memory.size 1`, 64 pages. Each memory alone fits a 2 MB cap; together
/// they are twice it.
const TWO_MEMORY_MODULE: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
    0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, // type: (i32) -> (i32)
    0x03, 0x02, 0x01, 0x00, // function: one, of type 0
    0x05, 0x07, 0x02, // memory: two,
    0x01, 0x20, 0x20, 0x01, 0x20, 0x20, // each minimum 32 pages, maximum 32 pages
    0x07, 0x0a, 0x01, 0x06, b'd', b'i', b'g', b'e', b's', b't', 0x00, 0x00, // export "digest"
    0x0a, 0x09, 0x01, 0x07, 0x00, // code: one body, no locals
    0x3f, 0x00, 0x3f, 0x01, 0x6a, 0x0b, // memory.size 0; memory.size 1; i32.add; end
];

/// Task 033: a bundle of `module` in `root`, signed with a fresh key, that
/// declares `memory_mb`, or, with none, carries this capsule's manifest as it
/// is, so it declares the Runtime's default, 64.
fn declaring(root: &Path, name: &str, module: &[u8], memory_mb: Option<u32>) -> Declared {
    match memory_mb {
        Some(memory_mb) => signed_bundle_declaring(root, name, module, memory_mb),
        None => {
            let key = fresh_key();
            let (bundle, sig) = signed_bundle(root, name, module, &key);
            Declared {
                bundle,
                sig,
                accepted: vec![did(&key)],
            }
        }
    }
}

/// Task 033: `module`, bundled by [`declaring`] in `root`, through
/// `run_engine` on `wasmtime` and on `wasmer`, then through `run`, all on
/// [`marked`] stand-ins of `case`'s own. Every answer must be a refusal at the
/// entrypoint's path in the bundle, `capsule.wasm`, that prints exactly
/// `capsule.wasm: <text>`; `run`'s comes as `TwoEngineRefusal::Memory`. No
/// run folder is made in any of the three work roots, and neither stand-in is
/// started for a module run or asked `--version`. Returns the three reasons,
/// `run_engine`'s two then `run`'s.
fn refused_for_memory(
    root: &Path,
    case: &str,
    module: &[u8],
    memory_mb: Option<u32>,
    text: &str,
) -> Vec<Reason> {
    let signed = declaring(root, &format!("bundle-{case}"), module, memory_mb);
    let value = verify_bundle(&signed.bundle, Some(&signed.sig), &signed.accepted, &[])
        .unwrap_or_else(|refusal| panic!("{case}: the verifier refused: {refusal}"));
    let engines = work_root(root, &format!("engines-{case}"));
    let wasmtime = marked(&engines, "wasmtime", "printf 'same\\n'\n");
    let wasmer = marked(&engines, "wasmer", "printf 'same\\n'\n");
    let expected = format!("capsule.wasm: {text}");

    let mut reasons = Vec::new();
    for (engine_kind, program) in [(Engine::Wasmtime, &wasmtime), (Engine::Wasmer, &wasmer)] {
        let work = work_root(root, &format!("work-{case}-{engine_kind}"));
        let refusal = refused(run_engine(
            &value,
            engine_kind,
            program,
            &work,
            &TEST_CONTROL,
        ));
        assert_eq!(
            refusal.path,
            Path::new("capsule.wasm"),
            "{case}, {engine_kind}"
        );
        assert_eq!(refusal.to_string(), expected, "{case}, {engine_kind}");
        assert!(
            names(&work).is_empty(),
            "{case}, {engine_kind}: a run folder was made"
        );
        reasons.push(refusal.reason);
    }

    let work = work_root(root, &format!("work-{case}-run"));
    let refusal = match two_refused(run(&signed.input(&wasmtime, &wasmer, &work))) {
        TwoEngineRefusal::Memory(refusal) => refusal,
        other => panic!("{case}: run did not refuse the module's memory: {other}"),
    };
    assert_eq!(refusal.path, Path::new("capsule.wasm"), "{case}, run");
    assert_eq!(refusal.to_string(), expected, "{case}, run");
    assert!(
        names(&work).is_empty(),
        "{case}, run: a run folder was made"
    );
    reasons.push(refusal.reason);

    for name in ["wasmtime", "wasmer"] {
        assert!(
            !started(&engines, name),
            "{case}: {name} was started for a module run"
        );
        assert!(
            !queried(&engines, name),
            "{case}: {name} was asked --version"
        );
    }
    reasons
}

/// Task 033 (M1 C0 lab half): a module whose one memory declares no maximum
/// (minimum 1 page) is refused, by `run_engine` on both engines and by `run`,
/// before any engine process starts: no engine applies the declared size to
/// it, and it is never run uncapped. Stand-in engines.
#[test]
fn run_refuses_a_module_memory_with_no_maximum_on_both_engines() {
    let tmp = TempDir::new("run33-no-max");
    let root = canonical(&tmp);
    let module = memory_module(&NO_MAXIMUM, GROW_TO_THE_CAP);
    let reasons = refused_for_memory(
        &root,
        "no-max",
        &module,
        None,
        "the module's memory (minimum 1 × 64 KiB) declares no maximum: the module is not run uncapped",
    );
    assert_eq!(reasons.len(), 3);
    for reason in &reasons {
        assert!(
            matches!(reason, Reason::MemoryMaximumMissing { minimum: 1 }),
            "not MemoryMaximumMissing: {reason}"
        );
    }
}

/// Task 033: a memory maximum above the declared size is refused before any
/// engine process starts, by `run_engine` on both engines and by `run`: 33
/// pages under a declared 2 MB (32 pages), and 1025 pages under this
/// capsule's default 64 MB (1024 pages), each one page over. Stand-in engines.
#[test]
fn run_refuses_a_memory_maximum_above_the_declared_size_on_both_engines() {
    let tmp = TempDir::new("run33-above");
    let root = canonical(&tmp);
    let cases: [(&str, &[u8], Option<u32>, u64, u32, &str); 2] = [
        (
            "two-mb",
            &MAXIMUM_33,
            Some(2),
            33,
            2,
            "the module's memory maximum, 33 × 64 KiB, is above the declared 2 MB (32 × 64 KiB): the module is not run uncapped",
        ),
        (
            "default",
            &MAXIMUM_1025,
            None,
            1025,
            64,
            "the module's memory maximum, 1025 × 64 KiB, is above the declared 64 MB (1024 × 64 KiB): the module is not run uncapped",
        ),
    ];
    for (case, limits, declared, pages, memory_mb, text) in cases {
        let module = memory_module(limits, GROW_TO_THE_CAP);
        let reasons = refused_for_memory(&root, case, &module, declared, text);
        assert_eq!(reasons.len(), 3, "{case}");
        for reason in &reasons {
            assert!(
                matches!(
                    reason,
                    Reason::MemoryMaximumAboveDeclared { maximum, memory_mb: declared_mb }
                        if *maximum == pages && *declared_mb == memory_mb
                ),
                "{case}: not MemoryMaximumAboveDeclared {{ {pages}, {memory_mb} }}: {reason}"
            );
        }
    }
}

/// Task 033: the declared size caps the capsule's whole linear memory. A
/// module that declares 2 MB and has two memories, each with a maximum of 32
/// pages (2 MB), so 4 MB together, is refused with the more-than-one-memory
/// reason by `run_engine` on both engines and by `run`, before any engine
/// process starts. Stand-in engines; before task 033 this module reached
/// wasmtime, which refused it at start under `max-memories=1`.
#[test]
fn run_refuses_a_second_memory_before_any_engine_start() {
    let tmp = TempDir::new("run33-two-memories");
    let root = canonical(&tmp);
    let reasons = refused_for_memory(
        &root,
        "two-memories",
        TWO_MEMORY_MODULE,
        Some(2),
        "the module has 2 memories: the declared size caps one linear memory, so the module is not run uncapped",
    );
    assert_eq!(reasons.len(), 3);
    for reason in &reasons {
        assert!(
            matches!(reason, Reason::MemoryCountAboveOne { count: 2 }),
            "not MemoryCountAboveOne: {reason}"
        );
    }
}

/// Task 033: a module whose one memory's maximum is exactly the declared size
/// (32 pages under a declared 2 MB), and the zero-memory `MODULE`, which has no
/// linear memory to grow, both still run as before: through `run_engine` on
/// both stand-in engines, then through `run`, each module run started once and
/// each engine asked `--version` once, by `run`.
#[test]
fn run_starts_a_module_whose_maximum_fits_the_declared_size() {
    let tmp = TempDir::new("run33-fits");
    let root = canonical(&tmp);
    let fits = memory_module(&MAXIMUM_32, GROW_TO_THE_CAP);
    for (case, module, memory_mb) in [("fits", &fits[..], Some(2)), ("no-memory", MODULE, None)] {
        let signed = declaring(&root, &format!("bundle-{case}"), module, memory_mb);
        let value = verify_bundle(&signed.bundle, Some(&signed.sig), &signed.accepted, &[])
            .unwrap_or_else(|refusal| panic!("{case}: the verifier refused: {refusal}"));
        let engines = work_root(&root, &format!("engines-{case}"));
        let wasmtime = counting(&engines, "wasmtime");
        let wasmer = counting(&engines, "wasmer");
        for (engine_kind, program) in [(Engine::Wasmtime, &wasmtime), (Engine::Wasmer, &wasmer)] {
            let work = work_root(&root, &format!("work-{case}-{engine_kind}"));
            let stdout = ran(run_engine(
                &value,
                engine_kind,
                program,
                &work,
                &TEST_CONTROL,
            ));
            assert_eq!(stdout, b"same\n", "{case}, {engine_kind}");
        }
        let work = work_root(&root, &format!("work-{case}-run"));
        let passed = two_ran(run(&signed.input(&wasmtime, &wasmer, &work)));
        assert_eq!(passed.wasmtime(), b"same\n", "{case}");
        assert_eq!(passed.wasmer(), b"same\n", "{case}");
        for program in [&wasmtime, &wasmer] {
            assert_eq!(
                starts(program, "module"),
                2,
                "{case}: {}",
                program.display()
            );
            assert_eq!(
                starts(program, "version"),
                1,
                "{case}: {}",
                program.display()
            );
        }
    }
}

/// Task 033, real engine: [`grow_module`]'s maximum is 1024 pages, this
/// capsule's declared 64 MB, so `run_engine` starts it on `wasmer`, which has
/// no cap flag; a grow to exactly that maximum succeeds and `memory.grow`
/// returns the old size, 1.
#[test]
fn capsule_grows_within_its_module_maximum_on_wasmer() {
    let Some(program) = real_wasmer("the within-maximum run") else {
        return;
    };
    let tmp = TempDir::new("run33-wasmer-within");
    let root = canonical(&tmp);
    let (_, value) = verified_bundle(&root, "bundle", &grow_module(GROW_TO_THE_CAP));
    assert_eq!(value.memory_mb(), 64);
    let work = work_root(&root, "work");

    let stdout = ran(run_engine(
        &value,
        Engine::Wasmer,
        &program,
        &work,
        &TEST_CONTROL,
    ));
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        "1\n",
        "wasmer ({}): the grow to the module's maximum did not succeed",
        program.display()
    );
    eprintln!("PASS: wasmer grew to the module's 1024-page maximum and printed 1");
}

/// Task 033, real engine: on `wasmer`, which has no cap flag, the cap is the
/// module's own maximum (task 030, row m2): a grow one page past
/// [`grow_module`]'s 1024 pages fails, `memory.grow` returns -1, and the
/// engine exits 0 with `-1` as its output.
#[test]
fn memory_grow_past_the_module_maximum_returns_minus_one_on_wasmer() {
    let Some(program) = real_wasmer("the past-maximum run") else {
        return;
    };
    let tmp = TempDir::new("run33-wasmer-past");
    let root = canonical(&tmp);
    let (_, value) = verified_bundle(&root, "bundle", &grow_module(GROW_PAST_THE_CAP));
    assert_eq!(value.memory_mb(), 64);
    let work = work_root(&root, "work");

    let stdout = ran(run_engine(
        &value,
        Engine::Wasmer,
        &program,
        &work,
        &TEST_CONTROL,
    ));
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        "-1\n",
        "wasmer ({}): the grow past the module's maximum did not return -1",
        program.display()
    );
    eprintln!("PASS: wasmer returned -1 to a grow past the module's 1024-page maximum");
}

/// Task 032 (M1 C0 step ii): the capsule `tools/build` makes declares its own
/// memory maximum, which both engines apply with no flag (README, wc-010d0).
/// It defines exactly one memory and imports none, and that memory's maximum
/// in bytes is the declared `memory_mb` × 2^20 from the verifier's one
/// manifest read: 1024 pages for this capsule's 64. Its minimum is unchanged.
#[test]
fn built_capsule_declares_the_manifest_memory_as_its_maximum() {
    const WASM_PAGE_BYTES: u64 = 65536;
    let tmp = TempDir::new("run32-max");
    let root = canonical(&tmp);
    let built = built_capsule(&root);
    let (_bundle, value) = verified_bundle(&root, "bundle", &built);
    let shape = wasm_shape::read(&value.entrypoint().content).expect("read the module's shape");

    assert_eq!(shape.import_count, 0, "the capsule imports nothing");
    assert_eq!(
        shape.imported_memory_count, 0,
        "the capsule imports no memory"
    );
    assert_eq!(
        shape.memories.len(),
        1,
        "the capsule defines exactly one memory: {:?}",
        shape.memories
    );
    let memory = shape.memories[0];
    assert_eq!(memory.minimum, 16, "the minimum is unchanged");
    let maximum = memory
        .maximum
        .expect("the capsule declares no memory maximum");
    assert_eq!(
        u64::from(maximum) * WASM_PAGE_BYTES,
        u64::from(value.memory_mb()) << 20,
        "the maximum ({maximum} pages) is not the declared memory_mb ({} MB)",
        value.memory_mb()
    );
    assert_eq!(maximum, 1024, "64 MB is 1024 pages of 64 KiB");
}

/// wc-010b, real engines: the capsule `tools/build` makes, through `run` on
/// the real `wasmtime` and `wasmer`, still prints `FIXED_OUTPUT` on both, with
/// the cap on `wasmtime`'s argv. The cap is seen by a recording program at
/// `wasmtime`'s path: a shell that appends its arguments to a file and then
/// `exec`s the real `wasmtime`, so the shell is replaced, one process, never
/// an engine inside an engine. An engine not found prints SKIPPED and gives no
/// result.
#[test]
fn built_capsule_runs_under_the_declared_cap_on_wasmtime() {
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
            "SKIPPED: {} not found on PATH; the capped built-capsule run needs both (no result, not a PASS)",
            missing.join(" and ")
        );
        return;
    }
    let tmp = TempDir::new("run10-built");
    let root = canonical(&tmp);
    let built = built_capsule(&root);
    let key = fresh_key();
    let (bundle, sig) = signed_bundle(&root, "bundle", &built, &key);
    let accepted = [did(&key)];
    let engines = work_root(&root, "engines");
    let argv_log = engines.join("wasmtime.argv");
    let wasmtime = stand_in(
        &engines,
        "wasmtime",
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nexec '{}' \"$@\"\n",
            argv_log.display(),
            programs[0].display()
        ),
    );
    let work = work_root(&root, "work");

    let passed = two_ran(run(&RunInput {
        bundle: &bundle,
        signature: Some(&sig),
        accepted: &accepted,
        granted: &[],
        wasmtime: &wasmtime,
        wasmer: &programs[1],
        work_root: &work,
        control: &TEST_CONTROL,
    }));
    let expected = format!("{FIXED_OUTPUT}\n");
    for engine_kind in ENGINES {
        assert_eq!(
            passed.stdout(engine_kind),
            expected.as_bytes(),
            "{engine_kind}"
        );
    }
    let module = work.join("wasmtime").join("module.wasm");
    assert_eq!(
        fs::read_to_string(&argv_log).expect("read wasmtime's recorded argv"),
        format!(
            "--version\nrun\n--invoke\ndigest\n-W\nmax-memory-size=67108864,max-memories=1,trap-on-grow-failure=y\n{}\n1592590337\n",
            module.display()
        ),
        "wasmtime's argv: its version query, then its capped module run"
    );
    eprintln!(
        "PASS: under the declared 64 MB cap on wasmtime, both engines printed {FIXED_OUTPUT}"
    );
}

/// wc-010b: wasmer 7.5.0's CLI has no memory cap flag, so `run` gives it no
/// cap argument. Since task 033 its cap is the module's own memory maximum,
/// which `run` checks against the declared size before any start
/// (`capsule_grows_within_its_module_maximum_on_wasmer` and
/// `memory_grow_past_the_module_maximum_returns_minus_one_on_wasmer`). This
/// test, for a cap flag, is never run and never counted as a PASS.
#[test]
#[ignore = "SKIPPED: wasmer 7.5.0 has no memory cap flag in wasmer run --help or wasmer --help (wc-010a); its cap is the module's own memory maximum, checked by run (task 033)"]
fn memory_cap_on_wasmer_is_skipped() {
    panic!("SKIPPED: wasmer has no memory cap flag");
}

/// wc-010c: the receipt's line for an engine started with no memory cap
/// argument, with wc-010a's reason.
const WASMER_SKIPPED: &str =
    "wasmer_memory_cap: SKIPPED: no memory cap flag in wasmer run --help or wasmer --help (wc-010a)";

/// The receipt's line that starts with `key: `, if any.
fn receipt_line<'a>(receipt: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}: ");
    receipt.lines().find(|line| line.starts_with(&prefix))
}

/// wc-010c: the receipt records the declared size, not a fixed 64 MB: a
/// bundle that declares 2 MB, run through `run` on stand-in engines, gives
/// `memory_mb: 2`, 2097152 bytes, `wasmtime` ENFORCED with exactly the cap
/// argument it was started with, and `wasmer` SKIPPED with wc-010a's reason.
#[test]
fn receipt_records_the_declared_memory_cap() {
    let tmp = TempDir::new("run10c-receipt");
    let root = canonical(&tmp);
    let signed = signed_bundle_declaring(&root, "bundle", MODULE, 2);
    let engines = work_root(&root, "engines");
    let wasmtime = marked(&engines, "wasmtime", "printf 'same\\n'\n");
    let wasmer = marked(&engines, "wasmer", "printf 'same\\n'\n");
    let work = work_root(&root, "work");

    let passed = two_ran(run(&signed.input(&wasmtime, &wasmer, &work)));
    assert_eq!(passed.memory_mb(), 2, "the declared memory_mb");
    assert_eq!(passed.memory_cap_bytes(), 2_097_152, "2 × 2^20 bytes");

    let receipt = render(&passed);
    let lines: Vec<&str> = receipt.lines().collect();
    assert_eq!(lines.len(), 14, "the v2 receipt's lines:\n{receipt}");
    assert_eq!(lines[0], "schema: wc-005.run-receipt/v2");
    assert_eq!(
        lines[10..],
        [
            "memory_mb: 2",
            "memory_cap_bytes: 2097152",
            "wasmtime_memory_cap: ENFORCED max-memory-size=2097152,max-memories=1,trap-on-grow-failure=y",
            WASMER_SKIPPED,
        ],
        "the receipt's memory lines:\n{receipt}"
    );
}

/// wc-010c: the receipt's cap line is the argv the engine got, not a claim
/// beside it. With [`recording`] stand-ins, `wasmtime_memory_cap` is ENFORCED
/// with exactly the argument that followed `-W` in the argv `wasmtime` logged,
/// and `wasmer`, whose logged argv has no `-W` and no `max-memory-size`, gets
/// the SKIPPED line.
#[test]
fn receipt_cap_line_matches_the_argv_the_engine_got() {
    let tmp = TempDir::new("run10c-argv");
    let root = canonical(&tmp);
    let signed = signed_bundle_declaring(&root, "bundle", MODULE, 2);
    let engines = work_root(&root, "engines");
    let log = engines.join("log");
    let wasmtime = recording(&engines, "wasmtime", &log, "same");
    let wasmer = recording(&engines, "wasmer", &log, "same");
    let work = work_root(&root, "work");

    let passed = two_ran(run(&signed.input(&wasmtime, &wasmer, &work)));
    let receipt = render(&passed);

    let wasmtime_argv = logged_argv(&engines, "wasmtime");
    let after_w: Vec<&String> = wasmtime_argv
        .windows(2)
        .filter(|pair| pair[0] == "-W")
        .map(|pair| &pair[1])
        .collect();
    assert_eq!(
        after_w.len(),
        1,
        "wasmtime's logged argv {wasmtime_argv:?} has no single -W argument"
    );
    assert_eq!(
        receipt_line(&receipt, "wasmtime_memory_cap"),
        Some(format!("wasmtime_memory_cap: ENFORCED {}", after_w[0]).as_str()),
        "the receipt's wasmtime cap is not the argument after -W in its argv"
    );
    assert_eq!(
        passed.memory_cap(Engine::Wasmtime),
        Some(after_w[0].as_str())
    );

    let wasmer_argv = logged_argv(&engines, "wasmer");
    assert!(
        !wasmer_argv
            .iter()
            .any(|arg| arg == "-W" || arg.contains("max-memory-size")),
        "wasmer's logged argv {wasmer_argv:?} carries a memory cap"
    );
    assert_eq!(
        receipt_line(&receipt, "wasmer_memory_cap"),
        Some(WASMER_SKIPPED),
        "the receipt's wasmer cap line"
    );
    assert_eq!(passed.memory_cap(Engine::Wasmer), None);
}

/// Task 038: `run` refuses an engine whose `--version` first line does not
/// name its pinned version, before any module run: through `run`, each line
/// below, printed by one engine's stand-in while the other prints its pinned
/// line, is refused with the pin reason for that engine. No module run
/// starts, no run folder is made, and after an unpinned `wasmtime` the
/// `wasmer` stand-in is not asked `--version`.
#[test]
fn run_refuses_an_unpinned_engine_version_before_any_module_run() {
    let signed = signed_fixture();
    let tmp = TempDir::new("run038-unpinned");
    let root = canonical(&tmp);
    let cases = [
        ("newer", Engine::Wasmtime, "wasmtime 46.0.0 (x)"),
        ("longer-patch", Engine::Wasmtime, "wasmtime 45.0.10"),
        ("no-space", Engine::Wasmtime, "wasmtime-45.0.1"),
        ("newer", Engine::Wasmer, "wasmer 7.6.0"),
        ("name-only", Engine::Wasmer, "wasmer"),
        ("two-spaces", Engine::Wasmer, "wasmer  7.5.0"),
    ];
    for (kind, unpinned, line) in cases {
        let case = format!("{unpinned}-{kind}");
        let engines = work_root(&root, &format!("engines-{case}"));
        let mut programs = Vec::new();
        for engine_kind in ENGINES {
            programs.push(if engine_kind == unpinned {
                marked_with(
                    &engines,
                    engine_kind.name(),
                    &format!("printf '%s\\n' '{line}'\n"),
                    "printf same\n",
                )
            } else {
                marked(&engines, engine_kind.name(), "printf same\n")
            });
        }
        let program = &programs[if unpinned == Engine::Wasmtime { 0 } else { 1 }];
        let work = work_root(&root, &format!("work-{case}"));

        let refusal = version_refused(run(&input(&signed, &programs[0], &programs[1], &work)));
        assert_eq!(
            refusal.to_string(),
            format!(
                "{}: {unpinned} --version printed {line:?}, not the pinned version {unpinned} {}: no module run starts",
                program.display(),
                unpinned.pinned_version()
            ),
            "{case}"
        );
        assert_eq!(&refusal.path, program, "{case}");
        match refusal.reason {
            Reason::VersionNotPinned {
                engine,
                printed,
                pinned,
            } => {
                assert_eq!(engine, unpinned, "{case}");
                assert_eq!(printed, line.as_bytes(), "{case}");
                assert_eq!(pinned, unpinned.pinned_version(), "{case}");
            }
            other => panic!("{case}: not the pin reason: {other}"),
        }
        for engine_kind in ENGINES {
            assert!(
                !started(&engines, engine_kind.name()),
                "{case}: {engine_kind}'s module run started"
            );
        }
        assert!(names(&work).is_empty(), "{case}: a run folder was made");
        if unpinned == Engine::Wasmtime {
            assert!(
                !queried(&engines, "wasmer"),
                "{case}: wasmer was asked --version after an unpinned wasmtime"
            );
        }
    }
}

/// Task 038: a first line whose first two words are the engine's name and its
/// pinned version passes the pin check whatever follows them, and the receipt
/// still records the line as printed.
#[test]
fn run_accepts_the_pinned_version_with_any_tail() {
    let signed = signed_fixture();
    let tmp = TempDir::new("run038-tail");
    let root = canonical(&tmp);
    assert_eq!((WASMTIME_VERSION, WASMER_VERSION), ("45.0.1", "7.5.0"));
    for (case, wasmtime_line, wasmer_line) in [
        (
            "real-lines",
            "wasmtime 45.0.1 (83166ba31 2026-06-05)",
            "wasmer 7.5.0",
        ),
        (
            "stand-in-tail",
            "wasmtime 45.0.1 (stand-in)",
            "wasmer 7.5.0",
        ),
    ] {
        let engines = work_root(&root, &format!("engines-{case}"));
        let wasmtime = marked_with(
            &engines,
            "wasmtime",
            &format!("printf '%s\\n' '{wasmtime_line}'\n"),
            "printf same\n",
        );
        let wasmer = marked_with(
            &engines,
            "wasmer",
            &format!("printf '%s\\n' '{wasmer_line}'\n"),
            "printf same\n",
        );
        let work = work_root(&root, &format!("work-{case}"));

        let passed = two_ran(run(&input(&signed, &wasmtime, &wasmer, &work)));
        assert_eq!(
            passed.version(Engine::Wasmtime),
            wasmtime_line.as_bytes(),
            "{case}"
        );
        assert_eq!(
            passed.version(Engine::Wasmer),
            wasmer_line.as_bytes(),
            "{case}"
        );
        let receipt = render(&passed);
        for (key, line) in [
            ("wasmtime_version", wasmtime_line),
            ("wasmer_version", wasmer_line),
        ] {
            let expected = format!("{key}: \"{line}\"");
            assert_eq!(
                receipt_line(&receipt, key),
                Some(expected.as_str()),
                "{case}: the receipt does not record the line as printed"
            );
        }
        for engine_kind in ENGINES {
            assert!(
                started(&engines, engine_kind.name()),
                "{case}: {engine_kind} did not run"
            );
        }
    }
}

/// The first stderr line wasmtime 45.0.1 printed for an unknown `-W` key,
/// with exit status 2 (LOG, task 038's first probe).
const REJECTED_CAP_LINE: &str = "error: unknown -W / --wasm option: max-memory-sizeX";

/// Task 038: a capped start the engine rejects is refused with the cap reason,
/// naming the `-W` argument `run` passed, and the module is never run again
/// without it: `wasmtime` was started for a module run exactly once, with
/// `-W`, and `wasmer` never. Any other nonzero exit stays `EngineFailed`.
#[test]
fn run_refuses_a_rejected_memory_cap_without_retrying_it() {
    let signed = signed_fixture();
    let tmp = TempDir::new("run038-cap-rejected");
    let root = canonical(&tmp);

    // A pinned wasmtime that rejects any start whose argv holds -W, as the
    // probe did, and otherwise prints the digest output. Each module start
    // is counted in its `.starts` file and its argv appended to `.argv`.
    let rejecting = format!(
        "printf 'module\\n' >> \"$0.starts\"\nprintf '%s\\n' \"$@\" >> \"$0.argv\"\n\
         for arg in \"$@\"; do\n\
         if [ \"$arg\" = -W ]; then printf '%s\\n' '{REJECTED_CAP_LINE}' >&2; exit 2; fi\n\
         done\nprintf same\n"
    );
    let engines = work_root(&root, "engines");
    let wasmtime = marked(&engines, "wasmtime", &rejecting);
    let wasmer = marked(&engines, "wasmer", "printf same\n");
    let work = work_root(&root, "work");

    let refusal = two_refused(run(&input(&signed, &wasmtime, &wasmer, &work)));
    let module_runs = starts(&wasmtime, "module");
    assert_eq!(
        module_runs, 1,
        "wasmtime was started for {module_runs} module runs, not once"
    );
    let argv_path = PathBuf::from(format!("{}.argv", wasmtime.display()));
    let argv: Vec<String> = fs::read_to_string(&argv_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", argv_path.display()))
        .lines()
        .map(str::to_owned)
        .collect();
    let passed_cap: Vec<&String> = argv
        .windows(2)
        .filter(|pair| pair[0] == "-W")
        .map(|pair| &pair[1])
        .collect();
    assert_eq!(
        passed_cap.len(),
        1,
        "wasmtime's argv {argv:?} has no single -W argument"
    );
    let argument = passed_cap[0];
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: wasmtime rejected the memory cap argument -W {argument} (exit status: 2): {REJECTED_CAP_LINE}; the module is not run without its cap",
            wasmtime.display()
        )
    );
    match refusal {
        TwoEngineRefusal::Engine(Refusal {
            path,
            reason:
                Reason::CapRejected {
                    engine,
                    argument: rejected,
                    status,
                    stderr,
                },
        }) => {
            assert_eq!(path, wasmtime);
            assert_eq!(engine, Engine::Wasmtime);
            assert_eq!(&rejected, argument);
            assert_eq!(status.code(), Some(2));
            assert_eq!(stderr, format!("{REJECTED_CAP_LINE}\n"));
        }
        other => panic!("not the cap reason: {other}"),
    }
    assert!(
        !started(&engines, "wasmer"),
        "wasmer was started after wasmtime rejected its cap"
    );
    assert!(names(&work).is_empty(), "a run folder was left");

    // Other failures stay EngineFailed: other stderr with the measured
    // status, the measured line with another status, an `error: ` line that
    // does not name -W, and the measured failure from wasmer, which is given
    // no cap argument.
    let cases = [
        ("other-stderr", Engine::Wasmtime, "boom: bad module", 2),
        ("other-status", Engine::Wasmtime, REJECTED_CAP_LINE, 3),
        (
            "no-option",
            Engine::Wasmtime,
            "error: failed to open wasm module",
            2,
        ),
        ("uncapped", Engine::Wasmer, REJECTED_CAP_LINE, 2),
    ];
    for (kind, failing_engine, line, code) in cases {
        let case = format!("{failing_engine}-{kind}");
        let engines = work_root(&root, &format!("engines-{case}"));
        let failing_body = format!("printf '%s\\n' '{line}' >&2\nexit {code}\n");
        let mut programs = Vec::new();
        for engine_kind in ENGINES {
            programs.push(if engine_kind == failing_engine {
                marked(&engines, engine_kind.name(), &failing_body)
            } else {
                marked(&engines, engine_kind.name(), "printf same\n")
            });
        }
        let failing = &programs[if failing_engine == Engine::Wasmtime {
            0
        } else {
            1
        }];
        let work = work_root(&root, &format!("work-{case}"));
        let refusal = two_refused(run(&input(&signed, &programs[0], &programs[1], &work)));
        assert_eq!(
            refusal.to_string(),
            format!(
                "{}: {failing_engine} failed (exit status: {code}): {line}",
                failing.display()
            ),
            "{case}"
        );
        match refusal {
            TwoEngineRefusal::Engine(Refusal {
                reason:
                    Reason::EngineFailed {
                        engine,
                        status,
                        stderr,
                    },
                ..
            }) => {
                assert_eq!(engine, failing_engine, "{case}");
                assert_eq!(status.code(), Some(code), "{case}");
                assert_eq!(stderr, format!("{line}\n"), "{case}");
            }
            other => panic!("{case}: not EngineFailed: {other}"),
        }
    }
}

/// The real `wasmer` on PATH, by an absolute path, or `None` after a SKIPPED
/// line: an engine not found gives no result, never a PASS.
fn real_wasmer(test: &str) -> Option<PathBuf> {
    let program = find_engine(Engine::Wasmer.name());
    if program.is_none() {
        eprintln!("SKIPPED: wasmer not found on PATH; {test} needs it (no result, not a PASS)");
    }
    program
}

/// Both real engines, in [`ENGINES`] order, or `None` after a SKIPPED line for
/// each one not found.
fn real_engines(test: &str) -> Option<[PathBuf; 2]> {
    match (real_wasmtime(test), real_wasmer(test)) {
        (Some(wasmtime), Some(wasmer)) => Some([wasmtime, wasmer]),
        _ => None,
    }
}

/// Task 040: the census tools, each started by its absolute path. A tool that
/// does not start fails the test with its path; the census never skips.
const PGREP: &str = "/usr/bin/pgrep";
const LSOF: &str = "/usr/sbin/lsof";
const PS: &str = "/bin/ps";
const KILL: &str = "/bin/kill";
const SLEEP: &str = "/bin/sleep";
/// Task 042: stops a killed-run test's engines when its wait or kill failed.
const PKILL: &str = "/usr/bin/pkill";

/// Run a census `tool` with `args`. Exit 1 with nothing on stdout or stderr is
/// "found nothing", an empty list. An exit in `found` with stdout and nothing
/// on stderr is "found something": its stdout lines. A tool that does not
/// start (task 042: an `Err`, not a panic, so a caller can stop its engines
/// first), any other exit or any stderr is an `Err` with that text, never
/// "found nothing".
fn census_tool(
    tool: &str,
    args: &[&std::ffi::OsStr],
    found: &[i32],
) -> Result<Vec<String>, String> {
    let output = std::process::Command::new(tool)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| format!("the census tool {tool} did not start: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    match output.status.code() {
        Some(1) if stdout.is_empty() && stderr.is_empty() => Ok(Vec::new()),
        Some(code) if found.contains(&code) && stderr.is_empty() && !stdout.is_empty() => {
            Ok(stdout.lines().map(str::to_owned).collect())
        }
        _ => Err(format!(
            "{tool} {args:?} ({}): stdout {stdout:?}, stderr {stderr:?}",
            output.status
        )),
    }
}

/// The pids of the live processes with `work_root` in their argv:
/// `pgrep -f <work_root>`, which exits 0 when it lists one.
fn live_processes(work_root: &Path) -> Result<Vec<String>, String> {
    census_tool(PGREP, &["-f".as_ref(), work_root.as_os_str()], &[0])
}

/// The argv of the live process `pid`, as one line: `ps -o args= -p <pid>`.
fn live_argv(pid: &str) -> Result<String, String> {
    let lines = census_tool(
        PS,
        &["-o".as_ref(), "args=".as_ref(), "-p".as_ref(), pid.as_ref()],
        &[0],
    )?;
    match lines.as_slice() {
        [line] => Ok(line.trim_end().to_owned()),
        _ => Err(format!("{PS}: pid {pid} gave {lines:?}, not one line")),
    }
}

/// Task 040 (M1 A12 lab half): every leftover under `work_root`, each with its
/// kind, or an empty list only when all three hold: `work_root` has no entry
/// (`entry: <name>`); no live process has `work_root` in its argv (`process:
/// <pid> <argv>`, from `pgrep -f`); and no process holds a file open under it
/// (`open file: <lsof line>`, from `lsof +D`). A census tool that answers in
/// any other way is a leftover too (`census failed: ...`), never a pass. The
/// one census; every cleanup test asserts its result empty.
fn census(work_root: &Path) -> Vec<String> {
    let mut leftovers: Vec<String> = names(work_root)
        .into_iter()
        .map(|name| format!("entry: {name}"))
        .collect();
    match live_processes(work_root) {
        Ok(pids) => leftovers.extend(pids.iter().map(|pid| match live_argv(pid) {
            Ok(argv) => format!("process: {pid} {argv}"),
            Err(error) => format!("process: {pid} (argv not read: {error})"),
        })),
        Err(error) => leftovers.push(format!("census failed: {error}")),
    }
    // This Mac's lsof exits 1 even when it lists an open file under `+D`
    // (measured, LOG task 040), so a listing with exit 0 or 1 is read; exit 1
    // with nothing printed is still the only "none".
    match census_tool(LSOF, &["+D".as_ref(), work_root.as_os_str()], &[0, 1]) {
        // lsof's first line is its column header.
        Ok(lines) => leftovers.extend(
            lines
                .iter()
                .skip(1)
                .map(|line| format!("open file: {line}")),
        ),
        Err(error) => leftovers.push(format!("census failed: {error}")),
    }
    leftovers
}

/// Assert `census(work_root)` is empty, printing every leftover.
fn assert_census_empty(work_root: &Path, case: &str) {
    let leftovers = census(work_root);
    assert!(
        leftovers.is_empty(),
        "{case}: the census found leftovers under {}:\n{}",
        work_root.display(),
        leftovers.join("\n")
    );
    eprintln!("PASS: {case}: the census found nothing under the scratch root");
}

/// A core module whose one export, `digest (i32) -> i32`, the runner's
/// [`DIGEST_EXPORT`], runs the hand-written `body` (no locals), in
/// [`grow_module`]'s style: no import and no memory.
fn digest_module(body: &[u8]) -> Vec<u8> {
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    // Type section: one type, (i32) -> (i32).
    module.extend_from_slice(&[0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f]);
    // Function section: one function, of type 0.
    module.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    // Export section: "digest", function 0.
    module.extend_from_slice(&[0x07, 0x0a, 0x01, 0x06]);
    module.extend_from_slice(b"digest");
    module.extend_from_slice(&[0x00, 0x00]);
    // Code section: one body, its size, no locals, then `body`.
    let size = u8::try_from(body.len() + 1).expect("a short body");
    module.extend_from_slice(&[0x0a, size + 2, 0x01, size, 0x00]);
    module.extend_from_slice(body);
    module
}

/// `unreachable; end`: `digest` traps.
const TRAP_BODY: &[u8] = &[0x00, 0x0b];

/// `loop br 0 end; unreachable; end`: `digest` loops forever.
const LOOP_BODY: &[u8] = &[0x03, 0x40, 0x0c, 0x00, 0x0b, 0x00, 0x0b];

/// The engine flags that would give the guest a host folder, environment or
/// network; none may be in a live engine's argv (task 014's fixed argv).
const PREOPEN_FLAGS: [&str; 5] = ["--dir", "--mapdir", "--env", "--net", "-S"];

/// What is wrong with a live engine's `argv` (one `ps` line): a preopen, env
/// or network flag, or a path under `work_root` other than `module`; or
/// `module` not there exactly once.
fn argv_faults(argv: &str, work_root: &Path, module: &Path) -> Vec<String> {
    let root = work_root.to_string_lossy();
    let module = module.to_string_lossy();
    let words: Vec<&str> = argv.split(' ').collect();
    let mut faults = Vec::new();
    for word in &words {
        // A prefix match: `--dir=x`, `--env=K=V` and `-Sinherit-network` too.
        if PREOPEN_FLAGS.iter().any(|flag| word.starts_with(flag)) {
            faults.push(format!("a preopen, env or network flag: {word}"));
        }
        if word.contains(root.as_ref()) && *word != module.as_ref() {
            faults.push(format!(
                "a scratch-root path that is not the module: {word}"
            ));
        }
    }
    let module_words = words
        .iter()
        .filter(|word| **word == module.as_ref())
        .count();
    if module_words != 1 {
        faults.push(format!(
            "the module path is there {module_words} times, not once"
        ));
    }
    faults
}

/// Task 040, census self-test, no engine: a file left in a work root, a live
/// `/bin/sleep` whose argv holds a path under it (its `argv[0]`: `sleep` takes
/// only time intervals) and a file handle open under it are each reported by
/// kind; once the file is removed, the process stopped and the handle closed,
/// the census is empty.
#[test]
fn census_reports_each_kind_of_leftover() {
    use std::os::unix::process::CommandExt;
    let tmp = TempDir::new("run40-census");
    let work = work_root(&canonical(&tmp), "work");
    assert_census_empty(&work, "an empty work root");

    let left = work.join("left.txt");
    fs::write(&left, b"left").expect("leave a file");
    let open = fs::File::open(&left).expect("open the left file");
    let mut sleeper = std::process::Command::new(SLEEP)
        .arg0(work.join("sleeper"))
        .arg("30")
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("{SLEEP} did not start: {error}"));

    let leftovers = census(&work);
    sleeper.kill().expect("stop the sleeper");
    sleeper.wait().expect("reap the sleeper");
    let count = |kind: &str| {
        leftovers
            .iter()
            .filter(|line| line.starts_with(kind))
            .count()
    };
    let all = leftovers.join("\n");
    assert_eq!(count("entry: "), 1, "the left file:\n{all}");
    assert!(
        leftovers.contains(&"entry: left.txt".to_owned()),
        "the left file by name:\n{all}"
    );
    assert_eq!(count("process: "), 1, "the live sleeper:\n{all}");
    assert!(
        leftovers.contains(&format!(
            "process: {} {} 30",
            sleeper.id(),
            work.join("sleeper").display()
        )),
        "the sleeper by pid and argv:\n{all}"
    );
    assert_eq!(count("open file: "), 1, "the open handle:\n{all}");
    let open_line = leftovers
        .iter()
        .find(|line| line.starts_with("open file: "))
        .expect("an open file line");
    assert!(
        open_line.contains(&format!(" {} ", std::process::id()))
            && open_line.ends_with(&left.display().to_string()),
        "the open handle by this process and path: {open_line}"
    );
    assert_eq!(count("census failed: "), 0, "a census tool failed:\n{all}");
    assert_eq!(leftovers.len(), 3, "only the three leftovers:\n{all}");

    drop(open);
    fs::remove_file(&left).expect("remove the left file");
    assert_census_empty(&work, "after the file, the process and the handle are gone");
}

/// Task 040, normal run: one two-engine `run` of the signed capsule
/// `tools/build` makes, on both real engines; both print `FIXED_OUTPUT`, and
/// then the census finds nothing under the work root.
#[test]
fn normal_run_leaves_nothing_under_the_scratch_root() {
    let Some([wasmtime, wasmer]) = real_engines("the normal-run census") else {
        return;
    };
    let tmp = TempDir::new("run40-normal");
    let root = canonical(&tmp);
    let built = built_capsule(&root);
    let key = fresh_key();
    let (bundle, sig) = signed_bundle(&root, "bundle", &built, &key);
    let accepted = [did(&key)];
    let work = work_root(&root, "work");

    let passed = two_ran(run(&RunInput {
        bundle: &bundle,
        signature: Some(&sig),
        accepted: &accepted,
        granted: &[],
        wasmtime: &wasmtime,
        wasmer: &wasmer,
        work_root: &work,
        control: &TEST_CONTROL,
    }));
    let expected = format!("{FIXED_OUTPUT}\n");
    assert_eq!(passed.wasmtime(), passed.wasmer(), "the outputs differ");
    assert_eq!(passed.wasmtime(), expected.as_bytes(), "not FIXED_OUTPUT");
    assert_census_empty(&work, "normal run on wasmtime and wasmer");
}

/// Task 040, trapped run: on each real engine, `run_engine` on a module whose
/// `digest` runs `unreachable` is refused as `EngineFailed` with a nonzero
/// exit status and the trap on stderr; then the census finds nothing under
/// that run's work root.
#[test]
fn trapped_run_leaves_nothing_under_the_scratch_root() {
    let Some(programs) = real_engines("the trapped-run census") else {
        return;
    };
    let tmp = TempDir::new("run40-trapped");
    let root = canonical(&tmp);
    let (_, value) = verified_bundle(&root, "bundle", &digest_module(TRAP_BODY));

    for (engine_kind, program) in ENGINES.into_iter().zip(&programs) {
        let work = work_root(&root, &format!("work-{engine_kind}"));
        let refusal = refused(run_engine(
            &value,
            engine_kind,
            program,
            &work,
            &TEST_CONTROL,
        ));
        match &refusal.reason {
            Reason::EngineFailed {
                engine,
                status,
                stderr,
            } => {
                assert_eq!(*engine, engine_kind);
                assert!(
                    status.code().is_some_and(|code| code != 0),
                    "{engine_kind}: not a nonzero exit status: {status}"
                );
                assert!(
                    stderr.to_lowercase().contains("unreachable"),
                    "{engine_kind}: no trap on stderr: {stderr:?}"
                );
                eprintln!(
                    "PASS: {engine_kind} trapped ({status}): {}",
                    stderr
                        .lines()
                        .find(|line| line.to_lowercase().contains("unreachable"))
                        .unwrap_or("")
                );
            }
            _ => panic!("{engine_kind}: not EngineFailed: {refusal}"),
        }
        assert_eq!(refusal.path, *program, "{engine_kind}");
        assert_census_empty(&work, &format!("trapped run on {engine_kind}"));
    }
}

/// Task 042: stop every engine of the run under `work_root`, for a killed-run
/// test that cannot go on: `pkill -KILL -f <work_root>` every 50 ms while
/// `runner` has not finished, for at most 10 s. It returns what went wrong on
/// the way, for the failure message: a `pkill` that did not start or exited
/// other than 0 (killed one) or 1 (none), and a runner still running after
/// 10 s.
fn stop_run_engines<T>(work_root: &Path, runner: &std::thread::JoinHandle<T>) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut problems = Vec::new();
    while !runner.is_finished() {
        if Instant::now() >= deadline {
            problems.push(format!("the runner still ran after 10 s of {PKILL}"));
            break;
        }
        let problem = match std::process::Command::new(PKILL)
            .args(["-KILL", "-f"])
            .arg(work_root)
            .stdin(std::process::Stdio::null())
            .output()
        {
            Ok(output) if matches!(output.status.code(), Some(0 | 1)) => None,
            Ok(output) => Some(format!(
                "{PKILL} -KILL -f {} ({}): stderr {:?}",
                work_root.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )),
            Err(error) => Some(format!("{PKILL} did not start: {error}")),
        };
        if let Some(problem) = problem.filter(|problem| !problems.contains(problem)) {
            problems.push(problem);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    problems
}

/// Task 043: the killed-run test's run control: 120 s, far above its 10 s wait.
static KILLED_RUN_CONTROL: RunControl = RunControl::new(Duration::from_secs(120));

/// Task 040, killed run: on each real engine, `run_engine` runs on a thread on
/// a module whose `digest` loops forever. The test waits (at most 10 s,
/// polling `pgrep -f <work root>`) for the one engine process, reads its argv,
/// kills it with `SIGKILL`, and joins the thread: the run is refused as
/// `EngineFailed`, stopped by signal 9. The live argv held no preopen, env or
/// network flag and no scratch-root path but the module file; then the census
/// finds nothing under that run's work root.
///
/// Task 042: the thread is joined on every path before any check can fail. If
/// the wait fails (a `pgrep` that does not start or answers with an error, no
/// engine process within 10 s, or the run ending first), or `/bin/kill` does
/// not start or fails, [`stop_run_engines`] first kills every engine of that
/// run until the thread has finished (at most 10 s), then the thread is joined,
/// and only then does the test fail, with the first reason and then what the
/// stop found. If the thread still runs after those 10 s, the join waits for
/// it: the test never leaves a detached thread that can still start the
/// engine. A failed check never leaves an engine looping.
///
/// Task 043: its run budget, [`KILLED_RUN_CONTROL`], is far above the 10 s
/// wait, so the SIGKILL the test sends is the one that stops the engine, and
/// the run stays `EngineFailed`, never `BudgetExceeded`.
#[test]
fn killed_run_leaves_nothing_under_the_scratch_root() {
    use std::os::unix::process::ExitStatusExt;
    let Some(programs) = real_engines("the killed-run census") else {
        return;
    };
    let tmp = TempDir::new("run40-killed");
    let root = canonical(&tmp);
    let (_, value) = verified_bundle(&root, "bundle", &digest_module(LOOP_BODY));

    for (engine_kind, program) in ENGINES.into_iter().zip(programs) {
        let work = work_root(&root, &format!("work-{engine_kind}"));
        let module = work.join(engine_kind.name()).join("module.wasm");
        let runner = {
            let (value, program, work) = (value.clone(), program.clone(), work.clone());
            std::thread::spawn(move || {
                run_engine(&value, engine_kind, &program, &work, &KILLED_RUN_CONTROL)
            })
        };

        let deadline = Instant::now() + Duration::from_secs(10);
        let pids = loop {
            match live_processes(&work) {
                Ok(pids) if !pids.is_empty() => break Ok(pids),
                Ok(_) if Instant::now() < deadline && !runner.is_finished() => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Ok(_) => {
                    break Err(
                        "no engine process showed up within 10 s, or the run ended first"
                            .to_owned(),
                    )
                }
                Err(error) => break Err(error),
            }
        };
        let pids = match pids {
            Ok(pids) => pids,
            Err(error) => {
                let stopped = stop_run_engines(&work, &runner);
                let joined = runner.join();
                panic!(
                    "{engine_kind}: {error}; then stopped its engines (problems: {stopped:?}) \
                     and joined the runner (it panicked: {})",
                    joined.is_err()
                );
            }
        };
        let argv: Vec<Result<String, String>> = pids.iter().map(|pid| live_argv(pid)).collect();
        let killed = std::process::Command::new(KILL)
            .args(["-KILL"])
            .args(&pids)
            .status()
            .map_err(|error| format!("{KILL} did not start: {error}"));
        let stopped = match &killed {
            Ok(status) if status.success() => Vec::new(),
            _ => stop_run_engines(&work, &runner),
        };
        let result = runner.join().expect("the runner thread panicked");

        let killed = killed.unwrap_or_else(|error| {
            panic!("{engine_kind}: {error}; then stopped its engines (problems: {stopped:?})")
        });
        assert!(
            killed.success(),
            "{engine_kind}: {KILL} -KILL {pids:?}: {killed}; then stopped its engines \
             (problems: {stopped:?})"
        );
        assert_eq!(
            pids.len(),
            1,
            "{engine_kind}: not one engine process: {argv:?}"
        );
        let argv = argv[0]
            .clone()
            .unwrap_or_else(|error| panic!("{engine_kind}: {error}"));
        assert!(
            argv.starts_with(&format!(
                "{} run --invoke {DIGEST_EXPORT} ",
                program.display()
            )),
            "{engine_kind}: not the engine's module run: {argv}"
        );
        let faults = argv_faults(&argv, &work, &module);
        assert!(
            faults.is_empty(),
            "{engine_kind}: the live argv {argv:?}:\n{}",
            faults.join("\n")
        );
        eprintln!("PASS: {engine_kind}'s live argv held no preopen, env or network flag: {argv}");

        let refusal = refused(result);
        match &refusal.reason {
            Reason::EngineFailed { engine, status, .. } => {
                assert_eq!(*engine, engine_kind);
                assert_eq!(
                    status.signal(),
                    Some(9),
                    "{engine_kind}: not stopped by SIGKILL: {status}"
                );
            }
            _ => panic!("{engine_kind}: not EngineFailed: {refusal}"),
        }
        assert_census_empty(&work, &format!("killed run on {engine_kind}"));
    }
}

/// Task 043: the budget the looping-capsule tests give each module run.
const LOOP_BUDGET: Duration = Duration::from_millis(500);

/// Task 043: how long past its budget a budget test waits for its run's answer
/// before it stops the run's engines and fails.
const WATCHDOG_GRACE: Duration = Duration::from_secs(20);

/// Task 043: run `call` on a thread and return its answer and how long it took.
/// The canonical runner gives `cargo test` no time limit, so the test waits at
/// most `budget` + [`WATCHDOG_GRACE`]: if no answer comes by then,
/// [`stop_run_engines`] stops every engine of the run under `work_root`, the
/// thread is joined, and only then does the test fail.
fn answer_within_watchdog<T: Send + 'static>(
    work_root: &Path,
    budget: Duration,
    call: impl FnOnce() -> T + Send + 'static,
) -> (T, Duration) {
    let runner = std::thread::spawn(move || {
        let started = Instant::now();
        let answer = call();
        (answer, started.elapsed())
    });
    let deadline = Instant::now() + budget + WATCHDOG_GRACE;
    while !runner.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if !runner.is_finished() {
        let stopped = stop_run_engines(work_root, &runner);
        let joined = runner.join();
        panic!(
            "no answer within the budget {budget:?} + {WATCHDOG_GRACE:?}; then stopped the run's \
             engines (problems: {stopped:?}) and joined the runner (it panicked: {})",
            joined.is_err()
        );
    }
    runner.join().expect("the runner thread panicked")
}

/// Task 043: `refusal` is `BudgetExceeded` for `engine_kind` at `program` with
/// exactly `budget`, with its exact text, and the run took at least the budget
/// and under budget + 5 s.
fn assert_stopped_at_budget(
    refusal: &Refusal,
    engine_kind: Engine,
    program: &Path,
    budget: Duration,
    elapsed: Duration,
) {
    match &refusal.reason {
        Reason::BudgetExceeded {
            engine,
            budget: stopped_at,
        } => {
            assert_eq!(*engine, engine_kind, "{refusal}");
            assert_eq!(*stopped_at, budget, "{engine_kind}: {refusal}");
        }
        _ => panic!("{engine_kind}: not BudgetExceeded: {refusal}"),
    }
    assert_eq!(refusal.path, program, "{engine_kind}");
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: {engine_kind} still ran at its run budget of {} ms: the runner stopped it with SIGKILL",
            program.display(),
            budget.as_millis()
        )
    );
    assert!(
        elapsed >= budget,
        "{engine_kind}: refused after {elapsed:?}, before its budget {budget:?}"
    );
    assert!(
        elapsed < budget + Duration::from_secs(5),
        "{engine_kind}: refused after {elapsed:?}, not within 5 s of its budget {budget:?}"
    );
}

/// Task 043 (M1 A7 lab half): on each real engine, `run_engine` on a module
/// whose `digest` loops forever, with a 500 ms budget, on a thread under
/// [`answer_within_watchdog`]: the runner stops the engine and refuses the run
/// as `BudgetExceeded` for that engine and budget, after at least the budget
/// and under budget + 5 s; then the census finds nothing under its work root.
/// SKIPPED, no result, when either engine is missing.
#[test]
fn looping_capsule_is_stopped_at_its_run_budget_on_both_engines() {
    let Some(programs) = real_engines("the run-budget test") else {
        return;
    };
    let tmp = TempDir::new("run43-budget");
    let root = canonical(&tmp);
    let (_, value) = verified_bundle(&root, "bundle", &digest_module(LOOP_BODY));

    for (engine_kind, program) in ENGINES.into_iter().zip(programs) {
        let work = work_root(&root, &format!("work-{engine_kind}"));
        let (result, elapsed) = answer_within_watchdog(&work, LOOP_BUDGET, {
            let (value, program, work) = (value.clone(), program.clone(), work.clone());
            move || {
                let control = RunControl::new(LOOP_BUDGET);
                run_engine(&value, engine_kind, &program, &work, &control)
            }
        });
        let refusal = refused(result);
        assert_stopped_at_budget(&refusal, engine_kind, &program, LOOP_BUDGET, elapsed);
        eprintln!("PASS: {engine_kind} stopped after {elapsed:?}: {refusal}");
        assert_census_empty(&work, &format!("budget-stopped run on {engine_kind}"));
    }
}

/// Task 043: `run` with a looping `wasmtime` (the real one if found, else a
/// pinned stand-in whose module run `exec`s `/bin/sleep 600`, under the module
/// path as its `argv[0]`, so `pkill -f <work root>` still finds it) and a
/// [`counting`] `wasmer`, with a 500 ms budget, under the watchdog: the answer
/// is `TwoEngineRefusal::Engine` with `BudgetExceeded` for `wasmtime`;
/// `wasmer` is asked `--version` but never started for a module run; the census
/// finds nothing under the work root.
#[test]
fn run_stops_wasmtime_at_its_budget_and_never_starts_wasmer() {
    let tmp = TempDir::new("run43-two");
    let root = canonical(&tmp);
    let engines = work_root(&root, "engines");
    let wasmtime = find_engine(Engine::Wasmtime.name()).unwrap_or_else(|| {
        eprintln!("wasmtime not found on PATH: a looping stand-in takes its place");
        marked(
            &engines,
            "wasmtime",
            &format!("{MODULE_ARGUMENT}exec -a \"$module\" /bin/sleep 600\n"),
        )
    });
    let wasmer = counting(&engines, "wasmer");
    let key = fresh_key();
    let (bundle, sig) = signed_bundle(&root, "bundle", &digest_module(LOOP_BODY), &key);
    let accepted = vec![did(&key)];
    let work = work_root(&root, "work");

    let (result, elapsed) = answer_within_watchdog(&work, LOOP_BUDGET, {
        let (wasmtime, wasmer, work) = (wasmtime.clone(), wasmer.clone(), work.clone());
        move || {
            run(&RunInput {
                bundle: &bundle,
                signature: Some(&sig),
                accepted: &accepted,
                granted: &[],
                wasmtime: &wasmtime,
                wasmer: &wasmer,
                work_root: &work,
                control: &RunControl::new(LOOP_BUDGET),
            })
        }
    });
    let refusal = match two_refused(result) {
        TwoEngineRefusal::Engine(refusal) => refusal,
        other => panic!("not an engine refusal: {other}"),
    };
    // `elapsed` holds both `--version` queries too, so it is only an upper
    // bound on the module run; it is still at least the budget.
    assert_stopped_at_budget(&refusal, Engine::Wasmtime, &wasmtime, LOOP_BUDGET, elapsed);
    assert_eq!(starts(&wasmer, "module"), 0, "wasmer ran a module");
    assert_eq!(starts(&wasmer, "version"), 1, "wasmer --version queries");
    assert_census_empty(&work, "run stopped at wasmtime's budget");
}

/// Task 043: a zero budget is refused before any engine starts. Per engine,
/// `run_engine` with a [`counting`] stand-in, and then `run` with two, are each
/// refused with the zero-budget reason (exact text, with the work root as its
/// path); no module run and no `--version` query is counted, and each work
/// root is empty.
#[test]
fn zero_run_budget_is_refused_before_any_engine_starts() {
    let (_bundle, value) = fixture();
    let tmp = TempDir::new("run43-zero");
    let root = canonical(&tmp);
    let zero = RunControl::new(Duration::ZERO);
    let zero_text = |work: &Path| {
        format!(
            "{}: the run budget is zero: no engine is started",
            work.display()
        )
    };

    for engine_kind in ENGINES {
        let engines = work_root(&root, &format!("{engine_kind}-engines"));
        let program = counting(&engines, engine_kind.name());
        let work = work_root(&root, &format!("{engine_kind}-work"));
        let refusal = refused(run_engine(&value, engine_kind, &program, &work, &zero));
        assert!(
            matches!(refusal.reason, Reason::BudgetZero),
            "{engine_kind}: {refusal}"
        );
        assert_eq!(refusal.to_string(), zero_text(&work), "{engine_kind}");
        assert_eq!(starts(&program, "module"), 0, "{engine_kind}: a module run");
        assert_eq!(
            starts(&program, "version"),
            0,
            "{engine_kind}: a version query"
        );
        assert!(names(&work).is_empty(), "{engine_kind}: {:?}", names(&work));
    }

    let signed = signed_fixture();
    let engines = work_root(&root, "two-engines");
    let wasmtime = counting(&engines, "wasmtime");
    let wasmer = counting(&engines, "wasmer");
    let work = work_root(&root, "two-work");
    let refusal = match two_refused(run(&RunInput {
        control: &zero,
        ..input(&signed, &wasmtime, &wasmer, &work)
    })) {
        TwoEngineRefusal::Engine(refusal) => refusal,
        other => panic!("not an engine refusal: {other}"),
    };
    assert!(matches!(refusal.reason, Reason::BudgetZero), "{refusal}");
    assert_eq!(refusal.to_string(), zero_text(&work));
    for program in [&wasmtime, &wasmer] {
        assert_eq!(starts(program, "module"), 0, "{}", program.display());
        assert_eq!(starts(program, "version"), 0, "{}", program.display());
    }
    assert!(names(&work).is_empty(), "{:?}", names(&work));
}

/// Task 043: a stand-in that writes 128 KiB, twice a pipe buffer, to stderr
/// and then to stdout with shell builtins only (no child process can hold a
/// pipe), then exits with `status`.
fn loud(folder: &Path, name: &str, status: u8) -> PathBuf {
    let script = format!(
        "#!/bin/sh\ns=x\nfor i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17; do s=\"$s$s\"; done\nprintf '%s' \"$s\" >&2\nprintf '%s' \"$s\"\nexit {status}\n"
    );
    stand_in(folder, name, &script)
}

/// Task 043: the runner reads the engine's stdout and stderr on a thread each
/// while it waits, so an engine that writes more than a pipe holds to stderr
/// before stdout is never blocked: under a 5 s budget and the watchdog, a
/// passing stand-in's 128 KiB stdout and a failing one's 128 KiB stderr each
/// come back in full.
#[test]
fn engine_output_past_a_pipe_buffer_never_blocks_it() {
    const OUTPUT_BUDGET: Duration = Duration::from_secs(5);
    let (_bundle, value) = fixture();
    let tmp = TempDir::new("run43-pipes");
    let root = canonical(&tmp);
    let engines = work_root(&root, "engines");
    for (status, name) in [(0, "passing"), (3, "failing")] {
        let program = loud(&engines, name, status);
        let work = work_root(&root, &format!("work-{name}"));
        let (result, _) = answer_within_watchdog(&work, OUTPUT_BUDGET, {
            let (value, program, work) = (value.clone(), program.clone(), work.clone());
            move || {
                let control = RunControl::new(OUTPUT_BUDGET);
                run_engine(&value, Engine::Wasmtime, &program, &work, &control)
            }
        });
        let printed = match result {
            Ok(run) => run.stdout,
            Err(Refusal {
                reason: Reason::EngineFailed { stderr, .. },
                ..
            }) => stderr.into_bytes(),
            Err(refusal) => panic!("{name}: {refusal}"),
        };
        assert_eq!(printed.len(), 1 << 17, "{name}: not all 128 KiB came back");
        assert!(
            printed.iter().all(|byte| *byte == b'x'),
            "{name}: other bytes"
        );
    }
}

/// Task 044: the five lines of `receipt`, after checking it ends in a newline.
fn receipt_lines(receipt: &str) -> Vec<&str> {
    assert!(receipt.ends_with('\n'), "no final newline: {receipt:?}");
    receipt.lines().collect()
}

/// Task 044 (M1 A7 lab half): `run` with a pinned stand-in `wasmtime` whose
/// module run `exec`s `/bin/sleep 600` (under the module path as its
/// `argv[0]`, so the watchdog's `pkill -f <work root>` finds it) and a
/// [`counting`] `wasmer`, with a 200 ms budget, under the watchdog: the
/// refusal receipt is exactly its five lines, naming `budget_exceeded` and
/// `wasmtime`, never a generic failure.
#[test]
fn budget_refusal_receipt_names_its_reason() {
    const BUDGET: Duration = Duration::from_millis(200);
    let signed = signed_fixture();
    let tmp = TempDir::new("run44-budget-receipt");
    let root = canonical(&tmp);
    let engines = work_root(&root, "engines");
    let wasmtime = marked(
        &engines,
        "wasmtime",
        &format!("{MODULE_ARGUMENT}exec -a \"$module\" /bin/sleep 600\n"),
    );
    let wasmer = counting(&engines, "wasmer");
    let work = work_root(&root, "work");

    let (result, _) = answer_within_watchdog(&work, BUDGET, {
        let (wasmtime, wasmer, work) = (wasmtime.clone(), wasmer.clone(), work.clone());
        move || {
            run(&RunInput {
                control: &RunControl::new(BUDGET),
                ..input(&signed, &wasmtime, &wasmer, &work)
            })
        }
    });
    let refusal = two_refused(result);
    let receipt = render_refused(&refusal);
    assert_eq!(
        receipt_lines(&receipt),
        [
            "schema: wc-005.run-refusal/v1".to_owned(),
            "outcome: refused".to_owned(),
            "reason: budget_exceeded".to_owned(),
            "engine: wasmtime".to_owned(),
            format!(
                "detail: \"{}: wasmtime still ran at its run budget of 200 ms: the runner stopped it with SIGKILL\"",
                wasmtime.display()
            ),
        ]
    );
    assert_eq!(starts(&wasmer, "module"), 0, "wasmer ran a module");
    assert_census_empty(&work, "budget refusal receipt run");
}

/// Task 044: which `Reason` variant `reason` is, as an index, by an exhaustive
/// `match` with no wildcard arm. It is coverage only: a new variant makes this
/// test fail to build until it has an example below. The ids come from the
/// tools crate alone.
fn reason_variant(reason: &Reason) -> usize {
    match reason {
        Reason::EngineNotAbsolute => 0,
        Reason::WorkRootNotAbsolute => 1,
        Reason::WorkRootUnresolved(_) => 2,
        Reason::WorkRootNotCanonical { .. } => 3,
        Reason::WorkRootMetadataFailed(_) => 4,
        Reason::WorkRootNotAFolder => 5,
        Reason::RunDirExists => 6,
        Reason::RunDirNotCreated(_) => 7,
        Reason::ModuleNotCreated(_) => 8,
        Reason::ModuleNotWritten(_) => 9,
        Reason::Writer(_) => 10,
        Reason::EngineDidNotStart { .. } => 11,
        Reason::EngineFailed { .. } => 12,
        Reason::VersionDidNotStart { .. } => 13,
        Reason::VersionFailed { .. } => 14,
        Reason::VersionEmpty { .. } => 15,
        Reason::VersionNotPinned { .. } => 16,
        Reason::CapRejected { .. } => 17,
        Reason::RunDirNotRemoved(_) => 18,
        Reason::BudgetZero => 19,
        Reason::BudgetExceeded { .. } => 20,
        Reason::EngineNotStopped { .. } => 21,
        Reason::EngineNotWaited { .. } => 22,
        Reason::OutputNotRead { .. } => 23,
        Reason::MemoryNotRead(_) => 24,
        Reason::MemoryCountAboveOne { .. } => 25,
        Reason::MemoryMaximumMissing { .. } => 26,
        Reason::MemoryMaximumAboveDeclared { .. } => 27,
    }
}

/// The number of `Reason` variants [`reason_variant`] numbers.
const REASON_VARIANTS: usize = 28;

/// Whether `id` is lowercase snake_case: lowercase ASCII words joined by
/// single underscores.
fn is_snake_case(id: &str) -> bool {
    !id.is_empty()
        && id
            .split('_')
            .all(|word| !word.is_empty() && word.bytes().all(|byte| byte.is_ascii_lowercase()))
}

/// Task 044: one example value per `Reason` variant (as a module run's
/// refusal, a version query's for the version reasons, or, task 033, the
/// memory check's, `TwoEngineRefusal::Memory`, for the memory reasons) and per
/// `TwoEngineRefusal` variant, constructed here. Each renders the five lines
/// with its own `reason:` id, lowercase snake_case and distinct from every
/// other; `engine:` is the engine its reason names (`wasmer` in every example
/// that names one), else `none`, so a verifier refusal and `OutputsDiffer`
/// both say `none`; `detail:` is its Display through `escape_ascii`.
#[test]
fn refusal_receipt_ids_are_distinct_and_named() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    let path = Path::new("/lab/path");
    let error = || io::Error::from_raw_os_error(2);
    let status = ExitStatus::from_raw(3 << 8);
    let engine = Engine::Wasmer;
    let reasons = [
        Reason::EngineNotAbsolute,
        Reason::WorkRootNotAbsolute,
        Reason::WorkRootUnresolved(error()),
        Reason::WorkRootNotCanonical {
            canonical: PathBuf::from("/private/lab"),
        },
        Reason::WorkRootMetadataFailed(error()),
        Reason::WorkRootNotAFolder,
        Reason::RunDirExists,
        Reason::RunDirNotCreated(error()),
        Reason::ModuleNotCreated(error()),
        Reason::ModuleNotWritten(error()),
        Reason::Writer(WriteReason::OutDirExists),
        Reason::EngineDidNotStart {
            engine,
            error: error(),
        },
        Reason::EngineFailed {
            engine,
            status,
            stderr: "boom\n".to_owned(),
        },
        Reason::VersionDidNotStart {
            engine,
            error: error(),
        },
        Reason::VersionFailed {
            engine,
            status,
            stderr: "boom\n".to_owned(),
        },
        Reason::VersionEmpty { engine },
        Reason::VersionNotPinned {
            engine,
            printed: b"wasmer 9.9.9 \"quoted\"".to_vec(),
            pinned: WASMER_VERSION,
        },
        Reason::CapRejected {
            engine,
            argument: "max-memory-size=1".to_owned(),
            status,
            stderr: "error: bad -W value\n".to_owned(),
        },
        Reason::RunDirNotRemoved(error()),
        Reason::BudgetZero,
        Reason::BudgetExceeded {
            engine,
            budget: Duration::from_millis(200),
        },
        Reason::EngineNotStopped {
            engine,
            error: error(),
        },
        Reason::EngineNotWaited {
            engine,
            error: error(),
        },
        Reason::OutputNotRead {
            engine,
            error: error(),
        },
        Reason::MemoryNotRead(AuditRefusal::Malformed),
        Reason::MemoryCountAboveOne { count: 2 },
        Reason::MemoryMaximumMissing { minimum: 1 },
        Reason::MemoryMaximumAboveDeclared {
            maximum: 33,
            memory_mb: 2,
        },
    ];
    let mut covered: Vec<usize> = reasons.iter().map(reason_variant).collect();
    covered.sort_unstable();
    assert_eq!(
        covered,
        (0..REASON_VARIANTS).collect::<Vec<_>>(),
        "one example per Reason variant"
    );

    let mut examples: Vec<(TwoEngineRefusal, &str)> = Vec::new();
    for reason in reasons {
        let named = if refusal_names_engine(&reason) {
            "wasmer"
        } else {
            "none"
        };
        let version = matches!(
            reason,
            Reason::VersionDidNotStart { .. }
                | Reason::VersionFailed { .. }
                | Reason::VersionEmpty { .. }
                | Reason::VersionNotPinned { .. }
        );
        let refusal = Refusal {
            path: path.to_path_buf(),
            reason,
        };
        let refusal = if version {
            TwoEngineRefusal::Version(refusal)
        } else if is_memory_reason(&refusal.reason) {
            TwoEngineRefusal::Memory(refusal)
        } else {
            TwoEngineRefusal::Engine(refusal)
        };
        examples.push((refusal, named));
    }
    examples.push((TwoEngineRefusal::Verify(VerifyRefusal::Unsigned), "none"));
    examples.push((
        TwoEngineRefusal::OutputsDiffer {
            wasmtime: b"1\n".to_vec(),
            wasmer: b"2\n".to_vec(),
        },
        "none",
    ));

    let mut ids = std::collections::BTreeSet::new();
    for (refusal, named) in &examples {
        let receipt = render_refused(refusal);
        let lines = receipt_lines(&receipt);
        assert_eq!(lines.len(), 5, "{refusal}: {receipt:?}");
        assert_eq!(lines[0], "schema: wc-005.run-refusal/v1", "{refusal}");
        assert_eq!(lines[1], "outcome: refused", "{refusal}");
        let id = lines[2]
            .strip_prefix("reason: ")
            .unwrap_or_else(|| panic!("{refusal}: no reason line: {receipt:?}"));
        assert!(is_snake_case(id), "{refusal}: {id:?} is not snake_case");
        assert!(
            ids.insert(id.to_owned()),
            "{refusal}: the id {id} is not distinct"
        );
        assert_eq!(lines[3], format!("engine: {named}"), "{refusal}");
        assert_eq!(
            lines[4],
            format!(
                "detail: \"{}\"",
                refusal.to_string().as_bytes().escape_ascii()
            ),
            "{refusal}"
        );
    }
    assert_eq!(ids.len(), REASON_VARIANTS + 2, "{ids:?}");

    let receipt = render_refused(&examples[REASON_VARIANTS].0);
    assert_eq!(
        receipt_lines(&receipt)[2..],
        [
            "reason: verify_refused",
            "engine: none",
            "detail: \"the bundle has no signature: an unsigned bundle is refused\"",
        ],
        "the verifier refusal"
    );
    let receipt = render_refused(&examples[REASON_VARIANTS + 1].0);
    assert_eq!(
        receipt_lines(&receipt)[2..],
        [
            "reason: outputs_differ",
            "engine: none",
            "detail: \"the engines\\' outputs differ: wasmtime printed \\\"1\\\\n\\\", wasmer printed \\\"2\\\\n\\\"\"",
        ],
        "OutputsDiffer"
    );

    // Task 033: one id per Reason, as for a version query's refusal: a
    // memory reason from `run_engine` (as `TwoEngineRefusal::Engine`) has the
    // id it has from `run`'s memory check (as `TwoEngineRefusal::Memory`).
    let from_run_engine = TwoEngineRefusal::Engine(Refusal {
        path: PathBuf::from("capsule.wasm"),
        reason: Reason::MemoryMaximumMissing { minimum: 1 },
    });
    assert_eq!(
        receipt_lines(&render_refused(&from_run_engine))[2..4],
        ["reason: memory_maximum_missing", "engine: none"],
        "a memory reason from run_engine"
    );
}

/// Whether `reason` is one of task 033's memory-check reasons, which `run`
/// returns as `TwoEngineRefusal::Memory`.
fn is_memory_reason(reason: &Reason) -> bool {
    matches!(
        reason,
        Reason::MemoryNotRead(_)
            | Reason::MemoryCountAboveOne { .. }
            | Reason::MemoryMaximumMissing { .. }
            | Reason::MemoryMaximumAboveDeclared { .. }
    )
}

/// Whether the example `reason` above has an `engine` field. Coverage only, as
/// [`reason_variant`]; the receipt's own rule is in the tools crate.
fn refusal_names_engine(reason: &Reason) -> bool {
    matches!(
        reason,
        Reason::EngineDidNotStart { .. }
            | Reason::EngineFailed { .. }
            | Reason::VersionDidNotStart { .. }
            | Reason::VersionFailed { .. }
            | Reason::VersionEmpty { .. }
            | Reason::VersionNotPinned { .. }
            | Reason::CapRejected { .. }
            | Reason::BudgetExceeded { .. }
            | Reason::EngineNotStopped { .. }
            | Reason::EngineNotWaited { .. }
            | Reason::OutputNotRead { .. }
    )
}

/// Task 044: the refusal receipt of a real `run` refusal (a zero budget) is
/// written byte for byte to a new path; at the receipt just written, a planted
/// file, a live link and a dangling link it is refused with the shared
/// writer's own reason and cause, and nothing at or behind the path changes.
#[test]
fn refusal_receipt_write_refuses_an_existing_path() {
    let signed = signed_fixture();
    let tmp = TempDir::new("run44-refusal-write");
    let root = canonical(&tmp);
    let engines = work_root(&root, "engines");
    let wasmtime = counting(&engines, "wasmtime");
    let wasmer = counting(&engines, "wasmer");
    let work = work_root(&root, "work");
    let zero = RunControl::new(Duration::ZERO);
    let refusal = two_refused(run(&RunInput {
        control: &zero,
        ..input(&signed, &wasmtime, &wasmer, &work)
    }));

    let receipts = work_root(&root, "receipts");
    let written = receipts.join("refusal.txt");
    write_refused_receipt(&refusal, &written)
        .unwrap_or_else(|refusal| panic!("the refusal receipt was refused: {refusal}"));
    let first = render_refused(&refusal);
    assert_eq!(
        fs::read_to_string(&written).expect("read the refusal receipt"),
        first
    );
    assert!(first.contains("\nreason: budget_zero\n"), "{first}");

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
        ("the refusal receipt already written", &written),
        ("a planted file", &planted),
        ("a live link", &live),
        ("a dangling link", &dangling),
    ] {
        let link_before = fs::read_link(path).ok();
        let bytes_before = fs::read(path).ok();
        let write_refusal = write_refused_receipt(&refusal, path)
            .err()
            .unwrap_or_else(|| panic!("{kind}: the receipt was written over an existing path"));
        assert_eq!(&write_refusal.path, path, "{kind}");
        match &write_refusal.reason {
            WriteReason::ManifestNotCreated(error) => {
                assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{kind}");
                assert_eq!(error.raw_os_error(), Some(17), "{kind}");
            }
            other => panic!("{kind}: {other}"),
        }
        let own = write_new_file(path, b"other bytes")
            .err()
            .unwrap_or_else(|| panic!("{kind}: the shared writer wrote over an existing path"));
        assert_eq!(write_refusal.to_string(), own.to_string(), "{kind}");
        assert_eq!(
            write_refusal.to_string(),
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
        fs::read_to_string(&written).expect("read the refusal receipt"),
        first,
        "the first refusal receipt changed"
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
            "refusal.txt",
            "target.txt"
        ]
    );
}

/// Task 041 (M1 A8 lab half): the variable naming the case folder the outer
/// test gives its child, the inner test.
const A8_CASE: &str = "WASM_CAPSULE_LAB_A8_CASE";

/// The inner test the outer test starts in a child with the fixture `HOME`.
const A8_INNER: &str = "host_secret_fixture_run_inside_the_child";

/// One task 041 case folder, laid out once for the outer and the inner test.
/// Nothing in it is inside the lane tree: it is a test temp dir.
struct HostSecretCase {
    root: PathBuf,
}

impl HostSecretCase {
    /// The throwaway `HOME` the child gets.
    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// The host secret: `<home>/keys/host-secret`.
    fn fixture(&self) -> PathBuf {
        self.home().join("keys").join("host-secret")
    }

    /// The capsule `tools/build` made, built by the outer test.
    fn capsule(&self) -> PathBuf {
        self.root.join("out").join("capsule.wasm")
    }

    /// The recording shim in front of the real `engine`.
    fn shim(&self, engine: Engine) -> PathBuf {
        self.root.join("shims").join(engine.name())
    }

    /// What the shim of `engine` recorded as `what` (`argv` or `env`) when
    /// started for `kind` (`version` or `run`).
    fn record(&self, engine: Engine, kind: &str, what: &str) -> PathBuf {
        self.root
            .join("records")
            .join(format!("{}.{kind}.{what}", engine.name()))
    }

    /// The work root of the run, apart from `HOME`, the shims and the records.
    fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    /// The recorded `argv` or `env` lines of `engine`'s `kind` start.
    fn recorded_lines(&self, engine: Engine, kind: &str, what: &str) -> Vec<String> {
        let path = self.record(engine, kind, what);
        fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// A recording shim for `engine` at `case.shim(engine)`: started for
/// `--version` or for a module run, it writes its arguments, one per line, and
/// the environment it was given (`/usr/bin/env`, which inherits the shim
/// shell's exported environment, the one `exec` passes on) into the case's
/// records, then `exec`s the real engine at the absolute path `real` with the
/// same arguments. No engine runs inside an engine: the shim is replaced by it.
fn host_secret_shim(case: &HostSecretCase, engine: Engine, real: &Path) -> PathBuf {
    let records = |kind: &str, what: &str| case.record(engine, kind, what).display().to_string();
    let script = format!(
        concat!(
            "#!/bin/sh\n",
            "if [ \"$1\" = --version ]; then\n",
            "printf '%s\\n' \"$@\" > '{version_argv}'\n",
            "/usr/bin/env > '{version_env}'\n",
            "else\n",
            "printf '%s\\n' \"$@\" > '{run_argv}'\n",
            "/usr/bin/env > '{run_env}'\n",
            "fi\n",
            "exec '{real}' \"$@\"\n",
        ),
        version_argv = records("version", "argv"),
        version_env = records("version", "env"),
        run_argv = records("run", "argv"),
        run_env = records("run", "env"),
        real = real.display(),
    );
    let shims = case.root.join("shims");
    fs::create_dir_all(&shims).expect("create the shim folder");
    stand_in(&shims, engine.name(), &script)
}

/// Task 041, M1 A8 lab half, the outer test: a throwaway `HOME` holding
/// `keys/host-secret`, a marker made fresh from a fresh test key's DID, is
/// given only to a child, this test binary run as `--exact` [`A8_INNER`], so
/// no process-wide state changes here. The capsule is built first (cargo and
/// rustup read `HOME`), and a recording shim is put in front of each real
/// engine. The child's stdout and stderr are printed when it fails. If either
/// real engine is not on PATH, it prints SKIPPED and starts no child.
#[test]
fn host_secret_fixture_never_reaches_either_real_engine() {
    let Some(programs) = real_engines("the host-secret run") else {
        return;
    };
    let tmp = TempDir::new("run41-a8");
    let case = HostSecretCase {
        root: canonical(&tmp),
    };
    built_capsule(&case.root);
    fs::create_dir_all(case.fixture().parent().expect("the keys folder"))
        .expect("create <home>/keys");
    let marker = format!("host-secret-marker {}", did(&fresh_key()));
    fs::write(case.fixture(), &marker).expect("write the host secret fixture");
    fs::create_dir(case.root.join("records")).expect("create the records folder");
    for (engine_kind, real) in ENGINES.into_iter().zip(&programs) {
        host_secret_shim(&case, engine_kind, real);
    }

    let child = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", A8_INNER, "--ignored", "--nocapture"])
        .env("HOME", case.home())
        .env(A8_CASE, &case.root)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("start the child test");
    let stdout = String::from_utf8_lossy(&child.stdout);
    let stderr = String::from_utf8_lossy(&child.stderr);
    assert!(
        child.status.success() && stdout.contains("test result: ok. 1 passed;"),
        "the child {A8_INNER} did not pass ({}):\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
        child.status
    );
    eprint!("{stderr}");
    eprintln!("PASS: the host secret reached neither real engine nor either output");
}

/// Task 041, the inner test, run only by
/// `host_secret_fixture_never_reaches_either_real_engine` in a child whose
/// `HOME` is the fixture home; it fails at once under any other `HOME`. It
/// signs the built capsule with a fresh key, reads an empty grants file and
/// calls `run` with both recording shims. For each engine: the module run's
/// argv has no preopen, env or network flag ([`argv_faults`]) and no argument
/// holding the `HOME` folder; neither start's environment has `HOME` or a value
/// holding the `HOME` folder or the marker; its stdout is `FIXED_OUTPUT` and a
/// newline, holding neither.
#[test]
#[ignore = "run only as the child of host_secret_fixture_never_reaches_either_real_engine, which sets HOME to its fixture"]
fn host_secret_fixture_run_inside_the_child() {
    let root = std::env::var_os(A8_CASE).unwrap_or_else(|| {
        panic!("{A8_CASE} is not set: run host_secret_fixture_never_reaches_either_real_engine")
    });
    let case = HostSecretCase {
        root: PathBuf::from(root),
    };
    assert_eq!(
        std::env::var_os("HOME"),
        Some(case.home().into_os_string()),
        "HOME is not the fixture home"
    );
    let marker = fs::read_to_string(case.fixture()).expect("read the fixture's marker");
    assert!(!marker.is_empty(), "an empty marker proves nothing");
    let home = case.home().display().to_string();
    let fixture = case.fixture().display().to_string();
    assert!(
        !case.root.display().to_string().contains(' '),
        "argv_faults splits on spaces, so the case folder must hold none"
    );

    let key = fresh_key();
    let capsule = fs::read(case.capsule()).expect("read the built capsule");
    let (bundle, sig) = signed_bundle(&case.root, "bundle", &capsule, &key);
    let accepted = [did(&key)];
    let grants = grants_file(&case.root, "grants.json", &[]);
    let granted = read_grants(&grants).expect("read the empty grants file");
    let work = work_root(&case.root, "work");
    assert_eq!(work, case.work());
    let passed = two_ran(run(&RunInput {
        bundle: &bundle,
        signature: Some(&sig),
        accepted: &accepted,
        granted: &granted,
        wasmtime: &case.shim(Engine::Wasmtime),
        wasmer: &case.shim(Engine::Wasmer),
        work_root: &work,
        control: &TEST_CONTROL,
    }));

    let expected = format!("{FIXED_OUTPUT}\n");
    for engine_kind in ENGINES {
        let module = work.join(engine_kind.name()).join("module.wasm");
        let argv = case.recorded_lines(engine_kind, "run", "argv");
        let faults = argv_faults(&argv.join(" "), &work, &module);
        assert!(
            faults.is_empty(),
            "{engine_kind}: the module run's argv {argv:?}:\n{}",
            faults.join("\n")
        );
        for arg in &argv {
            assert!(
                !arg.contains(&home),
                "{engine_kind}: an argument holds the HOME folder {home}: {arg}"
            );
        }
        assert_eq!(
            case.recorded_lines(engine_kind, "version", "argv"),
            ["--version"],
            "{engine_kind}: the version query's argv"
        );
        for kind in ["version", "run"] {
            let env = case.recorded_lines(engine_kind, kind, "env");
            for line in &env {
                assert!(
                    !line.starts_with("HOME="),
                    "{engine_kind} {kind}: the environment has HOME: {line}"
                );
                assert!(
                    !line.contains(&home) && !line.contains(&fixture),
                    "{engine_kind} {kind}: an environment value holds the HOME folder: {line}"
                );
                assert!(
                    !line.contains(&marker),
                    "{engine_kind} {kind}: an environment value holds the marker: {line}"
                );
            }
            eprintln!("{engine_kind} {kind} environment: {env:?}");
        }
        let stdout = passed.stdout(engine_kind);
        assert_eq!(stdout, expected.as_bytes(), "{engine_kind}: the stdout");
        let stdout = String::from_utf8_lossy(stdout);
        assert!(
            !stdout.contains(&marker) && !stdout.contains(&fixture),
            "{engine_kind}: the stdout holds the marker or the fixture path"
        );
        eprintln!(
            "{engine_kind} ({}) module run argv: {argv:?}",
            String::from_utf8_lossy(passed.version(engine_kind))
        );
    }
    eprintln!("PASS: neither engine got the HOME folder, HOME or the marker");
}

/// The `wasi_snapshot_preview1` file and environment imports task 041 probes.
const HOST_SECRET_PROBES: [&str; 5] = [
    "path_open",
    "fd_read",
    "fd_prestat_get",
    "environ_get",
    "environ_sizes_get",
];

/// The module the probe imports come from.
const WASI_PREVIEW1: &str = "wasi_snapshot_preview1";

/// Task 041, M1 A8 lab half: a signed module importing each of
/// [`HOST_SECRET_PROBES`] from `wasi_snapshot_preview1` is refused by `run`:
/// with no grant as undeclared, with a `call` grant as an import with no typed
/// lab operation, each by its exact text and variant. No run folder is made and
/// no engine is asked anything, not even `--version`.
#[test]
fn host_secret_probe_imports_are_refused_before_any_engine_starts() {
    let tmp = TempDir::new("run41-probes");
    let root = canonical(&tmp);
    assert_eq!(
        importing("env", "f"),
        IMPORTING_MODULE,
        "the one module builder"
    );

    for name in HOST_SECRET_PROBES {
        let module = importing(WASI_PREVIEW1, name);
        let import = (WASI_PREVIEW1.to_owned(), name.to_owned());

        let case = format!("{name}-not-granted");
        let (result, ran) = run_with_grants(&root, &case, &module, &[]);
        let refusal = two_refused(result);
        assert_eq!(
            refusal.to_string(),
            format!("undeclared import {WASI_PREVIEW1}.{name}"),
            "{case}"
        );
        match refusal {
            TwoEngineRefusal::Verify(reason) => assert_eq!(
                reason,
                VerifyRefusal::Audit(AuditRefusal::Undeclared {
                    module: import.0.clone(),
                    name: import.1.clone(),
                }),
                "{case}"
            ),
            other => panic!("{case}: not a verifier refusal: {other}"),
        }
        assert!(names(&ran.work).is_empty(), "{case}: a run folder was made");
        assert_engine_starts(&ran, 0, &case);

        let case = format!("{name}-granted");
        let (result, ran) =
            run_with_grants(&root, &case, &module, &[(WASI_PREVIEW1, name, "call")]);
        let refusal = two_refused(result);
        assert_eq!(
            refusal.to_string(),
            format!("no typed lab operation for import {WASI_PREVIEW1}.{name}"),
            "{case}"
        );
        match refusal {
            TwoEngineRefusal::Verify(reason) => assert_eq!(
                reason,
                VerifyRefusal::UntypedImport {
                    module: import.0,
                    name: import.1,
                },
                "{case}"
            ),
            other => panic!("{case}: not a verifier refusal: {other}"),
        }
        assert!(names(&ran.work).is_empty(), "{case}: a run folder was made");
        assert_engine_starts(&ran, 0, &case);
        eprintln!("PASS: {WASI_PREVIEW1}.{name} refused, granted or not, before any engine");
    }
}
