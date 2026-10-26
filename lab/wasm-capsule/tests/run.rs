//! wc-005: the two-engine runner, `wasm_capsule_tools::run` (PRINCIPLES P3,
//! P10, P11, P18). It verifies first through wc-004's one verify path, stages
//! the verified entries, names the copy again, and runs the entrypoint module
//! under `wasmtime` and `wasmer`, two test-only host engines (neither
//! endorsed), which must agree.
//!
//! One test starts the real engines: a behaviour proof on this core module,
//! not on the Component ABI. Every other test points the runner at stand-in
//! engines, small scripts this file writes into the test's own temp dir.
//! A stand-in logs each call's arguments and prints what the test told it
//! to, so no real engine starts. The engines are runner inputs, never the
//! environment: the tests share one process, and none changes process-wide
//! state.
//!
//! Every test key is made fresh in memory inside its test and never written.

mod common;

use capsule::{FIXED_INPUT, FIXED_OUTPUT};
use capsule_identity::{sign_bundle, BundleEntry, NameSignature};
use common::build::{lane_dir, run_build, Receipt, TempDir};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use wasm_capsule_tools::run::{
    run, run_observed, Engine, Engines, Moment, Reason, RunRefusal, TwoEngineRun, INVOKE_ARGUMENTS,
    INVOKE_FUNCTION, RECEIPT_SCHEMA,
};
use wasm_capsule_tools::verify::{verify_bundle, VerifiedBundle, VerifyRefusal};
use wasm_capsule_tools::{bundle_identity, CAPSULE_MANIFEST};

/// The smallest core Wasm module: the magic and version 1, no sections. The
/// stand-in engines never read it.
const MODULE: &[u8] = b"\0asm\x01\0\0\0";

/// Another valid core module, different bytes: a custom section `x` with no
/// data.
const OTHER_MODULE: &[u8] = b"\0asm\x01\0\0\0\0\x02\x01x";

/// The exact engine versions this lab pins (BACKLOG, W1).
const WASMTIME_VERSION: &str = "wasmtime 45.0.1";
const WASMER_VERSION: &str = "wasmer 7.5.0";

/// The flags that would hand a guest a directory, the environment or the
/// network on either engine (`run --help` of each).
const AMBIENT_FLAGS: &[&str] = &[
    "--dir",
    "--mapdir",
    "--env",
    "--env-file",
    "--net",
    "--volume",
    "-S",
    "--wasi",
];

fn fresh_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// The canonical `did:key` of `key`, from the Runtime's own encoder.
fn did(key: &SigningKey) -> String {
    elastos_identity::encode_signing_key_did(key)
}

fn sign(key: &SigningKey, bundle: &Path) -> NameSignature {
    sign_bundle(key, bundle).unwrap_or_else(|refusal| panic!("sign_bundle refused: {refusal}"))
}

/// This capsule's manifest with its entrypoint changed to `entrypoint`.
fn manifest_with_entrypoint(entrypoint: &str) -> Vec<u8> {
    let text = std::str::from_utf8(CAPSULE_MANIFEST).expect("the manifest is UTF-8");
    let declared = "\"entrypoint\": \"capsule.wasm\"";
    assert_eq!(
        text.matches(declared).count(),
        1,
        "the manifest's entrypoint"
    );
    text.replace(declared, &format!("\"entrypoint\": \"{entrypoint}\""))
        .into_bytes()
}

/// A new bundle folder `name` under `tmp`, holding `manifest` as
/// `capsule.json` and each of `files` (folders made as needed).
fn bundle_with(tmp: &TempDir, name: &str, manifest: &[u8], files: &[(&str, &[u8])]) -> PathBuf {
    let bundle = tmp.path().join(name);
    fs::create_dir(&bundle).expect("create the bundle folder");
    fs::write(bundle.join("capsule.json"), manifest).expect("write capsule.json");
    for (path, bytes) in files {
        let path = bundle.join(path);
        fs::create_dir_all(path.parent().expect("a parent")).expect("create a bundle folder");
        fs::write(path, bytes).expect("write a bundle file");
    }
    bundle
}

/// This capsule's manifest beside the 8-byte module.
fn fixture(tmp: &TempDir) -> PathBuf {
    bundle_with(tmp, "bundle", CAPSULE_MANIFEST, &[("capsule.wasm", MODULE)])
}

/// A signed bundle: the bundle, its signature and the accepted list.
struct Signed {
    bundle: PathBuf,
    sig: NameSignature,
    accepted: Vec<String>,
}

fn signed(bundle: PathBuf) -> Signed {
    let key = fresh_key();
    let sig = sign(&key, &bundle);
    Signed {
        bundle,
        sig,
        accepted: vec![did(&key)],
    }
}

impl Signed {
    fn verified(&self) -> VerifiedBundle {
        verify_bundle(&self.bundle, Some(&self.sig), &self.accepted, &[])
            .unwrap_or_else(|refusal| panic!("the verifier refused: {refusal}"))
    }

    fn run(&self, engines: Engines<'_>, out: &Path) -> Result<TwoEngineRun, RunRefusal> {
        run(&self.bundle, Some(&self.sig), &self.accepted, engines, out)
    }

    fn run_observed(
        &self,
        engines: Engines<'_>,
        out: &Path,
        observe: impl FnMut(Moment, &Path),
    ) -> Result<TwoEngineRun, RunRefusal> {
        run_observed(
            &self.bundle,
            Some(&self.sig),
            &self.accepted,
            engines,
            out,
            observe,
        )
    }
}

/// What a stand-in engine does.
struct Shim<'a> {
    /// What it prints for `--version`.
    version: &'a str,
    /// Its exit status for `--version`.
    version_status: u8,
    /// Delete itself after answering `--version`, so the run cannot start.
    vanish_after_version: bool,
    /// What it prints on stdout when asked to run a module.
    stdout: &'a [u8],
    /// Its exit status when asked to run a module.
    status: u8,
}

impl Default for Shim<'_> {
    fn default() -> Self {
        Shim {
            version: "stand-in 0.0.0",
            version_status: 0,
            vanish_after_version: false,
            stdout: b"42\n",
            status: 0,
        }
    }
}

/// A stand-in engine, `name`, in its own folder under `tmp`.
struct StandIn {
    program: PathBuf,
    log: PathBuf,
}

impl StandIn {
    fn new(tmp: &TempDir, name: &str, shim: Shim<'_>) -> StandIn {
        let folder = tmp.path().join(format!("engine-{name}"));
        fs::create_dir(&folder).expect("create the stand-in folder");
        let program = folder.join(name);
        let log = folder.join("calls.log");
        let stdout = folder.join("stdout");
        fs::write(&stdout, shim.stdout).expect("write the stand-in's stdout");
        let vanish = if shim.vanish_after_version {
            "rm -- \"$0\"\n"
        } else {
            ""
        };
        let script = format!(
            "#!/bin/bash\n\
             (IFS=$'\\x1f'; printf '%s\\n' \"$*\") >> '{log}'\n\
             if [ \"$1\" = \"--version\" ]; then\n\
             printf '%s\\n' '{version}'\n\
             {vanish}\
             exit {version_status}\n\
             fi\n\
             cat '{stdout}'\n\
             exit {status}\n",
            log = log.display(),
            version = shim.version,
            version_status = shim.version_status,
            stdout = stdout.display(),
            status = shim.status,
        );
        fs::write(&program, script).expect("write the stand-in");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755))
            .expect("make the stand-in executable");
        StandIn { program, log }
    }

    /// Each call's arguments, in order. No log means no call.
    fn calls(&self) -> Vec<Vec<String>> {
        match fs::read_to_string(&self.log) {
            Ok(text) => text
                .lines()
                .map(|line| line.split('\x1f').map(str::to_owned).collect())
                .collect(),
            Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("read the stand-in log: {error}"),
        }
    }
}

/// Two stand-in engines.
struct StandIns {
    wasmtime: StandIn,
    wasmer: StandIn,
}

impl StandIns {
    fn new(tmp: &TempDir, wasmtime: Shim<'_>, wasmer: Shim<'_>) -> StandIns {
        StandIns {
            wasmtime: StandIn::new(tmp, "wasmtime", wasmtime),
            wasmer: StandIn::new(tmp, "wasmer", wasmer),
        }
    }

    fn agreeing(tmp: &TempDir) -> StandIns {
        StandIns::new(tmp, Shim::default(), Shim::default())
    }

    fn engines(&self) -> Engines<'_> {
        Engines {
            wasmtime: &self.wasmtime.program,
            wasmer: &self.wasmer.program,
        }
    }

    fn assert_none_started(&self) {
        assert_eq!(
            self.wasmtime.calls(),
            Vec::<Vec<String>>::new(),
            "wasmtime was started"
        );
        assert_eq!(
            self.wasmer.calls(),
            Vec::<Vec<String>>::new(),
            "wasmer was started"
        );
    }
}

fn ran(result: Result<TwoEngineRun, RunRefusal>) -> TwoEngineRun {
    result.unwrap_or_else(|refusal| panic!("the runner refused: {refusal}"))
}

fn refused(result: Result<TwoEngineRun, RunRefusal>) -> RunRefusal {
    match result {
        Ok(run) => panic!("the runner ran {} and printed {:?}", run.cid, run.stdout),
        Err(refusal) => refusal,
    }
}

/// The run arguments each engine must get for `module`, exactly.
fn expected_run_args(module: &Path) -> Vec<String> {
    let mut args = vec![
        "run".to_owned(),
        "--invoke".to_owned(),
        INVOKE_FUNCTION.to_owned(),
        module.display().to_string(),
    ];
    args.extend(INVOKE_ARGUMENTS.iter().map(|arg| (*arg).to_owned()));
    args
}

/// Every regular file under `root`, as (relative `/` path, bytes), sorted.
fn files_under(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut folders = vec![root.to_path_buf()];
    while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(&folder).expect("list a staged folder") {
            let path = entry.expect("read a staged entry").path();
            let kind = fs::symlink_metadata(&path).expect("stat a staged entry");
            if kind.is_dir() {
                folders.push(path);
            } else {
                assert!(kind.is_file(), "{} is not a regular file", path.display());
                let relative = path.strip_prefix(root).expect("under the root");
                let bytes = fs::read(&path).expect("read a staged file");
                files.push((relative.display().to_string(), bytes));
            }
        }
    }
    files.sort();
    files
}

fn sorted(entries: &[BundleEntry]) -> Vec<(String, Vec<u8>)> {
    let mut entries: Vec<(String, Vec<u8>)> = entries
        .iter()
        .map(|entry| (entry.path.clone(), entry.content.clone()))
        .collect();
    entries.sort();
    entries
}

/// The program `name` from the test process's PATH. The runner itself never
/// reads the environment; the test finds the installed engine and passes its
/// path in.
fn installed_engine(name: &str) -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH is set");
    std::env::split_paths(&path)
        .map(|folder| folder.join(name))
        .find(|program| program.is_file())
        .unwrap_or_else(|| panic!("{name} is not installed: the lab pins it (BACKLOG, W1)"))
}

#[test]
fn same_name_same_output_on_wasmtime_and_wasmer() {
    // A behaviour proof on two real engines, for this one core module.
    let tmp = TempDir::new("run-real");
    let built = tmp.path().join("built");
    fs::create_dir(&built).expect("create OUT_DIR for tools/build");
    run_build(&lane_dir(), &built);
    let module = fs::read(built.join("capsule.wasm")).expect("read the built capsule.wasm");
    let bundle = signed(bundle_with(
        &tmp,
        "bundle",
        CAPSULE_MANIFEST,
        &[("capsule.wasm", &module)],
    ));
    let wasmtime = installed_engine("wasmtime");
    let wasmer = installed_engine("wasmer");
    let engines = Engines {
        wasmtime: &wasmtime,
        wasmer: &wasmer,
    };
    let out = tmp.path().join("out");

    let result = ran(bundle.run(engines, &out));
    let expected = format!("{}\n", FIXED_OUTPUT as i64);
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        expected,
        "digest({FIXED_INPUT:#x}) is not FIXED_OUTPUT"
    );
    let cid = bundle_identity(&bundle.bundle).expect("the bundle is named");
    assert_eq!(result.cid, cid);
    assert!(
        result
            .wasmtime_version
            .starts_with(&format!("{WASMTIME_VERSION} ")),
        "wasmtime is {:?}, not {WASMTIME_VERSION}",
        result.wasmtime_version
    );
    assert_eq!(result.wasmer_version, WASMER_VERSION);

    let text = fs::read_to_string(&result.receipt).expect("read the receipt");
    let receipt = Receipt::parse(&text);
    assert_eq!(receipt.get("schema"), RECEIPT_SCHEMA);
    assert_eq!(receipt.get("bundle"), cid.to_string());
    assert_eq!(receipt.get("entrypoint"), "capsule.wasm");
    assert_eq!(receipt.get("function"), "digest");
    assert_eq!(receipt.get("arguments"), FIXED_INPUT.to_string());
    assert_eq!(receipt.get("wasmtime_version"), result.wasmtime_version);
    assert_eq!(receipt.get("wasmer_version"), WASMER_VERSION);
    for engine in ["wasmtime", "wasmer"] {
        assert_eq!(receipt.get(&format!("{engine}_exit")), "0");
        assert_eq!(
            receipt.get(&format!("{engine}_stdout")),
            format!("{expected:?}")
        );
    }
    // The name is the lab CID alone: no engine version is part of it.
    let name = receipt.get("bundle");
    for version in ["45.0.1", "7.5.0", "wasmtime", "wasmer"] {
        assert!(!name.contains(version), "the name holds {version}: {name}");
    }
}

#[test]
fn runner_refuses_an_unverified_bundle() {
    let tmp = TempDir::new("run-unverified");
    let stand_ins = StandIns::agreeing(&tmp);
    let bundle = fixture(&tmp);
    let key = fresh_key();
    let other = fresh_key();
    let sig = sign(&key, &bundle);
    let accepted = [did(&key)];

    // No signature, a signer not on the list, and bytes changed after signing.
    let changed = signed(bundle_with(
        &tmp,
        "changed",
        CAPSULE_MANIFEST,
        &[("capsule.wasm", MODULE)],
    ));
    fs::write(changed.bundle.join("capsule.wasm"), OTHER_MODULE).expect("change capsule.wasm");
    let cases: [(&Path, Option<&NameSignature>, Vec<String>, &str); 3] = [
        (bundle.as_path(), None, accepted.to_vec(), "unsigned"),
        (
            bundle.as_path(),
            Some(&sig),
            vec![did(&other)],
            "an unlisted signer",
        ),
        (
            changed.bundle.as_path(),
            Some(&changed.sig),
            changed.accepted.clone(),
            "changed after signing",
        ),
    ];
    for (index, (bundle, sig, accepted, kind)) in cases.into_iter().enumerate() {
        let out = tmp.path().join(format!("out-{index}"));
        let own = verify_bundle(bundle, sig, &accepted, &[]).expect_err("the verifier refuses");
        let refusal = refused(run(bundle, sig, &accepted, stand_ins.engines(), &out));
        assert_eq!(refusal.path, bundle, "{kind}");
        assert_eq!(
            refusal.to_string(),
            format!(
                "{}: not verified, no engine started: {own}",
                bundle.display()
            ),
            "{kind}"
        );
        match refusal.reason {
            Reason::Verify(reason) => assert_eq!(reason, own, "{kind}"),
            other => panic!("{kind}: not the verifier's refusal: {other}"),
        }
        assert!(!out.exists(), "{kind}: OUT_DIR was made");
    }
    stand_ins.assert_none_started();
    assert_eq!(
        verify_bundle(&bundle, None, &accepted, &[]).expect_err("unsigned"),
        VerifyRefusal::Unsigned
    );
}

#[test]
fn runner_passes_no_directory_env_or_network_flags() {
    // An argv proof, not behaviour: it checks the exact command line each
    // engine gets. The real-engine test proves the module's output.
    let tmp = TempDir::new("run-argv");
    let stand_ins = StandIns::agreeing(&tmp);
    let bundle = signed(fixture(&tmp));
    let out = tmp.path().join("out");

    ran(bundle.run(stand_ins.engines(), &out));
    let module = out.join("staged").join("capsule.wasm");
    for (engine, stand_in) in [
        ("wasmtime", &stand_ins.wasmtime),
        ("wasmer", &stand_ins.wasmer),
    ] {
        let calls = stand_in.calls();
        assert_eq!(
            calls,
            [vec!["--version".to_owned()], expected_run_args(&module)],
            "{engine}'s command lines"
        );
        for arg in calls.iter().flatten() {
            for flag in AMBIENT_FLAGS {
                assert!(
                    arg != flag && !arg.starts_with(&format!("{flag}=")),
                    "{engine} got the ambient flag {arg:?}"
                );
            }
        }
    }
    let wasmer_args = stand_ins.wasmer.calls().concat();
    for flag in ["--env", "--dir"] {
        assert!(
            !wasmer_args.iter().any(|arg| arg.starts_with(flag)),
            "wasmer got {flag}: {wasmer_args:?}"
        );
    }
}

#[test]
fn differing_engine_outputs_are_reported_as_a_failure() {
    let tmp = TempDir::new("run-differ");
    let stand_ins = StandIns::new(
        &tmp,
        Shim {
            stdout: b"1\n",
            ..Shim::default()
        },
        Shim {
            stdout: b"2\n",
            ..Shim::default()
        },
    );
    let bundle = signed(fixture(&tmp));
    let out = tmp.path().join("out");

    let refusal = refused(bundle.run(stand_ins.engines(), &out));
    let module = out.join("staged").join("capsule.wasm");
    assert_eq!(refusal.path, module);
    assert!(
        matches!(
            &refusal.reason,
            Reason::OutputsDiffer { wasmtime, wasmer }
                if wasmtime == b"1\n" && wasmer == b"2\n"
        ),
        "not the differing-output reason: {refusal}"
    );
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: the engines' stdout differs: wasmtime \"1\\n\", wasmer \"2\\n\"",
            module.display()
        )
    );
    assert!(
        !out.join("receipt.txt").exists(),
        "a refused run has a receipt"
    );
}

#[test]
fn matching_engine_failures_are_refused() {
    // Both engines fail the same way: equal output and equal status are
    // still a failure.
    let tmp = TempDir::new("run-both-fail");
    let failing = || Shim {
        stdout: b"same\n",
        status: 3,
        ..Shim::default()
    };
    let stand_ins = StandIns::new(&tmp, failing(), failing());
    let bundle = signed(fixture(&tmp));
    let out = tmp.path().join("out");

    let refusal = refused(bundle.run(stand_ins.engines(), &out));
    assert_eq!(refusal.path, stand_ins.wasmtime.program);
    assert!(
        matches!(
            &refusal.reason,
            Reason::EngineFailed { engine: Engine::Wasmtime, status, .. }
                if status.code() == Some(3)
        ),
        "not wasmtime's failure: {refusal}"
    );
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: wasmtime failed (exit status: 3); its stderr: \"\"",
            stand_ins.wasmtime.program.display()
        )
    );
    assert!(
        !out.join("receipt.txt").exists(),
        "a refused run has a receipt"
    );

    // Only one engine fails: that engine is named.
    let tmp = TempDir::new("run-one-fails");
    let stand_ins = StandIns::new(&tmp, Shim::default(), failing());
    let out = tmp.path().join("out");
    let refusal = refused(bundle.run(stand_ins.engines(), &out));
    assert_eq!(refusal.path, stand_ins.wasmer.program);
    assert!(
        matches!(
            &refusal.reason,
            Reason::EngineFailed { engine: Engine::Wasmer, status, .. }
                if status.code() == Some(3)
        ),
        "not wasmer's failure: {refusal}"
    );
}

#[test]
fn runner_executes_audited_entrypoint() {
    // The manifest names main.wasm; capsule.wasm is another module beside it.
    let tmp = TempDir::new("run-entrypoint");
    let stand_ins = StandIns::agreeing(&tmp);
    let bundle = signed(bundle_with(
        &tmp,
        "bundle",
        &manifest_with_entrypoint("main.wasm"),
        &[("main.wasm", MODULE), ("capsule.wasm", OTHER_MODULE)],
    ));
    let verified = bundle.verified();
    assert_eq!(verified.entrypoint().path, "main.wasm");
    let out = tmp.path().join("out");

    ran(bundle.run(stand_ins.engines(), &out));
    let module = out.join("staged").join("main.wasm");
    for stand_in in [&stand_ins.wasmtime, &stand_ins.wasmer] {
        let calls = stand_in.calls();
        assert_eq!(calls.len(), 2, "calls: {calls:?}");
        assert_eq!(calls[1], expected_run_args(&module), "not the entrypoint");
    }
    assert_eq!(
        fs::read(&module).expect("read the staged entrypoint"),
        verified.entrypoint().content,
        "the engines did not get the audited bytes"
    );
}

#[test]
fn runner_stages_all_verified_entries() {
    let tmp = TempDir::new("run-stage");
    let stand_ins = StandIns::agreeing(&tmp);
    let bundle = signed(bundle_with(
        &tmp,
        "bundle",
        CAPSULE_MANIFEST,
        &[
            ("capsule.wasm", MODULE),
            ("data/notes.txt", b"a nested entry\n"),
            ("data/deep/blob.bin", &[0, 1, 2, 3]),
        ],
    ));
    let verified = bundle.verified();
    let out = tmp.path().join("out");

    // The source module changes once the staged folder is made: the runner
    // stages the verified bytes, never a re-read of the bundle.
    let source = bundle.bundle.join("capsule.wasm");
    let result = ran(bundle.run_observed(stand_ins.engines(), &out, |moment, _| {
        if moment == Moment::StagedFolderMade {
            fs::write(&source, OTHER_MODULE).expect("change the source module");
        }
    }));
    let staged = out.join("staged");
    assert_eq!(files_under(&staged), sorted(verified.entries()));
    assert_eq!(sorted(verified.entries()).len(), 4, "every entry");
    assert_eq!(bundle_identity(&staged).expect("named"), verified.cid());
    assert_eq!(result.cid, verified.cid());

    // The engines run the staged copy, not the bundle's own file.
    let module = staged.join("capsule.wasm");
    for stand_in in [&stand_ins.wasmtime, &stand_ins.wasmer] {
        assert_eq!(
            stand_in.calls()[1],
            expected_run_args(&module),
            "the engine did not get the staged module"
        );
    }
}

#[test]
fn runner_refuses_staged_name_mismatch() {
    let tmp = TempDir::new("run-mismatch");
    let stand_ins = StandIns::agreeing(&tmp);
    let bundle = signed(fixture(&tmp));
    let verified = bundle.verified();
    let out = tmp.path().join("out");

    // Another process adds a file to the staged copy before it is named.
    let refusal = refused(
        bundle.run_observed(stand_ins.engines(), &out, |moment, staged| {
            if moment == Moment::EntriesStaged {
                fs::write(staged.join("planted.txt"), b"not verified\n").expect("plant a file");
            }
        }),
    );
    let staged = out.join("staged");
    let copy = bundle_identity(&staged).expect("the changed copy is named");
    assert_ne!(copy, verified.cid());
    assert_eq!(refusal.path, staged);
    assert!(
        matches!(
            &refusal.reason,
            Reason::StagedNameMismatch { verified: v, staged: s }
                if *v == verified.cid() && *s == copy
        ),
        "not the name mismatch: {refusal}"
    );
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: the staged copy is named {copy}, not the verified {}: no engine started",
            staged.display(),
            verified.cid()
        )
    );
    stand_ins.assert_none_started();
}

#[test]
fn receipt_records_observed_engine_versions() {
    let tmp = TempDir::new("run-versions");
    let stand_ins = StandIns::new(
        &tmp,
        Shim {
            version: "wasmtime 99.1.2 (stand-in)",
            ..Shim::default()
        },
        Shim {
            version: "wasmer 98.0.0-stand-in",
            ..Shim::default()
        },
    );
    let bundle = signed(fixture(&tmp));
    let out = tmp.path().join("out");

    let result = ran(bundle.run(stand_ins.engines(), &out));
    assert_eq!(result.wasmtime_version, "wasmtime 99.1.2 (stand-in)");
    assert_eq!(result.wasmer_version, "wasmer 98.0.0-stand-in");
    assert_eq!(result.receipt, out.join("receipt.txt"));
    let receipt = Receipt::parse(&fs::read_to_string(&result.receipt).expect("read"));
    assert_eq!(
        receipt.get("wasmtime_version"),
        "wasmtime 99.1.2 (stand-in)"
    );
    assert_eq!(receipt.get("wasmer_version"), "wasmer 98.0.0-stand-in");
    assert_eq!(receipt.get("wasmtime_stdout"), "\"42\\n\"");
    assert_eq!(receipt.get("wasmer_stdout"), "\"42\\n\"");
}

/// The refusal's io cause, for the reasons that carry one.
fn cause(reason: &Reason) -> &std::io::Error {
    match reason {
        Reason::OutDirNotCreated(cause)
        | Reason::FolderNotStaged(cause)
        | Reason::EntryNotStaged(cause)
        | Reason::ReceiptNotWritten(cause)
        | Reason::VersionNotQueried { cause, .. }
        | Reason::EngineNotStarted { cause, .. } => cause,
        other => panic!("no io cause: {other}"),
    }
}

/// Check one operation failure: its path, its reason's own words with the
/// system's cause, and the cause's kind.
fn assert_failure(
    refusal: &RunRefusal,
    path: &Path,
    words: &str,
    kind: ErrorKind,
    is_reason: fn(&Reason) -> bool,
) {
    assert!(is_reason(&refusal.reason), "{words}: got {refusal}");
    assert_eq!(refusal.path, path, "{words}");
    let cause = cause(&refusal.reason);
    assert_eq!(cause.kind(), kind, "{words}");
    assert_eq!(
        refusal.to_string(),
        format!("{}: {words}: {cause}", path.display())
    );
}

#[test]
fn runner_operation_failures_keep_their_cause() {
    let tmp = TempDir::new("run-causes");
    let agreeing = StandIns::agreeing(&tmp);
    let bundle = signed(bundle_with(
        &tmp,
        "bundle",
        CAPSULE_MANIFEST,
        &[("capsule.wasm", MODULE), ("data/notes.txt", b"nested\n")],
    ));
    let out = |name: &str| tmp.path().join(name);

    // Staging: OUT_DIR already there, OUT_DIR's parent missing, a file where
    // a staged folder goes, and a file where a staged entry goes.
    fs::create_dir(out("existing")).expect("create a folder");
    let refusal = refused(bundle.run(agreeing.engines(), &out("existing")));
    assert!(matches!(refusal.reason, Reason::OutDirExists), "{refusal}");
    assert_eq!(refusal.path, out("existing"));

    let orphan = out("missing").join("out");
    let refusal = refused(bundle.run(agreeing.engines(), &orphan));
    assert_failure(
        &refusal,
        &orphan,
        "OUT_DIR cannot be created",
        ErrorKind::NotFound,
        |reason| matches!(reason, Reason::OutDirNotCreated(_)),
    );

    let plant = |name: &'static str| {
        move |moment: Moment, staged: &Path| {
            if moment == Moment::StagedFolderMade {
                fs::write(staged.join(name), b"planted\n").expect("plant a file");
            }
        }
    };
    let refusal = refused(bundle.run_observed(agreeing.engines(), &out("folder"), plant("data")));
    assert_failure(
        &refusal,
        &out("folder").join("staged").join("data"),
        "a staged folder cannot be created",
        ErrorKind::AlreadyExists,
        |reason| matches!(reason, Reason::FolderNotStaged(_)),
    );
    let refusal =
        refused(bundle.run_observed(agreeing.engines(), &out("entry"), plant("capsule.json")));
    assert_failure(
        &refusal,
        &out("entry").join("staged").join("capsule.json"),
        "a verified entry cannot be staged",
        ErrorKind::AlreadyExists,
        |reason| matches!(reason, Reason::EntryNotStaged(_)),
    );

    // The version query: a program that is not there, and one that fails.
    let absent = tmp.path().join("no-such-engine");
    let engines = Engines {
        wasmtime: &absent,
        wasmer: &agreeing.wasmer.program,
    };
    let refusal = refused(bundle.run(engines, &out("version-start")));
    assert_failure(
        &refusal,
        &absent,
        "wasmtime --version did not start",
        ErrorKind::NotFound,
        |reason| {
            matches!(
                reason,
                Reason::VersionNotQueried {
                    engine: Engine::Wasmtime,
                    ..
                }
            )
        },
    );
    let failing = StandIn::new(
        &tmp,
        "failing-version",
        Shim {
            version_status: 4,
            ..Shim::default()
        },
    );
    let engines = Engines {
        wasmtime: &agreeing.wasmtime.program,
        wasmer: &failing.program,
    };
    let refusal = refused(bundle.run(engines, &out("version-fail")));
    assert_eq!(refusal.path, failing.program);
    assert!(
        matches!(
            &refusal.reason,
            Reason::VersionQueryFailed { engine: Engine::Wasmer, status }
                if status.code() == Some(4)
        ),
        "not the failed version query: {refusal}"
    );
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: wasmer --version failed (exit status: 4)",
            failing.program.display()
        )
    );

    // The engine start: the program answers --version, then is gone.
    let vanishing = StandIn::new(
        &tmp,
        "vanishing",
        Shim {
            vanish_after_version: true,
            ..Shim::default()
        },
    );
    let engines = Engines {
        wasmtime: &vanishing.program,
        wasmer: &agreeing.wasmer.program,
    };
    let refusal = refused(bundle.run(engines, &out("engine-start")));
    assert_failure(
        &refusal,
        &vanishing.program,
        "wasmtime did not start",
        ErrorKind::NotFound,
        |reason| {
            matches!(
                reason,
                Reason::EngineNotStarted {
                    engine: Engine::Wasmtime,
                    ..
                }
            )
        },
    );

    // The receipt: something is already at its path when it is written.
    let receipt_out = out("receipt");
    let receipt = receipt_out.join("receipt.txt");
    let refusal = refused(
        bundle.run_observed(agreeing.engines(), &receipt_out, |moment, _| {
            if moment == Moment::EntriesStaged {
                fs::write(&receipt, b"planted\n").expect("plant a receipt");
            }
        }),
    );
    assert_failure(
        &refusal,
        &receipt,
        "the receipt cannot be written",
        ErrorKind::AlreadyExists,
        |reason| matches!(reason, Reason::ReceiptNotWritten(_)),
    );
    assert_eq!(fs::read(&receipt).expect("read"), b"planted\n");
}

/// The runner's module, without its whole-line comments.
fn runner_code() -> String {
    include_str!("../tools/src/run.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn runner_has_one_verify_path_and_reads_no_environment() {
    let code = runner_code();
    assert_eq!(
        code.matches("verify_bundle(").count(),
        1,
        "the runner verifies in more than one place"
    );
    // Built at run time, so this file does not match itself.
    let own_checks = [
        ["verify", "_checked"].concat(),
        ["checked", "_bundle"].concat(),
        ["audit", "("].concat(),
        ["Capsule", "Manifest"].concat(),
        ["serde", "_json"].concat(),
    ];
    for own in &own_checks {
        assert!(!code.contains(own.as_str()), "the runner holds {own}");
    }
    for ambient in [["env", "::"].concat(), ["var", "_os"].concat()] {
        assert!(
            !code.contains(ambient.as_str()),
            "the runner reads the environment: {ambient}"
        );
    }
    assert_eq!(
        code.matches("Command::new(").count(),
        1,
        "the runner starts processes in more than one place"
    );
}
