//! Confinement proof for wallet-provider.
//!
//! Each test starts the real provider binary under `capsules/wallet-provider/confine.sb`
//! with `/usr/bin/sandbox-exec` and drives it over its normal stdin/stdout
//! protocol. The provider opens no network listener or socket: it reads
//! line-delimited JSON from stdin and writes one JSON response per line to
//! stdout, and the profile denies every network operation.
//!
//! `CONFINEMENT.md` says the confinement tests exercise these profiles on
//! macOS through `/usr/bin/sandbox-exec`. On a declared host OS a missing
//! `/usr/bin/sandbox-exec` fails the test, and `sandbox_available` is the call
//! that fails it. On any other OS, when that tool is missing, the test prints
//! why it did not run and returns.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use bitcoin::hashes::Hash as _;
use elastos_auth::ethereum_signed_message_hash;
use elastos_protected_content_contracts::{
    CanonicalContract, ContentAccessIdV1, CustodyCommitteeAuthorizationIdentityV1,
    CustodyEpochIdentityV1, CustodyPoolIdentityV1, Digest32, EncryptedContentIdentityV1,
    EvmContractAddressV1, EvmFunctionSelectorV1, EvmRightsMethodAbiV1, KeyEnvelopeIdentityV1,
    ProfileIdentityV1, ProtectedContentBindingV1, RecipientKeyIdentityV1, ReplayNonce16,
    RightsActionV1, RightsObservationFinalityV1, RightsPolicyBodyV1, RightsRequestV1,
    RightsSubjectSourceV1, RuntimeSessionBindingV1, ThresholdV1, WalletAddress,
};
use elastos_wallet_contract::{
    Erc1271ProofEvidenceV1, ManagedRecoveryKeyEntryV1, ManagedRecoverySetV1, PublicNetwork,
    ValidatedChainOutcomeBindingV1, ValidatedChainOutcomeV1, VerifiedWalletInvocationContext,
    WalletProviderOperationV2, WalletProviderRequestV2, WalletProviderResponseV2, WalletResultV2,
    PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT, VALIDATED_CHAIN_OUTCOME_SCHEMA,
};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::LazyLock;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// The one lab profile generator, included rather than copied: the did, wallet
// and model test crates all name this one file (P10).
#[path = "common/profile_generator.rs"]
mod profile_generator;

use profile_generator::{
    declared_entries, generate_profile, platform_baseline_justification, platform_baseline_status,
    write_generated_profile, DeclaredClaim, CONTRACT_RIGHTS, DECLARED_RIGHTS_ROLE,
    PLATFORM_BASELINE, PLATFORM_BASELINE_IDS, PROFILE_HEAD,
};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
/// The host OSes where `CONFINEMENT.md` says the confinement tests exercise
/// these profiles through `/usr/bin/sandbox-exec`, so a test there must run,
/// not skip.
const DECLARED_CONFINED_OS: [&str; 1] = ["macos"];
const PROVIDER_BINARY: &str = env!("CARGO_BIN_EXE_wallet-provider");
const PROFILE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/confine.sb");
const WALLET_KEY_FILE: &str = "wallet-key.hex";
/// The storage key's length in bytes; its file holds the same value as lowercase
/// hex digits and one newline.
#[cfg(target_os = "linux")]
const WALLET_KEY_BYTES: usize = 32;
const WALLET_DIR: [&str; 3] = ["ElastOS", "SystemServices", "Wallet"];
/// The provider names the stand-in launcher serves. One derivation picks each
/// provider's storage-root layout from its name.
const DID_PROVIDER: &str = "did-provider";
const WALLET_PROVIDER: &str = "wallet-provider";
/// The isolated fixture device key, the same input did's own confinement test
/// uses, so a started did provider derives the same DID there and here.
const DID_DEVICE_KEY: [u8; 32] = [0x42; 32];
/// How long a failure path waits for the child to exit before it reports.
const CHILD_EXIT_DEADLINE: Duration = Duration::from_secs(10);
/// How often the bounded wait checks whether the child has exited.
const CHILD_EXIT_POLL: Duration = Duration::from_millis(20);

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

/// The heap allocations a probe child makes after its fork. A forked child may
/// rely only on async-signal-safe calls, and the allocator is not one of them:
/// another thread of the parent can hold its lock at the moment of the fork, so
/// an allocation in the child can block for ever. The child counts its own
/// allocations and refuses its own report when the count is not zero.
///
/// The child is a fork of this process and holds only the calling thread, so
/// this flag in the child's own copy is the child's alone and the parent's
/// threads, which keep running in the parent's copy, cannot set it.
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static COUNT_ALLOCATIONS: AtomicBool = AtomicBool::new(false);

/// The test binary's allocator, which counts the probe child's allocations and
/// changes nothing else.
struct CountingAllocator;

unsafe impl std::alloc::GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        self.count_one();
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        self.count_one();
        unsafe { std::alloc::System.realloc(pointer, layout, size) }
    }
}

impl CountingAllocator {
    /// Counts this allocation when the calling process is a counted probe
    /// child.
    fn count_one(&self) {
        if COUNT_ALLOCATIONS.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Whether a sandbox test runs on this host.
///
/// A present `sandbox_exec` runs the test on any OS. A missing one is an error
/// on an OS where `CONFINEMENT.md` says the confinement tests exercise these
/// profiles, because a test there must run, not skip, and a skip would pass a
/// profile that was never exercised (P11). On any other OS it is a skip.
fn sandbox_gate(os: &str, sandbox_exec: &Path) -> Result<bool, String> {
    if sandbox_exec.is_file() {
        return Ok(true);
    }
    if DECLARED_CONFINED_OS.contains(&os) {
        return Err(format!(
            "CONFINEMENT.md says the confinement tests exercise these profiles on {os}, \
             so a test there must run, not skip: {} is absent",
            sandbox_exec.display()
        ));
    }
    Ok(false)
}

/// Returns `true` when the test can run, and fails it on a declared OS.
///
/// On `Err` from `sandbox_gate` this fails the test with that reason. It does
/// not return `false` for an error. It prints the skip line only when the gate
/// answers `Ok(false)`.
fn sandbox_available(os: &str, sandbox_exec: &Path) -> bool {
    match sandbox_gate(os, sandbox_exec) {
        Ok(true) => true,
        Ok(false) => {
            eprintln!(
                "SKIP provider confinement test: {} is absent; \
                 the profile was not exercised on this machine",
                sandbox_exec.display()
            );
            false
        }
        Err(reason) => panic!("{reason}"),
    }
}

/// A declared host OS runs its confinement tests; it never passes by skipping.
///
/// A missing `sandbox-exec` on `macos` is an error that names the OS and the
/// path, a missing one on `linux` is a skip, and a present one on `macos` runs
/// the test. The test starts no process, so it runs on every supported build
/// target.
///
/// Falsifier: return `Ok(false)` from the declared-OS branch (WP27); the
/// `macos` case fails because a missing `sandbox-exec` skips and passes.
#[test]
fn sandbox_gate_fails_instead_of_skipping_on_a_declared_os() {
    let missing = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/absent-sandbox-exec");
    assert!(
        !missing.exists(),
        "the fixture path must be absent: {}",
        missing.display()
    );
    let present = std::env::current_exe().expect("the test executable path must be available");
    assert!(
        present.is_file(),
        "the present fixture must be a file: {}",
        present.display()
    );

    let refusal = sandbox_gate("macos", &missing)
        .expect_err("a declared OS must run its confinement test, not skip it");
    assert!(
        refusal.contains("macos") && refusal.contains(&missing.display().to_string()),
        "the refusal must name the OS and the missing path: {refusal}"
    );
    assert_eq!(
        sandbox_gate("linux", &missing),
        Ok(false),
        "an undeclared OS may skip the test it cannot run"
    );
    assert_eq!(
        sandbox_gate("macos", &present),
        Ok(true),
        "a declared OS runs the test when sandbox-exec is present"
    );
}

/// The one caller fails the test when the gate refuses a declared host OS.
///
/// With `macos` and a missing `sandbox-exec` the call panics and its payload,
/// read as a `String`, is the gate's reason, which names the OS and the path.
/// A return fails this test with the returned value. A present path on
/// `macos` returns `true`. The test calls no OS that skips, so it prints no
/// skip line, and it starts no process.
///
/// Falsifier: WP30 returns `false` from the error arm of `sandbox_available`,
/// so a missing `sandbox-exec` on `macos` returns and this test fails.
#[test]
fn sandbox_available_fails_for_macos_when_sandbox_exec_is_missing() {
    let missing = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/absent-sandbox-exec");
    assert!(
        !missing.exists(),
        "the fixture path must be absent: {}",
        missing.display()
    );
    let present = std::env::current_exe().expect("the test executable path must be available");
    assert!(
        present.is_file(),
        "the present fixture must be a file: {}",
        present.display()
    );

    let settled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sandbox_available("macos", &missing)
    }));
    let failure = match settled {
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .expect("the gate's reason must arrive as a String payload"),
        Ok(returned) => panic!(
            "a missing sandbox-exec on macos must fail the test, but sandbox_available returned {returned}"
        ),
    };
    let expected = sandbox_gate("macos", &missing)
        .expect_err("a declared OS must refuse a missing sandbox-exec");
    assert_eq!(
        failure, expected,
        "the panic payload must be the gate's reason"
    );
    assert!(
        failure.contains("macos") && failure.contains(&missing.display().to_string()),
        "the refusal must name the OS and the missing path: {failure}"
    );
    assert!(
        sandbox_available("macos", &present),
        "a present sandbox-exec on macos must let the confined test run"
    );
}

/// The test launch refuses a second binding of a canonical parameter.
///
/// `start_with_profile` takes the three canonical bindings from
/// `canonical_bindings`, which derives them from one base, and then appends
/// the caller's parameters. A caller that binds `STORAGE_ROOT`,
/// `STORAGE_PARENT` or `PROVIDER_EXECUTABLE` again could point the launch at a
/// folder the test did not create, so the call panics with a message that
/// names the parameter and says the canonical bindings come only from
/// `canonical_bindings`. The refusal comes before the shared ancestors are
/// created and before any spawn, so the test needs no `sandbox_available` gate
/// and no directory appears under the base.
///
/// Falsifier: drop the refusal from `start_with_profile` (WP54); on a Mac this
/// returns a running provider instead of the panic, and without
/// `sandbox-exec` the spawn panics with a different message, so the test fails
/// on every host.
#[test]
fn start_with_profile_refuses_a_canonical_parameter() {
    for name in CANONICAL_PARAMS {
        let base = tempfile::tempdir().expect("temporary wallet base");
        let base = resolved(base.path());
        let rebinding = wallet_dir(&base).join("rebound");
        let settled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ConfinedProvider::start_with_profile(
                &base,
                Path::new(PROFILE_PATH),
                &[(name, rebinding.as_path())],
            )
        }));
        let failure = match settled {
            Err(payload) => payload,
            Ok(_provider) => panic!(
                "binding the canonical parameter {name} again must be refused, \
                 but start_with_profile returned a provider"
            ),
        };
        let message = failure
            .downcast_ref::<String>()
            .expect("the refusal must arrive as a String payload");
        assert!(
            message.contains(name),
            "the refusal must name {name}: {message}"
        );
        assert!(
            message.contains("canonical_bindings"),
            "the refusal must say the canonical bindings come only from canonical_bindings: {message}"
        );
        assert!(
            fs::read_dir(&base)
                .expect("the temporary base must be readable")
                .next()
                .is_none(),
            "the refusal must come before the shared ancestors are created: {}",
            base.display()
        );
    }
}

/// The same launch check owns canonical names encoded before `=`.
///
/// `sandbox-exec -D` reads the name before the first `=`, so a caller's
/// `STORAGE_ROOT=/outside` would replace the canonical storage binding.
/// Check every canonical name with an empty value, a path, and another `=`.
/// Each refusal names the caller's parameter and precedes directory creation.
///
/// Falsifier: WP55 checks the caller's whole name again, so an encoded
/// canonical name reaches the launch instead of this refusal.
#[test]
fn start_with_profile_refuses_an_encoded_canonical_parameter() {
    for canonical_name in CANONICAL_PARAMS {
        for suffix in ["", "/outside", "/outside=/fixture"] {
            let name = format!("{canonical_name}={suffix}");
            let base = tempfile::tempdir().expect("temporary wallet base");
            let base = resolved(base.path());
            let rebinding = wallet_dir(&base).join("rebound");
            let settled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ConfinedProvider::start_with_profile(
                    &base,
                    Path::new(PROFILE_PATH),
                    &[(name.as_str(), rebinding.as_path())],
                )
            }));
            let failure = match settled {
                Err(payload) => payload,
                Ok(_provider) => panic!(
                    "binding the encoded canonical parameter {name} must be refused, \
                     but start_with_profile returned a provider"
                ),
            };
            let message = failure
                .downcast_ref::<String>()
                .expect("the refusal must arrive as a String payload");
            assert_eq!(
                message,
                &format!(
                    "the launch must not bind the canonical parameter {name} again: \
                     canonical bindings come only from canonical_bindings"
                ),
                "the encoded canonical parameter must receive the canonical-binding refusal"
            );
            assert!(
                fs::read_dir(&base)
                    .expect("the temporary base must be readable")
                    .next()
                    .is_none(),
                "the refusal must come before the shared ancestors are created: {}",
                base.display()
            );
        }
    }
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the Unix epoch")
        .as_secs()
}

fn resolved(path: &Path) -> PathBuf {
    fs::canonicalize(path).expect("wallet directory must resolve")
}

fn wallet_dir(root: &Path) -> PathBuf {
    WALLET_DIR
        .iter()
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

/// The did-provider crate's directory, the source of its binary, profile and
/// declared-rights fixture.
fn did_provider_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/")
        .join(DID_PROVIDER)
}

/// The declared-rights fixture of the named provider, the stand-in's input.
fn declared_rights_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/")
        .join(name)
        .join("tests/fixtures/confine/declared-rights.json")
}

/// The committed `confine.sb` of the named provider, the oracle a generated
/// or launched profile must match.
fn confine_oracle_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/")
        .join(name)
        .join("confine.sb")
}

/// The did-provider binary this test crate starts.
///
/// One `cargo build` for did's manifest, run once per test process by the
/// `LazyLock` below, reads the `did-provider` bin artifact's `executable`. The
/// build uses the `CARGO` environment variable when set, `--locked` and
/// `--offline`, and creates nothing outside cargo's own target directories. A
/// failed build, or an artifact that names no executable, fails with the
/// command's output; there is no skip and no fallback to another binary.
fn did_provider_binary() -> &'static Path {
    static BINARY: LazyLock<PathBuf> = LazyLock::new(build_did_provider_binary);
    BINARY.as_path()
}

/// The `did-provider` bin artifact's `executable` that cargo's JSON output
/// reports, or a refusal that names `did-provider` and `executable`.
///
/// `build_did_provider_binary` feeds this function did's build output, and
/// `did_binary_is_the_executable_the_build_reports` feeds it fixture lines.
/// One reader serves both, so the output has one parser and no other place
/// reads a path from the build (P10).
fn did_binary_executable(build_output: &str) -> Result<PathBuf, String> {
    for line in build_output.lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if message["reason"].as_str() != Some("compiler-artifact") {
            continue;
        }
        if message["target"]["name"].as_str() != Some(DID_PROVIDER) {
            continue;
        }
        let is_bin = message["target"]["kind"]
            .as_array()
            .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("bin")));
        if !is_bin {
            continue;
        }
        if let Some(executable) = message["executable"].as_str() {
            return Ok(PathBuf::from(executable));
        }
    }
    Err(format!(
        "cargo's JSON output carries no {DID_PROVIDER} bin artifact that names an executable"
    ))
}

fn build_did_provider_binary() -> PathBuf {
    let manifest = did_provider_dir().join("Cargo.toml");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(&cargo)
        .arg("build")
        .arg("--locked")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--bin")
        .arg(DID_PROVIDER)
        .arg("--message-format=json")
        .current_dir(did_provider_dir())
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "did-provider build {} must start: {err}",
                manifest.display()
            )
        });
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "did-provider build {} must succeed: {stderr}",
        manifest.display()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    did_binary_executable(&stdout)
        .unwrap_or_else(|reason| panic!("{reason}; standard output: {stdout}"))
}

/// The storage root a provider name keeps under `base`. did-provider keeps
/// its identity state at `<base>/did`; wallet-provider keeps its state under
/// `wallet_dir(base)`. The launcher and the oracle both read this one
/// derivation, so a did start cannot drift into wallet's layout. Any other
/// name is refused, because the stand-in serves these two and a guessed layout
/// would be a fallback (P11).
fn provider_storage_root(name: &str, base: &Path) -> PathBuf {
    match name {
        DID_PROVIDER => base.join("did"),
        WALLET_PROVIDER => wallet_dir(base),
        other => panic!(
            "the stand-in serves only {DID_PROVIDER} and {WALLET_PROVIDER}, \
             so {other} has no storage root layout"
        ),
    }
}

/// The layout derivation refuses a provider name it does not serve, and the
/// refusal names the name and both served names.
///
/// The test calls the derivation only and starts nothing.
///
/// Falsifier: WP129 returns `wallet_dir(base)` for the unknown-name arm, so
/// this test fails because no refusal comes.
#[test]
fn provider_storage_root_refuses_an_unknown_provider_name() {
    let base = Path::new("/fixture/base");
    let refusal = std::panic::catch_unwind(|| provider_storage_root("model-provider", base))
        .expect_err("an unknown provider name must be refused");
    let message = refusal
        .downcast_ref::<String>()
        .unwrap_or_else(|| panic!("the refusal must be a formatted reason"));
    assert_eq!(
        message.as_str(),
        "the stand-in serves only did-provider and wallet-provider, \
         so model-provider has no storage root layout",
        "the refusal must name the unknown provider and both served names"
    );
}

/// The three parameter bindings the tests make for one provider's storage
/// root and the program a launch binds. The provider name picks the layout:
/// did's `STORAGE_PARENT` is `base` and wallet's is the wallet directory's
/// parent. Every caller passes the program it names, so a launch for another
/// binary binds that binary and never a second copy of this derivation.
fn canonical_bindings(name: &str, base: &Path, program: &Path) -> [(&'static str, PathBuf); 3] {
    let root = provider_storage_root(name, base);
    let parent = storage_parent(name, base);
    [
        ("STORAGE_ROOT", root),
        ("STORAGE_PARENT", parent),
        ("PROVIDER_EXECUTABLE", resolved(program)),
    ]
}

/// The `STORAGE_PARENT` path the canonical bindings derive for `base`, so a
/// fixture that needs the granted parent reads the one derivation instead of
/// building the path again.
fn storage_parent(name: &str, base: &Path) -> PathBuf {
    provider_storage_root(name, base)
        .parent()
        .expect("provider storage parent")
        .to_path_buf()
}

/// One provider's inputs to its Landlock ruleset: the declared rights its
/// committed file holds, the three parameter bindings its launch uses, and the
/// binary that launch starts.
struct ProviderRulesetInputs {
    declared: Value,
    bindings: [(&'static str, PathBuf); 3],
    binary: &'static Path,
}

/// The one chooser of a provider's ruleset inputs under `base`. The ruleset
/// test and the did journey read a provider's inputs here, so each provider's
/// rules name its own root and no second derivation exists (P10).
///
/// It adds no provider-name refusal of its own. The bindings come from
/// `canonical_bindings`, which derives every path through
/// `provider_storage_root`, so an unknown name is refused there with that one
/// message; the declared rights come from that provider's own file through
/// `read_declared_rights`, which refuses a file that names another provider
/// (P11).
fn provider_ruleset_inputs(name: &str, base: &Path) -> Result<ProviderRulesetInputs, String> {
    // did's binary is the one this crate builds; every other served name uses
    // this crate's own binary. An unknown name never reaches a returned value,
    // because `canonical_bindings` refuses it through `provider_storage_root`.
    let binary = if name == DID_PROVIDER {
        did_provider_binary()
    } else {
        Path::new(PROVIDER_BINARY)
    };
    let bindings = canonical_bindings(name, base, binary);
    let declared = read_declared_rights(name, &declared_rights_path(name))?;
    Ok(ProviderRulesetInputs {
        declared,
        bindings,
        binary,
    })
}

/// The `init` config the stand-in sends for `name` at `base`. The stand-in
/// sends `base_path` to both providers, and did also receives the isolated
/// fixture device key so its `get_did` answers. It builds this one config for
/// both providers.
fn provider_init_config(name: &str, base: &Path) -> Value {
    let mut config = json!({ "base_path": base.display().to_string() });
    if name == DID_PROVIDER {
        config["encryption_key"] = json!(hex::encode(DID_DEVICE_KEY));
    }
    config
}

/// The test creates the directory `STORAGE_PARENT` names before the launch,
/// and the provider creates its storage root (`Wallet` or `did`). The binding
/// the launch receives names that directory, so the folder created and the
/// folder bound cannot drift apart (P10). `start_with_profile` refuses a second
/// binding of a canonical parameter, so this derivation stays the only source
/// of those three paths; `start_with_profile_refuses_a_canonical_parameter` and
/// WP54 hold that rule.
/// `start_with_profile_refuses_an_encoded_canonical_parameter` and WP55 cover
/// names encoded before `=` through the same check.
fn create_shared_ancestors(bindings: &[(&'static str, PathBuf)]) {
    let (_, parent) = bindings
        .iter()
        .find(|(name, _)| *name == "STORAGE_PARENT")
        .expect("the tests bind STORAGE_PARENT");
    fs::create_dir_all(parent).expect("prepare shared service directories");
}

fn runtime_invocation_envelope() -> Value {
    json!({
        "schema": "elastos.provider.invocation/v1",
        "source": "runtime",
        "target": "wallet",
        "op": "wallet_contract",
        "capability": "provider:runtime->wallet:wallet_contract",
        "transport": "runtime-local-provider-plane",
        "carrier": null,
        "transfer": "json",
        "range": null,
        "progress": null,
        "abi": {
            "schema": "elastos.provider.transfer-abi/v1",
            "transfer": "json",
            "transport": "runtime-local-provider-plane",
            "range_supported": false,
            "progress_supported": false,
            "progress_mode": "none",
            "transport_native_stream": false,
            "backpressure": "not_applicable",
            "cancel_supported": false
        }
    })
}

fn wallet_request(operation: WalletProviderOperationV2) -> WalletProviderRequestV2 {
    let context = VerifiedWalletInvocationContext::new(
        "person:local:alice",
        "session:confine",
        Some("proof:confine".to_string()),
        "grant:confine",
        "wallet",
        "launch:confine",
    )
    .expect("confine test authority must be valid");
    let sequence = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
    let issued_at = now_ts();
    WalletProviderRequestV2::new(
        &context,
        format!("wallet-request:{sequence:032x}"),
        issued_at,
        issued_at.saturating_add(120),
        operation,
    )
    .expect("confine test request must be valid")
}

/// The child's exit, or the deadline that ended the wait.
enum ChildExit {
    Exited(ExitStatus),
    TimedOut,
}

impl ChildExit {
    fn code(&self) -> Option<i32> {
        match self {
            Self::Exited(status) => status.code(),
            Self::TimedOut => None,
        }
    }
}

impl std::fmt::Display for ChildExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exited(status) => write!(f, "{status}"),
            Self::TimedOut => write!(
                f,
                "no exit within {}s, so it was killed",
                CHILD_EXIT_DEADLINE.as_secs()
            ),
        }
    }
}

/// The real provider binary, confined by `confine.sb`, speaking its normal
/// line-delimited JSON protocol.
///
/// `spawn` is the only spawn path. It pipes all three streams and drains
/// standard error on its own thread from the moment the child starts, so a
/// child that fills the pipe still reaches its own exit. A request the child
/// never answered fails with the one message from `unanswered`, which names the
/// request, the child's exit status or the deadline that ended the wait, and
/// all the child wrote to standard error. An answer that is not JSON fails with
/// its own message, which names the request, the parse error and the answer.
struct ConfinedProvider {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr_reader: Option<JoinHandle<String>>,
    stderr_text: String,
    /// The marker's answer before and after the launcher's own filter install,
    /// reported by the child over the one fixed record. `None` for a child that
    /// installed none.
    #[cfg(target_os = "linux")]
    seccomp_launch_answers: Option<[i64; 2]>,
}

impl ConfinedProvider {
    /// The one spawn path; `command` already carries its arguments. A spawn
    /// that fails, including a `pre_exec` install that refuses, returns the OS
    /// error instead of panicking, because a caller that must report the
    /// failing install step reads the child's record and not this errno.
    fn try_spawn(mut command: Command) -> Result<Self, String> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("the test child must start: {err}"))?;
        let stdin = child.stdin.take().expect("provider stdin");
        let stdout = BufReader::new(child.stdout.take().expect("provider stdout"));
        let mut stderr_pipe = child.stderr.take().expect("provider stderr");
        let stderr_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut bytes);
            String::from_utf8_lossy(&bytes).into_owned()
        });
        Ok(Self {
            child,
            stdin,
            stdout,
            stderr_reader: Some(stderr_reader),
            stderr_text: String::new(),
            #[cfg(target_os = "linux")]
            seccomp_launch_answers: None,
        })
    }

    /// The same path for a caller whose child must start: a failure is the
    /// test's own failure, so it panics with the reason `try_spawn` returned.
    fn spawn(command: Command) -> Self {
        Self::try_spawn(command).unwrap_or_else(|failure| panic!("{failure}"))
    }

    fn start(base: &Path) -> Self {
        Self::start_with_profile(base, Path::new(PROFILE_PATH), &[])
    }

    fn start_with_profile(base: &Path, profile: &Path, parameters: &[(&str, &Path)]) -> Self {
        for (name, _) in parameters {
            // Match the name sandbox-exec reads from the serialized -D binding.
            let binding_name = name.split_once('=').map_or(*name, |(binding, _)| binding);
            assert!(
                !CANONICAL_PARAMS.contains(&binding_name),
                "the launch must not bind the canonical parameter {name} again: \
                 canonical bindings come only from canonical_bindings"
            );
        }
        let canonical = canonical_bindings(WALLET_PROVIDER, base, Path::new(PROVIDER_BINARY));
        create_shared_ancestors(&canonical);
        let mut bindings: Vec<(&str, &Path)> = canonical
            .iter()
            .map(|(name, path)| (*name, path.as_path()))
            .collect();
        bindings.extend_from_slice(parameters);
        Self::start_under(profile, &bindings, Path::new(PROVIDER_BINARY))
    }

    /// The one launch builder: `program` under `profile`, with exactly the
    /// `bindings` it is given. The tests start the provider binary; a test
    /// that needs another program passes it through the same builder. A
    /// caller can leave a parameter unbound, as a Runtime bug would.
    fn start_under(profile: &Path, bindings: &[(&str, &Path)], program: &Path) -> Self {
        let mut command = Command::new(SANDBOX_EXEC);
        command.arg("-f").arg(profile);
        for (name, path) in bindings {
            command.arg("-D").arg(format!("{name}={}", path.display()));
        }
        command.arg(program);
        Self::spawn(command)
    }

    /// The Linux seat of the one launch builder: `program` with the launch
    /// list installed in `pre_exec`, through the same `spawn`. The program is
    /// the one this function is given, so a Linux start cannot run another
    /// binary.
    ///
    /// The install report crosses the fork as one fixed record on a socket
    /// pair, because Rust's exec-error pipe carries only a raw errno and no
    /// step. An install that refuses reports the step and its errno, and the
    /// parent turns it into that step's own reason, so a failed install starts
    /// nothing (P11). A missing, short, long or unknown-step record is a
    /// refusal with its own reason and never a bare spawn error.
    ///
    /// Every other OS refuses the start by name and starts nothing: a seccomp
    /// filter is installed on Linux only, and a provider never runs
    /// unconfined here. The file row uses this same function.
    #[cfg(target_os = "linux")]
    fn start_under_seccomp(allow: &SeccompAllowList, program: &Path) -> Result<Self, String> {
        Self::start_under_linux_policy(allow, None, program)
    }

    /// The one Linux launch path. `start_under_seccomp` and the file-row start
    /// both reach it, so there is one socket pair, one `pre_exec` and one
    /// `spawn`. `landlock` is the file row when the policy carries one.
    ///
    /// The installs run in the order the kernel forces: the ruleset first, then
    /// the seccomp filter. Landlock's own calls are in no seccomp list row, so a
    /// filter installed first would refuse them and the file row would never
    /// apply. A start that cannot apply its ruleset reports that step and starts
    /// nothing (P11). The copies the closure holds are made before the fork, so
    /// the child allocates nothing after it.
    #[cfg(target_os = "linux")]
    fn start_under_linux_policy(
        allow: &SeccompAllowList,
        landlock: Option<&LandlockRuleset>,
        program: &Path,
    ) -> Result<Self, String> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::net::UnixStream;
        use std::os::unix::process::CommandExt as _;

        let allow = allow.with_launch_essentials();
        // The `pre_exec` closure must be `'static`, so it owns its own copy of
        // the ruleset rather than borrowing the caller's. The copy is made
        // before the fork.
        let landlock = landlock
            .map(PreparedLandlockRuleset::new)
            .transpose()
            .map_err(|failure| format!("{} start is refused: {failure}", allow.provider))?;
        let provider_name = allow.provider.clone();
        let (mut reader, writer) = UnixStream::pair().map_err(|err| {
            format!(
                "{} start is refused: the seccomp install report channel could not open: {err}",
                allow.provider
            )
        })?;
        let mut command = Command::new(program);
        // The closure holds the list, the prepared ruleset and the reporting
        // socket before the fork, so the child allocates nothing after it.
        unsafe {
            command.pre_exec(move || {
                let before = seccomp_launch_marker_answer();
                // The file row first, because no seccomp row admits Landlock's
                // own system calls.
                let install = match &landlock {
                    Some(ruleset) => {
                        install_landlock(ruleset).map_err(SeccompInstallFailure::Landlock)
                    }
                    None => Ok(()),
                }
                .and_then(|()| install_seccomp(&allow));
                let record = match install {
                    Ok(()) => seccomp_launch_record(
                        SECCOMP_LAUNCH_INSTALLED,
                        before,
                        seccomp_launch_marker_answer(),
                    ),
                    Err(failure) => failure.launch_record(),
                };
                // `write` is admitted by the list and is async-signal-safe
                // after a fork; a socket write is not in the list at all.
                write_seccomp_launch_record(&record, |bytes| {
                    let written =
                        libc::write(writer.as_raw_fd(), bytes.as_ptr().cast(), bytes.len());
                    if written < 0 {
                        return Err(*libc::__errno_location());
                    }
                    Ok(written as usize)
                })
                .map_err(|failure| std::io::Error::from_raw_os_error(failure.errno()))?;
                install.map_err(|failure| std::io::Error::from_raw_os_error(failure.errno()))
            });
        }
        // `try_spawn` owns the command, so the parent's copy of the report
        // socket closes when it returns and the read below sees end of file.
        let spawned = Self::try_spawn(command);
        let mut record = Vec::new();
        reader
            .read_to_end(&mut record)
            .map_err(|err| format!("{provider_name} start is refused: {err}"))?;
        // What the child did instead of reporting: it did not start, with that
        // reason, or it started and its own report never arrived. Either way the
        // record decides the first half of the refusal, so a reporting failure
        // keeps the install report's own reason (P11).
        let child = match &spawned {
            Err(failure) => failure.as_str(),
            Ok(_) => "the child started and its install report arrived incomplete",
        };
        let answers = match seccomp_launch_answers_or_refusal(&record, child) {
            Ok(answers) => answers,
            Err(refusal) => return Err(format!("{provider_name} start is refused: {refusal}")),
        };
        let mut provider = spawned?;
        provider.seccomp_launch_answers = Some(answers);
        Ok(provider)
    }

    /// The file row's launch: the same one Linux path, with the ruleset
    /// installed before the seccomp filter.
    #[cfg(target_os = "linux")]
    fn start_under_landlock(
        allow: &SeccompAllowList,
        ruleset: &LandlockRuleset,
        program: &Path,
    ) -> Result<Self, String> {
        Self::start_under_linux_policy(allow, Some(ruleset), program)
    }

    /// The same function where no seccomp filter exists: the start is refused
    /// by name and nothing runs (P11). The file-row start calls this one
    /// refusal, so both name the filter's OS and run nothing.
    #[cfg(not(target_os = "linux"))]
    fn start_under_seccomp(allow: &SeccompAllowList, _: &Path) -> Result<Self, String> {
        Err(format!(
            "{} start is refused: a seccomp filter is installed on linux only",
            allow.provider
        ))
    }

    /// The same refusal where no seccomp filter exists, so a file-row start on
    /// another OS names the filter's OS and runs nothing (P11).
    #[cfg(not(target_os = "linux"))]
    fn start_under_landlock(
        allow: &SeccompAllowList,
        _: &LandlockRuleset,
        program: &Path,
    ) -> Result<Self, String> {
        Self::start_under_seccomp(allow, program)
    }

    /// The filter mode the launched child reports in its own
    /// `/proc/<pid>/status`: `2` for `SECCOMP_MODE_FILTER`. The mode alone also
    /// accepts an inherited filter, so the journey compares the marker's answer
    /// across this launcher's own install as well.
    #[cfg(target_os = "linux")]
    fn launched_seccomp_mode(&self) -> u32 {
        let path = format!("/proc/{}/status", self.child.id());
        let status = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("the launched provider's {path} must be readable: {err}"));
        let line = status
            .lines()
            .find(|line| line.starts_with("Seccomp:"))
            .unwrap_or_else(|| panic!("{path} must report a Seccomp line: {status}"));
        line["Seccomp:".len()..]
            .trim()
            .parse()
            .unwrap_or_else(|err| panic!("{path} must report a filter mode: {line}: {err}"))
    }

    /// Sends one request and returns its answer; a failure panics with the
    /// message from `try_send`. A request the child never answered fails with
    /// the one message from `unanswered`, which names the request, the child's
    /// exit status or the deadline that ended the wait, and all the child
    /// wrote to standard error. An answer that is not JSON fails with its own
    /// message, which names the request, the parse error and the answer.
    fn send(&mut self, request: &Value) -> Value {
        self.try_send(request)
            .unwrap_or_else(|failure| panic!("{failure}"))
    }

    /// Sends one request and returns its answer. A request the child never
    /// answered fails with the one message from `unanswered`, which names the
    /// request, the child's exit status or the deadline that ended the wait,
    /// and all the child wrote to standard error. An answer that is not JSON
    /// fails with its own message, which names the request, the parse error
    /// and the answer.
    fn try_send(&mut self, request: &Value) -> Result<Value, String> {
        let written = writeln!(self.stdin, "{request}").and_then(|()| self.stdin.flush());
        if let Err(err) = written {
            return Err(self.unanswered(request, &format!("writing the request failed: {err}")));
        }
        let mut response = String::new();
        match self.stdout.read_line(&mut response) {
            Ok(0) => Err(self.unanswered(request, "the response stream ended")),
            Ok(_) => serde_json::from_str(&response).map_err(|err| {
                format!("provider answered request {request} with invalid JSON: {err}: {response}")
            }),
            Err(err) => {
                Err(self.unanswered(request, &format!("reading the response failed: {err}")))
            }
        }
    }

    /// Waits up to `CHILD_EXIT_DEADLINE` for the child to exit.
    fn wait_for_exit(&mut self) -> ChildExit {
        let started = Instant::now();
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("child status must be readable")
            {
                return ChildExit::Exited(status);
            }
            if started.elapsed() >= CHILD_EXIT_DEADLINE {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return ChildExit::TimedOut;
            }
            std::thread::sleep(CHILD_EXIT_POLL);
        }
    }

    /// Every byte the child wrote to standard error, once the drainer reached
    /// end of file. Call it after the child exits.
    fn stderr(&mut self) -> &str {
        if let Some(reader) = self.stderr_reader.take() {
            self.stderr_text = reader.join().expect("the stderr drainer must not panic");
        }
        &self.stderr_text
    }

    /// The one failure message for a request the provider never answered.
    fn unanswered(&mut self, request: &Value, cause: &str) -> String {
        let exit = self.wait_for_exit();
        let stderr = self.stderr().to_string();
        format!(
            "provider did not answer request {request} ({cause}); child {exit}; standard error: {stderr}"
        )
    }

    fn init(&mut self, root: &Path) -> Value {
        self.send(&json!({
            "op": "init",
            "config": { "base_path": root.display().to_string() }
        }))
    }

    fn wallet(&mut self, operation: WalletProviderOperationV2) -> WalletResultV2 {
        self.wallet_with_lifecycle(operation).0
    }

    /// Sends one wallet operation and returns its raw answer and the request
    /// it answered, so a caller can record a refusal instead of decoding an
    /// ok result. It is the one wallet request path.
    fn wallet_request_and_answer(
        &mut self,
        operation: WalletProviderOperationV2,
    ) -> (WalletProviderRequestV2, Value) {
        let request = wallet_request(operation);
        let response = self.send(&json!({
            "op": "wallet_contract",
            "request": request,
            "_runtime_invocation": runtime_invocation_envelope(),
        }));
        (request, response)
    }

    /// The same request path as `wallet`, and the request's lifecycle id, so a
    /// test can find the record an effectful call saves in the store.
    fn wallet_with_lifecycle(
        &mut self,
        operation: WalletProviderOperationV2,
    ) -> (WalletResultV2, String) {
        let (request, response) = self.wallet_request_and_answer(operation);
        let lifecycle_id = request.lifecycle_id.clone();
        assert_eq!(
            response["status"], "ok",
            "wallet_contract must answer through the protocol: {response}"
        );
        let data = response
            .get("data")
            .expect("wallet_contract answer must carry a bound response");
        let bytes = serde_json::to_vec(data).expect("bound response must serialize");
        let result = WalletProviderResponseV2::decode_for_request(&bytes, &request)
            .expect("provider response must bind to its request")
            .result;
        (result, lifecycle_id)
    }

    /// Sends `shutdown`, checks that it answers `ok` and that the child exited
    /// with status 0, and returns the answer so a caller can hold it to its
    /// exact shape.
    fn shutdown(&mut self) -> Value {
        let response = self.send(&json!({ "op": "shutdown" }));
        assert_eq!(response["status"], "ok", "shutdown must answer: {response}");
        let exit = self.wait_for_exit();
        assert!(exit.code() == Some(0), "confined provider {exit}");
        response
    }
}

impl Drop for ConfinedProvider {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

/// One of the three Linux confinement primitives the design names, as a
/// simulated host report can leave it unavailable. This is test input: nothing
/// here reads a kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StandinPrimitive {
    Landlock,
    UserNamespaces,
    SeccompFilter,
}

impl StandinPrimitive {
    /// The design's exact refusal words for this missing primitive.
    fn design_refusal(self) -> &'static str {
        match self {
            Self::Landlock => "linux confinement refused: the kernel has no Landlock",
            Self::UserNamespaces => "linux confinement refused: user namespaces are turned off",
            Self::SeccompFilter => {
                "linux confinement refused: the seccomp filter cannot be installed"
            }
        }
    }
}

/// The one host report the stand-in reads, in place of a bare OS name.
///
/// `unavailable` is test input a simulated host on any OS can carry: the
/// Linux C0 rows carry Landlock, user namespaces or the seccomp filter
/// missing, and the `macos` row carries Landlock missing.
/// `standin_host_refusal` refuses such a host before it reads the OS list,
/// `DECLARED_CONFINED_OS`, so a host that carries a missing primitive is
/// refused whatever its OS. `reporting` names no missing primitive, so cases
/// that call `reporting(std::env::consts::OS)` keep their behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StandinHost {
    os: &'static str,
    unavailable: Option<StandinPrimitive>,
}

impl StandinHost {
    /// A host that reports every primitive present.
    fn reporting(os: &'static str) -> Self {
        Self {
            os,
            unavailable: None,
        }
    }

    /// A simulated Linux host whose report leaves `primitive` unavailable.
    fn linux_missing(primitive: StandinPrimitive) -> Self {
        Self::missing("linux", primitive)
    }

    /// A simulated host on `os` whose report leaves `primitive` unavailable.
    fn missing(os: &'static str, primitive: StandinPrimitive) -> Self {
        Self {
            os,
            unavailable: Some(primitive),
        }
    }
}

/// The one confinement policy a stand-in start carries.
///
/// A macOS start runs under its generated Seatbelt profile, the one file the
/// lab writer generates; a Linux start would run under the seccomp allow list
/// generated from the same declared rights. The file row adds the Landlock
/// ruleset beside that list. The policy is one input of the one launcher, so
/// the OS policies reach the start by one entry point (P10).
#[derive(Debug, Clone, Copy)]
enum StandinPolicy<'a> {
    /// The generated Seatbelt profile the start runs under.
    Seatbelt(&'a Path),
    /// The generated seccomp allow list the start installs.
    Seccomp(&'a SeccompAllowList),
    /// The generated seccomp allow list and the Landlock file row. The one
    /// Linux launch installs the ruleset first and the filter second.
    Landlock {
        allow: &'a SeccompAllowList,
        ruleset: &'a LandlockRuleset,
    },
}

/// The one rule that decides whether the stand-in can confine `host` under
/// `policy`.
///
/// A host that reports a primitive unavailable is refused first, on every OS,
/// so the report reaches this rule before the `DECLARED_CONFINED_OS` lookup and
/// an OS in that list cannot pass a start with a missing primitive. That
/// early refusal is the one host check (P10).
///
/// Each refusal starts `{name} start on {os} is refused:` and then carries only
/// its own case's words. Under a `Seatbelt` policy, `DECLARED_CONFINED_OS` is
/// the only list of OSes where the stand-in applies confinement: a host that
/// reports a primitive unavailable carries the design's exact words for that
/// primitive; an OS with no confinement design names that OS and the list; and
/// a simulated Linux host that reports nothing missing says Linux is designed,
/// not enforced, in this lab, so `linux` is not in `DECLARED_CONFINED_OS`. A
/// `Seccomp` policy is the Linux policy, so the same rule accepts it on `linux`
/// alone and refuses it on every other OS by name. A `Landlock` policy carries
/// that same filter, so it is accepted on `linux` alone in those same words.
/// `DECLARED_CONFINED_OS` stays the macOS list: accepting a seccomp policy on a
/// simulated Linux host is a host-report answer about that policy, not a claim
/// that Linux is confined.
fn standin_host_refusal(
    name: &str,
    host: StandinHost,
    policy: StandinPolicy<'_>,
) -> Result<(), String> {
    let confined_os = DECLARED_CONFINED_OS.join(", ");
    if let Some(primitive) = host.unavailable {
        let reason = primitive.design_refusal();
        return Err(format!("{name} start on {} is refused: {reason}", host.os));
    }
    match policy {
        StandinPolicy::Seatbelt(_) => {
            if DECLARED_CONFINED_OS.contains(&host.os) {
                return Ok(());
            }
            let reason = if host.os == "linux" {
                format!(
                    "linux is designed, not enforced, in this lab, so linux is not in \
                     DECLARED_CONFINED_OS ({confined_os})"
                )
            } else {
                format!(
                    "{os} has no confinement design, and the lab stand-in applies confinement only on \
                     {confined_os}",
                    os = host.os
                )
            };
            Err(format!("{name} start on {} is refused: {reason}", host.os))
        }
        StandinPolicy::Seccomp(_) | StandinPolicy::Landlock { .. } => {
            if host.os == "linux" {
                return Ok(());
            }
            Err(format!(
                "{name} start on {} is refused: the seccomp allow list is the linux policy, \
                 and {} is not linux",
                host.os, host.os
            ))
        }
    }
}

/// Lab stand-in for the Runtime's provider launch, not the Runtime.
///
/// This function is a lane copy that is to move under the one shared stand-in,
/// `lab/agent-conformance/standin-runtime/` (owned by cx-agent-conformance),
/// per Flint and Rong, 2026-10-27 19:25; the move is not done. Draft PR #309
/// at `513988ebd` names no provider-launch ask, a gap routed to Flint, so this
/// function copies `ProviderBridge::spawn`'s inputs instead of an RA route.
///
/// It copies the inputs of `ProviderBridge::spawn(binary_path, config)` with
/// `ProviderConfig.base_path` (read only, in `elastos/`), plus the provider
/// name, the host report, the one confinement policy and the declared rights
/// the lab generator profiles from. `Ok(ConfinedProvider)` is Started: the
/// provider answered `init` `ok` under the generated profile. `Err(String)` is
/// Refused: no provider is returned, and the reason says why.
///
/// It refuses, in this order:
///
/// 1. a host that `standin_host_refusal` refuses under this policy, with that
///    one reason, before any tool, binary or profile check, so a refused host
///    writes no profile and creates no storage root. A host that reports a
///    missing primitive is refused whatever its OS. The reason starts
///    `{name} start on {os} is refused:` and holds the words of its own case
///    for a host that reports a primitive unavailable, for an OS with no
///    confinement design, for a simulated Linux host that reports nothing
///    missing under a `Seatbelt` policy, and for a host that is not Linux under
///    a `Seccomp` policy;
/// 2. an absent `sandbox_exec`, with a reason that names the OS and the path;
/// 3. a present `sandbox_exec` that is not `SANDBOX_EXEC`, with a reason that
///    names the OS, the given path and `SANDBOX_EXEC`, so the tool the stand-in
///    checks is the one `start_under` runs;
/// 4. a `Seccomp` or `Landlock` policy whose list was generated for another
///    provider, with a reason that names both providers, and a `Landlock`
///    policy whose ruleset was generated for another provider, with a reason
///    that names both providers;
/// 5. a `binary_path` that is not a file, with a reason that names the
///    provider and that path, before any profile is written;
/// 6. a refusal of `write_generated_profile`, returned unchanged;
/// 7. a start that `sandbox-exec` refuses, with the `try_send` failure;
/// 8. an `init` that does not answer `ok`, with the answer.
///
/// `policy` is the one input that says how the start is confined. A `Seatbelt`
/// policy writes the profile the one lab writer generates from the declared
/// rights into `profile_dir`, creates the shared ancestors, starts
/// `binary_path` under that profile through `start_under` with the canonical
/// bindings for `name`, `base_path` and `binary_path`, and never starts
/// `binary_path` outside `sandbox-exec`. A `Seccomp` policy writes no profile
/// and starts that same `binary_path` through the same `ConfinedProvider::spawn`
/// by `start_under_seccomp`, which installs the allow list in `pre_exec`; on a
/// host without a filter that call refuses the start by name, so no provider
/// starts unconfined on any host this build runs on. A `Landlock` policy starts
/// through `start_under_landlock`, the same launch with the ruleset installed
/// before the filter. Before that fork the launcher creates and syncs
/// `STORAGE_ROOT`: a path rule needs a descriptor on the path, and the actor
/// that creates the root publishes its entry. The provider does not publish a
/// directory another actor created. A failure there refuses the start and names
/// the path. Both then send `init` with
/// the provider config from `provider_init_config`. `name` and `binary_path`
/// are inputs rather than this provider's constants, so another provider's
/// binary can start through this same function.
fn standin_spawn_confined_provider(
    host: StandinHost,
    policy: StandinPolicy<'_>,
    name: &str,
    binary_path: &Path,
    base_path: &Path,
    declared: &Value,
    profile_dir: &Path,
) -> Result<ConfinedProvider, String> {
    standin_host_refusal(name, host, policy)?;
    let os = host.os;
    if let StandinPolicy::Seatbelt(sandbox_exec) = policy {
        if !sandbox_exec.is_file() {
            return Err(format!(
                "{name} start on {os} is refused: the confinement tool {} is absent",
                sandbox_exec.display()
            ));
        }
        if sandbox_exec != Path::new(SANDBOX_EXEC) {
            return Err(format!(
                "{name} start on {os} is refused: the confinement tool {} is not {SANDBOX_EXEC}, \
                 which is the one the stand-in runs",
                sandbox_exec.display()
            ));
        }
    }
    if let StandinPolicy::Seccomp(allow) = policy {
        if allow.provider != name {
            return Err(format!(
                "{name} start is refused: the seccomp allow list was generated for {}",
                allow.provider
            ));
        }
    }
    if let StandinPolicy::Landlock { allow, ruleset } = policy {
        // The same list check as the Seccomp arm, then the ruleset's provider.
        if allow.provider != name {
            return Err(format!(
                "{name} start is refused: the seccomp allow list was generated for {}",
                allow.provider
            ));
        }
        if ruleset.provider != name {
            return Err(format!(
                "{name} start is refused: the landlock ruleset was generated for {}",
                ruleset.provider
            ));
        }
    }
    if !binary_path.is_file() {
        return Err(format!(
            "{name} start is refused: the provider binary {} is not a file",
            binary_path.display()
        ));
    }
    let canonical = canonical_bindings(name, base_path, binary_path);
    let mut provider = match policy {
        StandinPolicy::Seatbelt(_) => {
            let profile = profile_dir.join(format!("{name}-standin.sb"));
            write_generated_profile(name, declared, &profile)?;
            create_shared_ancestors(&canonical);
            let bindings: Vec<(&str, &Path)> = canonical
                .iter()
                .map(|(binding, path)| (*binding, path.as_path()))
                .collect();
            ConfinedProvider::start_under(&profile, &bindings, binary_path)
        }
        StandinPolicy::Seccomp(allow) => {
            create_shared_ancestors(&canonical);
            ConfinedProvider::start_under_seccomp(allow, binary_path)?
        }
        StandinPolicy::Landlock { allow, ruleset } => {
            create_shared_ancestors(&canonical);
            // A Landlock path rule needs a descriptor on `STORAGE_ROOT`, so the
            // root must exist before any rule is installed. The launcher creates
            // and syncs it here, in the parent, before the fork. This is the
            // half the provider no longer does: the provider stops publishing a
            // directory another actor created, and the actor that creates the
            // root publishes its entry. No profile form and no right is added.
            let storage_root = provider_storage_root(name, base_path);
            let parent = storage_root
                .parent()
                .expect("a bound storage root has a parent");
            fs::create_dir_all(&storage_root)
                .and_then(|()| {
                    fs::File::open(&storage_root)?.sync_all()?;
                    fs::File::open(parent)?.sync_all()
                })
                .map_err(|err| {
                    format!(
                        "{name} start is refused: the storage root {} must be creatable: {err}",
                        storage_root.display()
                    )
                })?;
            ConfinedProvider::start_under_landlock(allow, ruleset, binary_path)?
        }
    };
    let init = json!({
        "op": "init",
        "config": provider_init_config(name, base_path),
    });
    match provider.try_send(&init) {
        Ok(answer) if answer["status"] == "ok" => Ok(provider),
        Ok(answer) => Err(format!("{name} start is refused: init answered {answer}")),
        Err(failure) => Err(format!("{name} start is refused: {failure}")),
    }
}

fn assert_storage_error(response: &Value) {
    assert_eq!(
        response["status"], "error",
        "expected a storage refusal, got {response}"
    );
    assert_eq!(response["code"], "storage_error");
    let message = response["message"]
        .as_str()
        .expect("storage refusal must carry a reason");
    assert!(
        message.contains("wallet storage"),
        "storage refusal must state what it could not reach: {message}"
    );
}

fn ok_data(result: WalletResultV2) -> Value {
    match result {
        WalletResultV2::Ok { data } => data,
        WalletResultV2::Error { code, message } => {
            panic!("expected wallet operation success, got {code}: {message}")
        }
    }
}

fn read_store(root: &Path) -> Value {
    let path = wallet_dir(root).join("wallet-state.json");
    let bytes = fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    serde_json::from_slice(&bytes).expect("wallet store must be JSON")
}

/// The confined provider serves real wallet operations over its protocol and
/// keeps account and key state under the wallet directory it was given.
///
/// Falsifier: deny the storage-root write in `confine.sb`; `Init` then fails
/// and this test fails.
#[test]
fn confined_provider_serves_wallet_operations_under_its_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");
    assert_eq!(init["data"]["storage_configured"], true);
    assert_eq!(init["data"]["managed_wallets_configured"], true);

    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["status"], "ok",
        "capsule status must answer: {status}"
    );

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Confined".to_string()),
            create_new: false,
        }),
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();
    assert!(
        !account_id.is_empty(),
        "managed account id must not be empty"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListAccounts {
        include_revoked: false,
    }));
    let accounts = data["accounts"]
        .as_array()
        .expect("account listing must be an array");
    assert!(
        accounts
            .iter()
            .any(|account| account["account_id"] == account_id.as_str()),
        "the created managed account must be listed: {data}"
    );

    let store = read_store(&root);
    assert!(
        store["accounts"].as_array().is_some_and(|accounts| accounts
            .iter()
            .any(|account| account["account_id"] == account_id.as_str())),
        "account state must land under the wallet root: {store}"
    );
    let key_path = wallet_dir(&root).join(WALLET_KEY_FILE);
    assert!(
        fs::metadata(&key_path).is_ok_and(|metadata| metadata.len() > 0),
        "the storage key must land under the wallet root: {}",
        key_path.display()
    );

    provider.shutdown();
}

/// The calls that name no granted resource answer under the profile and leave
/// the wallet directory as the setup left it.
///
/// `status`, `shutdown`, `wallet_contract list_accounts`, `default_account`
/// and `list_approvals` name no granted resource: after `init`,
/// `create_managed_account`, `set_default_account` and one pending
/// `request_approval`, the wallet directory holds `wallet-key.hex` and
/// `wallet-state.json`, and each call leaves those names and those bytes
/// unchanged.
///
/// Honesty limit: the profile grants `file-read*` on the literal
/// `STORAGE_PARENT`, so the parent directory itself can be stat'ed. This case
/// compares the wallet directory's final entry names and each file's bytes
/// against the setup snapshot, so it shows each call answers `ok` under the
/// kernel's enforcement and that no call changed, added or removed a name
/// under the wallet directory. It counts no syscalls and changes no grant.
///
/// Falsifiers: read `/etc/hosts`, outside every grant, in `status`'s ok arm and
/// answer `storage_error` when that read is denied (WP139), so `status` stops
/// answering ok and this case fails on its first answer; append one byte to
/// `wallet-key.hex` in `status`'s ok arm while every answer stays ok (WP140),
/// so only the wallet directory comparison catches it, at `status`; and write
/// one file into the wallet directory in `shutdown`'s arm before it answers
/// (WP145), so the final comparison after `shutdown` finds a name the setup
/// did not leave. WP139 and WP140 both plant in `status`, the first call, and
/// WP145 plants in `shutdown`, the last, so the three registered plants for
/// this case reach its first and its last call only; a regression in
/// `list_accounts`, `default_account` or `list_approvals` alone would fail
/// this case with no plant of its own.
#[test]
fn no_right_calls_answer_under_the_profile_and_leave_the_root_unchanged() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(fixture.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("NoRight".to_string()),
            create_new: false,
        }),
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();
    let address = data["account"]["address"]
        .as_str()
        .expect("managed account must name its address")
        .to_string();
    ok_data(
        provider.wallet(WalletProviderOperationV2::SetDefaultAccount {
            chain_namespace: "eip155:20".to_string(),
            intent: "publish_envelope".to_string(),
            account_id: account_id.clone(),
        }),
    );
    let data = ok_data(provider.wallet(personal_sign_approval(
        &account_id,
        &address,
        "No-right approval",
    )));
    let request_id = data["approval_request"]["request_id"]
        .as_str()
        .expect("an approval request must name its id")
        .to_string();

    // The wallet directory the setup left: the key and the store.
    let mut setup = fs::read_dir(wallet_dir(&root))
        .expect("wallet directory after the setup")
        .map(|entry| {
            let entry = entry.expect("wallet directory entry after the setup");
            (
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path()).expect("wallet file bytes after the setup"),
            )
        })
        .collect::<Vec<(String, Vec<u8>)>>();
    setup.sort();
    assert_eq!(
        setup
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec![WALLET_KEY_FILE, "wallet-state.json"],
        "the setup must leave exactly the key and the store under the wallet directory"
    );

    // The one comparison every call below makes: the wallet directory's entry
    // names and each file's bytes, against the setup snapshot. A changed,
    // added or removed name, or changed bytes, is an `Err` that names the call
    // and the path. It counts no syscalls.
    fn unchanged(root: &Path, call: &str, setup: &[(String, Vec<u8>)]) -> Result<(), String> {
        let dir = wallet_dir(root);
        let mut after = Vec::new();
        let entries = fs::read_dir(&dir)
            .map_err(|err| format!("{call} could not list {}: {err}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|err| {
                format!("{call} could not read an entry of {}: {err}", dir.display())
            })?;
            let path = entry.path();
            let bytes = fs::read(&path)
                .map_err(|err| format!("{call} could not read {}: {err}", path.display()))?;
            after.push((entry.file_name().to_string_lossy().into_owned(), bytes));
        }
        after.sort();
        if after == setup {
            return Ok(());
        }
        let changed = after
            .iter()
            .find(|(name, bytes)| {
                setup
                    .iter()
                    .find(|(known, _)| known == name)
                    .is_none_or(|(_, known_bytes)| known_bytes != bytes)
            })
            .or_else(|| {
                setup
                    .iter()
                    .find(|(name, _)| !after.iter().any(|(now, _)| now == name))
            })
            .map(|(name, _)| name.as_str());
        Err(match changed {
            Some(name) => format!("{call} changed {}", dir.join(name).display()),
            None => format!("{call} changed the entry set under {}", dir.display()),
        })
    }

    let status = provider.send(&json!({ "op": "status" }));
    let watched = unchanged(&root, "status", &setup);
    assert!(watched.is_ok(), "{}", watched.unwrap_err());
    assert_eq!(status["status"], "ok", "status must answer: {status}");
    assert_eq!(
        status["data"]["storage_configured"], true,
        "status must report its storage root: {status}"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListAccounts {
        include_revoked: false,
    }));
    let watched = unchanged(&root, "list_accounts", &setup);
    assert!(watched.is_ok(), "{}", watched.unwrap_err());
    assert!(
        data["accounts"].as_array().is_some_and(|accounts| accounts
            .iter()
            .any(|account| account["account_id"] == account_id.as_str())),
        "list_accounts must answer the created account: {data}"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::DefaultAccount {
        chain_namespace: "eip155:20".to_string(),
        intent: "publish_envelope".to_string(),
    }));
    let watched = unchanged(&root, "default_account", &setup);
    assert!(watched.is_ok(), "{}", watched.unwrap_err());
    assert_eq!(
        data["default_account"]["account_id"].as_str(),
        Some(account_id.as_str()),
        "default_account must answer the account the setup made the default"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListApprovals {
        include_resolved: false,
    }));
    let watched = unchanged(&root, "list_approvals", &setup);
    assert!(watched.is_ok(), "{}", watched.unwrap_err());
    let approvals = data["approval_requests"]
        .as_array()
        .unwrap_or_else(|| panic!("list_approvals must answer an approval_requests array: {data}"));
    assert_eq!(
        approvals.len(),
        1,
        "list_approvals must answer exactly the one pending request the setup made: {data}"
    );
    assert_eq!(
        approvals[0]["request_id"].as_str(),
        Some(request_id.as_str()),
        "list_approvals must answer the request the setup made: {data}"
    );
    assert_eq!(
        approvals[0]["status"].as_str(),
        Some("pending"),
        "list_approvals must answer the request as still pending: {data}"
    );

    let shutdown = provider.shutdown();
    let watched = unchanged(&root, "shutdown", &setup);
    assert!(watched.is_ok(), "{}", watched.unwrap_err());
    assert_eq!(
        shutdown,
        json!({ "status": "ok" }),
        "shutdown must answer status only, with no data field"
    );
}

/// The wallet account edits answer under the profile and persist under
/// `STORAGE_ROOT`.
///
/// One provider `init`s the root, creates a managed account, then renames it,
/// sets it as the default for `publish_envelope`, reads that default back and
/// revokes the account; each answer passes through `ok_data`. A second
/// provider on the same root `init`s it and reloads the new label and the
/// revoked marker from `list_accounts` with `include_revoked` and from
/// `wallet-state.json` under the wallet directory.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no profile edit can fail one of these calls and
/// leave `init` working; WP18 is the only removal this side can use, and this
/// test fails on its first call.
#[test]
fn account_edits_persist_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Editable".to_string()),
            create_new: false,
        }),
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();

    let renamed = "Renamed";
    let data = ok_data(provider.wallet(WalletProviderOperationV2::RenameAccount {
        account_id: account_id.clone(),
        label: renamed.to_string(),
    }));
    assert_eq!(
        data["account"]["label"], renamed,
        "rename_account must answer the new label"
    );

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::SetDefaultAccount {
            chain_namespace: "eip155:20".to_string(),
            intent: "publish_envelope".to_string(),
            account_id: account_id.clone(),
        }),
    );
    assert_eq!(
        data["default_account"]["account_id"], account_id,
        "set_default_account must answer the account just set"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::DefaultAccount {
        chain_namespace: "eip155:20".to_string(),
        intent: "publish_envelope".to_string(),
    }));
    assert_eq!(
        data["default_account"]["account_id"], account_id,
        "default_account must answer the account just set"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::RevokeAccount {
        account_id: account_id.clone(),
    }));
    assert!(
        data["account"]["revoked_at"].is_number(),
        "revoke_account must answer the revoked account"
    );

    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined re-Init must succeed: {init}"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListAccounts {
        include_revoked: true,
    }));
    let listed = data["accounts"]
        .as_array()
        .and_then(|accounts| {
            accounts
                .iter()
                .find(|account| account["account_id"] == account_id.as_str())
        })
        .expect("the reloaded listing must hold the created account");
    assert_eq!(
        listed["label"], renamed,
        "the renamed label must reload from the store"
    );
    assert!(
        listed["revoked_at"].is_number(),
        "the revoked marker must reload from the store"
    );

    let store = read_store(&root);
    let stored = store["accounts"]
        .as_array()
        .and_then(|accounts| {
            accounts
                .iter()
                .find(|account| account["account_id"] == account_id.as_str())
        })
        .expect("the store under the wallet directory must hold the account");
    assert_eq!(
        stored["label"], renamed,
        "the store under the wallet directory must hold the new label"
    );
    assert!(
        stored["revoked_at"].is_number(),
        "the store under the wallet directory must hold the revoked marker"
    );

    provider.shutdown();
}

/// The managed recovery calls answer under the profile and persist under
/// `STORAGE_ROOT`.
///
/// One provider `init`s a source root, creates one managed account on
/// `eip155:20` and one on Bitcoin, then exports the first account's recovery
/// key and the set of both active managed accounts; each answer passes through
/// `ok_data`. A second provider on a second root imports the exported key
/// under a new label and then the exported set, and a fresh start on that root
/// `init`s it and reloads both accounts with `managed_key_available` and the
/// set's labels from `list_accounts` and from `wallet-state.json` under its
/// wallet directory. A fresh start on the source root shows the export
/// requests' consumed lifecycle records in that root's store. The exported key
/// and set stay test data in the temporary roots, and no assertion formats
/// them.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no profile edit can fail one of these calls and
/// leave `init` working; this test fails on its first `init`.
#[test]
fn managed_recovery_writes_persist_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let source_root = tempfile::tempdir().expect("temporary source root");
    let source_root = resolved(source_root.path());
    let target_root = tempfile::tempdir().expect("temporary target root");
    let target_root = resolved(target_root.path());
    let bitcoin_chain = "bip122:000000000019d6689c085ae165831e93";

    let mut source = ConfinedProvider::start(&source_root);
    let init = source.init(&source_root);
    assert_eq!(
        init["status"], "ok",
        "confined source Init must succeed: {init}"
    );

    let data = ok_data(
        source.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Spending".to_string()),
            create_new: true,
        }),
    );
    let spending_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();

    let data = ok_data(
        source.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: bitcoin_chain.to_string(),
            label: Some("Savings".to_string()),
            create_new: true,
        }),
    );
    let savings_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();

    let (result, export_key_lifecycle) =
        source.wallet_with_lifecycle(WalletProviderOperationV2::ExportManagedRecoveryKey {
            account_id: spending_id.clone(),
        });
    let recovery_key = ok_data(result);
    assert_eq!(
        recovery_key["schema"], "elastos.wallet.recovery-key/v1",
        "export_managed_recovery_key must answer its schema"
    );
    assert_eq!(
        recovery_key["account_id"].as_str(),
        Some(spending_id.as_str()),
        "export_managed_recovery_key must answer the requested account"
    );

    let (result, export_set_lifecycle) =
        source.wallet_with_lifecycle(WalletProviderOperationV2::ExportManagedRecoverySet {});
    let data = ok_data(result);
    let exported_labels = data["keys"]
        .as_array()
        .expect("export_managed_recovery_set must answer its keys")
        .iter()
        .filter_map(|entry| entry["label"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        exported_labels.len(),
        2,
        "export_managed_recovery_set must answer both active managed accounts"
    );
    assert!(
        exported_labels.contains(&"Spending") && exported_labels.contains(&"Savings"),
        "export_managed_recovery_set must answer both labels"
    );
    let recovery_set: ManagedRecoverySetV1 =
        serde_json::from_value(data).expect("the exported set must decode as a recovery set");
    source.shutdown();

    let mut target = ConfinedProvider::start(&target_root);
    let init = target.init(&target_root);
    assert_eq!(
        init["status"], "ok",
        "confined target Init must succeed: {init}"
    );
    let (result, import_key_lifecycle) =
        target.wallet_with_lifecycle(WalletProviderOperationV2::ImportManagedRecoveryKey {
            recovery_key,
            label: Some("Recovered".to_string()),
        });
    let data = ok_data(result);
    assert_eq!(
        data["imported"], true,
        "import_managed_recovery_key must answer that it imported"
    );
    assert_eq!(
        data["account"]["account_id"].as_str(),
        Some(spending_id.as_str()),
        "import_managed_recovery_key must answer the recovered account"
    );
    assert_eq!(
        data["account"]["label"], "Recovered",
        "import_managed_recovery_key must answer the new label"
    );

    let (result, import_set_lifecycle) =
        target.wallet_with_lifecycle(WalletProviderOperationV2::ImportManagedRecoverySet {
            recovery_set,
        });
    let data = ok_data(result);
    assert_eq!(
        data["imported"], true,
        "import_managed_recovery_set must answer that it imported"
    );
    assert_eq!(
        data["account_count"], 2,
        "import_managed_recovery_set must answer both recovered accounts"
    );
    target.shutdown();

    let mut target = ConfinedProvider::start(&target_root);
    let init = target.init(&target_root);
    assert_eq!(
        init["status"], "ok",
        "confined target re-Init must succeed: {init}"
    );

    let data = ok_data(target.wallet(WalletProviderOperationV2::ListAccounts {
        include_revoked: false,
    }));
    let accounts = data["accounts"]
        .as_array()
        .expect("list_accounts must answer its accounts");
    assert_eq!(
        accounts.len(),
        2,
        "the reloaded listing must hold both imported accounts"
    );
    for (account_id, label) in [(&spending_id, "Spending"), (&savings_id, "Savings")] {
        let account = accounts
            .iter()
            .find(|account| account["account_id"].as_str() == Some(account_id.as_str()))
            .expect("the reloaded listing must hold the imported account");
        assert_eq!(
            account["label"], label,
            "the set import must restore the label after the re-Init"
        );
        assert_eq!(
            account["signing_status"], "managed_key_available",
            "the imported account must keep its key available after the re-Init"
        );
    }

    let store = read_store(&target_root);
    let stored = store["accounts"]
        .as_array()
        .expect("the store under the target root must hold its accounts");
    assert_eq!(
        stored.len(),
        2,
        "the store under the target root must hold both imported accounts"
    );
    for (account_id, label) in [(&spending_id, "Spending"), (&savings_id, "Savings")] {
        let account = stored
            .iter()
            .find(|account| account["account_id"].as_str() == Some(account_id.as_str()))
            .expect("the store under the target root must hold the imported account");
        assert_eq!(
            account["label"], label,
            "the store under the target root must hold the restored label"
        );
    }
    for lifecycle_id in [&import_key_lifecycle, &import_set_lifecycle] {
        assert!(
            store["consumed_lifecycles"]
                .as_array()
                .is_some_and(|records| records.iter().any(|record| {
                    record["lifecycle_id"].as_str() == Some(lifecycle_id.as_str())
                })),
            "the reloaded store must hold the import request's consumed lifecycle"
        );
    }
    target.shutdown();

    let mut source = ConfinedProvider::start(&source_root);
    let init = source.init(&source_root);
    assert_eq!(
        init["status"], "ok",
        "confined source re-Init must succeed: {init}"
    );
    let store = read_store(&source_root);
    for lifecycle_id in [&export_key_lifecycle, &export_set_lifecycle] {
        assert!(
            store["consumed_lifecycles"]
                .as_array()
                .is_some_and(|records| records.iter().any(|record| {
                    record["lifecycle_id"].as_str() == Some(lifecycle_id.as_str())
                })),
            "the reloaded store must hold the export request's consumed lifecycle"
        );
    }
    source.shutdown();
}

/// The fixed test key the EVM proof calls sign with.
fn evm_test_signing_key() -> SigningKey {
    SigningKey::from_bytes((&[3u8; 32]).into()).expect("deterministic test key")
}

/// The address of `signing_key`, derived as `src/tests/support.rs::test_address`
/// derives it.
fn evm_test_address(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    format!("0x{}", hex::encode(&digest[12..]))
}

/// Signs `message` as `src/tests/support.rs::sign_message_bytes` signs it.
fn sign_test_message(signing_key: &SigningKey, message: &str) -> String {
    let hash = ethereum_signed_message_hash(message.as_bytes());
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&hash)
        .expect("test signature should be recoverable");
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery_id.to_byte());
    format!("0x{}", hex::encode(bytes))
}

/// The ERC-1271 evidence in `src/tests/support.rs::erc1271_proof`'s shape: the
/// SIWE message hash, a SHA-256 of the signature bytes, and no chain access.
fn erc1271_evidence(message: &str, signature: &str, contract: &str) -> Erc1271ProofEvidenceV1 {
    let message_hash = ethereum_signed_message_hash(message.as_bytes());
    let signature_hex = signature.strip_prefix("0x").unwrap_or(signature);
    let signature_bytes = hex::decode(signature_hex).expect("test signature must be hex");
    serde_json::from_value(json!({
        "schema": "elastos.chain.erc1271_proof/v1",
        "network": "esc-local",
        "chain_id": 20,
        "contract": contract.to_ascii_lowercase(),
        "message_hash": format!("0x{}", hex::encode(message_hash)),
        "signature_hash": format!("0x{}", hex::encode(Sha256::digest(&signature_bytes))),
        "valid": true,
        "magic_value": "0x1626ba7e",
        "checked_at": now_ts(),
    }))
    .expect("the ERC-1271 evidence must decode as its typed value")
}

/// The fixed test key the Bitcoin proof calls sign with.
fn bitcoin_test_signing_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).expect("deterministic test key")
}

/// The P2PKH address of `signing_key`, derived as
/// `src/tests/support.rs::bitcoin_p2pkh_test_address` derives it.
fn bitcoin_test_address(signing_key: &SigningKey) -> String {
    let pubkey = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let compressed =
        bitcoin::CompressedPublicKey::from_slice(&pubkey).expect("deterministic test public key");
    bitcoin::Address::p2pkh(compressed, bitcoin::Network::Bitcoin).to_string()
}

/// The compressed public key of `signing_key`, encoded as
/// `src/tests/support.rs::bitcoin_test_public_key` encodes it.
fn bitcoin_test_public_key(signing_key: &SigningKey) -> String {
    hex::encode(
        signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    )
}

/// Signs `message` as `src/tests/support.rs::sign_bitcoin_message` signs it,
/// with the pinned `bitcoin` crate's public message hash.
fn sign_bitcoin_test_message(signing_key: &SigningKey, message: &str) -> String {
    let hash = bitcoin::sign_message::signed_msg_hash(message);
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&hash.to_byte_array())
        .expect("test Bitcoin message signature");
    let mut bytes = vec![27 + recovery_id.to_byte()];
    bytes.extend_from_slice(signature.to_bytes().as_ref());
    BASE64_STANDARD.encode(bytes)
}

/// The result error of one wallet call, refusing an ok answer.
fn result_error(result: WalletResultV2) -> (String, String) {
    match result {
        WalletResultV2::Ok { data } => {
            panic!("expected a wallet operation result error, got {data}")
        }
        WalletResultV2::Error { code, message } => (code, message),
    }
}

/// The EVM proof and account-link calls answer under the profile and persist
/// under `STORAGE_ROOT`.
///
/// One provider `init`s a root and asks for two challenges: one for a fixed
/// EOA address and one for a fixed contract address. A fresh confined start on
/// the same root `init`s it and `status` shows `pending_challenge_count` 2, so
/// both challenges reloaded from the store. `verify_proof` on the first and
/// `verify_contract_proof` on the second answer ok with `proof_type` `siwe` and
/// `siwe_erc1271`, and `link_verified_account` with the first answer's
/// `proof_binding_id` answers ok. A second restart `init`s the same root and
/// `status` shows `pending_challenge_count` 0; each replayed verify answers
/// `invalid_proof` with "already consumed"; `list_accounts` holds the linked
/// account with that binding; and `read_store` shows both challenges with
/// `consumed_at` set under the root's wallet directory. The fixed signing key,
/// the messages and the signature stay test data in the temporary root, and no
/// assertion formats them.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no narrower profile falsifier exists: no profile
/// edit can fail one of these calls and leave `init` working, and this test
/// fails on its first `init`.
#[test]
fn evm_proofs_and_link_persist_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let signing_key = evm_test_signing_key();
    let eoa_address = evm_test_address(&signing_key);
    let contract = "0x00000000000000000000000000000000000000cc";

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(provider.wallet(WalletProviderOperationV2::Challenge {
        domain: "http://elastos.local".to_string(),
        uri: "http://elastos.local/apps/home/".to_string(),
        address: eoa_address.clone(),
        chain_id: 20,
        resources: vec!["elastos://wallet/account/link".to_string()],
    }));
    let eoa_message = data["message"]
        .as_str()
        .expect("a challenge must answer its message")
        .to_string();
    let eoa_challenge_id = data["challenge_id"]
        .as_str()
        .expect("a challenge must answer its id")
        .to_string();

    let data = ok_data(provider.wallet(WalletProviderOperationV2::Challenge {
        domain: "http://elastos.local".to_string(),
        uri: "http://elastos.local/apps/home/".to_string(),
        address: contract.to_string(),
        chain_id: 20,
        resources: vec!["elastos://wallet/account/link".to_string()],
    }));
    let contract_message = data["message"]
        .as_str()
        .expect("a challenge must answer its message")
        .to_string();
    let contract_challenge_id = data["challenge_id"]
        .as_str()
        .expect("a challenge must answer its id")
        .to_string();
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined re-Init must succeed: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["data"]["pending_challenge_count"], 2,
        "both challenges must reload from the store: {status}"
    );

    let eoa_signature = sign_test_message(&signing_key, &eoa_message);
    let data = ok_data(provider.wallet(WalletProviderOperationV2::VerifyProof {
        message: eoa_message.clone(),
        signature: eoa_signature.clone(),
    }));
    assert_eq!(
        data["proof_type"], "siwe",
        "verify_proof must answer its proof type"
    );
    assert_eq!(data["chain_namespace"], "eip155:20");
    assert_eq!(data["address"], eoa_address.to_ascii_lowercase());
    let proof_binding_id = data["proof_binding_id"]
        .as_str()
        .expect("a verified proof must answer its binding")
        .to_string();
    assert_eq!(
        proof_binding_id,
        format!(
            "proof:wallet:eip155:20:{}",
            eoa_address.to_ascii_lowercase()
        ),
        "the verified proof must answer its binding"
    );

    let contract_signature = "0x01020304";
    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::VerifyContractProof {
            message: contract_message.clone(),
            signature: contract_signature.to_string(),
            evidence: erc1271_evidence(&contract_message, contract_signature, contract),
        }),
    );
    assert_eq!(
        data["proof_type"], "siwe_erc1271",
        "verify_contract_proof must answer its proof type"
    );
    assert_eq!(data["chain_namespace"], "eip155:20");
    assert_eq!(data["address"], contract);
    assert_eq!(
        data["proof_binding_id"],
        format!("proof:wallet:eip155:20:{contract}"),
        "the contract proof must answer its binding"
    );

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::LinkVerifiedAccount {
            proof_binding_id: proof_binding_id.clone(),
            chain_namespace: "eip155:20".to_string(),
            address: eoa_address.clone(),
            proof_type: "siwe".to_string(),
            label: Some("Proof".to_string()),
        }),
    );
    assert_eq!(
        data["account"]["proof_binding_id"].as_str(),
        Some(proof_binding_id.as_str()),
        "link_verified_account must answer the binding it was given"
    );
    let linked_account_id = data["account"]["account_id"]
        .as_str()
        .expect("a linked account must name its id")
        .to_string();
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined second re-Init must succeed: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["data"]["pending_challenge_count"], 0,
        "both consumed challenges must reload from the store: {status}"
    );

    for operation in [
        WalletProviderOperationV2::VerifyProof {
            message: eoa_message.clone(),
            signature: eoa_signature.clone(),
        },
        WalletProviderOperationV2::VerifyContractProof {
            message: contract_message.clone(),
            signature: contract_signature.to_string(),
            evidence: erc1271_evidence(&contract_message, contract_signature, contract),
        },
    ] {
        let (code, message) = result_error(provider.wallet(operation));
        assert_eq!(
            code, "invalid_proof",
            "a replayed verify must be refused: {message}"
        );
        assert!(
            message.contains("already consumed"),
            "a replay must name the consumed challenge: {message}"
        );
    }

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListAccounts {
        include_revoked: false,
    }));
    let accounts = data["accounts"]
        .as_array()
        .expect("list_accounts must answer its accounts");
    assert_eq!(
        accounts.len(),
        1,
        "the reloaded listing must hold the linked account"
    );
    assert_eq!(accounts[0]["account_id"], linked_account_id);
    assert_eq!(
        accounts[0]["proof_binding_id"].as_str(),
        Some(proof_binding_id.as_str()),
        "the reloaded listing must hold the proof binding"
    );
    assert_eq!(accounts[0]["proof_type"], "siwe");
    assert_eq!(accounts[0]["address"], eoa_address.to_ascii_lowercase());

    let store = read_store(&root);
    let stored = store["challenges"]
        .as_array()
        .expect("the store under the wallet directory must hold its challenges");
    assert_eq!(
        stored.len(),
        2,
        "the store under the wallet directory must hold both challenges"
    );
    for challenge_id in [&eoa_challenge_id, &contract_challenge_id] {
        let challenge = stored
            .iter()
            .find(|stored| {
                stored["challenge"]["challenge_id"].as_str() == Some(challenge_id.as_str())
            })
            .expect("the store under the wallet directory must hold the challenge");
        assert!(
            challenge["consumed_at"].as_u64().is_some(),
            "the store under the wallet directory must hold the consumed challenge"
        );
    }
    provider.shutdown();
}

/// The Bitcoin proof calls answer under the profile and persist under
/// `STORAGE_ROOT`.
///
/// One provider `init`s a root and asks for a challenge for a fixed P2PKH
/// address. The answer is ok with `proof_type` `bitcoin_signed_message`, and
/// the test signs the challenge message. A fresh confined start on the same
/// root `init`s it and `status` shows `pending_bitcoin_challenge_count` 1, so
/// the challenge reloaded from the store. `verify_bip322_proof` with the
/// `bitcoin_signed_message` signature, type and public key answers ok with
/// `proof_type` `bitcoin_signed_message` and the same address. A second
/// restart `init`s the same root and `status` shows
/// `pending_bitcoin_challenge_count` 0; the replayed verify answers
/// `invalid_proof` with "already consumed"; and `read_store` shows the
/// challenge with `consumed_at` set under the root's wallet directory. The
/// fixed signing key, the message and the signature stay test data in the
/// temporary root, and no assertion formats them.
///
/// The test signs the `bitcoin_signed_message` type on a P2PKH address, not
/// the `bip322_simple` type: the simple type is signed through
/// `src/crypto/bitcoin.rs`'s `bip322_message_hash`, `bip322_to_spend_tx` and
/// `bip322_to_sign_tx`, which are `pub(crate)` in a binary crate, so an
/// integration test cannot call them, and building them again here would be a
/// second copy of that rule (P10). Both types reach the same handler, the same
/// stored challenge and the same consumption.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no narrower profile falsifier exists: no profile
/// edit can fail one of these calls and leave `init` working, and this test
/// fails on its first `init`.
#[test]
fn bitcoin_proofs_persist_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let signing_key = bitcoin_test_signing_key();
    let address = bitcoin_test_address(&signing_key);
    let public_key = bitcoin_test_public_key(&signing_key);

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::BitcoinChallenge {
            domain: "elastos.local".to_string(),
            uri: "http://elastos.local/apps/home/".to_string(),
            address: address.clone(),
            network: PublicNetwork::bitcoin(),
            resources: vec!["elastos://wallet/account/link".to_string()],
        }),
    );
    assert_eq!(
        data["proof_type"], "bitcoin_signed_message",
        "a P2PKH challenge must answer the signed-message proof type"
    );
    let message = data["message"]
        .as_str()
        .expect("a Bitcoin challenge must answer its message")
        .to_string();
    let challenge_id = data["challenge_id"]
        .as_str()
        .expect("a Bitcoin challenge must answer its id")
        .to_string();
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined re-Init must succeed: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["data"]["pending_bitcoin_challenge_count"], 1,
        "the Bitcoin challenge must reload from the store: {status}"
    );

    let signature = sign_bitcoin_test_message(&signing_key, &message);
    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::VerifyBip322Proof {
            message: message.clone(),
            signature: signature.clone(),
            signature_type: "bitcoin_signed_message".to_string(),
            public_key: Some(public_key.clone()),
        }),
    );
    assert_eq!(
        data["proof_type"], "bitcoin_signed_message",
        "verify_bip322_proof must answer its proof type"
    );
    assert_eq!(
        data["address"], address,
        "verify_bip322_proof must answer the challenge address"
    );
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined second re-Init must succeed: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["data"]["pending_bitcoin_challenge_count"], 0,
        "the consumed Bitcoin challenge must reload from the store: {status}"
    );

    let (code, refusal) = result_error(provider.wallet(
        WalletProviderOperationV2::VerifyBip322Proof {
            message: message.clone(),
            signature,
            signature_type: "bitcoin_signed_message".to_string(),
            public_key: Some(public_key),
        },
    ));
    assert_eq!(
        code, "invalid_proof",
        "a replayed verify must be refused: {refusal}"
    );
    assert!(
        refusal.contains("already consumed"),
        "a replay must name the consumed challenge: {refusal}"
    );

    let store = read_store(&root);
    let stored = store["bitcoin_challenges"]
        .as_array()
        .expect("the store under the wallet directory must hold its Bitcoin challenges");
    assert_eq!(
        stored.len(),
        1,
        "the store under the wallet directory must hold the challenge"
    );
    assert_eq!(
        stored[0]["challenge"]["challenge_id"].as_str(),
        Some(challenge_id.as_str())
    );
    assert!(
        stored[0]["consumed_at"].as_u64().is_some(),
        "the store under the wallet directory must hold the consumed challenge"
    );
    provider.shutdown();
}

/// The `request_approval` operation of
/// `src/tests/approvals/managed.rs::managed_account_signs_only_after_runtime_approval`
/// for a Browser `personal_sign` request on a managed `eip155:20` account.
///
/// The integration test writes the payload value itself because
/// `src/tests/support.rs::browser_personal_sign_payload` is crate-private; it is
/// request data, not provider logic. `expires_at` is ten minutes ahead, inside
/// `src/main.rs`'s `MAX_APPROVAL_REQUEST_TTL_SECS` of thirty minutes, as the
/// unit test's `APPROVAL_REQUEST_TTL_SECS` does.
fn personal_sign_approval(
    account_id: &str,
    address: &str,
    message: &str,
) -> WalletProviderOperationV2 {
    WalletProviderOperationV2::RequestApproval {
        account_id: account_id.to_string(),
        chain_namespace: "eip155:20".to_string(),
        intent: "browser_personal_sign".to_string(),
        resource: "elastos://wallet/eip155:20/sign/browser_personal_sign".to_string(),
        reason: "Browser page requests personal_sign".to_string(),
        payload: json!({
            "schema": "elastos.browser.wallet-signature-request/v1",
            "method": "personal_sign",
            "params": [message, address],
            "message": message,
            "address": address,
            "account_id": account_id,
            "chain_namespace": "eip155:20",
            "page_url": "https://dapp.example/sign",
            "origin": "https://dapp.example",
            "requires_wallet_approval": true
        }),
        expires_at: now_ts().saturating_add(10 * 60),
    }
}

/// The managed approval calls answer under the profile and persist under
/// `STORAGE_ROOT`.
///
/// One provider `init`s a root, creates one managed account on `eip155:20` and
/// sends two `request_approval` calls whose answers pass through `ok_data`.
/// Every request carries principal `person:local:alice`, session
/// `session:confine` and actor `wallet`, the same across restarts. A fresh
/// confined start on the same root `init`s it and `status` shows
/// `pending_approval_count` 2, so both requests reloaded from the store, and
/// `list_approvals` without `include_resolved` lists both request ids. Then
/// `approve_and_sign_managed` on the first answers `completed` with a
/// signature, and `reject_approval` on the second answers `rejected`. A second
/// restart `init`s the same root and `status` shows `pending_approval_count` 0;
/// `list_approvals` without `include_resolved` is empty and with it shows the
/// first `completed` and the second `rejected`; a replayed
/// `approve_and_sign_managed` on the first answers `invalid_request` with
/// "not pending"; and `read_store` shows both requests with those statuses
/// under the root's wallet directory. The payloads and the signature stay test
/// data in the temporary root, and no assertion formats them.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no profile edit can fail one of these calls and
/// leave `init` working; no narrower profile falsifier exists, and this test
/// fails on its first `init`.
#[test]
fn managed_approvals_persist_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Approvals".to_string()),
            create_new: false,
        }),
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();
    let address = data["account"]["address"]
        .as_str()
        .expect("managed account must name its address")
        .to_string();

    let mut request_ids = Vec::new();
    for message in ["First managed approval", "Second managed approval"] {
        let data = ok_data(provider.wallet(personal_sign_approval(&account_id, &address, message)));
        let approval = &data["approval_request"];
        assert_eq!(
            approval["status"], "pending",
            "request_approval must answer a pending request"
        );
        request_ids.push(
            approval["request_id"]
                .as_str()
                .expect("an approval request must name its id")
                .to_string(),
        );
    }
    let first_id = request_ids[0].clone();
    let second_id = request_ids[1].clone();
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined re-Init must succeed: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["data"]["pending_approval_count"], 2,
        "both approval requests must reload from the store: {status}"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListApprovals {
        include_resolved: false,
    }));
    let pending = data["approval_requests"]
        .as_array()
        .expect("list_approvals must answer its requests");
    assert_eq!(
        pending.len(),
        2,
        "the reloaded listing must hold both pending approvals"
    );
    for request_id in [&first_id, &second_id] {
        assert!(
            pending
                .iter()
                .any(|request| request["request_id"].as_str() == Some(request_id.as_str())),
            "the reloaded listing must hold the pending approval"
        );
    }

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: first_id.clone(),
            reason: "approved".to_string(),
        }),
    );
    assert_eq!(
        data["approval_request"]["status"], "completed",
        "approve_and_sign_managed must answer the completed request"
    );
    assert!(
        data["signature"]
            .as_str()
            .is_some_and(|signature| !signature.is_empty()),
        "approve_and_sign_managed must answer a signature"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::RejectApproval {
        request_id: second_id.clone(),
        reason: "rejected".to_string(),
    }));
    assert_eq!(
        data["approval_request"]["status"], "rejected",
        "reject_approval must answer the rejected request"
    );
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined second re-Init must succeed: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["data"]["pending_approval_count"], 0,
        "both resolved approvals must reload from the store: {status}"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListApprovals {
        include_resolved: false,
    }));
    assert!(
        data["approval_requests"]
            .as_array()
            .is_some_and(|requests| requests.is_empty()),
        "resolved approvals must stay out of the pending listing"
    );

    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListApprovals {
        include_resolved: true,
    }));
    let resolved = data["approval_requests"]
        .as_array()
        .expect("list_approvals must answer its requests");
    for (request_id, expected) in [(&first_id, "completed"), (&second_id, "rejected")] {
        let request = resolved
            .iter()
            .find(|request| request["request_id"].as_str() == Some(request_id.as_str()))
            .expect("the resolved listing must hold the request");
        assert_eq!(
            request["status"], expected,
            "the resolved listing must hold the stored status"
        );
    }

    let (code, refusal) = result_error(provider.wallet(
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: first_id.clone(),
            reason: "approved again".to_string(),
        },
    ));
    assert_eq!(
        code, "invalid_request",
        "a replayed approve must be refused: {refusal}"
    );
    assert!(
        refusal.contains("not pending"),
        "a replay must name the resolved request: {refusal}"
    );

    let store = read_store(&root);
    let stored = store["approval_requests"]
        .as_array()
        .expect("the store under the wallet directory must hold its approvals");
    for (request_id, expected) in [(&first_id, "completed"), (&second_id, "rejected")] {
        let request = stored
            .iter()
            .find(|request| request["request_id"].as_str() == Some(request_id.as_str()))
            .expect("the store under the wallet directory must hold the request");
        assert_eq!(
            request["status"], expected,
            "the store under the wallet directory must hold the status"
        );
    }
    provider.shutdown();
}

/// The fixed digest a rights fixture field uses.
fn rights_digest(seed: u8) -> Digest32 {
    Digest32::new([seed; 32])
}

/// The 20-byte Wallet address a rights request binds.
fn rights_wallet_address(address: &str) -> WalletAddress {
    let hex = address.strip_prefix("0x").unwrap_or(address);
    let bytes = hex::decode(hex).expect("the rights wallet address must be hex");
    WalletAddress::new(
        bytes
            .try_into()
            .expect("the rights wallet must be a 20-byte address"),
    )
}

/// The protected-content rights request the wallet test signs.
///
/// This is request data, not provider logic. It repeats the constant inputs
/// `src/tests/approvals/protected_content.rs::RightsRequestFixture::build`
/// builds, because that fixture is crate-private and this integration test is
/// a separate crate. Only the wallet address, the validity window and the
/// nonce vary.
fn protected_content_rights_request(
    address: &str,
    issued_at: u64,
    expires_at: u64,
    nonce: u8,
) -> RightsRequestV1 {
    let encrypted_content = EncryptedContentIdentityV1::new(rights_digest(0x11), 4096)
        .expect("the rights content identity must be valid");
    let key_envelope = KeyEnvelopeIdentityV1::new(
        encrypted_content.clone(),
        rights_digest(0x22),
        2048,
        rights_digest(0x23),
        ThresholdV1::new(2, 3).expect("the rights threshold must be valid"),
        CustodyPoolIdentityV1::new(rights_digest(0x24), 512)
            .expect("the rights custody pool must be valid"),
        CustodyEpochIdentityV1::new(rights_digest(0x25), 512)
            .expect("the rights custody epoch must be valid"),
        CustodyCommitteeAuthorizationIdentityV1::new(rights_digest(0x26), 512)
            .expect("the rights committee authorization must be valid"),
    )
    .expect("the rights key envelope must be valid");
    let action = RightsActionV1::View;
    let policy = RightsPolicyBodyV1::new(
        encrypted_content.clone(),
        ContentAccessIdV1::new([0x27; 16]).expect("the rights content access id must be valid"),
        action,
        RightsSubjectSourceV1::WalletAddress,
        20,
        EvmContractAddressV1::new([0x44; 20]).expect("the rights contract must be valid"),
        EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78])
            .expect("the rights selector must be valid"),
        EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
        RightsObservationFinalityV1::finalized(),
    )
    .expect("the rights policy must be valid");
    let binding = ProtectedContentBindingV1::new(
        encrypted_content,
        key_envelope,
        policy
            .policy_identity()
            .expect("the rights policy identity must be valid"),
        ProfileIdentityV1::from_did_key("did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z")
            .expect("the rights profile identity must be valid"),
        rights_wallet_address(address),
        RuntimeSessionBindingV1::new(rights_digest(0x66))
            .expect("the rights runtime session binding must be valid"),
    )
    .expect("the rights binding must be valid");
    RightsRequestV1::new(
        binding,
        action,
        RecipientKeyIdentityV1::new("x25519-hkdf-sha256-hpke-v1", rights_digest(0xa0))
            .expect("the rights recipient key must be valid"),
        issued_at,
        expires_at,
        ReplayNonce16::new([nonce; 16]),
    )
    .expect("the rights request must be valid")
}

/// The protected-content rights call answers under the profile and persists
/// under `STORAGE_ROOT`.
///
/// One provider `init`s a root and creates one managed account on `eip155:20`,
/// then sends `request_protected_content_rights_signature` with a rights
/// request bound to that account's address over the window `now_ts()` to
/// `now_ts()` plus 120 s. Every request carries principal `person:local:alice`,
/// session `session:confine` and actor `wallet`, the same across restarts. The
/// answer requires approval, holds intent
/// `protected_content_rights_signature`, and carries the hex sent in
/// `approval_request.payload.canonical_rights_request_hex`. A fresh confined
/// start on the same root `init`s it, and `approve_and_sign_managed` on the
/// request answers ok with `approval_request.status` `completed` and a
/// `signed_result` present. After a second restart, a replayed
/// `approve_and_sign_managed` answers `invalid_request` with "not pending", and
/// `read_store` shows the request `completed` with a `signed_result` under the
/// root's wallet directory. The rights request and the signed result stay test
/// data in the temporary root, and no assertion message prints them.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no profile edit can fail this call and leave `init`
/// working; no narrower profile falsifier exists, and this test fails on its
/// first `init`.
#[test]
fn protected_content_rights_request_persists_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Protected content".to_string()),
            create_new: false,
        }),
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();
    let address = data["account"]["address"]
        .as_str()
        .expect("managed account must name its address")
        .to_string();

    let issued_at = now_ts();
    let rights_request =
        protected_content_rights_request(&address, issued_at, issued_at.saturating_add(120), 0x51);
    let canonical_rights_request_hex = hex::encode(
        rights_request
            .canonical_bytes()
            .expect("the rights request must encode canonically"),
    );
    let data = ok_data(provider.wallet(
        WalletProviderOperationV2::RequestProtectedContentRightsSignature {
            account_id,
            canonical_rights_request_hex: canonical_rights_request_hex.clone(),
            reason: "Review and sign the exact protected-content rights request".to_string(),
        },
    ));
    assert_eq!(
        data["requires_approval"], true,
        "the rights call must answer a request that needs approval"
    );
    assert_eq!(
        data["approval_request"]["intent"], PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT,
        "the approval request must carry the rights intent"
    );
    assert!(
        data["approval_request"]["payload"]["canonical_rights_request_hex"]
            .as_str()
            .is_some_and(|hex| hex == canonical_rights_request_hex.as_str()),
        "the approval request must carry the hex sent"
    );
    let request_id = data["approval_request"]["request_id"]
        .as_str()
        .expect("an approval request must name its id")
        .to_string();
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined re-Init must succeed: {init}"
    );
    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: request_id.clone(),
            reason: "approved".to_string(),
        }),
    );
    assert_eq!(
        data["approval_request"]["status"], "completed",
        "approve_and_sign_managed must answer the completed request"
    );
    assert!(
        data["approval_request"]["signed_result"].is_object(),
        "approve_and_sign_managed must answer a signed result"
    );
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined second re-Init must succeed: {init}"
    );
    let (code, refusal) = result_error(provider.wallet(
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: request_id.clone(),
            reason: "approved again".to_string(),
        },
    ));
    assert_eq!(
        code, "invalid_request",
        "a replayed approve must be refused: {refusal}"
    );
    assert!(
        refusal.contains("not pending"),
        "a replay must name the resolved request: {refusal}"
    );

    let store = read_store(&root);
    let stored = store["approval_requests"]
        .as_array()
        .expect("the store under the wallet directory must hold its approvals")
        .iter()
        .find(|request| request["request_id"].as_str() == Some(request_id.as_str()))
        .expect("the store under the wallet directory must hold the request");
    assert_eq!(
        stored["status"], "completed",
        "the store must hold the completed status"
    );
    assert!(
        stored["signed_result"].is_object(),
        "the store must hold the signed result"
    );
    provider.shutdown();
}

/// The external connector address the connector-path test links.
const CONNECTOR_ADDRESS: &str = "0x3333333333333333333333333333333333333333";
/// The transaction hash the connector-path test completes with.
const CONNECTOR_TRANSACTION_HASH: &str =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The external transaction intent the connector approval carries.
///
/// This is request data, not provider logic. It repeats the value
/// `src/tests/support.rs::transaction_intent_payload` builds, because that
/// function is crate-private and this integration test is a separate crate,
/// and adds the `page_url`, `origin` and `network` fields the external
/// handoff uses.
fn external_transaction_payload(from: &str) -> Value {
    json!({
        "schema": "elastos.chain.unsigned_transaction_intent/v1",
        "transaction_type": "eip155_legacy",
        "from": from,
        "to": "0x0000000000000000000000000000000000000002",
        "value": "0x0",
        "data": "0x",
        "chain_id": 20,
        "nonce": "0x7",
        "gas_price": "0x3b9aca00",
        "gas_limit": "0x5208",
        "requires_wallet_approval": true,
        "wallet_intent": "transaction_intent",
        "page_url": "https://ela.city/cinema/view/test",
        "origin": "https://ela.city",
        "network": { "id": "esc-mainnet" }
    })
}

/// The external connector's validated Chain outcome for one approval request.
///
/// `chain_observation` carries the fields the provider's chain-observation
/// binding checks: the network, the transaction hash and the originating
/// account.
fn external_chain_outcome(
    request_id: &str,
    account_id: &str,
    transaction_hash: &str,
) -> ValidatedChainOutcomeV1 {
    ValidatedChainOutcomeV1 {
        schema: VALIDATED_CHAIN_OUTCOME_SCHEMA.to_string(),
        approval_request_id: request_id.to_string(),
        account_id: account_id.to_string(),
        chain_namespace: "eip155:20".to_string(),
        network: PublicNetwork::new("esc-mainnet").expect("the fixture network must be valid"),
        binding: ValidatedChainOutcomeBindingV1::ExternalConnector {
            connector_id: "wallet".to_string(),
            originating_address: CONNECTOR_ADDRESS.to_string(),
        },
        transaction_hash: transaction_hash.to_string(),
        chain_observation: json!({
            "network": "esc-mainnet",
            "hash": transaction_hash,
            "transaction": {
                "hash": transaction_hash,
                "from": CONNECTOR_ADDRESS,
                "blockNumber": "0x2a"
            }
        }),
        confirmed_at: now_ts(),
    }
}

/// The connector handoff and Chain outcome calls answer under the profile and
/// persist under `STORAGE_ROOT`.
///
/// One provider `init`s a root, links a fixed external address with proof type
/// `siwe`, so the linked account's `connector_id` is the actor `wallet`, and
/// sends one `request_approval` with intent `transaction_intent`; its answer
/// holds a `pending` request. `approve_connector_handoff` answers `approved`
/// with a handoff of intent `transaction_intent`. Every request carries
/// principal `person:local:alice`, session `session:confine`, grant
/// `grant:confine`, launch `launch:confine` and actor `wallet`, the same across
/// restarts. A fresh confined start on the same root `init`s it, a replayed
/// `approve_connector_handoff` answers `invalid_request` with "not pending",
/// `complete_connector_handoff` answers `completed` with the transaction hash
/// sent in `signed_result`, and `attach_validated_chain_outcome` answers ok
/// with the outcome in `approval_request.validated_chain_outcome`. After a
/// second restart, a replayed `complete_connector_handoff` answers
/// `invalid_request` with "must be approved before completion", the same
/// outcome attached again answers ok, a substituted outcome answers
/// `chain_outcome_conflict` with "substitution was rejected", and `read_store`
/// shows the request `completed` with that outcome under the root's wallet
/// directory. The payload, the handoff, the transaction hash and the outcome
/// stay test data in the temporary root, and no assertion message prints a
/// whole payload, outcome or store.
///
/// Falsifier: WP18 removes the `STORAGE_ROOT` subpath grant. One grant covers
/// every `storage` call, so no profile edit can fail one of these calls and
/// leave `init` working; no narrower profile falsifier exists, and this test
/// fails on its first `init`.
#[test]
fn connector_handoff_and_chain_outcome_persist_under_storage_root() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::LinkVerifiedAccount {
            proof_binding_id: format!("proof:eip155:20:{CONNECTOR_ADDRESS}"),
            chain_namespace: "eip155:20".to_string(),
            address: CONNECTOR_ADDRESS.to_string(),
            proof_type: "siwe".to_string(),
            label: None,
        }),
    );
    assert_eq!(
        data["account"]["connector_id"], "wallet",
        "the linked account must carry the request's actor as its connector"
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("the linked account must name its id")
        .to_string();

    let data = ok_data(provider.wallet(WalletProviderOperationV2::RequestApproval {
        account_id: account_id.clone(),
        chain_namespace: "eip155:20".to_string(),
        intent: "transaction_intent".to_string(),
        resource: "elastos://chain/esc-mainnet/broadcast_transaction".to_string(),
        reason: "Send EVM transaction".to_string(),
        payload: external_transaction_payload(CONNECTOR_ADDRESS),
        expires_at: now_ts().saturating_add(10 * 60),
    }));
    let approval = &data["approval_request"];
    assert_eq!(
        approval["status"], "pending",
        "request_approval must answer a pending request"
    );
    let request_id = approval["request_id"]
        .as_str()
        .expect("an approval request must name its id")
        .to_string();
    let payload_hash = approval["payload_hash"]
        .as_str()
        .expect("an approval request must name its payload hash")
        .to_string();

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::ApproveConnectorHandoff {
            request_id: request_id.clone(),
            reason: "Approved transaction".to_string(),
        }),
    );
    assert_eq!(
        data["approval_request"]["status"], "approved",
        "approve_connector_handoff must answer the approved request"
    );
    assert_eq!(
        data["handoff"]["intent"], "transaction_intent",
        "the handoff must carry the approval's intent"
    );
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined re-Init must succeed: {init}"
    );

    let (code, refusal) = result_error(provider.wallet(
        WalletProviderOperationV2::ApproveConnectorHandoff {
            request_id: request_id.clone(),
            reason: "Approved again".to_string(),
        },
    ));
    assert_eq!(
        code, "invalid_request",
        "a replayed approve must be refused: {refusal}"
    );
    assert!(
        refusal.contains("not pending"),
        "a replay must name the resolved request: {refusal}"
    );

    let completion = WalletProviderOperationV2::CompleteConnectorHandoff {
        request_id: request_id.clone(),
        payload_hash: payload_hash.clone(),
        signature: None,
        signature_type: None,
        public_key: None,
        signer: CONNECTOR_ADDRESS.to_string(),
        transaction_hash: Some(CONNECTOR_TRANSACTION_HASH.to_string()),
    };
    let data = ok_data(provider.wallet(completion.clone()));
    assert_eq!(
        data["approval_request"]["status"], "completed",
        "complete_connector_handoff must answer the completed request"
    );
    assert_eq!(
        data["approval_request"]["signed_result"]["transaction_hash"], CONNECTOR_TRANSACTION_HASH,
        "the completion must answer the transaction hash sent"
    );

    let outcome = external_chain_outcome(&request_id, &account_id, CONNECTOR_TRANSACTION_HASH);
    let expected_outcome =
        serde_json::to_value(&outcome).expect("the fixture outcome must serialize");
    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::AttachValidatedChainOutcome {
            outcome: outcome.clone(),
        }),
    );
    assert!(
        data["approval_request"]["validated_chain_outcome"] == expected_outcome,
        "the attach answer must carry the stored outcome"
    );
    provider.shutdown();

    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(
        init["status"], "ok",
        "confined second re-Init must succeed: {init}"
    );

    let (code, refusal) = result_error(provider.wallet(completion));
    assert_eq!(
        code, "invalid_request",
        "a replayed completion must be refused: {refusal}"
    );
    assert!(
        refusal.contains("must be approved before completion"),
        "a replay must name the completed request: {refusal}"
    );

    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::AttachValidatedChainOutcome {
            outcome: outcome.clone(),
        }),
    );
    assert!(
        data["approval_request"]["validated_chain_outcome"] == expected_outcome,
        "the same outcome attached again must answer the stored outcome"
    );

    let mut substituted = outcome.clone();
    substituted.chain_observation["status"] = json!("substituted");
    let (code, refusal) = result_error(provider.wallet(
        WalletProviderOperationV2::AttachValidatedChainOutcome {
            outcome: substituted,
        },
    ));
    assert_eq!(
        code, "chain_outcome_conflict",
        "a substituted outcome must be refused: {refusal}"
    );
    assert!(
        refusal.contains("substitution was rejected"),
        "the refusal must name the substitution: {refusal}"
    );

    let store = read_store(&root);
    let stored = store["approval_requests"]
        .as_array()
        .expect("the store under the wallet directory must hold its approvals")
        .iter()
        .find(|request| request["request_id"].as_str() == Some(request_id.as_str()))
        .expect("the store under the wallet directory must hold the request");
    assert_eq!(
        stored["status"], "completed",
        "the store must hold the completed status"
    );
    assert!(
        stored["validated_chain_outcome"] == expected_outcome,
        "the store must hold the attached outcome"
    );
    provider.shutdown();
}

/// The denied outside-write case beneath `STORAGE_PARENT` whose wallet
/// directory the profile cannot create, named as the suite records it.
const FRESH_OUTSIDE_CASE: &str = "<STORAGE_PARENT>/Fresh";

/// The denied outside-write cases, each named as the stand-in suite records
/// it: one unrelated base, two bases beneath `root`, and the fresh base
/// beneath `STORAGE_PARENT`. `confined_outside_write_is_denied` and the
/// stand-in suite both read this one list.
fn outside_write_cases(root: &Path, outside: &Path) -> [(&'static str, PathBuf); 4] {
    let parent = storage_parent(WALLET_PROVIDER, root);
    [
        ("an unrelated base", outside.to_path_buf()),
        ("<root>/sibling", root.join("sibling")),
        (
            "<root>/ElastOS/SystemServices/Sibling",
            root.join("ElastOS/SystemServices/Sibling"),
        ),
        (FRESH_OUTSIDE_CASE, parent.join("Fresh")),
    ]
}

/// Prepares one outside-write case's parent before `init`: every case gets
/// its existing parent so denial must reach `Wallet`, except the fresh base
/// beneath `STORAGE_PARENT`, where nothing is precreated and the first
/// ungranted step is the `mkdir` of `Fresh`.
fn prepare_outside_write_case(case: &str, base: &Path) {
    if case == FRESH_OUTSIDE_CASE {
        return;
    }
    let parent = storage_parent(WALLET_PROVIDER, base);
    fs::create_dir_all(parent).expect("outside parent fixture");
}

/// A write outside the wallet directory is denied by the profile, and the
/// provider reports it and stays in service.
///
/// The last case is the write beneath `STORAGE_PARENT`: `Init` for
/// `<STORAGE_PARENT>/Fresh`, where nothing is precreated at `Fresh` or beneath
/// it, walks up to the granted parent, so its first ungranted step is the
/// `mkdir` of `Fresh`. A write grant on the parent (WP65) creates it, so this
/// test fails on the absence check. `outside_write_cases` holds the case list
/// once; the stand-in suite reads the same list.
///
/// Falsifier: replace `(deny default)` with `(allow default)`; the outside
/// `Init` then succeeds and this test fails.
#[test]
fn confined_outside_write_is_denied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let outside = tempfile::tempdir().expect("temporary outside directory");
    let outside = resolved(outside.path());
    let mut provider = ConfinedProvider::start(&root);

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    // Both an unrelated base and a sibling inside the shared base are outside
    // the wallet grant. Precreate their parents so denial must reach Wallet.
    for (case, denied_base) in &outside_write_cases(&root, &outside) {
        prepare_outside_write_case(case, denied_base);
        let outside_wallet = wallet_dir(denied_base);
        let denied = provider.init(denied_base);
        assert_storage_error(&denied);
        assert!(
            !outside_wallet.exists(),
            "a denied write must create nothing outside the wallet root at {case}: {}",
            outside_wallet.display()
        );

        // Nothing is precreated at `<STORAGE_PARENT>/Fresh` or beneath it, so
        // the walk reaches the granted parent and the first ungranted step is
        // the `mkdir`.
        if *case == FRESH_OUTSIDE_CASE {
            assert!(
                !denied_base.exists(),
                "a denied write beneath STORAGE_PARENT must create nothing: {}",
                denied_base.display()
            );
            let message = denied["message"]
                .as_str()
                .expect("storage refusal must carry a reason");
            assert!(
                message.starts_with("failed to create wallet storage directory"),
                "the refused step must be the write beneath STORAGE_PARENT, not an inspect: {message}"
            );
        }

        let status = provider.send(&json!({ "op": "status" }));
        assert_eq!(
            status["status"], "ok",
            "the provider must answer after a denied write instead of exiting: {status}"
        );
    }

    let recovered = provider.init(&root);
    assert_eq!(
        recovered["status"], "ok",
        "the allowed root remains usable: {recovered}"
    );

    provider.shutdown();
}

/// A read outside the wallet directory is denied by the profile, so the
/// provider refuses that root instead of adopting state it was not granted.
///
/// Falsifier: add a sibling-file read allowance to `confine.sb`; the outside
/// `Init` then adopts the planted key and this test fails.
#[test]
fn confined_outside_read_is_denied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let outside = root.join("sibling");
    let outside_wallet = wallet_dir(&outside);
    plant_storage_key(&outside_wallet);
    // Let Init inspect/sync the fixture directories and stat the key and
    // absent store. Only reading the key's contents remains denied. The
    // profile under test is still read from the single confine.sb source.
    let profile = fs::read_to_string(PROFILE_PATH).expect("profile source");
    let mut read_profile = tempfile::NamedTempFile::new().expect("read fixture profile");
    write!(read_profile, "{profile}\n\
        (allow file-read* (literal (param \"READ_FIXTURE_WALLET\")) (literal (param \"READ_FIXTURE_PARENT\")))\n\
        (allow file-read-metadata (literal (param \"READ_FIXTURE_KEY\")) (literal (param \"READ_FIXTURE_STORE\")))\n")
        .expect("write read fixture profile");
    let key_path = outside_wallet.join(WALLET_KEY_FILE);
    let store_path = outside_wallet.join("wallet-state.json");
    let outside_parent = storage_parent(WALLET_PROVIDER, &outside);
    let mut provider = ConfinedProvider::start_with_profile(
        &root,
        read_profile.path(),
        &[
            ("READ_FIXTURE_WALLET", &outside_wallet),
            ("READ_FIXTURE_PARENT", outside_parent.as_path()),
            ("READ_FIXTURE_KEY", &key_path),
            ("READ_FIXTURE_STORE", &store_path),
        ],
    );

    let denied = provider.init(&outside);
    assert_storage_error(&denied);
    assert!(
        denied["message"]
            .as_str()
            .unwrap()
            .starts_with("failed to open wallet storage key:"),
        "the refusal must reach the planted key read: {denied}"
    );

    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["status"], "ok",
        "the provider must answer after a denied read: {status}"
    );

    provider.shutdown();
}

/// A key planted beneath `STORAGE_PARENT` stays unread.
///
/// The parent read grants the directory itself only, not a directory beneath
/// it, and the storage-root write grant stops at `STORAGE_ROOT`. The test
/// plants a complete key at
/// `<STORAGE_PARENT>/Sibling/ElastOS/SystemServices/Wallet`, beneath
/// `STORAGE_PARENT` and outside `STORAGE_ROOT`, and records its bytes. With
/// the real profile `init` for that sibling base refuses with `storage_error`,
/// the planted bytes stay unchanged and no `wallet-state.json` appears beside
/// them. The provider then serves its own root, and the key it writes there
/// differs from the planted one, so it never adopted the planted key. The
/// write half beneath the parent is the `<STORAGE_PARENT>/Fresh` case of
/// `confined_outside_write_is_denied`, which is refused at its first write
/// (the `mkdir`).
///
/// Falsifier: widen the parent read from `literal` to `subpath` (WP57); the
/// planted key then loads, `init` answers ok and this test fails on its
/// refusal.
#[test]
fn planted_key_beneath_storage_parent_is_not_read() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    // `<STORAGE_PARENT>/Sibling`: beneath the granted parent and outside
    // `STORAGE_ROOT`, which is `<STORAGE_PARENT>/Wallet`.
    let planted = storage_parent(WALLET_PROVIDER, &root).join("Sibling");
    let planted_wallet = wallet_dir(&planted);
    plant_storage_key(&planted_wallet);
    let planted_key = planted_wallet.join(WALLET_KEY_FILE);
    let planted_bytes = fs::read(&planted_key).expect("planted key file");

    let mut provider = ConfinedProvider::start(&root);

    let denied = provider.init(&planted);
    assert_storage_error(&denied);
    assert_eq!(
        fs::read(&planted_key).expect("planted key stays readable to the test"),
        planted_bytes,
        "the planted key must stay unchanged after the refused read"
    );
    assert!(
        !planted_wallet.join("wallet-state.json").exists(),
        "a refused read must write no store beside the planted key: {}",
        planted_wallet.display()
    );

    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["status"], "ok",
        "the provider must answer after a denied read: {status}"
    );

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "the granted root must serve: {init}");
    let own_key = wallet_dir(&root).join(WALLET_KEY_FILE);
    let own_bytes = fs::read(&own_key).expect("the provider writes its own key");
    assert_ne!(
        own_bytes,
        planted_bytes,
        "the provider must not adopt the planted key: {}",
        own_key.display()
    );

    provider.shutdown();
}

/// Account operations beneath `STORAGE_PARENT` are refused.
///
/// `<STORAGE_PARENT>/Sibling` is outside `STORAGE_ROOT`, and its wallet
/// directory is precreated empty, so the refusal is neither the `mkdir` of
/// `<STORAGE_PARENT>/Fresh` nor a read of a planted key. `init` for that
/// sibling base refuses with `storage_error`, and `init` resets the root
/// first, so the provider keeps no usable root. The wallet calls that follow
/// therefore answer through `data.result` with `status` `error`, `code`
/// `not_initialized` and a reason, and the sibling's wallet directory stays
/// empty. The array sends `rename_account`, `revoke_account`,
/// `set_default_account` and `default_account` before the
/// `export_managed_recovery_key`, `import_managed_recovery_key`,
/// `export_managed_recovery_set` and `import_managed_recovery_set` calls, then
/// the `challenge`, `verify_proof`, `verify_contract_proof` and
/// `link_verified_account` calls of task 082, the `bitcoin_challenge` and
/// `verify_bip322_proof` calls of task 083, the `request_approval`,
/// `approve_and_sign_managed`, `reject_approval` and `list_approvals` calls of
/// task 084, the `approve_connector_handoff`, `complete_connector_handoff` and
/// `attach_validated_chain_outcome` calls of task 085, the
/// `request_protected_content_rights_signature` call of task 086, and the
/// `create_managed_account` and `list_accounts` calls that 072 named come last.
/// The loop sends every call in the array and records each call that is not
/// refused; after the loop one assertion fails, naming every recorded kind
/// with its result status and code, so a WP88 run names every call in the
/// array. The array runs before the `storage_error` check, so a grant on the
/// parent fails on the calls that are not refused rather than only on `init`.
/// `list_accounts` is sent only to
/// show that the refused `create_managed_account` created nothing. After
/// `init` for the granted root answers ok, the same call answers ok, the
/// listing holds that account, and the account is in the store under the root.
///
/// Falsifiers: append a read and write grant on `STORAGE_PARENT` (WP88); the
/// sibling `init` then succeeds, so the loop records every call that is not
/// refused and the one assertion names them all. Remove the storage-root
/// grant (WP18); the granted `init` fails, so this test fails on its ok.
#[test]
fn account_operations_beneath_storage_parent_are_refused() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    // `<STORAGE_PARENT>/Sibling`: beneath the granted parent and outside
    // `STORAGE_ROOT`, which is `<STORAGE_PARENT>/Wallet`.
    let sibling = storage_parent(WALLET_PROVIDER, &root).join("Sibling");
    let sibling_wallet = wallet_dir(&sibling);
    fs::create_dir_all(&sibling_wallet).expect("precreate the sibling wallet directory");
    let mut provider = ConfinedProvider::start(&root);

    let denied = provider.init(&sibling);

    // The four account edits of task 080, the four managed-recovery calls of
    // task 081, the four EVM proof and link calls of task 082, the two
    // Bitcoin proof calls of task 083 and the four managed approval calls of
    // task 084 come first, so a grant on `STORAGE_PARENT` answers these calls
    // without the refusal this test requires.
    let operations = [
        WalletProviderOperationV2::RenameAccount {
            account_id: "wallet:eip155:20:0xabc".to_string(),
            label: "Outside".to_string(),
        },
        WalletProviderOperationV2::RevokeAccount {
            account_id: "wallet:eip155:20:0xabc".to_string(),
        },
        WalletProviderOperationV2::SetDefaultAccount {
            chain_namespace: "eip155:20".to_string(),
            intent: "publish_envelope".to_string(),
            account_id: "wallet:eip155:20:0xabc".to_string(),
        },
        WalletProviderOperationV2::DefaultAccount {
            chain_namespace: "eip155:20".to_string(),
            intent: "publish_envelope".to_string(),
        },
        WalletProviderOperationV2::ExportManagedRecoveryKey {
            account_id: "wallet:eip155:20:0xabc".to_string(),
        },
        WalletProviderOperationV2::ImportManagedRecoveryKey {
            recovery_key: json!({}),
            label: Some("Outside".to_string()),
        },
        WalletProviderOperationV2::ExportManagedRecoverySet {},
        WalletProviderOperationV2::ImportManagedRecoverySet {
            recovery_set: ManagedRecoverySetV1::new(vec![ManagedRecoveryKeyEntryV1 {
                account_id: "wallet:eip155:20:0xabc".to_string(),
                recovery_key: json!({}),
                label: Some("Outside".to_string()),
            }])
            .expect("the outside fixture set must be well formed"),
        },
        WalletProviderOperationV2::Challenge {
            domain: "http://elastos.local".to_string(),
            uri: "http://elastos.local/apps/home/".to_string(),
            address: "0x00000000000000000000000000000000000000ab".to_string(),
            chain_id: 20,
            resources: vec![],
        },
        WalletProviderOperationV2::VerifyProof {
            message: "Outside EVM proof".to_string(),
            signature: "0x01020304".to_string(),
        },
        WalletProviderOperationV2::VerifyContractProof {
            message: "Outside EVM proof".to_string(),
            signature: "0x01020304".to_string(),
            evidence: erc1271_evidence(
                "Outside EVM proof",
                "0x01020304",
                "0x00000000000000000000000000000000000000cc",
            ),
        },
        WalletProviderOperationV2::LinkVerifiedAccount {
            proof_binding_id: "proof:eip155:20:0xabc".to_string(),
            chain_namespace: "eip155:20".to_string(),
            address: "0xabc".to_string(),
            proof_type: "siwe".to_string(),
            label: Some("Outside".to_string()),
        },
        WalletProviderOperationV2::BitcoinChallenge {
            domain: "elastos.local".to_string(),
            uri: "http://elastos.local/apps/home/".to_string(),
            address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
            network: PublicNetwork::bitcoin(),
            resources: vec!["elastos://wallet/account/link".to_string()],
        },
        WalletProviderOperationV2::VerifyBip322Proof {
            message: "Outside Bitcoin proof".to_string(),
            signature: "signature".to_string(),
            signature_type: "bitcoin_signed_message".to_string(),
            public_key: Some(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            ),
        },
        personal_sign_approval(
            "wallet:eip155:20:0xabc",
            "0x00000000000000000000000000000000000000ab",
            "Outside approval",
        ),
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: "wallet-request:outside".to_string(),
            reason: "Outside approval".to_string(),
        },
        WalletProviderOperationV2::RejectApproval {
            request_id: "wallet-request:outside".to_string(),
            reason: "Outside rejection".to_string(),
        },
        WalletProviderOperationV2::ListApprovals {
            include_resolved: false,
        },
        WalletProviderOperationV2::ApproveConnectorHandoff {
            request_id: "wallet-request:outside".to_string(),
            reason: "Outside connector approval".to_string(),
        },
        WalletProviderOperationV2::CompleteConnectorHandoff {
            request_id: "wallet-request:outside".to_string(),
            payload_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            signature: None,
            signature_type: None,
            public_key: None,
            signer: CONNECTOR_ADDRESS.to_string(),
            transaction_hash: Some(CONNECTOR_TRANSACTION_HASH.to_string()),
        },
        WalletProviderOperationV2::AttachValidatedChainOutcome {
            outcome: external_chain_outcome(
                "wallet-request:00000000000000000000000000000000",
                &format!("wallet:eip155:20:{CONNECTOR_ADDRESS}"),
                CONNECTOR_TRANSACTION_HASH,
            ),
        },
        WalletProviderOperationV2::RequestProtectedContentRightsSignature {
            account_id: "wallet:eip155:20:0xabc".to_string(),
            canonical_rights_request_hex: hex::encode(
                protected_content_rights_request(
                    "0x00000000000000000000000000000000000000ab",
                    now_ts(),
                    now_ts().saturating_add(120),
                    0x52,
                )
                .canonical_bytes()
                .expect("the outside rights request must encode canonically"),
            ),
            reason: "Outside protected-content rights request".to_string(),
        },
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Outside".to_string()),
            create_new: false,
        },
        WalletProviderOperationV2::ListAccounts {
            include_revoked: false,
        },
    ];
    let mut not_refused = Vec::new();
    for operation in operations {
        let kind = operation_kind(&operation);
        let request = wallet_request(operation);
        let answer = provider.send(&json!({
            "op": "wallet_contract",
            "request": request,
            "_runtime_invocation": runtime_invocation_envelope(),
        }));
        let result = answer.get("data").and_then(|data| data.get("result"));
        let refused = answer.get("status").and_then(Value::as_str) == Some("ok")
            && result
                .and_then(|result| result.get("status"))
                .and_then(Value::as_str)
                == Some("error")
            && result
                .and_then(|result| result.get("code"))
                .and_then(Value::as_str)
                == Some("not_initialized")
            && result
                .and_then(|result| result.get("message"))
                .and_then(Value::as_str)
                .is_some_and(|message| !message.is_empty());
        if !refused {
            not_refused.push((
                kind,
                refusal_field(result.and_then(|result| result.get("status"))),
                refusal_field(result.and_then(|result| result.get("code"))),
            ));
        }
    }
    assert!(
        not_refused.is_empty(),
        "every call beneath STORAGE_PARENT must be refused with not_initialized; \
         calls not refused: {}",
        not_refused
            .iter()
            .map(|(kind, status, code)| format!("{kind} (status {status}, code {code})"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // The refused `init` is why every call above answered `not_initialized`.
    assert_storage_error(&denied);
    let message = denied["message"]
        .as_str()
        .expect("storage refusal must carry a reason");
    assert!(
        message.starts_with("failed to inspect wallet storage directory"),
        "the refused step must be the inspect beneath STORAGE_PARENT: {message}"
    );

    assert!(
        !sibling_wallet.join(WALLET_KEY_FILE).exists(),
        "the refused account call must create no key: {}",
        sibling_wallet.display()
    );
    assert!(
        !sibling_wallet.join("wallet-state.json").exists(),
        "the refused account call must create no store: {}",
        sibling_wallet.display()
    );

    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "the granted root must serve: {init}");
    let data = ok_data(
        provider.wallet(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Inside".to_string()),
            create_new: false,
        }),
    );
    let account_id = data["account"]["account_id"]
        .as_str()
        .expect("managed account must name its id")
        .to_string();
    let data = ok_data(provider.wallet(WalletProviderOperationV2::ListAccounts {
        include_revoked: false,
    }));
    assert!(
        data["accounts"].as_array().is_some_and(|accounts| accounts
            .iter()
            .any(|account| account["account_id"] == account_id.as_str())),
        "the created managed account must be listed: {data}"
    );
    let store = read_store(&root);
    assert!(
        store["accounts"].as_array().is_some_and(|accounts| accounts
            .iter()
            .any(|account| account["account_id"] == account_id.as_str())),
        "account state must land under the wallet root: {store}"
    );

    provider.shutdown();
}

/// The serde `kind` tag of one wallet operation, so a failure names it.
fn operation_kind(operation: &WalletProviderOperationV2) -> String {
    serde_json::to_value(operation)
        .expect("the operation must serialize")
        .get("kind")
        .and_then(Value::as_str)
        .expect("the operation must serialize with its kind tag")
        .to_string()
}

/// The text a refusal record prints for a result status or code.
fn refusal_field(field: Option<&Value>) -> String {
    field
        .and_then(Value::as_str)
        .map_or_else(|| "none".to_string(), |text| text.to_string())
}

/// A complete key file makes the outside root readable if the profile ever
/// grants that path, so the denial above proves the profile, not the file.
fn plant_storage_key(wallet_dir: &Path) {
    fs::create_dir_all(wallet_dir).expect("plant wallet directory");
    let key_path = wallet_dir.join(WALLET_KEY_FILE);
    fs::write(&key_path, format!("{}\n", "11".repeat(32))).expect("plant storage key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("planted key must be private so only the read rule decides");
    }
}

/// A confined start that cannot apply its profile is refused, and the refusal
/// says why.
///
/// Three profiles cannot be applied: a path that does not exist, a copy of
/// `confine.sb` with its last `)` removed, and the real profile with every
/// parameter bound except `STORAGE_ROOT`. `sandbox-exec` exits before the
/// provider starts in each case. The test waits for that exit first, then
/// sends `init`, and requires the one harness failure to name the request, the
/// exit status and `sandbox-exec`'s own line on standard error.
///
/// Falsifier: start the provider directly when the profile file is missing
/// (WP28); case (a) then times out at the bounded wait with the provider
/// running, so this test fails before `try_send`. Drop the child's standard
/// error from `unanswered` (WP29); every failure loses `sandbox-exec`'s line
/// and this test fails.
#[test]
fn startup_is_refused_when_the_profile_cannot_be_applied() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary wallet root");
    let base = resolved(fixture.path());
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile_root = resolved(profile_root.path());
    let missing_profile = profile_root.join("absent-profile.sb");
    let source = fs::read_to_string(PROFILE_PATH).expect("profile source");
    let last = source.rfind(')').expect("the profile must close");
    let mut unclosed = source;
    unclosed.remove(last);
    let unclosed_profile = profile_root.join("unclosed-profile.sb");
    fs::write(&unclosed_profile, unclosed).expect("unclosed profile must be writable");

    let wallet_root = wallet_dir(&base);
    let canonical = canonical_bindings(WALLET_PROVIDER, &base, Path::new(PROVIDER_BINARY));
    create_shared_ancestors(&canonical);
    let unbound_root: Vec<(&str, PathBuf)> = canonical
        .iter()
        .filter(|(name, _)| *name != "STORAGE_ROOT")
        .cloned()
        .collect();
    let request = json!({
        "op": "init",
        "config": { "base_path": base.display().to_string() }
    });
    // Each case keeps the stable part of `sandbox-exec`'s line that discovery
    // quoted on this host.
    type StartupRefusalCase<'a> = (&'a str, PathBuf, Vec<(&'a str, PathBuf)>, String);
    let cases: [StartupRefusalCase<'_>; 3] = [
        (
            "(a) the profile file does not exist",
            missing_profile.clone(),
            canonical.to_vec(),
            missing_profile.display().to_string(),
        ),
        (
            "(b) the profile does not parse",
            unclosed_profile,
            canonical.to_vec(),
            "syntax error: expecting ')'".to_string(),
        ),
        (
            "(c) the profile names an unbound parameter",
            PathBuf::from(PROFILE_PATH),
            unbound_root,
            "invalid data type of path filter".to_string(),
        ),
    ];

    for (case, profile, bindings, marker) in cases {
        let bindings: Vec<(&str, &Path)> = bindings
            .iter()
            .map(|(name, path)| (*name, path.as_path()))
            .collect();
        let mut provider =
            ConfinedProvider::start_under(&profile, &bindings, Path::new(PROVIDER_BINARY));
        let exit = provider.wait_for_exit();
        assert!(
            exit.code().is_some(),
            "{case}: sandbox-exec must exit instead of starting the provider: {exit}"
        );
        assert_ne!(
            exit.code(),
            Some(0),
            "{case}: sandbox-exec must refuse the profile: {exit}"
        );
        let failure = provider
            .try_send(&request)
            .expect_err("a refused start must not answer a request");
        assert!(
            failure.contains(&request.to_string()),
            "{case}: the failure must name the request: {failure}"
        );
        assert!(
            failure.contains(&exit.to_string()),
            "{case}: the failure must name the exit status: {failure}"
        );
        assert!(
            failure.contains(&marker),
            "{case}: the failure must carry sandbox-exec's line: {failure}"
        );
        assert!(
            !failure.contains("execvp"),
            "{case}: sandbox-exec must refuse the profile before any exec: {failure}"
        );
        assert!(
            !wallet_root.exists(),
            "{case}: a refused start must create no wallet directory: {}",
            wallet_root.display()
        );
        eprintln!("{case} startup refusal: {failure}");
    }
}

/// The lab writer refuses an unnamed right and writes no profile, and the
/// wallet start under that unwritten path is refused before the provider runs.
///
/// For each name of `allow_rule_profiles` (did first, then wallet) the test
/// reads `capsules/<name>/tests/fixtures/confine/declared-rights.json` and adds
/// one entry: a rights entry `unnamed-right` (case (a)) or a platform-baseline
/// entry `unnamed-baseline` with that name's justification prefix and a reason
/// (case (b)). `write_generated_profile` must return exactly
/// `<name> declares <id>, which the shared contract does not name`, creating no
/// file at that name's path; an `Ok` panics naming the provider and the case.
/// The start half is wallet only: `PROVIDER_BINARY` is the wallet binary, and
/// did's harness cannot run the generator. For did the test runs the file half
/// and starts nothing. For wallet, the confined start under the missing path
/// exits non-zero before any request; `try_send` of `init` fails naming the
/// request, the exit status and the missing path, and no wallet directory is
/// created. On a host without the sandbox gate the file half still runs and
/// wallet's start half is skipped through the existing gate only.
///
/// Falsifier: WP106 makes the rights-list id refusal in `declared_entries`
/// never fire, so case (a) writes a profile and the test panics at the refusal
/// check in the did case; WP107 makes the platform-baseline id refusal never
/// fire, so case (b) panics at that check in the did case; WP108 makes
/// `write_generated_profile` create the path before it calls
/// `generate_profile`, so both cases fail the no-file assertion in the did case.
#[test]
fn generator_refuses_an_unnamed_right_and_the_start_is_refused() {
    let fixture = tempfile::tempdir().expect("temporary wallet root");
    let base = resolved(fixture.path());
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    let rule = r#"(allow file-read* (literal "/private/var/cc-confine-unnamed"))"#;
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile_root = resolved(profile_root.path());
    let canonical = canonical_bindings(WALLET_PROVIDER, &base, Path::new(PROVIDER_BINARY));
    create_shared_ancestors(&canonical);
    let wallet_root = wallet_dir(&base);
    let request = json!({
        "op": "init",
        "config": { "base_path": base.display().to_string() }
    });
    for name in allow_rule_profiles() {
        let declared_path = capsules
            .join(name)
            .join("tests/fixtures/confine/declared-rights.json");
        let declared =
            read_declared_rights(name, &declared_path).unwrap_or_else(|err| panic!("{err}"));
        let prefix = platform_baseline_justification(name);
        let cases: [(&str, &str, Value); 2] = [
            (
                "(a) an unnamed right",
                "unnamed-right",
                json!({ "id": "unnamed-right", "rules": [rule] }),
            ),
            (
                "(b) an unnamed platform-baseline rule",
                "unnamed-baseline",
                json!({
                    "id": "unnamed-baseline",
                    "justification": format!(
                        "{prefix}a declared right that the shared contract does not name"
                    ),
                    "rules": [rule],
                }),
            ),
        ];
        for (case, id, entry) in cases {
            let mut declared = declared.clone();
            if id == "unnamed-right" {
                declared["rights"]
                    .as_array_mut()
                    .expect("declared rights")
                    .push(entry);
            } else {
                declared[PLATFORM_BASELINE]["rules"]
                    .as_array_mut()
                    .expect("platform-baseline rules")
                    .push(entry);
            }
            let path = profile_root.join(format!("{name}-{id}-profile.sb"));
            let refusal = match write_generated_profile(name, &declared, &path) {
                Ok(()) => panic!(
                    "{name} {case}: an unnamed id must be refused, but a profile was written"
                ),
                Err(refusal) => refusal,
            };
            assert_eq!(
                refusal,
                format!("{name} declares {id}, which the shared contract does not name"),
                "{name} {case}: the refusal must be the one unnamed-id reason"
            );
            eprintln!("{name} {case} refusal: {refusal}");
            assert!(
                !path.exists(),
                "{name} {case}: a refused profile must create no file: {}",
                path.display()
            );
            if name != "wallet-provider" {
                continue;
            }
            if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
                continue;
            }
            let bindings: Vec<(&str, &Path)> = canonical
                .iter()
                .map(|(name, path)| (*name, path.as_path()))
                .collect();
            let mut provider =
                ConfinedProvider::start_under(&path, &bindings, Path::new(PROVIDER_BINARY));
            let exit = provider.wait_for_exit();
            assert!(
                exit.code().is_some(),
                "{case}: sandbox-exec must exit instead of starting the provider: {exit}"
            );
            assert_ne!(
                exit.code(),
                Some(0),
                "{case}: sandbox-exec must refuse the missing profile: {exit}"
            );
            let failure = provider
                .try_send(&request)
                .expect_err("a refused start must not answer a request");
            assert!(
                failure.contains(&request.to_string()),
                "{case}: the failure must name the request: {failure}"
            );
            assert!(
                failure.contains(&exit.to_string()),
                "{case}: the failure must name the exit status: {failure}"
            );
            assert!(
                failure.contains(&path.display().to_string()),
                "{case}: the failure must name the missing path: {failure}"
            );
            assert!(
                !failure.contains("execvp"),
                "{case}: sandbox-exec must refuse the profile before any exec: {failure}"
            );
            assert!(
                !wallet_root.exists(),
                "{case}: a refused start must create no wallet directory: {}",
                wallet_root.display()
            );
            eprintln!("{case} startup refusal: {failure}");
        }
    }
}

/// The one build-output reader returns the executable the build reports, and
/// refuses output that names no did bin artifact.
///
/// The fixture output holds a `did-provider` non-bin test artifact whose
/// `executable` is `/fixture/out/deps/did_provider-test`, another crate's bin
/// artifact and the `did-provider` bin artifact whose `executable` is
/// `/fixture/out/did-provider`, outside any `target` directory. Only the bin
/// artifact's executable is read, so the non-bin artifact's executable comes
/// before it and the kind check skips it. Output without a `did-provider` bin
/// artifact gives the reader's refusal, which names `did-provider` and
/// `executable`, and that output still carries the non-bin artifact. The test
/// starts no process and needs no sandbox.
///
/// Falsifier: WP128 returns
/// `did_provider_dir().join("target/debug/did-provider")` instead of the
/// reported `executable`, so this test fails on the fixture path.
/// `standin_launcher_finds_the_built_did_binary` alone still passes under
/// WP128, because the guessed file exists after did's build. WP130 disables
/// the kind check, so this test fails because the non-bin artifact's
/// executable is read first.
#[test]
fn did_binary_is_the_executable_the_build_reports() {
    let did_test = json!({
        "reason": "compiler-artifact",
        "target": { "name": DID_PROVIDER, "kind": ["test"] },
        "executable": "/fixture/out/deps/did_provider-test",
    });
    let other_bin = json!({
        "reason": "compiler-artifact",
        "target": { "name": WALLET_PROVIDER, "kind": ["bin"] },
        "executable": "/fixture/out/wallet-provider",
    });
    let did_bin = json!({
        "reason": "compiler-artifact",
        "target": { "name": DID_PROVIDER, "kind": ["bin"] },
        "executable": "/fixture/out/did-provider",
    });
    let output = [did_test.clone(), other_bin.clone(), did_bin]
        .map(|line| line.to_string())
        .join("\n");
    assert_eq!(
        did_binary_executable(&output).expect("the did-provider bin artifact must be read"),
        PathBuf::from("/fixture/out/did-provider"),
        "the reader must return the executable the build reports"
    );
    let without_did_bin = [did_test, other_bin]
        .map(|line| line.to_string())
        .join("\n");
    let reason = did_binary_executable(&without_did_bin)
        .expect_err("output without a did-provider bin artifact must be refused");
    assert!(
        reason.contains(DID_PROVIDER) && reason.contains("executable"),
        "the refusal must name did-provider and executable: {reason}"
    );
}

/// The stand-in finds the did binary through one build of did's manifest.
///
/// `did_provider_binary` runs `cargo build --locked --offline --manifest-path
/// capsules/did-provider/Cargo.toml --bin did-provider --message-format=json`
/// once and reads the bin artifact's `executable`. The path must be an existing
/// file named `did-provider` under did's own `target` directory, or under the
/// target directory cargo reported. A failed build fails this test with the
/// build's output; there is no skip and no fallback to another binary.
#[test]
fn standin_launcher_finds_the_built_did_binary() {
    let binary = did_provider_binary();
    assert!(
        binary.is_file(),
        "the did-provider binary must exist: {}",
        binary.display()
    );
    assert_eq!(
        binary.file_name().and_then(std::ffi::OsStr::to_str),
        Some(DID_PROVIDER),
        "the binary must be named {DID_PROVIDER}: {}",
        binary.display()
    );
    let did_target = did_provider_dir().join("target");
    let cargo_target = std::env::var_os("CARGO_TARGET_DIR").map(|dir| {
        let dir = PathBuf::from(dir);
        if dir.is_absolute() {
            dir
        } else {
            did_provider_dir().join(dir)
        }
    });
    assert!(
        binary.starts_with(&did_target)
            || cargo_target
                .as_ref()
                .is_some_and(|target| binary.starts_with(target)),
        "the binary must sit under did's target directory or the target \
         directory cargo reported: {}",
        binary.display()
    );
}

/// The lab stand-in launcher refuses a start it cannot confine, for the named
/// provider with its own binary and declared rights.
///
/// The host rows run on every host and start no process. Case (a) `plan9`, a
/// forced unsupported OS, refuses with one reason that says it has no
/// confinement design and names the list where the stand-in applies
/// confinement. Cases (b1) to (b3) are simulated Linux host reports, each
/// naming `StandinPrimitive::Landlock`, `StandinPrimitive::UserNamespaces` or
/// `StandinPrimitive::SeccompFilter` as unavailable, and each refuses with the
/// design's exact words for that primitive. Case (b4) is a simulated Linux
/// host that reports nothing missing; it refuses with a reason that says Linux
/// is designed, not enforced, in this lab, so `linux` is not in
/// `DECLARED_CONFINED_OS`. Case (b5) is a simulated `macos` host, an OS in
/// `DECLARED_CONFINED_OS`, whose report leaves Landlock unavailable; it
/// refuses with that primitive's design words and `on macos`, and its tool is
/// the real `SANDBOX_EXEC` path, so without the missing-primitive-first rule
/// the stand-in would go on to the tool checks and start. Each host reason
/// starts `{name} start on {os} is refused:` and carries only its own case's
/// words. Case (c) `macos` with the absent
/// `tests/absent-sandbox-exec` refuses with a reason that names the OS,
/// the path and `is absent`, and carries no `SANDBOX_EXEC` path, so the absent
/// check answers it and not the later wrong-tool check. Case (c2) `macos` with
/// the test executable as the tool refuses with a reason that names the OS,
/// that path and `SANDBOX_EXEC`. Every row creates no storage root under its
/// base and no profile file.
///
/// Cases (c3) a `binary_path` that is not a file, (d) an added
/// `unnamed-right` rights entry, (e) a declared `storage` rule that names a
/// parameter the launch does not bind, and (f) an `init` that cannot create
/// its storage root run only through `sandbox_available`. Case (c3)
/// refuses with a reason that names the provider and the absent path before
/// any profile, and creates neither a profile nor a storage root. Case (d)
/// returns the exact unnamed-id reason and writes no profile. Case (e) writes
/// the profile, and `sandbox-exec` exits before the provider, so the reason
/// carries the exit status and `sandbox-exec`'s line. Case (f) writes the
/// profile, and `init` answers a JSON error because the provider's storage
/// root is a planted regular file, so the reason holds `init answered` and the
/// answer, and the planted path stays a regular file. Cases (c3), (d) and (e)
/// create no storage root.
///
/// Falsifier: WP112 starts the binary bare in the host refusal, so (a) returns
/// Started; WP113 starts it bare after a failed `init`, so (e) returns Started;
/// WP115 ignores the writer's refusal and starts under the committed
/// `confine.sb`, so (d) returns Started instead of its reason. WP118 removes
/// the check that the tool is `SANDBOX_EXEC`, so (c2) is Started; WP119
/// removes the binary-file check, so (c3) panics in `resolved`; WP120 returns
/// `Ok(provider)` for an `init` answer that is not `ok`, so (f) is Started.
/// WP125 makes the absent-tool check never fire, so (c) reads the wrong-tool
/// reason instead; WP126 drops the OS from the wrong-tool reason, so (c2)
/// loses `on macos`. WP131 starts the binary bare on a simulated Linux host
/// that reports a primitive unavailable, so (b1) returns Started; WP132
/// returns one fixed reason that names no primitive, so (b1) loses the
/// design's Landlock words. WP135 moves the `DECLARED_CONFINED_OS` lookup back
/// above the missing-primitive check, so (b5) returns Started where
/// `sandbox-exec` exists; WP136 prefixes the missing-primitive reason with
/// `linux has no confinement design; `, so (b1) carries the forbidden words;
/// WP137 drops the `{name} start on {os} is refused: ` prefix from the final
/// `Err`, so (a) lacks it.
fn standin_refusals_for(name: &str, provider: &Path, declared: &Value) {
    let present = std::env::current_exe().expect("the test executable path must be available");
    let absent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/absent-sandbox-exec");
    assert!(
        !absent.exists(),
        "the fixture path must be absent: {}",
        absent.display()
    );
    let confined_os = DECLARED_CONFINED_OS.join(", ");
    let absent_text = absent.display().to_string();
    let present_text = present.display().to_string();
    let missing_landlock = "linux confinement refused: the kernel has no Landlock";
    let missing_user_namespaces = "linux confinement refused: user namespaces are turned off";
    let missing_seccomp = "linux confinement refused: the seccomp filter cannot be installed";
    let designed_not_enforced = "linux is designed, not enforced";
    type StandinRefusalCase<'a> = (&'a str, StandinHost, &'a Path, Vec<&'a str>, Vec<&'a str>);
    let cases: [StandinRefusalCase<'_>; 8] = [
        (
            "(a) a forced unsupported OS",
            StandinHost::reporting("plan9"),
            present.as_path(),
            vec!["plan9", "has no confinement design", confined_os.as_str()],
            vec![
                designed_not_enforced,
                missing_landlock,
                missing_user_namespaces,
                missing_seccomp,
            ],
        ),
        (
            "(b1) linux without Landlock",
            StandinHost::linux_missing(StandinPrimitive::Landlock),
            present.as_path(),
            vec![missing_landlock],
            vec![
                missing_user_namespaces,
                missing_seccomp,
                designed_not_enforced,
                "has no confinement design",
            ],
        ),
        (
            "(b2) linux without user namespaces",
            StandinHost::linux_missing(StandinPrimitive::UserNamespaces),
            present.as_path(),
            vec![missing_user_namespaces],
            vec![
                missing_landlock,
                missing_seccomp,
                designed_not_enforced,
                "has no confinement design",
            ],
        ),
        (
            "(b3) linux without the seccomp filter",
            StandinHost::linux_missing(StandinPrimitive::SeccompFilter),
            present.as_path(),
            vec![missing_seccomp],
            vec![
                missing_landlock,
                missing_user_namespaces,
                designed_not_enforced,
                "has no confinement design",
            ],
        ),
        (
            "(b4) linux with every primitive reported present",
            StandinHost::reporting("linux"),
            present.as_path(),
            vec![designed_not_enforced, "not in DECLARED_CONFINED_OS"],
            vec![
                missing_landlock,
                missing_user_namespaces,
                missing_seccomp,
                "has no confinement design",
            ],
        ),
        (
            "(b5) macos whose report leaves Landlock unavailable",
            StandinHost::missing("macos", StandinPrimitive::Landlock),
            Path::new(SANDBOX_EXEC),
            vec![missing_landlock, "on macos"],
            vec![
                missing_user_namespaces,
                missing_seccomp,
                designed_not_enforced,
                "has no confinement design",
            ],
        ),
        (
            "(c) macos without the tool",
            StandinHost::reporting("macos"),
            absent.as_path(),
            vec!["on macos", "is absent", absent_text.as_str()],
            vec![SANDBOX_EXEC],
        ),
        (
            "(c2) macos with another tool",
            StandinHost::reporting("macos"),
            present.as_path(),
            vec!["on macos", present_text.as_str(), SANDBOX_EXEC],
            vec![],
        ),
    ];
    for (case, host, sandbox_exec, named, forbidden) in cases {
        let fixture = tempfile::tempdir().expect("temporary wallet base");
        let base = resolved(fixture.path());
        let profile_root = tempfile::tempdir().expect("temporary profile root");
        let profile_dir = resolved(profile_root.path());
        let refusal = standin_spawn_confined_provider(
            host,
            StandinPolicy::Seatbelt(sandbox_exec),
            name,
            provider,
            &base,
            declared,
            &profile_dir,
        )
        .err()
        .unwrap_or_else(|| panic!("{case}: a start on {} must be refused", host.os));
        let prefix = format!("{name} start on {} is refused: ", host.os);
        assert!(
            refusal.starts_with(&prefix),
            "{case}: the refusal must start with {prefix:?}: {refusal}"
        );
        for expected in named {
            assert!(
                refusal.contains(expected),
                "{case}: the refusal must name {expected}: {refusal}"
            );
        }
        for unexpected in forbidden {
            assert!(
                !refusal.contains(unexpected),
                "{case}: the refusal must not carry {unexpected}: {refusal}"
            );
        }
        eprintln!("{name} {case} stand-in refusal: {refusal}");
        assert!(
            !provider_storage_root(name, &base).exists(),
            "{case}: a refused start must create no storage root: {}",
            provider_storage_root(name, &base).display()
        );
        assert!(
            fs::read_dir(&profile_dir)
                .expect("the profile directory must be readable")
                .next()
                .is_none(),
            "{case}: a refused start must write no profile: {}",
            profile_dir.display()
        );
    }

    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }

    // (c3) A binary path that is not a file is refused before any profile.
    let fixture = tempfile::tempdir().expect("temporary wallet base");
    let base = resolved(fixture.path());
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile_dir = resolved(profile_root.path());
    let absent_binary = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/absent-provider-binary");
    assert!(
        !absent_binary.exists(),
        "the fixture path must be absent: {}",
        absent_binary.display()
    );
    let refusal = standin_spawn_confined_provider(
        StandinHost::reporting(std::env::consts::OS),
        StandinPolicy::Seatbelt(Path::new(SANDBOX_EXEC)),
        name,
        &absent_binary,
        &base,
        declared,
        &profile_dir,
    )
    .err()
    .expect("(c3) a binary path that is not a file must be refused");
    assert!(
        refusal.contains(name) && refusal.contains(&absent_binary.display().to_string()),
        "(c3) the refusal must name the provider and the path: {refusal}"
    );
    assert!(
        !refusal.contains("must resolve"),
        "(c3) the refusal must come before the binary is resolved: {refusal}"
    );
    eprintln!("{name} (c3) stand-in refusal: {refusal}");
    assert!(
        fs::read_dir(&profile_dir)
            .expect("the profile directory must be readable")
            .next()
            .is_none(),
        "(c3) a refused start must write no profile: {}",
        profile_dir.display()
    );
    assert!(
        !provider_storage_root(name, &base).exists(),
        "(c3) a refused start must create no storage root: {}",
        provider_storage_root(name, &base).display()
    );

    // (d) A right the shared contract does not name is refused unchanged.
    let fixture = tempfile::tempdir().expect("temporary wallet base");
    let base = resolved(fixture.path());
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile_dir = resolved(profile_root.path());
    let mut unnamed = declared.clone();
    unnamed["rights"]
        .as_array_mut()
        .expect("the declared rights must hold a rights list")
        .push(json!({
            "id": "unnamed-right",
            "rules": [r#"(allow file-read* (literal "/private/var/cc-confine-standin"))"#],
        }));
    let refusal = standin_spawn_confined_provider(
        StandinHost::reporting(std::env::consts::OS),
        StandinPolicy::Seatbelt(Path::new(SANDBOX_EXEC)),
        name,
        provider,
        &base,
        &unnamed,
        &profile_dir,
    )
    .err()
    .expect("(d) an unnamed right must be refused");
    assert_eq!(
        refusal,
        format!("{name} declares unnamed-right, which the shared contract does not name"),
        "(d) the refusal must be the one unnamed-id reason"
    );
    eprintln!("{name} (d) stand-in refusal: {refusal}");
    assert!(
        fs::read_dir(&profile_dir)
            .expect("the profile directory must be readable")
            .next()
            .is_none(),
        "(d) a refused profile must create no file: {}",
        profile_dir.display()
    );
    assert!(
        !provider_storage_root(name, &base).exists(),
        "(d) a refused start must create no storage root: {}",
        provider_storage_root(name, &base).display()
    );

    // (e) A parameter the launch does not bind makes sandbox-exec exit before
    // the provider starts.
    let fixture = tempfile::tempdir().expect("temporary wallet base");
    let base = resolved(fixture.path());
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile_dir = resolved(profile_root.path());
    let mut unbound = declared.clone();
    let storage = unbound["rights"]
        .as_array_mut()
        .expect("the declared rights must hold a rights list")
        .iter_mut()
        .find(|entry| entry["id"] == "storage")
        .expect("the declared rights must hold the storage right");
    storage["rules"]
        .as_array_mut()
        .expect("the storage right must hold a rules list")
        .push(json!(
            r#"(allow file-read* (literal (param "STORAGE_UNBOUND")))"#
        ));
    let refusal = standin_spawn_confined_provider(
        StandinHost::reporting(std::env::consts::OS),
        StandinPolicy::Seatbelt(Path::new(SANDBOX_EXEC)),
        name,
        provider,
        &base,
        &unbound,
        &profile_dir,
    )
    .err()
    .expect("(e) a profile the launch cannot apply must be refused");
    assert!(
        refusal.contains("exit status:"),
        "(e) the refusal must name the exit status: {refusal}"
    );
    assert!(
        refusal.contains("invalid data type of path filter"),
        "(e) the refusal must carry sandbox-exec's line: {refusal}"
    );
    assert!(
        !refusal.contains("execvp"),
        "(e) sandbox-exec must refuse the profile before any exec: {refusal}"
    );
    eprintln!("{name} (e) stand-in refusal: {refusal}");
    assert!(
        !provider_storage_root(name, &base).exists(),
        "(e) a refused start must create no storage root: {}",
        provider_storage_root(name, &base).display()
    );

    // (f) An init answer whose status is not ok is refused with the answer.
    let fixture = tempfile::tempdir().expect("temporary wallet base");
    let base = resolved(fixture.path());
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile_dir = resolved(profile_root.path());
    let planted = provider_storage_root(name, &base);
    fs::create_dir_all(storage_parent(name, &base)).expect("prepare the storage parent");
    fs::write(&planted, b"not a directory").expect("plant a regular file at the storage root");
    let refusal = standin_spawn_confined_provider(
        StandinHost::reporting(std::env::consts::OS),
        StandinPolicy::Seatbelt(Path::new(SANDBOX_EXEC)),
        name,
        provider,
        &base,
        declared,
        &profile_dir,
    )
    .err()
    .expect("(f) an init answer that is not ok must be refused");
    assert!(
        refusal.contains("init answered"),
        "(f) the refusal must carry the init answer: {refusal}"
    );
    assert!(
        refusal.contains(r#""status":"error""#),
        "(f) the refusal must carry the answer's status: {refusal}"
    );
    eprintln!("{name} (f) stand-in refusal: {refusal}");
    assert!(
        fs::metadata(&planted)
            .expect("the planted path must still exist")
            .is_file(),
        "(f) the planted storage-root path must stay a regular file: {}",
        planted.display()
    );
}

/// One provider's macOS leg of the C0 journey through the lab stand-in.
///
/// The stand-in starts `provider` from the provider's committed declared-rights
/// file, so `init` answered `ok` and created the provider's storage root inside
/// the profile. One outside write is then refused and creates nothing: for
/// wallet, `init` at an unrelated base whose shared parent exists first is
/// refused by `assert_storage_error`; for did, the granted nickname file points
/// at an unrelated directory, `set_nickname` answers `storage_error` and the
/// outside directory stays empty. The root still answers, one profile sits in
/// `profile_dir`, and `shutdown` answers `ok` and exits 0. The stand-in is test
/// code and not the Runtime.
fn standin_confined_journey(name: &str, provider: &Path, declared: &Value) {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary provider base");
    let base = resolved(fixture.path());
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile_dir = resolved(profile_root.path());
    let mut started = standin_spawn_confined_provider(
        StandinHost::reporting(std::env::consts::OS),
        StandinPolicy::Seatbelt(Path::new(SANDBOX_EXEC)),
        name,
        provider,
        &base,
        declared,
        &profile_dir,
    )
    .unwrap_or_else(|err| panic!("{err}"));

    match name {
        WALLET_PROVIDER => {
            assert!(
                wallet_dir(&base).is_dir(),
                "init must have created the wallet directory inside the profile: {}",
                wallet_dir(&base).display()
            );
            let status = started.send(&json!({ "op": "status" }));
            assert_eq!(
                status["status"], "ok",
                "the started provider must answer status: {status}"
            );
            let outside = tempfile::tempdir().expect("temporary outside directory");
            let outside = resolved(outside.path());
            let outside_wallet = wallet_dir(&outside);
            fs::create_dir_all(storage_parent(WALLET_PROVIDER, &outside))
                .expect("outside parent fixture");
            let denied = started.init(&outside);
            assert_storage_error(&denied);
            assert!(
                !outside_wallet.exists(),
                "a denied write must create nothing outside the wallet root: {}",
                outside_wallet.display()
            );
            let root = started.init(&base);
            assert_eq!(root["status"], "ok", "the root still answers: {root}");
        }
        DID_PROVIDER => {
            let did = started.send(&json!({ "op": "get_did" }));
            assert_eq!(
                did["status"], "ok",
                "the started provider must answer get_did: {did}"
            );
            let did_value = did["data"]["did"]
                .as_str()
                .expect("get_did must name the DID")
                .to_string();
            assert!(
                did_value.starts_with("did:key:"),
                "get_did must answer a did:key DID: {did}"
            );

            let storage = provider_storage_root(DID_PROVIDER, &base);
            let granted = storage.join("nickname.enc");
            let allowed = started.send(&json!({ "op": "set_nickname", "nickname": "Allowed" }));
            assert_eq!(
                allowed["status"], "ok",
                "the granted write must succeed: {allowed}"
            );
            assert!(
                granted.is_file(),
                "the granted nickname file must exist: {}",
                granted.display()
            );

            let outside = tempfile::tempdir().expect("temporary outside directory");
            let outside = resolved(outside.path());
            let target = outside.join("nickname.enc");
            fs::remove_file(&granted).expect("remove the granted nickname file");
            std::os::unix::fs::symlink(&target, &granted).expect("point the granted path outside");
            let denied = started.send(&json!({ "op": "set_nickname", "nickname": "Outside" }));
            assert_eq!(
                denied["status"], "error",
                "the outside write must be denied: {denied}"
            );
            assert_eq!(denied["code"], "storage_error");
            assert!(
                denied["message"].as_str().is_some_and(
                    |message| message.starts_with("did-provider: failed to save nickname:")
                ),
                "the denial must name the failed write: {denied}"
            );
            assert!(
                !target.exists(),
                "the outside write must create nothing: {}",
                target.display()
            );
            assert_eq!(
                fs::read_dir(&outside)
                    .expect("the outside directory must be readable")
                    .count(),
                0,
                "the outside directory must stay empty: {}",
                outside.display()
            );
            fs::remove_file(&granted).expect("remove the outside symlink");

            let after = started.send(&json!({ "op": "get_did" }));
            assert_eq!(
                after["status"], "ok",
                "the provider must stay in service: {after}"
            );
        }
        other => panic!("the journey names no provider whose leg it knows: {other}"),
    }

    assert_eq!(
        fs::read_dir(&profile_dir)
            .expect("the profile directory must be readable")
            .count(),
        1,
        "the launcher must write one profile into the directory it is given: {}",
        profile_dir.display()
    );
    started.shutdown();
}

/// M1 check C0, one end-to-end journey: did first, then wallet, each starts
/// confined through the lab stand-in on macOS, or the stand-in refuses the
/// host with its own reason and starts no provider.
///
/// Each provider passes its own committed declared-rights file and its own
/// binary. `standin_confined_journey` runs the macOS leg first, so a stand-in
/// that starts a provider bare fails at the outside write. Then
/// `standin_refusals_for` runs every host and process refusal, including the
/// three simulated Linux host reports that each name one missing primitive, a
/// simulated `macos` host that reports Landlock unavailable, and the simulated
/// Linux host that reports nothing missing; a reported missing primitive is
/// refused whatever its OS. Every refused case returns no provider, writes no
/// profile and creates no storage root. The did
/// binary comes from `did_provider_binary`; the wallet binary comes from
/// `CARGO_BIN_EXE_wallet-provider`. Linux stays a design plus a simulated
/// refusal: nothing here probes a real kernel or claims Linux enforcement. The
/// stand-in is test code and not the Runtime.
///
/// Falsifier: WP112 starts the binary bare in the host refusal, so did's case
/// (a) returns Started; WP114 (and the host rows' planted fallbacks) start the
/// binary without the generator and `sandbox-exec`, so the macOS leg succeeds
/// at the outside write; WP113 starts it bare after a failed `init`, so did's
/// case (e) returns Started; WP115 ignores the writer's refusal and starts
/// under the committed `confine.sb`, so did's case (d) returns Started instead
/// of its reason. WP118 removes the tool check, so did's case (c2) is Started;
/// WP119 removes the binary-file check, so did's case (c3) panics in
/// `resolved`; WP120 returns `Ok(provider)` for an `init` answer that is not
/// `ok`, so did's case (f) is Started. WP125 makes the absent-tool check never
/// fire, so did's case (c) reads the wrong-tool reason and lacks `is absent`;
/// WP126 drops the OS from the wrong-tool reason, so did's case (c2) lacks `on
/// macos`. WP131 starts the binary bare on a simulated Linux host that reports
/// a primitive unavailable, so did's Landlock row returns Started. WP132
/// returns one fixed reason that names no primitive, so did's Landlock row
/// loses the design's words. WP135 moves the `DECLARED_CONFINED_OS` lookup
/// back above the missing-primitive check, so did's new `macos` Landlock row
/// returns Started; WP136 prefixes the missing-primitive reason with
/// `linux has no confinement design; `, so did's Landlock row carries the
/// forbidden words; WP137 drops the `{name} start on {os} is refused: `
/// prefix from the final `Err`, so did's first host row, plan9, lacks it.
#[test]
fn standin_c0_journey_starts_confined_or_refuses_each_unconfinable_host() {
    let providers: [(&str, &Path, Value); 2] = [
        (
            DID_PROVIDER,
            did_provider_binary(),
            read_declared_rights(DID_PROVIDER, &declared_rights_path(DID_PROVIDER))
                .unwrap_or_else(|err| panic!("{err}")),
        ),
        (
            WALLET_PROVIDER,
            Path::new(PROVIDER_BINARY),
            read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
                .unwrap_or_else(|err| panic!("{err}")),
        ),
    ];
    for (name, provider, declared) in &providers {
        standin_confined_journey(name, provider, declared);
        standin_refusals_for(name, provider, declared);
    }
}

/// The class one suite case must answer with, carried by the entry the suite
/// pushes for that case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuiteClass {
    /// A permitted call, which must answer `ok`.
    Permitted,
    /// A denied call, which the profile must refuse.
    Denied,
}

/// One suite case's answer: `Ok`, or the refusal answer's `status`, its `code`
/// and the stable start of its `message`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SuiteOutcome {
    Ok,
    Refused {
        status: String,
        code: String,
        message: String,
    },
}

/// One named case of the stand-in suite, in the order the suite runs it, with
/// the class the suite expects of it and the answer it gave.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SuiteEntry {
    case: &'static str,
    class: SuiteClass,
    outcome: SuiteOutcome,
}

/// The suite's cases in the order the suite runs them, with the class each
/// case must answer with. `assert_suite_outcomes` requires every record's
/// names and classes to equal this list, so a case that drops out or changes
/// class fails with the case named. `outside_write_cases` holds the four
/// outside bases and their names, and this list repeats those names as the
/// expectation each record is checked against.
const SUITE_CASES: [(&str, SuiteClass); 9] = [
    ("init at the wallet root", SuiteClass::Permitted),
    ("status", SuiteClass::Permitted),
    ("create_managed_account", SuiteClass::Permitted),
    ("an unrelated base", SuiteClass::Denied),
    ("<root>/sibling", SuiteClass::Denied),
    ("<root>/ElastOS/SystemServices/Sibling", SuiteClass::Denied),
    (FRESH_OUTSIDE_CASE, SuiteClass::Denied),
    ("planted key beneath STORAGE_PARENT", SuiteClass::Denied),
    ("status after the denied cases", SuiteClass::Permitted),
];

/// The did suite's cases in the order the suite runs them, with the class each
/// case must answer with. The permitted cases are from
/// `confined_provider_serves_did_operations_under_its_root`; the outside
/// writes are both targets of `outside_write_denied`, the unrelated directory
/// and the sibling of `did/` under the same base; the planted read is the read
/// half of `planted_file_beneath_storage_parent_is_neither_read_nor_written`;
/// and the final `get_did` is the service check both tests make after a
/// refusal.
///
/// The permitted cases come first, as `DID_PERMITTED_CASES` says, so a caller
/// that runs only them judges its record against the same leading entries
/// instead of a second case list.
const DID_SUITE_CASES: [(&str, SuiteClass); 10] = [
    // `confined_provider_serves_did_operations_under_its_root` (did's
    // tests/confine.rs:407) runs these six operations.
    ("init at the did root", SuiteClass::Permitted),
    ("get_did", SuiteClass::Permitted),
    ("resolve", SuiteClass::Permitted),
    ("set_nickname", SuiteClass::Permitted),
    ("get_nickname", SuiteClass::Permitted),
    ("get_persona_did", SuiteClass::Permitted),
    // The first target of `outside_write_denied` (did's tests/confine.rs:557).
    (
        "outside write through the granted nickname file",
        SuiteClass::Denied,
    ),
    // The second target of `outside_write_denied`
    // (did's tests/confine.rs:576): a sibling of `did/` under the same base,
    // which the test creates before it links. Only this target separates a
    // write grant on `STORAGE_ROOT` from one on `STORAGE_PARENT`.
    (
        "outside write to a sibling of the did root",
        SuiteClass::Denied,
    ),
    // The read half of
    // `planted_file_beneath_storage_parent_is_neither_read_nor_written`
    // (did's tests/confine.rs:703).
    (
        "planted nickname beneath STORAGE_PARENT",
        SuiteClass::Denied,
    ),
    // The service check that both tests make after a refusal.
    ("get_did after the denied cases", SuiteClass::Permitted),
];

/// How many leading entries of `DID_SUITE_CASES` are the permitted operations,
/// which is the part `did_standin_permitted_operations` records. The denied
/// cases follow them, and the trailing service check is not one of these
/// operations, so it is not counted. Only the Linux journey slices that prefix,
/// so the constant is compiled where that journey is.
#[cfg(target_os = "linux")]
const DID_PERMITTED_CASES: usize = 6;

/// The stable start of a refusal message: its text before the first path
/// separator, trimmed. Each provider runs on its own temporary root, so the
/// record keeps no temporary path and two records compare equal.
fn stable_message_start(message: &str) -> String {
    message
        .split('/')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// The suite entry for one answer, so a permitted call and a refusal share one
/// record shape. The refusal keeps the answer's `status` and its `code` through
/// the one field reader, so two refusals that differ only in `code` do not
/// compare equal.
fn suite_entry(case: &'static str, class: SuiteClass, answer: &Value) -> SuiteEntry {
    let outcome = if answer["status"] == "ok" {
        SuiteOutcome::Ok
    } else {
        SuiteOutcome::Refused {
            status: refusal_field(answer.get("status")),
            code: refusal_field(answer.get("code")),
            message: stable_message_start(answer["message"].as_str().unwrap_or_default()),
        }
    };
    SuiteEntry {
        case,
        class,
        outcome,
    }
}

/// The suite entry for one wallet answer: `Ok` only when the bound result is
/// `Ok`, and the outer answer's `status` beside the inner result's `code` and
/// stable message start for an error. The provider answers every
/// `wallet_contract` request with an outer `ok` and puts the result in
/// `data.result`, so the outer status proves nothing about the effect and the
/// inner `code` is the refusal a permitted case must not hide. An outer answer
/// that is not `ok` or that does not bind to its request fails the test,
/// because the one wallet request path always answers a bound response.
fn wallet_suite_entry(
    label: &str,
    case: &'static str,
    class: SuiteClass,
    request: &WalletProviderRequestV2,
    answer: &Value,
) -> SuiteEntry {
    assert_eq!(
        answer["status"], "ok",
        "{label}: {case}: wallet_contract must answer through the protocol: {answer}"
    );
    let data = answer.get("data").unwrap_or_else(|| {
        panic!("{label}: {case}: wallet_contract answer must carry a bound response: {answer}")
    });
    let bytes = serde_json::to_vec(data)
        .unwrap_or_else(|err| panic!("{label}: {case}: the bound response must serialize: {err}"));
    let result = WalletProviderResponseV2::decode_for_request(&bytes, request)
        .unwrap_or_else(|err| {
            panic!("{label}: {case}: provider response must bind to its request: {err}")
        })
        .result;
    let outcome = match result {
        WalletResultV2::Ok { .. } => SuiteOutcome::Ok,
        WalletResultV2::Error { code, message } => SuiteOutcome::Refused {
            status: refusal_field(answer.get("status")),
            code,
            message: stable_message_start(&message),
        },
    };
    SuiteEntry {
        case,
        class,
        outcome,
    }
}

/// The one stand-in suite: the permitted wallet calls of
/// `confined_provider_serves_wallet_operations_under_its_root` and the denied
/// cases of `confined_outside_write_is_denied` and
/// `planted_key_beneath_storage_parent_is_not_read`, run against one started
/// provider and one root. It returns one entry per case in a fixed order: `init`
/// at the root, `status`, the first wallet call of the permitted test (which
/// creates a managed account and writes its key material under the wallet
/// root), the four outside writes of the one shared case list, the planted key
/// read beneath `STORAGE_PARENT` on its own base, and the `status` after the
/// denied cases, which shows the provider stays in service. The denied cases
/// run between the permitted calls because `init` resets the root before it
/// refuses. Each entry carries the class of the case it was pushed for, so no
/// caller reads the class from the entry's position. A wallet call is `Ok` only
/// when its bound result is `Ok`, so an inner storage or validation refusal
/// cannot read as a permitted case. A refusal keeps the answer's `status`, its
/// `code` and the stable start of its `message`, so two records from different
/// roots compare equal. Both callers drive one started provider through this
/// function; it starts none. `label` names the provider, the `B3 journey` and
/// the start this call drives, and every refusal this function raises starts
/// with it, so a failed step names the provider and the step.
fn wallet_standin_suite(
    provider: &mut ConfinedProvider,
    root: &Path,
    label: &str,
) -> Vec<SuiteEntry> {
    let mut record = Vec::new();

    let init = provider.init(root);
    record.push(suite_entry(
        "init at the wallet root",
        SuiteClass::Permitted,
        &init,
    ));

    let status = provider.send(&json!({ "op": "status" }));
    record.push(suite_entry("status", SuiteClass::Permitted, &status));

    let (request, answer) =
        provider.wallet_request_and_answer(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".to_string(),
            label: Some("Confined".to_string()),
            create_new: false,
        });
    record.push(wallet_suite_entry(
        label,
        "create_managed_account",
        SuiteClass::Permitted,
        &request,
        &answer,
    ));

    let outside = tempfile::tempdir().unwrap_or_else(|err| {
        panic!("{label}: the temporary outside directory must be created: {err}")
    });
    let outside = resolved(outside.path());
    for (case, denied_base) in &outside_write_cases(root, &outside) {
        prepare_outside_write_case(case, denied_base);
        let denied = provider.init(denied_base);
        record.push(suite_entry(case, SuiteClass::Denied, &denied));
    }

    // Its own base beneath `STORAGE_PARENT`, taken from the canonical bindings
    // so the fixture and the launch keep one source for that path, and so the
    // planted read starts without the refused `init` of the outside-write
    // sibling case.
    let planted = storage_parent(WALLET_PROVIDER, root).join("Planted");
    let planted_wallet = wallet_dir(&planted);
    plant_storage_key(&planted_wallet);
    let denied = provider.init(&planted);
    record.push(suite_entry(
        "planted key beneath STORAGE_PARENT",
        SuiteClass::Denied,
        &denied,
    ));

    let status = provider.send(&json!({ "op": "status" }));
    record.push(suite_entry(
        "status after the denied cases",
        SuiteClass::Permitted,
        &status,
    ));

    record
}

/// The permitted did operations on one started provider and one root, using the
/// record type and judgement of `wallet_standin_suite`, and the did suite's
/// first half.
///
/// It returns one entry per case of the first `DID_PERMITTED_CASES` entries of
/// `DID_SUITE_CASES`, in that order: `init` with did's fixture device key,
/// `get_did`, `resolve` of that DID, `set_nickname`, `get_nickname` returning
/// the stored nickname, and `get_persona_did`. `get_did` must answer a
/// `did:key:` value and `resolve` must echo that DID as its document id, so a
/// provider that answers neither call cannot pass on an `ok` status alone.
/// `set_nickname`, `get_nickname` and `get_persona_did` need `init`'s device
/// key and the nickname file it wrote, so this helper is kept whole: a caller
/// that wants only the calls a filter cannot change drives all six, and the
/// calls under `STORAGE_ROOT` that need file state stay in the one helper.
///
/// Every refusal this function raises starts with `label`, which names the
/// provider, the journey and the start this call drives. It starts no provider.
fn did_standin_permitted_operations(
    provider: &mut ConfinedProvider,
    root: &Path,
    label: &str,
) -> Vec<SuiteEntry> {
    let mut record = Vec::new();

    let init = provider.send(&json!({
        "op": "init",
        "config": provider_init_config(DID_PROVIDER, root),
    }));
    record.push(suite_entry(
        "init at the did root",
        SuiteClass::Permitted,
        &init,
    ));

    let did_data = provider.send(&json!({ "op": "get_did" }));
    let did = did_data["data"]["did"]
        .as_str()
        .unwrap_or_else(|| panic!("{label}: get_did must name the DID: {did_data}"))
        .to_string();
    assert!(
        did.starts_with("did:key:"),
        "{label}: get_did must answer a did:key DID: {did}"
    );
    record.push(suite_entry("get_did", SuiteClass::Permitted, &did_data));

    let resolved = provider.send(&json!({ "op": "resolve", "did": did }));
    assert_eq!(
        resolved["data"]["document"]["id"], did,
        "{label}: resolve must answer the document of the DID it was asked about: {resolved}"
    );
    record.push(suite_entry("resolve", SuiteClass::Permitted, &resolved));

    let set = provider.send(&json!({ "op": "set_nickname", "nickname": "Confined" }));
    record.push(suite_entry("set_nickname", SuiteClass::Permitted, &set));

    let nickname = provider.send(&json!({ "op": "get_nickname" }));
    assert_eq!(
        nickname["data"]["nickname"], "Confined",
        "{label}: the confined provider must return the stored nickname: {nickname}"
    );
    record.push(suite_entry(
        "get_nickname",
        SuiteClass::Permitted,
        &nickname,
    ));

    let persona = provider.send(&json!({ "op": "get_persona_did", "name": "fixture" }));
    assert_eq!(
        persona["data"]["owner_did"], did,
        "{label}: the persona must belong to the provider's DID: {persona}"
    );
    record.push(suite_entry(
        "get_persona_did",
        SuiteClass::Permitted,
        &persona,
    ));

    record
}

/// The did suite on one started provider and one root, using the record type
/// and judgement of `wallet_standin_suite`. It returns one entry per case of
/// `DID_SUITE_CASES` in its order: the six permitted operations of
/// `did_standin_permitted_operations`; the outside writes of both
/// `outside_write_denied` targets, the first pointing the granted nickname file
/// at an unrelated directory and the second at a sibling of `did/` under the
/// same base; the planted read of
/// `planted_file_beneath_storage_parent_is_neither_read_nor_written`, which
/// points the granted file at its own encrypted copy beneath `STORAGE_PARENT`;
/// and `get_did` after the denied cases. Each entry carries the class of the
/// case it was pushed for. A refusal keeps the answer's `status`, its `code`
/// and the stable start of its `message`, so two records from different roots
/// compare equal. Both callers drive one started provider through this
/// function; it starts none. `label` names the provider, the `B3 journey` and
/// the start this call drives, and every refusal this function raises starts
/// with it, so a failed step names the provider and the step.
fn did_standin_suite(provider: &mut ConfinedProvider, root: &Path, label: &str) -> Vec<SuiteEntry> {
    let mut record = did_standin_permitted_operations(provider, root, label);

    // The first `outside_write_denied` target: an unrelated directory. The
    // granted nickname file is a symlink to that target, so the profile must
    // refuse the write and the target directory must stay empty.
    let granted = provider_storage_root(DID_PROVIDER, root).join("nickname.enc");
    assert!(
        granted.is_file(),
        "{label}: set_nickname must have written the granted file: {}",
        granted.display()
    );
    let outside = tempfile::tempdir().unwrap_or_else(|err| {
        panic!("{label}: the temporary outside directory must be created: {err}")
    });
    let outside = resolved(outside.path());
    let target = outside.join("nickname.enc");
    fs::remove_file(&granted)
        .unwrap_or_else(|err| panic!("{label}: the granted nickname file must be removed: {err}"));
    std::os::unix::fs::symlink(&target, &granted)
        .unwrap_or_else(|err| panic!("{label}: the granted path must point outside: {err}"));
    let denied = provider.send(&json!({ "op": "set_nickname", "nickname": "Outside" }));
    assert_eq!(
        denied["status"], "error",
        "{label}: the outside write must be denied: {denied}"
    );
    assert_eq!(
        denied["code"], "storage_error",
        "{label}: the outside write must refuse with storage_error: {denied}"
    );
    assert!(
        denied["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("did-provider: failed to save nickname:")),
        "{label}: the denial must name the failed write: {denied}"
    );
    assert!(
        !target.exists(),
        "{label}: nothing may land outside the storage root: {}",
        target.display()
    );
    assert_eq!(
        fs::read_dir(&outside)
            .unwrap_or_else(|err| panic!("{label}: the outside directory must be readable: {err}"))
            .count(),
        0,
        "{label}: the outside directory must stay empty: {}",
        outside.display()
    );
    record.push(suite_entry(
        "outside write through the granted nickname file",
        SuiteClass::Denied,
        &denied,
    ));
    fs::remove_file(&granted)
        .unwrap_or_else(|err| panic!("{label}: the outside symlink must be removed: {err}"));

    // The second `outside_write_denied` target: a sibling of `did/` under the
    // same base. The test creates it before it links, so the refusal comes from
    // the profile and not from a missing path, and only this target separates a
    // write grant on `STORAGE_ROOT` from one on `STORAGE_PARENT`.
    let restored = provider.send(&json!({ "op": "set_nickname", "nickname": "Sibling source" }));
    assert_eq!(
        restored["status"], "ok",
        "{label}: the granted write must recover the file: {restored}"
    );
    let sibling = storage_parent(DID_PROVIDER, root).join("sibling");
    fs::create_dir_all(&sibling).unwrap_or_else(|err| {
        panic!("{label}: the sibling directory under the same base must be created: {err}")
    });
    let target = sibling.join("nickname.enc");
    fs::remove_file(&granted)
        .unwrap_or_else(|err| panic!("{label}: the granted nickname file must be removed: {err}"));
    std::os::unix::fs::symlink(&target, &granted)
        .unwrap_or_else(|err| panic!("{label}: the granted path must point at its sibling: {err}"));
    let denied = provider.send(&json!({ "op": "set_nickname", "nickname": "Sibling" }));
    assert_eq!(
        denied["status"], "error",
        "{label}: the sibling write must be denied: {denied}"
    );
    assert_eq!(
        denied["code"], "storage_error",
        "{label}: the sibling write must refuse with storage_error: {denied}"
    );
    assert!(
        denied["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("did-provider: failed to save nickname:")),
        "{label}: the denial must name the failed write: {denied}"
    );
    assert!(
        !target.exists(),
        "{label}: nothing may land beside the storage root: {}",
        target.display()
    );
    assert_eq!(
        fs::read_dir(&sibling)
            .unwrap_or_else(|err| panic!("{label}: the sibling directory must be readable: {err}"))
            .count(),
        0,
        "{label}: the sibling directory must stay empty: {}",
        sibling.display()
    );
    record.push(suite_entry(
        "outside write to a sibling of the did root",
        SuiteClass::Denied,
        &denied,
    ));
    fs::remove_file(&granted)
        .unwrap_or_else(|err| panic!("{label}: the sibling symlink must be removed: {err}"));

    // The read half of `planted_file_beneath_storage_parent_is_neither_read_nor_written`:
    // the provider's own encrypted nickname is copied beneath STORAGE_PARENT,
    // and the granted path points at that copy. `init` must refuse the read.
    let restored = provider.send(&json!({ "op": "set_nickname", "nickname": "Planted source" }));
    assert_eq!(
        restored["status"], "ok",
        "{label}: the granted write must recover the file: {restored}"
    );
    let planted = storage_parent(DID_PROVIDER, root)
        .join("sibling")
        .join("did");
    fs::create_dir_all(&planted).unwrap_or_else(|err| {
        panic!("{label}: the planted directory beneath STORAGE_PARENT must be created: {err}")
    });
    let planted_path = planted.join("nickname.enc");
    fs::copy(&granted, &planted_path).unwrap_or_else(|err| {
        panic!("{label}: the encrypted nickname must be copied beneath the parent: {err}")
    });
    let planted_bytes = fs::read(&planted_path)
        .unwrap_or_else(|err| panic!("{label}: the planted file must be readable: {err}"));
    fs::remove_file(&granted)
        .unwrap_or_else(|err| panic!("{label}: the granted nickname file must be removed: {err}"));
    std::os::unix::fs::symlink(&planted_path, &granted)
        .unwrap_or_else(|err| panic!("{label}: the granted path must point at the plant: {err}"));
    let denied = provider.send(&json!({
        "op": "init",
        "config": provider_init_config(DID_PROVIDER, root),
    }));
    assert_eq!(
        denied["status"], "error",
        "{label}: the planted read must be denied: {denied}"
    );
    assert_eq!(
        denied["code"], "storage_error",
        "{label}: the planted read must refuse with storage_error: {denied}"
    );
    assert!(
        denied["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("did-provider: failed to read nickname:")),
        "{label}: the refusal must reach the nickname loader: {denied}"
    );
    assert_eq!(
        fs::read(&planted_path)
            .unwrap_or_else(|err| panic!("{label}: the planted file must stay readable: {err}")),
        planted_bytes,
        "{label}: the planted file must stay unchanged"
    );
    record.push(suite_entry(
        "planted nickname beneath STORAGE_PARENT",
        SuiteClass::Denied,
        &denied,
    ));
    fs::remove_file(&granted)
        .unwrap_or_else(|err| panic!("{label}: the planted symlink must be removed: {err}"));

    let after = provider.send(&json!({ "op": "get_did" }));
    record.push(suite_entry(
        "get_did after the denied cases",
        SuiteClass::Permitted,
        &after,
    ));

    record
}

/// Requires the record to hold one entry per case of `cases`, in that order,
/// with that case's name and class, and judges each entry's own class: a
/// permitted case answers `ok` and a denied case is refused. A case that drops
/// out, arrives in another order or changes class fails with the case named.
fn assert_suite_outcomes(label: &str, record: &[SuiteEntry], cases: &[(&str, SuiteClass)]) {
    for (index, (case, class)) in cases.iter().enumerate() {
        let Some(entry) = record.get(index) else {
            panic!(
                "{label} suite must record case {case:?} as {class:?}: the record holds {} entries",
                record.len()
            );
        };
        assert_eq!(
            (entry.case, entry.class),
            (*case, *class),
            "{label} must record case {case:?} as {class:?}"
        );
        match entry.class {
            SuiteClass::Permitted => assert!(
                entry.outcome == SuiteOutcome::Ok,
                "{label} must permit case {:?}: {:?}",
                entry.case,
                entry.outcome
            ),
            SuiteClass::Denied => assert!(
                matches!(entry.outcome, SuiteOutcome::Refused { .. }),
                "{label} must refuse case {:?}: {:?}",
                entry.case,
                entry.outcome
            ),
        }
    }
    assert_eq!(
        record.len(),
        cases.len(),
        "{label} suite must record no case beyond {:?}",
        cases.last().map(|(case, _)| *case)
    );
}

/// Requires the stand-in record of `name` to equal its committed-profile
/// record entry by entry, and names the provider, the step and the first case
/// that differs. The B3 journey compares both providers through this one
/// function, so did and wallet apply one comparison rule (P10).
fn assert_standin_matches_oracle(
    name: &str,
    oracle_record: &[SuiteEntry],
    standin_record: &[SuiteEntry],
) {
    assert_eq!(
        oracle_record.len(),
        standin_record.len(),
        "{name} stand-in start must record as many cases as the committed confine.sb: \
         committed {}, stand-in {}",
        oracle_record.len(),
        standin_record.len()
    );
    for (oracle_entry, standin_entry) in oracle_record.iter().zip(standin_record) {
        assert_eq!(
            oracle_entry, standin_entry,
            "{name} stand-in start differs from the committed confine.sb on case {:?}: \
             committed {:?}, stand-in {:?}",
            oracle_entry.case, oracle_entry.outcome, standin_entry.outcome
        );
    }
}

/// One provider's place in the B3 journey: the name the stand-in serves, the
/// binary it starts, the one suite that drives that provider, and the cases
/// that suite must record.
struct B3Provider {
    name: &'static str,
    binary: &'static Path,
    suite: fn(&mut ConfinedProvider, &Path, &str) -> Vec<SuiteEntry>,
    cases: &'static [(&'static str, SuiteClass)],
}

/// Starts `name`'s binary under that provider's committed `confine.sb` on
/// `root`, through the one launch builder and the provider's canonical
/// bindings. The B3 journey takes this start as the record the committed
/// oracle itself produces.
fn standin_oracle_start(name: &str, binary: &Path, root: &Path) -> ConfinedProvider {
    let bindings = canonical_bindings(name, root, binary);
    create_shared_ancestors(&bindings);
    let paths: Vec<(&str, &Path)> = bindings
        .iter()
        .map(|(binding, path)| (*binding, path.as_path()))
        .collect();
    ConfinedProvider::start_under(&confine_oracle_path(name), &paths, binary)
}

/// One provider's leg of the B3 journey, from its committed declared-rights
/// file to its permitted and denied suite record.
///
/// The leg reads the provider's committed declared-rights file and its
/// committed `confine.sb`, then starts the binary through the lab stand-in into
/// a fresh profile directory. It reads the one file the stand-in wrote there,
/// which is the file the launch used, and requires that file to pass
/// `check_profile_contract`, to pass `check_declared_rights` against the
/// declared rights it was generated from, and to equal the committed oracle
/// through `compare_profile_to_its_oracle`. The provider's suite then drives
/// the stand-in start and a second start under the committed file, each on its
/// own fresh root; both records must hold every case of `provider.cases` in
/// order with its class, and the two records must agree entry by entry. Each
/// suite step's failure starts with the provider, `B3 journey` and the start it
/// drives. A refusal of `standin_oracle_start`'s own launch comes from
/// `ConfinedProvider::start_under`, which this journey does not change. The
/// stand-in is test code and not the Runtime.
fn standin_b3_journey(provider: &B3Provider) {
    let name = provider.name;
    let declared = read_declared_rights(name, &declared_rights_path(name))
        .unwrap_or_else(|err| panic!("{name} B3 journey: {err}"));
    let committed = read_allow_rule_profile(name, &confine_oracle_path(name))
        .unwrap_or_else(|err| panic!("{name} B3 journey: {err}"));

    let standin_fixture = tempfile::tempdir().expect("temporary provider root");
    let standin_root = resolved(standin_fixture.path());
    let profile_fixture = tempfile::tempdir().expect("temporary profile root");
    let profile_dir = resolved(profile_fixture.path());
    let mut standin = standin_spawn_confined_provider(
        StandinHost::reporting(std::env::consts::OS),
        StandinPolicy::Seatbelt(Path::new(SANDBOX_EXEC)),
        name,
        provider.binary,
        &standin_root,
        &declared,
        &profile_dir,
    )
    .unwrap_or_else(|err| panic!("{name} B3 journey: the stand-in start is refused: {err}"));

    let launched = read_launched_profile(name, &profile_dir)
        .unwrap_or_else(|err| panic!("{name} B3 journey: {err}"));
    check_profile_contract(name, &launched).unwrap_or_else(|err| {
        panic!("{name} B3 journey: the launched profile must pass the contract check: {err}")
    });
    check_declared_rights(name, &launched, &declared).unwrap_or_else(|err| {
        panic!("{name} B3 journey: the launched profile must trace to its declared rights: {err}")
    });
    compare_profile_to_its_oracle(name, &launched, &committed).unwrap_or_else(|err| {
        panic!("{name} B3 journey: the launched profile and its oracle disagree: {err}")
    });

    let standin_label = format!("{name} B3 journey (the stand-in start)");
    let standin_record = (provider.suite)(&mut standin, &standin_root, &standin_label);

    let oracle_fixture = tempfile::tempdir().expect("temporary provider root");
    let oracle_root = resolved(oracle_fixture.path());
    let mut oracle = standin_oracle_start(name, provider.binary, &oracle_root);
    let oracle_label = format!("{name} B3 journey (the start under the committed confine.sb)");
    let oracle_record = (provider.suite)(&mut oracle, &oracle_root, &oracle_label);

    standin.shutdown();
    oracle.shutdown();

    assert_suite_outcomes(
        &format!("{name}'s committed confine.sb"),
        &oracle_record,
        provider.cases,
    );
    assert_suite_outcomes(
        &format!("{name}'s stand-in launched profile"),
        &standin_record,
        provider.cases,
    );
    assert_standin_matches_oracle(name, &oracle_record, &standin_record);
}

/// M1 check B3, one end-to-end journey for each file profile: did first, then
/// wallet. Each provider starts from its committed declared-rights file
/// through the lab stand-in into a fresh profile directory, and the one file
/// the stand-in wrote there is the file the launch used. That file must pass
/// the two contract checks and equal the provider's committed `confine.sb`
/// through the one comparison body `compare_profile_to_its_oracle`
/// (`standin_b3_journey`). The same provider's permitted and denied suite then
/// runs on the stand-in start and on a start under the committed file, and
/// both records must hold their provider's cases in order and agree entry by
/// entry. A stand-in that changes the launched profile after the writer, in a
/// way the suite does not exercise, fails at the launched-file checks, and a
/// deny form there fails only at the oracle comparison. The stand-in is test
/// code and not the Runtime.
///
/// Falsifier: WP116 binds the stand-in's `STORAGE_ROOT` to the base instead of
/// the provider's storage root; the widened grant permits did's sibling write
/// beneath the base, so did's suite step fails at the sibling write where the
/// record must refuse it. WP121 removes the planted-key push, so wallet's
/// stand-in record holds eight entries where `SUITE_CASES` holds nine and the
/// journey fails naming the missing case. WP124 makes the stand-in use wallet's
/// root layout for did, so did's start is refused at its first `init`. WP127
/// appends a write grant on `STORAGE_PARENT` to did's launched profile, so the
/// journey fails at did's launched-profile check, where `check_declared_rights`
/// refuses the appended allow form because no declared right names it. WP133
/// appends one allow form the suite does not exercise to the launched file, so
/// the journey fails at that same check, where `check_declared_rights` refuses
/// the appended allow form because no declared right names it. WP134 removes
/// `(deny network*)` from the launched file, so the journey fails at that same
/// check, where `check_profile_contract` refuses the profile without its
/// explicit network denial. WP138 appends
/// `(deny file-write* (literal "/private/var/cc-confine-launched"))` to the
/// launched file; only `compare_profile_to_its_oracle` catches it, because the
/// head keeps its order, the contract checks read only allow forms and no suite
/// case reads that literal, so the journey fails at its launched profile and
/// its oracle disagree panic, which names the planted form.
#[test]
fn standin_b3_journey_matches_the_oracle_from_declared_rights_to_the_suite() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let providers = [
        B3Provider {
            name: DID_PROVIDER,
            binary: did_provider_binary(),
            suite: did_standin_suite,
            cases: &DID_SUITE_CASES,
        },
        B3Provider {
            name: WALLET_PROVIDER,
            binary: Path::new(PROVIDER_BINARY),
            suite: wallet_standin_suite,
            cases: &SUITE_CASES,
        },
    ];
    for provider in &providers {
        standin_b3_journey(provider);
    }
}

/// The stand-in start uses the generated profile, not the committed file.
///
/// A declared-rights copy whose `storage` right keeps only its
/// `STORAGE_PARENT` read drops the wallet-root write rule. The stand-in then
/// writes a generated profile without that write, and the provider's `init`
/// cannot create the wallet root, so the start is Refused with the `init`
/// answer and no wallet directory exists after. This holds only when the launch
/// uses the generated profile.
///
/// Falsifier: WP117 writes the generated profile but starts under the committed
/// `confine.sb`; the start is then Started because the committed write rule
/// creates the wallet root, and this test fails.
#[test]
fn standin_start_runs_under_the_generated_profile_not_the_committed_file() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let declared_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/confine/declared-rights.json");
    let mut declared = read_declared_rights("wallet-provider", &declared_path)
        .unwrap_or_else(|err| panic!("{err}"));
    let storage = declared["rights"]
        .as_array_mut()
        .expect("the declared rights must hold a rights list")
        .iter_mut()
        .find(|entry| entry["id"] == "storage")
        .expect("the declared rights must hold the storage right");
    storage["rules"] = json!([r#"(allow file-read* (literal (param "STORAGE_PARENT")))"#]);

    let fixture = tempfile::tempdir().expect("temporary wallet root");
    let base = resolved(fixture.path());
    let profile_fixture = tempfile::tempdir().expect("temporary profile root");
    let profile_dir = resolved(profile_fixture.path());
    let refusal = standin_spawn_confined_provider(
        StandinHost::reporting(std::env::consts::OS),
        StandinPolicy::Seatbelt(Path::new(SANDBOX_EXEC)),
        "wallet-provider",
        Path::new(PROVIDER_BINARY),
        &base,
        &declared,
        &profile_dir,
    )
    .err()
    .expect(
        "the stand-in must refuse a start whose generated profile cannot create the wallet root",
    );
    assert!(
        refusal.contains("storage_error"),
        "the refusal must carry the init storage refusal: {refusal}"
    );
    assert!(
        !wallet_dir(&base).exists(),
        "a refused start must create no wallet directory: {}",
        wallet_dir(&base).display()
    );
}

/// The suite records a wallet call as `Ok` only when its bound result is `Ok`.
///
/// `handle_wallet_contract` answers every `wallet_contract` request with an
/// outer `ok` and puts the real result in `data.result`, so an inner refusal
/// must not read as a permitted case. The test starts the provider under the
/// committed profile, `init`s the root, sends `create_managed_account` with a
/// chain namespace the wallet refuses, and requires `wallet_suite_entry` to
/// record `Refused` with the outer `ok` status beside the inner
/// `invalid_request` code and its reason. Both callers of the suite read this
/// one entry function.
///
/// Falsifier: WP123 records every bound result as `Ok` in `wallet_suite_entry`;
/// this test fails because the entry reads `Ok`.
#[test]
fn wallet_suite_entry_records_an_inner_refusal_as_refused() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let root = tempfile::tempdir().expect("temporary wallet root");
    let root = resolved(root.path());
    let mut provider = ConfinedProvider::start(&root);
    let init = provider.init(&root);
    assert_eq!(init["status"], "ok", "confined Init must succeed: {init}");

    let (request, answer) =
        provider.wallet_request_and_answer(WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "bogus".to_string(),
            label: Some("Refused".to_string()),
            create_new: false,
        });
    assert_eq!(
        answer["status"], "ok",
        "the outer answer stays ok for an inner refusal: {answer}"
    );
    let entry = wallet_suite_entry(
        "wallet_suite_entry test",
        "create_managed_account",
        SuiteClass::Denied,
        &request,
        &answer,
    );
    assert_eq!(
        entry.outcome,
        SuiteOutcome::Refused {
            status: "ok".to_string(),
            code: "invalid_request".to_string(),
            message: "managed wallets support EVM chains and Bitcoin mainnet P2WPKH".to_string(),
        },
        "an inner refusal must be recorded from the bound result: {entry:?}"
    );

    provider.shutdown();
}

/// A suite refusal keeps the answer's `code` beside its `status`, so two
/// refusals that differ only in `code` do not compare equal.
///
/// The two answers below carry the same `status` and the same message text and
/// differ only in `code`, which is what the stand-in comparison would otherwise
/// miss. The test builds both answers in the test, reads no file and starts no
/// process, so it runs on every host.
///
/// Falsifier: WP122 drops the `code` from the refusal record in `suite_entry`;
/// this test fails because the two entries are equal.
#[test]
fn suite_entry_keeps_the_refusal_code() {
    let storage_refusal = json!({
        "status": "error",
        "code": "storage_error",
        "message": "wallet storage is not writable",
    });
    let invalid_refusal = json!({
        "status": "error",
        "code": "invalid_request",
        "message": "wallet storage is not writable",
    });

    let storage_entry = suite_entry(
        "init at the wallet root",
        SuiteClass::Denied,
        &storage_refusal,
    );
    let invalid_entry = suite_entry(
        "init at the wallet root",
        SuiteClass::Denied,
        &invalid_refusal,
    );
    assert_ne!(
        storage_entry, invalid_entry,
        "two refusals that differ only in code must not compare equal"
    );
    assert_eq!(
        storage_entry.outcome,
        SuiteOutcome::Refused {
            status: "error".to_string(),
            code: "storage_error".to_string(),
            message: "wallet storage is not writable".to_string(),
        },
        "the refusal record must keep status, code and message start: {storage_entry:?}"
    );
    assert_eq!(
        invalid_entry.outcome,
        SuiteOutcome::Refused {
            status: "error".to_string(),
            code: "invalid_request".to_string(),
            message: "wallet storage is not writable".to_string(),
        },
        "the refusal record must keep status, code and message start: {invalid_entry:?}"
    );
}

/// The stored-copy fixture shared by `unbound_copy_is_refused_under_profile`
/// and its control. It keeps the temporary base alive, resolves it, creates
/// `STORAGE_ROOT` first, and copies the provider binary there byte for byte,
/// so the copy and the binary differ only by path.
struct StoredCopy {
    _fixture: tempfile::TempDir,
    base: PathBuf,
    storage: PathBuf,
    copy: PathBuf,
}

impl StoredCopy {
    fn prepare() -> Self {
        let fixture = tempfile::tempdir().expect("temporary wallet base");
        let base = resolved(fixture.path());
        let binary = resolved(Path::new(PROVIDER_BINARY));
        let bindings = canonical_bindings(WALLET_PROVIDER, &base, Path::new(PROVIDER_BINARY));
        create_shared_ancestors(&bindings);
        let storage = wallet_dir(&base);
        fs::create_dir(&storage).expect("STORAGE_ROOT must be created first");
        let copy = storage.join(binary.file_name().expect("the provider binary's file name"));
        fs::copy(&binary, &copy).expect("copy the provider binary under STORAGE_ROOT");
        let copy = resolved(&copy);
        assert_eq!(
            fs::read(&copy).expect("the copy must be readable"),
            fs::read(&binary).expect("the binary must be readable"),
            "the copy must be byte-identical to the bound binary"
        );
        Self {
            _fixture: fixture,
            base,
            storage,
            copy,
        }
    }
}

/// Under the real profile, only the path bound as `PROVIDER_EXECUTABLE` can be
/// started. The test runs `confine.sb` itself, with no fixture rule. It binds
/// the real provider binary as `PROVIDER_EXECUTABLE` and the storage
/// parameters as usual, and starts the byte-identical copy under
/// `STORAGE_ROOT`. `sandbox-exec` applies the profile before it executes its
/// program, so the refused step is that exec of the copy, checked by the same
/// `process-exec` rule as any exec by the confined provider. `sandbox-exec`
/// exits 71 and logs `execvp() of '<copy>' failed: Operation not permitted`,
/// and `STORAGE_ROOT` keeps only the copy. A missing program also exits 71,
/// but with `No such file or directory`, so the test checks the EPERM line.
/// `bound_copy_serves_under_profile` is the control: the same copy from the
/// same fixture, bound and started, serves.
///
/// Falsifier: append one `(allow process-exec)` after the exec rule (WP56);
/// the copy starts and stays alive to the deadline, so this test fails on its
/// deadline assertion.
#[test]
fn unbound_copy_is_refused_under_profile() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let stored = StoredCopy::prepare();
    let before = fs::read(&stored.copy).expect("the copy must be readable");
    let request = json!({
        "op": "init",
        "config": { "base_path": stored.base.display().to_string() }
    });
    let canonical = canonical_bindings(WALLET_PROVIDER, &stored.base, Path::new(PROVIDER_BINARY));
    let bindings: Vec<(&str, &Path)> = canonical
        .iter()
        .map(|(name, path)| (*name, path.as_path()))
        .collect();
    let mut refused =
        ConfinedProvider::start_under(Path::new(PROFILE_PATH), &bindings, &stored.copy);

    let exit = refused.wait_for_exit();
    assert!(
        !matches!(exit, ChildExit::TimedOut),
        "the profile must refuse the exec, so sandbox-exec must exit: {exit}"
    );
    assert_eq!(
        exit.code(),
        Some(71),
        "sandbox-exec must exit 71 when the profile refuses the exec: {exit}"
    );
    refused
        .try_send(&request)
        .expect_err("the refused copy must not answer init");

    // Quote only `sandbox-exec`'s exec lines, never the whole stream.
    let copy = stored.copy.display().to_string();
    let stderr = refused.stderr();
    let execs: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("execvp()"))
        .collect();
    assert!(
        execs
            .iter()
            .any(|line| line.contains(&copy) && line.contains("Operation not permitted")),
        "sandbox-exec must log the refused exec of {copy} with EPERM: {execs:?}"
    );

    let entries: Vec<PathBuf> = fs::read_dir(&stored.storage)
        .expect("STORAGE_ROOT must stay readable")
        .map(|entry| entry.expect("STORAGE_ROOT entry").path())
        .collect();
    assert_eq!(
        entries,
        std::slice::from_ref(&stored.copy),
        "STORAGE_ROOT must hold only the copy"
    );
    assert_eq!(
        fs::read(&stored.copy).expect("the copy must stay readable"),
        before,
        "the refused run must leave the copy's bytes unchanged"
    );
}

/// The control for `unbound_copy_is_refused_under_profile`: the same fixture,
/// with the copy at the same place under `STORAGE_ROOT` bound as
/// `PROVIDER_EXECUTABLE` and started under the same `confine.sb`. `init` with
/// `base_path` as the fixture base answers `ok`, a following `status` answers
/// `ok`, and `shutdown` exits 0. The binding is the only difference between
/// the two runs.
#[test]
fn bound_copy_serves_under_profile() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let stored = StoredCopy::prepare();
    let bound: Vec<(&str, PathBuf)> =
        canonical_bindings(WALLET_PROVIDER, &stored.base, Path::new(PROVIDER_BINARY))
            .into_iter()
            .map(|(name, path)| match name {
                "PROVIDER_EXECUTABLE" => (name, stored.copy.clone()),
                _ => (name, path),
            })
            .collect();
    let bindings: Vec<(&str, &Path)> = bound
        .iter()
        .map(|(name, path)| (*name, path.as_path()))
        .collect();
    let mut provider =
        ConfinedProvider::start_under(Path::new(PROFILE_PATH), &bindings, &stored.copy);
    let init = provider.init(&stored.base);
    assert_eq!(
        init["status"], "ok",
        "the bound copy must answer init: {init}"
    );
    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(
        status["status"], "ok",
        "the bound copy must answer status: {status}"
    );
    provider.shutdown();
}

/// A confined start that fails before it answers shows its reason.
///
/// The fixture profile keeps `(version 1)` first and `(deny default)` second,
/// so `sandbox-exec` cannot exec the provider. The test waits for that child to
/// exit, sends `init`, and requires the one harness failure to name the
/// request, the exit status and `sandbox-exec`'s own denial on standard error.
/// A fixture child that reads one request and exits without answering reaches
/// the response-stream branch of the same harness with the same three facts.
///
/// Falsifier: use a fixed `Operation not permitted` instead of the child's
/// standard error in `unanswered` (WP42); the denied start's failure names no
/// `execvp()` denial, so this test fails on that assertion at the first case.
#[test]
fn startup_denial_reports_its_reason() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let fixture = tempfile::tempdir().expect("temporary wallet root");
    let base = resolved(fixture.path());
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile = resolved(profile_root.path()).join("deny-all.sb");
    fs::write(&profile, "(version 1)\n(deny default)\n").expect("fixture profile must be writable");
    let request = json!({
        "op": "init",
        "config": { "base_path": base.display().to_string() }
    });

    // The denied provider exits before it reads the request, so the harness
    // cannot write it. It reports the exit status and the sandbox denial.
    let canonical = canonical_bindings(WALLET_PROVIDER, &base, Path::new(PROVIDER_BINARY));
    create_shared_ancestors(&canonical);
    let bindings: Vec<(&str, &Path)> = canonical
        .iter()
        .map(|(name, path)| (*name, path.as_path()))
        .collect();
    let mut denied = ConfinedProvider::start_under(&profile, &bindings, Path::new(PROVIDER_BINARY));
    let exit = denied.wait_for_exit();
    assert_ne!(
        exit.code(),
        Some(0),
        "sandbox-exec must not exec the provider: {exit}"
    );
    let denial = denied
        .try_send(&request)
        .expect_err("a denied provider must not answer");
    assert!(
        denial.contains(&request.to_string()),
        "the failure must name the request: {denial}"
    );
    assert!(
        denial.contains(&exit.to_string()),
        "the failure must name the exit status: {denial}"
    );
    assert!(
        denial.contains("Operation not permitted"),
        "the failure must carry sandbox-exec's denial: {denial}"
    );
    assert!(
        denial.contains("execvp()") && denial.contains(PROVIDER_BINARY),
        "the denial must be sandbox-exec's exec denial of the provider binary: {denial}"
    );
    eprintln!("startup denial failure: {denial}");

    // A child that answers nothing reaches the response-stream branch with the
    // same three facts.
    let mut silent = ConfinedProvider::spawn({
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("read request; printf 'fixture: read one request\\n' >&2; exit 3");
        command
    });
    let silence = silent
        .try_send(&request)
        .expect_err("a child that exits without answering must fail");
    let exit = silent.wait_for_exit();
    assert_eq!(
        exit.code(),
        Some(3),
        "the fixture must reach its own exit: {exit}"
    );
    assert!(
        silence.contains(&request.to_string()),
        "the failure must name the request: {silence}"
    );
    assert!(
        silence.contains(&exit.to_string()),
        "the failure must name the exit status: {silence}"
    );
    assert!(
        silence.contains("fixture: read one request"),
        "the failure must carry the child's standard error: {silence}"
    );
    eprintln!("response-stream failure: {silence}");
}

/// The harness drains standard error while the child runs.
///
/// The fixture writes 128 KiB, more than the pipe buffer, to standard error and
/// exits with status 7. The harness must reach that status within its bounded
/// deadline and collect every byte.
///
/// Falsifier: start reading only after `wait_for_exit` has returned (WP41);
/// the fixture fills the pipe and blocks, so the wait kills it, and this test
/// fails on its exit assertion, `no exit within 10s, so it was killed`.
#[test]
fn stderr_is_drained_before_wait() {
    let mut child = ConfinedProvider::spawn({
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("dd if=/dev/zero bs=1024 count=128 >&2 2>/dev/null; exit 7");
        command
    });
    let exit = child.wait_for_exit();
    assert_eq!(
        exit.code(),
        Some(7),
        "the child must reach its own exit: {exit}"
    );
    let stderr = child.stderr();
    assert_eq!(stderr.len(), 128 * 1024, "every drained byte must survive");
    assert!(
        stderr.as_bytes().iter().all(|byte| *byte == 0),
        "the drained bytes must be the fixture's zero bytes"
    );
}

/// An answer that is not JSON fails with its own message.
///
/// Through `spawn`, a fixture child reads one request, prints `not json` and a
/// newline to standard output, and exits 0. The failure names the request,
/// `invalid JSON`, the parse error `serde_json` gives for the answer and the
/// answer itself, and it does not say the provider did not answer. The test
/// starts no sandbox and does not call `sandbox_available`.
///
/// Falsifier: return the shared unanswered message from the invalid-JSON branch
/// (WP43); the answer loses its parse error and says the provider did not
/// answer, so this test fails on its `invalid JSON` assertion.
#[test]
fn invalid_json_answer_names_the_request_and_the_parse_error() {
    let mut child = ConfinedProvider::spawn({
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("read request; echo 'not json'; exit 0");
        command
    });
    let request = json!({ "op": "status" });
    let failure = child
        .try_send(&request)
        .expect_err("an answer that is not JSON must fail");
    let parse_error = serde_json::from_str::<Value>("not json\n")
        .expect_err("the fixture answer must not parse as JSON")
        .to_string();
    assert!(
        failure.contains(&request.to_string()),
        "the failure must name the request: {failure}"
    );
    assert!(
        failure.contains("invalid JSON"),
        "the failure must name the invalid JSON answer: {failure}"
    );
    assert!(
        failure.contains(&parse_error),
        "the failure must carry the parse error: {failure}"
    );
    assert!(
        failure.contains("not json"),
        "the failure must carry the answer: {failure}"
    );
    assert!(
        !failure.contains("did not answer"),
        "an invalid answer is not an unanswered request: {failure}"
    );
    eprintln!("invalid-JSON failure: {failure}");
}

/// Whether `form` is a top-level allow rule, whichever way it writes the
/// operator: `(allow file-read*)` and `(allow(literal "/x"))` put a space or a
/// nested form after `allow`, `(allow)` is the bare operator, and
/// `(allow network*)` is the spaced spelling. The three predicates below, the
/// allow-form selector `allow_forms`, the seccomp mapping table's lookup and
/// the Landlock ruleset builder all call this one function, so the rule has
/// one spelling in this file (P10).
///
/// `allow` must be a whole token of the form: `(allowed ...)`, `(allowing x)`
/// and `(notallow)` are not allow forms.
fn is_allow_form(form: &str) -> bool {
    allow_form_rest(form).is_some()
}

/// The text after the `allow` operator of a top-level allow form, or `None`
/// where the form is not one. `is_allow_form` answers the boolean question and
/// `is_exec_allow` reads its operation names from this same rest, so the form
/// head has one spelling (P10).
fn allow_form_rest(form: &str) -> Option<&str> {
    let rest = form.strip_prefix('(')?.trim_start();
    let operation = rest.split([' ', '(', ')']).next().unwrap_or_default();
    if operation != "allow" {
        return None;
    }
    Some(&rest[operation.len()..])
}

/// Whether `form` is a top-level allow rule that grants the network. This is
/// the one copy of the rule, used both by the provider's own profile test and
/// by the shared file-profile contract check (P10).
fn is_network_allow(form: &str) -> bool {
    is_allow_form(form) && form.contains("network")
}

/// Whether `form` is a top-level allow rule that grants every operation by
/// default. This is the one copy of the rule, used both by the provider's own
/// profile test and by the shared file-profile contract check (P10).
fn is_default_allow(form: &str) -> bool {
    is_allow_form(form) && form.split([' ', '(', ')']).any(|token| token == "default")
}

/// Whether `form` is a top-level allow rule that grants `process-exec`: one of
/// its operation names, the bare tokens directly inside the allow form before
/// or after a nested filter or a string, is `process*` or starts with
/// `process-exec`, and each of those grants it. An allow form may write its
/// first filter directly after `allow`. A token inside a nested filter is that
/// filter's argument and a token inside a string is text, so neither names an
/// operation. `profile_characters` is the one string reader, so an escaped
/// quote or parenthesis reads here as `profile_forms` reads it. This is the one
/// copy of the rule, used by the shared file-profile contract check (P10).
fn is_exec_allow(form: &str) -> bool {
    let Some(rest) = allow_form_rest(form) else {
        return false;
    };
    if !rest.is_empty() && !rest.starts_with([' ', '(']) {
        return false;
    }
    let mut operations: Vec<String> = Vec::new();
    let mut operation = String::new();
    let mut depth = 0usize;
    for (ch, in_string) in profile_characters(rest) {
        if in_string {
            flush_operation(&mut operation, depth, &mut operations);
            continue;
        }
        match ch {
            '(' | ')' => {
                flush_operation(&mut operation, depth, &mut operations);
                depth = if ch == '(' {
                    depth + 1
                } else {
                    depth.saturating_sub(1)
                };
            }
            _ if ch.is_whitespace() => {
                flush_operation(&mut operation, depth, &mut operations);
            }
            _ => operation.push(ch),
        }
    }
    flush_operation(&mut operation, depth, &mut operations);
    operations
        .iter()
        .any(|operation| operation == "process*" || operation.starts_with("process-exec"))
}

/// Records one finished operation token when it sits directly inside the allow
/// form, and drops it when it sits inside a nested filter.
fn flush_operation(operation: &mut String, depth: usize, operations: &mut Vec<String>) {
    if depth == 0 && !operation.is_empty() {
        operations.push(std::mem::take(operation));
    } else {
        operation.clear();
    }
}

/// The profile denies every network operation: it starts from `(deny default)`
/// and grants no network rule. The provider has no network path of its own,
/// so this rule is what keeps that true if a later change adds one.
///
/// Falsifier: add `(allow network*)` to `confine.sb`; this test fails.
#[test]
fn profile_denies_network() {
    let profile = fs::read_to_string(PROFILE_PATH).expect("profile must be readable");
    let forms = profile_forms(&profile);
    assert_eq!(
        forms.first().map(String::as_str),
        Some("(version 1)"),
        "the profile must start with its version"
    );
    assert!(
        forms.iter().any(|form| form == "(deny default)"),
        "the profile must deny by default"
    );
    for form in &forms {
        assert!(
            !is_default_allow(form),
            "the profile must reject allow default, including after deny default: {form}"
        );
        assert!(
            !is_network_allow(form),
            "the profile must not grant network access: {form}"
        );
    }
}

/// The parameter tokens every file-profile provider's profile declares. The
/// tests bind these three for each launch; one generator for every provider is
/// the Runtime bridge change, and that Runtime half is not built. A
/// provider-prefixed token would add a second path for one operation (P10).
const CANONICAL_PARAMS: [&str; 3] = ["PROVIDER_EXECUTABLE", "STORAGE_ROOT", "STORAGE_PARENT"];
const PARAM_PREFIX: &str = "(param \"";
/// The three rules every file profile binds verbatim.
const SHARED_RULES: [&str; 3] = [
    r#"(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))"#,
    r#"(allow file-read* (literal (param "STORAGE_PARENT")))"#,
    r#"(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))"#,
];
/// The two allow forms did and wallet hold for startup: the provider reads the
/// root directory to resolve its own path, and reads kernel facts before the
/// protocol starts.
const STARTUP_RULES: [&str; 2] = [
    r#"(allow file-read* (literal "/"))"#,
    r#"(allow sysctl-read)"#,
];
/// The one id the shared contract names for each pinned allow rule: the three
/// shared rules and the two startup forms. A shared rule must be claimed by its
/// id, and a startup form must be claimed by its id whenever the profile holds
/// it. The model profile's root read, `(allow file-read-data (literal "/"))`,
/// is a different form and stays out of the table.
const PINNED_RULES: &[(&str, &str)] = &[
    (SHARED_RULES[0], "bound-executable"),
    (SHARED_RULES[1], "storage"),
    (SHARED_RULES[2], "storage"),
    (STARTUP_RULES[0], "startup-root-directory"),
    (STARTUP_RULES[1], "startup-sysctl"),
];
/// The file profiles the one contract check requires. Every one of them must
/// present the contract, in this order.
const FILE_PROFILES: [&str; 3] = ["did-provider", "wallet-provider", "model-provider"];

/// The parameter names one form's `(param "NAME")` tokens carry, in order.
/// An unclosed token is a refusal. The contract check and the Landlock path
/// reader both use this scan, so the token has one reader (P10).
fn parameter_tokens(form: &str) -> Result<Vec<&str>, ()> {
    let mut tokens = Vec::new();
    let mut rest = form;
    while let Some(at) = rest.find(PARAM_PREFIX) {
        let tail = &rest[at + PARAM_PREFIX.len()..];
        let Some(end) = tail.find('"') else {
            return Err(());
        };
        tokens.push(&tail[..end]);
        rest = &tail[end..];
    }
    Ok(tokens)
}

/// The one file-profile contract every file profile declares: `(version 1)`
/// first, `(deny default)` second, an explicit `(deny network*)`, no
/// `(allow default)`, no network allow, exactly one `process-exec` allow (the
/// shared exec rule), only the canonical parameter tokens, and the three
/// shared rules verbatim. The profile the Runtime generates must
/// match it; that Runtime bridge change is not built. Every refusal names the
/// profile and the rule.
fn check_profile_contract(name: &str, profile: &str) -> Result<(), String> {
    let forms = profile_forms(profile);
    if forms.first().map(String::as_str) != Some("(version 1)") {
        return Err(format!("{name} must start with (version 1)"));
    }
    if forms.get(1).map(String::as_str) != Some("(deny default)") {
        return Err(format!(
            "{name} must deny by default immediately after the version"
        ));
    }
    if !forms.iter().any(|form| form == "(deny network*)") {
        return Err(format!(
            "{name} must deny the network explicitly with (deny network*)"
        ));
    }
    let mut exec_allows = Vec::new();
    for form in &forms {
        if is_default_allow(form) {
            return Err(format!("{name} must reject (allow default): {form}"));
        }
        if is_network_allow(form) {
            return Err(format!(
                "{name} must not grant network access; a network allow is refused: {form}"
            ));
        }
        if is_exec_allow(form) {
            exec_allows.push(form.as_str());
        }
        let tokens = match parameter_tokens(form) {
            Ok(tokens) => tokens,
            Err(()) => return Err(format!("{name} parameter token must close: {form}")),
        };
        for token in tokens {
            if !CANONICAL_PARAMS.contains(&token) {
                return Err(format!(
                    "{name} declares the non-canonical parameter token {token}; \
                     every file profile binds STORAGE_ROOT, STORAGE_PARENT and PROVIDER_EXECUTABLE"
                ));
            }
        }
    }
    if exec_allows.len() > 1 {
        let shared = exec_allows.iter().position(|form| *form == SHARED_RULES[0]);
        let quoted = exec_allows
            .iter()
            .enumerate()
            .filter(|(index, _)| Some(*index) != shared)
            .map(|(_, form)| format!("`{form}`"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "{name} holds more than one process-exec allow, so it has a second exec path (P10); \
             the extra rules are {quoted}"
        ));
    }
    for rule in SHARED_RULES {
        if !forms.iter().any(|form| form == rule) {
            return Err(format!("{name} must bind the shared rule {rule}"));
        }
    }
    Ok(())
}

/// Runs the one contract check over every required file profile under
/// `capsules` and returns the names it checked, in list order.
///
/// `did-provider`, `wallet-provider` and `model-provider` are required; a
/// missing or unreadable one is a refusal that names its path. There is no
/// skip path.
fn check_file_profiles(capsules: &Path) -> Result<Vec<&'static str>, String> {
    let mut checked = Vec::new();
    for name in FILE_PROFILES {
        let path = capsules.join(name).join("confine.sb");
        let profile = match fs::read_to_string(&path) {
            Ok(profile) => profile,
            Err(err) => {
                return Err(format!(
                    "{name} profile {} must be readable: {err}",
                    path.display()
                ))
            }
        };
        check_profile_contract(name, &profile)?;
        checked.push(name);
    }
    Ok(checked)
}

/// The one declared-rights check for the did and wallet profiles: every
/// top-level allow form of `profile` traces to exactly one right the shared
/// contract names or to one platform-baseline rule, every declared rule is
/// exactly one allow form of that profile, no id or rule is declared twice, and
/// every platform-baseline entry gives a justification that starts with its
/// provider's executable prefix.
///
/// The check reads no file. It refuses, in this order: a document without the
/// role, provider, rights list or platform baseline; a platform baseline
/// without its own status sentence; a platform baseline without its rules
/// list; an entry of the declared rights list or the platform-baseline rules
/// list without a string id, whose reason names that list and the entry; an
/// entry without a rules list; a rule that is not a string; an id the shared
/// contract does not name; a platform-baseline entry without a justification
/// that starts with the provider's prefix and gives a reason; an entry with no
/// rules; an id declared more than once; a rule repeated inside one entry; an
/// allow form the profile holds more than once; an allow form with no claimant
/// or with more than one; a declared rule that is not exactly one allow form;
/// and a rule the pin table names for one id that the file claims for another.
/// The pin table holds the three shared rules and the two startup forms: a
/// shared rule must be claimed by its id, and a startup form must be claimed by
/// its id whenever the profile holds it. Each refusal starts with the provider
/// name and quotes the rule or names the id (P11).
fn check_declared_rights(name: &str, profile: &str, declared: &Value) -> Result<(), String> {
    let (rights, baseline) = declared_entries(name, declared)?;
    let claims: Vec<&DeclaredClaim> = rights.iter().chain(baseline.iter()).collect();
    for claim in &claims {
        if claim.rules.is_empty() {
            return Err(format!("{name} declares {} with no rules", claim.id));
        }
    }
    for (index, claim) in claims.iter().enumerate() {
        if claims[..index].iter().any(|earlier| earlier.id == claim.id) {
            return Err(format!("{name} declares {} more than once", claim.id));
        }
    }
    for claim in &claims {
        for (index, rule) in claim.rules.iter().enumerate() {
            if claim.rules[..index].contains(rule) {
                return Err(format!(
                    "{name} declares {} with the rule {rule} more than once",
                    claim.id
                ));
            }
        }
    }
    let forms = allow_forms(profile);
    for (index, form) in forms.iter().enumerate() {
        if forms[..index].contains(form) {
            return Err(format!(
                "{name} profile holds the allow rule {form} more than once"
            ));
        }
    }
    for form in &forms {
        let claimants: Vec<&str> = claims
            .iter()
            .filter(|claim| claim.rules.iter().any(|rule| rule == form))
            .map(|claim| claim.id.as_str())
            .collect();
        match claimants.len() {
            0 => {
                return Err(format!(
                    "{name} allow rule has no declared right and no platform-baseline rule: {form}"
                ))
            }
            1 => {}
            _ => {
                return Err(format!(
                    "{name} allow rule is claimed more than once: {form} ({})",
                    claimants.join(", ")
                ))
            }
        }
    }
    for claim in &claims {
        for rule in &claim.rules {
            if forms.iter().filter(|form| *form == rule).count() != 1 {
                return Err(format!(
                    "{name} declared rule is not an allow rule of its profile: {rule}"
                ));
            }
        }
    }
    for &(rule, expected) in PINNED_RULES {
        // A startup form is pinned only when the profile holds it; the model
        // profile reads the root directory with its own form.
        if !forms.iter().any(|form| form == rule) && !SHARED_RULES.contains(&rule) {
            continue;
        }
        let claimant = claims
            .iter()
            .find(|claim| claim.rules.iter().any(|candidate| candidate == rule))
            .map(|claim| claim.id.as_str());
        if claimant != Some(expected) {
            return Err(format!("{name} rule {rule} must be claimed by {expected}"));
        }
    }
    Ok(())
}

/// Reads one provider's declared-rights file. A missing, unreadable or invalid
/// file is a refusal that names the path; there is no skip path.
fn read_declared_rights(name: &str, path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|err| {
        format!(
            "{name} declared-rights file {} must be readable: {err}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).map_err(|err| {
        format!(
            "{name} declared-rights file {} must be valid JSON: {err}",
            path.display()
        )
    })
}

/// The one mapping table from a top-level allow form's text to the syscall
/// names it admits: the Linux seat of the file-profile contract.
///
/// The rows follow the contract's meaning rather than one kernel call.
/// `file-read*` keeps the calls that read an opened file or a directory entry;
/// `file-write*` keeps the calls that change one, plus the reads its own
/// callers make. The startup rows carry the loader's start reads and the kernel
/// facts `sysctl-read` names.
///
/// `ptrace`, `mount`, `bpf` and `keyctl` appear in no row, so the program's
/// default decision is the only answer they receive. Adding one of them to a
/// row would grant it and turn
/// `seccomp_program_denies_by_default_and_lists_no_undeclared_call` red.
///
/// This table is the only source of the list's syscalls: the builder adds none
/// of its own, so a syscall enters the filter only through a row an allow form
/// of the generated profile selects.
const SECCOMP_RULE_SYSCALLS: &[(&str, &[&str])] = &[
    (SHARED_RULES[0], &["execve", "execveat"]),
    (
        SHARED_RULES[1],
        &[
            "faccessat",
            "fstat",
            "getdents64",
            "lseek",
            "newfstatat",
            "openat",
            "openat2",
            "pread64",
            "read",
            "readlinkat",
            "readv",
            "statx",
        ],
    ),
    (
        SHARED_RULES[2],
        &[
            "faccessat",
            "fchmod",
            "fdatasync",
            "fstat",
            "fsync",
            "ftruncate",
            "getdents64",
            "linkat",
            "lseek",
            "mkdirat",
            "newfstatat",
            "openat",
            "openat2",
            "pread64",
            "pwrite64",
            "read",
            "readlinkat",
            "readv",
            "renameat2",
            "statx",
            "unlinkat",
            "write",
            "writev",
        ],
    ),
    (
        STARTUP_RULES[0],
        &[
            "faccessat",
            "fstat",
            "getdents64",
            "lseek",
            "newfstatat",
            "openat",
            "openat2",
            "pread64",
            "read",
            "readlinkat",
            "readv",
            "statx",
        ],
    ),
    (STARTUP_RULES[1], &["uname", "sysinfo"]),
];

/// The system call numbers the filter tests against, per audit architecture:
/// x86-64 first, then aarch64. `None` marks a call the target does not have.
const SECCOMP_SYSCALL_NUMBERS: &[(&str, Option<u32>, Option<u32>)] = &[
    ("bpf", Some(321), Some(280)),
    ("close", Some(3), Some(57)),
    ("execve", Some(59), Some(221)),
    ("execveat", Some(322), Some(281)),
    ("exit_group", Some(231), Some(94)),
    ("faccessat", Some(269), Some(48)),
    ("fchmod", Some(91), Some(52)),
    ("fdatasync", Some(75), Some(83)),
    ("fstat", Some(5), Some(80)),
    ("fsync", Some(74), Some(82)),
    ("ftruncate", Some(77), Some(46)),
    ("getdents64", Some(217), Some(61)),
    ("getrandom", Some(318), Some(278)),
    ("keyctl", Some(250), Some(219)),
    ("linkat", Some(265), Some(37)),
    ("lseek", Some(8), Some(62)),
    ("mkdirat", Some(258), Some(34)),
    ("mmap", Some(9), Some(222)),
    ("mount", Some(165), Some(40)),
    ("mprotect", Some(10), Some(226)),
    ("newfstatat", Some(262), Some(79)),
    ("openat", Some(257), Some(56)),
    ("openat2", Some(437), Some(437)),
    ("ppoll", Some(271), Some(73)),
    ("pread64", Some(17), Some(67)),
    ("ptrace", Some(101), Some(117)),
    ("pwrite64", Some(18), Some(68)),
    ("read", Some(0), Some(63)),
    ("readlinkat", Some(267), Some(78)),
    ("readv", Some(19), Some(65)),
    ("renameat2", Some(316), Some(276)),
    ("rt_sigaction", Some(13), Some(134)),
    ("statx", Some(332), Some(291)),
    ("sysinfo", Some(99), Some(179)),
    ("uname", Some(63), Some(160)),
    ("unlinkat", Some(263), Some(35)),
    ("write", Some(1), Some(64)),
    ("writev", Some(20), Some(66)),
];

/// The audit architecture this target's kernel reports in `seccomp_data.arch`.
/// A filter built for one architecture refuses the other instead of reading its
/// syscall numbers as its own.
#[cfg(target_arch = "x86_64")]
const SECCOMP_AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const SECCOMP_AUDIT_ARCH: u32 = 0xc000_00b7;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const SECCOMP_AUDIT_ARCH: u32 = 0;

/// The first number of the x32 call space on x86-64.
const SECCOMP_X32_FIRST: u32 = 0x4000_0000;
/// `seccomp_data.arch` sits at byte offset 4 and `seccomp_data.nr` at 0.
const SECCOMP_ARCH_OFFSET: u32 = 4;
const SECCOMP_NUMBER_OFFSET: u32 = 0;
/// The classic-BPF codes the filter uses: load a word, test equality, test
/// greater-or-equal, and return a decision.
const SECCOMP_BPF_LD_W_ABS: u16 = 0x20;
const SECCOMP_BPF_JEQ_K: u16 = 0x15;
const SECCOMP_BPF_JGE_K: u16 = 0x35;
const SECCOMP_BPF_RET_K: u16 = 0x06;
/// `SECCOMP_RET_ALLOW`, and the marker errno this filter answers with. The
/// marker is `EACCES`, so a refusal is distinguishable from the `EPERM` a
/// kernel gives an unprivileged process for a call it may not make: a `bpf`
/// assertion that reads `EPERM` would pass with no filter installed.
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_DENY_ERRNO: i32 = libc::EACCES;

/// One classic-BPF instruction. The filter is built as this plain value so a
/// test can walk it on every OS, and it becomes a `libc::sock_filter` only
/// where a kernel reads it (task 148).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SeccompInstruction {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl SeccompInstruction {
    const fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

/// The value the filter returns for a refused call: `SECCOMP_RET_ERRNO` with
/// the deny marker.
const fn seccomp_deny_return() -> u32 {
    0x0005_0000 | SECCOMP_DENY_ERRNO as u32
}

/// The generated Linux policy of one provider: the provider name, the audit
/// architecture the program was built for, the syscall names it admits in
/// program order, and the program itself.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SeccompAllowList {
    provider: String,
    audit_arch: u32,
    syscalls: Vec<&'static str>,
    program: Vec<SeccompInstruction>,
    /// A step an install must refuse, so a launch refusal is proved without a
    /// kernel that would refuse it. It is test input and `None` in every real
    /// launch.
    #[cfg(target_os = "linux")]
    injected_step_failure: Option<(SeccompStep, i32)>,
}

impl SeccompAllowList {
    /// Whether the list admits `name`.
    fn admits(&self, name: &str) -> bool {
        self.syscalls.contains(&name)
    }

    /// The list a launch installs: this declared list plus the measured launch
    /// set, rebuilt by the one program builder. It is the only place the two
    /// sources join, so the launcher and the probe install the same filter and
    /// no second list is written (P10).
    ///
    /// The launch set is measured, not declared: no declared right covers a
    /// runtime's own plumbing, and a launch that loses one cannot speak its
    /// protocol. `LAUNCH_ESSENTIALS` holds none of the four calls the default
    /// decision refuses, so adding the set leaves their answer unchanged.
    ///
    /// It makes no kernel call and reads no file, so it runs on every OS: the
    /// journey that installs the result is Linux-only, and the list a launch
    /// would install can be read and compared wherever the tests run.
    fn with_launch_essentials(&self) -> Self {
        let mut syscalls = self.syscalls.clone();
        for (syscall, _) in LAUNCH_ESSENTIALS {
            let syscall = *syscall;
            if !syscalls.contains(&syscall) {
                syscalls.push(syscall);
            }
        }
        syscalls.sort_unstable();
        Self {
            provider: self.provider.clone(),
            audit_arch: self.audit_arch,
            program: seccomp_program(&syscalls, self.audit_arch),
            syscalls,
            #[cfg(target_os = "linux")]
            injected_step_failure: self.injected_step_failure,
        }
    }
}

/// The number `name` has on `audit_arch`, or `None` where the call does not
/// exist there. One reader serves the filter builder and every test (P10).
fn seccomp_syscall_number(name: &str, audit_arch: u32) -> Option<u32> {
    let (_, x86_64, aarch64) = SECCOMP_SYSCALL_NUMBERS
        .iter()
        .find(|(candidate, _, _)| *candidate == name)
        .unwrap_or_else(|| panic!("{name} has no syscall number row"));
    match audit_arch {
        0xc000_003e => *x86_64,
        0xc000_00b7 => *aarch64,
        _ => None,
    }
}

/// The one builder: the allow list of `name`, rendered from the profile
/// `generate_profile` produces from `declared` and read back through
/// `profile_forms`. It reads no file, holds no rule text of its own and never
/// reads the declared-rights document directly, so the JSON has one reader and
/// the profile one parser (P10).
///
/// Every admitted syscall comes from a mapping-table row an allow form selects,
/// so a declaration with no allow form yields an empty list and a program whose
/// only decisions are the ABI guards and the deny marker. The launch set a
/// Linux start additionally needs is measured on the Linux host by the task
/// that owns the kernel calls; nothing here adds a syscall of its own.
///
/// It refuses, in this order: whatever `generate_profile` refuses, with that
/// reason unchanged; an allow form the mapping table does not hold, with a
/// reason that names the provider and the form, before any filter is built; and
/// a target whose audit architecture the filter cannot name.
///
/// The head forms and the deny forms grant nothing, so they take no row and add
/// no syscall.
fn seccomp_allow_list_from_declared_rights(
    name: &str,
    declared: &Value,
) -> Result<SeccompAllowList, String> {
    let rendered = generate_profile(name, declared)?;
    let mut syscalls: Vec<&'static str> = Vec::new();
    for form in profile_forms(&rendered) {
        if !is_allow_form(&form) {
            // The version, the default denial and the network denial grant
            // nothing, so no syscall answers to them.
            continue;
        }
        let Some(row) = SECCOMP_RULE_SYSCALLS
            .iter()
            .find(|(allowed, _)| *allowed == form.as_str())
        else {
            return Err(format!(
                "{name} seccomp allow list refuses the allow form {form}: \
                 the mapping table has no syscall row for it, so no filter is built"
            ));
        };
        for syscall in row.1 {
            if !syscalls.contains(syscall) {
                syscalls.push(syscall);
            }
        }
    }
    if SECCOMP_AUDIT_ARCH == 0 {
        return Err(format!(
            "{name} seccomp allow list is unavailable on target architecture {}: \
             the lab filter checks one audit architecture and this target has none",
            std::env::consts::ARCH
        ));
    }
    syscalls.sort_unstable();
    let program = seccomp_program(&syscalls, SECCOMP_AUDIT_ARCH);
    Ok(SeccompAllowList {
        provider: name.to_string(),
        audit_arch: SECCOMP_AUDIT_ARCH,
        syscalls,
        program,
        #[cfg(target_os = "linux")]
        injected_step_failure: None,
    })
}

/// The program of `syscalls`, in the one shape the list has: the audit-arch
/// check, the x32 guard, one equality test per admitted number with an `ALLOW`
/// return behind it, and the deny marker as the final decision. The default arm
/// is the marker, so every call the list does not name is refused.
fn seccomp_program(syscalls: &[&'static str], audit_arch: u32) -> Vec<SeccompInstruction> {
    let mut program = vec![
        SeccompInstruction::stmt(SECCOMP_BPF_LD_W_ABS, SECCOMP_ARCH_OFFSET),
        // A wrong audit architecture falls through to the deny marker.
        SeccompInstruction::jump(SECCOMP_BPF_JEQ_K, audit_arch, 1, 0),
        SeccompInstruction::stmt(SECCOMP_BPF_RET_K, seccomp_deny_return()),
        SeccompInstruction::stmt(SECCOMP_BPF_LD_W_ABS, SECCOMP_NUMBER_OFFSET),
        // A number in the x32 space is not the call it looks like.
        SeccompInstruction::jump(SECCOMP_BPF_JGE_K, SECCOMP_X32_FIRST, 0, 1),
        SeccompInstruction::stmt(SECCOMP_BPF_RET_K, seccomp_deny_return()),
    ];
    for syscall in syscalls {
        let Some(number) = seccomp_syscall_number(syscall, audit_arch) else {
            continue;
        };
        program.push(SeccompInstruction::jump(SECCOMP_BPF_JEQ_K, number, 0, 1));
        program.push(SeccompInstruction::stmt(
            SECCOMP_BPF_RET_K,
            SECCOMP_RET_ALLOW,
        ));
    }
    program.push(SeccompInstruction::stmt(
        SECCOMP_BPF_RET_K,
        seccomp_deny_return(),
    ));
    program
}

/// The two steps a seccomp install takes, in order. Each has its own refusal,
/// so a failure names the step that failed and keeps its errno (P11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeccompStep {
    NoNewPrivileges,
    Filter,
}

/// A fixed-size refusal value. Its `Display` implementation allocates, so the
/// launcher formats it in the parent and never after fork.
///
/// The `Landlock` arm carries the file row's install failure, so the one record
/// layout and the one decoder carry both installs and no second reporting path
/// exists (P10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeccompInstallFailure {
    Step(SeccompStep, i32),
    AuditArchitecture(u32),
    Landlock(LandlockInstallFailure),
}

impl SeccompInstallFailure {
    /// Both child paths report failures through the same fixed record and
    /// decoder. This conversion uses only stack values after a fork. A Landlock
    /// step is encoded here, in this one record builder. The byte writer stays
    /// the writer of a finished record.
    fn launch_record(self) -> [u8; SECCOMP_LAUNCH_RECORD_LEN] {
        match self {
            Self::Landlock(failure) => failure.launch_record(),
            Self::Step(SeccompStep::NoNewPrivileges, errno) => {
                seccomp_launch_record(SECCOMP_LAUNCH_NO_NEW_PRIVS, i64::from(errno), 0)
            }
            Self::Step(SeccompStep::Filter, errno) => {
                seccomp_launch_record(SECCOMP_LAUNCH_FILTER, i64::from(errno), 0)
            }
            Self::AuditArchitecture(arch) => {
                seccomp_launch_record(SECCOMP_LAUNCH_AUDIT_ARCH, 0, i64::from(arch))
            }
        }
    }
}

/// The errno an install failure reports to the spawn's error pipe. One mapping
/// serves every `pre_exec` caller, so the child's exit status cannot differ
/// between the two installs (P10).
#[cfg(target_os = "linux")]
impl SeccompInstallFailure {
    fn errno(self) -> i32 {
        match self {
            Self::Step(_, errno) => errno,
            Self::AuditArchitecture(_) => libc::EINVAL,
            Self::Landlock(failure) => failure.errno,
        }
    }
}

impl std::fmt::Display for SeccompInstallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Step(SeccompStep::NoNewPrivileges, errno) => write!(
                f,
                "seccomp install refused: PR_SET_NO_NEW_PRIVS failed with errno {errno}"
            ),
            Self::Step(SeccompStep::Filter, errno) => write!(
                f,
                "seccomp install refused: the filter install failed with errno {errno}"
            ),
            Self::AuditArchitecture(arch) => write!(
                f,
                "seccomp install refused: the list was built for audit architecture {arch:#x} \
                 and this target reports {SECCOMP_AUDIT_ARCH:#x}"
            ),
            Self::Landlock(failure) => write!(f, "{failure}"),
        }
    }
}

/// The one step sequencer, and it makes no kernel call: the architecture check
/// first, then `NoNewPrivileges`, then `Filter`, stopping at the first failure
/// with that step's own reason and errno. A failure of the first step means the
/// second never runs.
fn install_seccomp_with(
    allow: &SeccompAllowList,
    mut steps: impl FnMut(SeccompStep) -> Result<(), i32>,
) -> Result<(), SeccompInstallFailure> {
    if allow.audit_arch != SECCOMP_AUDIT_ARCH {
        return Err(SeccompInstallFailure::AuditArchitecture(allow.audit_arch));
    }
    for step in [SeccompStep::NoNewPrivileges, SeccompStep::Filter] {
        steps(step).map_err(|errno| SeccompInstallFailure::Step(step, errno))?;
    }
    Ok(())
}

/// The Landlock filesystem rights, by the bit the ABI numbers. The values are
/// the kernel's `<linux/landlock.h>` flags, written here as plain numbers so the
/// ruleset builder and every test read one table on every OS. `REFER`,
/// `TRUNCATE` and `IOCTL_DEV` arrived in ABI 2, 3 and 5, so a row that needs one
/// of them departs a lower-ABI kernel wider, and the builder refuses that ABI
/// instead of installing a weaker rule.
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

/// The one mapping table from a top-level allow form's text to the Landlock
/// filesystem rights its path rule carries: the file row of the Linux seat of
/// the file-profile contract.
///
/// An entry whose rights are `0` is a form that is deliberately given no path
/// right, and it is written down rather than omitted so a reader cannot mistake
/// "no rule" for "not yet considered". Every allow form a wallet profile
/// carries has exactly one entry here, so no form is left without a decision and
/// no form can be added to a profile without one:
///
/// - the `STORAGE_ROOT` subpath form carries read-file, read-dir, write-file,
///   remove-file, remove-dir, make-dir and make-reg, because `init` creates the
///   wallet directory and its key file inside the root, and a path rule on that
///   directory covers the tree `subpath` names;
/// - the `bound-executable` exec form carries only `EXECUTE` on that file,
///   which is what the declared `process-exec` permission authorizes;
/// - the `STORAGE_PARENT` read form carries no right: a Landlock path rule on a
///   directory covers the whole tree beneath it, so a read rule on the parent
///   would grant every sibling of `STORAGE_ROOT`;
/// - the root read form `(allow file-read* (literal "/"))` carries no right: a
///   read rule on `/` would grant the whole filesystem and add a fourth path;
/// - `(allow sysctl-read)` carries no path right. Landlock has no sysctl right,
///   and the form names kernel facts rather than a path.
///
/// The head forms (`(version 1)`, `(deny default)`) and the deny forms grant
/// nothing, so they take no entry at all.
///
/// Falsifier: WP202 adds `READ_FILE` to the `STORAGE_PARENT` row, so
/// `landlock_ruleset_follows_the_declared_rights` fails on that decision.
const LANDLOCK_RULE_RIGHTS: &[(&str, u64)] = &[
    (
        SHARED_RULES[2],
        LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG,
    ),
    (SHARED_RULES[0], LANDLOCK_ACCESS_FS_EXECUTE),
    (SHARED_RULES[1], 0),
    (STARTUP_RULES[0], 0),
    (STARTUP_RULES[1], 0),
];

/// The ABI each Landlock right needs. `READ_FILE`, `READ_DIR`, `WRITE_FILE`
/// and `EXECUTE` are ABI 1; `REMOVE_FILE`, `REMOVE_DIR`, `MAKE_DIR` and
/// `MAKE_REG` are also ABI 1. A row whose rights all exist at ABI 1 needs ABI
/// 1, and the builder reads this table to name the row a lower ABI cannot
/// express.
///
/// The table holds one entry per Landlock right so a row added later with a
/// newer right cannot silently claim ABI 1: a right with no entry is a
/// programmatic error the builder reports as its own reason.
const LANDLOCK_RIGHT_ABI: &[(u64, u32)] = &[
    (LANDLOCK_ACCESS_FS_EXECUTE, 1),
    (LANDLOCK_ACCESS_FS_WRITE_FILE, 1),
    (LANDLOCK_ACCESS_FS_READ_FILE, 1),
    (LANDLOCK_ACCESS_FS_READ_DIR, 1),
    (LANDLOCK_ACCESS_FS_REMOVE_DIR, 1),
    (LANDLOCK_ACCESS_FS_REMOVE_FILE, 1),
    (LANDLOCK_ACCESS_FS_MAKE_CHAR, 1),
    (LANDLOCK_ACCESS_FS_MAKE_DIR, 1),
    (LANDLOCK_ACCESS_FS_MAKE_REG, 1),
    (LANDLOCK_ACCESS_FS_MAKE_SOCK, 1),
    (LANDLOCK_ACCESS_FS_MAKE_FIFO, 1),
    (LANDLOCK_ACCESS_FS_MAKE_BLOCK, 1),
    (LANDLOCK_ACCESS_FS_MAKE_SYM, 1),
    (LANDLOCK_ACCESS_FS_REFER, 2),
    (LANDLOCK_ACCESS_FS_TRUNCATE, 3),
    (LANDLOCK_ACCESS_FS_IOCTL_DEV, 5),
];

/// The lowest Landlock ABI that can express every right of `rights`, or `None`
/// where a right has no table entry. It reads the one ABI table. A missing
/// entry is `None`, never ABI 1.
fn landlock_rights_abi(rights: u64) -> Option<u32> {
    let mut needed = 0u32;
    let mut known = 0u64;
    for (right, abi) in LANDLOCK_RIGHT_ABI {
        known |= *right;
        if rights & right == 0 {
            continue;
        }
        needed = needed.max(*abi);
    }
    if rights & !known != 0 {
        return None;
    }
    Some(needed)
}

/// The refusal of one row the reported `abi` cannot express, naming the row, or
/// `None` where the ABI can express it. This is the one copy of the ABI rule:
/// the ruleset builder and the test that presents a low ABI both read it (P10).
fn landlock_row_abi_refusal(row: &str, rights: u64, abi: u32) -> Option<String> {
    let Some(needed) = landlock_rights_abi(rights) else {
        return Some(format!(
            "linux confinement refused: the Landlock ABI cannot express {row}, \
             because a right in it has no ABI table entry"
        ));
    };
    if abi < needed {
        return Some(format!(
            "linux confinement refused: the Landlock ABI cannot express {row}, \
             which needs ABI {needed} and this kernel reports ABI {abi}"
        ));
    }
    None
}

/// The rights the file row must be able to *deny*, with the row name its refusal
/// uses. The oracle's `(deny default)` file row refuses every file write outside
/// `STORAGE_ROOT`, and a truncation and a device ioctl are writes there, so a
/// kernel whose ABI reports no right for them leaves them permitted outside the
/// root. `CONFINEMENT-LINUX.md` states the same rule for the `STORAGE_ROOT` row:
/// a wider departure is not confinement, so the start is refused.
///
/// The ABI each right needs is read from the one ABI table by
/// `landlock_row_abi_refusal`, so this constant holds no ABI version of its own.
/// `TRUNCATE` arrives at ABI 3 and `IOCTL_DEV` at ABI 5, so only ABI 5 or later
/// can refuse a write outside the root and a lower ABI builds no ruleset.
///
/// Falsifier: WP203 drops the builder's check of this pair, so ABI 1 builds a
/// ruleset and `landlock_ruleset_refuses_an_abi_that_cannot_express_a_row` fails.
const LANDLOCK_REQUIRED_DENIALS: (&str, u64) = (
    "the default-denial file rights",
    LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV,
);

/// The rights the builder handles in every ruleset: every right the ABI can
/// report at the version the ruleset was built for, so a right no rule covers is
/// refused by the default denial instead of being permitted. `handled_access_fs`
/// must name every right the kernel knows at that ABI, because an unnamed right
/// is not restricted at all.
///
/// `REFER`, `TRUNCATE` and `IOCTL_DEV` are added only at the ABI that defines
/// them: naming a right a lower-ABI kernel does not know makes
/// `landlock_create_ruleset` fail with `EINVAL`, so the mask is built from the
/// same ABI table the rows are checked against.
///
/// Falsifier: WP204 keeps only the read rights, so
/// `landlock_ruleset_handles_every_right_the_abi_reports` fails on the mask.
fn landlock_handled_rights(abi: u32) -> u64 {
    let mut handled = 0u64;
    for (right, introduced) in LANDLOCK_RIGHT_ABI {
        if *introduced <= abi {
            handled |= *right;
        }
    }
    handled
}

/// One path rule of a Landlock ruleset: the parameter it names, the path bound
/// to that parameter, and the rights the rule grants there.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LandlockPathRule {
    parameter: &'static str,
    path: PathBuf,
    rights: u64,
}

/// The generated Landlock policy of one provider: the provider name, the ABI it
/// was built for, the access mask it handles, and its path rules.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LandlockRuleset {
    provider: String,
    abi: u32,
    handled: u64,
    rules: Vec<LandlockPathRule>,
    /// A step an install must refuse, so a launch refusal is proved without a
    /// kernel that would refuse it. It is test input and `None` in every real
    /// launch.
    injected_step_failure: Option<(LandlockStep, i32)>,
}

/// The loader paths a dynamically linked provider needs under a path-only
/// ruleset, and the failure that follows when that entry alone is dropped.
///
/// On the Linux host measured for the stopped file-row branch, a ruleset that
/// grants `EXECUTE` on the bound wallet binary alone makes `execve` fail
/// `EACCES` (13) before the provider's first instruction. These four paths are
/// the aarch64 loader and the libraries that binary maps. Each entry carries
/// `EXECUTE | READ_FILE`. The note after each path is the failure that named it
/// when that entry alone was dropped from a working ruleset on that host:
///
/// - `/lib/ld-linux-aarch64.so.1`: without `EXECUTE` the loader cannot be
///   entered, and `execve` answers `EACCES` (13) before the provider's first
///   instruction; without `READ_FILE` the loader cannot map itself.
/// - `/lib/aarch64-linux-gnu/libc.so.6`: without `READ_FILE` the loader fails
///   to map `libc.so.6` and exits with `error while loading shared libraries:
///   libc.so.6: cannot open shared object file`.
/// - `/lib/aarch64-linux-gnu/libgcc_s.so.1`: without `READ_FILE` the loader
///   fails to map `libgcc_s.so.1` and exits with `error while loading shared
///   libraries: libgcc_s.so.1: cannot open shared object file`.
/// - `/lib/aarch64-linux-gnu/libm.so.6`: without `READ_FILE` the loader fails
///   to map `libm.so.6` and exits with `error while loading shared libraries:
///   libm.so.6: cannot open shared object file`.
///
/// This session did not repeat that drop-one measurement against the wallet
/// binary on spark1, so `CONFINEMENT-LINUX.md` records the file row as GAP.
/// The paths stay here so the ruleset the installer would apply is the one the
/// Mac test reads. The table is compiled on every OS.
const LANDLOCK_LOADER_PATHS: &[(&str, &str)] = &[
    (
        "/lib/ld-linux-aarch64.so.1",
        "without EXECUTE here the loader cannot be entered, and execve answers \
         EACCES (13) before the provider's first instruction; without READ_FILE the loader \
         cannot map itself",
    ),
    (
        "/lib/aarch64-linux-gnu/libc.so.6",
        "without READ_FILE here the loader fails to map libc.so.6 and exits with \
         `error while loading shared libraries: libc.so.6: cannot open shared object file`",
    ),
    (
        "/lib/aarch64-linux-gnu/libgcc_s.so.1",
        "without READ_FILE here the loader fails to map libgcc_s.so.1 and exits with \
         `error while loading shared libraries: libgcc_s.so.1: cannot open shared object file`",
    ),
    (
        "/lib/aarch64-linux-gnu/libm.so.6",
        "without READ_FILE here the loader fails to map libm.so.6 and exits with \
         `error while loading shared libraries: libm.so.6: cannot open shared object file`",
    ),
];

/// The one builder of a provider's Landlock file row: the ruleset of `name`,
/// rendered from the profile `generate_profile` produces from `declared` and read
/// back through `profile_forms`. Like the seccomp builder it reads no file, holds
/// no rule text of its own and never reads the declared-rights document
/// directly, so the JSON has one reader and the profile one parser (P10).
///
/// `bindings` carries the three parameter paths the launch binds, so the ruleset
/// names the same paths the start uses and no second derivation exists. A rule is
/// built only for a parameter a row grants a right on: a row whose rights are
/// `0` is a decision written down, and it adds no rule.
///
/// `abi` is the version the kernel reported, passed in rather than read here, so
/// every OS can drive this function and a test can present an ABI below a row's.
/// It refuses, in this order: whatever `generate_profile` refuses, with that
/// reason unchanged; an allow form the rights table does not hold, with a reason
/// that names the provider and the form and builds no ruleset; an ABI below a
/// row's, with `linux confinement refused: the Landlock ABI cannot express
/// <row>`, naming the row; a form whose parameter the launch does not bind; and
/// an ABI below the rights the default denial must be able to refuse, with the
/// same words and `LANDLOCK_REQUIRED_DENIALS`' row name. Every refusal builds no
/// ruleset.
///
/// The loader entries are added only where the provider needs them, which is
/// every launch of a dynamically linked provider; the builder takes them as an
/// input so a test can build a ruleset without them and read the difference.
/// A launch of the real binary passes `LANDLOCK_LOADER_PATHS`. A test that
/// reads the declared rows alone passes an empty list.
fn landlock_path_rules(
    name: &str,
    declared: &Value,
    bindings: &[(&'static str, PathBuf)],
    abi: u32,
    loader: &[(&str, &str)],
) -> Result<LandlockRuleset, String> {
    let rendered = generate_profile(name, declared)?;
    let mut rules: Vec<LandlockPathRule> = Vec::new();
    for form in profile_forms(&rendered) {
        if !is_allow_form(&form) {
            // The version, the default denial and the network denial grant
            // nothing, so they take no row and add no path.
            continue;
        }
        let Some((_, rights)) = LANDLOCK_RULE_RIGHTS
            .iter()
            .find(|(allowed, _)| *allowed == form.as_str())
        else {
            return Err(format!(
                "{name} landlock ruleset refuses the allow form {form}: \
                 the rights table has no row for it, so no ruleset is built"
            ));
        };
        if *rights == 0 {
            // A row that grants no right is a decision, not an omission.
            continue;
        }
        if let Some(refusal) = landlock_row_abi_refusal(&format!("the {form} row"), *rights, abi) {
            return Err(refusal);
        }
        let Some((parameter, path)) = parameter_path_for_form(&form, bindings) else {
            // A form whose parameter the launch does not bind is a refusal
            // rather than a skipped rule: a rule on a path nobody bound would
            // grant nothing and hide a drift between the profile and the launch.
            return Err(format!(
                "{name} landlock ruleset refuses the allow form {form}: \
                 the launch binds no parameter it names, so no ruleset is built"
            ));
        };
        rules.push(LandlockPathRule {
            parameter,
            path,
            rights: *rights,
        });
    }
    for (path, _) in loader {
        rules.push(LandlockPathRule {
            parameter: "LANDLOCK_LOADER_PATHS",
            path: PathBuf::from(path),
            rights: LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
        });
    }
    // The row's decisions are checked above; the denial the default arm must
    // make is checked here, so an ABI that grants every row but cannot refuse a
    // write outside `STORAGE_ROOT` builds no ruleset.
    let (denial_row, denial_rights) = LANDLOCK_REQUIRED_DENIALS;
    if let Some(refusal) = landlock_row_abi_refusal(denial_row, denial_rights, abi) {
        return Err(refusal);
    }
    Ok(LandlockRuleset {
        provider: name.to_string(),
        abi,
        handled: landlock_handled_rights(abi),
        rules,
        injected_step_failure: None,
    })
}

/// The parameter and bound path an allow form names, or `None` where the form
/// names no parameter the launch binds. It reads the form's `(param "NAME")`
/// token through `parameter_tokens`, the same reader the contract check uses,
/// so the token has one spelling, and it answers the path from the one
/// bindings list.
fn parameter_path_for_form<'a>(
    form: &str,
    bindings: &'a [(&'static str, PathBuf)],
) -> Option<(&'static str, PathBuf)> {
    let Ok(tokens) = parameter_tokens(form) else {
        return None;
    };
    for (parameter, path) in bindings {
        if tokens.contains(parameter) {
            return Some((*parameter, path.clone()));
        }
    }
    None
}

/// The step a Landlock install was taking when it failed. Each has its own
/// refusal, so a failure names the step and keeps its errno (P11).
///
/// `AddRule` names its rule by position in the ruleset rather than by parameter,
/// because the loader entries share one parameter name and a name would not tell
/// four rules apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LandlockStep {
    /// `landlock_create_ruleset`.
    CreateRuleset,
    /// `landlock_add_rule` for the rule at this position.
    AddRule(usize),
    /// `prctl(PR_SET_NO_NEW_PRIVS)`, which `landlock_restrict_self` requires.
    NoNewPrivileges,
    /// `landlock_restrict_self`.
    RestrictSelf,
}

/// One Landlock install failure: the step that failed and its errno.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LandlockInstallFailure {
    step: LandlockStep,
    errno: i32,
}

impl LandlockInstallFailure {
    const fn new(step: LandlockStep, errno: i32) -> Self {
        Self { step, errno }
    }

    /// The step's own words. `Display` and the launch record both read this one
    /// copy, so the step wording cannot drift (P10).
    fn step_words(self) -> String {
        match self.step {
            LandlockStep::CreateRuleset => "the ruleset could not be created".to_string(),
            LandlockStep::AddRule(index) => format!("the path rule {index} could not be added"),
            LandlockStep::NoNewPrivileges => "PR_SET_NO_NEW_PRIVS failed".to_string(),
            LandlockStep::RestrictSelf => "landlock_restrict_self failed".to_string(),
        }
    }

    /// The one fixed record this failure crosses the fork as. The record's
    /// first field names a Landlock outcome, the second names the step, and the
    /// third holds the errno. `SeccompInstallFailure::launch_record` is the
    /// caller, so the tags are encoded in that one builder.
    fn launch_record(self) -> [u8; SECCOMP_LAUNCH_RECORD_LEN] {
        let step = match self.step {
            LandlockStep::CreateRuleset => SECCOMP_LAUNCH_LANDLOCK_CREATE,
            LandlockStep::AddRule(index) => SECCOMP_LAUNCH_LANDLOCK_ADD_FIRST + index as i64,
            LandlockStep::NoNewPrivileges => SECCOMP_LAUNCH_LANDLOCK_NO_NEW_PRIVS,
            LandlockStep::RestrictSelf => SECCOMP_LAUNCH_LANDLOCK_RESTRICT_SELF,
        };
        seccomp_launch_record(SECCOMP_LAUNCH_LANDLOCK, step, i64::from(self.errno))
    }

    /// The failure a record's two fields name, or `None` where the step it names
    /// is no Landlock step. The decoder turns `Some` into this step's words
    /// through `step_words`.
    fn from_record(step: i64, errno: i32) -> Option<Self> {
        let step = match step {
            SECCOMP_LAUNCH_LANDLOCK_CREATE => LandlockStep::CreateRuleset,
            SECCOMP_LAUNCH_LANDLOCK_NO_NEW_PRIVS => LandlockStep::NoNewPrivileges,
            SECCOMP_LAUNCH_LANDLOCK_RESTRICT_SELF => LandlockStep::RestrictSelf,
            index if index >= SECCOMP_LAUNCH_LANDLOCK_ADD_FIRST => {
                LandlockStep::AddRule((index - SECCOMP_LAUNCH_LANDLOCK_ADD_FIRST) as usize)
            }
            _ => return None,
        };
        Some(Self::new(step, errno))
    }
}

impl std::fmt::Display for LandlockInstallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "landlock install refused: {} with errno {}",
            self.step_words(),
            self.errno
        )
    }
}

/// The one Landlock step sequencer, and it makes no kernel call: it runs the
/// steps in the order an install must take them, stopping at the first failure
/// with that step's own errno. A failure of the first step means no later step
/// runs, so a partly built ruleset is never installed.
///
/// The order is the one the kernel requires: every rule is added first, then
/// `PR_SET_NO_NEW_PRIVS`, then `landlock_restrict_self`. Without
/// `PR_SET_NO_NEW_PRIVS` first, `restrict_self` fails `EPERM` (1) and nothing is
/// confined, so an install that skipped or reordered that step would leave the
/// provider unconfined while answering `ok`.
///
/// Falsifier: WP210 runs the final call before `PR_SET_NO_NEW_PRIVS`, so
/// `landlock_install_refuses_each_failed_step` fails on its recorded order.
fn install_landlock_with(
    ruleset: &LandlockRuleset,
    mut steps: impl FnMut(LandlockStep) -> Result<(), i32>,
) -> Result<(), LandlockInstallFailure> {
    let mut run =
        |step: LandlockStep| steps(step).map_err(|errno| LandlockInstallFailure::new(step, errno));
    run(LandlockStep::CreateRuleset)?;
    for index in 0..ruleset.rules.len() {
        run(LandlockStep::AddRule(index))?;
    }
    run(LandlockStep::NoNewPrivileges)?;
    run(LandlockStep::RestrictSelf)
}

/// The ABI refusal of `ruleset`, or an empty string where its rows fit its ABI.
/// It reads the ruleset's own rows through the one ABI rule, so a row the ABI
/// cannot express has one refusal spelling (P10).
fn landlock_abi_refusal(ruleset: &LandlockRuleset) -> String {
    for rule in &ruleset.rules {
        if let Some(refusal) = landlock_row_abi_refusal(
            &format!("the {} row", rule.parameter),
            rule.rights,
            ruleset.abi,
        ) {
            return refusal;
        }
    }
    String::new()
}

/// Each served provider's committed declared rights yield the `STORAGE_ROOT`
/// rule on that provider's own root and the `EXECUTE` rule on that provider's
/// own binary, the three zero-right rows stay decisions that add no path, and a
/// declaration the shared contract does not name keeps `declared_entries`'
/// reason. One body runs over `DID_PROVIDER` and `WALLET_PROVIDER`, each with
/// its own base, its own declared-rights file and its own binary, so a rule
/// path cannot be read for one provider and bound for the other (P10).
///
/// The test reads a ruleset's own rules and the paths the launch binds. It
/// installs no ruleset and starts no provider, so it says nothing about a
/// kernel.
///
/// Falsifier: WP202 adds `READ_FILE` to the `STORAGE_PARENT` row, so this test
/// fails on the parent decision. WP216 makes the chooser ignore the provider
/// name and answer wallet's `STORAGE_ROOT` binding for both, so the did
/// iteration fails on the expected root.
#[test]
fn landlock_ruleset_follows_the_declared_rights() {
    for name in [DID_PROVIDER, WALLET_PROVIDER] {
        let fixture = tempfile::tempdir().expect("temporary provider base");
        let base = resolved(fixture.path());
        let inputs = provider_ruleset_inputs(name, &base).unwrap_or_else(|err| panic!("{err}"));
        let declared = &inputs.declared;
        let bindings = &inputs.bindings;
        let ruleset = landlock_path_rules(name, declared, bindings, 7, &[])
            .unwrap_or_else(|err| panic!("{err}"));
        assert!(ruleset.injected_step_failure.is_none());
        assert_eq!(LANDLOCK_RULE_RIGHTS.len(), 5);

        let rule = |parameter: &str| {
            ruleset
                .rules
                .iter()
                .find(|rule| rule.parameter == parameter)
                .unwrap_or_else(|| {
                    panic!("{name}: the ruleset must hold the {parameter} rule: {ruleset:?}")
                })
        };
        let bound = |parameter: &str| {
            bindings
                .iter()
                .find(|(binding, _)| *binding == parameter)
                .unwrap_or_else(|| panic!("{name}: the launch must bind {parameter}"))
                .1
                .clone()
        };
        println!(
            "{name}: STORAGE_PARENT {}, STORAGE_ROOT {} (rights {:#x}), PROVIDER_EXECUTABLE {}",
            bound("STORAGE_PARENT").display(),
            rule("STORAGE_ROOT").path.display(),
            rule("STORAGE_ROOT").rights,
            rule("PROVIDER_EXECUTABLE").path.display(),
        );

        assert_eq!(
            rule("STORAGE_ROOT").rights,
            LANDLOCK_ACCESS_FS_READ_FILE
                | LANDLOCK_ACCESS_FS_READ_DIR
                | LANDLOCK_ACCESS_FS_WRITE_FILE
                | LANDLOCK_ACCESS_FS_REMOVE_FILE
                | LANDLOCK_ACCESS_FS_REMOVE_DIR
                | LANDLOCK_ACCESS_FS_MAKE_DIR
                | LANDLOCK_ACCESS_FS_MAKE_REG,
            "{name}: the storage subpath row must carry the seven rights init needs"
        );
        assert_eq!(rule("STORAGE_ROOT").path, bound("STORAGE_ROOT"));
        // The expected root is written from the layout this provider keeps, not
        // from the chooser under test: did keeps `<base>/did` and wallet keeps the
        // three-component wallet path under its base.
        let expected_root = if name == DID_PROVIDER {
            base.join("did")
        } else {
            wallet_dir(&base)
        };
        assert_eq!(
            provider_storage_root(name, &base),
            expected_root,
            "{name}: the layout derivation must keep the root this provider's name names"
        );
        assert_eq!(
            rule("STORAGE_ROOT").path,
            expected_root,
            "{name}: the STORAGE_ROOT rule must bind this provider's own root"
        );
        assert_eq!(
            rule("PROVIDER_EXECUTABLE").rights,
            LANDLOCK_ACCESS_FS_EXECUTE,
            "{name}: the bound-executable row must carry execution-only rights"
        );
        assert_eq!(
            rule("PROVIDER_EXECUTABLE").path,
            bound("PROVIDER_EXECUTABLE")
        );
        assert_eq!(
            rule("PROVIDER_EXECUTABLE").path,
            resolved(inputs.binary),
            "{name}: the PROVIDER_EXECUTABLE rule must bind this provider's own binary"
        );

        let parent = LANDLOCK_RULE_RIGHTS
            .iter()
            .find(|(form, _)| *form == SHARED_RULES[1])
            .expect("the parent form must have an explicit decision")
            .1;
        assert_eq!(parent, 0, "the STORAGE_PARENT row must grant no right");
        assert_eq!(
            parent & LANDLOCK_ACCESS_FS_READ_FILE,
            0,
            "the STORAGE_PARENT row must grant no read"
        );
        assert_eq!(
            parent & LANDLOCK_ACCESS_FS_WRITE_FILE,
            0,
            "the STORAGE_PARENT row must grant no write"
        );
        for form in [STARTUP_RULES[0], STARTUP_RULES[1]] {
            let rights = LANDLOCK_RULE_RIGHTS
                .iter()
                .find(|(candidate, _)| *candidate == form)
                .unwrap_or_else(|| panic!("{form} must have an explicit decision"))
                .1;
            assert_eq!(rights, 0, "{form} must grant no path right");
        }
        assert!(
            !ruleset
                .rules
                .iter()
                .any(|rule| rule.parameter == "STORAGE_PARENT"),
            "the zero-right parent form must add no path"
        );

        let mut without_storage = declared.clone();
        without_storage["rights"]
            .as_array_mut()
            .expect("the declared rights must hold a rights list")
            .retain(|entry| entry["id"] != "storage");
        let reduced = landlock_path_rules(name, &without_storage, bindings, 7, &[])
            .unwrap_or_else(|err| panic!("{err}"));
        assert!(
            !reduced
                .rules
                .iter()
                .any(|rule| rule.parameter == "STORAGE_ROOT"),
            "{name}: removing the storage right must remove the STORAGE_ROOT rule: {reduced:?}"
        );
        assert!(
            reduced
                .rules
                .iter()
                .any(|rule| rule.parameter == "PROVIDER_EXECUTABLE"),
            "{name}: the bound-executable right stays, so its rule stays: {reduced:?}"
        );

        let mut unnamed = declared.clone();
        unnamed["rights"]
            .as_array_mut()
            .expect("the declared rights must hold a rights list")
            .push(json!({
                "id": "unnamed-right",
                "rules": [r#"(allow file-read* (literal "/private/var/cc-landlock-unnamed"))"#],
            }));
        let refusal = landlock_path_rules(name, &unnamed, bindings, 7, &[])
            .expect_err("an id the shared contract does not name must be refused");
        assert_eq!(
            refusal,
            format!("{name} declares unnamed-right, which the shared contract does not name"),
            "{name}: the refusal must be declared_entries' own reason, unchanged"
        );

        let mut unmapped = declared.clone();
        unmapped["rights"]
            .as_array_mut()
            .expect("the declared rights must hold a rights list")
            .iter_mut()
            .find(|entry| entry["id"] == "storage")
            .expect("the declared rights must hold the storage right")["rules"]
            .as_array_mut()
            .expect("the storage right must hold a rules list")
            .push(json!(
                r#"(allow mach-lookup (global-name "com.apple.system.logger"))"#
            ));
        let refusal = landlock_path_rules(name, &unmapped, bindings, 7, &[])
            .expect_err("an allow form with no rights row must be refused");
        assert_eq!(
        refusal,
        format!(
            "{name} landlock ruleset refuses the allow form \
             (allow mach-lookup (global-name \"com.apple.system.logger\")): \
             the rights table has no row for it, so no ruleset is built"
        ),
        "{name}: an allow form the rights table does not hold must be refused in these exact words"
    );

        let exec_binding: Vec<(&'static str, PathBuf)> = bindings
            .iter()
            .filter(|(binding, _)| *binding == "PROVIDER_EXECUTABLE")
            .cloned()
            .collect();
        let refusal = landlock_path_rules(name, declared, &exec_binding, 7, &[])
            .expect_err("a form whose parameter the launch does not bind must be refused");
        assert_eq!(
            refusal,
            format!(
                "{name} landlock ruleset refuses the allow form {}: \
             the launch binds no parameter it names, so no ruleset is built",
                SHARED_RULES[2]
            ),
            "{name}: an unbound parameter must be refused rather than skipped"
        );
    }
}

/// ABI 1, 2 and 4 build no ruleset, because the default denial must be able to
/// refuse a truncation and a device ioctl. ABI 5 and above build one. `REFER`,
/// `TRUNCATE` and `IOCTL_DEV` are each refused below the ABI that introduced
/// them and accepted at their own, by `landlock_row_abi_refusal`.
///
/// Falsifier: WP203 drops the required-denial check, so ABI 1 builds a ruleset
/// and this test fails.
#[test]
fn landlock_ruleset_refuses_an_abi_that_cannot_express_a_row() {
    let declared = read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
        .unwrap_or_else(|err| panic!("{err}"));
    let fixture = tempfile::tempdir().expect("temporary wallet base");
    let base = resolved(fixture.path());
    let bindings = canonical_bindings(WALLET_PROVIDER, &base, Path::new(PROVIDER_BINARY));

    for (rights, required, too_low) in [
        (LANDLOCK_ACCESS_FS_REFER, 2, 1),
        (LANDLOCK_ACCESS_FS_TRUNCATE, 3, 2),
        (LANDLOCK_ACCESS_FS_IOCTL_DEV, 5, 4),
    ] {
        assert_eq!(landlock_rights_abi(rights), Some(required));
        let mut fixture = LandlockRuleset {
            provider: WALLET_PROVIDER.to_string(),
            abi: too_low,
            handled: landlock_handled_rights(too_low),
            rules: vec![LandlockPathRule {
                parameter: "STORAGE_ROOT",
                path: PathBuf::from("/fixture/base/ElastOS/SystemServices/Wallet"),
                rights,
            }],
            injected_step_failure: None,
        };
        assert_eq!(
            landlock_abi_refusal(&fixture),
            format!(
                "linux confinement refused: the Landlock ABI cannot express the STORAGE_ROOT row, \
                 which needs ABI {required} and this kernel reports ABI {too_low}"
            ),
            "a row the ABI cannot express must be refused in these exact words"
        );
        assert_eq!(
            landlock_row_abi_refusal("the STORAGE_ROOT row", rights, too_low),
            Some(landlock_abi_refusal(&fixture)),
            "the three rights must be refused by the one ABI function"
        );
        fixture.abi = required;
        assert!(
            landlock_abi_refusal(&fixture).is_empty(),
            "the row must be accepted at ABI {required}"
        );
        assert!(
            landlock_row_abi_refusal("the STORAGE_ROOT row", rights, required).is_none(),
            "the same function must accept the right at its own ABI"
        );
    }

    assert_eq!(
        landlock_rights_abi(1u64 << 16),
        None,
        "a right with no ABI table entry must not be read as ABI 1"
    );
    assert_eq!(
        landlock_row_abi_refusal("the unknown row", 1u64 << 16, 7),
        Some(
            "linux confinement refused: the Landlock ABI cannot express the unknown row, \
             because a right in it has no ABI table entry"
                .to_string()
        ),
        "a right with no ABI table entry is its own refusal"
    );

    for (too_low, needed) in [(1, 5), (2, 5), (4, 5)] {
        let refusal = landlock_path_rules(WALLET_PROVIDER, &declared, &bindings, too_low, &[])
            .expect_err("an ABI below the default denial's rights must be refused");
        assert_eq!(
            refusal,
            format!(
                "linux confinement refused: the Landlock ABI cannot express {}, \
                 which needs ABI {needed} and this kernel reports ABI {too_low}",
                LANDLOCK_REQUIRED_DENIALS.0
            ),
            "an ABI that cannot refuse the write boundary must be refused in these words"
        );
    }
    let needed = landlock_rights_abi(LANDLOCK_REQUIRED_DENIALS.1)
        .expect("the default denial's rights must have ABI entries");
    assert_eq!(needed, 5);
    for abi in needed..8 {
        let ruleset = landlock_path_rules(WALLET_PROVIDER, &declared, &bindings, abi, &[])
            .unwrap_or_else(|err| panic!("ABI {abi} must build a ruleset: {err}"));
        assert_eq!(ruleset.abi, abi);
        assert!(
            ruleset
                .rules
                .iter()
                .any(|rule| rule.parameter == "STORAGE_ROOT"),
            "ABI {abi} must keep the STORAGE_ROOT rule: {ruleset:?}"
        );
    }
}

/// The handled mask equals the ABI table's rights for the version the ruleset
/// claims, so no right that version knows is left unrestricted.
///
/// Falsifier: WP204 keeps only the read rights in the mask, so this test fails.
#[test]
fn landlock_ruleset_handles_every_right_the_abi_reports() {
    let declared = read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
        .unwrap_or_else(|err| panic!("{err}"));
    let fixture = tempfile::tempdir().expect("temporary wallet base");
    let base = resolved(fixture.path());
    let bindings = canonical_bindings(WALLET_PROVIDER, &base, Path::new(PROVIDER_BINARY));
    for abi in [5, 6, 7] {
        let ruleset = landlock_path_rules(WALLET_PROVIDER, &declared, &bindings, abi, &[])
            .unwrap_or_else(|err| panic!("ABI {abi} must build a ruleset: {err}"));
        let mut reported = 0u64;
        for (right, introduced) in LANDLOCK_RIGHT_ABI {
            if abi >= *introduced {
                reported |= *right;
            }
        }
        assert_eq!(
            ruleset.handled, reported,
            "ABI {abi} must handle every right its table reports"
        );
        for right in [
            LANDLOCK_ACCESS_FS_EXECUTE,
            LANDLOCK_ACCESS_FS_WRITE_FILE,
            LANDLOCK_ACCESS_FS_TRUNCATE,
            LANDLOCK_ACCESS_FS_IOCTL_DEV,
        ] {
            assert_ne!(
                ruleset.handled & right,
                0,
                "ABI {abi} must restrict {right:#x}"
            );
        }
    }
}

/// The five install steps run in order, each failure keeps its step and errno
/// and its own reason, and a failed first step runs no later step.
///
/// Falsifier: WP210 runs the final call before `PR_SET_NO_NEW_PRIVS`, so this
/// test fails on its recorded order.
#[test]
fn landlock_install_refuses_each_failed_step() {
    let declared = read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
        .unwrap_or_else(|err| panic!("{err}"));
    let fixture = tempfile::tempdir().expect("temporary install fixture");
    let base = resolved(fixture.path());
    let bindings = canonical_bindings(WALLET_PROVIDER, &base, Path::new(PROVIDER_BINARY));
    let ruleset = landlock_path_rules(WALLET_PROVIDER, &declared, &bindings, 7, &[]).unwrap();
    assert_eq!(ruleset.rules.len(), 2);
    let order = [
        LandlockStep::CreateRuleset,
        LandlockStep::AddRule(0),
        LandlockStep::AddRule(1),
        LandlockStep::NoNewPrivileges,
        LandlockStep::RestrictSelf,
    ];
    let cases = [
        (
            LandlockStep::CreateRuleset,
            libc::EINVAL,
            "landlock install refused: the ruleset could not be created with errno 22",
        ),
        (
            LandlockStep::AddRule(0),
            libc::EACCES,
            "landlock install refused: the path rule 0 could not be added with errno 13",
        ),
        (
            LandlockStep::AddRule(1),
            libc::ENOENT,
            "landlock install refused: the path rule 1 could not be added with errno 2",
        ),
        (
            LandlockStep::NoNewPrivileges,
            libc::EPERM,
            "landlock install refused: PR_SET_NO_NEW_PRIVS failed with errno 1",
        ),
        (
            LandlockStep::RestrictSelf,
            libc::EBADF,
            "landlock install refused: landlock_restrict_self failed with errno 9",
        ),
    ];
    let mut seen = Vec::new();
    install_landlock_with(&ruleset, |step| {
        seen.push(step);
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, order);
    for (position, (failed, errno, expected)) in cases.into_iter().enumerate() {
        let mut seen = Vec::new();
        let failure = install_landlock_with(&ruleset, |step| {
            seen.push(step);
            if step == failed {
                Err(errno)
            } else {
                Ok(())
            }
        })
        .expect_err("each failed install step must refuse");
        assert_eq!(
            seen,
            &order[..=position],
            "a refused install must stop at its failed step"
        );
        assert_eq!(failure, LandlockInstallFailure::new(failed, errno));
        assert_eq!(failure.step, failed);
        assert_eq!(failure.errno, errno);
        assert_eq!(failure.to_string(), expected);
    }
}

/// The one record carries each Landlock step's own words across the fork. The
/// test drives `decode_seccomp_launch_record` and
/// `seccomp_launch_answers_or_refusal`, the one decoder and the one place a
/// record becomes a launch result. It reads `LandlockInstallFailure`'s one
/// wording function, so it is not a second copy of
/// `landlock_install_refuses_each_failed_step`, which holds the sequencer's
/// order. An unknown first field keeps the existing unknown-step reason. No
/// case is a bare spawn error.
///
/// The test builds records and reads them. It starts no process and calls no
/// kernel, so it runs on every OS.
///
/// Falsifier: WP211 reads a Landlock step as an installed record, so this test
/// loses that step's reason.
#[test]
fn landlock_install_record_decodes_each_failed_step() {
    let child = "the child started and its install report arrived incomplete";
    let cases = [
        (
            LandlockStep::CreateRuleset,
            libc::EINVAL,
            "landlock install refused: the ruleset could not be created with errno 22",
        ),
        (
            LandlockStep::AddRule(0),
            libc::EACCES,
            "landlock install refused: the path rule 0 could not be added with errno 13",
        ),
        (
            LandlockStep::AddRule(3),
            libc::ENOENT,
            "landlock install refused: the path rule 3 could not be added with errno 2",
        ),
        (
            LandlockStep::NoNewPrivileges,
            libc::EPERM,
            "landlock install refused: PR_SET_NO_NEW_PRIVS failed with errno 1",
        ),
        (
            LandlockStep::RestrictSelf,
            libc::EPERM,
            "landlock install refused: landlock_restrict_self failed with errno 1",
        ),
    ];
    for (step, errno, expected) in cases {
        let failure = LandlockInstallFailure::new(step, errno);
        assert!(
            failure.to_string().contains(&failure.step_words()),
            "the launch words must come from the one wording function"
        );
        assert_eq!(failure.to_string(), expected);
        let record = SeccompInstallFailure::Landlock(failure).launch_record();
        let decoded = decode_seccomp_launch_record(&record)
            .unwrap_or_else(|err| panic!("the record must decode {step:?}: {err}"));
        assert_eq!(
            decoded,
            SeccompLaunchRecord::Refused(SeccompInstallFailure::Landlock(failure)),
            "the one decoder must carry {step:?}"
        );
        let refusal = seccomp_launch_answers_or_refusal(&record, child)
            .expect_err("a Landlock step must be a launch refusal");
        assert_eq!(
            refusal, expected,
            "the launch answer must be the step's own words"
        );
        assert!(
            !refusal.contains("the test child must start"),
            "a Landlock refusal must not be a bare spawn error: {refusal}"
        );
    }

    let mut unknown = [0u8; SECCOMP_LAUNCH_RECORD_LEN];
    unknown[..8].copy_from_slice(&9i64.to_ne_bytes());
    let step_refusal =
        decode_seccomp_launch_record(&unknown).expect_err("an unknown first field must be refused");
    assert_eq!(
        step_refusal,
        "seccomp install report refused: the child named step 9, which is no install step"
    );
    let launch = seccomp_launch_answers_or_refusal(&unknown, child)
        .expect_err("an unknown first field must refuse the launch");
    assert_eq!(
        launch,
        format!("{step_refusal}; {child}"),
        "the unknown first field must keep the record's reason and name the child"
    );
    assert!(
        !launch.contains("the test child must start"),
        "an unknown first field must not be a bare spawn error: {launch}"
    );
}

/// Wallet's ruleset names each measured loader entry with `EXECUTE | READ_FILE`,
/// and the storage-root rule keeps the seven rights the declared row carries.
/// The test builds the ruleset from wallet's committed declared-rights file
/// through `landlock_path_rules` and `LANDLOCK_LOADER_PATHS`. It starts no
/// process and calls no kernel, so it runs on every OS.
///
/// Falsifier: WP212 adds the loader entry without `READ_FILE`, so this test
/// fails on the rule's rights.
#[test]
fn landlock_ruleset_names_each_measured_loader_entry() {
    let declared = read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
        .unwrap_or_else(|err| panic!("{err}"));
    let fixture = tempfile::tempdir().expect("temporary wallet base");
    let base = resolved(fixture.path());
    let bindings = canonical_bindings(WALLET_PROVIDER, &base, Path::new(PROVIDER_BINARY));
    let ruleset = landlock_path_rules(
        WALLET_PROVIDER,
        &declared,
        &bindings,
        7,
        LANDLOCK_LOADER_PATHS,
    )
    .unwrap_or_else(|err| panic!("{err}"));
    let loaders: Vec<_> = ruleset
        .rules
        .iter()
        .filter(|rule| rule.parameter == "LANDLOCK_LOADER_PATHS")
        .collect();
    assert_eq!(
        loaders.len(),
        LANDLOCK_LOADER_PATHS.len(),
        "the ruleset must hold one rule per measured loader entry"
    );
    for (rule, (path, _)) in loaders.iter().zip(LANDLOCK_LOADER_PATHS) {
        assert_eq!(rule.path, PathBuf::from(path));
        assert_eq!(
            rule.rights,
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
            "the loader rule for {path} must carry EXECUTE and READ_FILE"
        );
    }
    let storage = ruleset
        .rules
        .iter()
        .find(|rule| rule.parameter == "STORAGE_ROOT")
        .expect("the ruleset must hold the STORAGE_ROOT rule");
    assert_eq!(
        storage.rights,
        LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG,
        "the storage-root rule must keep the seven rights the declared row carries"
    );
}

/// The one install record writer, and it makes no kernel call: it writes the
/// whole record to `write`, completing a short write and retrying on `EINTR`.
///
/// The install report crosses `pre_exec` as a fixed record, because Rust's
/// exec-error pipe carries only a raw errno and no step. A failed write and a
/// zero-byte write keep their own reasons and their own errno, so the two are
/// told apart (P11).
fn write_seccomp_launch_record(
    record: &[u8],
    mut write: impl FnMut(&[u8]) -> Result<usize, i32>,
) -> Result<(), SeccompLaunchWriteFailure> {
    let mut written = 0;
    while written < record.len() {
        match write(&record[written..]) {
            Ok(0) => return Err(SeccompLaunchWriteFailure::WroteNothing),
            Ok(count) => written += count,
            Err(errno) if errno == libc::EINTR => continue,
            Err(errno) => return Err(SeccompLaunchWriteFailure::Failed(errno)),
        }
    }
    Ok(())
}

/// One of the two ways the install report fails to reach the parent. Each keeps
/// its own reason and errno, so a failed write and a zero-byte write are told
/// apart (P11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeccompLaunchWriteFailure {
    Failed(i32),
    WroteNothing,
}

impl SeccompLaunchWriteFailure {
    fn errno(self) -> i32 {
        match self {
            Self::Failed(errno) => errno,
            Self::WroteNothing => libc::EIO,
        }
    }
}

impl std::fmt::Display for SeccompLaunchWriteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(errno) => write!(
                f,
                "seccomp launch refused: the install record could not be written, errno {errno}"
            ),
            Self::WroteNothing => {
                write!(
                    f,
                    "seccomp launch refused: the install record wrote no bytes"
                )
            }
        }
    }
}

/// The system calls a launch needs beside the forms-derived part, and the call
/// whose failure named each entry. No declared right covers them: they are the
/// runtime's own plumbing, and a launch that loses one cannot speak its
/// protocol.
///
/// The list is measured, not guessed. Each entry earned its place by dropping it
/// alone from the whole list and reading the call that failed on the Linux host
/// the proof ran on, and the comment after each name is that call, quoted from
/// the run. `mount`, `ptrace`, `bpf` and `keyctl` are in no entry here and in no
/// table row, so the default decision is the only answer they receive.
///
/// The table is data and makes no kernel call, so it is compiled on every OS
/// where the list's launch set is compared; the install that reads it stays
/// Linux-only.
const LAUNCH_ESSENTIALS: &[(&str, &str)] = &[
    (
        "close",
        "close(3) refused in the loader, before the first mapping",
    ),
    (
        "exit_group",
        "exit_group(0) refused as the provider ended its own run",
    ),
    (
        "getrandom",
        "getrandom(0xec92ac7c6700, 8, GRND_NONBLOCK) refused in the loader",
    ),
    (
        "mmap",
        "mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) refused \
         in the loader, and the provider then took SIGSEGV",
    ),
    (
        "mprotect",
        "mprotect(0xf2640329f000, 65536, PROT_NONE) refused in the loader",
    ),
    (
        "ppoll",
        "ppoll([{fd=0, events=0}, {fd=1, events=0}, {fd=2, events=0}], 3, {tv_sec=0, \
         tv_nsec=0}, NULL, 0) refused while the provider waits",
    ),
    (
        "rt_sigaction",
        "rt_sigaction(SIGPIPE, {sa_handler=SIG_IGN, sa_mask=[PIPE], sa_flags=SA_RESTART}, \
         0xffffea09ff80, 8) refused in the loader",
    ),
];

/// The largest program the install's stack buffer holds.
#[cfg(target_os = "linux")]
const SECCOMP_PROGRAM_CAPACITY: usize = 256;

/// The one install function, and the only place a seccomp filter becomes a
/// kernel call. The launcher calls it from `pre_exec` and the probe child calls
/// it in-process, so both install the same filter by one path (P10).
///
/// It copies the program into a fixed stack buffer and makes only the two
/// `prctl` calls, in the Runtime's order and through 147's sequencing:
/// `no_new_privs` first, then the filter, each with its own refusal and errno
/// (P11). It allocates nothing after a fork, so a `pre_exec` caller may use it
/// as is. `install_seccomp_with` checks the audit architecture first, so a list
/// built for another architecture is refused before either kernel call.
#[cfg(target_os = "linux")]
fn install_seccomp(allow: &SeccompAllowList) -> Result<(), SeccompInstallFailure> {
    if allow.program.len() > SECCOMP_PROGRAM_CAPACITY {
        // The buffer is fixed because this runs after a fork. A longer program
        // is refused as a failed filter step instead of installed truncated,
        // because a short filter loses rows and could end on an `ALLOW`.
        return Err(SeccompInstallFailure::Step(
            SeccompStep::Filter,
            libc::E2BIG,
        ));
    }
    let mut code = [libc::sock_filter {
        code: 0,
        jt: 0,
        jf: 0,
        k: 0,
    }; SECCOMP_PROGRAM_CAPACITY];
    for (slot, instruction) in code.iter_mut().zip(&allow.program) {
        *slot = libc::sock_filter {
            code: instruction.code,
            jt: instruction.jt,
            jf: instruction.jf,
            k: instruction.k,
        };
    }
    let mut program = libc::sock_fprog {
        len: allow.program.len() as u16,
        filter: code.as_mut_ptr(),
    };
    install_seccomp_with(allow, |step| {
        if let Some((failed, errno)) = allow.injected_step_failure {
            if failed == step {
                return Err(errno);
            }
        }
        let installed = unsafe {
            match step {
                SeccompStep::NoNewPrivileges => libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
                SeccompStep::Filter => libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &mut program as *mut libc::sock_fprog,
                ),
            }
        };
        if installed == 0 {
            return Ok(());
        }
        Err(unsafe { *libc::__errno_location() })
    })
}

/// The `PR_SET_NO_NEW_PRIVS` value `install_landlock` sets before its
/// `restrict_self` call, and the one the seccomp installer also sets. Both
/// installers ask the kernel for the same state. Without it
/// `landlock_restrict_self` fails `EPERM` (1) and nothing is confined.
#[cfg(target_os = "linux")]
const LANDLOCK_NO_NEW_PRIVS: libc::c_int = 1;

/// The Landlock ruleset and path-rule attribute layouts the kernel's
/// `<linux/landlock.h>` declares. They are written here as plain values so the
/// kernel calls take exactly the size and fields the ABI names, and so a reader
/// sees the whole layout in one place.
#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: libc::c_int,
}

/// `LANDLOCK_RULE_PATH_BENEATH`, the one rule type this ruleset uses.
#[cfg(target_os = "linux")]
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

/// `LANDLOCK_CREATE_RULESET_VERSION`, which asks the kernel for the ABI version
/// instead of creating a ruleset.
#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

/// The reported Landlock ABI of the running kernel, read once through
/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`. A kernel
/// without Landlock answers `ENOSYS` or `EOPNOTSUPP`, which is its own refusal
/// so a start says the kernel has no Landlock rather than assuming a version.
///
/// The caller passes the result to `landlock_path_rules`, so the ABI is read once
/// and the ruleset is built against the version the kernel actually reports.
#[cfg(target_os = "linux")]
fn landlock_abi() -> Result<u32, LandlockInstallFailure> {
    let reported = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if reported >= 0 {
        return Ok(reported as u32);
    }
    let errno = unsafe { *libc::__errno_location() };
    // `ENOSYS` and `EOPNOTSUPP` are the kernel's own answer that Landlock is
    // absent. They stay this step's refusal, with that errno, and are not read
    // as ABI 0.
    Err(LandlockInstallFailure::new(
        LandlockStep::CreateRuleset,
        errno,
    ))
}

/// All owned paths are converted before fork. Both child callers take this
/// prepared value, so the installer cannot allocate or perform lossy conversion.
#[cfg(target_os = "linux")]
struct PreparedLandlockRuleset {
    ruleset: LandlockRuleset,
    paths: Vec<std::ffi::CString>,
    /// Negative fixture only: reach restrict_self with no_new_privs still clear.
    skip_no_new_privileges: bool,
}

#[cfg(target_os = "linux")]
impl PreparedLandlockRuleset {
    fn new(ruleset: &LandlockRuleset) -> Result<Self, LandlockInstallFailure> {
        use std::os::unix::ffi::OsStrExt as _;
        let paths = ruleset
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                std::ffi::CString::new(rule.path.as_os_str().as_bytes()).map_err(|_| {
                    LandlockInstallFailure::new(LandlockStep::AddRule(index), libc::EINVAL)
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            ruleset: ruleset.clone(),
            paths,
            skip_no_new_privileges: false,
        })
    }
}

/// The one install function, and the only place a Landlock ruleset becomes a
/// kernel call. The launcher and the probe child both call it, so both install
/// the same policy by one path (P10).
/// It runs `install_landlock_with`'s steps in that order and makes one kernel
/// call for each: `landlock_create_ruleset` with the handled mask the ruleset
/// carries, one `landlock_add_rule` per path rule with an `O_PATH` descriptor
/// on that path, `prctl(PR_SET_NO_NEW_PRIVS)`, and `landlock_restrict_self` on
/// the ruleset descriptor the create step returned. Each failure returns that
/// step's own errno (P11). A rule's descriptor is closed as soon as its rule is
/// added, and the ruleset descriptor is closed on every result, so a refused
/// install leaves no descriptor behind. It allocates nothing after the fork.
///
/// `injected_step_failure` is test input: a launch can be refused at a named
/// step without a kernel that would refuse it, and every real launch has `None`.
#[cfg(target_os = "linux")]
fn install_landlock(prepared: &PreparedLandlockRuleset) -> Result<(), LandlockInstallFailure> {
    let ruleset = &prepared.ruleset;
    let mut descriptor: libc::c_int = -1;
    let result = install_landlock_with(ruleset, |step| {
        if let Some((failed, errno)) = ruleset.injected_step_failure {
            if failed == step {
                return Err(errno);
            }
        }
        // Each arm makes one kernel call and answers its errno. `errno` is read
        // at once, before any later call can overwrite it.
        let (answer, errno) = match step {
            LandlockStep::CreateRuleset => {
                let mut attr = LandlockRulesetAttr {
                    handled_access_fs: ruleset.handled,
                };
                let answer = unsafe {
                    libc::syscall(
                        libc::SYS_landlock_create_ruleset,
                        &mut attr as *mut LandlockRulesetAttr,
                        std::mem::size_of::<LandlockRulesetAttr>(),
                        0u32,
                    )
                };
                let errno = unsafe { *libc::__errno_location() };
                if answer >= 0 {
                    descriptor = answer as libc::c_int;
                }
                (answer, errno)
            }
            LandlockStep::AddRule(index) => {
                let Some(rule) = ruleset.rules.get(index) else {
                    return Err(libc::EINVAL);
                };
                let Some(path) = prepared.paths.get(index) else {
                    return Err(libc::EINVAL);
                };
                let path_descriptor =
                    unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                if path_descriptor < 0 {
                    return Err(unsafe { *libc::__errno_location() });
                }
                let mut attr = LandlockPathBeneathAttr {
                    allowed_access: rule.rights,
                    parent_fd: path_descriptor,
                };
                let answer = unsafe {
                    libc::syscall(
                        libc::SYS_landlock_add_rule,
                        descriptor,
                        LANDLOCK_RULE_PATH_BENEATH,
                        &mut attr as *mut LandlockPathBeneathAttr,
                        0u32,
                    )
                };
                let errno = unsafe { *libc::__errno_location() };
                unsafe { libc::close(path_descriptor) };
                (answer, errno)
            }
            LandlockStep::NoNewPrivileges => {
                if prepared.skip_no_new_privileges {
                    return Ok(());
                }
                let answer = unsafe {
                    libc::prctl(libc::PR_SET_NO_NEW_PRIVS, LANDLOCK_NO_NEW_PRIVS, 0, 0, 0)
                };
                (answer as libc::c_long, unsafe { *libc::__errno_location() })
            }
            LandlockStep::RestrictSelf => {
                let answer =
                    unsafe { libc::syscall(libc::SYS_landlock_restrict_self, descriptor, 0u32) };
                (answer, unsafe { *libc::__errno_location() })
            }
        };
        if answer < 0 {
            Err(errno)
        } else {
            Ok(())
        }
    });
    if descriptor >= 0 {
        unsafe { libc::close(descriptor) };
    }
    result
}

/// The one install record: three signed 64-bit fields, in native byte order,
/// written by the child before it execs. The first field names the outcome, and
/// the other two carry that outcome's two values.
const SECCOMP_LAUNCH_RECORD_LEN: usize = 24;
/// The record's first field when the filter is installed: the marker's answer
/// before the install, then the marker's answer after it.
const SECCOMP_LAUNCH_INSTALLED: i64 = 0;
/// `PR_SET_NO_NEW_PRIVS` failed: the second field is that step's errno.
const SECCOMP_LAUNCH_NO_NEW_PRIVS: i64 = 1;
/// The filter install failed: the second field is that step's errno.
const SECCOMP_LAUNCH_FILTER: i64 = 2;
/// The list was built for another audit architecture: the third field is it.
const SECCOMP_LAUNCH_AUDIT_ARCH: i64 = 3;
/// A Landlock step failed: the second field is the step below and the third is
/// its errno. Encoding these tags belongs to `SeccompInstallFailure::launch_record`.
/// `write_seccomp_launch_record` still writes the finished bytes.
const SECCOMP_LAUNCH_LANDLOCK: i64 = 4;
/// The Landlock steps a record can name, in the record's second field.
const SECCOMP_LAUNCH_LANDLOCK_CREATE: i64 = 0;
/// The first rule position; a rule's record value is this plus its position.
const SECCOMP_LAUNCH_LANDLOCK_ADD_FIRST: i64 = 1;
/// `PR_SET_NO_NEW_PRIVS` failed inside the Landlock install. It is a value no
/// rule position can take, because a ruleset holds far fewer rules than this.
const SECCOMP_LAUNCH_LANDLOCK_NO_NEW_PRIVS: i64 = 1_000_000;
/// `landlock_restrict_self` failed.
const SECCOMP_LAUNCH_LANDLOCK_RESTRICT_SELF: i64 = 1_000_001;

/// One child's install report, read from the fixed record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeccompLaunchRecord {
    /// The filter is installed: the marker's answer before and after it.
    Installed([i64; 2]),
    /// The install refused at this step, with its errno.
    Refused(SeccompInstallFailure),
}

/// The one record reader. A record that is not exactly one record's length is
/// `RecordLength`, and a first field that names no outcome is `UnknownStep`, so
/// each has its own reason and neither reads as a bare spawn error (P11).
///
/// The refusal names only counts and no bytes: a partly written record is the
/// child's report, not evidence to quote.
fn decode_seccomp_launch_record(record: &[u8]) -> Result<SeccompLaunchRecord, String> {
    if record.len() != SECCOMP_LAUNCH_RECORD_LEN {
        return Err(format!(
            "seccomp install report refused: the child reported {} bytes and one record is {}",
            record.len(),
            SECCOMP_LAUNCH_RECORD_LEN
        ));
    }
    let mut fields = [0i64; 3];
    for (field, bytes) in fields.iter_mut().zip(record.chunks_exact(8)) {
        *field = i64::from_ne_bytes(bytes.try_into().expect("one 8-byte record field"));
    }
    let [step, first, second] = fields;
    match step {
        SECCOMP_LAUNCH_INSTALLED => Ok(SeccompLaunchRecord::Installed([first, second])),
        SECCOMP_LAUNCH_NO_NEW_PRIVS => Ok(SeccompLaunchRecord::Refused(
            SeccompInstallFailure::Step(SeccompStep::NoNewPrivileges, first as i32),
        )),
        SECCOMP_LAUNCH_FILTER => Ok(SeccompLaunchRecord::Refused(SeccompInstallFailure::Step(
            SeccompStep::Filter,
            first as i32,
        ))),
        SECCOMP_LAUNCH_AUDIT_ARCH => Ok(SeccompLaunchRecord::Refused(
            SeccompInstallFailure::AuditArchitecture(second as u32),
        )),
        SECCOMP_LAUNCH_LANDLOCK => {
            let failure = LandlockInstallFailure::from_record(first, second as i32).ok_or_else(
                || {
                    format!(
                        "seccomp install report refused: the child named step {first}, which is no install step"
                    )
                },
            )?;
            Ok(SeccompLaunchRecord::Refused(
                SeccompInstallFailure::Landlock(failure),
            ))
        }
        other => Err(format!(
            "seccomp install report refused: the child named step {other}, which is no install step"
        )),
    }
}

/// The one place a launched child's install report becomes the launcher's
/// answer: the marker's two answers when the filter is installed, that step's
/// own reason when the install refused, and, for a record that is missing,
/// short, long or names an unknown step, the record reader's reason together
/// with what the child did instead.
///
/// `child` describes the launched child: it did not start, with the reason the
/// spawn gave, or it started and reported nothing. A child whose own write
/// failed or that never ran leaves no record, so without this the caller would
/// receive a bare spawn error and lose the reason the install report carries.
/// The reader reads bytes and makes no kernel call, so every OS can hold it.
fn seccomp_launch_answers_or_refusal(record: &[u8], child: &str) -> Result<[i64; 2], String> {
    match decode_seccomp_launch_record(record) {
        Ok(SeccompLaunchRecord::Installed(answers)) => Ok(answers),
        Ok(SeccompLaunchRecord::Refused(failure)) => Err(failure.to_string()),
        Err(refusal) => Err(format!("{refusal}; {child}")),
    }
}

/// What one marker call answers in this process right now: the errno it failed
/// with, or the value it returned.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeccompAnswer {
    Errno(i32),
    Returned(i64),
}

#[cfg(target_os = "linux")]
impl SeccompAnswer {
    /// The answer as the probe writes it and reads it back: `errno:<n>` for a
    /// failed call and `ok:<n>` for one that returned.
    fn text(self) -> String {
        match self {
            Self::Errno(errno) => format!("errno:{errno}"),
            Self::Returned(value) => format!("ok:{value}"),
        }
    }

    /// The answer a probe record token names, or `None` when it names none.
    fn parse(token: &str) -> Option<Self> {
        if let Some(errno) = token.strip_prefix("errno:") {
            return errno.parse().ok().map(Self::Errno);
        }
        token
            .strip_prefix("ok:")
            .and_then(|value| value.parse().ok())
            .map(Self::Returned)
    }
}

/// Runs one kernel call and turns it into its answer. One reader serves every
/// probe call, so the four calls cannot measure their failures differently.
#[cfg(target_os = "linux")]
fn seccomp_answer(call: impl FnOnce() -> i64) -> SeccompAnswer {
    let answer = call();
    if answer == -1 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .expect("a failed call must carry an errno");
        SeccompAnswer::Errno(errno)
    } else {
        SeccompAnswer::Returned(answer)
    }
}

/// The call whose answer distinguishes this filter from the host: a `bpf`
/// request with an invalid command and null attributes, which the kernel
/// refuses with `EINVAL` and which this filter refuses with the deny marker.
///
/// The marker is read before and after the install in the same process, so a
/// child that inherits a filter from its parent cannot show the change. The
/// answer is negative for an errno, so a returned value is distinguishable.
#[cfg(target_os = "linux")]
fn seccomp_launch_marker_answer() -> i64 {
    let answer = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            -1 as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
        )
    };
    if answer == -1 {
        -i64::from(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        answer
    }
}

/// The four calls the filter refuses and no allow form names. The journey
/// requires each of them to answer the deny marker after the install and to
/// answer something else before it, so a host that already refuses a call
/// cannot stand in for the filter.
#[cfg(target_os = "linux")]
const SECCOMP_PROBE_CALLS: &[&str] = &["ptrace", "mount", "bpf", "keyctl"];

/// The keyring `keyctl` names in the probe: the session keyring. It is a real
/// keyring this process is expected to hold, so without the filter the call
/// answers a usable id and the filter's refusal is the only reason it stops.
const SECCOMP_PROBE_KEYRING: libc::c_long = -3;

/// The `keyctl` request the probe makes: `KEYCTL_GET_KEYRING_ID`, command `0`.
const SECCOMP_PROBE_KEYCTL_GET_KEYRING_ID: libc::c_long = 0;

/// How many registers `keyctl` reads for the probe's request: the command, the
/// keyring, the create flag and two unused arguments.
const SECCOMP_PROBE_KEYCTL_ARGUMENTS: usize = 5;

/// Every argument the probe passes to one call, so the call's whole argument
/// list is visible in one place and no register is left to chance.
///
/// `keyctl`'s command decides how many of its other arguments the kernel reads,
/// and command `0` reads a special keyring id that may hold `-1` to `-9`. A
/// call that passed a shorter argument list would leave the registers after it
/// unspecified, so the kernel could select another keyring or be asked to
/// create one. This table names all of them: the command, the keyring, and a
/// create flag of `0` that refuses creation, followed by two unused zeros. It
/// carries no kernel call, so every OS can read it.
const SECCOMP_PROBE_KEYCTL_TABLE: [libc::c_long; SECCOMP_PROBE_KEYCTL_ARGUMENTS] = [
    SECCOMP_PROBE_KEYCTL_GET_KEYRING_ID,
    SECCOMP_PROBE_KEYRING,
    0,
    0,
    0,
];

/// The `keyctl` probe passes its complete argument list: command `0`, a named
/// keyring, and a create flag of `0` that refuses creation, with two unused
/// zeros behind it. The command's own reference makes all of these arguments
/// part of the request, and a short argument list would leave the kernel
/// reading registers this probe never set, so it could select another keyring
/// or be asked to create one.
///
/// The test reads the table and the probe's call, so a call that passed fewer
/// arguments than the command reads fails here even though the call compiles.
/// It makes no kernel call and starts no process, so it runs on every OS.
///
/// Falsifier: WP166 passes only the command to `keyctl`, so the call's own
/// list omits the keyring, create flag and unused arguments while the table
/// still supplies the complete fixture.
#[test]
fn seccomp_keyctl_probe_supplies_every_argument_without_creation() {
    assert_eq!(
        SECCOMP_PROBE_KEYCTL_TABLE[0], SECCOMP_PROBE_KEYCTL_GET_KEYRING_ID,
        "the probe must make the KEYCTL_GET_KEYRING_ID request"
    );
    assert_eq!(
        SECCOMP_PROBE_KEYCTL_TABLE[1], SECCOMP_PROBE_KEYRING,
        "the probe must name the keyring it reads, and a special id is a real id"
    );
    assert!(
        SECCOMP_PROBE_KEYCTL_TABLE[1] < 0 && SECCOMP_PROBE_KEYCTL_TABLE[1] >= -9,
        "the keyring must be a special keyring id, which is -1 to -9: {}",
        SECCOMP_PROBE_KEYCTL_TABLE[1]
    );
    assert_eq!(
        SECCOMP_PROBE_KEYCTL_TABLE[2], 0,
        "the create flag must be 0, because a probe asks for no keyring to be created"
    );
    assert_eq!(
        SECCOMP_PROBE_KEYCTL_TABLE[3..],
        [0; SECCOMP_PROBE_KEYCTL_ARGUMENTS - 3],
        "the arguments after the create flag are unused and must be named as zeros"
    );

    // The call's own argument list, read from the source that makes it, so a
    // probe that passed a shorter list cannot pass on a table it never uses.
    let source = fs::read_to_string(Path::new("tests/confine.rs"))
        .expect("this test's own source must be readable");
    let signature = "fn seccomp_probe_answers(call: &str) -> SeccompAnswer {";
    let call = source
        .rsplit_once(signature)
        .map(|(_, call)| call)
        .expect("the probe must hold its one call reader");
    let keyctl = call
        .split("\"keyctl\" =>")
        .nth(1)
        .expect("the probe must hold its keyctl arm");
    let keyctl = keyctl
        .split("other =>")
        .next()
        .expect("the keyctl arm must end before the catch-all");
    assert!(
        keyctl.contains("libc::syscall(libc::SYS_keyctl, command, keyring, create, first, second)"),
        "the keyctl call must pass the table's five arguments and no register it did not set: \
         {keyctl}"
    );
    assert!(
        keyctl.contains(
            "let [command, keyring, create, first, second] = SECCOMP_PROBE_KEYCTL_TABLE;"
        ),
        "the keyctl call must read its whole argument list from the one table: {keyctl}"
    );
}

/// What `call` answers in this process right now. The probe child calls this
/// once before the filter and once after, through the same function, so the two
/// records cannot differ in what they measure. Each arm passes its complete
/// argument list: no call relies on a register this function did not set.
#[cfg(target_os = "linux")]
fn seccomp_probe_answers(call: &str) -> SeccompAnswer {
    match call {
        "ptrace" => {
            seccomp_answer(|| unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) as i64 })
        }
        "mount" => seccomp_answer(|| unsafe {
            libc::mount(
                c"/nonexistent-seccomp-probe-source".as_ptr(),
                c"/nonexistent-seccomp-probe-target".as_ptr(),
                c"none".as_ptr(),
                0,
                std::ptr::null(),
            ) as i64
        }),
        "bpf" => seccomp_answer(|| unsafe {
            libc::syscall(
                libc::SYS_bpf,
                0 as libc::c_long,
                0 as libc::c_long,
                0 as libc::c_long,
            )
        }),
        "keyctl" => seccomp_answer(|| unsafe {
            let [command, keyring, create, first, second] = SECCOMP_PROBE_KEYCTL_TABLE;
            libc::syscall(libc::SYS_keyctl, command, keyring, create, first, second)
        }),
        other => panic!("the probe names no call {other}"),
    }
}

/// The allow list is an allow list, not a deny list.
///
/// The program's final decision is the deny marker, and every `ALLOW` return is
/// reachable only through an equality test against a number the list names: the
/// test walks each test's true and false jump and requires the true jump to land
/// on its `ALLOW` and the false jump to step over it, so a changed jump target
/// fails even when the syscall number is right. It then collects every number
/// the program tests and requires that set to equal the numbers the admitted
/// syscalls name, so a number swapped for an undeclared call's fails even when
/// every jump target is right.
///
/// It also holds the architecture guard: a program whose audit-arch test
/// refused the target instead of admitting it would deny every call, and one
/// with no guard would read another architecture's numbers as its own. A
/// fixture program built for the other architecture shows the guard is part of
/// the program and falls through to the marker.
///
/// The test reads the built program, starts no process and calls no kernel, so
/// it runs on every OS.
///
/// Falsifier: WP146 replaces the default decision with `ALLOW` and refuses only
/// `socket`, `connect` and `execve`, so the last instruction allows. WP150
/// admits both architecture branches. WP151 makes a false jump land on its own
/// `ALLOW`, so a call the test does not name is admitted. WP161 tests `ptrace`'s
/// number where an admitted syscall's belongs, so the program tests a number no
/// row names and admits a call the list never derived.
#[test]
fn seccomp_program_denies_by_default_and_lists_no_undeclared_call() {
    let declared = read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
        .unwrap_or_else(|err| panic!("{err}"));
    let allow = seccomp_allow_list_from_declared_rights(WALLET_PROVIDER, &declared)
        .unwrap_or_else(|err| panic!("{err}"));
    let program = &allow.program;

    let last = program.last().expect("the program must hold a decision");
    assert_eq!(
        *last,
        SeccompInstruction::stmt(SECCOMP_BPF_RET_K, seccomp_deny_return()),
        "the final decision must be the deny marker, not ALLOW"
    );

    let mut allowed = 0usize;
    for (index, instruction) in program.iter().enumerate() {
        if instruction.code != SECCOMP_BPF_RET_K || instruction.k != SECCOMP_RET_ALLOW {
            continue;
        }
        allowed += 1;
        let test_index = index
            .checked_sub(1)
            .expect("an ALLOW return must follow its equality test");
        let test = program[test_index];
        assert_eq!(
            test.code, SECCOMP_BPF_JEQ_K,
            "instruction {index} allows without an equality test in front of it"
        );
        assert_eq!(
            index + usize::from(test.jt),
            index,
            "instruction {test_index} must jump to its own ALLOW on a true test"
        );
        assert_eq!(
            index + usize::from(test.jf),
            index + 1,
            "instruction {test_index} must step over its ALLOW on a false test"
        );
        assert_eq!(
            test.jt, 0,
            "instruction {test_index} must not jump past its own ALLOW on a true test"
        );
        assert_eq!(
            test.jf, 1,
            "instruction {test_index} must step over its own ALLOW on a false test"
        );
    }
    assert_eq!(
        allowed,
        allow.syscalls.len(),
        "the program must hold one ALLOW per admitted syscall"
    );

    // Every equality test names a number the list admits, and every admitted
    // syscall has its own equality test: a number swapped for an undeclared
    // call's passes the layout checks above but fails here.
    let mut expected: Vec<u32> = allow
        .syscalls
        .iter()
        .filter_map(|syscall| seccomp_syscall_number(syscall, SECCOMP_AUDIT_ARCH))
        .collect();
    expected.sort_unstable();
    let mut tested: Vec<u32> = program
        .iter()
        .filter(|instruction| instruction.code == SECCOMP_BPF_JEQ_K)
        .map(|instruction| instruction.k)
        .filter(|number| *number != SECCOMP_AUDIT_ARCH)
        .collect();
    tested.sort_unstable();
    for number in &tested {
        assert!(
            expected.contains(number),
            "the program must test only admitted syscall numbers, and {number} is in no row: {:?}",
            allow.syscalls
        );
    }
    assert_eq!(
        tested, expected,
        "the program must test exactly the admitted syscall numbers: {:?}",
        allow.syscalls
    );

    for denied in ["bpf", "keyctl", "mount", "ptrace"] {
        assert!(
            !allow.admits(denied),
            "{denied} must be in no allow-list entry, so the default decision refuses it"
        );
        let Some(number) = seccomp_syscall_number(denied, SECCOMP_AUDIT_ARCH) else {
            continue;
        };
        assert!(
            !program
                .iter()
                .any(|instruction| instruction.code == SECCOMP_BPF_JEQ_K
                    && instruction.k == number),
            "the program must test no equality against {denied}'s number {number}"
        );
    }

    // The audit-arch check reads `seccomp_data.arch`, jumps to its admit arm
    // only for this target's architecture, and falls through to the marker.
    assert_eq!(
        program[0],
        SeccompInstruction::stmt(SECCOMP_BPF_LD_W_ABS, SECCOMP_ARCH_OFFSET),
        "the program must load seccomp_data.arch first"
    );
    assert_eq!(
        program[1],
        SeccompInstruction::jump(SECCOMP_BPF_JEQ_K, SECCOMP_AUDIT_ARCH, 1, 0),
        "the architecture test must jump to its admit arm only for {SECCOMP_AUDIT_ARCH:#x}"
    );
    assert_eq!(
        program[2],
        SeccompInstruction::stmt(SECCOMP_BPF_RET_K, seccomp_deny_return()),
        "a wrong architecture must be refused with the deny marker"
    );
    assert_eq!(
        program[3],
        SeccompInstruction::stmt(SECCOMP_BPF_LD_W_ABS, SECCOMP_NUMBER_OFFSET),
        "the admit arm must load seccomp_data.nr"
    );

    // A program built for the other architecture carries that architecture in
    // its guard and the other architecture's numbers, so the guard is part of
    // the program and not of the caller.
    for foreign in [0xc000_003e, 0xc000_00b7]
        .into_iter()
        .filter(|arch| *arch != SECCOMP_AUDIT_ARCH)
    {
        let fixture = seccomp_program(&["read"], foreign);
        assert_eq!(
            fixture[1],
            SeccompInstruction::jump(SECCOMP_BPF_JEQ_K, foreign, 1, 0),
            "a fixture program must guard its own architecture {foreign:#x}"
        );
        assert_eq!(
            fixture[2],
            SeccompInstruction::stmt(SECCOMP_BPF_RET_K, seccomp_deny_return()),
            "the foreign fixture's wrong-architecture arm must be the deny marker"
        );
        assert_eq!(
            fixture.last(),
            Some(&SeccompInstruction::stmt(
                SECCOMP_BPF_RET_K,
                seccomp_deny_return()
            )),
            "the foreign fixture must also deny by default"
        );
    }
}

/// The allow list follows the declared rights: the file syscalls of `storage`
/// and the exec syscalls of `bound-executable` come from the two rights, a copy
/// of the file without `storage` yields a list without the calls only that right
/// brings, a copy with no allow form at all yields an empty list and a program
/// with no `ALLOW` decision, and a copy holding an id the shared contract does
/// not name is refused with `declared_entries`' existing reason, unchanged.
///
/// The removed right's own calls are the ones the startup-root-directory row
/// does not also grant, because that row still admits `read`, `openat` and the
/// other reads of an opened file. The empty case is the one that forbids a
/// second permission source: the builder adds no syscall of its own beside the
/// rows an allow form selects. The test reads the committed fixture, starts no
/// process and calls no kernel, so it runs on every OS.
///
/// Falsifier: WP147 makes the builder return a fixed list and ignore its
/// declared input, so neither the removal case nor its syscalls change. WP160
/// adds an unconditional syscall beside the rows, so the empty case admits it
/// and this test fails on the empty list.
#[test]
fn seccomp_allow_list_follows_the_declared_rights() {
    let declared = read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
        .unwrap_or_else(|err| panic!("{err}"));
    let allow = seccomp_allow_list_from_declared_rights(WALLET_PROVIDER, &declared)
        .unwrap_or_else(|err| panic!("{err}"));

    for syscall in ["execve", "execveat"] {
        assert!(
            allow.admits(syscall),
            "the bound-executable row must admit {syscall}: {:?}",
            allow.syscalls
        );
    }
    for syscall in ["mkdirat", "write", "unlinkat", "renameat2", "fchmod"] {
        assert!(
            allow.admits(syscall),
            "the storage rows must admit {syscall}: {:?}",
            allow.syscalls
        );
    }

    let mut without_storage = declared.clone();
    without_storage["rights"]
        .as_array_mut()
        .expect("the declared rights must hold a rights list")
        .retain(|entry| entry["id"] != "storage");
    let reduced = seccomp_allow_list_from_declared_rights(WALLET_PROVIDER, &without_storage)
        .unwrap_or_else(|err| panic!("{err}"));
    for syscall in ["mkdirat", "write", "unlinkat", "renameat2", "fchmod"] {
        assert!(
            allow.admits(syscall),
            "the storage right must admit {syscall}: {:?}",
            allow.syscalls
        );
        assert!(
            !reduced.admits(syscall),
            "removing the storage right must remove {syscall} from the list: {:?}",
            reduced.syscalls
        );
    }
    assert!(
        reduced.admits("execve"),
        "the bound-executable right stays, so execve stays: {:?}",
        reduced.syscalls
    );
    assert!(
        reduced.admits("read"),
        "the startup-root-directory row still admits read: {:?}",
        reduced.syscalls
    );

    // A declaration with no allow form grants nothing: the list is empty and the
    // program holds no `ALLOW` decision, so a builder that adds a syscall of its
    // own beside the rows shows here.
    let mut empty = declared.clone();
    empty["rights"]
        .as_array_mut()
        .expect("the declared rights must hold a rights list")
        .clear();
    empty[PLATFORM_BASELINE]["rules"]
        .as_array_mut()
        .expect("the platform baseline must hold a rules list")
        .clear();
    let nothing = seccomp_allow_list_from_declared_rights(WALLET_PROVIDER, &empty)
        .unwrap_or_else(|err| panic!("{err}"));
    assert!(
        nothing.syscalls.is_empty(),
        "a declaration with no allow form must admit no syscall: {:?}",
        nothing.syscalls
    );
    assert!(
        !nothing
            .program
            .iter()
            .any(|instruction| instruction.code == SECCOMP_BPF_RET_K
                && instruction.k == SECCOMP_RET_ALLOW),
        "a program built from no allow form must hold no ALLOW decision"
    );
    assert_eq!(
        nothing.program.last(),
        Some(&SeccompInstruction::stmt(
            SECCOMP_BPF_RET_K,
            seccomp_deny_return()
        )),
        "a program built from no allow form must end on the deny marker"
    );

    let mut unnamed = declared.clone();
    unnamed["rights"]
        .as_array_mut()
        .expect("the declared rights must hold a rights list")
        .push(json!({
            "id": "unnamed-right",
            "rules": [r#"(allow file-read* (literal "/private/var/cc-seccomp-unnamed"))"#],
        }));
    let refusal = seccomp_allow_list_from_declared_rights(WALLET_PROVIDER, &unnamed)
        .expect_err("an id the shared contract does not name must be refused");
    assert_eq!(
        refusal,
        format!(
            "{WALLET_PROVIDER} declares unnamed-right, which the shared contract does not name"
        ),
        "the refusal must be declared_entries' own reason, unchanged"
    );
}

/// An allow form the mapping table does not hold is a refusal that names the
/// provider and the form and builds no filter, symmetrical to
/// `check_profile_contract`'s refusals.
///
/// Each of the three spellings of an allow form is tried: `(allow)`,
/// `(allow(file-read*))` and the spaced `(allow file-read*)`. All three are
/// allow forms to the one recogniser, and none of them is a row of the mapping
/// table, so each is refused by name. The test reads the committed fixture,
/// starts no process and calls no kernel, so it runs on every OS.
///
/// Falsifier: WP148 skips an allow form with no row instead of refusing it, so
/// the list is built and no refusal comes. WP149 makes the recogniser require a
/// space after the operator, so `(allow)` and `(allow(file-read*))` are not
/// allow forms, take no row and are read as head forms instead of refused.
#[test]
fn seccomp_rejects_unmapped_allow_form() {
    let declared = read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
        .unwrap_or_else(|err| panic!("{err}"));
    for form in [
        "(allow)",
        r#"(allow(file-read* (literal "/private/var/cc-seccomp-unmapped")))"#,
        r#"(allow mach-lookup (global-name "com.apple.system.logger"))"#,
    ] {
        let mut unmapped = declared.clone();
        let storage = unmapped["rights"]
            .as_array_mut()
            .expect("the declared rights must hold a rights list")
            .iter_mut()
            .find(|entry| entry["id"] == "storage")
            .expect("the declared rights must hold the storage right");
        storage["rules"]
            .as_array_mut()
            .expect("the storage right must hold a rules list")
            .push(json!(form));

        let refusal = seccomp_allow_list_from_declared_rights(WALLET_PROVIDER, &unmapped)
            .expect_err("an allow form with no syscall row must be refused");
        assert!(
            refusal.contains(WALLET_PROVIDER),
            "the refusal must name the provider: {refusal}"
        );
        assert!(
            refusal.contains(form),
            "the refusal must quote the offending form: {refusal}"
        );
        assert!(
            refusal.contains("no filter is built"),
            "the refusal must state that no filter is built: {refusal}"
        );
        assert_eq!(
            refusal,
            format!(
                "{WALLET_PROVIDER} seccomp allow list refuses the allow form {form}: \
                 the mapping table has no syscall row for it, so no filter is built"
            )
        );
    }
}

/// The install rule gives each failed step its own reason and keeps its errno:
/// `PR_SET_NO_NEW_PRIVS` failing and the filter failing are told apart, each
/// message carries the errno it read, a failed first step stops before the
/// filter, and the two steps run in that order.
///
/// The test injects the steps, so it runs on every OS and calls no kernel.
///
/// Falsifier: WP152 reverses the two steps, so the filter runs before
/// `no_new_privs` and the test fails on its recorded order. WP153 returns one
/// fixed reason for both steps, so the second step's refusal names the first
/// step and the test fails on it. WP154 continues after a failed first step, so
/// the test fails on its recorded order.
#[test]
fn seccomp_install_refuses_each_failed_step() {
    let declared = read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
        .unwrap_or_else(|err| panic!("{err}"));
    let allow = seccomp_allow_list_from_declared_rights(WALLET_PROVIDER, &declared)
        .unwrap_or_else(|err| panic!("{err}"));

    let mut ran: Vec<SeccompStep> = Vec::new();
    let failure = install_seccomp_with(&allow, |step| {
        ran.push(step);
        if step == SeccompStep::NoNewPrivileges {
            Err(libc::EPERM)
        } else {
            Ok(())
        }
    })
    .expect_err("a failed no_new_privs step must be refused");
    assert_eq!(
        failure.to_string(),
        format!(
            "seccomp install refused: PR_SET_NO_NEW_PRIVS failed with errno {}",
            libc::EPERM
        ),
        "the first step's refusal must name that step and its errno"
    );
    assert_eq!(
        ran,
        vec![SeccompStep::NoNewPrivileges],
        "a failed first step must stop before the filter"
    );

    let mut ran: Vec<SeccompStep> = Vec::new();
    let failure = install_seccomp_with(&allow, |step| {
        ran.push(step);
        if step == SeccompStep::Filter {
            Err(libc::EINVAL)
        } else {
            Ok(())
        }
    })
    .expect_err("a failed filter step must be refused");
    assert_eq!(
        failure.to_string(),
        format!(
            "seccomp install refused: the filter install failed with errno {}",
            libc::EINVAL
        ),
        "the filter step's refusal must name that step and its errno"
    );
    assert_eq!(
        ran,
        vec![SeccompStep::NoNewPrivileges, SeccompStep::Filter],
        "the filter runs after no_new_privs"
    );

    let first = SeccompInstallFailure::Step(SeccompStep::NoNewPrivileges, libc::EPERM);
    let second = SeccompInstallFailure::Step(SeccompStep::Filter, libc::EPERM);
    assert_ne!(
        first.to_string(),
        second.to_string(),
        "the two steps must give distinct reasons for one errno"
    );

    let mut wrong_arch = allow.clone();
    wrong_arch.audit_arch = SECCOMP_AUDIT_ARCH.wrapping_add(1);
    let failure = install_seccomp_with(&wrong_arch, |_| {
        panic!("the architecture refusal precedes both kernel steps")
    })
    .expect_err("a list built for another architecture must be refused");
    assert!(
        failure.to_string().contains("audit architecture"),
        "the refusal must name the audit architecture: {failure}"
    );
}

/// The install record's two reporting failures each keep their own reason and
/// errno, and the two reasons differ: a failed write and a zero-byte write are
/// told apart. The write loop completes a short write and retries on `EINTR`
/// instead of giving up.
///
/// The test reads the one pure write function and calls no kernel, so it runs on
/// every OS.
///
/// Falsifier: WP155 truncates the record at its first short write, so the loop
/// stops early and the test fails on the record it expects. WP156 suppresses the
/// `EINTR` retry, so the interrupted write is reported as a failure and the test
/// fails on it. WP157 returns one fixed reason for both reporting failures, so
/// the test fails because the two reasons are equal.
#[test]
fn seccomp_launch_refuses_each_reporting_failure() {
    let record = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    // A short write is completed, and `EINTR` is retried, so the whole record
    // arrives.
    let mut written: Vec<u8> = Vec::new();
    let mut calls = 0usize;
    write_seccomp_launch_record(&record, |bytes| {
        calls += 1;
        match calls {
            1 => {
                written.extend_from_slice(&bytes[..2]);
                Ok(2)
            }
            2 => Err(libc::EINTR),
            _ => {
                written.extend_from_slice(&bytes[..1]);
                Ok(1)
            }
        }
    })
    .expect("a short write and an interrupted write must both be completed");
    assert_eq!(
        written,
        record.to_vec(),
        "the loop must write every byte of the record"
    );
    assert_eq!(
        calls,
        record.len(),
        "the loop must retry after EINTR and finish one byte at a time"
    );

    let failed = write_seccomp_launch_record(&record, |_| Err(libc::EPIPE))
        .expect_err("a failed write must be refused");
    assert_eq!(failed, SeccompLaunchWriteFailure::Failed(libc::EPIPE));
    assert_eq!(failed.errno(), libc::EPIPE);

    let nothing = write_seccomp_launch_record(&record, |_| Ok(0))
        .expect_err("a zero-byte write must be refused");
    assert_eq!(nothing, SeccompLaunchWriteFailure::WroteNothing);
    assert_eq!(nothing.errno(), libc::EIO);

    assert_ne!(
        failed.to_string(),
        nothing.to_string(),
        "the two reporting failures must give distinct reasons"
    );
    assert!(
        failed.to_string().contains("could not be written")
            && failed
                .to_string()
                .contains(&format!("errno {}", libc::EPIPE)),
        "the failed write must carry its own words and errno: {failed}"
    );
    assert!(
        nothing.to_string().contains("wrote no bytes"),
        "the zero-byte write must carry its own words: {nothing}"
    );
}

/// The install record's shape decides the launch reason: a record that is
/// missing, short, long or names an unknown step is a refusal with its own
/// words and never a bare spawn error, and a complete installed record carries
/// the two marker answers the journey compares.
///
/// The launcher's own answer is read through `seccomp_launch_answers_or_refusal`,
/// the one place the record becomes a launch result, so a child that never wrote
/// a record keeps the record's reason and adds what it did instead. A failed
/// write, a zero-byte write, a child that did not start and a child that started
/// and reported nothing each give their own refusal, and no case is the bare
/// spawn error finding 4 named.
///
/// The test reads the one pure record reader and parses no bytes a kernel wrote,
/// so it runs on every OS.
///
/// Falsifier: WP163 accepts any record length, so a short record decodes as an
/// installed one and the missing-length refusal does not come. WP164 decodes an
/// unknown first field as an installed record, so the unknown-step refusal does
/// not come. WP167 bypasses the reader when the child also failed to start, so
/// the missing-report case answers the spawn's reason alone and the test fails
/// on it.
#[test]
fn seccomp_launch_record_refuses_missing_or_unknown_report() {
    let missing = decode_seccomp_launch_record(&[]).expect_err("a missing record must be refused");
    assert_eq!(
        missing,
        format!(
            "seccomp install report refused: the child reported 0 bytes and one record is \
             {SECCOMP_LAUNCH_RECORD_LEN}"
        ),
        "a missing record must name its own reason"
    );

    let mut reasons: Vec<String> = vec![missing.clone()];
    for length in [SECCOMP_LAUNCH_RECORD_LEN - 8, SECCOMP_LAUNCH_RECORD_LEN + 8] {
        let record = vec![0u8; length];
        let refusal = decode_seccomp_launch_record(&record)
            .expect_err("a short or long record must be refused");
        assert_eq!(
            refusal,
            format!(
                "seccomp install report refused: the child reported {length} bytes and one \
                 record is {SECCOMP_LAUNCH_RECORD_LEN}"
            ),
            "a record of {length} bytes must name its length and the record's"
        );
        reasons.push(refusal);
    }

    let mut unknown = [0u8; SECCOMP_LAUNCH_RECORD_LEN];
    unknown[..8].copy_from_slice(&7i64.to_ne_bytes());
    let refusal =
        decode_seccomp_launch_record(&unknown).expect_err("an unknown step must be refused");
    assert_eq!(
        refusal, "seccomp install report refused: the child named step 7, which is no install step",
        "an unknown step must name the step the child gave"
    );
    reasons.push(refusal);
    assert_eq!(
        reasons.len(),
        reasons
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        "each record case must give its own reason: {reasons:?}"
    );

    // The launcher's own answer, one case per child outcome. Each keeps the
    // record's reason and names what the child did instead, and no case is the
    // bare spawn error.
    let mut launch_reasons: Vec<String> = Vec::new();
    for (record, child) in [
        (
            Vec::new(),
            "the test child must start: No such file or directory (os error 2)",
        ),
        (
            Vec::new(),
            "the child started and its install report arrived incomplete",
        ),
        (
            vec![0u8; SECCOMP_LAUNCH_RECORD_LEN - 8],
            "the child started and its install report arrived incomplete",
        ),
        (
            unknown.to_vec(),
            "the child started and its install report arrived incomplete",
        ),
    ] {
        let refusal = seccomp_launch_answers_or_refusal(&record, child)
            .expect_err("a record this child did not complete must be refused");
        assert!(
            refusal.starts_with("seccomp install report refused: "),
            "the launcher's refusal must carry the record's reason: {refusal}"
        );
        assert!(
            refusal.contains(child),
            "the launcher's refusal must say what the child did instead: {refusal}"
        );
        launch_reasons.push(refusal);
    }
    let missing_report = &launch_reasons[0];
    assert!(
        missing_report.contains("reported 0 bytes"),
        "a child that never reported must answer the missing-report reason, not the spawn's \
         alone: {missing_report}"
    );
    assert_eq!(
        launch_reasons.len(),
        launch_reasons
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        "each child outcome must give its own reason: {launch_reasons:?}"
    );
    assert_eq!(
        seccomp_launch_answers_or_refusal(
            &seccomp_launch_record(
                SECCOMP_LAUNCH_INSTALLED,
                -i64::from(libc::EINVAL),
                -i64::from(SECCOMP_DENY_ERRNO),
            ),
            "the child started and reported an installed filter"
        )
        .expect("a complete installed record must answer the launcher's two answers"),
        [-i64::from(libc::EINVAL), -i64::from(SECCOMP_DENY_ERRNO)],
        "the launcher must carry the marker's two answers"
    );

    let installed = decode_seccomp_launch_record(&seccomp_launch_record(
        SECCOMP_LAUNCH_INSTALLED,
        -i64::from(libc::EINVAL),
        -i64::from(SECCOMP_DENY_ERRNO),
    ))
    .expect("a complete installed record must decode");
    assert_eq!(
        installed,
        SeccompLaunchRecord::Installed([-i64::from(libc::EINVAL), -i64::from(SECCOMP_DENY_ERRNO)]),
        "an installed record must carry the marker's answer before and after the install"
    );

    for (step, errno) in [
        (SECCOMP_LAUNCH_NO_NEW_PRIVS, libc::EPERM),
        (SECCOMP_LAUNCH_FILTER, libc::EINVAL),
    ] {
        let decoded =
            decode_seccomp_launch_record(&seccomp_launch_record(step, i64::from(errno), 0))
                .expect("a failed-step record must decode");
        let SeccompLaunchRecord::Refused(failure) = decoded else {
            panic!("a failed step must decode as a refusal");
        };
        assert_eq!(
            failure.launch_record(),
            seccomp_launch_record(step, i64::from(errno), 0),
            "both child paths must encode the same failed-step record"
        );
        assert!(
            failure.to_string().starts_with("seccomp install refused: ")
                && failure.to_string().contains(&format!("errno {errno}")),
            "the refusal must name the step and its errno: {failure}"
        );
    }
    let supplied_arch = SECCOMP_AUDIT_ARCH.wrapping_add(1);
    let failure = SeccompInstallFailure::AuditArchitecture(supplied_arch);
    assert_eq!(
        failure.launch_record(),
        seccomp_launch_record(SECCOMP_LAUNCH_AUDIT_ARCH, 0, i64::from(supplied_arch)),
        "the architecture must keep all its unsigned bits in the fixed record"
    );
    assert_eq!(
        decode_seccomp_launch_record(&failure.launch_record()).unwrap(),
        SeccompLaunchRecord::Refused(failure),
        "the shared decoder must preserve the architecture refusal for both child paths"
    );
}

/// One install record's bytes, so the reader's cases are built by the record's
/// own layout instead of a hand-written literal.
fn seccomp_launch_record(step: i64, first: i64, second: i64) -> [u8; SECCOMP_LAUNCH_RECORD_LEN] {
    let mut record = [0u8; SECCOMP_LAUNCH_RECORD_LEN];
    for (field, value) in record.chunks_exact_mut(8).zip([step, first, second]) {
        field.copy_from_slice(&value.to_ne_bytes());
    }
    record
}

/// A failed install starts nothing, and says which step failed with its errno:
/// each injected step failure and a list built for another architecture come
/// back from the launcher as that step's own reason, and no program runs.
///
/// The requested program is a byte-identical copy of the provider binary, so a
/// start that got past the install would show as a live process whose own
/// `/proc/<pid>/exe` names that copy. The test requires the refusal and then
/// requires no such process to exist, so "starts nothing" is observed and not
/// inferred. On another OS the launcher has no filter at all, and the refusal
/// there names the provider and says the filter is a linux policy.
///
/// Falsifier: WP168 suppresses the `NoNewPrivileges` install failure, so the
/// filter case names `no_new_privs` and the test fails on it. WP169 suppresses
/// the `Filter` install failure, so that case never refuses.
///
/// All three plants reach this test's Linux arm only, which is not compiled on
/// the Mac, so none of them is registered in `falsifiers.json`: they are
/// recorded in `CONFINEMENT-LINUX.md` and re-run on the Linux host with their
/// red output quoted there.
#[test]
fn linux_seccomp_launch_refuses_each_failed_install() {
    let declared = read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
        .unwrap_or_else(|err| panic!("{err}"));
    let allow = seccomp_allow_list_from_declared_rights(WALLET_PROVIDER, &declared)
        .unwrap_or_else(|err| panic!("{err}"));
    let fixture = tempfile::tempdir().expect("temporary launch fixture");
    let fixture = resolved(fixture.path());
    let program = fixture.join("requested-program");
    fs::copy(Path::new(PROVIDER_BINARY), &program).expect("the fixture copy must be writable");

    #[cfg(not(target_os = "linux"))]
    {
        let refusal = ConfinedProvider::start_under_seccomp(&allow, &program)
            .err()
            .expect("a start without a filter must be refused");
        assert_eq!(
            refusal,
            format!(
                "{WALLET_PROVIDER} start is refused: a seccomp filter is installed on linux only"
            ),
            "the refusal must name the provider and say the filter is a linux policy"
        );
    }

    #[cfg(target_os = "linux")]
    {
        let mut cases: Vec<(SeccompAllowList, String)> = Vec::new();
        for (failed, errno) in [
            (SeccompStep::NoNewPrivileges, libc::EPERM),
            (SeccompStep::Filter, libc::EINVAL),
        ] {
            let mut candidate = allow.clone();
            candidate.injected_step_failure = Some((failed, errno));
            cases.push((
                candidate,
                format!(
                    "{WALLET_PROVIDER} start is refused: {}",
                    SeccompInstallFailure::Step(failed, errno)
                ),
            ));
        }
        let mut wrong_arch = allow.clone();
        wrong_arch.audit_arch = SECCOMP_AUDIT_ARCH.wrapping_add(1);
        cases.push((
            wrong_arch.clone(),
            format!(
                "{WALLET_PROVIDER} start is refused: {}",
                SeccompInstallFailure::AuditArchitecture(wrong_arch.audit_arch)
            ),
        ));

        for (candidate, expected) in cases {
            let refusal = ConfinedProvider::start_under_seccomp(&candidate, &program)
                .err()
                .unwrap_or_else(|| panic!("{expected} must refuse the start"));
            assert_eq!(
                refusal, expected,
                "the refusal must be that step's own reason and errno"
            );
            assert!(
                running_programs(&program).is_empty(),
                "a refused install must start nothing, and {} runs {}",
                program.display(),
                running_programs(&program).len()
            );
        }
    }
}

/// The launcher starts the program it is given and no other: the fixture holds
/// the provider binary and a byte-identical copy of it, the launcher is given the
/// copy, and the started child's own `/proc/<pid>/exe` must name that copy. A
/// start that substituted the provider binary would run a different path and fail
/// here, even though both files hold the same bytes.
///
/// The copy is byte-identical so only the path can tell them apart, and the
/// provider binary is the program under test because it is the one the filter's
/// measured launch set was measured against.
///
/// Falsifier: WP170 substitutes `PROVIDER_BINARY` for the given program, so the
/// child's `/proc/<pid>/exe` names the original and the test fails on it. It
/// reaches a Linux-only arm, so it is not registered in `falsifiers.json` and
/// `CONFINEMENT-LINUX.md` records it with the red run on the Linux host.
#[test]
fn linux_seccomp_launcher_runs_the_requested_program() {
    let declared = read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
        .unwrap_or_else(|err| panic!("{err}"));
    let allow = seccomp_allow_list_from_declared_rights(WALLET_PROVIDER, &declared)
        .unwrap_or_else(|err| panic!("{err}"));

    #[cfg(not(target_os = "linux"))]
    {
        let refusal = ConfinedProvider::start_under_seccomp(&allow, Path::new(PROVIDER_BINARY))
            .err()
            .expect("a start without a filter must be refused");
        assert_eq!(
            refusal,
            format!(
                "{WALLET_PROVIDER} start is refused: a seccomp filter is installed on linux only"
            ),
            "the refusal must name the provider and say the filter is a linux policy"
        );
        return;
    }

    #[cfg(target_os = "linux")]
    {
        let fixture = tempfile::tempdir().expect("temporary launch fixture");
        let fixture = resolved(fixture.path());
        let original = resolved(Path::new(PROVIDER_BINARY));
        let requested = fixture.join("requested-program");
        fs::copy(&original, &requested).expect("the fixture copy must be writable");
        assert_eq!(
            fs::read(&requested).expect("the copy must be readable"),
            fs::read(&original).expect("the provider binary must be readable"),
            "the copy must be byte-identical, so only its path tells the two apart"
        );

        let mut provider = ConfinedProvider::start_under_seccomp(&allow, &requested)
            .unwrap_or_else(|refusal| panic!("the requested program must start: {refusal}"));
        let launched = fs::read_link(format!("/proc/{}/exe", provider.child.id()))
            .expect("the launched child's own /proc exe link must be readable");
        let _ = provider.wait_for_exit();
        assert_eq!(
            launched, requested,
            "the launcher must run the program it is given and no other"
        );
    }
}

/// The pids whose own `/proc/<pid>/exe` names `program`. It reads `/proc` and
/// starts nothing, so a refusal can be checked for the process it must not
/// leave behind.
#[cfg(target_os = "linux")]
fn running_programs(program: &Path) -> Vec<libc::pid_t> {
    let mut pids = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return pids;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        if fs::read_link(entry.path().join("exe")).is_ok_and(|exe| exe == program) {
            pids.push(pid);
        }
    }
    pids
}

/// The prefix every probe record line starts with.
#[cfg(target_os = "linux")]
const SECCOMP_PROBE_MARKER: &str = "seccomp-probe:";
/// The prefix the probe child's own refusal starts with.
#[cfg(target_os = "linux")]
const SECCOMP_PROBE_REFUSED: &str = "seccomp-probe-refused:";
/// The prefix the probe child writes its own allocation count under.
#[cfg(target_os = "linux")]
const SECCOMP_PROBE_ALLOCATIONS: &str = "seccomp-probe-allocations:";
/// `SECCOMP_MODE_FILTER`, the mode `/proc/<pid>/status` reports for a process
/// that carries a seccomp filter.
#[cfg(target_os = "linux")]
const SECCOMP_MODE_FILTER: u32 = 2;

/// The probe child's report: one `(call, before, after)` per refused call, and
/// the number of times the child allocated after its fork.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SeccompProbeReport {
    records: Vec<(&'static str, SeccompAnswer, SeccompAnswer)>,
    /// The child's own allocation count after the fork, which must be zero.
    allocations: usize,
}

/// What the probe child is asked to do; a plain value, because it crosses a fork
/// into a child that allocates nothing.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeccompProbeRun {
    /// The kernel proof: record the four calls, install the filter, record them
    /// again and report.
    Filter,
    /// Exit at once with no report, so a complete report is required to pass.
    WithoutReport,
    /// Write a complete report and never exit, so only the bounded wait ends
    /// the run.
    WithoutExit,
    /// Trace itself and stop, so the wait sees a stopped child that is still
    /// alive: `PTRACE_TRACEME` makes its stops reportable without `WUNTRACED`.
    Stopped,
    /// Allocate after the fork, so the allocation guard has something to count.
    Allocating,
    /// Check that another probe's pipe ends were closed in this fork-only
    /// child, then run the normal filter proof.
    CheckInheritedDescriptors([std::os::fd::RawFd; 2]),
}

/// The probe child's own body: record the four calls, install the filter through
/// `install_seccomp`, record them again, write one line per call and end the
/// process at once.
///
/// It runs in a forked child before any exec, so its filter reaches only that
/// child and the harness above it stays unfiltered. It allocates nothing and
/// writes with raw `write` calls, because a forked child may rely only on
/// async-signal-safe calls. The allocation guard counts this child's own
/// allocations, and a child that allocated refuses its own report instead of
/// writing it, so a `Vec` after the fork cannot pass as a fixed array. Both sets
/// of answers live in fixed arrays of the list's own length. It ends with
/// `exit_group`, because ending one thread would leave the other waiting on
/// calls this filter refuses.
#[cfg(target_os = "linux")]
fn run_seccomp_probe_child(
    report: std::os::fd::RawFd,
    run: SeccompProbeRun,
    allow: &SeccompAllowList,
    prepared_report: Option<&[u8]>,
) -> ! {
    // CLOEXEC protects exec children. This one shared ownership check also
    // closes other probes' pipes and launcher sockets in fork-only children.
    if let Err(errno) = retain_probe_report_descriptor(report) {
        write_all(
            report,
            b"the probe child could not close inherited descriptors: errno ",
        );
        write_number(report, i64::from(errno));
        unsafe { libc::_exit(71) }
    }
    if let SeccompProbeRun::CheckInheritedDescriptors(inherited) = run {
        for fd in inherited {
            let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if result != -1 || unsafe { *libc::__errno_location() } != libc::EBADF {
                write_all(
                    report,
                    b"the probe child retained another probe's descriptor",
                );
                unsafe { libc::_exit(71) }
            }
        }
    }
    if run == SeccompProbeRun::WithoutReport {
        unsafe { libc::_exit(0) }
    }
    if run == SeccompProbeRun::Stopped {
        // A traced child's stops are reportable without `WUNTRACED`, so a wait
        // that read this stop as an end would leave the child alive. Raising
        // SIGSTOP is the same observable state as an external stop.
        unsafe {
            libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
            libc::raise(libc::SIGSTOP);
        }
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }
    if run == SeccompProbeRun::WithoutExit {
        write_all(
            report,
            prepared_report.expect("the parent prepares this report"),
        );
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    // From here on this child counts its own allocations, so the report can
    // say whether anything after the fork took the allocator.
    begin_counting_child_allocations();
    if run == SeccompProbeRun::Allocating {
        // The guard's own fixture: one allocation after the fork, so the count
        // is not zero and the test can see the guard fire.
        let allocated: Vec<u8> = Vec::with_capacity(1);
        let _ = allocated.capacity();
    }

    let mut before = [SeccompAnswer::Returned(0); SECCOMP_PROBE_CALLS.len()];
    for (slot, call) in before.iter_mut().zip(SECCOMP_PROBE_CALLS) {
        *slot = seccomp_probe_answers(call);
    }
    // The probe installs the same filter the launcher installs, so it proves
    // that filter and not a second one. `LAUNCH_ESSENTIALS` holds none of the
    // four refused calls, so their answer is still the default decision.
    if let Err(failure) = install_seccomp(allow) {
        write_all(report, SECCOMP_PROBE_REFUSED.as_bytes());
        write_all(report, &failure.launch_record());
        unsafe { libc::_exit(70) }
    }
    let mut after = [SeccompAnswer::Returned(0); SECCOMP_PROBE_CALLS.len()];
    for (slot, call) in after.iter_mut().zip(SECCOMP_PROBE_CALLS) {
        *slot = seccomp_probe_answers(call);
    }
    let mut buffer = [0u8; 512];
    for ((call, before), after) in SECCOMP_PROBE_CALLS.iter().zip(before).zip(after) {
        let mut written = 0usize;
        written += copy_bytes(&mut buffer[written..], SECCOMP_PROBE_MARKER.as_bytes());
        written += copy_bytes(&mut buffer[written..], b" ");
        written += copy_bytes(&mut buffer[written..], call.as_bytes());
        written += copy_bytes(&mut buffer[written..], b" ");
        written += copy_answer(&mut buffer[written..], before);
        written += copy_bytes(&mut buffer[written..], b" ");
        written += copy_answer(&mut buffer[written..], after);
        written += copy_bytes(&mut buffer[written..], b"\n");
        write_all(report, &buffer[..written]);
    }
    // The guard: this child writes how many times it allocated after the fork,
    // and the test that decides the rule requires the count to be zero. The
    // line is written whatever the count, so a child that allocated still
    // reports and the count itself is the evidence.
    write_all(report, SECCOMP_PROBE_ALLOCATIONS.as_bytes());
    write_number(report, child_allocations() as i64);
    write_all(report, b"\n");
    unsafe {
        libc::syscall(libc::SYS_exit_group, 0 as libc::c_long);
    }
    unreachable!("exit_group must not return")
}

/// The fork-only child owns exactly its report writer. Closing both ranges
/// also covers descriptors created by concurrent threads before the fork.
/// This runs before installing the filter, using raw syscalls and stack values.
/// A kernel that cannot close the ranges refuses the probe before it runs.
#[cfg(target_os = "linux")]
fn retain_probe_report_descriptor(report: std::os::fd::RawFd) -> Result<(), i32> {
    for (first, last) in [(0, report as u32), (report as u32 + 1, u32::MAX)] {
        if first == last {
            continue;
        }
        let last = if first == 0 { last - 1 } else { last };
        if unsafe { libc::syscall(libc::SYS_close_range, first, last, 0u32) } != 0 {
            return Err(unsafe { *libc::__errno_location() });
        }
    }
    Ok(())
}

/// Makes this probe child count its own allocations. It runs in the forked
/// child, after the fork, so the flag it sets is the child's own copy: the
/// parent's threads keep running in the parent's copy and set nothing here.
#[cfg(target_os = "linux")]
fn begin_counting_child_allocations() {
    ALLOCATIONS.store(0, Ordering::SeqCst);
    COUNT_ALLOCATIONS.store(true, Ordering::SeqCst);
}

/// How many allocations this probe child made since it started counting.
#[cfg(target_os = "linux")]
fn child_allocations() -> usize {
    ALLOCATIONS.load(Ordering::SeqCst)
}

/// Writes `bytes` to `fd` with the raw `write` call the filter admits.
#[cfg(target_os = "linux")]
fn write_all(fd: std::os::fd::RawFd, bytes: &[u8]) {
    let mut written = 0usize;
    while written < bytes.len() {
        let count =
            unsafe { libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written) };
        if count <= 0 {
            return;
        }
        written += count as usize;
    }
}

/// Writes `value` as decimal digits to `fd`, with no formatting and no
/// allocation.
#[cfg(target_os = "linux")]
fn write_number(fd: std::os::fd::RawFd, value: i64) {
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    loop {
        digits[count] = b'0' + (magnitude % 10) as u8;
        magnitude /= 10;
        count += 1;
        if magnitude == 0 {
            break;
        }
    }
    if negative {
        write_all(fd, b"-");
    }
    while count > 0 {
        count -= 1;
        write_all(fd, &digits[count..=count]);
    }
}

/// The list the launcher and the probe both install for `name`: the one list
/// built from that provider's committed declared rights, plus the measured
/// launch set, through the one builder and the one join. It is built once per
/// run, in the parent, before any fork.
///
/// The provider name is an argument and not this crate's constant, so the list a
/// launch installs for either provider is read through the same helper (P10). It
/// makes no kernel call and reads one file, so the provider-name test can ask it
/// about both providers wherever the tests run; the journey that installs the
/// result is Linux-only.
///
/// It refuses, with `read_declared_rights`' or `seccomp_allow_list_from_declared_rights`'
/// own reason unchanged, a name whose declared-rights file cannot be read.
fn seccomp_probe_list(name: &str) -> Result<SeccompAllowList, String> {
    let declared = read_declared_rights(name, &declared_rights_path(name))?;
    seccomp_allow_list_from_declared_rights(name, &declared)
        .map(|allow| allow.with_launch_essentials())
}

/// The one file-to-list helper reads the provider it was asked for, and the one
/// builder refuses a name whose declared-rights read fails.
///
/// Asking for both providers must give two lists whose `provider` fields are the
/// two names asked for, and whose admitted syscalls still carry each provider's
/// own declared rights, so a helper that ignored its argument and read wallet's
/// file twice would answer wallet's name both times. The refusal case reads a
/// name with no committed file and requires the reader's own reason, which names
/// that provider and that path, so the helper has no fallback.
///
/// The test reads files and builds two lists. It starts no process and makes no
/// kernel call, so it runs on every OS: the journey that installs a list is
/// Linux-only, and this rule about which provider's file was read is not.
///
/// Falsifier: a `seccomp_probe_list` that ignores its provider argument and
/// always reads wallet's declared-rights file makes both lists answer
/// `wallet-provider`, so this test fails on the did case.
#[test]
fn seccomp_allow_list_names_the_provider_it_was_built_for() {
    for name in [DID_PROVIDER, WALLET_PROVIDER] {
        let allow = seccomp_probe_list(name).unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(
            allow.provider, name,
            "the allow list must name the provider it was built for"
        );
        for syscall in ["execve", "execveat", "mkdirat", "write", "unlinkat"] {
            assert!(
                allow.admits(syscall),
                "{name}'s declared rights must admit {syscall}: {:?}",
                allow.syscalls
            );
        }
        for syscall in ["ptrace", "mount", "bpf", "keyctl", "fchmodat"] {
            assert!(
                !allow.admits(syscall),
                "{name}'s list must admit no undeclared call, and it admits {syscall}"
            );
        }
    }
    let missing = "absent-provider";
    let refusal = seccomp_probe_list(missing)
        .expect_err("a name with no committed declared-rights file must be refused");
    assert!(
        refusal.starts_with(&format!("{missing} declared-rights file ")),
        "the refusal must be the reader's own reason, which names the provider: {refusal}"
    );
    assert!(
        refusal.contains("must be readable"),
        "the refusal must say the file could not be read: {refusal}"
    );
    assert!(
        refusal.contains(&declared_rights_path(missing).display().to_string()),
        "the refusal must name the path it could not read: {refusal}"
    );
}

/// Copies `bytes` into `into` and returns how much it wrote. The probe's report
/// is built in a fixed buffer after the filter is installed, where no allocator
/// may be called.
#[cfg(target_os = "linux")]
fn copy_bytes(into: &mut [u8], bytes: &[u8]) -> usize {
    into[..bytes.len()].copy_from_slice(bytes);
    bytes.len()
}

/// Writes one answer as `errno:<n>` or `ok:<n>` into `into` and returns how much
/// it wrote, without formatting a `String`.
#[cfg(target_os = "linux")]
fn copy_answer(into: &mut [u8], answer: SeccompAnswer) -> usize {
    let (prefix, value) = match answer {
        SeccompAnswer::Errno(errno) => (&b"errno:"[..], i64::from(errno)),
        SeccompAnswer::Returned(value) => (&b"ok:"[..], value),
    };
    let mut written = copy_bytes(into, prefix);
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    loop {
        digits[count] = b'0' + (magnitude % 10) as u8;
        magnitude /= 10;
        count += 1;
        if magnitude == 0 {
            break;
        }
    }
    if negative {
        written += copy_bytes(&mut into[written..], b"-");
    }
    while count > 0 {
        count -= 1;
        written += copy_bytes(&mut into[written..], &digits[count..=count]);
    }
    written
}

/// How a probe child ended.
///
/// A stop is its own end, because a stopped child is alive: `PTRACE_TRACEME`
/// makes a child's stops reportable without `WUNTRACED`, so a wait that read a
/// stop as an end would leave the child and its pipe behind (P11).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeExit {
    Code(i32),
    Signal(i32),
    /// The child stopped with this signal; it was killed and reaped.
    Stopped(i32),
    TimedOut,
    /// The child could not be waited on any more, with this errno.
    Gone(i32),
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for ProbeExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code(0) => write!(f, "exit status: 0"),
            Self::Code(code) => write!(f, "exit status: {code}"),
            Self::Signal(signal) => write!(f, "signal: {signal}"),
            Self::Stopped(signal) => write!(
                f,
                "stopped by signal: {signal}, so it was killed and reaped"
            ),
            Self::Gone(errno) => write!(f, "no longer waitable, errno {errno}"),
            Self::TimedOut => write!(
                f,
                "no exit within {}s, so it was killed",
                CHILD_EXIT_DEADLINE.as_secs()
            ),
        }
    }
}

/// The child's report, or a refusal naming what it did instead. The child is a
/// fork of this process, so its filter reaches only itself. The read is bounded
/// and the child is reaped on every result, including a timeout, so a repeated
/// journey leaves no probe behind.
///
/// The reap is asserted before the report is read, so no early return can skip
/// it: a wait that ended without reaping the child fails here whatever the child
/// wrote.
#[cfg(target_os = "linux")]
fn seccomp_denied_call_probe(
    allow: &SeccompAllowList,
    run: SeccompProbeRun,
) -> Result<SeccompProbeReport, String> {
    seccomp_denied_call_probe_with_pipe(allow, run, |_| {})
}

/// The probe's one channel and fork path. The observer runs in the parent
/// after pipe creation and before the fork, so the inheritance test can hold
/// that exact race window open while it launches other children.
#[cfg(target_os = "linux")]
fn seccomp_denied_call_probe_with_pipe(
    allow: &SeccompAllowList,
    run: SeccompProbeRun,
    observe_pipe: impl FnOnce([std::os::fd::RawFd; 2]),
) -> Result<SeccompProbeReport, String> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(format!(
            "seccomp probe refused: the report pipe could not open: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut reader = unsafe { fs::File::from_raw_fd(fds[0]) };
    let writer = unsafe { fs::File::from_raw_fd(fds[1]) };
    observe_pipe(fds);
    // The lifecycle fixture's report is built here, where an allocator is
    // allowed, and the child only writes it. Counted children allocate nothing,
    // so that report says zero.
    let prepared = match run {
        SeccompProbeRun::WithoutExit => Some(probe_report_text(&SeccompProbeReport {
            records: SECCOMP_PROBE_CALLS
                .iter()
                .map(|call| {
                    (
                        *call,
                        SeccompAnswer::Errno(libc::EPERM),
                        SeccompAnswer::Errno(SECCOMP_DENY_ERRNO),
                    )
                })
                .collect(),
            allocations: 0,
        })),
        _ => None,
    };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "seccomp probe refused: the probe child could not start: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        run_seccomp_probe_child(
            writer.as_raw_fd(),
            run,
            allow,
            prepared.as_deref().map(str::as_bytes),
        );
    }
    drop(writer);

    let exit = wait_for_probe_exit(pid);
    // The wait must have reaped the child on every result: a second wait finds
    // no child, so a repeated journey leaves no probe running. This is asserted
    // here, before any arm can return, so no early return skips it.
    assert_probe_reaped(pid);
    // Reports fit within PIPE_BUF, so the child can write before this read.
    // The parent owns the nonblocking reader throughout, including every
    // error and deadline. A concurrent exec may briefly hold a CLOEXEC writer
    // before exec closes it; wait for that close within the same bound.
    let started = Instant::now();
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 512];
    loop {
        if started.elapsed() >= CHILD_EXIT_DEADLINE {
            return Err(format!(
                "seccomp probe refused: child {exit} wrote no complete report within {}s",
                CHILD_EXIT_DEADLINE.as_secs()
            ));
        }
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.len() > libc::PIPE_BUF {
                    return Err("seccomp probe refused: the report exceeds PIPE_BUF".into());
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(CHILD_EXIT_POLL);
            }
            Err(err) => {
                return Err(format!(
                    "seccomp probe refused: reading the report failed: {err}"
                ))
            }
        }
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();

    match exit {
        ProbeExit::Code(code) if code == 0 => {}
        ProbeExit::Code(_) if bytes.starts_with(SECCOMP_PROBE_REFUSED.as_bytes()) => {
            return Err(
                match decode_seccomp_launch_record(&bytes[SECCOMP_PROBE_REFUSED.len()..]) {
                    Ok(SeccompLaunchRecord::Refused(failure)) => format!(
                        "seccomp probe refused: the probe child must install the filter: {failure}"
                    ),
                    Ok(SeccompLaunchRecord::Installed(_)) => {
                        "seccomp probe refused: the refused child reported an installed filter"
                            .into()
                    }
                    Err(reason) => format!("seccomp probe refused: {reason}"),
                },
            );
        }
        other => {
            return Err(format!(
                "seccomp probe refused: child {other}; report: {text}"
            ))
        }
    }
    let report = parse_seccomp_probe_report(&text)
        .map_err(|refusal| format!("seccomp probe refused: {refusal}"))?;
    // The guard's one decision: a child that allocated after its fork may have
    // blocked on an allocator lock another thread held at the fork, so its
    // report is refused with its own reason. A child that allocated nothing
    // reports zero and is accepted.
    if report.allocations != 0 {
        return Err(format!(
            "seccomp probe refused: the probe child allocated {} times after its fork, where \
             only async-signal-safe calls are available",
            report.allocations
        ));
    }
    Ok(report)
}

/// Asserts that this process no longer holds `pid`: a second wait answers
/// `ECHILD`, so the child was reaped. It is called on every probe result before
/// any arm can return, so no path can skip the reaping rule.
#[cfg(target_os = "linux")]
fn assert_probe_reaped(pid: libc::pid_t) {
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    let errno = std::io::Error::last_os_error().raw_os_error();
    assert_eq!(
        waited, -1,
        "the probe child must already be reaped, and a second wait answered {waited}"
    );
    assert_eq!(
        errno,
        Some(libc::ECHILD),
        "the probe child must already be reaped with ECHILD, and the wait answered {errno:?}"
    );
}

/// Waits up to `CHILD_EXIT_DEADLINE` for `pid` to end, killing and reaping it
/// on every other result. It is the one wait for a probe child.
///
/// A stop is not an end: `PTRACE_TRACEME` makes a child's stops reportable
/// without `WUNTRACED`, so a stopped child is killed with `SIGKILL` and reaped
/// before this returns, exactly as a timed-out child is. An `EINTR` from
/// `waitpid` retries the same wait instead of ending it, and a child the kernel
/// no longer holds is `Gone` with its errno. Every arm leaves no child behind,
/// so the caller can finish its bounded read and a repeated journey reaps everything.
#[cfg(target_os = "linux")]
fn wait_for_probe_exit(pid: libc::pid_t) -> ProbeExit {
    let started = Instant::now();
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        let errno = if waited < 0 {
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ECHILD)
        } else {
            0
        };
        if waited == pid {
            if libc::WIFEXITED(status) {
                return ProbeExit::Code(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                return ProbeExit::Signal(libc::WTERMSIG(status));
            }
            if libc::WIFSTOPPED(status) {
                // The child is alive and stopped, and this wait will never see
                // its end: kill and reap it here rather than return a result a
                // reader could read as an end.
                return ProbeExit::Stopped(kill_and_reap(pid, libc::WSTOPSIG(status)));
            }
            return ProbeExit::Code(libc::WEXITSTATUS(status));
        }
        if waited < 0 {
            if errno == libc::EINTR {
                continue;
            }
            // `ECHILD` is the one errno that says this process holds no such
            // child any more, so nothing is left to reap and no wait can help.
            return ProbeExit::Gone(errno);
        }
        if started.elapsed() >= CHILD_EXIT_DEADLINE {
            kill_and_reap(pid, 0);
            return ProbeExit::TimedOut;
        }
        std::thread::sleep(CHILD_EXIT_POLL);
    }
}

/// Kills `pid` with `SIGKILL` and reaps it, returning `stop_signal` so its
/// caller can report a stop. A child the kernel no longer holds is already
/// reaped, so this returns without waiting. It is the one kill-and-reap for a
/// probe child.
#[cfg(target_os = "linux")]
fn kill_and_reap(pid: libc::pid_t, stop_signal: i32) -> i32 {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            break;
        }
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ECHILD);
        if errno == libc::EINTR {
            continue;
        }
        // Any other errno means the kernel holds no child for this pid, so it
        // has been reaped already and the wait cannot succeed.
        break;
    }
    stop_signal
}

/// The report text for `report`, built with an allocator before a fork. It is
/// the same text the child writes, so the parser reads one shape from both.
#[cfg(target_os = "linux")]
fn probe_report_text(report: &SeccompProbeReport) -> String {
    let mut text: String = report
        .records
        .iter()
        .map(|(call, before, after)| {
            format!(
                "{SECCOMP_PROBE_MARKER} {call} {} {}\n",
                before.text(),
                after.text()
            )
        })
        .collect();
    text.push_str(&format!(
        "{SECCOMP_PROBE_ALLOCATIONS}{}\n",
        report.allocations
    ));
    text
}

/// The four records the probe child wrote, each with its unfiltered and filtered
/// answer, and the child's own allocation count. A missing or unreadable record
/// is a refusal that names the call, so a child that stopped early cannot pass
/// the journey, and a missing count is its own refusal.
#[cfg(target_os = "linux")]
fn parse_seccomp_probe_report(text: &str) -> Result<SeccompProbeReport, String> {
    let mut records = Vec::new();
    for call in SECCOMP_PROBE_CALLS {
        let marker = format!("{SECCOMP_PROBE_MARKER} {call} ");
        let line = text
            .lines()
            .find(|line| line.starts_with(&marker))
            .ok_or_else(|| format!("the probe recorded no answer for {call}: {text}"))?;
        let (before, after) = line[marker.len()..]
            .split_once(' ')
            .ok_or_else(|| format!("{call} must hold two answers: {line}"))?;
        let before = SeccompAnswer::parse(before)
            .ok_or_else(|| format!("{call}: {before} is not an answer"))?;
        let after = SeccompAnswer::parse(after)
            .ok_or_else(|| format!("{call}: {after} is not an answer"))?;
        records.push((*call, before, after));
    }
    let line = text
        .lines()
        .find(|line| line.starts_with(SECCOMP_PROBE_ALLOCATIONS))
        .ok_or_else(|| format!("the probe recorded no allocation count: {text}"))?;
    let allocations = line[SECCOMP_PROBE_ALLOCATIONS.len()..]
        .trim()
        .parse::<usize>()
        .map_err(|err| format!("the probe's allocation count is not a number: {line}: {err}"))?;
    Ok(SeccompProbeReport {
        records,
        allocations,
    })
}

/// Every child the probe starts is reaped, a failed install is reported rather
/// than left to hang, a stopped child and a child that never exits are both
/// killed at a bound, a child that allocated after its fork is refused, and a
/// repeated journey answers the same as the first.
///
/// The test covers both failed install steps and a wrong audit architecture,
/// then missing reports, stops, timeouts, allocations and repeated kernel
/// proofs. Each child must end, and the kernel proof must give the same four
/// records twice in a row, so the second journey reaps everything the first
/// started.
///
/// Falsifier: WP171 reads a stopped child as an end, so this test hangs on the
/// stopped case until the harness kills it, and the stopped child is never
/// reaped. WP172 omits the `SIGKILL` and reap for a timed-out probe, so that
/// child is left behind. WP173 removes the reaping assertion, so a child the
/// harness leaves running keeps the test green where it must fail. WP174 omits
/// the `waitpid` and reap entirely, so no child is ever reaped. WP175 collects
/// the filtered answers with a `Vec` after the fork, so the allocation guard
/// counts one and the guard case's refusal does not come.
///
/// Every plant here reaches a Linux-only arm, so none of them is registered in
/// `falsifiers.json`; `CONFINEMENT-LINUX.md` records them and quotes the red run
/// on the Linux host.
#[cfg(target_os = "linux")]
#[test]
fn linux_seccomp_probe_reaps_failures_and_repeated_journeys() {
    let started = Instant::now();

    let allow = seccomp_probe_list(WALLET_PROVIDER).unwrap_or_else(|err| panic!("{err}"));
    for (step, errno, reason) in [
        (
            SeccompStep::NoNewPrivileges,
            libc::EPERM,
            "seccomp install refused: PR_SET_NO_NEW_PRIVS failed with errno 1",
        ),
        (
            SeccompStep::Filter,
            libc::EINVAL,
            "seccomp install refused: the filter install failed with errno 22",
        ),
    ] {
        let mut candidate = allow.clone();
        candidate.injected_step_failure = Some((step, errno));
        assert_eq!(
            seccomp_denied_call_probe(&candidate, SeccompProbeRun::Filter).unwrap_err(),
            format!("seccomp probe refused: the probe child must install the filter: {reason}"),
            "the probe must preserve each install step's own refusal"
        );
    }
    let mut wrong_arch = allow.clone();
    wrong_arch.audit_arch = SECCOMP_AUDIT_ARCH.wrapping_add(1);
    assert_eq!(
        seccomp_denied_call_probe(&wrong_arch, SeccompProbeRun::Filter).unwrap_err(),
        format!(
            "seccomp probe refused: the probe child must install the filter: \
             seccomp install refused: the list was built for audit architecture {:#x} \
             and this target reports {SECCOMP_AUDIT_ARCH:#x}",
            wrong_arch.audit_arch
        ),
        "the probe must preserve the supplied and target audit architectures"
    );
    let failed = seccomp_denied_call_probe(&allow, SeccompProbeRun::Filter)
        .expect("the filter proof must pass on this host");
    assert_eq!(
        failed.records.len(),
        SECCOMP_PROBE_CALLS.len(),
        "the probe must record every refused call"
    );
    assert_eq!(
        failed.allocations, 0,
        "the kernel-proof child must allocate nothing after its fork, and it allocated"
    );

    let empty = seccomp_denied_call_probe(&allow, SeccompProbeRun::WithoutReport)
        .expect_err("a child with no report must be refused");
    assert!(
        empty.contains("the probe recorded no answer for ptrace"),
        "a child that reports nothing must name the first record: {empty}"
    );

    // A stopped child is alive, not ended. The wait must kill and reap it, and
    // the report it never finished must be refused by name.
    let stopped = seccomp_denied_call_probe(&allow, SeccompProbeRun::Stopped)
        .expect_err("a child that stops must be killed and reaped");
    assert!(
        stopped.contains("stopped by signal") && stopped.contains("killed and reaped"),
        "a stopped child must be reported as stopped and reaped: {stopped}"
    );

    let held = seccomp_denied_call_probe(&allow, SeccompProbeRun::WithoutExit)
        .expect_err("a child that never exits must be killed at the deadline");
    assert!(
        held.contains("so it was killed"),
        "a child that never exits must be reported as killed: {held}"
    );

    // The guard fires on a child that allocates after its fork, so the zero the
    // kernel proof reported above is a measurement and not a constant.
    let allocated = seccomp_denied_call_probe(&allow, SeccompProbeRun::Allocating)
        .expect_err("a child that allocates after its fork must be refused");
    assert!(
        allocated.contains("allocated") && allocated.contains("after its fork"),
        "a child that allocates must be refused with that reason: {allocated}"
    );

    let first = seccomp_denied_call_probe(&allow, SeccompProbeRun::Filter)
        .unwrap_or_else(|failure| panic!("{failure}"));
    let second = seccomp_denied_call_probe(&allow, SeccompProbeRun::Filter)
        .unwrap_or_else(|failure| panic!("{failure}"));
    assert_eq!(
        first, second,
        "a repeated journey must answer the same as the first"
    );
    assert_eq!(
        first.records.len(),
        SECCOMP_PROBE_CALLS.len(),
        "the probe must record every refused call"
    );
    assert_eq!(
        first.allocations, 0,
        "both kernel-proof children must allocate nothing after their forks"
    );
    assert!(
        started.elapsed() < CHILD_EXIT_DEADLINE * 8,
        "the probe cases must finish well inside eight deadlines, and this took {:?}",
        started.elapsed()
    );
}

/// Hold the report pipe open before its fork while a concurrent launch execs
/// and another fork-only probe runs. Both ends belong to the first probe;
/// neither other child may use them or keep its report reader waiting for EOF.
#[cfg(target_os = "linux")]
#[test]
fn linux_seccomp_probe_descriptors_stay_with_their_owner() {
    let allow = seccomp_probe_list(WALLET_PROVIDER).unwrap_or_else(|err| panic!("{err}"));
    let mut provider = None;
    let started = Instant::now();
    let report = seccomp_denied_call_probe_with_pipe(&allow, SeccompProbeRun::Filter, |fds| {
        let channel = fs::read_link(format!("/proc/self/fd/{}", fds[0]))
            .expect("the probe pipe must have a kernel identity");
        for fd in fds {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0, "the report descriptor must be open");
            assert_ne!(
                flags & libc::FD_CLOEXEC,
                0,
                "each report descriptor must be close-on-exec at creation"
            );
        }
        // The callback is a barrier after pipe creation: both pipe ends stay
        // open until this other thread has completed the provider's exec.
        provider = Some(std::thread::scope(|scope| {
            scope
                .spawn(|| ConfinedProvider::start_under_seccomp(&allow, Path::new(PROVIDER_BINARY)))
                .join()
                .expect("the concurrent launch thread must finish")
                .expect("the concurrent provider must start")
        }));
        let pid = provider.as_ref().unwrap().child.id();
        for entry in fs::read_dir(format!("/proc/{pid}/fd")).expect("the provider's descriptors") {
            let path = entry.expect("a provider descriptor").path();
            let identity = match fs::read_link(path) {
                Ok(identity) => identity,
                // The loader may close a descriptor after read_dir listed it.
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => panic!("the descriptor's kernel identity must be readable: {err}"),
            };
            assert_ne!(
                identity, channel,
                "the concurrent provider must inherit neither probe pipe end"
            );
        }
        let sibling =
            seccomp_denied_call_probe(&allow, SeccompProbeRun::CheckInheritedDescriptors(fds))
                .expect("a fork-only probe must close both inherited pipe ends before its calls");
        assert_eq!(sibling.allocations, 0);
    })
    .expect("the owner must reap its probe and reach EOF while the provider stays alive");
    assert_eq!(report.allocations, 0);
    let mut provider = provider.expect("the observer started the concurrent provider");
    assert!(
        provider.child.try_wait().unwrap().is_none(),
        "the provider must remain alive when the probe report reaches EOF"
    );
    assert!(
        started.elapsed() < CHILD_EXIT_DEADLINE,
        "descriptor ownership must let both probes finish before a timeout"
    );
    provider.shutdown();

    // Hold an extra writer in the parent to force the read deadline even after
    // the probe is reaped. The caller must close its reader on that error too.
    use std::os::fd::FromRawFd as _;
    let mut held_writer = None;
    let mut owned_fds = [0; 2];
    let mut channel = None;
    let refusal =
        seccomp_denied_call_probe_with_pipe(&allow, SeccompProbeRun::WithoutReport, |fds| {
            owned_fds = fds;
            channel = Some(fs::read_link(format!("/proc/self/fd/{}", fds[0])).unwrap());
            let duplicate = unsafe { libc::fcntl(fds[1], libc::F_DUPFD_CLOEXEC, 0) };
            assert!(duplicate >= 0, "the deadline fixture must hold a writer");
            held_writer = Some(unsafe { fs::File::from_raw_fd(duplicate) });
        })
        .expect_err("an open writer must cause a bounded report refusal");
    assert_eq!(
        refusal,
        "seccomp probe refused: child exit status: 0 wrote no complete report within 10s"
    );
    for fd in owned_fds {
        assert_ne!(
            fs::read_link(format!("/proc/self/fd/{fd}")).ok(),
            channel,
            "the deadline must close the probe owner's descriptors"
        );
    }
    drop(held_writer);
    assert!(started.elapsed() < CHILD_EXIT_DEADLINE * 3);
}

/// The one launcher decides each policy: a `Seatbelt` policy keeps today's host
/// answers unchanged, a `Seccomp` policy is accepted on `linux` alone, and a
/// start this build cannot confine is refused by name so no provider runs
/// unconfined on any OS.
///
/// The test drives `standin_host_refusal` and `standin_spawn_confined_provider`,
/// so it covers the launcher's own `Seccomp` seat and not only the host rule. It
/// creates no storage root, writes no profile file and starts no provider.
///
/// Falsifier: WP158 accepts a `linux` host under a `Seatbelt` policy, so the
/// unchanged refusal is lost. WP159 bypasses the launcher's `Seccomp` seat and
/// lets the start continue, so the `Seccomp` case returns Started.
#[test]
fn standin_host_refusal_decides_each_policy() {
    let name = WALLET_PROVIDER;
    let declared = read_declared_rights(name, &declared_rights_path(name))
        .unwrap_or_else(|err| panic!("{err}"));
    let allow = seccomp_allow_list_from_declared_rights(name, &declared)
        .unwrap_or_else(|err| panic!("{err}"));
    let confined_os = DECLARED_CONFINED_OS.join(", ");
    let seatbelt = StandinPolicy::Seatbelt(Path::new(SANDBOX_EXEC));
    let seccomp = StandinPolicy::Seccomp(&allow);

    // A Seatbelt policy keeps every today answer.
    standin_host_refusal(name, StandinHost::reporting("macos"), seatbelt)
        .expect("a macos host under a Seatbelt policy must be accepted");
    assert_eq!(
        standin_host_refusal(name, StandinHost::reporting("linux"), seatbelt).unwrap_err(),
        format!(
            "{name} start on linux is refused: linux is designed, not enforced, in this lab, \
             so linux is not in DECLARED_CONFINED_OS ({confined_os})"
        ),
        "a linux host under a Seatbelt policy must keep today's exact words"
    );
    assert_eq!(
        standin_host_refusal(name, StandinHost::reporting("plan9"), seatbelt).unwrap_err(),
        format!(
            "{name} start on plan9 is refused: plan9 has no confinement design, and the lab \
             stand-in applies confinement only on {confined_os}"
        ),
        "an OS with no confinement design must keep today's exact words"
    );

    // A Seccomp policy is the linux policy: linux is accepted, another OS is
    // refused by name, and a missing primitive outranks both.
    standin_host_refusal(name, StandinHost::reporting("linux"), seccomp)
        .expect("a linux host under a Seccomp policy must be accepted");
    assert_eq!(
        standin_host_refusal(name, StandinHost::reporting("macos"), seccomp).unwrap_err(),
        format!(
            "{name} start on macos is refused: the seccomp allow list is the linux policy, \
             and macos is not linux"
        ),
        "a non-linux host under a Seccomp policy must be refused by name"
    );
    assert_eq!(
        standin_host_refusal(
            name,
            StandinHost::missing("macos", StandinPrimitive::Landlock),
            seccomp
        )
        .unwrap_err(),
        format!(
            "{name} start on macos is refused: linux confinement refused: the kernel has no \
             Landlock"
        ),
        "a reported missing primitive must be refused before the policy's OS rule"
    );

    // A Landlock policy carries the same filter, so it is accepted on linux
    // alone in the Seccomp policy's words.
    let bindings = canonical_bindings(
        name,
        Path::new("/fixture/landlock"),
        Path::new(PROVIDER_BINARY),
    );
    let ruleset = landlock_path_rules(name, &declared, &bindings, 7, &[])
        .unwrap_or_else(|err| panic!("{err}"));
    let landlock = StandinPolicy::Landlock {
        allow: &allow,
        ruleset: &ruleset,
    };
    standin_host_refusal(name, StandinHost::reporting("linux"), landlock)
        .expect("a linux host under a Landlock policy must be accepted");
    assert_eq!(
        standin_host_refusal(name, StandinHost::reporting("macos"), landlock).unwrap_err(),
        format!(
            "{name} start on macos is refused: the seccomp allow list is the linux policy, \
             and macos is not linux"
        ),
        "a non-linux host under a Landlock policy must be refused in the Seccomp policy's words"
    );
    assert_eq!(
        standin_host_refusal(
            name,
            StandinHost::linux_missing(StandinPrimitive::Landlock),
            landlock
        )
        .unwrap_err(),
        format!(
            "{name} start on linux is refused: linux confinement refused: the kernel has no \
             Landlock"
        ),
        "a host that reports Landlock missing must be refused before the policy's OS rule"
    );

    // The launcher's own seat: a Seccomp start under a list generated for
    // another provider is refused by name before anything is created, and a
    // list generated for this provider reaches the one spawn path on linux and
    // the linux-only refusal on every other OS.
    let fixture = tempfile::tempdir().expect("temporary wallet base");
    let base = resolved(fixture.path());
    let profile_root = tempfile::tempdir().expect("temporary profile root");
    let profile_dir = resolved(profile_root.path());
    let other = SeccompAllowList {
        provider: DID_PROVIDER.to_string(),
        ..allow.clone()
    };
    let refusal = standin_spawn_confined_provider(
        StandinHost::reporting("linux"),
        StandinPolicy::Seccomp(&other),
        name,
        Path::new(PROVIDER_BINARY),
        &base,
        &declared,
        &profile_dir,
    )
    .err()
    .expect("a list generated for another provider must refuse the start");
    assert_eq!(
        refusal,
        format!("{name} start is refused: the seccomp allow list was generated for {DID_PROVIDER}"),
        "the launcher must refuse a list generated for another provider"
    );
    assert!(
        !provider_storage_root(name, &base).exists(),
        "a refused Seccomp start must create no storage root: {}",
        provider_storage_root(name, &base).display()
    );
    assert!(
        fs::read_dir(&profile_dir)
            .expect("the profile directory must be readable")
            .next()
            .is_none(),
        "a Seccomp start must write no profile: {}",
        profile_dir.display()
    );

    #[cfg(not(target_os = "linux"))]
    {
        let refusal = ConfinedProvider::start_under_seccomp(&allow, Path::new(PROVIDER_BINARY))
            .err()
            .expect("a start without a filter must be refused");
        assert_eq!(
            refusal,
            format!("{name} start is refused: a seccomp filter is installed on linux only"),
            "the linux-only refusal must name the provider and the policy's OS"
        );
        let file_row =
            ConfinedProvider::start_under_landlock(&allow, &ruleset, Path::new(PROVIDER_BINARY))
                .err()
                .expect("a file-row start without a filter must be refused");
        assert_eq!(
            file_row, refusal,
            "the file-row start must use the one linux-only refusal"
        );
    }
}

/// The journey's own label, on every OS: the one helper both the label test and
/// the journey print. On Linux it names the host and kernel the proof ran on;
/// anywhere else it says the journey is not applicable and names this OS, so a
/// Mac run cannot read as a Linux claim.
///
/// It reads no filter and starts no process, so it runs everywhere.
fn linux_seccomp_journey_label() -> String {
    if cfg!(target_os = "linux") {
        format!(
            "linux seccomp journey: applicable, host {}/{}, kernel {}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            linux_kernel_release()
        )
    } else {
        format!(
            "linux seccomp journey: not applicable on {}, because a seccomp filter is \
             installed on linux only and this test passes nothing on for a Linux claim",
            std::env::consts::OS
        )
    }
}

/// The kernel release this process runs under, read from `uname`; off Linux no
/// kernel release answers the question, so it names the OS instead.
fn linux_kernel_release() -> String {
    if !cfg!(target_os = "linux") {
        return std::env::consts::OS.to_string();
    }
    #[cfg(target_os = "linux")]
    {
        let mut name: libc::utsname = unsafe { std::mem::zeroed() };
        let read = unsafe { libc::uname(&mut name) };
        assert_eq!(
            read,
            0,
            "uname must answer: {}",
            std::io::Error::last_os_error()
        );
        let release: Vec<u8> = name
            .release
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8)
            .collect();
        String::from_utf8_lossy(&release).into_owned()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::consts::OS.to_string()
    }
}

/// The journey's label says where the journey stands: off Linux the shared
/// helper says it is not applicable and names this OS, and on Linux it names
/// the Linux host. The test reads no filter, starts no process and builds none,
/// so it runs on every OS.
///
/// Falsifier: WP162 labels the journey with a Linux host on a host that is not
/// Linux, so the off-Linux case reads a claim instead of `not applicable` and
/// the test fails on it.
#[test]
fn linux_seccomp_journey_is_not_applicable_off_linux() {
    let line = linux_seccomp_journey_label();
    if cfg!(target_os = "linux") {
        assert!(
            line.contains("linux") && !line.contains("not applicable"),
            "on Linux the label must name the host the journey ran on: {line}"
        );
    } else {
        assert!(
            line.contains("not applicable"),
            "off Linux the label must say the journey is not applicable: {line}"
        );
        assert!(
            line.contains(std::env::consts::OS),
            "the label must name this OS: {line}"
        );
        assert!(
            !line.contains("applicable, host"),
            "off Linux the label must claim no Linux host: {line}"
        );
    }
    eprintln!("{line}");
}

/// The file row's own label, on every OS: the one helper the label test and the
/// journey print. On Linux it names the host, kernel and reported ABI; anywhere
/// else it says the row is not applicable and names this OS, so a Mac run cannot
/// read as a Linux claim.
///
/// It reads no ruleset and starts no process, so it runs everywhere.
fn linux_landlock_journey_label(abi: Option<u32>) -> String {
    if cfg!(target_os = "linux") {
        match abi {
            Some(abi) => format!(
                "linux landlock file row: applicable, host {}/{}, kernel {}, Landlock ABI {abi}",
                std::env::consts::OS,
                std::env::consts::ARCH,
                linux_kernel_release()
            ),
            None => format!(
                "linux landlock file row: applicable, host {}/{}, kernel {}, and the kernel \
                 reports no Landlock ABI",
                std::env::consts::OS,
                std::env::consts::ARCH,
                linux_kernel_release()
            ),
        }
    } else {
        format!(
            "linux landlock file row: not applicable on {}, because a Landlock ruleset is \
             installed on linux only and this test passes nothing on for a Linux claim",
            std::env::consts::OS
        )
    }
}

/// The file row's label says where the row stands: off Linux the shared helper
/// says it is not applicable and names this OS, and on Linux it names the host
/// and the ABI. The test reads no ruleset, starts no process and calls no
/// kernel, so it runs on every OS. The host and ABI assertions run only on
/// Linux, so a Mac run does not skip this test.
///
/// Falsifier: WP213 labels the row with a Linux host on a host that is not
/// Linux, so the off-Linux case reads a claim instead of `not applicable`.
#[test]
fn linux_landlock_journey_is_not_applicable_off_linux() {
    let line = linux_landlock_journey_label(Some(7));
    if cfg!(target_os = "linux") {
        assert!(
            line.contains("linux") && !line.contains("not applicable"),
            "on Linux the label must name the host the row ran on: {line}"
        );
        assert!(
            line.contains("Landlock ABI"),
            "on Linux the label must name the reported ABI: {line}"
        );
    } else {
        assert!(
            line.contains("not applicable"),
            "off Linux the label must say the row is not applicable: {line}"
        );
        assert!(
            line.contains(std::env::consts::OS),
            "the label must name this OS: {line}"
        );
        assert!(
            !line.contains("applicable, host"),
            "off Linux the label must claim no Linux host: {line}"
        );
    }
    eprintln!("{line}");
}

/// One file call the Landlock probe makes and the path it makes it on. Only the
/// Linux journey and its probe child read it.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LandlockProbeCall {
    ReadInside,
    WriteInside,
    ReadExecutable,
    ReadBeneathParent,
    WriteBesideParent,
    TruncateBesideParent,
    ListParent,
    ListSibling,
    ListSiblingPrivate,
}

#[cfg(target_os = "linux")]
impl LandlockProbeCall {
    /// Every call the journey requires, in report order.
    const ALL: [Self; 9] = [
        Self::ReadInside,
        Self::WriteInside,
        Self::ReadExecutable,
        Self::ReadBeneathParent,
        Self::WriteBesideParent,
        Self::TruncateBesideParent,
        Self::ListParent,
        Self::ListSibling,
        Self::ListSiblingPrivate,
    ];

    /// The name the probe writes in its report and the test reads back.
    fn name(self) -> &'static str {
        match self {
            Self::ReadInside => "read-inside-storage-root",
            Self::WriteInside => "write-inside-storage-root",
            Self::ReadExecutable => "read-bound-executable",
            Self::ReadBeneathParent => "read-beneath-storage-parent",
            Self::WriteBesideParent => "write-beside-storage-parent",
            Self::TruncateBesideParent => "truncate-beside-storage-parent",
            Self::ListParent => "list-storage-parent",
            Self::ListSibling => "list-sibling",
            Self::ListSiblingPrivate => "list-sibling-private",
        }
    }

    /// The path this call uses under `base`, derived from the one storage-root
    /// and parent derivation so the probe and the ruleset cannot drift.
    fn path(self, base: &Path) -> PathBuf {
        let root = provider_storage_root(WALLET_PROVIDER, base);
        let parent = storage_parent(WALLET_PROVIDER, base);
        match self {
            Self::ReadInside => root.join(LANDLOCK_PROBE_INSIDE_FILE),
            Self::WriteInside => root.join(LANDLOCK_PROBE_INSIDE_WRITE),
            Self::ReadExecutable => resolved(Path::new(PROVIDER_BINARY)),
            Self::ReadBeneathParent => parent
                .join(LANDLOCK_PROBE_PARENT_SIBLING)
                .join("private")
                .join(LANDLOCK_PROBE_BENEATH_FILE),
            Self::WriteBesideParent => parent.join(LANDLOCK_PROBE_BESIDE_PARENT_WRITE),
            Self::TruncateBesideParent => parent.join(LANDLOCK_PROBE_BESIDE_PARENT_TRUNCATE),
            Self::ListParent => parent,
            Self::ListSibling => parent.join(LANDLOCK_PROBE_PARENT_SIBLING),
            Self::ListSiblingPrivate => parent.join(LANDLOCK_PROBE_PARENT_SIBLING).join("private"),
        }
    }
}

/// The fixture names the file-row journey plants under the wallet root and its
/// parent. The files are planted by the parent, outside the ruleset, so a write
/// the probe is refused cannot be mistaken for a file it could not create.
#[cfg(target_os = "linux")]
const LANDLOCK_PROBE_INSIDE_FILE: &str = "landlock-inside-read.txt";
#[cfg(target_os = "linux")]
const LANDLOCK_PROBE_INSIDE_WRITE: &str = "landlock-inside-write.txt";
#[cfg(target_os = "linux")]
const LANDLOCK_PROBE_PARENT_SIBLING: &str = "sibling";
#[cfg(target_os = "linux")]
const LANDLOCK_PROBE_BENEATH_FILE: &str = "marker";
#[cfg(target_os = "linux")]
const LANDLOCK_PROBE_BESIDE_PARENT_WRITE: &str = "landlock-beside-write.txt";
/// The file the probe truncates outside `STORAGE_ROOT`. The parent plants it
/// with content before each run, so a truncation that succeeds is visible in its
/// bytes afterwards and not only in the probe's answer.
#[cfg(target_os = "linux")]
const LANDLOCK_PROBE_BESIDE_PARENT_TRUNCATE: &str = "landlock-beside-truncate.txt";
/// The exact bytes the planted read and write fixtures hold.
#[cfg(target_os = "linux")]
const LANDLOCK_PROBE_FIXTURE_BYTES: &[u8] = b"landlock file row fixture\n";

/// The prefix every Landlock probe record line starts with.
#[cfg(target_os = "linux")]
const LANDLOCK_PROBE_MARKER: &str = "landlock-probe:";
#[cfg(target_os = "linux")]
const LANDLOCK_PROBE_REFUSED: &[u8] = b"landlock-probe-refused:";

/// What one file call answered: the errno it failed with or the value it
/// returned. It is `SeccompAnswer`'s shape, so the probe record format and its
/// parser stay one (P10).
#[cfg(target_os = "linux")]
type LandlockAnswer = SeccompAnswer;

/// The answers one probe child recorded, in `LandlockProbeCall::ALL` order.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LandlockProbeReport {
    answers: [LandlockAnswer; LandlockProbeCall::ALL.len()],
}

/// What the Landlock probe child is asked to do.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LandlockProbeRun {
    /// Install the ruleset through `install_landlock`, make the calls and
    /// report them.
    Confined,
    /// Make the same calls with no ruleset, which is the positive control.
    Control,
    /// Run the confined case beneath an allow-all seccomp fixture filter.
    /// The child handles it. No test in this slice asks for it.
    #[allow(dead_code)]
    ConfinedUnderFilter,
    /// Prove Landlock sets the flag itself, before a seccomp installer can.
    RequireNoNewPrivileges,
    /// Negative control through the same installer, with just that step skipped.
    WithoutNoNewPrivileges,
}

/// One file call, as the answer the kernel gave it. Each arm makes the call its
/// name states and passes the complete argument list, so no call relies on a
/// register this function left unset.
#[cfg(target_os = "linux")]
fn landlock_probe_call(call: LandlockProbeCall, path: &std::ffi::CStr) -> LandlockAnswer {
    match call {
        LandlockProbeCall::ReadInside
        | LandlockProbeCall::ReadBeneathParent
        | LandlockProbeCall::ReadExecutable => seccomp_answer(|| read_file_answer(path)),
        LandlockProbeCall::WriteInside | LandlockProbeCall::WriteBesideParent => {
            seccomp_answer(|| write_file_answer(path))
        }
        LandlockProbeCall::TruncateBesideParent => seccomp_answer(|| truncate_file_answer(path)),
        LandlockProbeCall::ListParent
        | LandlockProbeCall::ListSibling
        | LandlockProbeCall::ListSiblingPrivate => seccomp_answer(|| list_directory_answer(path)),
    }
}

/// Opens `path` for reading and reads up to 256 bytes, or returns its errno.
#[cfg(target_os = "linux")]
fn read_file_answer(path: &std::ffi::CStr) -> i64 {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return -1;
    }
    let mut buffer = [0u8; 256];
    let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    let errno = unsafe { *libc::__errno_location() };
    unsafe { libc::close(fd) };
    if read < 0 {
        unsafe { *libc::__errno_location() = errno };
        return -1;
    }
    read as i64
}

/// Creates `path` for writing and writes the fixture bytes, answering their
/// length, or `-1` with its errno.
#[cfg(target_os = "linux")]
fn write_file_answer(path: &std::ffi::CStr) -> i64 {
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return -1;
    }
    let written = unsafe {
        libc::write(
            fd,
            LANDLOCK_PROBE_FIXTURE_BYTES.as_ptr().cast(),
            LANDLOCK_PROBE_FIXTURE_BYTES.len(),
        )
    };
    let errno = unsafe { *libc::__errno_location() };
    unsafe { libc::close(fd) };
    if written < 0 {
        unsafe { *libc::__errno_location() = errno };
        return -1;
    }
    written as i64
}

/// Truncates `path` to zero bytes with `truncate(2)` and answers `0`, or `-1`
/// with its errno. It is a write outside `STORAGE_ROOT` that opens nothing for
/// writing, so a ruleset whose handled mask names `WRITE_FILE` alone still
/// permits it and the answer shows that mask's gap. The path is one the parent
/// plants with content before each run, so the test reads the file's length
/// afterwards and a permitted truncation is visible there.
#[cfg(target_os = "linux")]
fn truncate_file_answer(path: &std::ffi::CStr) -> i64 {
    (unsafe { libc::truncate(path.as_ptr(), 0) }) as i64
}

/// Read directory entries into a fixed stack buffer. `opendir`/`readdir` own
/// libc heap state, so the forked child uses open/getdents64/close directly.
#[cfg(target_os = "linux")]
fn list_directory_answer(path: &std::ffi::CStr) -> i64 {
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return -1;
    }
    let mut buffer = [0u8; 4096];
    let mut count = 0i64;
    let result = loop {
        let read =
            unsafe { libc::syscall(libc::SYS_getdents64, fd, buffer.as_mut_ptr(), buffer.len()) };
        if read < 0 {
            break Err(unsafe { *libc::__errno_location() });
        }
        if read == 0 {
            break Ok(count);
        }
        let mut offset = 0;
        while offset < read as usize {
            // linux_dirent64: u64 inode, i64 offset, u16 record length.
            if offset + 19 > read as usize {
                break;
            }
            let length = u16::from_ne_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;
            if length < 19 || offset + length > read as usize {
                break;
            }
            count += 1;
            offset += length;
        }
        if offset != read as usize {
            break Err(libc::EIO);
        }
    };
    unsafe { libc::close(fd) };
    match result {
        Ok(count) => count,
        Err(errno) => {
            unsafe { *libc::__errno_location() = errno };
            -1
        }
    }
}

/// The probe child's body: make the nine calls under `run`'s policy, write one
/// line per call, and end the process at once.
///
/// It runs in a forked child before any exec, so a ruleset it installs reaches
/// only that child and the harness above it stays unconfined. It allocates
/// nothing after the fork and writes with raw `write` calls, because a forked
/// child may rely only on async-signal-safe calls. The base path arrives as a C
/// string the parent built, so the child formats no path. It counts allocations
/// with the one guard the seccomp probe uses.
#[cfg(target_os = "linux")]
fn run_landlock_probe_child(
    report: std::os::fd::RawFd,
    run: LandlockProbeRun,
    ruleset: &PreparedLandlockRuleset,
    paths: &[std::ffi::CString],
    fixture_filter: &SeccompAllowList,
) -> ! {
    if let Err(errno) = retain_probe_report_descriptor(report) {
        write_all(
            report,
            b"the landlock probe child could not close inherited descriptors: errno ",
        );
        write_number(report, i64::from(errno));
        unsafe { libc::_exit(71) }
    }
    begin_counting_child_allocations();
    if matches!(
        run,
        LandlockProbeRun::RequireNoNewPrivileges | LandlockProbeRun::WithoutNoNewPrivileges
    ) {
        let flag = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        if flag != 0 {
            write_all(
                report,
                b"no_new_privs must be clear before the Landlock install\n",
            );
            unsafe { libc::_exit(72) }
        }
    }
    // The seccomp fixture filter is installed first so the confined case still
    // runs under it; it admits every call, so it changes no answer here.
    if run == LandlockProbeRun::ConfinedUnderFilter {
        if let Err(failure) = install_seccomp(fixture_filter) {
            write_all(report, LANDLOCK_PROBE_REFUSED);
            write_all(report, &failure.launch_record());
            unsafe { libc::_exit(70) }
        }
    }
    if run != LandlockProbeRun::Control {
        if let Err(failure) = install_landlock(ruleset) {
            write_all(report, LANDLOCK_PROBE_REFUSED);
            write_all(report, &failure.launch_record());
            unsafe { libc::_exit(70) }
        }
    }
    if run == LandlockProbeRun::RequireNoNewPrivileges
        && unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
    {
        write_all(
            report,
            b"no_new_privs must be set by the Landlock install\n",
        );
        unsafe { libc::_exit(73) }
    }
    let mut buffer = [0u8; 256];
    for (call, path) in LandlockProbeCall::ALL.into_iter().zip(paths) {
        let answer = landlock_probe_call(call, path);
        let mut written = copy_bytes(&mut buffer, LANDLOCK_PROBE_MARKER.as_bytes());
        written += copy_bytes(&mut buffer[written..], b" ");
        written += copy_bytes(&mut buffer[written..], call.name().as_bytes());
        written += copy_bytes(&mut buffer[written..], b" ");
        written += copy_answer(&mut buffer[written..], answer);
        written += copy_bytes(&mut buffer[written..], b"\n");
        write_all(report, &buffer[..written]);
    }
    unsafe {
        libc::syscall(libc::SYS_exit_group, 0 as libc::c_long);
    }
    unreachable!("exit_group must not return")
}

/// The allow-all seccomp fixture filter the confined-under-filter case installs:
/// wallet's probe list with one `ALLOW` decision, built before the fork because
/// the child allocates nothing.
#[cfg(target_os = "linux")]
fn landlock_probe_allow_all() -> SeccompAllowList {
    let mut allow =
        seccomp_probe_list(WALLET_PROVIDER).unwrap_or_else(|err| panic!("wallet's list: {err}"));
    allow.program = vec![SeccompInstruction::stmt(
        SECCOMP_BPF_RET_K,
        SECCOMP_RET_ALLOW,
    )];
    allow
}

/// Runs one Landlock probe child and returns its answers, or a refusal
/// naming what happened. The child is a fork of this process, so its ruleset
/// reaches only itself. The child is reaped on every result, including a
/// timeout, so a repeated journey leaves no probe behind.
#[cfg(target_os = "linux")]
fn landlock_file_probe(
    ruleset: &LandlockRuleset,
    run: LandlockProbeRun,
    base: &Path,
) -> Result<LandlockProbeReport, String> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    let mut prepared =
        PreparedLandlockRuleset::new(ruleset).map_err(|failure| failure.to_string())?;
    prepared.skip_no_new_privileges = run == LandlockProbeRun::WithoutNoNewPrivileges;
    let paths = LandlockProbeCall::ALL
        .into_iter()
        .map(|call| {
            std::ffi::CString::new(call.path(base).as_os_str().as_bytes())
                .map_err(|_| format!("landlock probe refused: {} path contains NUL", call.name()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fixture_filter = landlock_probe_allow_all();

    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(format!(
            "landlock probe refused: the report pipe could not open: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut reader = unsafe { fs::File::from_raw_fd(fds[0]) };
    let writer = unsafe { fs::File::from_raw_fd(fds[1]) };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "landlock probe refused: the probe child could not start: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        run_landlock_probe_child(writer.as_raw_fd(), run, &prepared, &paths, &fixture_filter);
    }
    drop(writer);

    let exit = wait_for_probe_exit(pid);
    assert_probe_reaped(pid);
    let started = Instant::now();
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 256];
    loop {
        if started.elapsed() >= CHILD_EXIT_DEADLINE {
            return Err(format!(
                "landlock probe refused: child {exit} wrote no complete report within {}s",
                CHILD_EXIT_DEADLINE.as_secs()
            ));
        }
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.len() > libc::PIPE_BUF {
                    return Err("landlock probe refused: the report exceeds PIPE_BUF".into());
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(CHILD_EXIT_POLL);
            }
            Err(err) => {
                return Err(format!(
                    "landlock probe refused: reading the report failed: {err}"
                ))
            }
        }
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    match exit {
        ProbeExit::Code(code) if code == 0 => {}
        ProbeExit::Code(_) if bytes.starts_with(LANDLOCK_PROBE_REFUSED) => {
            return Err(
                match decode_seccomp_launch_record(&bytes[LANDLOCK_PROBE_REFUSED.len()..]) {
                    Ok(SeccompLaunchRecord::Refused(failure)) => format!(
                        "landlock probe refused: the probe child must install the ruleset: {failure}"
                    ),
                    Ok(SeccompLaunchRecord::Installed(_)) => {
                        "landlock probe refused: the refused child reported an installed policy"
                            .into()
                    }
                    Err(reason) => reason,
                },
            );
        }
        other => {
            return Err(format!(
                "landlock probe refused: child {other}; report: {text}"
            ))
        }
    }
    parse_landlock_probe_report(&text)
        .map_err(|refusal| format!("landlock probe refused: {refusal}"))
}

/// The records the probe child wrote, each with its answer. A missing or
/// unreadable record is a refusal that names the call, so a child that stopped
/// early cannot pass the journey.
#[cfg(target_os = "linux")]
fn parse_landlock_probe_report(text: &str) -> Result<LandlockProbeReport, String> {
    let mut answers = [LandlockAnswer::Returned(0); LandlockProbeCall::ALL.len()];
    for (slot, call) in answers.iter_mut().zip(LandlockProbeCall::ALL) {
        let marker = format!("{LANDLOCK_PROBE_MARKER} {} ", call.name());
        let line = text
            .lines()
            .find(|line| line.starts_with(&marker))
            .ok_or_else(|| format!("the probe recorded no answer for {}: {text}", call.name()))?;
        let answer = line[marker.len()..].trim();
        *slot = LandlockAnswer::parse(answer)
            .ok_or_else(|| format!("{}: {answer} is not an answer", call.name()))?;
    }
    Ok(LandlockProbeReport { answers })
}

/// One fixture for all file-row probes. Paths and marker bytes are prepared
/// before fork; only the child receives the ruleset.
#[cfg(target_os = "linux")]
fn landlock_file_fixture(
    loader: &[(&str, &str)],
) -> (tempfile::TempDir, PathBuf, Value, LandlockRuleset) {
    let declared_rights =
        read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
            .unwrap_or_else(|err| panic!("{err}"));
    let fixture = tempfile::tempdir().expect("temporary wallet base");
    let base = resolved(fixture.path());

    let bindings = canonical_bindings(WALLET_PROVIDER, &base, Path::new(PROVIDER_BINARY));
    create_shared_ancestors(&bindings);
    let root = provider_storage_root(WALLET_PROVIDER, &base);
    fs::create_dir_all(&root).expect("the wallet root must be creatable");

    let reported_abi = landlock_abi().unwrap_or_else(|failure| {
        panic!("the host must report a Landlock ABI for this row: {failure}")
    });
    eprintln!("{}", linux_landlock_journey_label(Some(reported_abi)));
    let ruleset = landlock_path_rules(
        WALLET_PROVIDER,
        &declared_rights,
        &bindings,
        reported_abi,
        loader,
    )
    .unwrap_or_else(|err| panic!("{err}"));

    let inside_read = LandlockProbeCall::ReadInside.path(&base);
    let beneath_read = LandlockProbeCall::ReadBeneathParent.path(&base);
    fs::write(&inside_read, LANDLOCK_PROBE_FIXTURE_BYTES).unwrap_or_else(|err| {
        panic!(
            "the inside fixture {} must be writable: {err}",
            inside_read.display()
        )
    });
    fs::create_dir_all(
        beneath_read
            .parent()
            .expect("the planted file's sibling directory"),
    )
    .expect("the sibling directory must be creatable");
    fs::write(&beneath_read, LANDLOCK_PROBE_FIXTURE_BYTES).unwrap_or_else(|err| {
        panic!(
            "the planted file {} must be writable: {err}",
            beneath_read.display()
        )
    });
    assert_eq!(
        fs::read(&beneath_read).expect("the planted file must be readable outside any ruleset"),
        LANDLOCK_PROBE_FIXTURE_BYTES,
        "the planted file beneath STORAGE_PARENT must hold its bytes before the confined run"
    );
    plant_landlock_probe_truncate_fixture(&base);

    (fixture, base, declared_rights, ruleset)
}

/// Plants the file the probe truncates beside `STORAGE_PARENT`, outside every
/// grant, with the fixture bytes. A truncation the ruleset permits leaves it
/// empty, so the test reads its length on both sides of a run and a permitted
/// truncation cannot hide behind a file the parent never wrote.
#[cfg(target_os = "linux")]
fn plant_landlock_probe_truncate_fixture(base: &Path) {
    let path = LandlockProbeCall::TruncateBesideParent.path(base);
    fs::write(&path, LANDLOCK_PROBE_FIXTURE_BYTES).unwrap_or_else(|err| {
        panic!(
            "the truncate fixture {} must be writable: {err}",
            path.display()
        )
    });
    assert_eq!(
        fs::read(&path).expect("the truncate fixture must be readable outside any ruleset"),
        LANDLOCK_PROBE_FIXTURE_BYTES,
        "the truncate fixture must hold its bytes before the run"
    );
}

#[cfg(target_os = "linux")]
fn clear_landlock_probe_writes(base: &Path) {
    for call in [
        LandlockProbeCall::WriteInside,
        LandlockProbeCall::WriteBesideParent,
    ] {
        match fs::remove_file(call.path(base)) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!("the probe write fixture must be removable: {err}"),
        }
    }
}

/// The child enters with `no_new_privs` clear. `restrict_self` must refuse
/// `EPERM` (1) while that flag is clear, and a clear flag must still install a
/// fully confined report once the installer sets the flag itself.
#[cfg(target_os = "linux")]
#[test]
fn linux_landlock_requires_no_new_privs() {
    let (_fixture, base, _, ruleset) = landlock_file_fixture(&[]);
    let refusal = landlock_file_probe(&ruleset, LandlockProbeRun::WithoutNoNewPrivileges, &base)
        .expect_err("restrict_self must refuse when no_new_privs is clear");
    assert_eq!(
        refusal,
        "landlock probe refused: the probe child must install the ruleset: landlock install refused: landlock_restrict_self failed with errno 1"
    );
    let report = landlock_file_probe(&ruleset, LandlockProbeRun::RequireNoNewPrivileges, &base)
        .expect("Landlock must set no_new_privs from a clear flag and install successfully");
    for (call, answer) in LandlockProbeCall::ALL.into_iter().zip(report.answers) {
        if matches!(
            call,
            LandlockProbeCall::ReadInside | LandlockProbeCall::WriteInside
        ) {
            assert!(
                matches!(answer, LandlockAnswer::Returned(_)),
                "{} must succeed in the confined report, and it answered {answer:?}",
                call.name()
            );
        } else {
            assert_eq!(
                answer,
                LandlockAnswer::Errno(libc::EACCES),
                "{} must be refused EACCES in the confined report, and it answered {answer:?}",
                call.name()
            );
        }
    }
}

/// The journey: wallet starts under the generated Landlock file row and the
/// generated seccomp list, and one probe child under the same ruleset shows the
/// file row refusing every path outside `STORAGE_ROOT` while the same calls
/// succeed without it.
///
/// The positive control uses the same uid and the same fixtures and no ruleset,
/// and every control call must succeed. The confined run requires `EACCES` (13),
/// never `EPERM`, for the read of the bound executable, the read beneath
/// `STORAGE_PARENT`, the write beside it, the truncation beside it, and the
/// listings of `STORAGE_PARENT`, `sibling` and `sibling/private`. The inside
/// read and write succeed. The wallet start answers `init` `ok`, `status` `ok`
/// and an empty `list_accounts`. An `Init` for a base outside `STORAGE_ROOT` is
/// refused `storage_error` with `Permission denied` and creates nothing. The
/// truncate fixture keeps its bytes. A start on a non-Linux host, and a start
/// on a host that reports Landlock missing, are refused.
///
/// The two Linux-only plants are recorded in `CONFINEMENT-LINUX.md` and are not
/// registered: a launcher that skips only its own Landlock install fails the
/// outside `Init`, and a `STORAGE_PARENT` row that grants a read fails the
/// planted read beneath the parent.
#[cfg(target_os = "linux")]
#[test]
fn linux_wallet_file_row_is_refused_outside_storage_root() {
    let (_fixture, base, declared_rights, ruleset) = landlock_file_fixture(LANDLOCK_LOADER_PATHS);
    let profile_fixture = tempfile::tempdir().expect("temporary profile root");
    let profile_dir = resolved(profile_fixture.path());
    let root = provider_storage_root(WALLET_PROVIDER, &base);
    let inside_read = LandlockProbeCall::ReadInside.path(&base);
    let allow = seccomp_probe_list(WALLET_PROVIDER).unwrap_or_else(|err| panic!("{err}"));
    let policy = StandinPolicy::Landlock {
        allow: &allow,
        ruleset: &ruleset,
    };

    let missing = standin_spawn_confined_provider(
        StandinHost::linux_missing(StandinPrimitive::Landlock),
        policy,
        WALLET_PROVIDER,
        Path::new(PROVIDER_BINARY),
        &base,
        &declared_rights,
        &profile_dir,
    )
    .expect_err("a host that reports Landlock missing must refuse the start");
    assert!(
        missing.contains("linux confinement refused: the kernel has no Landlock"),
        "a missing Landlock report must keep the design's words: {missing}"
    );
    let other_os = standin_spawn_confined_provider(
        StandinHost::reporting("macos"),
        policy,
        WALLET_PROVIDER,
        Path::new(PROVIDER_BINARY),
        &base,
        &declared_rights,
        &profile_dir,
    )
    .expect_err("a non-linux host must refuse the start");
    assert!(
        other_os.contains("the seccomp allow list is the linux policy")
            && other_os.contains("macos is not linux"),
        "a non-linux host must be refused by name: {other_os}"
    );

    let control = landlock_file_probe(&ruleset, LandlockProbeRun::Control, &base)
        .unwrap_or_else(|failure| panic!("the positive control must run: {failure}"));
    for (call, answer) in LandlockProbeCall::ALL.iter().zip(control.answers) {
        assert!(
            matches!(answer, LandlockAnswer::Returned(_)),
            "the control must show {} succeeding without the ruleset, and it answered {answer:?} \
             ({call:?} on {}), so this run has no evidence for that call",
            call.name(),
            call.path(&base).display()
        );
        eprintln!("control {}: {}", call.name(), answer.text());
    }
    clear_landlock_probe_writes(&base);
    plant_landlock_probe_truncate_fixture(&base);

    let mut provider = standin_spawn_confined_provider(
        StandinHost::reporting("linux"),
        policy,
        WALLET_PROVIDER,
        Path::new(PROVIDER_BINARY),
        &base,
        &declared_rights,
        &profile_dir,
    )
    .unwrap_or_else(|err| panic!("the linux wallet start must be confined: {err}"));

    let status = provider.send(&json!({ "op": "status" }));
    assert_eq!(status["status"], "ok", "status must answer: {status}");
    let accounts = provider.wallet(WalletProviderOperationV2::ListAccounts {
        include_revoked: false,
    });
    assert_eq!(
        ok_data(accounts)["accounts"],
        json!([]),
        "a fresh wallet lists no account"
    );
    assert!(
        profile_dir_entries(&profile_dir).is_empty(),
        "a landlock start writes no profile: {}",
        profile_dir.display()
    );

    let outside_base = storage_parent(WALLET_PROVIDER, &base).join("landlock-outside-base");
    let outside_init = provider.init(&outside_base);
    assert_eq!(
        outside_init["status"], "error",
        "an Init for a base outside STORAGE_ROOT must be refused under the launch: {outside_init}"
    );
    assert_eq!(
        outside_init["code"], "storage_error",
        "the outside Init must be a storage refusal: {outside_init}"
    );
    let reason = outside_init["message"]
        .as_str()
        .unwrap_or_else(|| panic!("the outside Init must carry a reason: {outside_init}"));
    assert!(
        reason.contains("Permission denied"),
        "the outside Init must be refused by the kernel's own denial, and it answered: {reason}"
    );
    assert!(
        !outside_base.exists() && !provider_storage_root(WALLET_PROVIDER, &outside_base).exists(),
        "a refused outside Init must create nothing: {}",
        outside_base.display()
    );
    eprintln!("launch outside Init: {outside_init}");
    provider.shutdown();

    assert!(
        root.join(WALLET_KEY_FILE).exists(),
        "the confined launch must create its storage key under STORAGE_ROOT"
    );
    assert_eq!(
        fs::read(&inside_read).expect("the inside fixture must stay readable"),
        LANDLOCK_PROBE_FIXTURE_BYTES,
        "the launch must leave the inside fixture's bytes unchanged"
    );

    let confined = landlock_file_probe(&ruleset, LandlockProbeRun::Confined, &base)
        .unwrap_or_else(|failure| panic!("{failure}"));
    for ((call, control_answer), confined_answer) in LandlockProbeCall::ALL
        .iter()
        .zip(control.answers)
        .zip(confined.answers)
    {
        eprintln!(
            "confined {}: control {}, ruleset {}",
            call.name(),
            control_answer.text(),
            confined_answer.text()
        );
    }
    let refused = |call: LandlockProbeCall| {
        let index = LandlockProbeCall::ALL
            .iter()
            .position(|candidate| *candidate == call)
            .expect("the call is one of the probe's own");
        confined.answers[index]
    };
    for call in [
        LandlockProbeCall::ReadInside,
        LandlockProbeCall::WriteInside,
    ] {
        assert!(
            matches!(refused(call), LandlockAnswer::Returned(_)),
            "{} must succeed inside STORAGE_ROOT under the ruleset, and it answered {:?}",
            call.name(),
            refused(call)
        );
    }
    for call in [
        LandlockProbeCall::ReadExecutable,
        LandlockProbeCall::ReadBeneathParent,
        LandlockProbeCall::WriteBesideParent,
        LandlockProbeCall::TruncateBesideParent,
        LandlockProbeCall::ListParent,
        LandlockProbeCall::ListSibling,
        LandlockProbeCall::ListSiblingPrivate,
    ] {
        assert_eq!(
            refused(call),
            LandlockAnswer::Errno(libc::EACCES),
            "{} must be refused EACCES (13), never EPERM, and it answered {:?}",
            call.name(),
            refused(call)
        );
    }
    assert_eq!(
        fs::read(LandlockProbeCall::WriteInside.path(&base))
            .expect("the confined write must have created the file inside the root"),
        LANDLOCK_PROBE_FIXTURE_BYTES,
        "the confined write inside the root must hold its bytes"
    );
    assert!(
        !LandlockProbeCall::WriteBesideParent.path(&base).exists(),
        "a refused write beside the parent must leave no file: {}",
        LandlockProbeCall::WriteBesideParent.path(&base).display()
    );
    assert_eq!(
        fs::read(LandlockProbeCall::TruncateBesideParent.path(&base))
            .expect("a refused truncation must leave the planted file in place"),
        LANDLOCK_PROBE_FIXTURE_BYTES,
        "a refused truncation beside the parent must leave its bytes unchanged"
    );
}

/// Runs the calling test again in a child test process beneath an installed
/// allow-all fixture filter, so a launcher that skips only its own `pre_exec`
/// install cannot pass on the inherited filter alone.
///
/// `test_name` is the caller's own test name, which the child runs by that exact
/// name, so one fixture serves both providers' journeys instead of a copy per
/// caller. The fixture filter is installed through the one `install_seccomp`, and
/// its `ALLOW` decision leaves the host's own marker answer intact.
///
/// It returns `false` in the parent, which has run the child and required its
/// exit 0, and `true` in the child, whose own `/proc/self/status` the caller then
/// checks. The parent test runner keeps its own policy and the existing process
/// owner reaps the run.
#[cfg(target_os = "linux")]
fn seccomp_journey_runs_beneath_an_inherited_filter(name: &str, test_name: &str) -> bool {
    use std::os::unix::process::CommandExt as _;

    const INHERITED_FIXTURE: &str = "SECCOMP_INHERITED_FIXTURE";
    if std::env::var_os(INHERITED_FIXTURE).as_deref() == Some(std::ffi::OsStr::new("1")) {
        return true;
    }
    let mut inherited = seccomp_probe_list(name).unwrap_or_else(|err| panic!("{err}"));
    inherited.program = vec![SeccompInstruction::stmt(
        SECCOMP_BPF_RET_K,
        SECCOMP_RET_ALLOW,
    )];
    let mut command = Command::new(std::env::current_exe().expect("the journey test binary"));
    command
        .args(["--exact", test_name, "--nocapture"])
        .env(INHERITED_FIXTURE, "1");
    unsafe {
        command.pre_exec(move || {
            install_seccomp(&inherited)
                .map_err(|failure| std::io::Error::from_raw_os_error(failure.errno()))
        });
    }
    let mut journey = ConfinedProvider::spawn(command);
    let exit = journey.wait_for_exit();
    let stderr = journey.stderr().to_owned();
    let mut stdout = String::new();
    journey
        .stdout
        .read_to_string(&mut stdout)
        .expect("the journey output");
    eprintln!("{stdout}{stderr}");
    assert_eq!(
        exit.code(),
        Some(0),
        "{test_name} under an inherited filter must pass: {exit}"
    );
    false
}

/// One provider's named seccomp journey paths, so both journeys compare the same
/// three named fixtures instead of restating them per caller.
///
/// `inside` is the file the run writes under `STORAGE_ROOT`, `inside_fixture` is
/// a fixed-byte file beside it that the read-only calls must not change, and
/// `outside` is a sibling path outside `STORAGE_ROOT` that must stay absent. The
/// sibling is derived from `storage_parent` for both providers, so a path that
/// drifts out of the grant shows as a present file. `expected_fixture` is the
/// provider's own known bytes, so a run that wrote the wrong file fails.
struct SeccompJourneyFiles {
    inside: PathBuf,
    inside_fixture: PathBuf,
    outside: PathBuf,
    expected_fixture: &'static [u8],
}

/// The named journey fixtures of `name` under `base`, or a panic naming the
/// provider whose layout this function does not know. The lab serves two
/// providers and a guessed layout would be a fallback (P11).
fn seccomp_journey_files(name: &str, base: &Path) -> SeccompJourneyFiles {
    let root = provider_storage_root(name, base);
    let (inside_name, expected_fixture): (&str, &[u8]) = match name {
        WALLET_PROVIDER => (WALLET_KEY_FILE, b"wallet seccomp journey fixture\n"),
        DID_PROVIDER => ("nickname.enc", b"did seccomp journey fixture\n"),
        other => panic!("the journey names no provider whose fixtures it knows: {other}"),
    };
    SeccompJourneyFiles {
        inside: root.join(inside_name),
        inside_fixture: root.join("seccomp-inside-write"),
        outside: storage_parent(name, base).join("seccomp-outside-write"),
        expected_fixture,
    }
}

/// Both callers use these same comparisons after shutdown. Wallet's key-format
/// assertions then inspect the returned bytes separately.
fn assert_seccomp_journey_files(
    name: &str,
    files: &SeccompJourneyFiles,
    expected_inside: &[u8],
) -> Vec<u8> {
    let inside_reason = match name {
        WALLET_PROVIDER => {
            "the read-only journey must keep the exact key bytes from init".to_owned()
        }
        DID_PROVIDER => format!(
            "the {name} journey must keep the exact bytes set_nickname wrote under STORAGE_ROOT"
        ),
        other => panic!("the journey names no provider whose file evidence it knows: {other}"),
    };
    let written = fs::read(&files.inside)
        .unwrap_or_else(|err| panic!("the launch must write {}: {err}", files.inside.display()));
    assert_eq!(written, expected_inside, "{inside_reason}");
    assert_eq!(
        fs::read(&files.inside_fixture).expect("the named inside fixture must remain readable"),
        files.expected_fixture,
        "the named inside fixture must keep its exact expected bytes"
    );
    assert!(
        !files.outside.exists(),
        "the named sibling outside STORAGE_ROOT must stay absent after the run: {}",
        files.outside.display()
    );
    written
}

/// A changed provider file, a corrupt fixed-byte fixture and a present outside
/// sibling each fail the journey's one comparison for both provider layouts.
#[test]
fn seccomp_journey_file_comparison_catches_corruption_for_each_provider() {
    for name in [WALLET_PROVIDER, DID_PROVIDER] {
        for changed in ["inside", "inside_fixture", "outside"] {
            let base = tempfile::tempdir().expect("temporary journey comparison root");
            let files = seccomp_journey_files(name, base.path());
            fs::create_dir_all(provider_storage_root(name, base.path()))
                .expect("the provider fixture root must exist");
            let expected_inside = b"bytes written by the provider";
            fs::write(&files.inside, expected_inside).expect("the provider file must be writable");
            fs::write(&files.inside_fixture, files.expected_fixture)
                .expect("the named inside fixture must be writable");
            assert_seccomp_journey_files(name, &files, expected_inside);

            let changed_path = match changed {
                "inside" => &files.inside,
                "inside_fixture" => &files.inside_fixture,
                "outside" => &files.outside,
                _ => unreachable!(),
            };
            fs::write(changed_path, b"corrupt journey bytes")
                .expect("the plant must write its file");
            let failure = std::panic::catch_unwind(|| {
                assert_seccomp_journey_files(name, &files, expected_inside)
            })
            .expect_err("each changed file must fail the shared journey comparison");
            let reason = failure
                .downcast_ref::<String>()
                .expect("the comparison must report its assertion reason");
            let expected_reason = match changed {
                "inside" => match name {
                    WALLET_PROVIDER => "the read-only journey must keep the exact key bytes from init",
                    DID_PROVIDER => "the did-provider journey must keep the exact bytes set_nickname wrote under STORAGE_ROOT",
                    _ => unreachable!(),
                },
                "inside_fixture" => "the named inside fixture must keep its exact expected bytes",
                "outside" => "the named sibling outside STORAGE_ROOT must stay absent after the run",
                _ => unreachable!(),
            };
            assert!(
                reason.contains(expected_reason),
                "{name} {changed} must fail its own comparison: {reason}"
            );
        }
    }
}

/// One provider's Linux journey: `name` starts under the seccomp allow list built
/// from that provider's own committed declared-rights file, its permitted calls
/// answer under the filter. Wallet also runs the one probe child under that
/// filter to show the four refused calls answering the filter's own marker.
///
/// `binary` is that provider's own binary and `declared` its own declared rights,
/// so the one body serves both providers through `standin_spawn_confined_provider`
/// with a `Seccomp` policy, which reaches `ConfinedProvider::start_under_seccomp`
/// and that function's one `spawn`. `test_name` is the caller's own test name,
/// which the inherited-filter fixture re-runs. There is no per-provider launcher,
/// list builder or probe.
///
/// The list carries `name` as its `provider`, and its program must equal the
/// program built the same way for wallet. The two committed declared-rights files
/// declare the same rights and the same two platform-baseline ids, whose rule
/// text is identical, so the equality follows from that sameness: a difference
/// would be a per-provider widening of the filter and fails here.
///
/// The launched child must report `SECCOMP_MODE_FILTER` in its own
/// `/proc/<pid>/status`, and the mode alone also accepts an inherited filter, so
/// the launcher's record must additionally show the marker answering differently
/// before and after this launcher's own install.
///
/// For wallet, one probe child records what `ptrace(PTRACE_TRACEME)`, `mount`,
/// `bpf` and `keyctl` answer before the filter, installs the filter through
/// `install_seccomp`, and records the same four after. Each filtered answer must
/// be the deny marker, and the marker must differ from the unfiltered answer the
/// same probe recorded, so a host that already refuses a call cannot stand in
/// for the filter. That evidence belongs to the one probe and is not re-proven
/// per provider.
///
/// The comment below is the record of where this ran: the marker errno, the
/// host, and the call whose failure named each `LAUNCH_ESSENTIALS` entry.
#[cfg(target_os = "linux")]
fn seccomp_confined_journey(name: &str, binary: &Path, declared: &Value, test_name: &str) {
    if !seccomp_journey_runs_beneath_an_inherited_filter(name, test_name) {
        return;
    }
    let inherited_status = fs::read_to_string("/proc/self/status").expect("the fixture's status");
    assert!(
        inherited_status.lines().any(|line| line == "Seccomp:\t2"),
        "the journey fixture must already carry an inherited filter"
    );
    eprintln!("journey fixture before provider launch: Seccomp: 2 (inherited)");
    // Ran on spark1.local: aarch64, Ubuntu 24.04.4, kernel 6.17.0-1029-nvidia.
    // The deny marker is EACCES (13). Each unfiltered answer differed from it on
    // that host: ptrace(PTRACE_TRACEME) returned 0, mount answered ENOENT (2),
    // bpf answered EINVAL (22) and keyctl(KEYCTL_GET_KEYRING_ID, session
    // keyring, create 0) answered a session keyring id. EACCES is chosen because
    // the kernel answers EPERM for a call an unprivileged process may not make,
    // so a plain EPERM assertion would pass with no filter installed.
    //
    // Each LAUNCH_ESSENTIALS entry was dropped alone from the whole list on that
    // host and the call that then failed was read, for wallet's binary and again
    // for did's. The did measurement used the wider fchmodat policy recorded in
    // CONFINEMENT-LINUX.md; its journey still needs a policy-owner decision.
    // Both measurements named the same seven entries, so the set is one table:
    // close -> close(3) in the loader, refused before the first mapping;
    // exit_group -> exit_group(0) as the provider ended its own run; getrandom ->
    // getrandom(0xec92ac7c6700, 8, GRND_NONBLOCK) in the loader; mmap ->
    // mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    // in the loader, after which the provider took SIGSEGV; mprotect ->
    // mprotect(0xf2640329f000, 65536, PROT_NONE) in the loader; ppoll ->
    // ppoll([{fd=0}, {fd=1}, {fd=2}], 3, {tv_sec=0, tv_nsec=0}, NULL, 0) while
    // the provider waits; rt_sigaction -> rt_sigaction(SIGPIPE,
    // {sa_handler=SIG_IGN, sa_mask=[PIPE], sa_flags=SA_RESTART},
    // 0xffffea09ff80, 8). For did the same seven failed as
    // `libgcc_s.so.1: cannot close file descriptor`, an unclean exit, a `rand`
    // seed panic, `SIGSEGV`, `libgcc_s.so.1: cannot change memory protections`,
    // `SIGTRAP`, and `assertion failed: signal(libc::SIGPIPE, handler)`.

    let allow = seccomp_probe_list(name).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(
        allow.provider, name,
        "the seccomp allow list must name the provider it was built for"
    );
    let wallet_allow = seccomp_probe_list(WALLET_PROVIDER).unwrap_or_else(|err| panic!("{err}"));
    assert_eq!(
        allow.program, wallet_allow.program,
        "the {name} program must equal wallet's: the two declared-rights files \
         declare the same rights and the same two platform-baseline ids with \
         identical rule text, so a difference is a per-provider widening"
    );
    eprintln!("{}", linux_seccomp_journey_label());

    let fixture = tempfile::tempdir().expect("temporary provider base");
    let base = resolved(fixture.path());
    let profile_fixture = tempfile::tempdir().expect("temporary profile root");
    let profile_dir = resolved(profile_fixture.path());
    let files = seccomp_journey_files(name, &base);

    let mut provider = standin_spawn_confined_provider(
        StandinHost::reporting("linux"),
        StandinPolicy::Seccomp(&allow),
        name,
        binary,
        &base,
        declared,
        &profile_dir,
    )
    .unwrap_or_else(|err| panic!("the linux {name} start must be confined: {err}"));

    let label = format!("{name} seccomp journey");
    // Wallet init has made its root; did first creates it when writing a
    // nickname. Prepare the sentinel before either provider's operation suite
    // so an operation that corrupts it leaves the evidence for the comparison.
    fs::create_dir_all(provider_storage_root(name, &base))
        .expect("the provider fixture root must exist");
    fs::write(&files.inside_fixture, files.expected_fixture)
        .expect("the named inside fixture must be writable");
    // The bytes of the file the run wrote under STORAGE_ROOT, read at the point
    // the provider wrote it: wallet's `init` writes the random key, and did's
    // `set_nickname` writes the encrypted nickname.
    let expected_inside = match name {
        WALLET_PROVIDER => {
            // Init creates the random key. Keep those exact bytes as the expected
            // value across the read-only calls, and also compare a fixed byte
            // fixture.
            let expected_key = fs::read(&files.inside).expect("init must create the storage key");
            let status = provider.send(&json!({ "op": "status" }));
            assert_eq!(status["status"], "ok", "status must answer: {status}");
            let accounts = provider.wallet(WalletProviderOperationV2::ListAccounts {
                include_revoked: false,
            });
            assert_eq!(
                ok_data(accounts)["accounts"],
                json!([]),
                "a fresh wallet lists no account"
            );
            expected_key
        }
        DID_PROVIDER => {
            let record = did_standin_permitted_operations(&mut provider, &base, &label);
            assert_suite_outcomes(&label, &record, &DID_SUITE_CASES[..DID_PERMITTED_CASES]);
            fs::read(&files.inside).unwrap_or_else(|err| {
                panic!(
                    "{label}: set_nickname must write {}: {err}",
                    files.inside.display()
                )
            })
        }
        other => panic!("the journey names no provider whose permitted calls it knows: {other}"),
    };
    assert_eq!(
        provider.launched_seccomp_mode(),
        SECCOMP_MODE_FILTER,
        "the launched provider must carry SECCOMP_MODE_FILTER in its own /proc status, \
         so the launcher's pre_exec install is observed"
    );
    let [before_install, after_install] = provider
        .seccomp_launch_answers
        .expect("the launcher must report its own install's before and after answers");
    eprintln!("launcher marker: before {before_install}, after {after_install}");
    assert_ne!(
        before_install, after_install,
        "an inherited filter alone must not satisfy the launcher's own install"
    );
    assert_eq!(
        after_install,
        -i64::from(SECCOMP_DENY_ERRNO),
        "this launcher's install must supply the deny marker"
    );
    assert!(
        profile_dir_entries(&profile_dir).is_empty(),
        "a seccomp start writes no profile: {}",
        profile_dir.display()
    );
    provider.shutdown();

    let written = assert_seccomp_journey_files(name, &files, &expected_inside);
    if name == WALLET_PROVIDER {
        let text = String::from_utf8(written).expect("the storage key must be hex text");
        let digits = text
            .strip_suffix('\n')
            .expect("the storage key must end with a newline");
        assert_eq!(
            digits.len(),
            2 * WALLET_KEY_BYTES,
            "the storage key must hold its {} hex digits and a newline: {}",
            2 * WALLET_KEY_BYTES,
            files.inside.display()
        );
        assert!(
            digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "the storage key must be hex: {}",
            files.inside.display()
        );
    }

    // Wallet owns the four-call kernel proof; did proves program equality.
    if name == WALLET_PROVIDER {
        let probe = seccomp_denied_call_probe(&allow, SeccompProbeRun::Filter)
            .unwrap_or_else(|failure| panic!("{failure}"));
        for (call, before, after) in &probe.records {
            assert_eq!(
                *after,
                SeccompAnswer::Errno(SECCOMP_DENY_ERRNO),
                "{call} must answer the deny marker {SECCOMP_DENY_ERRNO} under the filter, \
                 and it answered {after:?}"
            );
            assert_ne!(
                after, before,
                "{call} answered {after:?} both with and without the filter, so this probe \
                 does not show the filter's own answer"
            );
            eprintln!("{call}: before {}, after {}", before.text(), after.text());
        }
        assert_eq!(
            probe.allocations, 0,
            "the probe child must allocate nothing after its fork"
        );
    }
}

/// The wallet half of the Linux journey, and the body is
/// `seccomp_confined_journey`: this caller passes wallet's own binary, file and
/// test name.
///
/// Falsifier: WP176 skips only the launcher's `pre_exec` install and leaves the
/// self-filtering probe intact. The journey inherits an allow-all fixture filter,
/// so the mode assertion passes and the before/after assertion fails. WP177
/// writes the named outside sibling, so the journey finds it present and fails.
/// WP162 labels the journey with a Linux host off Linux and is caught by
/// `linux_seccomp_journey_is_not_applicable_off_linux` on the Mac. Both Linux
/// plants reach a Linux-only test, so neither is registered in `falsifiers.json`;
/// `CONFINEMENT-LINUX.md` records them with the red run.
#[cfg(target_os = "linux")]
#[test]
fn linux_wallet_journey_runs_under_the_seccomp_allow_list() {
    let declared = read_declared_rights(WALLET_PROVIDER, &declared_rights_path(WALLET_PROVIDER))
        .unwrap_or_else(|err| panic!("{err}"));
    seccomp_confined_journey(
        WALLET_PROVIDER,
        Path::new(PROVIDER_BINARY),
        &declared,
        "linux_wallet_journey_runs_under_the_seccomp_allow_list",
    );
}

/// The did half of the Linux journey: the same body, the same installer and the
/// program as wallet, with did's own binary, did's own committed declared-rights
/// file and did's own operations. Wallet owns the four-call probe run.
///
/// The permitted calls are `did_standin_permitted_operations`, judged by
/// `assert_suite_outcomes` against the permitted prefix of `DID_SUITE_CASES`, so
/// `init`, `get_did` with a `did:key:` value, `resolve`, `set_nickname`,
/// `get_nickname` and `get_persona_did` answer under the filter. The did suite's
/// file-denial cases stay in the B3 and C0 journeys: a seccomp filter carries
/// syscall policy and not path policy, so they cannot pass under it alone.
///
/// Falsifier: a did launcher that skips only its `pre_exec` install is the same
/// plant as WP176 on this caller, caught by the `SECCOMP_MODE_FILTER` mode plus
/// the inherited-fixture before/after comparison; and a did provider that writes
/// the named outside sibling is WP177's plant on this caller, caught by the absent
/// sibling. Both reach a Linux-only test, so neither is registered in
/// `falsifiers.json`; `CONFINEMENT-LINUX.md` records them with the red run.
#[cfg(target_os = "linux")]
#[test]
fn linux_did_journey_runs_under_the_seccomp_allow_list() {
    let declared = read_declared_rights(DID_PROVIDER, &declared_rights_path(DID_PROVIDER))
        .unwrap_or_else(|err| panic!("{err}"));
    seccomp_confined_journey(
        DID_PROVIDER,
        did_provider_binary(),
        &declared,
        "linux_did_journey_runs_under_the_seccomp_allow_list",
    );
}

/// The names directly under `path`, sorted. A path that does not exist yet names
/// nothing, which is what an empty profile directory must report.
#[cfg(target_os = "linux")]
fn profile_dir_entries(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = match fs::read_dir(path) {
        Ok(entries) => entries
            .map(|entry| {
                entry
                    .expect("a profile directory entry must list")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort_unstable();
    names
}

/// Selects the removal check's profiles from the one file-profile list. The
/// model profile has its own removals in
/// `capsules/model-provider/confine-falsifiers.json` under that lane's bar.
fn allow_rule_profiles() -> impl Iterator<Item = &'static str> {
    FILE_PROFILES
        .into_iter()
        .filter(|name| *name != "model-provider")
}

/// The real profiles the removal check reads and the parsed entries of their
/// two lists. The entries are one list because wallet's list records the did
/// profile's `STORAGE_PARENT` removal (WP11).
#[derive(Debug)]
struct AllowRuleSources {
    profiles: Vec<(&'static str, String)>,
    entries: Vec<Value>,
}

/// One provider's falsifier list and its registered ids, in list order.
#[derive(Debug)]
struct FalsifierList {
    name: &'static str,
    ids: Vec<String>,
    entries: Vec<Value>,
}

/// Reads every `capsules/<name>/falsifiers.json` list selected by
/// `allow_rule_profiles` and returns each list's entries and ids.
///
/// A missing or unreadable list, a list that is not JSON, a document
/// without a `falsifiers` list and an entry whose `id` is missing or is not a
/// JSON string are refusals with distinct reasons that name the path; the
/// entry refusal also names the entry's position in the list. There is no
/// skip path. Both checks read the lists through this one function (P10).
fn read_falsifier_lists(capsules: &Path) -> Result<Vec<FalsifierList>, String> {
    let mut lists = Vec::new();
    for name in allow_rule_profiles() {
        let path = capsules.join(name).join("falsifiers.json");
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) => {
                return Err(format!(
                    "{name} falsifier list {} must be readable: {err}",
                    path.display()
                ))
            }
        };
        let doc: Value = match serde_json::from_str(&text) {
            Ok(doc) => doc,
            Err(err) => {
                return Err(format!(
                    "{name} falsifier list {} must be valid JSON: {err}",
                    path.display()
                ))
            }
        };
        let Some(list) = doc.get("falsifiers").and_then(Value::as_array) else {
            return Err(format!(
                "{name} falsifier list {} must hold a falsifiers list",
                path.display()
            ));
        };
        let entries: Vec<Value> = list.to_vec();
        let mut ids = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let Some(id) = entry["id"].as_str() else {
                return Err(format!(
                    "{name} falsifier list {} must give entry {index} a string id",
                    path.display()
                ));
            };
            ids.push(id.to_owned());
        }
        lists.push(FalsifierList { name, ids, entries });
    }
    Ok(lists)
}

/// Reads `capsules/<name>/confine.sb` and `capsules/<name>/falsifiers.json`
/// for the profiles selected by `allow_rule_profiles`.
///
/// A missing or unreadable profile, a profile that does not parse, a missing
/// or unreadable list, a list that is not JSON, a document without a
/// `falsifiers` list and an entry without a string id are refusals with
/// distinct reasons that name the path. There is no skip path.
fn read_allow_rule_sources(capsules: &Path) -> Result<AllowRuleSources, String> {
    let mut profiles = Vec::new();
    for name in allow_rule_profiles() {
        let path = capsules.join(name).join("confine.sb");
        profiles.push((name, read_allow_rule_profile(name, &path)?));
    }
    let entries = read_falsifier_lists(capsules)?
        .into_iter()
        .flat_map(|list| list.entries)
        .collect();
    Ok(AllowRuleSources { profiles, entries })
}

/// Reads one profile and proves that `profile_forms` accepts it, or refuses
/// with a reason that names the profile and its path. The removal check reads
/// each committed profile through it, and the generated-profile test and the
/// B3 journey read each provider's oracle through it too. There is no skip
/// path.
fn read_allow_rule_profile(name: &str, path: &Path) -> Result<String, String> {
    let profile = fs::read_to_string(path).map_err(|err| {
        format!(
            "{name} allow-rule profile {} must be readable: {err}",
            path.display()
        )
    })?;
    std::panic::catch_unwind(|| profile_forms(&profile))
        .map_err(|reason| {
            let detail = reason
                .downcast_ref::<String>()
                .map(String::as_str)
                .unwrap_or("the profile does not parse");
            format!(
                "{name} allow-rule profile {} must parse: {detail}",
                path.display()
            )
        })
        .map(|_forms| profile)
}

/// The one profile file the lab stand-in wrote into `profile_dir`, read as
/// text: the file the launch used, not a second copy of the generator's text.
/// A directory that does not hold exactly one entry is a refusal that names
/// the provider and the path, so the B3 journey reads no guessed file name and
/// there is no skip path.
fn read_launched_profile(name: &str, profile_dir: &Path) -> Result<String, String> {
    let mut entries = fs::read_dir(profile_dir)
        .map_err(|err| {
            format!(
                "{name} profile directory {} must be readable: {err}",
                profile_dir.display()
            )
        })?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            format!(
                "{name} profile directory {} must list: {err}",
                profile_dir.display()
            )
        })?;
    if entries.len() != 1 {
        return Err(format!(
            "{name} launcher must write exactly one profile into {}: found {}",
            profile_dir.display(),
            entries.len()
        ));
    }
    let profile = entries.remove(0);
    fs::read_to_string(&profile).map_err(|err| {
        format!(
            "{name} launched profile {} must be readable: {err}",
            profile.display()
        )
    })
}

/// The one heading line every confinement document uses for its falsifier
/// section.
const FALSIFIER_HEADING: &str = "## Falsifiers";

/// The heading line every operations table uses.
const OPERATIONS_HEADING: &str = "## Operations and the rights they need";

/// The providers whose `CONFINEMENT.md` operations table names the tests it
/// cites.
const OPERATIONS_TABLES: &[&str] = &["did-provider", "wallet-provider"];

/// Whether `character` can sit directly beside a falsifier id token.
fn falsifier_id_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

/// Every `DID` or `WP` id token in `text`, in the order it appears.
///
/// An id is a whole token: `DID` or `WP` followed by one or more digits, with
/// no letter, digit or `_` directly before or after it. So `DID10` does not
/// name `DID1`, and `WP45 to WP48` names only `WP45` and `WP48`.
fn falsifier_id_tokens(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    for (index, _) in text.char_indices() {
        if text[..index]
            .chars()
            .next_back()
            .is_some_and(falsifier_id_character)
        {
            continue;
        }
        let rest = &text[index..];
        let prefix = if rest.starts_with("DID") {
            "DID"
        } else if rest.starts_with("WP") {
            "WP"
        } else {
            continue;
        };
        let digits_start = index + prefix.len();
        let digits = text[digits_start..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if digits == 0 {
            continue;
        }
        let end = digits_start + digits;
        if text[end..]
            .chars()
            .next()
            .is_some_and(falsifier_id_character)
        {
            continue;
        }
        tokens.push(&text[index..end]);
    }
    tokens
}

/// Whether `section` names `id` as a whole token.
fn names_falsifier_id(section: &str, id: &str) -> bool {
    falsifier_id_tokens(section).contains(&id)
}

/// The section of `document` under its one `heading` line, or every problem
/// with that heading.
///
/// The document must hold exactly one line equal to `heading`. Its section runs
/// from that line to the next line that starts with `## `, or to the end of the
/// file. Each refusal names the document.
fn section_under_one_heading(
    document_name: &str,
    document: &str,
    heading: &str,
) -> Result<String, Vec<String>> {
    let lines: Vec<&str> = document.lines().collect();
    let heading_lines: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == heading)
        .map(|(index, _)| index)
        .collect();
    let Some(only) = heading_lines.first().copied() else {
        return Err(vec![format!(
            "{document_name} CONFINEMENT.md must hold one line {heading}; found none"
        )]);
    };
    if heading_lines.len() > 1 {
        return Err(vec![format!(
            "{document_name} CONFINEMENT.md must hold one line {heading}; found {}",
            heading_lines.len()
        )]);
    }
    let section_start = only + 1;
    let section_end = lines[section_start..]
        .iter()
        .position(|line| line.starts_with("## "))
        .map_or(lines.len(), |offset| section_start + offset);
    Ok(lines[section_start..section_end].join("\n"))
}

/// Every problem with one document's falsifier section, each naming the
/// document.
///
/// The document must hold exactly one line `## Falsifiers`. Its section runs
/// from that line to the next line that starts with `## `, or to the end of
/// the file. Every id of `own_ids` must be named in the section as a whole
/// token, and every id-shaped token there must appear in `registered_ids`,
/// which holds both lists' ids. An id may be named more than once.
fn falsifier_section_problems(
    document_name: &str,
    document: &str,
    own_ids: &[String],
    registered_ids: &[String],
) -> Vec<String> {
    let section = match section_under_one_heading(document_name, document, FALSIFIER_HEADING) {
        Ok(section) => section,
        Err(problems) => return problems,
    };
    let mut problems = Vec::new();
    for id in own_ids {
        if !names_falsifier_id(&section, id) {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: own falsifier id {id} is not named in \
                 {FALSIFIER_HEADING}"
            ));
        }
    }
    let mut seen: Vec<&str> = Vec::new();
    for token in falsifier_id_tokens(&section) {
        if registered_ids.iter().any(|id| id == token) || seen.contains(&token) {
            continue;
        }
        seen.push(token);
        problems.push(format!(
            "{document_name} CONFINEMENT.md: {FALSIFIER_HEADING} names {token}, which neither \
             falsifier list registers"
        ));
    }
    problems
}

/// Reads `capsules/<name>/CONFINEMENT.md`, or refuses with a reason that names
/// its path. There is no skip path.
fn read_confinement_document(capsules: &Path, name: &str) -> Result<String, String> {
    let path = capsules.join(name).join("CONFINEMENT.md");
    fs::read_to_string(&path).map_err(|err| {
        format!(
            "{name} confinement document {} must be readable: {err}",
            path.display()
        )
    })
}

/// Every backtick-delimited span in `text`, in order.
fn backtick_spans(text: &str) -> Vec<&str> {
    let mut spans = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else {
            break;
        };
        spans.push(&after[..close]);
        rest = &after[close + 1..];
    }
    spans
}

/// Every problem with one operations table's test citations, each naming the
/// document and the citation.
///
/// The section under `OPERATIONS_HEADING` must cite at least one backtick span
/// that holds a file relative to `capsule_dir`, two colons and a function
/// name. A cited path must be relative and resolve beneath `capsule_dir`,
/// including through symbolic links, before its file is read. The file must
/// hold `fn <fn>(`. The check does not decide whether it is a `#[test]`.
fn operations_table_citation_problems(
    document_name: &str,
    document: &str,
    capsule_dir: &Path,
) -> Vec<String> {
    let section = match section_under_one_heading(document_name, document, OPERATIONS_HEADING) {
        Ok(section) => section,
        Err(problems) => return problems,
    };
    let provider_root = match fs::canonicalize(capsule_dir) {
        Ok(root) => root,
        Err(err) => {
            return vec![format!(
                "{document_name} CONFINEMENT.md: provider directory {} cannot be resolved: {err}",
                capsule_dir.display()
            )];
        }
    };
    let mut problems = Vec::new();
    let mut citations: Vec<&str> = Vec::new();
    for span in backtick_spans(&section) {
        let Some((file, function)) = span.split_once("::") else {
            continue;
        };
        if citations.contains(&span) {
            continue;
        }
        citations.push(span);
        if Path::new(file).is_absolute() {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: {span} names an absolute path; \
                 cited files must be relative to the provider directory"
            ));
            continue;
        }
        let path = capsule_dir.join(file);
        let resolved = match fs::canonicalize(&path) {
            Ok(resolved) => resolved,
            Err(err) => {
                problems.push(format!(
                    "{document_name} CONFINEMENT.md: {span} names a file that is not \
                     readable because its path cannot be resolved: {} ({err})",
                    path.display()
                ));
                continue;
            }
        };
        if !resolved.starts_with(&provider_root) {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: {span} resolves outside the provider directory: \
                 {} (provider directory {})",
                resolved.display(),
                provider_root.display()
            ));
            continue;
        }
        let source = match fs::read_to_string(&resolved) {
            Ok(source) => source,
            Err(err) => {
                problems.push(format!(
                    "{document_name} CONFINEMENT.md: {span} names a file that is not \
                     readable: {} ({err})",
                    path.display()
                ));
                continue;
            }
        };
        if !source.contains(&format!("fn {function}(")) {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: {span} names a function that {} does not hold",
                path.display()
            ));
        }
    }
    if citations.is_empty() {
        problems.push(format!(
            "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} cites no file::fn test"
        ));
    }
    problems
}

/// The one Right cell value a row uses when its operation needs no declared
/// right.
const NO_DECLARED_RIGHT: &str = "none: needs no declared right";

/// The one Linux cell value every operations row uses in this lab.
const LINUX_STATUS: &str = "designed, not enforced";

/// The two sides a row whose Right is a declared right cites in its macOS cell.
const PERMITTED_SIDE: &str = "permitted:";
const OUTSIDE_SIDE: &str = "nearest outside refused:";

/// The one dispatch arm whose name expands to one row per contract kind.
const WALLET_CONTRACT_ARM: &str = "wallet_contract";

/// The one `handle` arm type both providers match on.
const REQUEST_ARM: &str = "Request::";

/// The one contract operation type wallet's dispatch expands.
const WALLET_OPERATION_ARM: &str = "WalletProviderOperationV2::";

/// One operations table row, reduced to the cells the row check reads.
struct OperationsRow {
    operation: String,
    inputs: String,
    right: String,
    macos: String,
    linux: String,
}

/// The one first cell of an operations table's header line.
const OPERATION_HEADER: &str = "Operation";

/// Every header cell, in the order used to read body cells.
const TABLE_HEADER: [&str; 7] = [
    OPERATION_HEADER,
    "Inputs",
    "Outputs",
    "Right",
    "Effect",
    "macOS rule and test",
    "Linux",
];

/// The one cell count every line of an operations table holds.
const TABLE_CELLS: usize = TABLE_HEADER.len();

/// Whether `line` can start a Markdown table. Outer bars are optional.
fn is_table_line(line: &str) -> bool {
    line.contains('|')
}

/// The trimmed cells of one Markdown table line, without its outer bars.
fn table_cells(line: &str) -> Vec<&str> {
    let mut cells: Vec<&str> = line.trim().split('|').collect();
    if cells.first() == Some(&"") {
        cells.remove(0);
    }
    if cells.last() == Some(&"") {
        cells.pop();
    }
    cells.into_iter().map(str::trim).collect()
}

/// Whether `cells` are the table's separator line: `TABLE_CELLS` dashes-only
/// cells, with at least one cell that is not empty.
fn is_separator_cells(cells: &[&str]) -> bool {
    cells.len() == TABLE_CELLS
        && cells
            .iter()
            .all(|cell| cell.chars().all(|character| character == '-'))
        && cells.iter().any(|cell| !cell.is_empty())
}

/// Every data row of one operations table section, in table order, and every
/// row that cannot be read.
///
/// The first line containing `|` is the complete `TABLE_HEADER`, and the next
/// nonempty line is the separator. Every later nonempty line is read as a row,
/// including a repeated header, an indented row and a row with either or both
/// outer bars omitted. Short rows are refused even when they hold no bar.
/// Every line holds the table's `TABLE_CELLS` cells. A section with no table
/// line, a first line that is not the header, a second line that would be a row
/// and a header with no second line are refusals that name the document and the
/// line; so is a row with any other cell count.
fn operations_table_rows(
    document_name: &str,
    section: &str,
) -> Result<(Vec<OperationsRow>, Vec<String>), Vec<String>> {
    let mut lines = section
        .lines()
        .skip_while(|line| !is_table_line(line))
        .filter(|line| !line.trim().is_empty());
    let Some(header) = lines.next() else {
        return Err(vec![format!(
            "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} holds no table line"
        )]);
    };
    let header_cells = table_cells(header);
    if header_cells != TABLE_HEADER {
        return Err(vec![format!(
            "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} table line 1 is not the header \
             {OPERATION_HEADER} over {TABLE_CELLS} cells: {}",
            header.trim()
        )]);
    }
    let Some(separator) = lines.next() else {
        return Err(vec![format!(
            "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} table line 1 is the header and \
             the table holds no separator line"
        )]);
    };
    if !is_separator_cells(&table_cells(separator)) {
        return Err(vec![format!(
            "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} table line 2 is not the \
             separator of {TABLE_CELLS} dash cells: {}",
            separator.trim()
        )]);
    }
    let mut rows = Vec::new();
    let mut problems = Vec::new();
    for line in lines {
        let cells = table_cells(line);
        if cells.len() != TABLE_CELLS {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row {} holds {} cells, \
                 and every row holds {TABLE_CELLS}",
                cells.first().copied().unwrap_or_default(),
                cells.len()
            ));
            continue;
        }
        rows.push(OperationsRow {
            operation: cells[0].to_string(),
            inputs: cells[1].to_string(),
            right: cells[3].to_string(),
            macos: cells[5].to_string(),
            linux: cells[6].to_string(),
        });
    }
    Ok((rows, problems))
}

/// `variant` in snake_case, by the rule the wire protocol uses
/// (`#[serde(rename_all = "snake_case")]`): an underscore before an upper-case
/// letter after the first character, then ASCII lower case.
fn variant_snake_case(variant: &str) -> String {
    let mut name = String::with_capacity(variant.len());
    for (index, character) in variant.char_indices() {
        if index > 0 && character.is_uppercase() {
            name.push('_');
        }
        name.push(character.to_ascii_lowercase());
    }
    name
}

/// Every `arm_type` variant the body of `signature` in `source` names, in body
/// order, or `None` when `source` holds no such signature line.
///
/// The body starts after the signature line and ends at the next line that
/// starts with `    fn `, or at the end of the file.
fn dispatch_arm_variants(source: &str, signature: &str, arm_type: &str) -> Option<Vec<String>> {
    let mut body = false;
    let mut variants = Vec::new();
    for line in source.lines() {
        if !body {
            if line.trim_start().starts_with(signature) {
                body = true;
            }
            continue;
        }
        if line.starts_with("    fn ") {
            break;
        }
        let mut rest = line;
        while let Some(at) = rest.find(arm_type) {
            let tail = &rest[at + arm_type.len()..];
            let variant: String = tail
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .collect();
            if !variant.is_empty() {
                variants.push(variant);
            }
            rest = tail;
        }
    }
    body.then_some(variants)
}

/// The body of the `enum <name>` or `struct <name>` declaration in `source`,
/// or `None` when `source` holds no such declaration.
///
/// The declaration is a line whose qualifier words precede `enum <name> {` or
/// `struct <name> {`, and whose text after the brace is empty, so a use of the
/// name elsewhere does not count. The body runs from that `{` to the `}` that
/// closes it, and a brace inside a string literal does not count. Comments are
/// removed before selecting the declaration or finding its closing brace. A
/// declaration spelled inside a string literal, including one that spans lines,
/// is text in that string and never the declaration.
fn item_body(source: &str, name: &str, kind: &str) -> Option<String> {
    let source = without_comments(source);
    let declaration = format!("{kind} {name} {{");
    let mut from = 0;
    while let Some(offset) = source[from..].find(&declaration) {
        let start = from + offset;
        from = start + declaration.len();
        if inside_string(&source, start) {
            continue;
        }
        let line_start = source[..start].rfind('\n').map_or(0, |index| index + 1);
        if !declaration_qualifier(source[line_start..start].trim()) {
            continue;
        }
        let line_end = source[from..]
            .find('\n')
            .map_or(source.len(), |index| from + index);
        if !source[from..line_end].trim().is_empty() {
            continue;
        }
        let body = &source[from..];
        return declaration_end(body).map(|end| body[..end].to_string());
    }
    None
}

/// Whether the text before a declaration's name on its line can precede an
/// item: nothing, or the qualifier words `pub`, a `pub(...)` visibility, and
/// the item kinds `struct` and `enum`.
fn declaration_qualifier(text: &str) -> bool {
    text.split_whitespace()
        .all(|word| word == "pub" || word.starts_with("pub(") || matches!(word, "struct" | "enum"))
}

/// One declaration's wire field names, or the reason the declaration cannot be
/// read.
#[derive(Debug, PartialEq)]
enum WireFieldNames {
    /// The source holds no such declaration.
    NoDeclaration,
    /// The declaration's field list cannot be read, with its reason.
    Unsupported(&'static str),
    /// The declaration's wire field names, in declaration order.
    Names(Vec<String>),
}

/// The wire field names of one enum arm or struct `item` in `source`, in
/// declaration order, or why they cannot be read.
///
/// A declaration starts at a line whose items before `item` are qualifier words
/// and whose text after it is `{` or `,`; a longer name that merely starts with
/// `item`, and a name that sits inside another item or a string, are other
/// items. A declaration with no fields, such as `Status,`, returns an empty
/// list, so a missing item and an item with no fields stay apart. Inside the
/// braces every field is one comma-separated item, and the active
/// `#[serde(rename = "...")]` on that item names the wire field; every other
/// field keeps its Rust name without a raw-identifier `r#` prefix. A trailing
/// comma is optional. The source's
/// comments are read as nothing, so no comment names an item or a field, and a
/// declaration spelled inside a string literal, including one that spans lines,
/// is text in that string and never the declaration. A field list whose
/// delimiters do not balance is `Unsupported` with its reason, never a shorter
/// list, so an unreadable declaration cannot pass by naming fewer fields.
fn wire_field_names(source: &str, item: &str) -> WireFieldNames {
    let source = without_comments(source);
    let source = source.as_str();
    let mut from = 0;
    while let Some(offset) = source[from..].find(item) {
        let start = from + offset;
        from = start + item.len();
        if inside_string(source, start) {
            continue;
        }
        let line_start = source[..start].rfind('\n').map_or(0, |index| index + 1);
        if !declaration_qualifier(source[line_start..start].trim()) {
            continue;
        }
        let rest = &source[from..];
        let head = rest.trim_start();
        let after_item = from + (rest.len() - head.len());
        match head.chars().next() {
            Some('{') => {
                let body = &source[after_item + 1..];
                let Some(end) = declaration_end(body) else {
                    return WireFieldNames::NoDeclaration;
                };
                return match field_names(&body[..end]) {
                    Ok(fields) => WireFieldNames::Names(fields),
                    Err(reason) => WireFieldNames::Unsupported(reason),
                };
            }
            Some(',') => return WireFieldNames::Names(Vec::new()),
            _ => continue,
        }
    }
    WireFieldNames::NoDeclaration
}

/// The wire names of the field items of one declaration body, or
/// `UNBALANCED_FIELD_LIST` when the body's delimiters do not balance.
fn field_names(body: &str) -> Result<Vec<String>, &'static str> {
    Ok(declaration_items(body)?
        .into_iter()
        .filter(|field| !field.trim().is_empty())
        .map(field_wire_name)
        .collect())
}

/// Whether `index`, a byte offset into `text`, falls inside a `"..."` string
/// literal, so text a string holds never selects a declaration.
///
/// The scan starts at the beginning of `text` and counts quote characters the
/// way `without_comments` does: a `"` opens a string, the matching unescaped
/// `"` closes it, and a backslash escapes the character after it, so an escaped
/// quote keeps the string open. Text at `index` itself is not read, so the
/// opening quote of a string is outside it. This is the one boundary test for
/// both item and field selection (P10).
fn inside_string(text: &str, index: usize) -> bool {
    let mut in_string = false;
    let mut quote_escape = false;
    for (at, character) in text.char_indices() {
        if at >= index {
            break;
        }
        if in_string {
            if character == '"' && !quote_escape {
                in_string = false;
            }
            quote_escape = character == '\\' && !quote_escape;
            continue;
        }
        if character == '"' {
            in_string = true;
            quote_escape = false;
        }
    }
    in_string
}

/// `text` with every `//` line comment and every `/* ... */` block comment
/// removed, and Rust strings decoded and quoted in ordinary escaped form.
/// Normalizing raw strings here lets every declaration scanner use the same
/// quoted-string boundary, including raw strings holding quotes or backslashes.
/// Character and byte-character literals are quoted as text at this same
/// boundary, so their punctuation cannot close a declaration or split a field.
/// Lifetime apostrophes stay in the source.
/// A `//` or `/*` inside a string literal stays part of that string, a
/// line comment ends at its newline and keeps it, so the items around it keep
/// their own lines, and a block comment keeps its newlines and one space so the
/// tokens around it stay apart. Block comments can nest.
fn without_comments(text: &str) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut characters = text.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        let rest = &text[index..];
        if let Some(length) = rust_character_literal_length(rest) {
            kept.push_str(&format!("{:?}", &rest[..length]));
            while characters
                .peek()
                .is_some_and(|(at, _)| *at < index + length)
            {
                characters.next();
            }
            continue;
        }
        if character == '"'
            || (character == 'r' && rest[1..].trim_start_matches('#').starts_with('"'))
        {
            let (value, length) = rust_string_literal(rest)
                .unwrap_or_else(|reason| panic!("wire field reader: {reason}"));
            kept.push_str(&format!("{value:?}"));
            while characters
                .peek()
                .is_some_and(|(at, _)| *at < index + length)
            {
                characters.next();
            }
            continue;
        }
        if character == '/' && characters.peek().is_some_and(|(_, next)| *next == '/') {
            for (_, next) in characters.by_ref() {
                if next == '\n' {
                    kept.push('\n');
                    break;
                }
            }
            continue;
        }
        if character == '/' && characters.peek().is_some_and(|(_, next)| *next == '*') {
            characters.next();
            let mut depth = 1usize;
            kept.push(' ');
            while let Some((_, next)) = characters.next() {
                if next == '/' && characters.peek().is_some_and(|(_, next)| *next == '*') {
                    characters.next();
                    depth += 1;
                } else if next == '*' && characters.peek().is_some_and(|(_, next)| *next == '/') {
                    characters.next();
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                } else if next == '\n' {
                    kept.push('\n');
                }
            }
            continue;
        }
        kept.push(character);
    }
    kept
}

/// The byte length of a character literal, or `None` for another token,
/// including a lifetime. Only literals starting with a backslash need a scan
/// for an unescaped closing apostrophe; a plain character has exactly one
/// scalar before its closing apostrophe. Byte characters use this same reader
/// after their `b` prefix. Escaped punctuation stays inside the literal.
fn rust_character_literal_length(text: &str) -> Option<usize> {
    let body = text.strip_prefix('\'')?;
    let first = body.chars().next()?;
    if first != '\\' {
        return body[first.len_utf8()..]
            .starts_with('\'')
            .then_some(first.len_utf8() + 2);
    }
    let mut escaped = false;
    for (index, character) in body.char_indices() {
        if character == '\'' && !escaped {
            return Some(index + 2);
        }
        escaped = character == '\\' && !escaped;
    }
    panic!("wire field reader: unterminated Rust character escape");
}

/// Decode one Rust string literal and return its byte length. Ordinary strings
/// support Rust's simple, ASCII and Unicode escapes and line continuations;
/// raw strings end at their matching quote and hash delimiter. A malformed or
/// unsupported literal has an explicit reason instead of supplying a wire name.
fn rust_string_literal(text: &str) -> Result<(String, usize), &'static str> {
    if let Some(raw) = text.strip_prefix('r') {
        let hashes = raw.len() - raw.trim_start_matches('#').len();
        let body = raw[hashes..]
            .strip_prefix('"')
            .ok_or("expected a Rust string literal")?;
        let closing = format!("\"{}", "#".repeat(hashes));
        let end = body.find(&closing).ok_or("unterminated raw Rust string")?;
        return Ok((
            body[..end].replace("\r\n", "\n"),
            2 + hashes + end + closing.len(),
        ));
    }
    let body = text
        .strip_prefix('"')
        .ok_or("expected a Rust string literal")?;
    let mut characters = body.char_indices().peekable();
    let mut value = String::new();
    while let Some((index, character)) = characters.next() {
        match character {
            '"' => return Ok((value, index + 2)),
            '\r' if characters.peek().is_some_and(|(_, next)| *next == '\n') => {
                characters.next();
                value.push('\n');
            }
            '\\' => {
                let (_, escape) = characters.next().ok_or("unterminated Rust string escape")?;
                match escape {
                    '\\' | '"' | '\'' => value.push(escape),
                    'n' => value.push('\n'),
                    'r' => value.push('\r'),
                    't' => value.push('\t'),
                    '0' => value.push('\0'),
                    'x' => {
                        let mut byte = 0;
                        for _ in 0..2 {
                            let digit = characters
                                .next()
                                .and_then(|(_, digit)| digit.to_digit(16))
                                .ok_or("invalid Rust ASCII escape")?;
                            byte = byte * 16 + digit;
                        }
                        if byte > 0x7f {
                            return Err("Rust ASCII escape exceeds 0x7f");
                        }
                        value.push(char::from_u32(byte).unwrap());
                    }
                    'u' => {
                        if characters.next().map(|(_, next)| next) != Some('{') {
                            return Err("invalid Rust Unicode escape");
                        }
                        let mut scalar = 0;
                        let mut digits = 0;
                        loop {
                            let (_, digit) = characters
                                .next()
                                .ok_or("unterminated Rust Unicode escape")?;
                            match digit {
                                '}' if digits > 0 => break,
                                '_' if digits > 0 => continue,
                                _ => {
                                    let digit = digit
                                        .to_digit(16)
                                        .filter(|_| digits < 6)
                                        .ok_or("invalid Rust Unicode escape")?;
                                    scalar = scalar * 16 + digit;
                                    digits += 1;
                                }
                            }
                        }
                        value.push(char::from_u32(scalar).ok_or("invalid Rust Unicode scalar")?);
                    }
                    '\n' | '\r' => {
                        if escape == '\r' && characters.next().map(|(_, next)| next) != Some('\n') {
                            return Err("invalid Rust line continuation");
                        }
                        while characters
                            .peek()
                            .is_some_and(|(_, next)| matches!(next, ' ' | '\t' | '\n' | '\r'))
                        {
                            characters.next();
                        }
                    }
                    _ => return Err("unsupported Rust string escape"),
                }
            }
            _ => value.push(character),
        }
    }
    Err("unterminated Rust string literal")
}

/// The index of the `}` that closes a body whose opening brace sits directly
/// before `text`, or `None` when `text` ends first. A brace inside a string
/// literal does not count. `without_comments` normalizes character and raw
/// string literals to this quoted form before the scan.
fn declaration_end(text: &str) -> Option<usize> {
    let mut depth = 1usize;
    let mut in_string = false;
    let mut quote_escape = false;
    for (index, character) in text.char_indices() {
        if in_string {
            if character == '"' && !quote_escape {
                in_string = false;
            }
            quote_escape = character == '\\' && !quote_escape;
            continue;
        }
        match character {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// The one reason a field list whose delimiters do not balance is refused.
const UNBALANCED_FIELD_LIST: &str =
    "unbalanced parentheses, brackets, braces or angle brackets in the field list";

/// The comma-separated items of one declaration body, split at the commas
/// outside parentheses, brackets, braces and angle brackets, so a field type
/// such as `Option<String>` and an attribute such as
/// `#[serde(default, skip_serializing_if = "x")]` each stay one item. Delimiters
/// inside a string literal, including after an escaped quote, do not count.
///
/// A body whose delimiters do not balance is refused with
/// `UNBALANCED_FIELD_LIST`, never read. An operator such as the `<<` of
/// `[u8; 1 << 2]` is not a delimiter, so it opens one that never closes and
/// every later field would join the item before it, which would drop a required
/// field from the list.
fn declaration_items(text: &str) -> Result<Vec<&str>, &'static str> {
    let mut items = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let mut in_string = false;
    let mut quote_escape = false;
    for (index, character) in text.char_indices() {
        if in_string {
            if character == '"' && !quote_escape {
                in_string = false;
            }
            quote_escape = character == '\\' && !quote_escape;
            continue;
        }
        match character {
            '"' => in_string = true,
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                items.push(&text[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(UNBALANCED_FIELD_LIST);
    }
    items.push(&text[start..]);
    Ok(items)
}

/// The wire name of one field item: the `rename = "..."` of the active
/// `#[serde(...)]` attribute the field carries, else the name it declares
/// before its `:`, without its leading attributes and without a `pub`
/// qualifier or raw-identifier prefix.
///
/// Only a `serde` attribute that stands before the field's name is read, and
/// only its `rename` entry supplies the decoded Rust string. Spacing around
/// `=` is immaterial; text inside another entry's value stays in that value.
/// Split serialize/deserialize renames and expressions are refused explicitly.
fn field_wire_name(field: &str) -> String {
    let mut declared = field.trim_start();
    let mut renamed = None;
    while let Some(attribute) = declared.strip_prefix('#') {
        let attributes = attribute
            .trim_start()
            .strip_prefix('[')
            .expect("wire field reader: expected a bracketed field attribute");
        let end =
            attribute_end(attributes).expect("wire field reader: unterminated field attribute");
        if is_serde_attribute(&attributes[..end]) {
            let (_, arguments) = attributes[..end].split_once('(').unwrap();
            let arguments = arguments
                .trim_end()
                .strip_suffix(')')
                .expect("wire field reader: unterminated serde attribute");
            for entry in declaration_items(arguments)
                .unwrap_or_else(|reason| panic!("wire field reader: serde attribute: {reason}"))
            {
                let entry = entry.trim();
                let entry = entry.strip_prefix("r#").unwrap_or(entry);
                let key_end = entry
                    .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                    .unwrap_or(entry.len());
                if &entry[..key_end] != "rename" {
                    continue;
                }
                let literal = entry[key_end..].trim_start().strip_prefix('=')
                    .expect("wire field reader: unsupported serde rename syntax; expected rename = <Rust string literal>")
                    .trim_start();
                let (name, length) = rust_string_literal(literal)
                    .unwrap_or_else(|reason| panic!("wire field reader: serde rename: {reason}"));
                assert!(
                    literal[length..].trim().is_empty(),
                    "wire field reader: unsupported tokens after serde rename string"
                );
                assert!(
                    renamed.replace(name).is_none(),
                    "wire field reader: duplicate serde rename"
                );
            }
        }
        declared = attributes[end + 1..].trim_start();
    }
    if let Some(name) = renamed {
        return name;
    }
    let name = declared
        .split(':')
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .last()
        .unwrap_or_default();
    name.strip_prefix("r#").unwrap_or(name).to_string()
}

/// Whether the text of one attribute, after its `#[`, is `serde(...)`. A longer
/// path such as `serde_with(...)` is another attribute.
fn is_serde_attribute(attribute: &str) -> bool {
    let attribute = attribute.trim_start();
    let attribute = attribute.strip_prefix("r#").unwrap_or(attribute);
    attribute
        .trim_start()
        .strip_prefix("serde")
        .is_some_and(|rest| rest.trim_start().starts_with('('))
}

/// The index of the `]` that closes the attribute whose text follows `#[`, or
/// `None` when the attribute ends first.
fn attribute_end(text: &str) -> Option<usize> {
    let mut depth = 1usize;
    let mut in_string = false;
    let mut quote_escape = false;
    for (index, character) in text.char_indices() {
        if in_string {
            if character == '"' && !quote_escape {
                in_string = false;
            }
            quote_escape = character == '\\' && !quote_escape;
            continue;
        }
        match character {
            '"' => in_string = true,
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// Every problem with one table's row set, each naming the document and the row
/// or the arm that has no partner.
///
/// The row set must equal the operations `provider_source` answers. Every
/// `Request::<Variant>` arm of `fn handle` is one name, and the names of the
/// ordinary arms appear in the table in dispatch order. Where `fn handle`
/// answers `wallet_contract`, every `WalletProviderOperationV2::<Variant>` arm
/// of `fn dispatch_wallet_operation` is one `wallet_contract <kind>` row, and
/// those rows follow the ordinary rows in their own dispatch order. Each arm
/// matches exactly one row. A name reaches snake_case by
/// `variant_snake_case`. The contract enum is the only list of kinds, so a new
/// kind fails here until its row exists.
fn row_set_problems(
    document_name: &str,
    rows: &[OperationsRow],
    provider_source: &str,
    provider_path: &Path,
) -> Vec<String> {
    let Some(arms) = dispatch_arm_variants(provider_source, "fn handle(", REQUEST_ARM) else {
        return vec![format!(
            "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row set cannot be checked \
             because {} holds no fn handle",
            provider_path.display()
        )];
    };
    let arm_names: Vec<String> = arms.iter().map(|arm| variant_snake_case(arm)).collect();
    let answers_contract = arm_names.iter().any(|name| name == WALLET_CONTRACT_ARM);
    let mut expected: Vec<String> = arm_names
        .into_iter()
        .filter(|name| name != WALLET_CONTRACT_ARM)
        .collect();
    if answers_contract {
        let Some(kinds) = dispatch_arm_variants(
            provider_source,
            "fn dispatch_wallet_operation(",
            WALLET_OPERATION_ARM,
        ) else {
            return vec![format!(
                "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row set cannot be checked \
                 because {} answers {WALLET_CONTRACT_ARM} and holds no \
                 fn dispatch_wallet_operation",
                provider_path.display()
            )];
        };
        for kind in &kinds {
            expected.push(format!(
                "{WALLET_CONTRACT_ARM} {}",
                variant_snake_case(kind)
            ));
        }
    }
    let observed: Vec<&str> = rows.iter().map(|row| row.operation.as_str()).collect();
    let mut unmatched_rows = observed.clone();
    let mut problems = Vec::new();
    for name in &expected {
        if let Some(index) = unmatched_rows.iter().position(|row| *row == name) {
            unmatched_rows.remove(index);
        } else {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row set: the arm {name} of \
                 {} has no row",
                provider_path.display()
            ));
        }
    }
    for name in unmatched_rows {
        if expected.iter().any(|expected| expected == name) {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row {name} has \
                 more copies than matching arms in {}",
                provider_path.display()
            ));
        } else {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row {name} has \
                 no arm in {}",
                provider_path.display()
            ));
        }
    }
    // Pair each occurrence before comparing order, so missing and surplus rows
    // each get their own reason, without also reporting their shifted positions.
    if problems.is_empty() {
        problems.extend(row_set_order_problems(
            document_name,
            &expected,
            &observed,
            provider_path,
        ));
    }
    problems
}

/// Compare the full row sequence after `row_set_problems` pairs every
/// occurrence: ordinary arms in dispatch order, then kinds in dispatch order.
fn row_set_order_problems(
    document_name: &str,
    expected: &[String],
    observed: &[&str],
    provider_path: &Path,
) -> Vec<String> {
    if expected
        .iter()
        .map(String::as_str)
        .eq(observed.iter().copied())
    {
        return Vec::new();
    }
    let is_kind = |name: &str| name.starts_with(&format!("{WALLET_CONTRACT_ARM} "));
    let mut problems = Vec::new();
    if let Some(first_kind) = observed.iter().position(|name| is_kind(name)) {
        if let Some(last_arm) = observed
            .iter()
            .rposition(|name| expected.iter().any(|expected| expected == name) && !is_kind(name))
        {
            if last_arm > first_kind {
                problems.push(format!(
                    "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row {} \
                     comes after the {WALLET_CONTRACT_ARM} rows, and the contract rows follow the \
                     ordinary arms of {}",
                    observed[last_arm],
                    provider_path.display()
                ));
                return problems;
            }
        }
    }
    if let Some((index, _)) = observed
        .iter()
        .enumerate()
        .find(|(index, found)| expected[*index] != **found)
    {
        problems.push(format!(
            "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row {} comes \
             where {} answers {}, and the table keeps the dispatch order",
            observed[index],
            provider_path.display(),
            expected[index]
        ));
    }
    problems
}

/// One item of an Inputs cell: its name, whether the cell wrote that name as a
/// backticked span (`true`) or as a bare word (`false`), and the child list a
/// balanced parenthesised group on that item holds.
///
/// `quoted` is part of the item. The bare word `none` and a backticked field
/// whose wire name is `none` are different items. Children are not: the one
/// compare is `inputs_match`.
#[derive(Debug)]
struct InputsItem {
    name: String,
    quoted: bool,
    children: Vec<InputsItem>,
}

impl PartialEq for InputsItem {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.quoted == other.quoted
    }
}

/// One leaf item, with the quoting the cell writes and no children.
fn input_leaf(name: &str, quoted: bool) -> InputsItem {
    InputsItem {
        name: name.to_string(),
        quoted,
        children: Vec::new(),
    }
}

/// The items of one Inputs cell, or `None` when the cell is not a list of
/// names the reader can take apart.
///
/// An item is one backticked span or one bare word, and each item records
/// which of the two the cell wrote. A balanced `(...)` group after the name is
/// that item's child list, read by this same function. An unbalanced or stray
/// parenthesis, an empty item and an unterminated backtick span each return
/// `None`, and the rule turns every `None` into a named refusal, never a pass.
fn input_items(cell: &str) -> Option<Vec<InputsItem>> {
    if cell.contains(['(', ')']) {
        return grouped_input_items(cell);
    }
    let mut items = Vec::new();
    for item in cell.split(',') {
        let item = item.trim();
        let quoted = item.starts_with('`');
        let name = if quoted {
            item.strip_prefix('`')?.strip_suffix('`')?
        } else {
            item
        };
        if name.is_empty() || name.contains('`') {
            return None;
        }
        items.push(InputsItem {
            name: name.to_string(),
            quoted,
            children: Vec::new(),
        });
    }
    Some(items)
}

/// The items of a cell that holds parentheses. A group is children of the item
/// it follows. A parenthesis inside a name, a group that does not close on the
/// item, and a cell whose groups do not balance each return `None`.
fn grouped_input_items(cell: &str) -> Option<Vec<InputsItem>> {
    let mut items = Vec::new();
    for part in split_input_list(cell)? {
        items.push(parse_input_item(part)?);
    }
    Some(items)
}

/// The comma-separated pieces of one Inputs list, split only at commas outside
/// backticks and outside parentheses, or `None` when a parenthesis has no pair.
fn split_input_list(cell: &str) -> Option<Vec<&str>> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut in_ticks = false;
    for (index, character) in cell.char_indices() {
        match character {
            '`' => in_ticks = !in_ticks,
            '(' if !in_ticks => depth += 1,
            ')' if !in_ticks => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
            }
            ',' if depth == 0 && !in_ticks => {
                items.push(&cell[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if depth != 0 || in_ticks {
        return None;
    }
    items.push(&cell[start..]);
    Some(items)
}

/// One Inputs item. The name ends at the group that follows it, and a
/// parenthesis inside the name is a stray parenthesis.
fn parse_input_item(raw: &str) -> Option<InputsItem> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (name, quoted, rest) = if let Some(after) = raw.strip_prefix('`') {
        let end = after.find('`')?;
        let name = &after[..end];
        if name.is_empty() || name.contains(['`', '(', ')']) {
            return None;
        }
        (name, true, after[end + 1..].trim())
    } else if raw.contains('`') {
        return None;
    } else {
        let (name, rest) = match raw.find('(') {
            Some(index) => (raw[..index].trim(), raw[index..].trim()),
            None => (raw, ""),
        };
        if name.is_empty() || name.contains(['(', ')']) {
            return None;
        }
        (name, false, rest)
    };
    let children = if rest.is_empty() {
        Vec::new()
    } else {
        input_items(input_group(rest)?)?
    };
    Some(InputsItem {
        name: name.to_string(),
        quoted,
        children,
    })
}

/// The text inside one `(...)` group that ends `text`, or `None` when the
/// parentheses do not form that one group.
fn input_group(text: &str) -> Option<&str> {
    let text = text.trim();
    let inner = text.strip_prefix('(')?;
    let mut depth = 1usize;
    let mut in_ticks = false;
    for (index, character) in inner.char_indices() {
        match character {
            '`' => in_ticks = !in_ticks,
            '(' if !in_ticks => depth += 1,
            ')' if !in_ticks => {
                depth -= 1;
                if depth == 0 {
                    if inner[index + 1..].trim().is_empty() {
                        return Some(inner[..index].trim());
                    }
                    return None;
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether one observed Inputs cell is exactly the expected item list: the same
/// names in the same order, each written the way the expected item is written,
/// and the same children under each item. A cell that stops before a declared
/// field, names another order, adds a name, writes a bare word where the table
/// writes a backticked name, or names a different child list is a different cell.
///
/// Equality of two items sees the name and the quoting. This function is the
/// one compare that also sees the children, including the names inside `params`.
fn inputs_match(observed: &[InputsItem], expected: &[InputsItem]) -> bool {
    observed.len() == expected.len()
        && observed
            .iter()
            .zip(expected)
            .all(|(observed, expected)| observed == expected)
        && observed
            .iter()
            .zip(expected)
            .all(|(observed, expected)| inputs_match(&observed.children, &expected.children))
}

/// One item list as an Inputs cell writes it, for a refusal's expected side.
/// A backticked name keeps its backticks, a bare word keeps none, and a child
/// list is the parenthesised group the cell writes after the name.
fn render_inputs(items: &[InputsItem]) -> String {
    items
        .iter()
        .map(render_input_item)
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_input_item(item: &InputsItem) -> String {
    let mut text = if item.quoted {
        format!("`{}`", item.name)
    } else {
        item.name.clone()
    };
    if !item.children.is_empty() {
        text.push_str(" (");
        text.push_str(&render_inputs(&item.children));
        text.push(')');
    }
    text
}

/// The Inputs items an ordinary row must hold: the backticked `op`, then the
/// arm's wire field names in declaration order.
fn ordinary_row_inputs(fields: &[String]) -> Vec<InputsItem> {
    let mut items = Vec::with_capacity(fields.len() + 1);
    items.push(input_leaf("op", true));
    for name in fields {
        items.push(input_leaf(name, true));
    }
    items
}

/// The children of one `params` group. An empty field list is the one bare
/// word `none`. A declared field is one backticked name, including a field
/// whose wire name is `none`. The bare word and the backticked name are
/// different items.
fn param_field_items(fields: &[String]) -> Vec<InputsItem> {
    if fields.is_empty() {
        return vec![input_leaf("none", false)];
    }
    fields.iter().map(|name| input_leaf(name, true)).collect()
}

/// The Inputs items one `wallet_contract <kind>` row must hold.
///
/// The cell starts with the backticked `op`. Each envelope field is a
/// backticked leaf, except the field whose wire name is `request`: that item's
/// children are the backticked token `kind: <kind>` and the backticked `params`
/// group. `params` holds the arm's wire field names, in declaration order.
/// The empty arm's only `params` child is the bare word `none`.
fn contract_row_inputs(kind: &str, envelope: &[String], params: &[String]) -> Vec<InputsItem> {
    let mut items = vec![input_leaf("op", true)];
    for name in envelope {
        if name == "request" {
            items.push(InputsItem {
                name: "request".to_string(),
                quoted: true,
                children: vec![
                    input_leaf(&format!("kind: {kind}"), true),
                    InputsItem {
                        name: "params".to_string(),
                        quoted: true,
                        children: param_field_items(params),
                    },
                ],
            });
        } else {
            items.push(input_leaf(name, true));
        }
    }
    items
}

/// The contract enum's source file. A provider source that declares the enum
/// is that source instead, so a fixture does not read this file.
fn wallet_operation_contract_path() -> PathBuf {
    let relative = Path::new("elastos/crates/elastos-wallet-contract/src/lib.rs");
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|dir| dir.join(relative).is_file())
        .map(|dir| dir.join(relative))
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(relative)
        })
}

/// The path a refusal names for the contract enum, and the text that holds it.
/// The provider dispatch is the text when it declares the enum. Otherwise this
/// opens the contract file.
fn contract_enum_text(sources: &WireSources<'_>) -> Result<(PathBuf, String), String> {
    if item_body(sources.dispatch, "WalletProviderOperationV2", "enum").is_some() {
        return Ok((
            sources.dispatch_path.to_path_buf(),
            sources.dispatch.to_string(),
        ));
    }
    let path = wallet_operation_contract_path();
    match fs::read_to_string(&path) {
        Ok(text) => Ok((path, text)),
        Err(err) => Err(format!(
            "Inputs cells cannot be checked because {} is not readable: {err}",
            path.display()
        )),
    }
}

/// The declaration path and the contract path, once when they are the same file.
fn inputs_source_label(declaration: &Path, contract: &Path) -> String {
    if declaration == contract {
        declaration.display().to_string()
    } else {
        format!("{} and {}", declaration.display(), contract.display())
    }
}

/// The file, relative to a provider directory, that declares the `Request`
/// enum a table's Inputs cells name. Wallet declares it in `src/protocol.rs`
/// and answers it from `src/main.rs`; did declares and answers it in its one
/// `src/main.rs`, and every other provider uses that one file for both.
fn request_declaration_file(name: &str) -> &'static str {
    match name {
        "wallet-provider" => "src/protocol.rs",
        _ => "src/main.rs",
    }
}

/// The provider sources one operations table's Inputs cells are read, each with
/// the path a refusal names. The caller reads both files; the rule opens none.
struct WireSources<'a> {
    /// The provider's `src/main.rs`, which holds its dispatch.
    dispatch: &'a str,
    dispatch_path: &'a Path,
    /// The provider file that declares its `Request` enum.
    declarations: &'a str,
    declarations_path: &'a Path,
}

/// Every problem with one table's ordinary Inputs cells, each naming the
/// document, the row, the cell and the source it read.
///
/// An ordinary row's cell holds the backticked `op` and then the wire names its
/// provider's `Request` arm declares, in declaration order. A first item other
/// than the backticked `op`, another name, another order, a missing name, an
/// extra name, a bare word where the table writes a backticked name and a cell
/// the reader cannot parse are each one problem for that row. A row whose
/// operation has no arm in `Request` is a named refusal, never a skip. A source
/// with no `fn handle` and one with no `enum Request` each keep their own
/// reason naming the file.
///
/// A row whose operation starts `wallet_contract ` names the backticked `op`,
/// the `WalletContract` envelope, and that kind's `params`. The kind is
/// `variant_snake_case` of the `WalletProviderOperationV2` arm. The field
/// whose wire name is `request` holds the backticked `kind: <kind>` token and
/// the backticked `params` group. An empty arm's `params` holds the bare word
/// `none`. The contract file is opened only when the table has such a row. An
/// unreadable contract file is one refusal that names the path. A row with no
/// matching dispatch arm stays with `row_set_problems`.
///
/// Honesty limits: the rule reads declarations, not serde's output, so a field
/// carrying `#[serde(skip)]` would be required here and would need the rule
/// widened when one is added, while `#[serde(default)]` and
/// `#[serde(skip_serializing_if = ...)]` fields are real wire names and are
/// required. It checks the names and their order, not a value's type.
///
/// Falsifier: WP181 makes `field_wire_name` honour no `serde` attribute, so a
/// renamed field reads as its Rust name; WP182 makes `inputs_match` tolerate a
/// cell that stops before a declared field.
/// WP183 and WP184 change character-literal and raw-identifier handling.
/// WP185 through WP197 change quoting, order, cell syntax, or source refusals.
/// WP198 makes the field-list reader read a list whose delimiters do not
/// balance as a shorter list. WP214 makes an empty arm and a field named
/// `none` the same item. WP215 makes `inputs_match` ignore children, so a
/// `params` list can name a field the arm does not declare.
/// `operations_table_row_check_refuses_each_bad_table` fails on each.
fn inputs_cell_problems(
    document_name: &str,
    rows: &[OperationsRow],
    sources: &WireSources<'_>,
) -> Vec<String> {
    let Some(handle_arms) = dispatch_arm_variants(sources.dispatch, "fn handle(", REQUEST_ARM)
    else {
        return vec![format!(
            "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} Inputs cells cannot be checked \
             because {} holds no fn handle",
            sources.dispatch_path.display()
        )];
    };
    let Some(request_body) = item_body(sources.declarations, "Request", "enum") else {
        return vec![format!(
            "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} Inputs cells cannot be checked \
             because {} declares no enum Request",
            sources.declarations_path.display()
        )];
    };
    let contract_prefix = format!("{WALLET_CONTRACT_ARM} ");
    let mut problems = Vec::new();
    let has_contract_row = rows
        .iter()
        .any(|row| row.operation.starts_with(&contract_prefix));
    // Open the contract file only when a row names a contract kind. did's table
    // has no such row, so it does not depend on that file.
    let mut loaded_contract: Option<LoadedContract> = None;
    let mut contract_blocked = false;
    if has_contract_row {
        match contract_enum_text(sources) {
            Err(reason) => {
                problems.push(format!(
                    "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} {reason}"
                ));
                contract_blocked = true;
            }
            Ok((path, text)) => {
                match prepare_contract_inputs(sources, &request_body, &path, &text) {
                    Ok(loaded) => loaded_contract = Some(loaded),
                    Err(reason) => {
                        problems.push(format!(
                            "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} {reason}"
                        ));
                        contract_blocked = true;
                    }
                }
            }
        }
    }
    for row in rows {
        let (expected, source_label) = if row.operation.starts_with(&contract_prefix) {
            if contract_blocked {
                continue;
            }
            let loaded = loaded_contract
                .as_ref()
                .expect("a contract row is checked only after its enum loads");
            let kind = &row.operation[contract_prefix.len()..];
            let Some(variant) = loaded
                .kinds
                .iter()
                .find(|arm| variant_snake_case(arm) == kind)
            else {
                // A row with no dispatch arm is `row_set_problems`'s to refuse.
                continue;
            };
            let params = match wire_field_names(&loaded.body, variant) {
                WireFieldNames::Names(fields) => fields,
                WireFieldNames::NoDeclaration => {
                    problems.push(format!(
                        "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row {} holds the \
                         Inputs cell {}, and {} declares no {variant} arm",
                        row.operation,
                        row.inputs,
                        loaded.path.display()
                    ));
                    continue;
                }
                WireFieldNames::Unsupported(reason) => {
                    problems.push(format!(
                        "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row {} holds the \
                         Inputs cell {}, and the {variant} arm of {} cannot be read: {reason}",
                        row.operation,
                        row.inputs,
                        loaded.path.display()
                    ));
                    continue;
                }
            };
            (
                contract_row_inputs(kind, &loaded.envelope, &params),
                loaded.label.clone(),
            )
        } else {
            let Some(variant) = handle_arms
                .iter()
                .find(|arm| variant_snake_case(arm) == row.operation)
            else {
                // A row with no dispatch arm is `row_set_problems`'s to refuse; this
                // rule names no second reason for it.
                continue;
            };
            let fields = match wire_field_names(&request_body, variant) {
                WireFieldNames::Names(fields) => fields,
                WireFieldNames::NoDeclaration => {
                    problems.push(format!(
                        "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row {} holds the Inputs \
                         cell {}, and {} declares no {variant} arm",
                        row.operation,
                        row.inputs,
                        sources.declarations_path.display()
                    ));
                    continue;
                }
                WireFieldNames::Unsupported(reason) => {
                    problems.push(format!(
                        "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row {} holds the Inputs \
                         cell {}, and the {variant} arm of {} cannot be read: {reason}",
                        row.operation,
                        row.inputs,
                        sources.declarations_path.display()
                    ));
                    continue;
                }
            };
            (
                ordinary_row_inputs(&fields),
                sources.declarations_path.display().to_string(),
            )
        };
        let matched =
            input_items(&row.inputs).is_some_and(|observed| inputs_match(&observed, &expected));
        if !matched {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row {} holds the Inputs cell \
                 {}, and {} names {}",
                row.operation,
                row.inputs,
                source_label,
                render_inputs(&expected)
            ));
        }
    }
    problems
}

/// One loaded contract enum: its path, the enum body, the dispatch kinds, the
/// `WalletContract` envelope fields, and the source label a refusal names.
struct LoadedContract {
    path: PathBuf,
    body: String,
    kinds: Vec<String>,
    envelope: Vec<String>,
    label: String,
}

/// The contract enum, the dispatch kinds and the `WalletContract` envelope, or
/// one reason the cells cannot be checked.
fn prepare_contract_inputs(
    sources: &WireSources<'_>,
    request_body: &str,
    path: &Path,
    text: &str,
) -> Result<LoadedContract, String> {
    let Some(kinds) = dispatch_arm_variants(
        sources.dispatch,
        "fn dispatch_wallet_operation(",
        WALLET_OPERATION_ARM,
    ) else {
        return Err(format!(
            "Inputs cells cannot be checked because {} answers {WALLET_CONTRACT_ARM} and holds \
             no fn dispatch_wallet_operation",
            sources.dispatch_path.display()
        ));
    };
    let Some(body) = item_body(text, "WalletProviderOperationV2", "enum") else {
        return Err(format!(
            "Inputs cells cannot be checked because {} declares no enum WalletProviderOperationV2",
            path.display()
        ));
    };
    let envelope = match wire_field_names(request_body, "WalletContract") {
        WireFieldNames::Names(fields) => fields,
        WireFieldNames::NoDeclaration => {
            return Err(format!(
                "Inputs cells cannot be checked because {} declares no WalletContract arm",
                sources.declarations_path.display()
            ));
        }
        WireFieldNames::Unsupported(reason) => {
            return Err(format!(
                "Inputs cells cannot be checked because the WalletContract arm of {} cannot be \
                 read: {reason}",
                sources.declarations_path.display()
            ));
        }
    };
    Ok(LoadedContract {
        path: path.to_path_buf(),
        body,
        kinds,
        envelope,
        label: inputs_source_label(sources.declarations_path, path),
    })
}

/// Whether `right` is exactly `NO_DECLARED_RIGHT` or one backtick span holding
/// an id `CONTRACT_RIGHTS` or `PLATFORM_BASELINE_IDS` declares.
fn declared_right_cell(right: &str) -> bool {
    if right == NO_DECLARED_RIGHT {
        return true;
    }
    right
        .strip_prefix('`')
        .and_then(|inner| inner.strip_suffix('`'))
        .is_some_and(|id| CONTRACT_RIGHTS.contains(&id) || PLATFORM_BASELINE_IDS.contains(&id))
}

/// Every problem with one row's Right value, naming the document, the row and
/// the value.
fn right_vocabulary_problems(document_name: &str, row: &OperationsRow) -> Vec<String> {
    if declared_right_cell(&row.right) {
        return Vec::new();
    }
    vec![format!(
        "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row {} holds the Right cell {}, which \
         is neither {NO_DECLARED_RIGHT} nor one declared contract id",
        row.operation, row.right
    )]
}

/// Every problem with the two sides one row cites, naming the document, the row
/// and the missing or extra side.
///
/// A row whose Right is a declared right cites `PERMITTED_SIDE` and
/// `OUTSIDE_SIDE` in its macOS cell. A `none:` row cites neither. A row whose
/// Right is neither value is left to `right_vocabulary_problems`.
fn right_side_problems(document_name: &str, row: &OperationsRow) -> Vec<String> {
    if !declared_right_cell(&row.right) {
        return Vec::new();
    }
    let mut problems = Vec::new();
    for (side, cited) in [
        (PERMITTED_SIDE, row.macos.contains(PERMITTED_SIDE)),
        (OUTSIDE_SIDE, row.macos.contains(OUTSIDE_SIDE)),
    ] {
        if row.right == NO_DECLARED_RIGHT {
            if cited {
                problems.push(format!(
                    "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row {} is \
                     {NO_DECLARED_RIGHT} and cites {side}",
                    row.operation
                ));
            }
        } else if !cited {
            problems.push(format!(
                "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row {} names the Right {} \
                 and does not cite {side}",
                row.operation, row.right
            ));
        }
    }
    problems
}

/// Every problem with one row's Linux cell, naming the document, the row and
/// the value.
fn linux_status_problems(document_name: &str, row: &OperationsRow) -> Vec<String> {
    if row.linux == LINUX_STATUS {
        return Vec::new();
    }
    vec![format!(
        "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row {} names the Linux cell {}, and \
         every Linux cell is {LINUX_STATUS}",
        row.operation, row.linux
    )]
}

/// Every problem with one operations table's rows, each naming the document,
/// the row (or the arm) and the value.
///
/// The section under `OPERATIONS_HEADING` must hold a table whose first line is
/// complete `TABLE_HEADER` and whose second is the dash separator. Every later
/// nonempty line is a row, including repeated headers and rows with leading
/// whitespace or omitted outer bars. Then the section must hold five things. Its row set,
/// in table order, must equal the operations `<provider_dir>/src/main.rs`
/// answers through `fn handle`, with a `wallet_contract` arm expanded to one
/// `wallet_contract <kind>` row per `fn dispatch_wallet_operation` arm. An
/// ordinary row's Inputs cell must name the backticked `op` and then the wire
/// field names its `Request` arm declares, in declaration order, from the file
/// `request_declaration_file` names. Each
/// Right cell must be exactly `NO_DECLARED_RIGHT` or one backtick span holding
/// an id `CONTRACT_RIGHTS` or `PLATFORM_BASELINE_IDS` declares. A row whose
/// Right is a declared right must cite `permitted:` and `nearest outside
/// refused:` in its macOS cell, and a `none:` row must cite neither. Every
/// Linux cell must be `LINUX_STATUS`.
///
/// Honesty limits: rule 1 reads the dispatch arms as text, so it shows the row
/// set matches the arms, not that every arm is reachable; rule 2 reads a
/// `wallet_contract` row's Inputs cell against that kind's declared `params`;
/// and the check says nothing about the Outputs keys, which stay held in
/// BACKLOG item 21.
fn operations_table_row_problems(
    document_name: &str,
    document: &str,
    provider_dir: &Path,
) -> Vec<String> {
    let section = match section_under_one_heading(document_name, document, OPERATIONS_HEADING) {
        Ok(section) => section,
        Err(problems) => return problems,
    };
    let (rows, mut problems) = match operations_table_rows(document_name, &section) {
        Ok(read) => read,
        Err(problems) => return problems,
    };
    let provider_path = provider_dir.join("src").join("main.rs");
    let mut dispatch: Option<String> = None;
    match fs::read_to_string(&provider_path) {
        Ok(source) => {
            problems.extend(row_set_problems(
                document_name,
                &rows,
                &source,
                &provider_path,
            ));
            dispatch = Some(source);
        }
        Err(err) => problems.push(format!(
            "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} row set cannot be checked \
             because {} is not readable: {err}",
            provider_path.display()
        )),
    }
    for row in &rows {
        problems.extend(right_vocabulary_problems(document_name, row));
        problems.extend(right_side_problems(document_name, row));
        problems.extend(linux_status_problems(document_name, row));
    }
    if let Some(source) = &dispatch {
        let declaration_path = provider_dir.join(request_declaration_file(document_name));
        let declarations = if declaration_path == provider_path {
            Ok(source.clone())
        } else {
            fs::read_to_string(&declaration_path)
        };
        match declarations {
            Ok(declarations) => problems.extend(inputs_cell_problems(
                document_name,
                &rows,
                &WireSources {
                    dispatch: source,
                    dispatch_path: &provider_path,
                    declarations: &declarations,
                    declarations_path: &declaration_path,
                },
            )),
            Err(err) => problems.push(format!(
                "{document_name} CONFINEMENT.md: {OPERATIONS_HEADING} Inputs cells cannot be \
                 checked because {} is not readable: {err}",
                declaration_path.display()
            )),
        }
    }
    problems
}

/// The top-level allow forms of `profile`, in profile order. This is the one
/// selector, used by the removal check and the declared-rights check (P10).
fn allow_forms(profile: &str) -> Vec<String> {
    profile_forms(profile)
        .into_iter()
        .filter(|form| is_allow_form(form))
        .collect()
}

/// The top-level allow forms of `profile` that no `entries` item removes.
///
/// An entry removes a form only when it expects a catch and one of its edits
/// names this profile's `confine.sb` by the one runner's path rule, holds the
/// form in its `old` forms and not in its `new` forms. A form that no entry
/// removes comes back by name, so a new grant cannot enter a profile silently.
///
/// Falsifier: WP45 to WP48 drop each removal condition in turn;
/// `allow_rule_removal_check_reports_an_unremoved_rule` fails on each.
fn unremoved_allow_forms(name: &str, profile: &str, entries: &[Value]) -> Vec<String> {
    let target = runner_edit_path(&format!("../../capsules/{name}/confine.sb"));
    allow_forms(profile)
        .into_iter()
        .filter(|form| {
            !target.as_ref().is_some_and(|target| {
                entries
                    .iter()
                    .any(|entry| entry_removes(entry, target, form))
            })
        })
        .collect()
}

/// Whether one list entry removes `form`. `expect` must be `caught`, because
/// an entry that expects no catch proves nothing about a form.
fn entry_removes(entry: &Value, target: &Path, form: &str) -> bool {
    entry["expect"].as_str() == Some("caught")
        && entry["edits"]
            .as_array()
            .is_some_and(|edits| edits.iter().any(|edit| edit_removes(edit, target, form)))
}

/// Whether one edit removes `form`: its file must name the profile by the
/// runner's path rule, its `old` forms must include the form and its `new`
/// forms must not.
fn edit_removes(edit: &Value, target: &Path, form: &str) -> bool {
    let Some(file) = edit["file"].as_str() else {
        return false;
    };
    if runner_edit_path(file).as_deref() != Some(target) {
        return false;
    }
    let old = edit["old"].as_str().unwrap_or_default();
    let new = edit["new"].as_str().unwrap_or_default();
    profile_forms(old).iter().any(|candidate| candidate == form)
        && !profile_forms(new).iter().any(|candidate| candidate == form)
}

/// Uses the runner's `examples/agent-host` base and filesystem resolution.
/// Like Python's `Path`, components discard `.` and repeated separators while
/// preserving the root and `..`. The runner replaces the final directory entry,
/// so resolve its parent, retaining a final symlink's own name.
fn runner_edit_path(file: &str) -> Option<PathBuf> {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/agent-host")
        .join(file)
        .components()
        .collect();
    if !path.is_file() {
        return None;
    }
    Some(path.parent()?.canonicalize().ok()?.join(path.file_name()?))
}

/// A minimal profile built from the contract's own pieces: the head forms and
/// the shared rules. It copies no provider's profile.
fn contract_fixture_profile(deny_network: bool) -> String {
    let mut fixture = String::from("(version 1)\n(deny default)\n");
    if deny_network {
        fixture.push_str("(deny network*)\n");
    }
    for rule in SHARED_RULES {
        fixture.push_str(rule);
        fixture.push('\n');
    }
    fixture
}

/// Writes `profile` as `capsules/<provider>/confine.sb` under a temporary
/// directory.
fn write_fixture_profile(capsules: &Path, provider: &str, profile: &str) {
    let dir = capsules.join(provider);
    fs::create_dir_all(&dir).expect("fixture provider directory");
    fs::write(dir.join("confine.sb"), profile).expect("fixture profile");
}

/// A temporary `capsules/` directory holding the passing fixture for all
/// three required file profiles.
fn contract_fixture_capsules() -> tempfile::TempDir {
    let capsules = tempfile::tempdir().expect("temporary capsules directory");
    let fixture = contract_fixture_profile(true);
    for name in FILE_PROFILES {
        write_fixture_profile(capsules.path(), name, &fixture);
    }
    capsules
}

/// The contract fixture profile plus the two allow forms did and wallet get for
/// startup, so the declared-rights fixture can trace all five forms.
fn declared_rights_fixture_profile() -> String {
    let mut profile = contract_fixture_profile(true);
    for rule in STARTUP_RULES {
        profile.push_str(rule);
        profile.push('\n');
    }
    profile
}

/// The declared-rights fixture for `provider`: the two rights and the two
/// platform-baseline rules, each holding the allow forms of
/// `declared_rights_fixture_profile` and a justification for its provider.
fn declared_rights_fixture(provider: &str) -> Value {
    let mut fixture = json!({
        "role": DECLARED_RIGHTS_ROLE,
        "provider": provider,
        "rights": [
            {"id": "storage", "rules": [SHARED_RULES[1], SHARED_RULES[2]]},
            {"id": "bound-executable", "rules": [SHARED_RULES[0]]},
        ],
    });
    let prefix = platform_baseline_justification(provider);
    fixture[PLATFORM_BASELINE] = json!({
        "status": platform_baseline_status(provider),
        "rules": [
            {
                "id": "startup-root-directory",
                "justification": format!(
                    "{prefix}file-read* of literal / is the startup root-directory read."
                ),
                "rules": [STARTUP_RULES[0]],
            },
            {
                "id": "startup-sysctl",
                "justification": format!(
                    "{prefix}sysctl-read is the startup read of kernel facts by the loader \
                     and the allocator."
                ),
                "rules": [STARTUP_RULES[1]],
            },
        ],
    });
    fixture
}

/// Writes `declared` as
/// `capsules/<provider>/tests/fixtures/confine/declared-rights.json` under a
/// temporary directory.
fn write_declared_rights(capsules: &Path, provider: &str, declared: &Value) {
    let dir = capsules.join(provider).join("tests/fixtures/confine");
    fs::create_dir_all(&dir).expect("fixture declared-rights directory");
    fs::write(dir.join("declared-rights.json"), declared.to_string())
        .expect("fixture declared rights");
}

/// The did, wallet and model file profiles present one contract: the same
/// canonical parameter tokens and the same deny-by-default head. The tests
/// bind `STORAGE_ROOT`, `STORAGE_PARENT` and `PROVIDER_EXECUTABLE` with one
/// launch for every provider, and the Runtime bridge change does the same; it
/// is not built. A provider-prefixed token would add a second path for one
/// operation (P10). All three profiles are required, in list order.
///
/// Falsifier: rename `STORAGE_ROOT` to `WALLET_STORAGE_ROOT` in either
/// `confine.sb`; this test fails on the non-canonical token.
#[test]
fn both_file_profiles_bind_one_storage_parameter_contract() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    let checked = check_file_profiles(capsules).unwrap_or_else(|err| panic!("{err}"));
    assert!(
        checked.starts_with(&FILE_PROFILES),
        "the required file profiles must be checked first: {checked:?}"
    );
}

/// Every top-level allow rule of the did and wallet profiles traces to exactly
/// one right the shared contract names, or to one platform-baseline rule.
///
/// The check reads `capsules/did-provider/confine.sb`,
/// `capsules/wallet-provider/confine.sb` and each provider's
/// `tests/fixtures/confine/declared-rights.json`. That file is a lab stand-in
/// for the Runtime generator's input and not a manifest field; the profile
/// rules are evidence for Anders to review and not accepted rights. Each
/// profile's allow forms and each declared rule meet one to one, the shared
/// rules keep their named rights, the two startup forms are claimed by
/// `startup-root-directory` and `startup-sysctl` whenever the profile holds
/// them, no id or rule is declared twice, and each platform-baseline entry
/// gives a justification that names the provider executable the Runtime binds.
/// An unreadable profile, an unreadable or invalid declared-rights file and
/// every refusal of the one check fail the test with the provider name and the
/// rule or id. The model profile is not read here. The test reads files and
/// starts no process, so it runs on every platform.
///
/// Falsifier: WP84 appends
/// `(allow file-read* (literal "/private/var/cc-confine-unnamed"))` to the did
/// profile, and WP85 appends the same rule to the wallet profile; this test
/// fails because no declared right and no platform-baseline rule claims that
/// form. WP86 renames the one platform-baseline key the check reads; this test
/// fails because the did and wallet files no longer hold it.
#[test]
fn every_did_and_wallet_allow_rule_traces_to_one_declared_right() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    for name in allow_rule_profiles() {
        let profile_path = capsules.join(name).join("confine.sb");
        let profile =
            read_allow_rule_profile(name, &profile_path).unwrap_or_else(|err| panic!("{err}"));
        let declared_path = capsules
            .join(name)
            .join("tests/fixtures/confine/declared-rights.json");
        let declared =
            read_declared_rights(name, &declared_path).unwrap_or_else(|err| panic!("{err}"));
        check_declared_rights(name, &profile, &declared).unwrap_or_else(|err| panic!("{err}"));
    }
}

/// The one profile comparison: requires `generated` to hold the contract head
/// in order and the same remaining forms as `committed`, in any order.
///
/// The committed profile holds only allow forms after its head, so the order
/// of those forms does not change what is granted and the comparison sorts
/// them; the head keeps its order. A mismatch returns the provider name, the
/// forms only `generated` holds and the forms only `committed` holds.
/// `generated_did_and_wallet_profiles_match_their_committed_oracles` compares
/// the lab generator's text with each committed oracle, and the B3 journey
/// compares the profile the stand-in launched with that same oracle, so the
/// two callers share one comparison body (P10).
fn compare_profile_to_its_oracle(
    name: &str,
    generated: &str,
    committed: &str,
) -> Result<(), String> {
    let generated_forms = profile_forms(generated);
    let committed_forms = profile_forms(committed);
    let head = |forms: &[String]| {
        forms
            .iter()
            .take(PROFILE_HEAD.len())
            .map(String::as_str)
            .eq(PROFILE_HEAD)
    };
    if !head(&generated_forms) {
        return Err(format!(
            "{name} generated profile must start with {PROFILE_HEAD:?}: {generated}"
        ));
    }
    if !head(&committed_forms) {
        return Err(format!(
            "{name} committed profile must start with {PROFILE_HEAD:?}: {committed}"
        ));
    }
    let mut generated_rest: Vec<String> = generated_forms
        .iter()
        .skip(PROFILE_HEAD.len())
        .cloned()
        .collect();
    let mut committed_rest: Vec<String> = committed_forms
        .iter()
        .skip(PROFILE_HEAD.len())
        .cloned()
        .collect();
    generated_rest.sort();
    committed_rest.sort();
    if generated_rest != committed_rest {
        let only_generated: Vec<&String> = generated_rest
            .iter()
            .filter(|form| !committed_rest.contains(form))
            .collect();
        let only_committed: Vec<&String> = committed_rest
            .iter()
            .filter(|form| !generated_rest.contains(form))
            .collect();
        return Err(format!(
            "{name} generated profile differs from its committed oracle: only in generated \
             {only_generated:?}, only in committed {only_committed:?}"
        ));
    }
    Ok(())
}

/// The one lab generator builds each did and wallet profile from its
/// declared-rights file and the contract head, and the generated profile
/// equals that provider's committed `confine.sb`, the test oracle.
///
/// The test reads each provider's `tests/fixtures/confine/declared-rights.json`
/// with `read_declared_rights`, generates its profile with `generate_profile`,
/// then requires `check_profile_contract` and `check_declared_rights` to accept
/// the generated profile. The committed profile is read with
/// `read_allow_rule_profile` and compared with the generated one through
/// `compare_profile_to_its_oracle`; the B3 journey calls that same comparison
/// on the profile the stand-in launched. The Runtime's own generator and its
/// comparison are not built. The test reads files and starts no process, so it
/// runs on every platform.
///
/// Falsifier: WP105 makes `generate_profile` emit
/// `(allow file-read* (literal "/private/var/cc-confine-generated"))` after
/// the head; this test fails because that rule is in neither declared-rights
/// file. WP109 makes `generate_profile` emit
/// `(deny file-write* (literal "/private/var/cc-confine-generated"))` after the
/// declared rules; this test fails only at the sorted-tail comparison, because
/// the head keeps its order and neither contract check reads a deny form.
#[test]
fn generated_did_and_wallet_profiles_match_their_committed_oracles() {
    for name in allow_rule_profiles() {
        let committed = read_allow_rule_profile(name, &confine_oracle_path(name))
            .unwrap_or_else(|err| panic!("{err}"));
        let declared = read_declared_rights(name, &declared_rights_path(name))
            .unwrap_or_else(|err| panic!("{err}"));
        let generated = generate_profile(name, &declared).unwrap_or_else(|err| panic!("{err}"));
        check_profile_contract(name, &generated).unwrap_or_else(|err| panic!("{err}"));
        check_declared_rights(name, &generated, &declared).unwrap_or_else(|err| panic!("{err}"));
        compare_profile_to_its_oracle(name, &generated, &committed)
            .unwrap_or_else(|err| panic!("{err}"));
    }
}

/// Fails when a file outside test code names the lab generator or writer.
///
/// A file may name `generate_profile` or `write_generated_profile` only when
/// its path relative to `root` has a component exactly `tests`, its file name
/// is exactly `falsifiers.json`, or its extension is `md`. Every other file
/// fails. The walk reads every regular file as bytes, so a non-UTF-8 file is
/// read, not skipped, and matches each name as a plain byte substring, so a
/// longer name that contains one also fails (P11). It does not follow symbolic
/// links. It skips `.git` (git data), `node_modules` (dependency build output)
/// and a directory whose name starts with `target` (cargo's `target/` and the
/// lane's `target-build/`); each skip is build output or git data, not source.
///
/// Returns the number of files it read, or one refusal that lists every
/// offending path, relative to `root` and sorted, with the reason.
fn check_lab_generator_names(root: &Path) -> Result<usize, String> {
    const NAMES: [&[u8]; 2] = [b"generate_profile", b"write_generated_profile"];
    let mut pending = vec![root.to_path_buf()];
    let mut read = 0usize;
    let mut offending: Vec<PathBuf> = Vec::new();
    while let Some(dir) = pending.pop() {
        let entries = fs::read_dir(&dir)
            .map_err(|err| format!("{} must be readable: {err}", dir.display()))?;
        for entry in entries {
            let entry =
                entry.map_err(|err| format!("{} must be readable: {err}", dir.display()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|err| format!("{} must be readable: {err}", path.display()))?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                let name = entry.file_name();
                let name = name.to_str().unwrap_or_default();
                if name == ".git" || name == "node_modules" || name.starts_with("target") {
                    continue;
                }
                pending.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let bytes = fs::read(&path)
                .map_err(|err| format!("{} must be readable: {err}", path.display()))?;
            read += 1;
            let relative = path.strip_prefix(root).unwrap_or(path.as_path());
            let in_tests = relative
                .components()
                .any(|component| component.as_os_str().to_str() == Some("tests"));
            let file_name = path.file_name().and_then(|name| name.to_str());
            let extension = path.extension().and_then(|extension| extension.to_str());
            if in_tests || file_name == Some("falsifiers.json") || extension == Some("md") {
                continue;
            }
            if NAMES
                .iter()
                .any(|name| bytes.windows(name.len()).any(|window| window == *name))
            {
                offending.push(relative.to_path_buf());
            }
        }
    }
    if offending.is_empty() {
        return Ok(read);
    }
    offending.sort();
    Err(offending
        .iter()
        .map(|path| {
            format!(
                "{} names the lab generator, which is test code only",
                path.display()
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

/// The lab generator and its writer are named only in test code.
///
/// The test walks the whole repository from `capsules/`'s parent and requires
/// that no file outside test code names `generate_profile` or
/// `write_generated_profile`. It prints how many files it read.
#[test]
fn lab_generator_is_named_only_in_test_code() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|capsules| capsules.parent())
        .expect("capsules/wallet-provider must sit under the repository root");
    let read = check_lab_generator_names(root).unwrap_or_else(|err| panic!("{err}"));
    println!("lab generator name check read {read} files");
}

/// A non-test file that names the lab generator is refused, and the exempt
/// files and build output are not.
///
/// The fixture holds `src/main.rs` and `elastos/x.py` naming the generator and
/// writer, the exempt `tests`, `falsifiers.json` and `md` names, and a
/// `target/` file naming it. The refusal names exactly the first two, sorted;
/// after they are removed the check returns `Ok`. A longer name that contains
/// `generate_profile` and a non-UTF-8 file naming it are then each refused,
/// because the check matches plain bytes and reads every file as bytes.
#[test]
fn lab_generator_name_check_refuses_a_non_test_file() {
    let root = tempfile::tempdir().expect("temporary repository root");
    let root = root.path();
    let files = [
        ("src/main.rs", "fn main() { generate_profile(); }\n"),
        ("elastos/x.py", "write_generated_profile(path)\n"),
        ("crate/tests/a.rs", "generate_profile\n"),
        ("crate/src/tests/b.rs", "write_generated_profile\n"),
        (
            "crate/falsifiers.json",
            "{\"about\": \"generate_profile\"}\n",
        ),
        ("crate/README.md", "generate_profile\n"),
        ("target/debug/planted.rs", "generate_profile\n"),
    ];
    for (path, contents) in files {
        let path = root.join(path);
        fs::create_dir_all(path.parent().expect("a fixture file has a parent"))
            .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        fs::write(&path, contents).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    }
    let refusal = check_lab_generator_names(root)
        .expect_err("a non-test file that names the generator must be refused");
    assert_eq!(
        refusal,
        "elastos/x.py names the lab generator, which is test code only\n\
         src/main.rs names the lab generator, which is test code only"
    );
    fs::remove_file(root.join("elastos/x.py")).expect("remove the python fixture");
    fs::remove_file(root.join("src/main.rs")).expect("remove the rust fixture");
    assert_eq!(
        check_lab_generator_names(root).expect("only test code and build output remain"),
        4
    );
    fs::write(root.join("crate/longer.rs"), "regenerate_profile\n")
        .expect("a fixture file under crate/");
    assert_eq!(
        check_lab_generator_names(root)
            .expect_err("a longer name that contains the generator name must be refused"),
        "crate/longer.rs names the lab generator, which is test code only"
    );
    fs::remove_file(root.join("crate/longer.rs")).expect("remove the longer-name fixture");
    fs::write(root.join("crate/binary.bin"), b"\xffgenerate_profile\xfe")
        .expect("a non-UTF-8 fixture file");
    assert_eq!(
        check_lab_generator_names(root)
            .expect_err("a non-UTF-8 file that names the generator must be read, not skipped"),
        "crate/binary.bin names the lab generator, which is test code only"
    );
    fs::remove_file(root.join("crate/binary.bin")).expect("remove the binary fixture");
}

/// The model provider's declared-rights file uses the same template as did and
/// wallet, and the one check reads it unchanged.
///
/// The test reads `capsules/model-provider/confine.sb` with
/// `read_allow_rule_profile` and the model's
/// `tests/fixtures/confine/declared-rights.json` with `read_declared_rights`,
/// then requires `check_declared_rights("model-provider", ...)` to return
/// `Ok`. A missing profile or declared-rights file fails with its path, as the
/// contract check fails on a missing model profile. `allow_rule_profiles()`
/// stays did and wallet, so the removal and trace checks do not read the model
/// pair. The test reads files and starts no process, so it runs on every
/// platform.
///
/// Falsifier: WP86 renames the one platform-baseline key the check reads; this
/// test fails because the model file no longer holds that key.
#[test]
fn model_declared_rights_read_on_the_did_and_wallet_template() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    let name = "model-provider";
    let profile_path = capsules.join(name).join("confine.sb");
    let profile =
        read_allow_rule_profile(name, &profile_path).unwrap_or_else(|err| panic!("{err}"));
    let declared_path = capsules
        .join(name)
        .join("tests/fixtures/confine/declared-rights.json");
    let declared = read_declared_rights(name, &declared_path).unwrap_or_else(|err| panic!("{err}"));
    check_declared_rights(name, &profile, &declared).unwrap_or_else(|err| panic!("{err}"));
}

/// The declared-rights check refuses each bad input with a reason that starts
/// with the provider name and names the rule or id.
///
/// A temporary `capsules/` directory holds the passing fixture for all three
/// required file profiles and the two platform-baseline allow forms, plus a
/// declared-rights file for each of did and wallet. The valid pair passes.
/// Then one case for each refusal, in the check's order: a file without the
/// lab role, a file that names another provider, a file without a rights list,
/// a file without a platform baseline, a platform baseline without its status
/// sentence, a platform baseline without its rules list, a right without a
/// rules list, a right with a rule that is not a string, a platform-baseline
/// entry without a string id whose reason names the platform-baseline rules
/// list and the entry, a right id and a platform-baseline id the shared
/// contract does not name, a platform-baseline entry with no justification, an
/// entry whose justification names another provider or gives no reason, an
/// entry with no rules, an id declared twice in the rights list, a rule
/// repeated inside one entry, an allow form the profile holds twice, an allow
/// form with no claimant and one with two claimants, a declared rule that is
/// not an allow form, a shared rule claimed by the wrong id, the two startup
/// rules swapped between their ids, the startup root read claimed by
/// `storage`, and the startup sysctl read claimed by `storage` while its
/// platform-baseline entry is removed. The fixtures are built in the test and
/// no process starts.
///
/// Falsifier: WP87 drops the justification refusal, so this test fails on its
/// missing-justification case. WP93 drops the prefix refusal, so the
/// justification that names another provider passes, and WP94 drops the
/// empty-reason refusal, so the bare prefix passes. WP95 drops the role
/// refusal, WP96 the provider refusal and WP97 the status refusal, so each
/// wrong value passes and the matching case finds no refusal. WP89 drops the
/// pin table's two startup rows, so the swap and moved-root-read cases pass.
/// WP90 drops the repeated-id refusal, WP91 the repeated-rule refusal, and
/// WP92 the duplicate-form refusal, so the profile that holds
/// `(allow sysctl-read)` twice reads "declared rule is not an allow rule of
/// its profile". WP98 drops the missing rights-list refusal, WP99 the missing
/// platform-baseline refusal and WP100 the missing baseline rules-list
/// refusal, each replaced with an empty value, so the check goes on and
/// refuses later with other words, and the case finds no refusal in its own
/// words. WP101 replaces the missing-id refusal with an empty id, so the
/// platform-baseline entry case reads the unnamed-id refusal instead. WP102
/// replaces the missing-rules-list refusal with an empty list, so the right
/// without its rules list reads "with no rules". WP103 skips a rule that is
/// not a string, so the right with a non-string rule passes the check. WP104
/// drops only the pin table's `startup-sysctl` row, so the sysctl read claimed
/// by `storage` passes.
#[test]
fn declared_rights_trace_refuses_each_bad_input() {
    let capsules = contract_fixture_capsules();
    let profile = declared_rights_fixture_profile();
    for name in allow_rule_profiles() {
        write_fixture_profile(capsules.path(), name, &profile);
        write_declared_rights(capsules.path(), name, &declared_rights_fixture(name));
    }
    let name = "did-provider";
    let declared_path = capsules
        .path()
        .join(name)
        .join("tests/fixtures/confine/declared-rights.json");
    let read = || {
        read_declared_rights(name, &declared_path)
            .expect("the fixture declared-rights file must be readable JSON")
    };
    check_declared_rights(name, &profile, &read()).expect("the full fixture must pass");

    let refuse = |declared: &Value, profile: &str| {
        let reason = check_declared_rights(name, profile, declared)
            .expect_err("a bad declared-rights input must be refused");
        assert!(
            reason.starts_with(name),
            "the refusal must start with the provider name: {reason}"
        );
        reason
    };

    let mut declared = read();
    declared["role"] = json!("approved rights");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("must give the role"),
        "a declared-rights file without the lab role must be refused by its role: {reason}"
    );

    let mut declared = read();
    declared["provider"] = json!("wallet-provider");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("must name the provider did-provider"),
        "a declared-rights file that names another provider must be refused by its provider: {reason}"
    );

    let mut declared = read();
    declared
        .as_object_mut()
        .expect("fixture declared rights")
        .remove("rights");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("must hold a rights list"),
        "a declared-rights file without a rights list must be refused by its rights: {reason}"
    );

    let mut declared = read();
    declared
        .as_object_mut()
        .expect("fixture declared rights")
        .remove(PLATFORM_BASELINE);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("must hold a platform baseline"),
        "a declared-rights file without a platform baseline must be refused by its baseline: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["status"] =
        json!(platform_baseline_status(name).replace(", not approved rights", ""));
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("must give the status"),
        "a platform baseline without its status sentence must be refused by its status: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]
        .as_object_mut()
        .expect("fixture platform baseline")
        .remove("rules");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("platform baseline must hold a rules list"),
        "a platform baseline without a rules list must be refused by its rules: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]
        .as_object_mut()
        .expect("fixture storage right")
        .remove("rules");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("storage") && reason.contains("without a rules list"),
        "a right without a rules list must be refused by id and words: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"] = json!([SHARED_RULES[1], 42, SHARED_RULES[2]]);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("storage") && reason.contains("not a string"),
        "a right with a rule that is not a string must be refused by id: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"][1]
        .as_object_mut()
        .expect("fixture platform-baseline entry")
        .remove("id");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("platform baseline rules")
            && reason.contains("entry 1")
            && reason.contains("string id"),
        "a platform-baseline entry without a string id must name the list and the entry: {reason}"
    );

    let mut declared = read();
    declared["rights"]
        .as_array_mut()
        .expect("fixture rights")
        .push(json!({"id": "network", "rules": [SHARED_RULES[1]]}));
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("network") && reason.contains("does not name"),
        "an unnamed right id must be refused by name: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"]
        .as_array_mut()
        .expect("fixture platform-baseline rules")
        .push(json!({"id": "startup-clock", "rules": ["(allow sysctl-read)"]}));
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("startup-clock") && reason.contains("does not name"),
        "an unnamed platform-baseline id must be refused by name: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"][0]
        .as_object_mut()
        .expect("fixture platform-baseline entry")
        .remove("justification");
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("startup-root-directory") && reason.contains("justification"),
        "a platform-baseline entry without a justification must be refused by id: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"][0]["justification"] = json!(format!(
        "{}the kernel resolves every absolute path through the root directory.",
        platform_baseline_justification("wallet-provider")
    ));
    let reason = check_declared_rights(name, &profile, &declared).expect_err(
        "a justification that starts with another provider's executable prefix must be refused",
    );
    assert!(
        reason.starts_with(name)
            && reason.contains("startup-root-directory")
            && reason.contains("must start with")
            && !reason.contains("gives no reason after"),
        "a justification with another provider's prefix must be refused by its prefix: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"][0]["justification"] =
        json!(platform_baseline_justification("did-provider"));
    let reason = check_declared_rights(name, &profile, &declared)
        .expect_err("a justification that gives no reason must be refused");
    assert!(
        reason.starts_with(name)
            && reason.contains("startup-root-directory")
            && reason.contains("gives no reason after")
            && !reason.contains("must start with"),
        "a platform-baseline justification without a reason must be refused as giving \
         no reason: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"] = json!([]);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("storage") && reason.contains("no rules"),
        "an entry with no rules must be refused by id: {reason}"
    );

    let mut declared = read();
    declared["rights"] = json!([
        {"id": "storage", "rules": [SHARED_RULES[1]]},
        {"id": "storage", "rules": [SHARED_RULES[2]]},
        {"id": "bound-executable", "rules": [SHARED_RULES[0]]},
    ]);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("storage") && reason.contains("more than once"),
        "an id declared twice in the rights list must be refused by id: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"]
        .as_array_mut()
        .expect("fixture storage rules")
        .push(json!(SHARED_RULES[1]));
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("storage")
            && reason.contains(SHARED_RULES[1])
            && reason.contains("more than once"),
        "a rule repeated inside one entry must be refused by id and rule: {reason}"
    );

    let mut duplicated = profile.clone();
    duplicated.push_str(STARTUP_RULES[1]);
    duplicated.push('\n');
    let reason = refuse(&read(), &duplicated);
    assert!(
        reason.contains(STARTUP_RULES[1])
            && reason.contains("profile holds the allow rule")
            && reason.contains("more than once"),
        "an allow form the profile holds twice must be refused with its rule: {reason}"
    );

    let mut widened = profile.clone();
    widened.push_str("(allow file-read* (literal \"/private/var/cc-confine-unnamed\"))\n");
    let reason = refuse(&read(), &widened);
    assert!(
        reason.contains("(allow file-read* (literal \"/private/var/cc-confine-unnamed\"))")
            && reason.contains("no declared right"),
        "an unclaimed allow form must be refused with its rule: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"][1]["rules"] = json!([SHARED_RULES[1]]);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains(SHARED_RULES[1])
            && reason.contains("storage")
            && reason.contains("startup-sysctl")
            && reason.contains("more than once"),
        "a form with two claimants must name the rule and both ids: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"]
        .as_array_mut()
        .expect("fixture storage rules")
        .push(json!("(allow file-read* (literal \"/etc\"))"));
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains("(allow file-read* (literal \"/etc\"))"),
        "a rule that is not an allow form must be refused with its text: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"] = json!([SHARED_RULES[0]]);
    declared["rights"][1]["rules"] = json!([SHARED_RULES[1], SHARED_RULES[2]]);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains(SHARED_RULES[0]) && reason.contains("bound-executable"),
        "a shared rule claimed by the wrong id must name the rule and the id: {reason}"
    );

    let mut declared = read();
    declared[PLATFORM_BASELINE]["rules"][0]["rules"] = json!([STARTUP_RULES[1]]);
    declared[PLATFORM_BASELINE]["rules"][1]["rules"] = json!([STARTUP_RULES[0]]);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains(STARTUP_RULES[0])
            && reason.contains("startup-root-directory")
            && reason.contains("must be claimed by"),
        "the two startup rules swapped between their ids must be refused by rule and id: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"]
        .as_array_mut()
        .expect("fixture storage rules")
        .push(json!(STARTUP_RULES[0]));
    declared[PLATFORM_BASELINE]["rules"]
        .as_array_mut()
        .expect("fixture platform-baseline rules")
        .remove(0);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains(STARTUP_RULES[0])
            && reason.contains("startup-root-directory")
            && reason.contains("must be claimed by"),
        "the startup root read moved under storage must be refused by rule and id: {reason}"
    );

    let mut declared = read();
    declared["rights"][0]["rules"]
        .as_array_mut()
        .expect("fixture storage rules")
        .push(json!(STARTUP_RULES[1]));
    declared[PLATFORM_BASELINE]["rules"]
        .as_array_mut()
        .expect("fixture platform-baseline rules")
        .remove(1);
    let reason = refuse(&declared, &profile);
    assert!(
        reason.contains(STARTUP_RULES[1])
            && reason.contains("startup-sysctl")
            && reason.contains("must be claimed by"),
        "the startup sysctl read moved under storage must be refused by rule and id: {reason}"
    );
}

/// Every top-level allow rule of the did and wallet profiles has a registered
/// removal falsifier in one of their two lists.
///
/// The check reads `capsules/did-provider/confine.sb`,
/// `capsules/wallet-provider/confine.sb` and those two providers'
/// `falsifiers.json`. A form that no entry removes fails the test with its
/// profile name and asks for a registered removal falsifier or deletion. An
/// unreadable or unparsable source fails with its path; there is no skip path.
/// The model profile is not read, because
/// `capsules/model-provider/confine-falsifiers.json` holds its own bar. The
/// test reads files and starts no process, so it runs on every platform.
///
/// Falsifier: WP44 appends `(allow file-read* (literal "/etc"))` to the did
/// profile; this test fails on that form. WP49 to WP53 make each source
/// refusal a skip, so `allow_rule_removal_check_rejects_bad_inputs` fails.
#[test]
fn every_did_and_wallet_allow_rule_has_a_registered_removal() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    let sources = read_allow_rule_sources(capsules).unwrap_or_else(|err| panic!("{err}"));
    for (name, profile) in &sources.profiles {
        let unremoved = unremoved_allow_forms(name, profile, &sources.entries);
        assert!(
            unremoved.is_empty(),
            "{name}: every top-level allow rule must get a registered removal \
             falsifier or be deleted; no entry removes: {unremoved:?}"
        );
    }
}

/// Every falsifier id registered for did or wallet is named in its own
/// document's `## Falsifiers` section, and neither section names an id that
/// neither list registers.
///
/// The check reads `capsules/did-provider/CONFINEMENT.md`,
/// `capsules/wallet-provider/CONFINEMENT.md` and both `falsifiers.json` lists
/// through the removal check's one list reader. A missing document or list is
/// a refusal that names its path, and there is no skip path. The test reads
/// files and starts no process, so it runs on every platform.
///
/// Before the document edits of task 061 this test failed with DID19, DID20
/// and every missing wallet id.
///
/// Falsifier: WP58 drops the own-id rule, WP59 the unregistered-id rule, WP60
/// matches an id as a substring, WP61 runs a section to the end of the file,
/// and WP62 to WP64 bypass each refusal; the fixture tests catch each one.
#[test]
fn every_falsifier_id_is_named_in_its_confinement_document() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    let lists = read_falsifier_lists(capsules).unwrap_or_else(|err| panic!("{err}"));
    let registered: Vec<String> = lists
        .iter()
        .flat_map(|list| list.ids.iter().cloned())
        .collect();
    let mut problems = Vec::new();
    for list in &lists {
        let document =
            read_confinement_document(capsules, list.name).unwrap_or_else(|err| panic!("{err}"));
        problems.extend(falsifier_section_problems(
            list.name,
            &document,
            &list.ids,
            &registered,
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Every test cited in an operations table exists where the table says.
///
/// The check reads `capsules/<name>/CONFINEMENT.md` for each name in
/// `OPERATIONS_TABLES`, cuts the section under `OPERATIONS_HEADING`, and
/// requires every backtick span of the form `<file>::<fn>` to name a file under
/// `capsules/<name>/` that holds `fn <fn>(`. A missing section, a section that
/// cites no test, a missing file and a missing function each fail with one
/// line. The check does not decide whether the function is a `#[test]`. The
/// test reads files and starts no process, so it runs on every platform.
///
/// Falsifier: WP78 renames `outside_write_denied` in did's `tests/confine.rs`,
/// so the did table's citation names a function that file does not hold and
/// this test fails. WP83 renames `confined_outside_write_is_denied` in this
/// provider's `tests/confine.rs`, so the wallet table's citation names a
/// function that file does not hold and this test fails.
#[test]
fn every_operations_table_cites_existing_tests() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    let mut problems = Vec::new();
    for name in OPERATIONS_TABLES {
        let document =
            read_confinement_document(capsules, name).unwrap_or_else(|err| panic!("{err}"));
        problems.extend(operations_table_citation_problems(
            name,
            &document,
            &capsules.join(name),
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Every row of an operations table matches its provider and the contract.
///
/// The check reads `capsules/<name>/CONFINEMENT.md` for each name in
/// `OPERATIONS_TABLES`, cuts the section under `OPERATIONS_HEADING`, and
/// requires five things of every row: the row set, in table order, equals the
/// operations `capsules/<name>/src/main.rs` answers through `fn handle`, with a
/// `wallet_contract` arm expanded to one row per `fn dispatch_wallet_operation`
/// arm; an ordinary row's Inputs cell names the backticked `op` and then its
/// `Request` arm's wire field names in declaration order; a `wallet_contract`
/// row's Inputs cell names that kind's `params`; the Right cell is
/// exactly `none: needs no declared right` or one
/// declared id in a backtick span; a row whose Right is a declared right cites
/// both `permitted:` and `nearest outside refused:`, and a `none:` row cites
/// neither; and every Linux cell is exactly `designed, not enforced`. Each
/// fault is one line naming the document, the row (or the arm) and the value.
/// The check reads files and starts no process, so it runs on every platform.
///
/// Falsifier: WP141 disables the row-set rule, so a table that omits a row or
/// adds one passes; WP142 disables the Right-vocabulary rule, so a Right cell
/// naming an undeclared id or `no named test shows this` passes; WP143 disables
/// the both-sides rule, so a right row with one side and a `none:` row with a
/// side pass; WP144 disables the Linux-status rule, so a cell naming another
/// status passes; WP181 disables the field reader's `serde` attribute and
/// WP182 the Inputs compare's length rule, so an ordinary row's stale Inputs
/// cell passes. `operations_table_row_check_refuses_each_bad_table` catches
/// each mutation with a bad-table fixture; this test checks the real tables.
#[test]
fn every_operations_table_row_matches_its_provider_and_the_contract() {
    let capsules = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("capsules/wallet-provider must sit under capsules/");
    let mut problems = Vec::new();
    for name in OPERATIONS_TABLES {
        let document =
            read_confinement_document(capsules, name).unwrap_or_else(|err| panic!("{err}"));
        problems.extend(operations_table_row_problems(
            name,
            &document,
            &capsules.join(name),
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The removal check reports an allow form that no entry removes, and only a
/// complete removal counts.
///
/// A fixture profile of `(version 1)`, `(deny default)`, `(allow sysctl-read)`
/// and `(allow process-exec)` with one entry that removes the sysctl rule
/// returns exactly `(allow process-exec)`. An entry whose `new` still holds the
/// form, whose `expect` is not `caught`, whose edit names the other provider's
/// `confine.sb`, or whose `old` does not hold the form removes nothing. One
/// entry for each form leaves nothing. The profile and list contents are built
/// in memory; only path resolution uses the filesystem. No process starts.
///
/// Falsifier: WP45 drops the `expect` condition, WP46 the profile-path
/// condition, WP47 the `old` condition and WP48 the `new` condition; this test
/// fails on each because the bypassing entry then counts as a removal.
#[test]
fn allow_rule_removal_check_reports_an_unremoved_rule() {
    let profile = "(version 1)\n(deny default)\n(allow sysctl-read)\n(allow process-exec)\n";
    let removes_sysctl = json!({
        "id": "F01",
        "expect": "caught",
        "edits": [{
            "file": "../../capsules/did-provider/confine.sb",
            "old": "(allow sysctl-read)",
            "new": ";; Removed: sysctl-read grant.",
        }],
        "tests": ["every_did_and_wallet_allow_rule_has_a_registered_removal"],
    });
    assert_eq!(
        unremoved_allow_forms(
            "did-provider",
            profile,
            std::slice::from_ref(&removes_sysctl)
        ),
        vec!["(allow process-exec)"],
        "the one entry removes only the sysctl rule"
    );

    let removes_exec = json!({
        "id": "F02",
        "expect": "caught",
        "edits": [{
            "file": "../../capsules/did-provider/confine.sb",
            "old": "(allow process-exec)",
            "new": ";; Removed: process-exec grant.",
        }],
        "tests": ["every_did_and_wallet_allow_rule_has_a_registered_removal"],
    });
    assert!(
        unremoved_allow_forms(
            "did-provider",
            profile,
            &[removes_sysctl.clone(), removes_exec.clone()]
        )
        .is_empty(),
        "a complete removal for each rule leaves no form"
    );

    for file in [
        "../../capsules/./did-provider/../did-provider/confine.sb".to_string(),
        "../../capsules//did-provider/confine.sb/.".to_string(),
        format!("{}/../did-provider/confine.sb", env!("CARGO_MANIFEST_DIR")),
    ] {
        let mut removal = removes_exec.clone();
        removal["edits"][0]["file"] = json!(file);
        assert!(
            unremoved_allow_forms("did-provider", profile, &[removes_sysctl.clone(), removal])
                .is_empty(),
            "a path that resolves to the same profile must count: {file}"
        );
    }

    let bypasses = [
        (
            "expect",
            json!({
                "id": "F03",
                "expect": "survives",
                "edits": [{
                    "file": "../../capsules/did-provider/confine.sb",
                    "old": "(allow process-exec)",
                    "new": ";; Removed: process-exec grant.",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
        (
            "profile path",
            json!({
                "id": "F04",
                "expect": "caught",
                "edits": [{
                    "file": "../../capsules/wallet-provider/confine.sb",
                    "old": "(allow process-exec)",
                    "new": ";; Removed: process-exec grant.",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
        (
            "old",
            json!({
                "id": "F05",
                "expect": "caught",
                "edits": [{
                    "file": "../../capsules/did-provider/confine.sb",
                    "old": "(deny default)",
                    "new": ";; Removed: default denial.",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
        (
            "new",
            json!({
                "id": "F06",
                "expect": "caught",
                "edits": [{
                    "file": "../../capsules/did-provider/confine.sb",
                    "old": "(allow process-exec)",
                    "new": "(allow process-exec)\n(allow sysctl-read)",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
        (
            "absolute profile path",
            json!({
                "id": "F07",
                "expect": "caught",
                "edits": [{
                    "file": "/../../capsules/did-provider/confine.sb",
                    "old": "(allow process-exec)",
                    "new": ";; Removed: process-exec grant.",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
        (
            "repository-relative profile path",
            json!({
                "id": "F08",
                "expect": "caught",
                "edits": [{
                    "file": "capsules/did-provider/confine.sb",
                    "old": "(allow process-exec)",
                    "new": ";; Removed: process-exec grant.",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
        (
            "non-directory profile-path component",
            json!({
                "id": "F09",
                "expect": "caught",
                "edits": [{
                    "file": "../../capsules/did-provider/Cargo.toml/../confine.sb",
                    "old": "(allow process-exec)",
                    "new": ";; Removed: process-exec grant.",
                }],
                "tests": ["allow_rule_removal_check_reports_an_unremoved_rule"],
            }),
        ),
    ];
    for (condition, bypass) in bypasses {
        let entries = [removes_sysctl.clone(), bypass];
        assert_eq!(
            unremoved_allow_forms("did-provider", profile, &entries),
            vec!["(allow process-exec)"],
            "an entry that bypasses the {condition} condition must not remove the rule"
        );
    }

    #[cfg(unix)]
    {
        let aliases = tempfile::tempdir().expect("temporary path aliases");
        let provider_alias = aliases.path().join("provider");
        std::os::unix::fs::symlink(env!("CARGO_MANIFEST_DIR"), &provider_alias)
            .expect("create a provider directory alias");
        let mut removal = removes_exec.clone();
        removal["edits"][0]["file"] = json!(provider_alias.join("../did-provider/confine.sb"));
        assert!(
            unremoved_allow_forms("did-provider", profile, &[removes_sysctl.clone(), removal])
                .is_empty(),
            "the runner resolves a parent after following its directory symlink"
        );

        let profile_alias = aliases.path().join("confine.sb");
        std::os::unix::fs::symlink(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../did-provider/confine.sb"),
            &profile_alias,
        )
        .expect("create a profile file alias");
        let mut removal = removes_exec;
        removal["edits"][0]["file"] = json!(profile_alias);
        assert_eq!(
            unremoved_allow_forms("did-provider", profile, &[removes_sysctl, removal]),
            vec!["(allow process-exec)"],
            "the runner replaces the final symlink itself, leaving the profile unchanged"
        );
    }
}

/// The one source reader refuses each bad input with its own path-bearing
/// reason.
///
/// A temporary `capsules/` directory holds one fixture profile and one fixture
/// list per required provider: the valid pair returns both profiles and the
/// combined entries. A missing profile, a profile that does not parse, a
/// missing list, a list that is not JSON, a document without a `falsifiers`
/// list, an entry without an `id` and an entry whose `id` is a number are each
/// a refusal with a distinct reason that names the offending path; an entry
/// refusal also holds the words `string id`. There is no skip path. The
/// fixtures are built in the test and no process starts.
///
/// Falsifier: WP49 turns the unreadable-profile refusal into a skip, WP53 the
/// parse refusal, WP50 the unreadable-list one, WP51 the not-JSON one, WP52
/// the missing-list one and WP66 the string-id refusal; this test fails on
/// each because the refusal does not come.
#[test]
fn allow_rule_removal_check_rejects_bad_inputs() {
    let capsules = tempfile::tempdir().expect("temporary capsules directory");
    let profile = "(version 1)\n(deny default)\n(allow sysctl-read)\n";
    let list = r#"{"about": "fixture", "falsifiers": []}"#;
    for name in FILE_PROFILES {
        write_fixture_profile(capsules.path(), name, profile);
        fs::write(capsules.path().join(name).join("falsifiers.json"), list)
            .expect("fixture falsifier list");
    }
    let sources = read_allow_rule_sources(capsules.path()).expect("a valid fixture pair must read");
    assert_eq!(
        sources.profiles.len(),
        FILE_PROFILES.len() - 1,
        "the reader must return both profiles"
    );
    assert_eq!(
        sources
            .profiles
            .iter()
            .map(|(name, _)| *name)
            .chain(std::iter::once("model-provider"))
            .collect::<Vec<_>>(),
        FILE_PROFILES,
        "the reader must cover the file-profile list apart from model"
    );
    assert!(
        sources.entries.is_empty(),
        "the fixture lists carry no entries"
    );

    let wallet_list = capsules
        .path()
        .join("wallet-provider")
        .join("falsifiers.json");
    let wallet_entry = json!({"id": "wallet-fixture"});
    fs::write(
        &wallet_list,
        json!({"falsifiers": [wallet_entry.clone()]}).to_string(),
    )
    .expect("write a wallet fixture entry");
    let sources =
        read_allow_rule_sources(capsules.path()).expect("the wallet fixture list must read");
    assert_eq!(
        sources.entries,
        vec![wallet_entry],
        "the reader must include the wallet list's entries"
    );
    fs::write(wallet_list, list).expect("restore the empty wallet fixture list");

    let did_profile = capsules.path().join("did-provider").join("confine.sb");
    fs::remove_file(&did_profile).expect("remove the fixture did profile");
    let refusal =
        read_allow_rule_sources(capsules.path()).expect_err("a missing profile must be refused");
    assert!(
        refusal.contains(&did_profile.display().to_string())
            && refusal.contains("must be readable"),
        "the refusal must name the missing profile path: {refusal}"
    );
    fs::write(&did_profile, "(deny default").expect("write a malformed fixture profile");
    let refusal =
        read_allow_rule_sources(capsules.path()).expect_err("a malformed profile must be refused");
    assert!(
        refusal.contains(&did_profile.display().to_string()) && refusal.contains("must parse"),
        "the refusal must name the malformed profile path: {refusal}"
    );
    write_fixture_profile(capsules.path(), "did-provider", profile);

    let did_list = capsules.path().join("did-provider").join("falsifiers.json");
    fs::remove_file(&did_list).expect("remove the fixture did list");
    let refusal =
        read_allow_rule_sources(capsules.path()).expect_err("a missing list must be refused");
    assert!(
        refusal.contains(&did_list.display().to_string()) && refusal.contains("must be readable"),
        "the refusal must name the missing list path: {refusal}"
    );
    fs::write(&did_list, "{").expect("write a malformed fixture list");
    let refusal =
        read_allow_rule_sources(capsules.path()).expect_err("a malformed list must be refused");
    assert!(
        refusal.contains(&did_list.display().to_string()) && refusal.contains("must be valid JSON"),
        "the refusal must name the malformed list path: {refusal}"
    );
    fs::write(&did_list, r#"{"about": "fixture"}"#).expect("write a fixture list without entries");
    let refusal = read_allow_rule_sources(capsules.path())
        .expect_err("a list without a falsifiers list must be refused");
    assert!(
        refusal.contains(&did_list.display().to_string())
            && refusal.contains("must hold a falsifiers list"),
        "the refusal must name the list path: {refusal}"
    );

    let missing_id = json!({"about": "fixture", "falsifiers": [{"title": "no id"}]});
    fs::write(&did_list, missing_id.to_string()).expect("write an entry without an id");
    let refusal = read_allow_rule_sources(capsules.path())
        .expect_err("an entry without an id must be refused");
    assert!(
        refusal.contains(&did_list.display().to_string())
            && refusal.contains("must give entry 0 a string id"),
        "the refusal must name the list path and the missing string id: {refusal}"
    );
    let numeric_id = json!({"about": "fixture", "falsifiers": [{"id": 7}]});
    fs::write(&did_list, numeric_id.to_string()).expect("write an entry with a number id");
    let refusal = read_allow_rule_sources(capsules.path())
        .expect_err("an entry with a number id must be refused");
    assert!(
        refusal.contains(&did_list.display().to_string())
            && refusal.contains("must give entry 0 a string id"),
        "the refusal must name the list path and the non-string id: {refusal}"
    );
}

/// The section check reports an own id that the section does not name and an
/// id-shaped token that neither list registers. It reports no problem when a
/// section names every id as a whole token.
///
/// The list holds `DID1`, `DID2` and `DID10`, and the section names `DID2`,
/// `DID10` and the unregistered `WP9`. `DID1` is missing even though `DID10`
/// appears, because an id counts only as a whole token. The check returns
/// exactly those two problems. A later case has a letter directly before the
/// token, `XDID1`, and another has a letter or `_` directly after its digits,
/// `DID1a` and `DID1_x`; each section names only `DID2`, so each returns
/// exactly the one problem that own id `DID1` is not named, and neither
/// reports its own token as unregistered. The fixtures are built in memory;
/// no file is read and no process starts.
///
/// Falsifier: WP58 drops the own-id rule, WP59 the unregistered-id rule and
/// WP60 matches an id as a substring; this test fails on each because the
/// corresponding problem does not come. WP67 drops the character-before check,
/// so `XDID1` then names `DID1`, and WP68 drops the character-after check, so
/// `DID1a` then names `DID1`; the test fails on the matching case because the
/// missing-id problem does not come.
#[test]
fn falsifier_section_check_reports_missing_and_stale_ids() {
    let own = vec!["DID1".to_string(), "DID2".to_string()];
    let registered = vec!["DID1".to_string(), "DID2".to_string(), "DID10".to_string()];
    let incomplete = "## Falsifiers\n\n- DID2 is named\n- DID10 is named\n- WP9 is named\n";
    assert_eq!(
        falsifier_section_problems("fixture-provider", incomplete, &own, &registered),
        vec![
            "fixture-provider CONFINEMENT.md: own falsifier id DID1 is not named in ## Falsifiers"
                .to_string(),
            "fixture-provider CONFINEMENT.md: ## Falsifiers names WP9, which neither falsifier list registers"
                .to_string(),
        ],
        "the check must report the missing own id and the unregistered id"
    );

    let prefixed = "## Falsifiers\n\n- DID2 is named\n- XDID1 is named\n";
    assert_eq!(
        falsifier_section_problems("fixture-provider", prefixed, &own, &registered),
        vec![
            "fixture-provider CONFINEMENT.md: own falsifier id DID1 is not named in ## Falsifiers"
                .to_string(),
        ],
        "a token with a letter directly before it must not name its own id"
    );

    let suffixed = "## Falsifiers\n\n- DID2 is named\n- DID1a is named\n- DID1_x is named\n";
    assert_eq!(
        falsifier_section_problems("fixture-provider", suffixed, &own, &registered),
        vec![
            "fixture-provider CONFINEMENT.md: own falsifier id DID1 is not named in ## Falsifiers"
                .to_string(),
        ],
        "a token with a letter or _ directly after its digits must not name its own id"
    );

    let complete = "## Tests\n\n- DID2 is named\n\n## Falsifiers\n\n- DID1\n- DID2\n- DID10\n";
    assert!(
        falsifier_section_problems("fixture-provider", complete, &own, &registered).is_empty(),
        "a section that names every id whole must report no problem"
    );
}

/// The section check refuses a document without its section, one with two
/// sections, and one whose id appears only after the section's next heading.
///
/// A document with no `## Falsifiers` line and one with two such lines each
/// return one problem that names the document and says how many headings were
/// found. A document whose section names `DID1` and whose `## Other` section
/// names `DID2` reports `DID2` as missing, because the section ends at the next
/// line that starts with `## `. The fixtures are built in memory; no file is
/// read and no process starts.
///
/// Falsifier: WP61 runs the section to the end of the file, WP62 bypasses the
/// missing-heading refusal and WP63 the duplicate-heading refusal; this test
/// fails on each because the expected problem does not come.
#[test]
fn falsifier_section_check_rejects_a_document_without_its_section() {
    let own = vec!["DID1".to_string(), "DID2".to_string()];
    let registered = own.clone();

    let missing = "## Tests\n\n- DID1 and DID2 are named\n";
    let problems = falsifier_section_problems("fixture-provider", missing, &own, &registered);
    assert_eq!(
        problems.len(),
        1,
        "no heading must be one problem: {problems:?}"
    );
    assert!(
        problems[0].contains("fixture-provider") && problems[0].contains("found none"),
        "the reason must name the document and the missing heading: {}",
        problems[0]
    );

    let doubled = "## Falsifiers\n\n- DID1\n\n## Falsifiers\n\n- DID2\n";
    let problems = falsifier_section_problems("fixture-provider", doubled, &own, &registered);
    assert_eq!(
        problems.len(),
        1,
        "two headings must be one problem: {problems:?}"
    );
    assert!(
        problems[0].contains("fixture-provider") && problems[0].contains("found 2"),
        "the reason must name the document and the heading count: {}",
        problems[0]
    );

    let later = "## Falsifiers\n\n- DID1\n\n## Other\n\n- DID2\n";
    assert_eq!(
        falsifier_section_problems("fixture-provider", later, &own, &registered),
        vec![
            "fixture-provider CONFINEMENT.md: own falsifier id DID2 is not named in ## Falsifiers"
                .to_string()
        ],
        "an id after the next ## heading is outside the section"
    );
}

/// The document reader refuses a missing document and a document it cannot
/// read, each with a reason that names its path, and reads a present one.
///
/// The real-document test reads through this same function, so no unreadable
/// document can become an empty one there. The fixtures are a temporary
/// directory; no process starts.
///
/// Falsifier: WP64 skips an unreadable `CONFINEMENT.md` and returns an empty
/// document; this test fails because the refusal does not come.
#[test]
fn falsifier_document_read_rejects_unreadable_source() {
    let capsules = tempfile::tempdir().expect("temporary capsules directory");
    let provider = capsules.path().join("did-provider");
    let path = provider.join("CONFINEMENT.md");
    let refusal = read_confinement_document(capsules.path(), "did-provider")
        .expect_err("a missing document must be refused");
    assert!(
        refusal.contains(&path.display().to_string()) && refusal.contains("must be readable"),
        "the refusal must name the document path: {refusal}"
    );

    fs::create_dir_all(&provider).expect("fixture provider directory");
    fs::write(&path, "## Falsifiers\n").expect("fixture document");
    assert_eq!(
        read_confinement_document(capsules.path(), "did-provider")
            .expect("a readable document must load"),
        "## Falsifiers\n",
        "the reader must return the document's text"
    );

    fs::remove_file(&path).expect("remove the fixture document");
    fs::create_dir(&path).expect("make the document path a directory");
    let refusal = read_confinement_document(capsules.path(), "did-provider")
        .expect_err("an unreadable document must be refused");
    assert!(
        refusal.contains(&path.display().to_string()) && refusal.contains("must be readable"),
        "the refusal must name the unreadable path: {refusal}"
    );
}

/// The operations-table check reports one line for each missing citation kind.
///
/// A temporary provider folder holds `tests/confine.rs` with `fn present_case()`
/// and `src/main.rs` with `fn unit_case()`. A document whose section cites
/// `tests/confine.rs::present_case` returns no problem. A cited function the
/// file does not hold, a cited file that is absent, a document without the
/// section and a section that cites no test each return one problem that names
/// the document, the citation and the reason. The fixtures are a temporary
/// directory; no process starts.
///
/// Falsifier: WP78 renames `outside_write_denied` in did's `tests/confine.rs`,
/// so the real document's citation names a missing function; the real-document
/// test above fails on it. WP79 bypasses the unresolved-file refusal and WP80
/// bypasses the no-citation refusal; this fixture test catches both.
#[test]
fn operations_table_check_reports_each_missing_citation() {
    let capsule = tempfile::tempdir().expect("temporary provider folder");
    fs::create_dir_all(capsule.path().join("tests")).expect("fixture tests folder");
    fs::create_dir_all(capsule.path().join("src")).expect("fixture src folder");
    fs::write(
        capsule.path().join("tests/confine.rs"),
        "fn present_case() {}\n",
    )
    .expect("fixture integration test file");
    fs::write(capsule.path().join("src/main.rs"), "fn unit_case() {}\n")
        .expect("fixture unit test file");

    let present = "## Operations and the rights they need\n\n| `tests/confine.rs::present_case` |\n\n## Host-OS status\n";
    assert!(
        operations_table_citation_problems("fixture-provider", present, capsule.path()).is_empty(),
        "a citation of a present function must pass"
    );

    let missing_function = "## Operations and the rights they need\n\n| `tests/confine.rs::absent_case` |\n\n## Host-OS status\n";
    let problems =
        operations_table_citation_problems("fixture-provider", missing_function, capsule.path());
    assert_eq!(
        problems.len(),
        1,
        "a missing function must be one problem: {problems:?}"
    );
    assert!(
        problems[0].contains("fixture-provider")
            && problems[0].contains("tests/confine.rs::absent_case")
            && problems[0].contains("does not hold"),
        "the reason must name the document, the citation and the missing function: {}",
        problems[0]
    );
    assert_eq!(
        problems,
        vec![format!(
            "fixture-provider CONFINEMENT.md: tests/confine.rs::absent_case names a function that {} does not hold",
            capsule.path().join("tests/confine.rs").display()
        )]
    );

    let missing_file = "## Operations and the rights they need\n\n| `tests/absent.rs::present_case` |\n\n## Host-OS status\n";
    let problems =
        operations_table_citation_problems("fixture-provider", missing_file, capsule.path());
    assert_eq!(
        problems.len(),
        1,
        "a missing file must be one problem: {problems:?}"
    );
    assert!(
        problems[0].contains("fixture-provider")
            && problems[0].contains("tests/absent.rs::present_case")
            && problems[0].contains("not readable"),
        "the reason must name the document, the citation and the missing file: {}",
        problems[0]
    );
    let absent_path = capsule.path().join("tests/absent.rs");
    let absent_error = fs::canonicalize(&absent_path).expect_err("fixture file is absent");
    assert_eq!(
        problems,
        vec![format!(
            "fixture-provider CONFINEMENT.md: tests/absent.rs::present_case names a file that is not readable because its path cannot be resolved: {} ({absent_error})",
            absent_path.display()
        )]
    );

    for file in ["tests", "tests/invalid-utf8.rs"] {
        let path = capsule.path().join(file);
        if file.ends_with(".rs") {
            fs::write(&path, [0xff]).expect("fixture invalid UTF-8 file");
        }
        let read_error = fs::read_to_string(&path).expect_err("fixture source is unreadable");
        let document = format!("{OPERATIONS_HEADING}\n\n`{file}::present_case`\n");
        assert_eq!(
            operations_table_citation_problems("fixture-provider", &document, capsule.path()),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {file}::present_case names a file that is not readable: {} ({read_error})",
                path.display()
            )]
        );
    }

    let missing_section = "## Tests\n\n- `tests/confine.rs::present_case` is cited\n";
    let problems =
        operations_table_citation_problems("fixture-provider", missing_section, capsule.path());
    assert_eq!(
        problems.len(),
        1,
        "a missing section must be one problem: {problems:?}"
    );
    assert!(
        problems[0].contains("fixture-provider")
            && problems[0].contains(OPERATIONS_HEADING)
            && problems[0].contains("found none"),
        "the reason must name the document and the missing heading: {}",
        problems[0]
    );
    assert_eq!(
        problems,
        vec!["fixture-provider CONFINEMENT.md must hold one line ## Operations and the rights they need; found none"]
    );

    let duplicate_section = format!("{present}\n{present}");
    assert_eq!(
        operations_table_citation_problems("fixture-provider", &duplicate_section, capsule.path()),
        vec!["fixture-provider CONFINEMENT.md must hold one line ## Operations and the rights they need; found 2"]
    );

    let no_citation = "## Operations and the rights they need\n\n| init |\n\n## Host-OS status\n";
    let problems =
        operations_table_citation_problems("fixture-provider", no_citation, capsule.path());
    assert_eq!(
        problems.len(),
        1,
        "a section without a citation must be one problem: {problems:?}"
    );
    assert!(
        problems[0].contains("fixture-provider") && problems[0].contains("cites no file::fn test"),
        "the reason must name the document and the missing citation: {}",
        problems[0]
    );
    assert_eq!(
        problems,
        vec!["fixture-provider CONFINEMENT.md: ## Operations and the rights they need cites no file::fn test"]
    );

    let absent_provider = capsule.path().join("absent-provider");
    let provider_error =
        fs::canonicalize(&absent_provider).expect_err("fixture provider is absent");
    assert_eq!(
        operations_table_citation_problems("fixture-provider", present, &absent_provider),
        vec![format!(
            "fixture-provider CONFINEMENT.md: provider directory {} cannot be resolved: {provider_error}",
            absent_provider.display()
        )]
    );
}

/// Citation evidence belongs to its named provider, including after resolving
/// a file link or a directory link. Absolute paths have their own refusal.
/// Every outside file holds the cited function, so accepting one loses the
/// containment refusal. A link to an inside file remains valid.
///
/// WP81 bypasses the absolute-path refusal and WP82 bypasses the resolved-path
/// containment refusal; this test catches each mutation. No process starts.
#[test]
fn operations_table_check_rejects_paths_outside_provider() {
    let capsules = tempfile::tempdir().expect("temporary capsules folder");
    let provider = capsules.path().join("fixture-provider");
    // The sibling shares the provider's string prefix but is a different path component.
    let sibling = capsules.path().join("fixture-provider-sibling");
    for dir in [&provider, &sibling] {
        fs::create_dir_all(dir.join("tests")).expect("fixture tests folder");
        fs::write(dir.join("tests/confine.rs"), "fn present_case() {}\n")
            .expect("fixture test source");
    }
    for file in [
        provider.join("tests/confine.rs"),
        sibling.join("tests/confine.rs"),
    ] {
        let span = format!("{}::present_case", file.display());
        let document = format!("{OPERATIONS_HEADING}\n\n`{span}`\n");
        assert_eq!(
            operations_table_citation_problems("fixture-provider", &document, &provider),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {span} names an absolute path; cited files must be relative to the provider directory"
            )]
        );
    }

    let mut outside = vec!["../fixture-provider-sibling/tests/confine.rs"];
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(
            sibling.join("tests/confine.rs"),
            provider.join("tests/outside.rs"),
        )
        .expect("fixture file link outside the provider");
        symlink(sibling.join("tests"), provider.join("linked-tests"))
            .expect("fixture directory link outside the provider");
        outside.extend(["tests/outside.rs", "linked-tests/confine.rs"]);
        symlink("confine.rs", provider.join("tests/inside.rs"))
            .expect("fixture file link inside the provider");
        let inside = format!("{OPERATIONS_HEADING}\n\n`tests/inside.rs::present_case`\n");
        assert!(
            operations_table_citation_problems("fixture-provider", &inside, &provider).is_empty(),
            "a relative citation that resolves inside the provider must pass"
        );
        // A provider directory reached through a link has the same canonical boundary.
        let provider_alias = capsules.path().join("provider-alias");
        symlink(&provider, &provider_alias).expect("fixture provider directory link");
        assert!(
            operations_table_citation_problems("fixture-provider", &inside, &provider_alias)
                .is_empty(),
            "the provider directory and citation must use the same resolved boundary"
        );
    }
    let root = fs::canonicalize(&provider).expect("fixture provider resolves");
    let escaped = fs::canonicalize(sibling.join("tests/confine.rs"))
        .expect("fixture outside source resolves");
    for file in outside {
        let span = format!("{file}::present_case");
        let document = format!("{OPERATIONS_HEADING}\n\n`{span}`\n");
        assert_eq!(
            operations_table_citation_problems("fixture-provider", &document, &provider),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {span} resolves outside the provider directory: {} (provider directory {})",
                escaped.display(),
                root.display()
            )]
        );
    }
}

/// The operations-table fixtures' provider source: `enum Request` declares the
/// arms the fixture table names, `fn handle` answers `init`, `status`, `echo`,
/// `wallet_contract` and `shutdown`, and `fn dispatch_wallet_operation` answers
/// the one `list_accounts` kind.
///
/// `init` carries a field whose wire name is `wire_name` by
/// `#[serde(rename = "...")]`, under a `//` comment that names an older
/// `stale_name`, so only the active attribute may name the field. `echo`
/// declares two plain fields. `Ping` declares one field and no dispatch arm
/// answers it, so the fixture table names no field of it. `Status` and
/// `Shutdown` declare no field.
const ROW_FIXTURE_PROVIDER: &str = "\
enum Request {
    Init {
        config: Value,
        // Previously rename = \"stale_name\".
        #[serde(rename = \"wire_name\")]
        field_name: Option<Value>,
    },
    Status,
    Echo {
        message: String,
        retry: u64,
    },
    WalletContract {
        request: Value,
        #[serde(rename = \"_runtime_invocation\")]
        runtime_invocation: Box<RuntimeInvocationEnvelope>,
    },
    Ping {
        reason: String,
    },
    Shutdown,
}

fn handle(&mut self, request: Request) -> Response {
    match request {
        Request::Init { config } => self.init(config),
        Request::Status => self.status(),
        Request::Echo { message, retry } => self.echo(message, retry),
        Request::WalletContract { request } => self.handle_wallet_contract(request),
        Request::Shutdown => Response::empty_ok(),
    }
}

fn dispatch_wallet_operation(&mut self, request: &WalletProviderRequestV2) -> Response {
    match &request.operation {
        WalletProviderOperationV2::ListAccounts { include_revoked } => self.accounts(*include_revoked),
    }
}
";

/// The Inputs cell of one fixture operation's row: the backticked `op` and then
/// the wire names the fixture `Request` arm declares, in declaration order. The
/// `wallet_contract list_accounts` cell names the real `ListAccounts` params,
/// because the fixture dispatch does not declare that enum.
fn fixture_inputs(operation: &str) -> String {
    match operation {
        "init" => "`op`, `config`, `wire_name`".to_string(),
        "echo" => "`op`, `message`, `retry`".to_string(),
        "wallet_contract list_accounts" => "`op`, `request` (`kind: list_accounts`, `params` \
                                            (`include_revoked`)), `_runtime_invocation`"
            .to_string(),
        "wallet_contract get_d_i_d" => "`op`, `request` (`kind: get_d_i_d`, `params` (none)), \
                                       `_runtime_invocation`"
            .to_string(),
        _ => "`op`".to_string(),
    }
}

/// One fixture operations row. The Outputs and Effect cells are unread by the
/// row check, so every row carries the same filler there.
fn fixture_row(operation: &str, inputs: &str, right: &str, macos: &str, linux: &str) -> String {
    format!(
        "| {operation} | {inputs} | ok: `status` | {right} | answers in memory | {macos} | {linux} |\n"
    )
}

/// One fixture operations row whose rows are in the fixture dispatch order and
/// whose Inputs, Right, macOS and Linux cells follow all five rules.
fn passing_fixture_row(operation: &str) -> String {
    if operation == "init" {
        fixture_row(
            operation,
            &fixture_inputs(operation),
            "`storage`",
            "permitted: `tests/confine.rs::present_case` shows the write. \
             nearest outside refused: `tests/confine.rs::present_case` shows the refusal.",
            LINUX_STATUS,
        )
    } else {
        fixture_row(
            operation,
            &fixture_inputs(operation),
            NO_DECLARED_RIGHT,
            "`tests/confine.rs::present_case` shows the answer.",
            LINUX_STATUS,
        )
    }
}

/// The operations table that passes the row check: a header, a separator and one
/// row for each operation of `operations`, in the order given.
fn fixture_row_document(operations: &[&str]) -> String {
    let mut document = format!(
        "{OPERATIONS_HEADING}\n\n| Operation | Inputs | Outputs | Right | Effect | macOS rule and \
         test | Linux |\n| --- | --- | --- | --- | --- | --- | --- |\n"
    );
    for operation in operations {
        document.push_str(&passing_fixture_row(operation));
    }
    document
}

/// The five operations the fixture dispatch answers, in table order: the
/// ordinary arms of `fn handle` in dispatch order, then the one contract kind.
const FIXTURE_OPERATIONS: [&str; 5] = [
    "init",
    "status",
    "echo",
    "shutdown",
    "wallet_contract list_accounts",
];

/// The row check refuses each bad table, one case per rule and sub-rule, and
/// names the rule.
///
/// A temporary provider folder holds `src/main.rs` with the fixture dispatch
/// and its `enum Request`: `fn handle` answers `init`, `status`, `echo`,
/// `wallet_contract` and `shutdown`, and `fn dispatch_wallet_operation` answers
/// `list_accounts`. The passing table returns no problem. Rule 1 refuses a
/// `handle` arm with no row, a row with no
/// arm, a kind arm with no row, ordinary rows in another order and a kind row
/// before an ordinary row. A two-kind fixture also refuses swapped kind rows,
/// duplicate ordinary and kind rows, and equal-length rows with the wrong
/// multiplicity. An acronym fixture requires serde's wire name. The table's
/// complete header and separator are checked before reading positional cells.
/// An appended row that repeats the header words, sits under leading whitespace
/// or omits either outer bar reaches every rule. Short rows, including a row
/// with no bars, are refused. Changed or swapped header labels are refused, and a
/// section with no table line, a first line that is not the header, a header
/// with no separator, a second line that would be a row and a separator with
/// another cell count are each refused as one problem. Rule 2 refuses a Right
/// cell that names an undeclared
/// id and one that says `no named test shows this`. Rule 3 refuses a right row
/// missing `permitted:`, a right row missing `nearest outside refused:` and a
/// `none:` row citing `permitted:`. Rule 4 refuses a Linux cell that is not
/// `designed, not enforced`, naming every row. Rule 5 refuses an ordinary row's
/// Inputs cell with an extra name, a missing name, another order, a renamed
/// field's Rust name, a name only a comment mentions, a bare word where the
/// table writes backticked names, no backticked `op`, an unterminated backtick
/// span, an empty item, a parenthesis and a longer name that starts with a
/// declared one. A two-field arm and a fieldless arm each pin their own expected
/// cell. An arm spelled inside an attribute string cannot hide a declared field.
/// Character and byte-character literals retain the field after their type;
/// raw identifiers use their wire spelling, and explicit renames keep their
/// literal value. Unsupported field attributes and literals keep exact reasons.
/// A `wallet_contract` row's Inputs cell is read against that kind's `params`.
/// A fixture enum keeps the bare word `none` apart from a field named `none`,
/// and a `params` list that drops, reorders or adds a name is refused.
/// A source with no
/// `enum Request`, an arm the declaration omits, a declaration file the caller
/// cannot read and a source with no `fn handle` each keep their own reason. The
/// four `snake_case` names the
/// contract already uses pin the helper. A missing or doubled heading stays with
/// `section_under_one_heading`, which already refuses it once. The fixtures are
/// a temporary directory; no process starts.
///
/// Falsifiers: WP141 disables the row-set rule, WP142 the Right-vocabulary
/// rule, WP143 the both-sides rule, WP144 the Linux-status rule, WP181 the one
/// field reader's `serde` attribute and WP182 the Inputs compare's length rule;
/// this test fails on that rule's cases, because the bad table is then accepted.
/// WP181 also fails the passing table, because `init`'s renamed field then reads
/// as its Rust name.
/// WP183 through WP197 cover literal boundaries, raw identifiers, quoting,
/// order, malformed cells and missing source or arm refusals. WP198 removes
/// the field-list reader's balance refusal, so a shift expression hides the
/// field after it. WP214 makes an empty arm and a field named `none` the same
/// item, so the bare marker passes for the renamed field. WP215 makes
/// `inputs_match` ignore children, so a `params` list can name an undeclared
/// field.
#[test]
fn operations_table_row_check_refuses_each_bad_table() {
    let provider = tempfile::tempdir().expect("temporary provider folder");
    fs::create_dir_all(provider.path().join("src")).expect("fixture src folder");
    let provider_source = provider.path().join("src/main.rs");
    fs::write(&provider_source, ROW_FIXTURE_PROVIDER).expect("fixture provider source");

    for (case, variant) in [
        ("VerifyDidRecovery", "verify_did_recovery"),
        ("VerifyBip322Proof", "verify_bip322_proof"),
        ("ImportManagedRecoverySet", "import_managed_recovery_set"),
        ("GetPersonaDid", "get_persona_did"),
        ("GetDID", "get_d_i_d"),
        ("DID", "d_i_d"),
        ("VerifyBIP322Proof", "verify_b_i_p322_proof"),
    ] {
        assert_eq!(
            variant_snake_case(case),
            variant,
            "{case} must reach its wire name"
        );
    }

    let passing = fixture_row_document(&FIXTURE_OPERATIONS);
    assert_eq!(
        operations_table_row_problems("fixture-provider", &passing, provider.path()),
        Vec::<String>::new(),
        "a table that follows all four rules must pass"
    );

    // Rule 1: an arm with no row, and a kind arm with no row.
    for (case, arm, anchor, arm_name) in [
        (
            "an arm with no row",
            "        Request::Ping => self.ping(),\n",
            "        Request::Shutdown",
            "ping",
        ),
        (
            "a kind arm with no row",
            "        WalletProviderOperationV2::DefaultAccount {} => self.default_account(),\n",
            "        WalletProviderOperationV2::ListAccounts",
            "wallet_contract default_account",
        ),
    ] {
        let source = ROW_FIXTURE_PROVIDER.replace(anchor, &format!("{arm}{anchor}"));
        assert_ne!(
            source, ROW_FIXTURE_PROVIDER,
            "{case} must change the source"
        );
        fs::write(&provider_source, &source).expect("fixture provider source rewrite");
        let problems = operations_table_row_problems("fixture-provider", &passing, provider.path());
        assert_eq!(
            problems.len(),
            1,
            "{case} must be one problem: {problems:?}"
        );
        assert!(
            problems[0].contains("row set")
                && problems[0].contains("has no row")
                && problems[0].contains(arm_name),
            "{case} must name the rule and the arm as {arm_name}: {}",
            problems[0]
        );
    }
    fs::write(&provider_source, ROW_FIXTURE_PROVIDER).expect("fixture provider source restore");

    // Rule 1: a row with no arm.
    let mut extra = fixture_row_document(&FIXTURE_OPERATIONS);
    extra.push_str(&passing_fixture_row("ping"));
    assert_eq!(
        operations_table_row_problems("fixture-provider", &extra, provider.path()),
        vec![format!(
            "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row ping has no \
             arm in {}",
            provider_source.display()
        )],
        "a row with no arm must be refused"
    );

    // A row that repeats the header words or sits under leading whitespace is
    // still a body row, so no appended row hides from the four rules.
    let clean = fixture_row_document(&FIXTURE_OPERATIONS);
    for (case, row, row_name) in [
        (
            "a row that repeats the header words",
            "| Operation | op | ok | `undeclared` | effect | permitted: | enforced |\n",
            "Operation",
        ),
        (
            "an indented row",
            "   | ping | op | ok | `undeclared` | effect | permitted: | enforced |\n",
            "ping",
        ),
    ] {
        let document = format!("{clean}{row}");
        assert_eq!(
            operations_table_row_problems("fixture-provider", &document, provider.path()),
            vec![
                format!(
                    "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row \
                     {row_name} has no arm in {}",
                    provider_source.display()
                ),
                format!(
                    "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row {row_name} holds \
                     the Right cell `undeclared`, which is neither {NO_DECLARED_RIGHT} nor one \
                     declared contract id"
                ),
                format!(
                    "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row {row_name} names \
                     the Linux cell enforced, and every Linux cell is {LINUX_STATUS}"
                ),
            ],
            "{case} must reach rules 1, 2 and 4"
        );
    }

    // Markdown permits either outer bar to be omitted. Each form must expose
    // the same extra operation, undeclared Right and invalid Linux claim.
    for row in [
        "phantom | op | ok | undeclared | effect | permitted: | enforced |\n",
        "| phantom | op | ok | undeclared | effect | permitted: | enforced\n",
        "phantom | op | ok | undeclared | effect | permitted: | enforced\n",
    ] {
        let document = format!("{clean}{row}");
        assert_eq!(
            operations_table_row_problems("fixture-provider", &document, provider.path()),
            vec![
                format!(
                    "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row \
                     phantom has no arm in {}",
                    provider_source.display()
                ),
                format!(
                    "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row phantom holds \
                     the Right cell undeclared, which is neither {NO_DECLARED_RIGHT} nor one \
                     declared contract id"
                ),
                format!(
                    "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row phantom names \
                     the Linux cell enforced, and every Linux cell is {LINUX_STATUS}"
                ),
            ],
            "a row with optional outer bars must reach rules 1, 2 and 4: {row}"
        );
    }
    assert_eq!(
        operations_table_row_problems(
            "fixture-provider",
            &format!("{clean}phantom\n"),
            provider.path()
        ),
        vec![format!(
            "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row phantom holds 1 cells, \
             and every row holds {TABLE_CELLS}"
        )],
        "a short row with no bars must be refused instead of skipped"
    );

    // Valid headers, separators and rows also accept either optional outer bar.
    for (omit_leading, omit_trailing) in [(true, false), (false, true), (true, true)] {
        let document = clean
            .lines()
            .map(|line| {
                let line = if omit_leading {
                    line.strip_prefix('|').unwrap_or(line)
                } else {
                    line
                };
                if omit_trailing {
                    line.strip_suffix('|').unwrap_or(line)
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            operations_table_row_problems("fixture-provider", &document, provider.path()),
            Vec::<String>::new(),
            "optional outer bars must preserve a valid table"
        );
    }

    // The table's shape is read by position, so a section that hides its rows
    // or its header is refused instead of read as an empty table.
    for (case, document, reason) in [
        (
            "a section with no table",
            format!("{OPERATIONS_HEADING}\n\nno table here\n"),
            format!("{OPERATIONS_HEADING} holds no table line"),
        ),
        (
            "a first line that is not the header",
            format!("{OPERATIONS_HEADING}\n\n{}", passing_fixture_row("init")),
            format!(
                "{OPERATIONS_HEADING} table line 1 is not the header {OPERATION_HEADER} over \
                 {TABLE_CELLS} cells: {}",
                passing_fixture_row("init").trim()
            ),
        ),
        (
            "a header with no separator",
            format!(
                "{OPERATIONS_HEADING}\n\n| Operation | Inputs | Outputs | Right | Effect | macOS \
                 rule and test | Linux |\n"
            ),
            format!(
                "{OPERATIONS_HEADING} table line 1 is the header and the table holds no \
                 separator line"
            ),
        ),
        (
            "swapped Right and Linux header labels",
            clean.replacen(
                "| Right | Effect | macOS rule and test | Linux |",
                "| Linux | Effect | macOS rule and test | Right |",
                1,
            ),
            format!(
                "{OPERATIONS_HEADING} table line 1 is not the header {OPERATION_HEADER} over \
                 {TABLE_CELLS} cells: | Operation | Inputs | Outputs | Linux | Effect | macOS \
                 rule and test | Right |"
            ),
        ),
        (
            "a second line that would be a row",
            fixture_row_document(&FIXTURE_OPERATIONS).replacen(
                "| --- | --- | --- | --- | --- | --- | --- |\n",
                &passing_fixture_row("init"),
                1,
            ),
            format!(
                "{OPERATIONS_HEADING} table line 2 is not the separator of {TABLE_CELLS} dash \
                 cells: {}",
                passing_fixture_row("init").trim()
            ),
        ),
        (
            "a separator with another cell count",
            fixture_row_document(&FIXTURE_OPERATIONS).replacen(
                "| --- | --- | --- | --- | --- | --- | --- |\n",
                "| --- | --- |\n",
                1,
            ),
            format!(
                "{OPERATIONS_HEADING} table line 2 is not the separator of {TABLE_CELLS} dash \
                 cells: | --- | --- |"
            ),
        ),
    ] {
        assert_eq!(
            operations_table_row_problems("fixture-provider", &document, provider.path()),
            vec![format!("fixture-provider CONFINEMENT.md: {reason}")],
            "{case} must be refused as one problem"
        );
    }

    // Every label owns its column's meaning, including the unchecked body cells.
    for label in [
        "Operation",
        "Inputs",
        "Outputs",
        "Right",
        "Effect",
        "macOS rule and test",
        "Linux",
    ] {
        let document = clean.replacen(&format!("| {label} |"), "| changed |", 1);
        assert_ne!(document, clean, "the {label} header must change");
        let header = document.lines().nth(2).expect("fixture header line");
        assert_eq!(
            operations_table_row_problems("fixture-provider", &document, provider.path()),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} table line 1 is not the \
                 header {OPERATION_HEADER} over {TABLE_CELLS} cells: {header}"
            )],
            "the complete header must be checked before reading the {label} column"
        );
    }

    let short_row = format!("{clean}| init | op | ok |\n");
    assert_eq!(
        operations_table_row_problems("fixture-provider", &short_row, provider.path()),
        vec![format!(
            "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row init holds 3 cells, and \
             every row holds {TABLE_CELLS}"
        )],
        "a row with another cell count must be refused"
    );

    // Rule 1: rows in another order, and a kind row before an ordinary row.
    assert_eq!(
        operations_table_row_problems(
            "fixture-provider",
            &fixture_row_document(&[
                "status",
                "init",
                "echo",
                "shutdown",
                "wallet_contract list_accounts",
            ]),
            provider.path()
        ),
        vec![format!(
            "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row status comes \
             where {} answers init, and the table keeps the dispatch order",
            provider_source.display()
        )],
        "ordinary rows out of dispatch order must be refused"
    );
    assert_eq!(
        operations_table_row_problems(
            "fixture-provider",
            &fixture_row_document(&[
                "wallet_contract list_accounts",
                "init",
                "status",
                "echo",
                "shutdown",
            ]),
            provider.path()
        ),
        vec![format!(
            "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row shutdown comes \
             after the wallet_contract rows, and the contract rows follow the ordinary arms of {}",
            provider_source.display()
        )],
        "a kind row before an ordinary row must be refused"
    );

    // Rule 1: both contract kinds retain their dispatch order and multiplicity.
    let two_kind_source = ROW_FIXTURE_PROVIDER.replace(
        "        WalletProviderOperationV2::ListAccounts",
        "        WalletProviderOperationV2::GetDID {} => self.get_did(),\n\
                WalletProviderOperationV2::ListAccounts",
    ) + "
enum WalletProviderOperationV2 {
    GetDID {},
    ListAccounts {
        include_revoked: bool,
    },
}
";
    assert_ne!(two_kind_source, ROW_FIXTURE_PROVIDER);
    fs::write(&provider_source, &two_kind_source).expect("two-kind fixture provider source");
    let two_kind_operations = [
        "init",
        "status",
        "echo",
        "shutdown",
        "wallet_contract get_d_i_d",
        "wallet_contract list_accounts",
    ];
    assert_eq!(
        operations_table_row_problems(
            "fixture-provider",
            &fixture_row_document(&two_kind_operations),
            provider.path()
        ),
        Vec::<String>::new(),
        "two kinds in dispatch order, including serde's acronym name, must pass"
    );

    let mut swapped_kinds = two_kind_operations;
    swapped_kinds.swap(4, 5);
    assert_eq!(
        operations_table_row_problems(
            "fixture-provider",
            &fixture_row_document(&swapped_kinds),
            provider.path()
        ),
        vec![format!(
            "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row \
             wallet_contract list_accounts comes where {} answers wallet_contract get_d_i_d, \
             and the table keeps the dispatch order",
            provider_source.display()
        )],
        "contract kinds out of dispatch order must be refused"
    );

    for (case, index) in [("the final kind row", 5), ("shutdown before the kinds", 3)] {
        let mut duplicate = two_kind_operations.to_vec();
        duplicate.insert(index + 1, duplicate[index]);
        assert_eq!(
            operations_table_row_problems(
                "fixture-provider",
                &fixture_row_document(&duplicate),
                provider.path()
            ),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row {} has \
                 more copies than matching arms in {}",
                duplicate[index],
                provider_source.display()
            )],
            "a duplicate of {case} must be refused"
        );
    }

    let mut replaced_kind = two_kind_operations;
    replaced_kind[4] = replaced_kind[5];
    assert_eq!(
        operations_table_row_problems(
            "fixture-provider",
            &fixture_row_document(&replaced_kind),
            provider.path()
        ),
        vec![
            format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set: the arm \
                 wallet_contract get_d_i_d of {} has no row",
                provider_source.display()
            ),
            format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row \
                 wallet_contract list_accounts has more copies than matching arms in {}",
                provider_source.display()
            ),
        ],
        "equal lengths with different multiplicities must be refused"
    );

    let mut wrong_acronym = two_kind_operations;
    wrong_acronym[4] = "wallet_contract get_did";
    assert_eq!(
        operations_table_row_problems(
            "fixture-provider",
            &fixture_row_document(&wrong_acronym),
            provider.path()
        ),
        vec![
            format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set: the arm \
                 wallet_contract get_d_i_d of {} has no row",
                provider_source.display()
            ),
            format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set: the row \
                 wallet_contract get_did has no arm in {}",
                provider_source.display()
            ),
        ],
        "an acronym row must name the operation as serde does"
    );
    fs::write(&provider_source, ROW_FIXTURE_PROVIDER).expect("fixture provider source restore");

    // Rule 2: a Right cell with an undeclared id, and one naming no test.
    for (case, right) in [
        ("an undeclared id", "`bound-net`"),
        ("no named test shows this", "no named test shows this"),
    ] {
        let document = passing.replacen("| `storage` |", &format!("| {right} |"), 1);
        assert_ne!(document, passing, "the fixture must hold the storage row");
        let problems =
            operations_table_row_problems("fixture-provider", &document, provider.path());
        assert_eq!(
            problems,
            vec![format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row init holds the Right \
                 cell {right}, which is neither {NO_DECLARED_RIGHT} nor one declared contract id"
            )],
            "a Right cell of {case} must be refused, and rule 3 must stay quiet"
        );
    }

    // Rule 3: one side missing from a right row, and a side on a none: row.
    for (case, document, reason) in [
        (
            "a right row missing permitted:",
            passing.replacen("permitted: ", "", 1),
            format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row init names the Right \
                 `storage` and does not cite {PERMITTED_SIDE}"
            ),
        ),
        (
            "a right row missing its outside side",
            passing.replacen("nearest outside refused: ", "", 1),
            format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row init names the Right \
                 `storage` and does not cite {OUTSIDE_SIDE}"
            ),
        ),
        (
            "a none: row citing a side",
            passing.replacen(
                "| `tests/confine.rs::present_case` shows the answer. |",
                "| permitted: `tests/confine.rs::present_case` shows the answer. |",
                1,
            ),
            format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row status is \
                 {NO_DECLARED_RIGHT} and cites {PERMITTED_SIDE}"
            ),
        ),
    ] {
        assert_ne!(document, passing, "{case} must change the fixture");
        assert_eq!(
            operations_table_row_problems("fixture-provider", &document, provider.path()),
            vec![reason],
            "{case} must be refused as one problem"
        );
    }

    // Rule 5: an ordinary row's Inputs cell against its `Request` arm. One
    // case per refusal: another name, a missing name, another order, a renamed
    // field's Rust name, a name the comment above the active attribute
    // mentions, a bare word where the table writes backticked names, a first
    // item that is not the backticked `op`, a cell the reader cannot parse and
    // a name that starts with an arm's name.
    let provider_paths = provider.path().join("src/main.rs").display().to_string();
    for (case, cell) in [
        ("an extra name", "`op`, `config`, `phantom`, `wire_name`"),
        ("a missing name", "`op`, `config`"),
        ("another order", "`op`, `wire_name`, `config`"),
        (
            "a renamed field's Rust name",
            "`op`, `config`, `field_name`",
        ),
        ("a name a comment names", "`op`, `config`, `stale_name`"),
        ("a bare word", "`op`, `config`, wire_name"),
        ("no backticked op", "op, `config`, `wire_name`"),
        ("no op", "`config`, `wire_name`"),
        (
            "an unterminated backtick span",
            "`op`, `config`, `wire_name",
        ),
        ("an empty item", "`op`, , `config`, `wire_name`"),
        ("a parenthesis", "`op`, `config` (`wire_name`)"),
        ("an opening parenthesis", "`op`, `config`, `wire(name`"),
        ("a closing parenthesis", "`op`, `config`, `wire)name`"),
        ("an empty cell", ""),
        ("an empty quoted item", "`op`, `config`, ``"),
        ("a leading empty item", ", `op`, `config`, `wire_name`"),
        ("a trailing empty item", "`op`, `config`, `wire_name`,"),
        ("an embedded backtick", "`op`, `config`, `wire`name`"),
        ("a longer name", "`op`, `config`, `wire_name_extra`"),
    ] {
        let document = passing.replacen(&fixture_inputs("init"), cell, 1);
        assert_ne!(document, passing, "{case} must change the Inputs cell");
        assert_eq!(
            operations_table_row_problems("fixture-provider", &document, provider.path()),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row init holds the Inputs \
                 cell {cell}, and {provider_paths} names `op`, `config`, `wire_name`"
            )],
            "an Inputs cell with {case} must be refused"
        );
    }

    // Pin the cell reader's syntax refusals independently of the field-name
    // comparison: malformed punctuation may also change the observed name.
    for cell in [
        "`op`, `wire(name`",
        "`op`, `wire)name`",
        "",
        "`op`, ``",
        ", `op`",
        "`op`, , `config`",
        "`op`,",
        "`op`, `config",
        "`op`, `con`fig`",
        "`op`, config`",
    ] {
        assert_eq!(input_items(cell), None, "malformed Inputs cell: {cell}");
    }

    // Character punctuation stays inside its literal in every declaration
    // scan. Each stale cell must name the field it omitted in the refusal.
    let init_start = ROW_FIXTURE_PROVIDER.find("    Init {").unwrap();
    let init_end = ROW_FIXTURE_PROVIDER.find("    Status,").unwrap();
    for field_type in [
        "[u8; ('}' as usize - '{' as usize)]",
        "[u8; (b'}' as usize - b'{' as usize)]",
        "[u8; (']' as usize + ',' as usize)]",
        r#"[u8; ('"' as usize + '\\' as usize + '\'' as usize)]"#,
        r#"[u8; ('\u{7d}' as usize - '\x7b' as usize)]"#,
        "&'static [u8; ('é' as usize + '>' as usize + '<' as usize)]",
    ] {
        let mut source = ROW_FIXTURE_PROVIDER.to_string();
        source.replace_range(
            init_start..init_end,
            &format!(
                "    Init {{\n        config: {field_type},\n        required: String,\n    }},\n"
            ),
        );
        fs::write(&provider_source, source).expect("character literal fixture");
        let stale = "`op`, `config`";
        let expected = "`op`, `config`, `required`";
        assert_eq!(
            operations_table_row_problems(
                "fixture-provider",
                &passing.replacen(&fixture_inputs("init"), stale, 1),
                provider.path()
            ),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row init holds the Inputs \
                 cell {stale}, and {provider_paths} names {expected}"
            )],
            "character literals in {field_type} must preserve the required field"
        );
        assert_eq!(
            operations_table_row_problems(
                "fixture-provider",
                &passing.replacen(&fixture_inputs("init"), expected, 1),
                provider.path()
            ),
            Vec::<String>::new(),
            "the complete field list must pass for {field_type}"
        );
    }

    // A field list whose delimiters do not balance is refused with its own
    // reason, never read as a shorter list. The `<<` of a shift expression
    // opens a delimiter that never closes, so every later field would join the
    // item before it and a cell that omits one would pass.
    for field_type in [
        "[u8; 1 << 2]",
        "[u8; 1 << 2 << 3]",
        "[u8; (1 << 2) as usize]",
        "Vec<[u8; 1 << 2]>",
    ] {
        let mut source = ROW_FIXTURE_PROVIDER.to_string();
        source.replace_range(
            init_start..init_end,
            &format!(
                "    Init {{\n        config: {field_type},\n        required: String,\n    }},\n"
            ),
        );
        fs::write(&provider_source, source).expect("unbalanced field list fixture");
        for cell in ["`op`, `config`", "`op`, `config`, `required`"] {
            assert_eq!(
                operations_table_row_problems(
                    "fixture-provider",
                    &passing.replacen(&fixture_inputs("init"), cell, 1),
                    provider.path()
                ),
                vec![format!(
                    "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row init holds the \
                     Inputs cell {cell}, and the Init arm of {provider_paths} cannot be read: \
                     {UNBALANCED_FIELD_LIST}"
                )],
                "an unbalanced field list in {field_type} must be refused, not read"
            );
        }
    }

    // An arrow's `>` needs no opener of its own, so it does not unbalance a
    // field list and the fields after it stay their own items.
    for field_type in ["Box<dyn Fn() -> u8>", "[u8; 3 >> 1]", "[u8; 1 > 0]"] {
        let mut source = ROW_FIXTURE_PROVIDER.to_string();
        source.replace_range(
            init_start..init_end,
            &format!(
                "    Init {{\n        config: {field_type},\n        required: String,\n    }},\n"
            ),
        );
        fs::write(&provider_source, source).expect("balanced field list fixture");
        let expected = "`op`, `config`, `required`";
        assert_eq!(
            operations_table_row_problems(
                "fixture-provider",
                &passing.replacen(&fixture_inputs("init"), expected, 1),
                provider.path()
            ),
            Vec::<String>::new(),
            "the complete field list must pass for {field_type}"
        );
        let stale = "`op`, `config`";
        assert_eq!(
            operations_table_row_problems(
                "fixture-provider",
                &passing.replacen(&fixture_inputs("init"), stale, 1),
                provider.path()
            ),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row init holds the Inputs \
                 cell {stale}, and {provider_paths} names {expected}"
            )],
            "the field after {field_type} must still be required"
        );
    }
    fs::write(&provider_source, ROW_FIXTURE_PROVIDER).expect("fixture provider source restore");

    // Serde removes r# from an identifier, while an explicit rename supplies
    // its literal wire name even when that name itself starts with r#.
    for (field, expected, stale) in [
        ("r#type: String", "`op`, `type`", "`op`, `r#type`"),
        (
            "#[serde(rename = \"r#type\")] r#type: String",
            "`op`, `r#type`",
            "`op`, `type`",
        ),
    ] {
        let mut source = ROW_FIXTURE_PROVIDER.to_string();
        source.replace_range(
            init_start..init_end,
            &format!("    Init {{\n        {field},\n    }},\n"),
        );
        fs::write(&provider_source, source).expect("raw identifier fixture");
        assert_eq!(
            operations_table_row_problems(
                "fixture-provider",
                &passing.replacen(&fixture_inputs("init"), expected, 1),
                provider.path()
            ),
            Vec::<String>::new(),
            "the raw identifier's wire name must pass"
        );
        assert_eq!(
            operations_table_row_problems(
                "fixture-provider",
                &passing.replacen(&fixture_inputs("init"), stale, 1),
                provider.path()
            ),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row init holds the Inputs \
                 cell {stale}, and {provider_paths} names {expected}"
            )],
            "the incorrect raw identifier spelling must be refused"
        );
    }
    fs::write(&provider_source, ROW_FIXTURE_PROVIDER).expect("fixture provider source restore");

    // Unsupported field syntax retains the reader's exact refusal. These
    // cases exercise each explicit field-attribute and literal refusal.
    let panic_message = |failure: Box<dyn std::any::Any + Send>| {
        failure
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| failure.downcast_ref::<&str>().map(|text| text.to_string()))
            .expect("the reader refusal must carry a string")
    };
    for (field, reason) in [
        (
            "#serde field: String",
            "expected a bracketed field attribute",
        ),
        (
            "#[serde(rename = \"wire\") field: String",
            "unterminated field attribute",
        ),
        (
            "#[serde(rename = \"wire\"] field: String",
            "unterminated serde attribute",
        ),
        (
            "#[serde(rename(deserialize = \"wire\"))] field: String",
            "unsupported serde rename syntax; expected rename = <Rust string literal>",
        ),
        (
            "#[serde(rename = \"wire\" extra)] field: String",
            "unsupported tokens after serde rename string",
        ),
        (
            "#[serde(rename = \"wire\", rename = \"other\")] field: String",
            "duplicate serde rename",
        ),
        (
            "#[serde(rename = \"wire\", other = 1 << 2)] field: String",
            "serde attribute: unbalanced parentheses, brackets, braces or angle brackets in the \
             field list",
        ),
    ] {
        let refusal = std::panic::catch_unwind(|| field_wire_name(field))
            .expect_err("unsupported field syntax must be refused");
        assert_eq!(
            panic_message(refusal),
            format!("wire field reader: {reason}")
        );
    }
    for (literal, reason) in [
        ("name", "expected a Rust string literal"),
        ("r#name", "expected a Rust string literal"),
        ("r#\"name", "unterminated raw Rust string"),
        ("\"name", "unterminated Rust string literal"),
        ("\"name\\", "unterminated Rust string escape"),
        (r#""\xg0""#, "invalid Rust ASCII escape"),
        (r#""\x80""#, "Rust ASCII escape exceeds 0x7f"),
        (r#""\u0""#, "invalid Rust Unicode escape"),
        ("\"\\u{1", "unterminated Rust Unicode escape"),
        (r#""\u{}""#, "invalid Rust Unicode escape"),
        (r#""\u{d800}""#, "invalid Rust Unicode scalar"),
        ("\"\\\rx\"", "invalid Rust line continuation"),
        (r#""\q""#, "unsupported Rust string escape"),
    ] {
        assert_eq!(rust_string_literal(literal), Err(reason));
        let field = format!("#[serde(rename = {literal})] field: String");
        // An unclosed literal also keeps its own reason through the direct
        // rename reader when its attribute delimiter is reachable.
        if !reason.starts_with("unterminated") {
            let refusal = std::panic::catch_unwind(|| field_wire_name(&field))
                .expect_err("unsupported rename literal must be refused");
            assert_eq!(
                panic_message(refusal),
                format!("wire field reader: serde rename: {reason}")
            );
        }
    }
    let refusal = std::panic::catch_unwind(|| without_comments("'\\"))
        .expect_err("an unclosed character escape must be refused");
    assert_eq!(
        panic_message(refusal),
        "wire field reader: unterminated Rust character escape"
    );

    // Rule 5: the fixture table's other ordinary rows name their own fields, so
    // a two-field arm and a fieldless arm each keep their own expected cell.
    for (operation, cell) in [
        ("echo", "`op`, `retry`, `message`"),
        ("shutdown", "`op`, `reason`"),
    ] {
        let row = passing_fixture_row(operation);
        let changed = fixture_row(
            operation,
            cell,
            NO_DECLARED_RIGHT,
            "`tests/confine.rs::present_case` shows the answer.",
            LINUX_STATUS,
        );
        let document = passing.replacen(&row, &changed, 1);
        assert_ne!(document, passing, "{operation} must change the Inputs cell");
        assert_eq!(
            operations_table_row_problems("fixture-provider", &document, provider.path()),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row {operation} holds the \
                 Inputs cell {cell}, and {provider_paths} names {}",
                fixture_inputs(operation)
            )],
            "{operation} must name its arm's fields in declaration order"
        );
    }

    // Rule 5: an attribute string that holds a copy of the arm without one of
    // its fields is text, so a cell that follows the copy is still refused.
    let documented = ROW_FIXTURE_PROVIDER.replacen(
        "    Init {\n        config: Value,\n",
        "    #[doc = \"\n    Init { config: Value },\n    \"]\n    Init {\n        config: Value,\n",
        1,
    );
    assert_ne!(documented, ROW_FIXTURE_PROVIDER);
    fs::write(&provider_source, &documented).expect("documented arm fixture");
    let stale = "`op`, `config`";
    assert_eq!(
        operations_table_row_problems(
            "fixture-provider",
            &passing.replacen(&fixture_inputs("init"), stale, 1),
            provider.path()
        ),
        vec![format!(
            "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row init holds the Inputs cell \
             {stale}, and {provider_paths} names `op`, `config`, `wire_name`"
        )],
        "an arm spelled inside an attribute string must not hide a declared field"
    );
    assert_eq!(
        operations_table_row_problems("fixture-provider", &passing, provider.path()),
        Vec::<String>::new(),
        "the real arm's fields must be the ones the passing table names"
    );
    fs::write(&provider_source, ROW_FIXTURE_PROVIDER).expect("fixture provider source restore");

    // Rule 5: a `wallet_contract` row is read. The fixture dispatch does not
    // declare the operation enum, so this cell is checked against the contract
    // file. A cell that is not that shape is one problem naming the source.
    let contract_path = wallet_operation_contract_path();
    let contract_label = inputs_source_label(provider_source.as_path(), &contract_path);
    let listed = fixture_inputs("wallet_contract list_accounts");
    let garbage = passing.replacen(
        &format!("| wallet_contract list_accounts | {listed} |"),
        "| wallet_contract list_accounts | garbage |",
        1,
    );
    assert_ne!(garbage, passing, "the contract row's cell must change");
    assert_eq!(
        operations_table_row_problems("fixture-provider", &garbage, provider.path()),
        vec![format!(
            "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row wallet_contract \
             list_accounts holds the Inputs cell garbage, and {contract_label} names {listed}"
        )],
        "a wallet_contract row's Inputs cell must be read"
    );

    // The bare word `none` and a field named `none` stay apart. The empty arm
    // passes on `params` (none) and is refused on `params` (`none`). The
    // renamed field is refused on the bare word and passes on the backticks.
    // A `params` list that drops, reorders or adds a name is refused by
    // `inputs_match`. The enum is fixture source, not the contract crate.
    let contract_dispatch = "\
        WalletProviderOperationV2::Empty {} => self.empty(),\n        \
        WalletProviderOperationV2::NamedNone { field } => self.named(field),\n        \
        WalletProviderOperationV2::Pair { beta, alpha } => self.pair(beta, alpha),\n";
    let contract_enum = "
enum WalletProviderOperationV2 {
    Empty {},
    NamedNone {
        #[serde(rename = \"none\")]
        field: String,
    },
    Pair {
        beta: u8,
        alpha: u8,
    },
}
";
    let contract_source = ROW_FIXTURE_PROVIDER.replace(
        "        WalletProviderOperationV2::ListAccounts { include_revoked } => self.accounts(*include_revoked),\n",
        contract_dispatch,
    ) + contract_enum;
    assert_ne!(contract_source, ROW_FIXTURE_PROVIDER);
    fs::write(&provider_source, &contract_source).expect("fixture contract source");
    let contract_cell = |kind: &str, params: &str| {
        format!("`op`, `request` (`kind: {kind}`, `params` ({params})), `_runtime_invocation`")
    };
    let mut contract_document = fixture_row_document(&["init", "status", "echo", "shutdown"]);
    for (kind, params) in [
        ("empty", "none"),
        ("named_none", "`none`"),
        ("pair", "`beta`, `alpha`"),
    ] {
        contract_document.push_str(&fixture_row(
            &format!("wallet_contract {kind}"),
            &contract_cell(kind, params),
            NO_DECLARED_RIGHT,
            "`tests/confine.rs::present_case` shows the answer.",
            LINUX_STATUS,
        ));
    }
    assert_eq!(
        operations_table_row_problems("fixture-provider", &contract_document, provider.path()),
        Vec::<String>::new(),
        "the fixture contract rows must pass"
    );
    let bare_params = param_field_items(&[]);
    let named_params = param_field_items(&["none".to_string()]);
    assert_ne!(
        bare_params, named_params,
        "a bare none and a field named none are different items"
    );
    for (items, other) in [(&bare_params, &named_params), (&named_params, &bare_params)] {
        let text = render_inputs(items);
        let parsed = input_items(&text).expect("the rendered item must parse");
        assert!(
            inputs_match(&parsed, items),
            "render_inputs must parse back to {text}"
        );
        assert!(
            !inputs_match(&parsed, other),
            "render_inputs of {text} must not parse back to the other item"
        );
    }
    let fixture_label = provider_source.display().to_string();
    for (case, kind, params) in [
        (
            "the bare marker on a field named none",
            "named_none",
            "none",
        ),
        ("a backticked none on an empty arm", "empty", "`none`"),
        ("a dropped params name", "pair", "`beta`"),
        ("a reordered params list", "pair", "`alpha`, `beta`"),
        ("an added params name", "pair", "`beta`, `alpha`, `extra`"),
    ] {
        let good = contract_cell(
            kind,
            match kind {
                "empty" => "none",
                "named_none" => "`none`",
                _ => "`beta`, `alpha`",
            },
        );
        let bad = contract_cell(kind, params);
        assert_ne!(good, bad, "{case} must change the cell");
        let observed = input_items(&bad).expect("{case} must parse");
        let fields: Vec<String> = match kind {
            "empty" => Vec::new(),
            "named_none" => vec!["none".to_string()],
            _ => vec!["beta".to_string(), "alpha".to_string()],
        };
        let expected = contract_row_inputs(
            kind,
            &["request".to_string(), "_runtime_invocation".to_string()],
            &fields,
        );
        assert!(
            !inputs_match(&observed, &expected),
            "{case} must fail inputs_match"
        );
        let document = contract_document.replacen(
            &format!("| wallet_contract {kind} | {good} |"),
            &format!("| wallet_contract {kind} | {bad} |"),
            1,
        );
        assert_eq!(
            operations_table_row_problems("fixture-provider", &document, provider.path()),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row wallet_contract {kind} \
                 holds the Inputs cell {bad}, and {fixture_label} names {good}"
            )],
            "{case} must be one refusal"
        );
    }
    fs::write(&provider_source, ROW_FIXTURE_PROVIDER).expect("fixture provider source restore");

    // Rule 5: every source refusal keeps its own reason that names the file.
    for (case, anchor, replacement, reason) in [
        (
            "a missing enum Request",
            "enum Request {",
            "enum OtherRequest {",
            format!(
                "Inputs cells cannot be checked because {provider_paths} declares no enum Request"
            ),
        ),
        (
            "no declared arm for the row",
            "    Echo {\n        message: String,\n        retry: u64,\n    },\n",
            "",
            format!(
                "row echo holds the Inputs cell `op`, `message`, `retry`, and {provider_paths} \
                 declares no Echo arm"
            ),
        ),
        (
            "a longer declaration name than the row's arm",
            "    Echo {",
            "    EchoExtra {",
            format!(
                "row echo holds the Inputs cell `op`, `message`, `retry`, and {provider_paths} \
                 declares no Echo arm"
            ),
        ),
    ] {
        assert_eq!(
            ROW_FIXTURE_PROVIDER.matches(anchor).count(),
            1,
            "{case} has one anchor"
        );
        fs::write(
            &provider_source,
            ROW_FIXTURE_PROVIDER.replacen(anchor, replacement, 1),
        )
        .expect("source refusal fixture");
        assert_eq!(
            operations_table_row_problems("fixture-provider", &passing, provider.path()),
            vec![format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} {reason}"
            )],
            "{case} must keep its exact refusal"
        );
        fs::write(&provider_source, ROW_FIXTURE_PROVIDER).expect("fixture provider source restore");
    }

    // Rule 5: a declaration file the caller cannot read keeps its own reason
    // that names the path. Wallet declares `Request` in `src/protocol.rs`, so a
    // fixture provider folder without that file is refused by name.
    let wallet_fixture = tempfile::tempdir().expect("temporary wallet fixture folder");
    fs::create_dir_all(wallet_fixture.path().join("src")).expect("wallet fixture src folder");
    fs::write(
        wallet_fixture.path().join("src/main.rs"),
        ROW_FIXTURE_PROVIDER,
    )
    .expect("wallet fixture provider source");
    let protocol_path = wallet_fixture.path().join("src/protocol.rs");
    let missing = operations_table_row_problems("wallet-provider", &passing, wallet_fixture.path());
    assert_eq!(
        missing.len(),
        1,
        "an unreadable declaration file must be one refusal: {missing:?}"
    );
    assert!(
        missing[0].starts_with(&format!(
            "wallet-provider CONFINEMENT.md: {OPERATIONS_HEADING} Inputs cells cannot be checked \
             because {} is not readable",
            protocol_path.display()
        )),
        "an unreadable declaration file must keep its own reason: {}",
        missing[0]
    );
    let read_error = fs::read_to_string(&protocol_path).expect_err("missing declaration source");
    assert_eq!(
        missing,
        vec![format!(
            "wallet-provider CONFINEMENT.md: {OPERATIONS_HEADING} Inputs cells cannot be checked \
             because {} is not readable: {read_error}",
            protocol_path.display()
        )]
    );
    fs::write(&protocol_path, ROW_FIXTURE_PROVIDER).expect("wallet fixture declaration source");
    assert_eq!(
        operations_table_row_problems("wallet-provider", &passing, wallet_fixture.path()),
        Vec::<String>::new(),
        "the declaration file the caller reads must be the one the names come from"
    );

    // Rule 5: a provider source with no `fn handle` keeps its own reason, and
    // the row-set rule keeps its own line beside it.
    let no_handle = ROW_FIXTURE_PROVIDER.replace("fn handle(", "fn answer(");
    assert_ne!(no_handle, ROW_FIXTURE_PROVIDER);
    fs::write(&provider_source, &no_handle).expect("no-handle fixture provider source");
    assert_eq!(
        operations_table_row_problems("fixture-provider", &passing, provider.path()),
        vec![
            format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set cannot be checked \
                 because {provider_paths} holds no fn handle"
            ),
            format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} Inputs cells cannot be \
                 checked because {provider_paths} holds no fn handle"
            ),
        ],
        "a source with no fn handle must keep both reasons"
    );
    fs::write(&provider_source, ROW_FIXTURE_PROVIDER).expect("fixture provider source restore");

    fs::remove_file(&provider_source).expect("remove fixture dispatch source");
    let read_error = fs::read_to_string(&provider_source).expect_err("missing dispatch source");
    assert_eq!(
        operations_table_row_problems("fixture-provider", &passing, provider.path()),
        vec![format!(
            "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row set cannot be checked \
             because {provider_paths} is not readable: {read_error}"
        )],
        "an unreadable dispatch file must keep its exact refusal"
    );
    fs::write(&provider_source, ROW_FIXTURE_PROVIDER).expect("fixture provider source restore");

    // Rule 4: a Linux cell that is not `designed, not enforced`, one per row.
    let enforced = passing.replace(LINUX_STATUS, "enforced by Landlock");
    assert_ne!(enforced, passing, "the fixture must name its Linux cells");
    let problems = operations_table_row_problems("fixture-provider", &enforced, provider.path());
    assert_eq!(
        problems.len(),
        FIXTURE_OPERATIONS.len(),
        "every row must be refused once: {problems:?}"
    );
    for (problem, operation) in problems.iter().zip(FIXTURE_OPERATIONS.iter()) {
        assert_eq!(
            problem,
            &format!(
                "fixture-provider CONFINEMENT.md: {OPERATIONS_HEADING} row {operation} names the \
                 Linux cell enforced by Landlock, and every Linux cell is {LINUX_STATUS}"
            ),
            "the refusal must name the rule, the row and the value"
        );
    }
}

/// The one contract check refuses a profile that omits the explicit network
/// denial, and names that rule. The fixtures are built in the test; no file
/// is read.
///
/// Falsifier: delete the `(deny network*)` requirement from
/// `check_profile_contract`; this test fails because the incomplete fixture
/// passes.
#[test]
fn file_profile_contract_rejects_a_profile_without_deny_network() {
    let complete = contract_fixture_profile(true);
    check_profile_contract("fixture-provider", &complete).expect(
        "a profile with the version, default denial, network denial and shared rules must pass",
    );
    let incomplete = contract_fixture_profile(false);
    let refusal = check_profile_contract("fixture-provider", &incomplete)
        .expect_err("a profile without its (deny network*) form must fail");
    assert!(
        refusal.contains("(deny network*)"),
        "the refusal must name the missing rule: {refusal}"
    );
}

/// The one contract check refuses a profile that grants the network, in any
/// allow form, and names that rule and the form. The fixtures are built in the
/// test; no file is read.
///
/// Falsifier: remove the network-allow rule from `check_profile_contract`;
/// this test fails because the granting fixture passes.
#[test]
fn file_profile_contract_rejects_a_network_allow() {
    let complete = contract_fixture_profile(true);
    check_profile_contract("fixture-provider", &complete).expect(
        "a profile with the version, default denial, network denial and shared rules must pass",
    );
    for grant in [
        "(allow network*)",
        r#"(allow network-outbound (remote ip "localhost:*"))"#,
    ] {
        let profile = format!("{complete}{grant}\n");
        let refusal = check_profile_contract("fixture-provider", &profile)
            .expect_err("a profile with a network allow must fail");
        assert!(
            refusal.contains("fixture-provider") && refusal.contains(grant),
            "the refusal must name the profile and the form: {refusal}"
        );
        assert!(
            refusal.contains("network allow is refused"),
            "the refusal must say a network allow is refused: {refusal}"
        );
    }
}

/// The one contract check refuses a profile that adds `(allow default)` after
/// its default denial and names that rule and the profile. The fixture is
/// built in the test; no file is read.
///
/// Falsifier: remove the allow-default rule from `check_profile_contract`;
/// this test fails because the granting fixture passes.
#[test]
fn file_profile_contract_rejects_an_allow_default() {
    let complete = contract_fixture_profile(true);
    check_profile_contract("fixture-provider", &complete).expect(
        "a profile with the version, default denial, network denial and shared rules must pass",
    );
    let profile = format!("{complete}(allow default)\n");
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("a profile with an (allow default) form must fail");
    assert!(
        refusal.contains("fixture-provider") && refusal.contains("must reject (allow default)"),
        "the refusal must name the profile and the rule: {refusal}"
    );
}

/// The one contract check refuses a profile that holds a second exec allow,
/// whichever form grants it, wherever it sits, and names the profile, every
/// extra rule and the reason. A fixture profile that appends `(allow
/// process-exec (literal "/bin/sh"))` keeps its own removal for the 055 removal
/// check, and the 056 and 059 copy tests still launch and refuse copies of the
/// provider binary, because `PROVIDER_EXECUTABLE` stays the only bound binary,
/// so neither test sees a second exec path. The unfiltered forms put the
/// operation name directly before the closing parenthesis, which `profile_forms`
/// keeps attached, so the predicate must read `)` as a token boundary too.
/// An allow form may put its first filter directly after `allow`, and an
/// escaped quote or parenthesis inside a string must stay inside that string.
/// `/usr/bin/sandbox-exec` loads `(version 1)(deny default)(allow file-read*
/// (literal "/x") process-exec)` without a load error: it attempts to start
/// `/usr/bin/true`, whose exec fails with `execvp() of '/usr/bin/true' failed:
/// Operation not permitted` and exit 71. The check refuses that form either
/// way, because it does not depend on what `sandbox-exec` accepts. The
/// fixtures are built in the test; no file is read and no process starts.
///
/// Falsifiers: WP69 disables the second-exec-allow refusal in
/// `check_profile_contract`; this test fails because the `/bin/sh` fixture
/// passes. WP70 does not read `)` as a token boundary, so the unfiltered
/// `(allow process*)` form passes. WP71 quotes every exec allow after the
/// first, so the fixture with `/bin/sh` before the shared rule quotes the
/// shared rule and misses the extra one. WP72 reads only the operation names
/// before the first filter, so the after-filter `process-exec` form passes.
/// WP73 quotes only the first extra rule, so the fixture with two extras and
/// no shared rule loses the second quote. WP74 counts a token inside a nested
/// filter as an operation, so the passing `(process-exec "/x")` fixture is
/// refused. WP75 counts text inside a string as an operation, so the passing
/// `(allow "process-exec")` fixture is refused. WP76 drops the escape flag in
/// `profile_characters`, so the escaped-string fixture parses differently and
/// this test and `file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does`
/// fail. WP77 requires `(allow ` with a space, so the flush-head form passes.
#[test]
fn file_profile_contract_rejects_a_second_exec_allow() {
    let complete = contract_fixture_profile(true);
    check_profile_contract("fixture-provider", &complete).expect(
        "a profile with the version, default denial, network denial and shared rules must pass",
    );
    for grant in [
        r#"(allow process-exec (literal "/bin/sh"))"#,
        SHARED_RULES[0],
        r#"(allow process* (literal "/bin/sh"))"#,
        r#"(allow process-exec)"#,
        r#"(allow process*)"#,
        r#"(allow file-read* process*)"#,
    ] {
        let profile = format!("{complete}{grant}\n");
        let refusal = check_profile_contract("fixture-provider", &profile)
            .expect_err("a profile with a second exec allow must fail");
        assert!(
            refusal.contains("fixture-provider")
                && refusal.contains(&format!("the extra rules are `{grant}`")),
            "the refusal must name the profile and quote the extra rule: {refusal}"
        );
        assert!(
            refusal.contains("more than one process-exec allow"),
            "the refusal must say there is more than one process-exec allow: {refusal}"
        );
        assert_generated_reason_has_no_failure(&refusal);
    }

    // The extra exec rule sits before the shared one, so a refusal that quotes
    // `exec_allows[1..]` names the shared rule and misses the extra one.
    let extra_before_shared = r#"(allow process-exec (literal "/bin/sh"))"#;
    let mut profile = String::from("(version 1)\n(deny default)\n(deny network*)\n");
    profile.push_str(extra_before_shared);
    profile.push('\n');
    for rule in SHARED_RULES {
        profile.push_str(rule);
        profile.push('\n');
    }
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("an extra exec rule before the shared one must fail");
    assert!(
        refusal.contains(&format!("the extra rules are `{extra_before_shared}`")),
        "the refusal must quote the extra rule that sits before the shared one: {refusal}"
    );
    assert!(
        !refusal.contains(SHARED_RULES[0]),
        "the refusal must not quote the one shared exec rule: {refusal}"
    );
    assert!(
        refusal.contains("more than one process-exec allow"),
        "the refusal must say there is more than one process-exec allow: {refusal}"
    );
    assert_generated_reason_has_no_failure(&refusal);

    // An operation name after a filter still names the allow form's operation.
    let after_filter = r#"(allow file-read* (literal "/x") process-exec)"#;
    let profile = format!("{complete}{after_filter}\n");
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("an operation name after a filter must still be counted");
    assert!(
        refusal.contains(&format!("the extra rules are `{after_filter}`")),
        "the refusal must quote the after-filter rule: {refusal}"
    );
    assert!(
        refusal.contains("more than one process-exec allow"),
        "the refusal must say there is more than one process-exec allow: {refusal}"
    );
    assert_generated_reason_has_no_failure(&refusal);

    // The first filter may sit directly after `allow`, so the allow head is
    // `(allow(` and the operation after the filter still counts.
    let flush_head = r#"(allow(literal "/x") process-exec)"#;
    let profile = format!("{complete}{flush_head}\n");
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("an operation after a filter that follows allow directly must be counted");
    assert!(
        refusal.contains(&format!("the extra rules are `{flush_head}`")),
        "the refusal must quote the flush-head rule: {refusal}"
    );
    assert!(
        refusal.contains("more than one process-exec allow"),
        "the refusal must say there is more than one process-exec allow: {refusal}"
    );
    assert_generated_reason_has_no_failure(&refusal);

    // An escaped quote and a parenthesis inside a string leave the following
    // operation outside the string, so the one string reader must keep them.
    let escaped_string = r#"(allow file-read* (literal "a\"b)") process-exec)"#;
    let profile = format!("{complete}{escaped_string}\n");
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("an operation after an escaped string must still be counted");
    assert!(
        refusal.contains(&format!("the extra rules are `{escaped_string}`")),
        "the refusal must quote the rule after the escaped string: {refusal}"
    );
    assert!(
        refusal.contains("more than one process-exec allow"),
        "the refusal must say there is more than one process-exec allow: {refusal}"
    );
    assert_generated_reason_has_no_failure(&refusal);

    // With no shared exec rule, every exec allow is an extra rule.
    let first_extra = r#"(allow process-exec (literal "/bin/sh"))"#;
    let second_extra = r#"(allow process* (literal "/bin/ksh"))"#;
    let mut profile = String::from("(version 1)\n(deny default)\n(deny network*)\n");
    for rule in [first_extra, second_extra, SHARED_RULES[1], SHARED_RULES[2]] {
        profile.push_str(rule);
        profile.push('\n');
    }
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("a profile without the shared exec rule still holds two exec allows");
    assert!(
        refusal.contains(&format!(
            "the extra rules are `{first_extra}`, `{second_extra}`"
        )),
        "the refusal must quote every exec allow when none is the shared one: {refusal}"
    );
    assert!(
        refusal.contains("more than one process-exec allow"),
        "the refusal must say there is more than one process-exec allow: {refusal}"
    );
    assert_generated_reason_has_no_failure(&refusal);

    // A token inside a string or a nested filter names text or a filter
    // argument, not an operation, so these profiles keep one exec allow. An
    // escaped quote stays inside its string, so the text after it is text too.
    for passing in [
        r#"(allow file-read* (literal "/process-exec"))"#,
        r#"(allow file-read* (process-exec "/x"))"#,
        r#"(allow file-read* (require-all (process*)))"#,
        r#"(allow "process-exec")"#,
        r#"(allow file-read* (literal "a\" process-exec "))"#,
    ] {
        let profile = format!("{complete}{passing}\n");
        check_profile_contract("fixture-provider", &profile)
            .expect("a token inside a string or a nested filter must not count as an operation");
    }
}

/// The part of the refusal the one check generates, before the rules it quotes.
/// The `error: ` ban covers that generated text; a quoted rule may hold any
/// path text of its own.
fn assert_generated_reason_has_no_failure(refusal: &str) {
    let generated = refusal
        .split("; the extra rules are ")
        .next()
        .unwrap_or_default();
    assert!(
        !generated.contains("error: "),
        "the generated reason must hold no failure text: {refusal}"
    );
}

/// The one contract check refuses a profile that binds a parameter token
/// outside the canonical three, and names the profile and that token. The
/// fixtures are built in the test; no file is read.
///
/// Falsifier: remove the canonical-token refusal from
/// `check_profile_contract`; this test fails because the extra-token fixture
/// passes.
#[test]
fn file_profile_contract_rejects_a_non_canonical_token() {
    let complete = contract_fixture_profile(true);
    check_profile_contract("fixture-provider", &complete).expect(
        "a profile with the version, default denial, network denial and shared rules must pass",
    );
    let profile = format!("{complete}(allow file-read* (literal (param \"READ_FIXTURE_KEY\")))\n");
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("a profile with a non-canonical parameter token must fail");
    assert!(
        refusal.contains("fixture-provider")
            && refusal.contains("non-canonical parameter token READ_FIXTURE_KEY"),
        "the refusal must name the profile and the token: {refusal}"
    );
}

/// The profile lines whose `;`, `(` and `)` sit inside strings, with an
/// `(allow default)` after the first one. `sandbox-exec` reads those three
/// characters as text, so the lines hold two forms and then one more.
const STRING_LINES: &str = r#"(deny file-read* (literal "/x;")) (allow default)
(deny file-read* (literal "/))"))
"#;

/// The parser reads a `;` and every parenthesis inside a string as
/// `sandbox-exec` does, so the one contract check sees the `(allow default)`
/// that these lines hold. It keeps an escaped quote and an escaped backslash
/// inside their string, keeps whitespace inside a string, collapses whitespace
/// outside strings, and loads a form after a comment's newline. The fixtures
/// are built in the test; no file is read and no process starts.
///
/// Falsifier: WP31 restores the plain cut at every `;` and the parenthesis
/// count inside strings; this test fails because the hidden `(allow default)`
/// then passes the check. WP32 to WP35 disable escaping, the in-string
/// whitespace, the outside collapse and the comment's end at its newline;
/// this test fails on each.
#[test]
fn file_profile_contract_reads_strings_and_comments_as_sandbox_exec_does() {
    let complete = contract_fixture_profile(true);
    check_profile_contract("fixture-provider", &complete)
        .expect("the passing fixture must pass the one check");
    let profile = format!("{complete}{STRING_LINES}");
    let refusal = check_profile_contract("fixture-provider", &profile)
        .expect_err("a fixture whose strings hold (allow default) must fail");
    assert!(
        refusal.contains("fixture-provider") && refusal.contains("must reject (allow default)"),
        "the refusal must name the profile and the rule: {refusal}"
    );

    let forms = profile_forms(STRING_LINES);
    assert_eq!(forms.len(), 3, "the two lines hold three forms: {forms:?}");
    assert_eq!(
        forms[1], "(allow default)",
        "the second form must be the allow default: {forms:?}"
    );

    assert_eq!(
        profile_forms("(version 1) ; (allow default)"),
        vec!["(version 1)"],
        "a `;` outside a string must comment out the rest of its line"
    );

    let escaped_quote = r#"(deny file-read* (literal "/a\"b)"))"#;
    assert_eq!(
        profile_forms(escaped_quote),
        vec![escaped_quote],
        "a backslash must escape the next character inside a string"
    );

    let escaped_backslash = r#"(deny file-read* (literal "/a\\"))"#;
    assert_eq!(
        profile_forms(escaped_backslash),
        vec![escaped_backslash],
        "an escaped backslash must stay inside its string"
    );

    let spaced = r#"(deny file-read* (literal "/a  b"))"#;
    assert_eq!(
        profile_forms(spaced),
        vec![spaced],
        "whitespace inside a string must be kept"
    );

    assert_eq!(
        profile_forms("(version   1)"),
        vec!["(version 1)"],
        "whitespace outside strings must collapse to one space"
    );

    assert_eq!(
        profile_forms("(version 1) ; (allow default)\n(deny default)"),
        vec!["(version 1)", "(deny default)"],
        "a form after a comment's newline must still load"
    );
}

/// A comment inside a form ends at its newline, and that newline still
/// separates the form's tokens, as `sandbox-exec` reads it. Without the
/// separator `(allow;x\ndefault)` reads as `(allowdefault)`, which matches
/// neither `is_default_allow` nor `is_network_allow`; both forms would then
/// pass the one check while `sandbox-exec` applies them. The fixtures are
/// built in the test; no file is read and no process starts.
///
/// Falsifier: WP38 drops the newline that ends a comment; this test fails
/// because the glued form passes the check and the parser returns
/// `(allowdefault)`.
#[test]
fn a_comment_inside_a_form_keeps_its_tokens_apart() {
    assert_eq!(
        profile_forms("(allow;x\ndefault)"),
        vec!["(allow default)"],
        "the newline that ends a comment must separate the tokens"
    );
    assert_eq!(
        profile_forms("(allow;x\nnetwork*)"),
        vec!["(allow network*)"],
        "the newline that ends a comment must separate the tokens"
    );

    let complete = contract_fixture_profile(true);
    for (line, refusal) in [
        (
            "(allow;x\ndefault)\n",
            "fixture-provider must reject (allow default): (allow default)",
        ),
        (
            "(allow;x\nnetwork*)\n",
            "fixture-provider must not grant network access; \
             a network allow is refused: (allow network*)",
        ),
    ] {
        let profile = format!("{complete}{line}");
        let reason = check_profile_contract("fixture-provider", &profile)
            .expect_err("a form split by a comment must fail the one check");
        assert_eq!(
            reason, refusal,
            "the refusal must be the exact reason for the hidden form"
        );
    }
}

/// Whitespace directly after an opening parenthesis does not change the rule
/// name, as `sandbox-exec` reads it. Without the normalization
/// `( allow default)` and `(;x\nallow default)` read as `( allow default)`,
/// which matches neither `is_default_allow` nor `is_network_allow`; the hidden
/// rule would then pass the one check while `sandbox-exec` applies it. The
/// same holds for the network form. The fixtures are built in the test; no
/// file is read and no process starts.
///
/// Falsifier: WP40 adds the separator space after an opening parenthesis; this
/// test fails because the parser returns `( allow default)` and both spaced
/// forms pass the check.
#[test]
fn a_space_after_the_opening_parenthesis_still_names_its_rule() {
    for line in ["(allow default)", "( allow default)", "(;x\nallow default)"] {
        assert_eq!(
            profile_forms(line),
            vec!["(allow default)"],
            "whitespace after the opening parenthesis must not name a new rule"
        );
    }
    for line in [
        "(allow network*)",
        "( allow network*)",
        "(;x\nallow network*)",
    ] {
        assert_eq!(
            profile_forms(line),
            vec!["(allow network*)"],
            "whitespace after the opening parenthesis must not name a new rule"
        );
    }

    let complete = contract_fixture_profile(true);
    for (line, refusal) in [
        (
            "( allow default)\n",
            "fixture-provider must reject (allow default): (allow default)",
        ),
        (
            "(;x\nallow default)\n",
            "fixture-provider must reject (allow default): (allow default)",
        ),
        (
            "( allow network*)\n",
            "fixture-provider must not grant network access; \
             a network allow is refused: (allow network*)",
        ),
        (
            "(;x\nallow network*)\n",
            "fixture-provider must not grant network access; \
             a network allow is refused: (allow network*)",
        ),
    ] {
        let profile = format!("{complete}{line}");
        let reason = check_profile_contract("fixture-provider", &profile)
            .expect_err("a spaced allow form must fail the one check");
        assert_eq!(
            reason, refusal,
            "the refusal must be the exact reason for the spaced form"
        );
    }
}

/// A bare value outside every form, such as `1` or `"x"`, is its own form,
/// as `sandbox-exec` reads it: whitespace or a `(` ends it. Without that split
/// `1 (allow default)` reads as one form, which matches neither
/// `is_default_allow` nor `is_network_allow`; the hidden rule would then pass
/// the one check while `sandbox-exec` applies it. A bare value at the end of the
/// profile is a form too, not an unclosed one. The fixtures are built in the
/// test; no file is read and no process starts.
///
/// Falsifier: WP39 drops the split outside every form; this test fails
/// because the parser returns `1 (allow default)` and the glued form passes
/// the check.
#[test]
fn a_bare_top_level_value_is_its_own_form() {
    assert_eq!(
        profile_forms("1\n(allow default)"),
        vec!["1", "(allow default)"],
        "whitespace outside every form must end a bare value"
    );
    assert_eq!(
        profile_forms("1(allow default)"),
        vec!["1", "(allow default)"],
        "a `(` outside every form must end a bare value"
    );
    assert_eq!(
        profile_forms(r#""x" (allow default)"#),
        vec![r#""x""#, "(allow default)"],
        "a bare string must be its own form"
    );
    assert_eq!(
        profile_forms("(version 1) 1"),
        vec!["(version 1)", "1"],
        "a bare value at the end of the profile must be its own form"
    );

    let complete = contract_fixture_profile(true);
    for (line, refusal) in [
        (
            "1\n(allow default)\n",
            "fixture-provider must reject (allow default): (allow default)",
        ),
        (
            "\"x\" (allow default)\n",
            "fixture-provider must reject (allow default): (allow default)",
        ),
        (
            "1(allow default)\n",
            "fixture-provider must reject (allow default): (allow default)",
        ),
        (
            "1 (allow network*)\n",
            "fixture-provider must not grant network access; \
             a network allow is refused: (allow network*)",
        ),
    ] {
        let profile = format!("{complete}{line}");
        let reason = check_profile_contract("fixture-provider", &profile)
            .expect_err("a form after a bare value must fail the one check");
        assert_eq!(
            reason, refusal,
            "the refusal must be the exact reason for the form after the bare value"
        );
    }
}

/// `sandbox-exec` itself reads a bare value before a form as two forms: it
/// evaluates the `1`, ignores it and applies the `(allow default)` after it.
/// The fixture writes `(version 1)(deny default) 1 (allow default)` to a
/// temporary file and runs `/usr/bin/true` under it, which must exit 0. Under
/// `(deny default)` alone `/usr/bin/true` cannot start, so the exit shows the
/// premise of `a_bare_top_level_value_is_its_own_form`. It checks that premise,
/// not a rule, so it carries no falsifier entry.
#[test]
fn the_bare_value_fixture_loads_under_sandbox_exec() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let mut file = tempfile::NamedTempFile::new().expect("temporary bare value fixture profile");
    file.write_all(b"(version 1)(deny default) 1 (allow default)\n")
        .expect("write the bare value fixture profile");
    let output = Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(file.path())
        .arg("/usr/bin/true")
        .output()
        .expect("sandbox-exec must start");
    assert!(
        output.status.success(),
        "sandbox-exec must load the bare value fixture and start true: {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `sandbox-exec` itself reads the two string lines as `profile_forms` does:
/// it parses their `;`, `(` and `)` as text and applies the `(allow default)`
/// they hold. The fixture writes `(version 1)`, `(deny default)` and those two
/// lines to a temporary file and runs `/usr/bin/true` under it, which must
/// exit 0. Under `(deny default)` alone `/usr/bin/true` cannot start, so the
/// exit shows the fixture's premise. It checks that premise, not a rule, so it
/// carries no falsifier entry.
#[test]
fn the_string_fixture_loads_under_sandbox_exec() {
    if !sandbox_available(std::env::consts::OS, Path::new(SANDBOX_EXEC)) {
        return;
    }
    let profile = format!("(version 1)\n(deny default)\n{STRING_LINES}");
    let mut file = tempfile::NamedTempFile::new().expect("temporary string fixture profile");
    file.write_all(profile.as_bytes())
        .expect("write the string fixture profile");
    let status = Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(file.path())
        .arg("/usr/bin/true")
        .status()
        .expect("sandbox-exec must start");
    assert!(
        status.success(),
        "sandbox-exec must load the string fixture and start true: {status}"
    );
}

/// The parser refuses an unclosed string with the existing "must not end
/// early" reason and a detail that names the string. It reads no form past it.
///
/// Falsifier: WP36 drops the unclosed-string refusal; this test fails because
/// the profile then ends as an unclosed form, whose reason names no string.
#[test]
fn profile_forms_rejects_unclosed_string() {
    let refusal = std::panic::catch_unwind(|| profile_forms("(literal \"/unclosed)"))
        .expect_err("an unclosed string must fail");
    let message = refusal
        .downcast_ref::<String>()
        .unwrap_or_else(|| panic!("the refusal must be a formatted reason"));
    assert_eq!(
        message.as_str(),
        "the profile must not end early: unclosed string in (literal \"/unclosed)",
        "the refusal must be the exact reason for the unclosed string"
    );
}

/// The parser refuses an unclosed form with the existing "must not end early"
/// reason and a detail that names the form, while a closed form loads.
///
/// Falsifier: WP37 drops the unclosed-form refusal; this test fails because
/// the incomplete profile returns no refusal.
#[test]
fn profile_forms_rejects_unclosed_form() {
    let refusal = std::panic::catch_unwind(|| profile_forms("(deny default"))
        .expect_err("an unclosed form must fail");
    let message = refusal
        .downcast_ref::<String>()
        .unwrap_or_else(|| panic!("the refusal must be a formatted reason"));
    assert_eq!(
        message.as_str(),
        "the profile must not end early: unclosed form (deny default",
        "the refusal must be the exact reason for the unclosed form"
    );
    assert_eq!(
        profile_forms("(deny default)"),
        vec!["(deny default)"],
        "a closed form must load"
    );
}

/// The one list requires the model profile with the did and wallet profiles
/// and refuses a missing or unreadable one instead of skipping it.
#[test]
fn file_profile_contract_checks_the_model_profile_when_present() {
    let capsules = contract_fixture_capsules();
    let checked =
        check_file_profiles(capsules.path()).expect("the three passing fixtures must pass");
    assert_eq!(
        checked,
        vec!["did-provider", "wallet-provider", "model-provider"],
        "the one list must check all three required profiles in order"
    );

    let capsules = contract_fixture_capsules();
    write_fixture_profile(
        capsules.path(),
        "model-provider",
        &contract_fixture_profile(false),
    );
    let refusal = check_file_profiles(capsules.path())
        .expect_err("a model profile without (deny network*) must fail");
    assert!(
        refusal.contains("model-provider") && refusal.contains("(deny network*)"),
        "the refusal must name the model profile and the missing rule: {refusal}"
    );

    let capsules = contract_fixture_capsules();
    let model_profile = capsules.path().join("model-provider").join("confine.sb");
    fs::remove_file(&model_profile).expect("remove the model profile");
    let refusal = check_file_profiles(capsules.path())
        .expect_err("a missing model profile is a required refusal, not a skip");
    assert!(
        refusal.contains("model-provider")
            && refusal.contains(&model_profile.display().to_string()),
        "the refusal must name the model profile and its path: {refusal}"
    );

    let capsules = contract_fixture_capsules();
    let model_profile = capsules.path().join("model-provider").join("confine.sb");
    fs::remove_file(&model_profile).expect("remove the model profile");
    fs::create_dir_all(&model_profile).expect("model profile directory");
    let refusal = check_file_profiles(capsules.path())
        .expect_err("a model profile directory is a read error, not an absence");
    assert!(
        refusal.contains(&model_profile.display().to_string()),
        "the refusal must name the model profile path: {refusal}"
    );

    let capsules = contract_fixture_capsules();
    fs::remove_file(capsules.path().join("did-provider").join("confine.sb"))
        .expect("remove the did profile");
    let refusal = check_file_profiles(capsules.path()).expect_err("the did profile is required");
    assert!(
        refusal.contains("did-provider"),
        "the refusal must name the did profile: {refusal}"
    );
}

/// Splits the profile into top-level s-expressions the way `sandbox-exec`
/// reads it. `profile_characters` removes comments and marks strings; this
/// function collapses whitespace outside strings, keeps every character inside
/// one, counts parentheses only outside strings and collects the forms. Outside
/// every form, whitespace or a `(` ends a bare value such as `1` or `"x"`, so
/// that value is its own form and every top-level form starts its own entry.
/// Whitespace directly after an opening parenthesis is dropped, so
/// `( allow default)` reads as the form `(allow default)`.
/// An unclosed form is a refusal with its own reason.
fn profile_forms(profile: &str) -> Vec<String> {
    let mut forms = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut space_due = false;
    for (ch, in_string) in profile_characters(profile) {
        if in_string {
            if space_due {
                push_separator(&mut current);
            }
            space_due = false;
            current.push(ch);
            continue;
        }
        if depth == 0 && (ch.is_whitespace() || ch == '(') && !current.is_empty() {
            forms.push(std::mem::take(&mut current));
        }
        match ch {
            _ if ch.is_whitespace() => space_due = true,
            '(' | ')' => {
                if space_due {
                    push_separator(&mut current);
                }
                space_due = false;
                current.push(ch);
                if ch == '(' {
                    depth += 1;
                } else {
                    depth = depth.saturating_sub(1);
                    if depth == 0 && !current.is_empty() {
                        forms.push(std::mem::take(&mut current));
                    }
                }
            }
            _ => {
                if space_due {
                    push_separator(&mut current);
                }
                space_due = false;
                current.push(ch);
            }
        }
    }
    if depth == 0 && !current.is_empty() {
        forms.push(std::mem::take(&mut current));
    }
    assert!(
        current.is_empty(),
        "the profile must not end early: unclosed form {current}"
    );
    forms
}

/// Adds the one separator space between tokens. No separator is added directly
/// after an opening parenthesis, where no token has started, so `( allow
/// default)` reads as the form `(allow default)` and the allow rules still
/// match it.
fn push_separator(current: &mut String) {
    if !current.is_empty() && !current.ends_with('(') {
        current.push(' ');
    }
}

/// The characters the profile reader consumes, each marked with whether it
/// sits inside a double-quoted string. A `;` outside a string starts a comment
/// that runs to the end of its line; the newline that ends the comment stays
/// as a separator, so a comment inside a form keeps its two tokens apart.
/// Inside a string a backslash escapes the next character, so a `;`, `(` and
/// `)` there stay text and a quote does not end the string. The reader reads
/// no block comment and no `#` literal, because no profile holds either. An
/// unclosed string is a refusal with its own reason.
fn profile_characters(profile: &str) -> Vec<(char, bool)> {
    let mut characters = Vec::new();
    let mut in_string = false;
    let mut in_comment = false;
    let mut escaped = false;
    for ch in profile.chars() {
        if in_comment {
            in_comment = ch != '\n';
            if !in_comment {
                characters.push((ch, false));
            }
            continue;
        }
        if escaped {
            characters.push((ch, true));
            escaped = false;
            continue;
        }
        if in_string && ch == '\\' {
            characters.push((ch, true));
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            characters.push((ch, true));
            continue;
        }
        if !in_string && ch == ';' {
            in_comment = true;
            continue;
        }
        characters.push((ch, in_string));
    }
    assert!(
        !in_string,
        "the profile must not end early: unclosed string in {profile}"
    );
    characters
}
