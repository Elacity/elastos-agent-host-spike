//! Shared lab provider launcher used by the did, wallet and model journeys.
//! The wallet confinement test calls this module through the lab crate's
//! public API. Its launch body stays in that test so its registered behavioral
//! plants remain on the path.

use std::path::Path;

/// Lab stand-in for the Runtime's provider launch, not the Runtime.
///
/// This lab entry calls the wallet test's launch body. It copies
/// `ProviderBridge::spawn`'s inputs instead of an RA route.
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
/// 6. a refusal of the lab profile writer, returned unchanged;
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
pub fn standin_spawn_confined_provider<H, P, D, R, E, F>(
    host: H,
    policy: P,
    name: &str,
    binary_path: &Path,
    base_path: &Path,
    declared: &D,
    profile_dir: &Path,
    launch: F,
) -> Result<R, E>
where
    F: FnOnce(H, P, &str, &Path, &Path, &D, &Path) -> Result<R, E>,
{
    launch(
        host,
        policy,
        name,
        binary_path,
        base_path,
        declared,
        profile_dir,
    )
}
