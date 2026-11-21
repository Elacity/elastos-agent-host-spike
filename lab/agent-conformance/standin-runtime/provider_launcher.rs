//! Shared lab provider launcher used by the did, wallet and model journeys.
//! This module is included by the wallet confinement test; it is not Runtime code.

use super::*;

/// Lab stand-in for the Runtime's provider launch, not the Runtime.
///
/// The launcher lives with the lab stand-in. It copies
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
pub(super) fn standin_spawn_confined_provider(
    host: StandinHost,
    policy: StandinPolicy<'_>,
    name: &str,
    binary_path: &Path,
    base_path: &Path,
    declared: &Value,
    profile_dir: &Path,
    write_profile: fn(&str, &Value, &Path) -> Result<(), String>,
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
            write_profile(name, declared, &profile)?;
            create_shared_ancestors(&canonical);
            let inert = model_inert_bindings(name);
            let mut bindings: Vec<(&str, &Path)> = canonical
                .iter()
                .map(|(binding, path)| (*binding, path.as_path()))
                .collect();
            bindings.extend(
                inert
                    .iter()
                    .map(|(binding, path)| (binding.as_str(), path.as_path())),
            );
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
