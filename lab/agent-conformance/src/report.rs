//! Cargo owns inventory/results. This parser owns both the table and receipt.

use crate::identity::{sha256, Observation, ProbeIdentity, PREFIX};
use crate::runtime::Launch;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

struct GapRow {
    ids: String,
    runtime_change: String,
}

/// Two `elastos run` clients. A3 is resident instances inside one Runtime.
pub const INSTANCE_GRANTS_SCOPE: &str =
    "process isolation, not A3 (A3 needs resident instances in one Runtime); lab half of A6 and A9";

/// What the bundle row covers. An installed Runtime records release capsules in
/// `components.json`; the bundles this suite launches are not among them.
pub const STAGED_BUNDLE_SCOPE: &str =
    "lab CID of each bundle the suite staged from this checkout and launched; not an installed bundle";

/// What the installed row covers: the installed records agree with each other,
/// and their release source commit is the repository commit this receipt
/// records. The suite reads those records; it does not run on the data folder
/// they describe.
pub const INSTALLED_RUNTIME_SCOPE: &str =
    "release head, release and components hash-check each other and name this repository commit; records only, the installed data folder did not run";

/// What the runtime-ran row covers: the suite was told a named binary whose
/// canonical path is the installed binary, and the one Runtime identity it
/// recorded names that path with the installed binary's SHA-256; after the
/// suite and its liveness check, `run.sh` made a private record folder, hashed
/// the installed binary, launched it once, saw it answer, and hashed it again;
/// both hashes match the installed record. Nothing here sees the bytes the
/// operating system then executed, and the suite's own launches use the named
/// path with the harness's pre-launch hash. The report's own bytes are the ones
/// hashed before the suite: `run.sh` hashes the report it built, hashes it
/// again after the suite, refuses a change with `reporter changed during the
/// suite: <first> <now>`, and runs a copy of the verified bytes from a folder
/// no test process was given.
pub const INSTALLED_RUNTIME_BINARY_SCOPE: &str =
    "the suite was told a named binary whose canonical path is the installed binary, and the Runtime identity it recorded names that path with the installed binary's SHA-256; run.sh hashed the report it built before the suite, hashed it again after the suite and its liveness check, refused a change, and ran a copy of those verified bytes from a folder no test process was given; it made the record after that, hashed the installed binary, launched it once and saw it answer, and hashed it again; both hashes match the installed record; what this does not show: nothing sees the bytes the operating system then executed";

/// The data folder the Runtime under test ran with, as the receipt states it.
pub const RUNTIME_DATA_FOLDER: &str =
    "throwaway: the suite created it for this run; not the installed data folder";

fn blocker_ids(reason: &str) -> BTreeSet<&str> {
    reason.split(';').map(str::trim).collect()
}

fn grade(name: &str, result: &str, gaps: &[GapRow]) -> Result<String, String> {
    if result == "ok" {
        if !gaps.is_empty() {
            return Err(format!("GAPS.md: {name}: still lists it as blocked"));
        }
        return Ok("PASS".into());
    }
    if let Some(reason) = result.strip_prefix("ignored, blocked: ") {
        let parts: Vec<_> = reason.split(';').map(str::trim).collect();
        if parts.iter().all(|part| !part.is_empty()) {
            check_blocked_gap(name, reason, gaps)?;
            return Ok(format!("BLOCKED ({})", parts.join("; ")));
        }
    }
    Ok("FAIL".into())
}

fn check_blocked_gap(name: &str, reason: &str, gaps: &[GapRow]) -> Result<(), String> {
    let ids = blocker_ids(reason);
    let joined = ids.iter().copied().collect::<Vec<_>>().join("; ");
    let gap = match gaps {
        [] => {
            return Err(format!(
                "GAPS.md: {name}: missing row for blocker IDs: {joined}"
            ))
        }
        [gap] => gap,
        _ => {
            return Err(format!(
                "GAPS.md: {name}: expected exactly one row for blocker IDs: {joined}; found {}",
                gaps.len()
            ))
        }
    };
    let listed_ids = blocker_ids(&gap.ids);
    if ids != listed_ids {
        let missing = ids
            .difference(&listed_ids)
            .copied()
            .collect::<Vec<_>>()
            .join("; ");
        let extra = listed_ids
            .difference(&ids)
            .copied()
            .map(|id| if id.is_empty() { "<empty>" } else { id })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "GAPS.md: {name}: missing blocker IDs: [{missing}]; extra blocker IDs: [{extra}]"
        ));
    }
    if gap.runtime_change.is_empty() {
        return Err(format!(
            "GAPS.md: {name}: missing Runtime change for blocker IDs: {joined}"
        ));
    }
    Ok(())
}

#[derive(Default)]
struct Evidence {
    rows: BTreeMap<String, Vec<String>>,
    gaps: BTreeMap<String, Vec<GapRow>>,
    gaps_readable: bool,
    skipped: BTreeMap<String, Vec<String>>,
    reasons: BTreeMap<String, Vec<String>>,
    identities: Identities,
    failures: Vec<String>,
    duplicate_inventory: bool,
}

impl Evidence {
    fn parse(listed: &str, output: &str, gaps: Option<&str>) -> Self {
        let mut evidence = Self::default();
        for line in listed.lines() {
            if let Some(name) = line.strip_suffix(": test") {
                if !test_name(name) || evidence.rows.insert(name.into(), Vec::new()).is_some() {
                    evidence.duplicate_inventory = true;
                }
            }
        }
        evidence.gaps_readable = gaps.is_some();
        if let Some(gaps) = gaps {
            for line in gaps.lines() {
                let Some(row) = line.trim().strip_prefix('|') else {
                    continue;
                };
                let mut cells = row.split('|').map(str::trim);
                let Some(name) = cells
                    .next()
                    .and_then(|cell| cell.strip_prefix('`')?.strip_suffix('`'))
                else {
                    continue;
                };
                if evidence.rows.contains_key(name) {
                    evidence.gaps.entry(name.into()).or_default().push(GapRow {
                        ids: cells.next().unwrap_or_default().into(),
                        runtime_change: cells.next().unwrap_or_default().into(),
                    });
                }
            }
        } else {
            evidence.failures.push("could not read GAPS.md".into());
        }
        for line in output.lines() {
            if let Some(encoded) = line.strip_prefix(PREFIX) {
                let result = serde_json::from_str::<Observation>(encoded)
                    .map_err(|_| "malformed identity observation".into())
                    .and_then(|observation| evidence.identities.observe(observation));
                if let Err(reason) = result {
                    evidence.failures.push(reason);
                }
            } else if let Some((name, result)) = line
                .strip_prefix("test ")
                .and_then(|s| s.split_once(" ... "))
            {
                if !test_name(name) {
                    evidence.duplicate_inventory = true;
                    continue;
                }
                let values = evidence
                    .rows
                    .entry(name.into())
                    .or_insert_with(|| vec!["FAIL".into()]);
                values.push(result.to_owned());
            } else if let Some((name, reason)) = line
                .strip_prefix("FAILURE ")
                .and_then(|s| s.split_once(": "))
            {
                if test_name(name) && !reason.is_empty() {
                    evidence
                        .reasons
                        .entry(name.into())
                        .or_default()
                        .push(reason.replace('|', "/"));
                }
            } else if let Some((name, reason)) = line
                .strip_prefix("SKIPPED ")
                .and_then(|s| s.split_once(": "))
            {
                if !test_name(name) {
                    evidence.duplicate_inventory = true;
                    continue;
                }
                evidence
                    .rows
                    .entry(name.into())
                    .or_insert_with(|| vec!["unlisted".into()]);
                evidence
                    .skipped
                    .entry(name.into())
                    .or_default()
                    .push(reason.into());
            }
        }
        for (name, values) in &evidence.rows {
            if values.len() == 1 {
                if let Err(reason) = grade(name, &values[0], evidence.gap_rows(name)) {
                    evidence
                        .reasons
                        .entry(name.clone())
                        .or_default()
                        .push(reason.clone());
                    evidence.failures.push(reason);
                }
            }
        }
        evidence
    }

    fn gap_rows(&self, name: &str) -> &[GapRow] {
        self.gaps.get(name).map(Vec::as_slice).unwrap_or_default()
    }

    fn table(&self, cargo_ok: bool) -> (String, bool) {
        let mut text = String::from("test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\n");
        if self.duplicate_inventory {
            text.push_str("cargo | FAIL\n");
            return (text, false);
        }
        let mut passed = cargo_ok && !self.rows.is_empty() && self.gaps_readable;
        if !passed {
            text.push_str("cargo | FAIL\n");
        }
        for (name, values) in &self.rows {
            let result = self.result(name, values);
            passed &= result == "PASS" || result.starts_with("BLOCKED (");
            text.push_str(&format!("{name} | {result}"));
            if result == "FAIL" {
                if let Some(reasons) = self.reasons.get(name) {
                    text.push_str(&format!(" | {}", reasons.join("; ")));
                }
            }
            if name == "real_agent_host_gets_no_ungranted_authority" {
                text.push_str(" | real agent-host capsule, deny half; no model call (RT3)");
            }
            if name == "real_agent_host_journal_under_usersai_principal" {
                text.push_str(" | P7 gap: real agent-host journal under Users/self, not UsersAI/self; moves when the UsersAI binding lands");
            }
            if matches!(
                name.as_str(),
                "granted_read_succeeds"
                    | "ungranted_sibling_read_is_refused"
                    | "run_leaves_no_live_grant"
            ) {
                text.push_str(" | cleanup census, lab half of A10/A11/A12; cancel and kill-worker have separate journey rows");
            }
            if matches!(
                name.as_str(),
                "two_instances_overlap_with_separate_grants"
                    | "instance_grant_does_not_authorise_sibling"
            ) {
                text.push_str(" | ");
                text.push_str(INSTANCE_GRANTS_SCOPE);
            }
            if name == "cancelled_instance_settles_with_reason_sibling_completes" {
                text.push_str(
                    " | cancel at the pending-request point, lab half of A10 (A12 census)",
                );
            }
            if name == "killed_worker_settlement_recorded_without_retry" {
                text.push_str(" | kill-worker settlement, lab half of A11 (A12 census); orphan settled by the fixture (AC-027-ORPHAN)");
            }
            if matches!(
                name.as_str(),
                "grant_refused_from_another_session" | "grant_refused_from_a_new_session"
            ) {
                text.push_str(" | session binding of a Runtime grant on the run client's route, lab client sessions (M1 A5 half); a Public read earns no A5 credit");
            }
            text.push('\n');
        }
        (text, passed)
    }

    fn result(&self, name: &str, values: &[String]) -> String {
        if let Some(reasons) = self.skipped.get(name) {
            if values == ["FAILED"] && reasons.len() == 1 && !reasons[0].trim().is_empty() {
                format!("SKIPPED ({})", reasons[0])
            } else {
                "FAIL".into()
            }
        } else if values.len() == 1 {
            grade(name, &values[0], self.gap_rows(name)).unwrap_or_else(|_| "FAIL".into())
        } else {
            "FAIL".into()
        }
    }

    fn require_identities(&mut self) {
        if self.identities.runtime.is_none() {
            self.failures.push("missing Runtime SHA-256".into());
        }
        if self.identities.provider.is_none() {
            self.failures
                .push("missing localhost-provider SHA-256".into());
        }
        // A skipped probe row does not waive this. A per-effect miss keeps
        // its own reason below and does not replace it.
        if self.identities.launched.is_empty() {
            self.failures.push("missing launched probe identity".into());
        }
        for (name, values) in &self.rows {
            // These are identity requirements of existing journeys, not a test
            // inventory or grader. Cargo still supplies both of those. Failed
            // and missing results require identities too; blocked rows do not run.
            let result = self.result(name, values);
            if result.starts_with("BLOCKED") || result.starts_with("SKIPPED") {
                continue;
            }
            let effects = required_effects(name);
            if effects.is_empty() {
                continue;
            }
            for effect in effects {
                if !self.identities.launched.contains_key(*effect) {
                    self.failures
                        .push(format!("missing launched probe identity: {effect}"));
                }
            }
        }
    }
}

fn test_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_:".contains(&byte))
}

fn required_effects(test: &str) -> &'static [&'static str] {
    match test {
        "real_agent_host_gets_no_ungranted_authority" => &["agent-host"],
        "default_activation_refuses_without_selector" => &["default"],
        "granted_read_succeeds" | "run_leaves_no_live_grant" => &["granted-read"],
        "ungranted_sibling_read_is_refused" => &["sibling-read"],
        "attach_secret_stays_in_memory" => &[
            "granted-read",
            "sibling-read",
            "host-key-read",
            "instance-1",
            "instance-2",
        ],
        "two_instances_overlap_with_separate_grants"
        | "instance_grant_does_not_authorise_sibling"
        | "cancelled_instance_settles_with_reason_sibling_completes"
        | "killed_worker_settlement_recorded_without_retry" => &["instance-1", "instance-2"],
        "host_key_read_is_refused" => &["host-key-read"],
        "ungranted_effect_is_refused" => &["read"],
        "agent_cannot_read_human_space_without_grant" => &["human-read"],
        "ungranted_memory_write_is_refused" => &["memory-write"],
        "no_policy_file_does_not_mean_allow" => &["granted-read"],
        "process_isolation::parallel_instances_complete_independently" => {
            &["task-a", "task-b", "task-c", "task-d"]
        }
        "process_isolation::runaway_trap_is_bounded_while_siblings_finish"
        | "process_isolation::runaway_is_stopped_with_reason" => {
            &["runaway", "task-b", "task-c", "task-d"]
        }
        _ => &[],
    }
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Default)]
struct Identities {
    /// The Runtime identity line: the SHA-256 taken when the binary was named
    /// and the path it names. Identity lines are read from the whole output,
    /// and a line does not say which test printed it, so a second, different
    /// hash is a failure wherever it came from, and the first one is not
    /// treated as the Runtime that ran. Nothing here shows a launch; the
    /// record `run.sh` wrote carries that.
    runtime: Option<RuntimeIdentity>,
    /// Set when a later identity line named a different Runtime path or
    /// SHA-256 than the first. That line fails `versions_receipt` with
    /// `conflicting elastos SHA-256` or `conflicting elastos path`, and the
    /// installed-path row fails too: not every identity the suite recorded
    /// names the installed binary.
    runtime_conflict: bool,
    provider: Option<String>,
    built: BTreeMap<String, ProbeIdentity>,
    launched: BTreeMap<String, ProbeIdentity>,
}

/// The Runtime identity the suite printed: the SHA-256 it took of the file
/// first, and the path it was named to launch. `path` is None when the suite
/// built its own Runtime, which was named no path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeIdentity {
    pub path: Option<String>,
    pub sha256: String,
}

impl Identities {
    fn observe(&mut self, observation: Observation) -> Result<(), String> {
        match observation {
            Observation::Native { role, sha256, path } => match role.as_str() {
                "elastos" => {
                    if !hex(&sha256, 64) {
                        return Err(format!("malformed {role} SHA-256"));
                    }
                    if let Some(old) = &self.runtime {
                        if old.sha256 != sha256 {
                            self.runtime_conflict = true;
                            return Err(format!("conflicting {role} SHA-256"));
                        }
                        if old.path != path {
                            self.runtime_conflict = true;
                            return Err(format!("conflicting {role} path"));
                        }
                    }
                    self.runtime = Some(RuntimeIdentity { path, sha256 });
                }
                "localhost-provider" => {
                    if !hex(&sha256, 64) {
                        return Err(format!("malformed {role} SHA-256"));
                    }
                    if self.provider.as_ref().is_some_and(|old| old != &sha256) {
                        return Err(format!("conflicting {role} SHA-256"));
                    }
                    self.provider = Some(sha256);
                }
                _ => return Err("malformed native role".into()),
            },
            Observation::BuildOnly { probe } => return self.observe_probe(probe, false),
            Observation::Launched { probe } => return self.observe_probe(probe, true),
        }
        Ok(())
    }

    fn observe_probe(&mut self, probe: ProbeIdentity, launched: bool) -> Result<(), String> {
        if probe.effect.is_empty()
            || probe.effect.len() > 64
            || !probe
                .effect
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err("malformed probe effect".into());
        }
        if !hex(&probe.component_sha256, 64) {
            return Err(format!("malformed component SHA-256: {}", probe.effect));
        }
        if probe
            .bundle_lab_cid
            .parse::<capsule_identity::LabCid>()
            .is_err()
        {
            return Err(format!("malformed bundle lab CID: {}", probe.effect));
        }
        for previous in [&self.built, &self.launched] {
            if previous.get(&probe.effect).is_some_and(|old| old != &probe) {
                return Err(format!("conflicting probe identity: {}", probe.effect));
            }
        }
        let destination = if launched {
            &mut self.launched
        } else {
            &mut self.built
        };
        destination.insert(probe.effect.clone(), probe);
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GitIdentity {
    pub commit: String,
    pub dirty: bool,
}

impl GitIdentity {
    pub fn read(repository: &Path) -> Result<Self, &'static str> {
        let query = |args: &[&str]| {
            Command::new("git")
                .current_dir(repository)
                .env("GIT_OPTIONAL_LOCKS", "0")
                .args(args)
                .output()
                .ok()
                .filter(|output| output.status.success())
        };
        let head = query(&["rev-parse", "--verify", "HEAD"]).ok_or("Git commit query failed")?;
        let commit = std::str::from_utf8(&head.stdout)
            .map_err(|_| "malformed Git commit")?
            .trim()
            .to_owned();
        let status = query(&["status", "--porcelain=v1", "--untracked-files=all"])
            .ok_or("Git dirty-state query failed")?;
        let identity = Self {
            commit,
            dirty: !status.stdout.is_empty(),
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), &'static str> {
        if !hex(&self.commit, 40) && !hex(&self.commit, 64) {
            return Err("malformed Git commit");
        }
        Ok(())
    }
}

/// One review of the tested candidate. It binds only when it passed and names
/// the exact commit checked out, on a clean tree, when the report is written;
/// any other review leaves A14 unbound. It does not show that the suite's
/// results came from that tree.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub reviewer: String,
    pub verdict: String,
    pub commit: String,
}

/// Every reason the reviews do not bind to `git`; empty means bound.
pub fn review_failures(reviews: Option<&[Review]>, git: Option<&GitIdentity>) -> Vec<String> {
    let mut failures = Vec::new();
    let reviews = match reviews {
        Some(reviews) if !reviews.is_empty() => reviews,
        _ => return vec!["missing review".into()],
    };
    match git {
        None => failures.push("reviews cannot bind: no Git identity".into()),
        Some(git) if git.dirty => failures.push("reviews cannot bind: dirty tree".into()),
        Some(_) => {}
    }
    for review in reviews {
        let reviewer = &review.reviewer;
        if !test_name(reviewer) {
            failures.push("malformed review: reviewer".into());
            continue;
        }
        if review.verdict != "pass" {
            failures.push(format!("review did not pass: {reviewer}"));
        }
        if git.is_some_and(|git| git.commit != review.commit) {
            failures.push(format!("review names another commit: {reviewer}"));
        }
    }
    failures.sort();
    failures.dedup();
    failures
}

/// Why a reviews file at `reviews` cannot bind to the tree at `repository`; None
/// when it can. Reviews name the commit they read, so the file has to live
/// outside that tree: a tracked or ignored file inside it leaves the tree clean
/// and would otherwise bind. Two places are checked with their links resolved:
/// the file the path leads to, and the folder the path names it in. So a link
/// outside the tree to a file inside it is refused, and so is a link inside the
/// tree to a file outside it. A relative path is taken from the current
/// directory, as the read of the file takes it.
pub fn reviews_file_failure(reviews: &Path, repository: &Path) -> Option<String> {
    let folder = match reviews.parent() {
        Some(folder) if !folder.as_os_str().is_empty() => folder,
        _ => Path::new("."),
    };
    let (Ok(file), Ok(folder), Ok(repository)) = (
        reviews.canonicalize(),
        folder.canonicalize(),
        repository.canonicalize(),
    ) else {
        return Some("could not resolve the reviews file against the repository".into());
    };
    (file.starts_with(&repository) || folder.starts_with(&repository))
        .then(|| "reviews file is inside the repository".into())
}

/// The installed Runtime a receipt can name, from the records the installer
/// keeps. Only the hash chain is checked: release-head.json names the hash of
/// release.json, which names the binary and components.json for one platform.
/// The receipt then binds the source commit it finds to the repository commit
/// with `release_commit_failures`. Neither signature is verified, so this shows
/// which release the installed bytes match, not that the release is genuine.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct InstalledRuntime {
    /// The installed binary path the report was given, as given. The recorded
    /// path is compared with it after both are resolved to canonical paths.
    pub binary_path: PathBuf,
    pub version: String,
    pub platform: String,
    pub source_commit: String,
    pub release_sha256: String,
    pub binary_sha256: String,
    pub components_sha256: String,
}

/// Every reason the installed bytes do not match their release; Ok only when
/// none. `binary_path` is where the installed binary was read.
pub fn installed_runtime(
    binary_path: &Path,
    head: &[u8],
    release: &[u8],
    platform: &str,
    binary: &[u8],
    components: &[u8],
) -> Result<InstalledRuntime, Vec<String>> {
    let parse = |bytes: &[u8], name: &str| {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .map_err(|_| vec![format!("malformed {name}")])
    };
    let field = |value: &serde_json::Value, pointer: &str| {
        value
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    if platform.is_empty()
        || !platform
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        return Err(vec!["malformed platform".into()]);
    }
    let (head, record) = (parse(head, "release head")?, parse(release, "release")?);
    let [release_sha256, binary_sha256, components_sha256] =
        [release, binary, components].map(sha256);
    let entry = format!("/payload/platforms/{platform}");
    // `pointer` reads a digit token as an array index, so the platform is looked
    // up by key in an object: a `platforms` array names no platform.
    if !record
        .pointer("/payload/platforms")
        .and_then(serde_json::Value::as_object)
        .and_then(|platforms| platforms.get(platform))
        .is_some_and(serde_json::Value::is_object)
    {
        return Err(vec![format!("release names no entry for {platform}")]);
    }
    let mut failures = Vec::new();
    for (named, actual, reason) in [
        (
            field(&head, "/payload/release_sha256"),
            &release_sha256,
            "release head names another release",
        ),
        (
            field(&record, &format!("{entry}/binary/sha256")),
            &binary_sha256,
            "binary does not match the release",
        ),
        (
            field(&record, &format!("{entry}/components/sha256")),
            &components_sha256,
            "components do not match the release",
        ),
    ] {
        if named.as_ref() != Some(actual) {
            failures.push(reason.to_owned());
        }
    }
    let version = field(&record, "/payload/version");
    if version.is_none() || version != field(&head, "/payload/version") {
        failures.push("release head names another version".into());
    }
    let source_commit = field(&record, "/payload/source/commit").filter(|commit| hex(commit, 40));
    if source_commit.is_none() {
        failures.push("malformed release source commit".into());
    }
    if !failures.is_empty() {
        failures.sort();
        return Err(failures);
    }
    let (Some(version), Some(source_commit)) = (version, source_commit) else {
        // Each missing field above pushes its reason, so this arm is not
        // reachable today. It keeps Err non-empty if one of those checks is
        // ever weakened.
        return Err(vec!["release record omits a required field".into()]);
    };
    Ok(InstalledRuntime {
        binary_path: binary_path.to_path_buf(),
        version,
        platform: platform.to_owned(),
        source_commit,
        release_sha256,
        binary_sha256,
        components_sha256,
    })
}

/// Every reason an installed release cannot serve as the release of this
/// repository commit; empty means its source commit is the one the receipt
/// records. `git` is the identity `review_binding` binds the reviews to, so a
/// release built from another commit fails here even when its own hash chain is
/// consistent.
pub fn release_commit_failures(
    installed: &InstalledRuntime,
    git: Option<&GitIdentity>,
) -> Vec<String> {
    match git {
        None => vec!["no repository commit to bind the release source to".into()],
        Some(git) if git.commit != installed.source_commit => vec![format!(
            "release source commit {} differs from repository commit {}",
            installed.source_commit, git.commit
        )],
        Some(_) => Vec::new(),
    }
}

/// The launch record the receipt grades: one record `run.sh` wrote after the
/// suite to the private folder it made then, and passed to the report on its
/// own command line. A test's own output carries no record, so text that looks
/// like a launch cannot stand in for one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchRecord {
    /// The report was named no record file: nothing was recorded.
    Missing,
    /// The file could not be read, or held a line `run.sh` would not write.
    Unreadable(String),
    /// The record, in the file `run.sh` wrote.
    Records(Vec<Launch>),
}

impl LaunchRecord {
    /// Reads the file at `path`. Every non-empty line must be one record
    /// `run.sh` writes; a line that is not is refused as a whole, so a partly
    /// understood file is no evidence.
    pub fn read(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::Unreadable("could not read the launch record file".into());
        };
        let mut launches = Vec::new();
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let Some(launch) = Launch::parse_record(line) else {
                return Self::Unreadable("malformed launch record".into());
            };
            launches.push(launch);
        }
        Self::Records(launches)
    }
}

/// Every reason the receipt cannot show that `run.sh` launched the installed
/// path; empty means the file `run.sh` passed to the report holds exactly one
/// record, and that record names the installed binary's path with the SHA-256
/// `run.sh` took of that file immediately before its launch. `record` is the
/// file `run.sh` named on the report's command line; the identity line printed
/// when the binary was named comes before any launch and is not a record.
/// `installed` is the installed Runtime once its hash chain matched and bound
/// to this commit. The check is of paths and hashes: it does not see the bytes
/// the operating system then executed. The file is `run.sh`'s: `run.sh` writes
/// it only after the suite has exited and its liveness check found no
/// surviving suite process, into a folder it makes then that no test process
/// is given, and names its path only to the report.
///
/// The A14 threat model: the code at the reviewed commit — the suite, its
/// tests, `run.sh` and this report — is trusted, because each review names
/// that exact commit and the tree must be clean before the suite, after it and
/// when the report is written. This row must not pass by accident, by a test
/// that misbehaves, or by anything the suite run leaves behind. A deliberate
/// change written into the reviewed commit is outside this model: review
/// binding covers it, and same-user code cannot be fenced off without
/// operating-system isolation, which this tool does not claim. `run.sh` hashes
/// the report it built before the suite and again after it, refuses a change
/// with `reporter changed during the suite: <first> <now>`, and runs a copy of
/// the verified bytes from a folder no test process was given.
pub fn installed_binary_launched_failures(
    record: &LaunchRecord,
    installed: Option<&InstalledRuntime>,
) -> Vec<String> {
    let Some(installed) = installed else {
        return vec!["no matched installed Runtime to compare".into()];
    };
    let launches = match record {
        LaunchRecord::Missing => return vec!["no launch record file".into()],
        LaunchRecord::Unreadable(reason) => return vec![reason.clone()],
        LaunchRecord::Records(launches) => launches,
    };
    if launches.is_empty() {
        return vec!["run.sh wrote no launch record for the installed path".into()];
    }
    if launches.len() != 1 {
        return vec![format!(
            "run.sh wrote {} launch records; exactly one is required",
            launches.len()
        )];
    }
    let launched = &launches[0];
    let Ok(installed_path) = std::fs::canonicalize(&installed.binary_path) else {
        return vec![format!(
            "could not resolve the installed binary path {}",
            installed.binary_path.display()
        )];
    };
    let Ok(named) = std::fs::canonicalize(&launched.path) else {
        return vec![format!(
            "could not resolve the launched path {} against the installed binary {}",
            launched.path,
            installed_path.display()
        )];
    };
    let mut failures = Vec::new();
    if named != installed_path {
        failures.push(format!(
            "run.sh launched {}, not the installed binary {}",
            named.display(),
            installed_path.display()
        ));
    } else if launched.sha256 != installed.binary_sha256 {
        failures.push(format!(
            "run.sh launched a Runtime with SHA-256 {}, installed binary is {}",
            launched.sha256, installed.binary_sha256
        ));
    }
    failures
}

/// Every reason the suite's own record does not show it ran the installed
/// binary; empty means the suite was told to launch a named binary
/// (`AGENT_CONFORMANCE_RUNTIME_BINARY`, `named` here) whose canonical path is
/// the installed binary's, and the one Runtime identity it recorded names that
/// path and that binary's SHA-256. `named` is the variable's value as `run.sh`
/// passed it through the environment; the report reads no test output for it.
/// A suite that was told nothing builds the checkout, so its launches are not
/// the installed binary and the row fails.
///
/// Identity lines come from the suite's own output: the code at the reviewed
/// commit prints them at the spawn point, before any Runtime starts, and a
/// test that deliberately wrote a different line would have to be written into
/// that reviewed commit. Review binding covers such a change, so these lines
/// are trusted on the same basis as the rest of the reviewed code.
pub fn suite_runtime_failures(
    suite: Option<&RuntimeIdentity>,
    named: Option<&Path>,
    installed: Option<&InstalledRuntime>,
) -> Vec<String> {
    let Some(installed) = installed else {
        return vec!["no matched installed Runtime to compare".into()];
    };
    let Ok(installed_path) = std::fs::canonicalize(&installed.binary_path) else {
        return vec![format!(
            "could not resolve the installed binary path {}",
            installed.binary_path.display()
        )];
    };
    let mut failures = Vec::new();
    match named {
        None => failures.push(
            "the suite was not told to launch a named binary (AGENT_CONFORMANCE_RUNTIME_BINARY unset); it builds the checkout, so its launches are not the installed binary".into(),
        ),
        Some(named) => match std::fs::canonicalize(named) {
            Ok(named) if named != installed_path => failures.push(format!(
                "the suite was told to launch {}, not the installed binary {}",
                named.display(),
                installed_path.display()
            )),
            Ok(_) => {}
            Err(_) => failures.push(format!(
                "could not resolve the named suite Runtime path {}",
                named.display()
            )),
        },
    }
    match suite {
        None => failures.push("the suite recorded no Runtime identity".into()),
        Some(suite) => {
            match &suite.path {
                None => failures.push(
                    "the suite recorded no named Runtime path; it built its own Runtime".into(),
                ),
                Some(path) => match std::fs::canonicalize(path) {
                    Ok(path) if path != installed_path => failures.push(format!(
                        "the suite recorded Runtime path {}, not the installed binary {}",
                        path.display(),
                        installed_path.display()
                    )),
                    Ok(_) => {}
                    Err(_) => failures.push(format!(
                        "could not resolve the suite's Runtime path {}",
                        path
                    )),
                },
            }
            if suite.sha256 != installed.binary_sha256 {
                failures.push(format!(
                    "the suite recorded Runtime SHA-256 {}, installed binary is {}",
                    suite.sha256, installed.binary_sha256
                ));
            }
        }
    }
    failures
}

/// The key a release uses for this machine's platform, as the Runtime's own
/// update check spells it.
pub fn release_platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-linux",
        ("linux", "aarch64") => "aarch64-linux",
        ("macos", "x86_64") => "x86_64-darwin",
        ("macos", "aarch64") => "aarch64-darwin",
        _ => "unknown",
    }
}

/// Reads an installed Runtime from where the installer keeps it and checks it
/// with `installed_runtime`: the binary at `binary`, and under `data` the files
/// `installation/release-head.json`, `installation/release.json` and
/// `components.json`. A file that cannot be read is its own reason, named by
/// file; nothing is checked until all four are read.
///
/// Each of the four is opened without following a link at its final name, and
/// must be a regular file: the Runtime admits its installed files the same way,
/// so a link there is refused with its own reason, not read through to some
/// other file. The open itself refuses the link, so there is no gap between a
/// check and the read. The folders above the four names are not checked.
///
/// What this does not check:
/// - signatures: only hashes are compared, so a match shows which release the
///   installed bytes belong to, not that the release is genuine;
/// - the bundle's hash: the capsule bundle the demo ran is not compared with
///   anything installed;
/// - that run.sh launched this path: `installed_binary_launched_failures`
///   compares the paths and the two hashes for the receipt's own row;
/// - behaviour on the installed data: only these records are read from the
///   installed data folder, and the Runtime under test runs with a throwaway
///   data folder of its own.
pub fn read_installed_runtime(
    binary: &Path,
    data: &Path,
    platform: &str,
) -> Result<InstalledRuntime, Vec<String>> {
    let mut failures = Vec::new();
    let mut read = |path: &Path, name: &str| {
        read_installed_file(path).unwrap_or_else(|reason| {
            failures.push(match reason {
                Unread::Link => format!("{name} is a symbolic link"),
                Unread::NotAFile => format!("{name} is not a regular file"),
                Unread::Other => format!("could not read {name}"),
            });
            Vec::new()
        })
    };
    let installation = data.join("installation");
    let head = read(&installation.join("release-head.json"), "release-head.json");
    let release = read(&installation.join("release.json"), "release.json");
    let program = read(binary, "the installed binary");
    let components = read(&data.join("components.json"), "components.json");
    if !failures.is_empty() {
        failures.sort();
        return Err(failures);
    }
    installed_runtime(binary, &head, &release, platform, &program, &components)
}

enum Unread {
    Link,
    NotAFile,
    Other,
}

/// The bytes of the regular file at `path`, never those of a link's target.
fn read_installed_file(path: &Path) -> Result<Vec<u8>, Unread> {
    use std::os::unix::fs::OpenOptionsExt;
    // NOFOLLOW makes the open fail on a link at the final name. NONBLOCK keeps
    // the open from waiting on a pipe placed there; it does nothing to a file.
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
                Unread::Link
            } else {
                Unread::Other
            }
        })?;
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(Unread::NotAFile);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| Unread::Other)?;
    Ok(bytes)
}

/// A missing, repeated or unlisted result fails closed. Cargo failure is also
/// visible even if compilation or a test binary failed before reporting a row.
pub fn table(listed: &str, output: &str, cargo_ok: bool, gaps: Option<&str>) -> (String, bool) {
    Evidence::parse(listed, output, gaps).table(cargo_ok)
}

pub struct RunReport {
    pub receipt_written: bool,
    pub receipt_bytes: Vec<u8>,
    pub table: String,
    pub passed: bool,
    pub failures: Vec<String>,
}

/// One parse, one table and one exclusive receipt. Only typed identities and
/// graded rows enter JSON; child output, HTTP bodies and environment do not.
pub fn write_run(
    listed: &str,
    output: &str,
    cargo_ok: bool,
    git: Result<GitIdentity, &str>,
    receipt: &Path,
    gaps: Option<&str>,
) -> RunReport {
    write_reviewed_run(listed, output, cargo_ok, git, None, receipt, gaps)
}

/// `write_run` with the reviews of the tested commit. Review binding is its own
/// table row and receipt field; it does not change the suite's command result.
pub fn write_reviewed_run(
    listed: &str,
    output: &str,
    cargo_ok: bool,
    git: Result<GitIdentity, &str>,
    reviews: Option<&[Review]>,
    receipt: &Path,
    gaps: Option<&str>,
) -> RunReport {
    let bound = Bound {
        reviews,
        reviews_file_failure: None,
        tree_check_failure: None,
        installed: None,
        launch_record: LaunchRecord::Missing,
        named_runtime: None,
    };
    write_bound_run(listed, output, cargo_ok, git, bound, receipt, gaps)
}

/// What a receipt binds beside the suite's own rows: the reviews of the tested
/// commit and, when one was given, the installed Runtime.
pub struct Bound<'a> {
    pub reviews: Option<&'a [Review]>,
    /// From `reviews_file_failure`: why the file the reviews were read from
    /// cannot bind, whatever the reviews say. `None` when it can, or when the
    /// reviews did not come from a file.
    pub reviews_file_failure: Option<String>,
    /// From a check around the suite: why the tree was not clean then. `None`
    /// when every such check saw a clean tree. `review_binding` fails on it, so
    /// a tree found dirty before or after the suite, or when the receipt is
    /// written, cannot bind reviews.
    pub tree_check_failure: Option<String>,
    /// `None` means no installed Runtime was given: the receipt then carries no
    /// installed Runtime row or field at all.
    pub installed: Option<Result<InstalledRuntime, Vec<String>>>,
    /// The launch record read from the private folder run.sh made after the
    /// suite and named on the command line. `Missing` means the report was
    /// named no file, so the installed-path row has no launch evidence.
    pub launch_record: LaunchRecord,
    /// The binary `run.sh`'s environment named for the suite
    /// (`AGENT_CONFORMANCE_RUNTIME_BINARY`), as given. `None` means the
    /// variable was unset, so the suite built the checkout.
    pub named_runtime: Option<PathBuf>,
}

/// `write_reviewed_run` with the installed Runtime. Like review binding, the
/// installed Runtime has its own table rows and receipt fields: one for its
/// hash chain and one for whether run.sh launched that path and saw it answer.
/// A row that fails does not change the suite's command result.
pub fn write_bound_run(
    listed: &str,
    output: &str,
    cargo_ok: bool,
    git: Result<GitIdentity, &str>,
    bound: Bound<'_>,
    receipt: &Path,
    gaps: Option<&str>,
) -> RunReport {
    let mut report = render_bound_run(listed, output, cargo_ok, git, bound, gaps);
    let written = write_exclusive(receipt, &report.receipt_bytes);
    report.receipt_written = written.is_ok();
    if let Err(reason) = written {
        report.table = report.table.replace(
            "versions_receipt (A14) | PASS",
            "versions_receipt (A14) | FAIL",
        );
        report.failures.push(reason);
        report.passed = false;
    }
    report
}

/// The writer and credential acceptance use these same in-memory bytes.
pub fn render_run(
    listed: &str,
    output: &str,
    cargo_ok: bool,
    git: Result<GitIdentity, &str>,
    gaps: Option<&str>,
) -> RunReport {
    render_reviewed_run(listed, output, cargo_ok, git, None, gaps)
}

pub fn render_reviewed_run(
    listed: &str,
    output: &str,
    cargo_ok: bool,
    git: Result<GitIdentity, &str>,
    reviews: Option<&[Review]>,
    gaps: Option<&str>,
) -> RunReport {
    let bound = Bound {
        reviews,
        reviews_file_failure: None,
        tree_check_failure: None,
        installed: None,
        launch_record: LaunchRecord::Missing,
        named_runtime: None,
    };
    render_bound_run(listed, output, cargo_ok, git, bound, gaps)
}

/// `render_reviewed_run` with the installed Runtime; `write_bound_run` writes
/// these same bytes.
pub fn render_bound_run(
    listed: &str,
    output: &str,
    cargo_ok: bool,
    git: Result<GitIdentity, &str>,
    bound: Bound<'_>,
    gaps: Option<&str>,
) -> RunReport {
    let Bound {
        reviews,
        reviews_file_failure,
        tree_check_failure,
        installed,
        launch_record,
        named_runtime,
    } = bound;
    let mut evidence = Evidence::parse(listed, output, gaps);
    let (mut table, suite_ok) = evidence.table(cargo_ok);
    evidence.require_identities();
    let git = match git.and_then(|git| git.validate().map(|()| git)) {
        Ok(git) => Some(git),
        Err(reason) => {
            evidence.failures.push(reason.into());
            None
        }
    };
    // The installed release must be the release of the commit this receipt
    // records, the same commit `review_binding` binds the reviews to. A record
    // whose chain matched but names another source commit fails the installed
    // rows, naming both commits.
    let installed = installed.map(|installed| {
        installed.and_then(|record| {
            let failures = release_commit_failures(&record, git.as_ref());
            if failures.is_empty() {
                Ok(record)
            } else {
                Err(failures)
            }
        })
    });
    evidence.failures.sort();
    evidence.failures.dedup();
    let complete = evidence.failures.is_empty();
    table.push_str(if complete {
        "versions_receipt (A14) | PASS\n"
    } else {
        "versions_receipt (A14) | FAIL\n"
    });
    let mut unbound = review_failures(reviews, git.as_ref());
    unbound.extend(reviews_file_failure);
    unbound.extend(tree_check_failure);
    unbound.sort();
    table.push_str(if unbound.is_empty() {
        "review_binding (A14) | PASS\n"
    } else {
        "review_binding (A14) | FAIL\n"
    });
    // The bundles are the ones the suite staged from this checkout and launched.
    // No installed Runtime keeps a record of them, so the row says "staged".
    let staged: BTreeSet<&str> = evidence
        .identities
        .launched
        .values()
        .map(|probe| probe.bundle_lab_cid.as_str())
        .collect();
    let unstaged: &[&str] = if staged.is_empty() {
        &["suite launched no staged bundle"]
    } else {
        &[]
    };
    table.push_str(&format!(
        "staged_bundle (A14) | {} | {STAGED_BUNDLE_SCOPE}\n",
        if unstaged.is_empty() { "PASS" } else { "FAIL" }
    ));
    // Whether the installed path ran is asked only when an installed Runtime
    // was given. Two records answer it: the file `run.sh` wrote after the suite
    // (paths and hashes of its one launch), and the suite's own Runtime
    // identity (the path it was told to launch beside the hash it took then).
    // The identity line is printed at the spawn point and carries no launch;
    // the file is made after the suite, and no test process is given its path.
    let not_launched = installed.as_ref().map(|installed| {
        let mut failures =
            installed_binary_launched_failures(&launch_record, installed.as_ref().ok());
        failures.extend(suite_runtime_failures(
            evidence.identities.runtime.as_ref(),
            named_runtime.as_deref(),
            installed.as_ref().ok(),
        ));
        if evidence.identities.runtime_conflict {
            failures.push(
                "the suite recorded conflicting Runtime identities; not every one names the installed binary"
                    .into(),
            );
        }
        failures.sort();
        failures.dedup();
        failures
    });
    if let Some(installed) = &installed {
        table.push_str(&format!(
            "installed_runtime (A14) | {} | {INSTALLED_RUNTIME_SCOPE}\n",
            if installed.is_ok() { "PASS" } else { "FAIL" }
        ));
    }
    if let Some(not_launched) = &not_launched {
        table.push_str(&format!(
            "installed_runtime_ran (A14) | {} | {INSTALLED_RUNTIME_BINARY_SCOPE}\n",
            if not_launched.is_empty() {
                "PASS"
            } else {
                "FAIL"
            }
        ));
    }
    let outcome = if !suite_ok {
        "FAIL"
    } else if table.contains(" | SKIPPED") {
        "SKIPPED"
    } else if table.contains(" | BLOCKED") {
        "BLOCKED"
    } else {
        "PASS"
    };
    let mut document = serde_json::json!({
        "schema": "agent-conformance.versions/v1",
        "description": "Version evidence only. The bundle lab CID and any separate signed record give zero admission or permission credit. Runtime decides admission; resource authority requires a Runtime grant for the requesting session. Only the observed Runtime journey supplies that evidence.",
        "identity_status": if complete { "complete" } else { "incomplete" },
        "repository": git,
        "runtime_sha256": evidence
            .identities
            .runtime
            .as_ref()
            .map(|runtime| &runtime.sha256),
        "runtime_path": evidence
            .identities
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.path.as_deref()),
        "localhost_provider_sha256": evidence.identities.provider,
        "probes": evidence.identities.launched.values().collect::<Vec<_>>(),
        "build_only_probes": evidence.identities.built.values().collect::<Vec<_>>(),
        "missing_or_invalid": evidence.failures,
        "reviews": reviews,
        "review_status": if unbound.is_empty() { "bound" } else { "unbound" },
        "review_failures": unbound,
        "staged_bundles": staged,
        "staged_bundle_status": if unstaged.is_empty() { "recorded" } else { "missing" },
        "staged_bundle_failures": unstaged,
        "staged_bundle_scope": STAGED_BUNDLE_SCOPE,
        "cargo_success": cargo_ok,
        "suite_outcome": outcome,
        "command_success": suite_ok && complete,
        "scope": "process isolation; diagnostic results; capsule isolation remains blocked",
        "instance_grants_scope": INSTANCE_GRANTS_SCOPE,
        "report": { "table": table, "sha256": sha256(table.as_bytes()) },
    });
    if let Some(installed) = installed {
        let (record, unmatched) = match installed {
            Ok(record) => (Some(record), Vec::new()),
            Err(reasons) => (None, reasons),
        };
        document["installed_runtime_status"] = if record.is_some() {
            "matched"
        } else {
            "unmatched"
        }
        .into();
        document["installed_runtime"] = serde_json::json!(record);
        document["installed_runtime_failures"] = unmatched.into();
        document["runtime_data_folder"] = RUNTIME_DATA_FOLDER.into();
    }
    if let Some(not_launched) = not_launched {
        document["installed_binary_launch_status"] = if not_launched.is_empty() {
            "run_sh_launched_installed_path_hash_matched"
        } else {
            "not_run_sh_launched_installed_path_hash_matched"
        }
        .into();
        document["installed_binary_launch_failures"] = not_launched.into();
    }
    let receipt_bytes = serde_json::to_vec_pretty(&document)
        .map(|mut bytes| {
            bytes.push(b'\n');
            bytes
        })
        .unwrap_or_else(|_| {
            evidence
                .failures
                .push("receipt serialization failed".into());
            Vec::new()
        });
    RunReport {
        receipt_written: false,
        receipt_bytes,
        table,
        passed: suite_ok && evidence.failures.is_empty(),
        failures: evidence.failures,
    }
}

/// One A14 row read back from a receipt: its name, whether it reads PASS, and
/// the reasons the receipt gives when it does not.
#[derive(Debug, PartialEq, Eq)]
pub struct A14Row {
    pub name: &'static str,
    pub passed: bool,
    pub reasons: Vec<String>,
}

/// The A14 rows of a written receipt, for the owner's command. All five must
/// be present: a receipt made without an installed Runtime has no installed
/// rows, and that is a failure here, named as a missing row. A row passes only
/// when the table holds it exactly once and its grade is exactly `PASS`: a
/// second copy fails it whatever the copies say, and so does any other grade.
/// The rows are read from the receipt's own table after the table is checked
/// against the hash the receipt records for it.
pub fn a14_rows(receipt: &[u8]) -> Result<Vec<A14Row>, String> {
    let document: serde_json::Value =
        serde_json::from_slice(receipt).map_err(|_| "malformed receipt")?;
    let table = document["report"]["table"]
        .as_str()
        .ok_or("receipt has no table")?;
    if document["report"]["sha256"].as_str() != Some(sha256(table.as_bytes()).as_str()) {
        return Err("receipt table does not match its recorded hash".into());
    }
    let rows = [
        ("versions_receipt", "missing_or_invalid"),
        ("review_binding", "review_failures"),
        ("staged_bundle", "staged_bundle_failures"),
        ("installed_runtime", "installed_runtime_failures"),
        ("installed_runtime_ran", "installed_binary_launch_failures"),
    ];
    Ok(rows
        .into_iter()
        .map(|(name, field)| {
            let prefix = format!("{name} (A14) | ");
            let grades: Vec<_> = table
                .lines()
                .filter_map(|line| line.strip_prefix(prefix.as_str()))
                .map(|rest| rest.split(" | ").next().unwrap_or_default())
                .collect();
            let passed = grades == ["PASS"];
            let mut reasons: Vec<String> = document[field]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|reason| reason.as_str().map(str::to_owned))
                .collect();
            if grades.is_empty() {
                reasons.push("row missing from the receipt".into());
            } else if grades.len() > 1 {
                reasons.push("row appears more than once in the receipt".into());
            } else if !passed && reasons.is_empty() {
                reasons.push("receipt gives no reason".into());
            }
            A14Row {
                name,
                passed,
                reasons,
            }
        })
        .collect())
}

fn write_exclusive(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("receipt serialization failed".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("receipt write failed: {:?}", error.kind()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("receipt write failed: {:?}", error.kind()))
}
