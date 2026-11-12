//! Cargo owns inventory/results. This parser owns both the table and receipt.

use crate::identity::{sha256, Observation, ProbeIdentity, PREFIX};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
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
    runtime: Option<String>,
    provider: Option<String>,
    built: BTreeMap<String, ProbeIdentity>,
    launched: BTreeMap<String, ProbeIdentity>,
}

impl Identities {
    fn observe(&mut self, observation: Observation) -> Result<(), String> {
        match observation {
            Observation::Native { role, sha256 } => {
                let slot = match role.as_str() {
                    "elastos" => &mut self.runtime,
                    "localhost-provider" => &mut self.provider,
                    _ => return Err("malformed native role".into()),
                };
                if !hex(&sha256, 64) {
                    return Err(format!("malformed {role} SHA-256"));
                }
                if slot.as_ref().is_some_and(|old| old != &sha256) {
                    return Err(format!("conflicting {role} SHA-256"));
                }
                *slot = Some(sha256);
            }
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

/// The installed Runtime a receipt can name, from the records the installer
/// keeps. Only the hash chain is checked: release-head.json names the hash of
/// release.json, which names the binary and components.json for one platform.
/// Neither signature is verified, so this shows which release the installed
/// bytes match, not that the release is genuine.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct InstalledRuntime {
    pub version: String,
    pub platform: String,
    pub source_commit: String,
    pub release_sha256: String,
    pub binary_sha256: String,
    pub components_sha256: String,
}

/// Every reason the installed bytes do not match their release; Ok only when
/// none.
pub fn installed_runtime(
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
        version,
        platform: platform.to_owned(),
        source_commit,
        release_sha256,
        binary_sha256,
        components_sha256,
    })
}

/// Every reason the receipt cannot say the suite ran the installed binary; empty
/// means the Runtime the suite launched has the installed binary's SHA-256.
/// `ran` is the hash the suite printed for the Runtime it launched; `installed`
/// is the installed Runtime once its hash chain matched. This compares bytes
/// by hash: it does not show which of the suite's rows launched that Runtime.
pub fn installed_runtime_ran_failures(
    ran: Option<&str>,
    installed: Option<&InstalledRuntime>,
) -> Vec<String> {
    match (ran, installed) {
        (_, None) => vec!["no matched installed Runtime to compare".into()],
        (None, Some(_)) => vec!["suite recorded no Runtime SHA-256".into()],
        (Some(ran), Some(installed)) if ran != installed.binary_sha256 => vec![format!(
            "suite ran Runtime {ran}, installed binary is {}",
            installed.binary_sha256
        )],
        _ => Vec::new(),
    }
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
/// What this does not check:
/// - signatures: only hashes are compared, so a match shows which release the
///   installed bytes belong to, not that the release is genuine;
/// - the bundle's hash: the capsule bundle the demo ran is not compared with
///   anything installed;
/// - that the suite ran this binary: `installed_runtime_ran_failures` compares
///   the two hashes for the receipt's own row.
pub fn read_installed_runtime(
    binary: &Path,
    data: &Path,
    platform: &str,
) -> Result<InstalledRuntime, Vec<String>> {
    let mut failures = Vec::new();
    let mut read = |path: &Path, name: &str| {
        std::fs::read(path).unwrap_or_else(|_| {
            failures.push(format!("could not read {name}"));
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
    installed_runtime(&head, &release, platform, &program, &components)
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
        installed: None,
    };
    write_bound_run(listed, output, cargo_ok, git, bound, receipt, gaps)
}

/// What a receipt binds beside the suite's own rows: the reviews of the tested
/// commit and, when one was given, the installed Runtime.
pub struct Bound<'a> {
    pub reviews: Option<&'a [Review]>,
    /// `None` means no installed Runtime was given: the receipt then carries no
    /// installed Runtime row or field at all.
    pub installed: Option<Result<InstalledRuntime, Vec<String>>>,
}

/// `write_reviewed_run` with the installed Runtime. Like review binding, the
/// installed Runtime has its own table rows and receipt fields: one for its
/// hash chain and one for whether the suite ran that binary. A row that fails
/// does not change the suite's command result.
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
        installed: None,
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
    let Bound { reviews, installed } = bound;
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
    evidence.failures.sort();
    evidence.failures.dedup();
    let complete = evidence.failures.is_empty();
    table.push_str(if complete {
        "versions_receipt (A14) | PASS\n"
    } else {
        "versions_receipt (A14) | FAIL\n"
    });
    let unbound = review_failures(reviews, git.as_ref());
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
    // Whether the suite ran the installed binary is asked only when an
    // installed Runtime was given.
    let not_ran = installed.as_ref().map(|installed| {
        installed_runtime_ran_failures(
            evidence.identities.runtime.as_deref(),
            installed.as_ref().ok(),
        )
    });
    if let Some(installed) = &installed {
        table.push_str(if installed.is_ok() {
            "installed_runtime (A14) | PASS\n"
        } else {
            "installed_runtime (A14) | FAIL\n"
        });
    }
    if let Some(not_ran) = &not_ran {
        table.push_str(if not_ran.is_empty() {
            "installed_runtime_ran (A14) | PASS\n"
        } else {
            "installed_runtime_ran (A14) | FAIL\n"
        });
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
        "runtime_sha256": evidence.identities.runtime,
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
    }
    if let Some(not_ran) = not_ran {
        document["installed_runtime_ran_status"] = if not_ran.is_empty() {
            "ran"
        } else {
            "not shown"
        }
        .into();
        document["installed_runtime_ran_failures"] = not_ran.into();
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
/// rows, and that is a failure here, named as a missing row. The rows are read
/// from the receipt's own table after the table is checked against the hash the
/// receipt records for it.
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
        ("installed_runtime_ran", "installed_runtime_ran_failures"),
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
