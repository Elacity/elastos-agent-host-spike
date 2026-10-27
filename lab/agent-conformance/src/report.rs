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
                if !test_name(name) {
                    evidence.duplicate_inventory = true;
                } else if evidence.rows.insert(name.into(), Vec::new()).is_some() {
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
                text.push_str(" | process-isolation lab half of A3, A6 and A9");
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
        "ungranted_network_is_refused" => &["network"],
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
        if !probe
            .bundle_lab_cid
            .parse::<capsule_identity::LabCid>()
            .is_ok()
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
    let mut report = render_run(listed, output, cargo_ok, git, gaps);
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
    let outcome = if !suite_ok {
        "FAIL"
    } else if table.contains(" | SKIPPED") {
        "SKIPPED"
    } else if table.contains(" | BLOCKED") {
        "BLOCKED"
    } else {
        "PASS"
    };
    let document = serde_json::json!({
        "schema": "agent-conformance.versions/v1",
        "description": "Version evidence only. The bundle lab CID and any separate signed record give zero admission or permission credit. Runtime decides admission; resource authority requires a Runtime grant for the requesting session. Only the observed Runtime journey supplies that evidence.",
        "identity_status": if complete { "complete" } else { "incomplete" },
        "repository": git,
        "runtime_sha256": evidence.identities.runtime,
        "localhost_provider_sha256": evidence.identities.provider,
        "probes": evidence.identities.launched.values().collect::<Vec<_>>(),
        "build_only_probes": evidence.identities.built.values().collect::<Vec<_>>(),
        "missing_or_invalid": evidence.failures,
        "cargo_success": cargo_ok,
        "suite_outcome": outcome,
        "command_success": suite_ok && complete,
        "scope": "process isolation; diagnostic results; capsule isolation remains blocked",
        "instance_grants_scope": "process-isolation lab half of A3, A6 and A9",
        "report": { "table": table, "sha256": sha256(table.as_bytes()) },
    });
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
