//! Cargo owns inventory/results. This parser owns both the table and receipt.

use crate::identity::{sha256, Observation, ProbeIdentity, PREFIX};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::process::Command;

fn grade(result: &str) -> String {
    if result == "ok" {
        return "PASS".into();
    }
    if let Some(reason) = result.strip_prefix("ignored, blocked: ") {
        if let Some(id) = reason.split_whitespace().next() {
            return format!("BLOCKED ({id})");
        }
    }
    "FAIL".into()
}

#[derive(Default)]
struct Evidence {
    rows: BTreeMap<String, Vec<String>>,
    identities: Identities,
    failures: Vec<String>,
    duplicate_inventory: bool,
}

impl Evidence {
    fn parse(listed: &str, output: &str) -> Self {
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
                values.push(grade(result));
            }
        }
        evidence
    }

    fn table(&self, cargo_ok: bool) -> (String, bool) {
        let mut text = String::from("test | PASS/FAIL/BLOCKED (id)\n");
        if self.duplicate_inventory {
            text.push_str("cargo | FAIL\n");
            return (text, false);
        }
        let mut passed = cargo_ok && !self.rows.is_empty();
        if !passed {
            text.push_str("cargo | FAIL\n");
        }
        for (name, values) in &self.rows {
            let result = if values.len() == 1 {
                &values[0]
            } else {
                "FAIL"
            };
            passed &= result != "FAIL";
            text.push_str(&format!("{name} | {result}\n"));
        }
        (text, passed)
    }

    fn require_identities(&mut self) {
        if self.identities.runtime.is_none() {
            self.failures.push("missing Runtime SHA-256".into());
        }
        if self.identities.provider.is_none() {
            self.failures
                .push("missing localhost-provider SHA-256".into());
        }
        if self.identities.launched.is_empty() {
            self.failures.push("missing launched probe identity".into());
        }
        for (name, values) in &self.rows {
            // These are identity requirements of existing journeys, not a test
            // inventory or grader. Cargo still supplies both of those. Failed
            // and missing results require identities too; blocked rows do not run.
            if values.len() == 1
                && (values[0].starts_with("BLOCKED") || values[0].starts_with("SKIPPED"))
            {
                continue;
            }
            for effect in required_effects(name) {
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
        "default_activation_refuses_without_selector" => &["default"],
        "ungranted_effect_is_refused" => &["read"],
        "ungranted_network_is_refused" => &["network"],
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
            .strip_prefix(capsule_identity::LAB_CID_PREFIX)
            .is_some_and(|value| hex(value, 64))
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
pub fn table(listed: &str, output: &str, cargo_ok: bool) -> (String, bool) {
    Evidence::parse(listed, output).table(cargo_ok)
}

pub struct RunReport {
    pub receipt_written: bool,
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
) -> RunReport {
    let mut evidence = Evidence::parse(listed, output);
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
        "report": { "table": table, "sha256": sha256(table.as_bytes()) },
    });
    let written = write_exclusive(receipt, &document);
    let receipt_written = written.is_ok();
    if let Err(reason) = written {
        table = table.replace(
            "versions_receipt (A14) | PASS",
            "versions_receipt (A14) | FAIL",
        );
        evidence.failures.push(reason);
    }
    RunReport {
        receipt_written,
        table,
        passed: suite_ok && evidence.failures.is_empty(),
        failures: evidence.failures,
    }
}

fn write_exclusive(path: &Path, document: &serde_json::Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(document).map_err(|_| "receipt serialization failed")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("receipt write failed: {:?}", error.kind()))?;
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("receipt write failed: {:?}", error.kind()))
}
