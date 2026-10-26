use agent_conformance::report::table;

#[test]
fn run_table_requires_cargo_results() {
    let listed = "works: test\nblocked: test\n";
    let output = "test works ... ok\ntest blocked ... ignored, blocked: RT3 model grant\n";
    assert_eq!(
        table(listed, output, true),
        (
            "test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\nblocked | BLOCKED (RT3 model grant)\nworks | PASS\n".into(),
            true
        )
    );
    for result in ["FAILED", "ignored", "ignored, blocked: ", "", "unknown"] {
        let (text, passed) = table("case: test\n", &format!("test case ... {result}\n"), true);
        assert!(!passed, "result must fail: {result}");
        assert!(text.contains("case | FAIL\n"));
    }
    for output in ["", "test case ... ok\ntest case ... ok\n"] {
        assert_eq!(
            table("case: test\n", output, true),
            (
                "test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\ncase | FAIL\n".into(),
                false
            )
        );
    }
    assert!(!table(listed, output, false).1);
    assert!(!table("", "test unlisted ... ok\n", true).1);
    assert!(!table("", "", true).1);
    assert!(!table("case: test\ncase: test\n", "test case ... ok\n", true).1);
    let (blocked, passed) = table(
        "memory: test\n",
        "test memory ... ignored, blocked: UsersAI binding; AC-002-ARGS\n",
        true,
    );
    assert!(passed);
    assert!(blocked.contains("memory | BLOCKED (UsersAI binding; AC-002-ARGS)\n"));
    let name = "process_isolation::parallel_instances_complete_independently";
    assert_eq!(
        table(
            &format!("{name}: test\n"),
            &format!("test {name} ... ok\n"),
            true
        )
        .0,
        format!("test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\n{name} | PASS\n")
    );
    let home = ThrowawayHome::new().unwrap();
    let (observations, git) = synthetic(1, true);
    for (index, (result, cargo_ok, expected, outcome)) in [
        ("ok", true, true, "PASS"),
        ("FAILED", true, false, "FAIL"),
        ("ok", false, false, "FAIL"),
        ("ignored, blocked: RT3 model grant", true, true, "BLOCKED"),
        ("ignored", true, false, "FAIL"),
    ]
    .into_iter()
    .enumerate()
    {
        let path = home.root().join(format!("combined-{index}.json"));
        let evidence = self::output(&observations).replace(
            &format!("test {LIVE} ... ok"),
            &format!("test {LIVE} ... {result}"),
        );
        let combined = write_run(
            &format!("{LIVE}: test\n"),
            &evidence,
            cargo_ok,
            Ok(git.clone()),
            &path,
        );
        assert_eq!(combined.passed, expected);
        assert_eq!(read_receipt(&path)["suite_outcome"], outcome);
        assert!(combined.table.contains("versions_receipt (A14) | PASS\n"));
        assert_eq!(read_receipt(&path)["report"]["table"], combined.table);
    }
    let no_identity = write_run(
        "case: test\n",
        "test case ... ok\n",
        true,
        Ok(git),
        &home.root().join("incomplete.json"),
    );
    assert!(!no_identity.passed);
    assert!(no_identity.table.contains("case | PASS\n"));
    assert!(no_identity
        .table
        .contains("versions_receipt (A14) | FAIL\n"));
    home.finish().unwrap();
}

#[test]
fn run_table_grades_blocker_lists_by_one_rule() {
    for (reason, expected) in [
        ("RT4", "BLOCKED (RT4)"),
        ("UsersAI binding", "BLOCKED (UsersAI binding)"),
        (
            "UsersAI binding; AC-002-ARGS",
            "BLOCKED (UsersAI binding; AC-002-ARGS)",
        ),
        (
            "\t RT4 ; UsersAI binding; AC-002-ARGS \t",
            "BLOCKED (RT4; UsersAI binding; AC-002-ARGS)",
        ),
        ("", "FAIL"),
        (" \t", "FAIL"),
        ("RT4;", "FAIL"),
        (";RT4", "FAIL"),
        ("RT4; \t; AC-002-ARGS", "FAIL"),
    ] {
        assert_eq!(
            table(
                "case: test\n",
                &format!("test case ... ignored, blocked: {reason}\n"),
                true,
            ),
            (
                format!("test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\ncase | {expected}\n"),
                expected != "FAIL",
            ),
            "blocker reason: {reason:?}",
        );
    }
}

use agent_conformance::harness::ThrowawayHome;
use agent_conformance::identity::{
    sha256, stage_probe, Observation, ProbeIdentity, MANIFEST, PREFIX,
};
use agent_conformance::report::{write_run, GitIdentity};
use serde_json::Value;
use std::{fs, path::Path};

const LIVE: &str = "default_activation_refuses_without_selector";

// These synthetic hashes test report wiring only. They are never emitted as
// this Cargo run's identities and supply zero live Runtime evidence.
fn synthetic(seed: u8, dirty: bool) -> (Vec<Observation>, GitIdentity) {
    (
        vec![
            Observation::Native {
                role: "elastos".into(),
                sha256: sha256(&[seed, 1]),
            },
            Observation::Native {
                role: "localhost-provider".into(),
                sha256: sha256(&[seed, 2]),
            },
            Observation::Launched {
                probe: ProbeIdentity {
                    effect: "default".into(),
                    component_sha256: sha256(&[seed, 3]),
                    bundle_lab_cid: synthetic_bundle_cid(&[seed, 4]),
                },
            },
        ],
        GitIdentity {
            commit: format!("{seed:040x}"),
            dirty,
        },
    )
}

fn synthetic_bundle_cid(content: &[u8]) -> String {
    capsule_identity::encode_entries(&[capsule_identity::BundleEntry {
        path: "synthetic.bin".into(),
        content: content.to_vec(),
    }])
    .unwrap()
    .to_string()
}

fn output(observations: &[Observation]) -> String {
    let mut output = format!("test {LIVE} ... ok\n");
    for observation in observations {
        output.push_str(&observation.line());
        output.push('\n');
    }
    output
}

fn read_receipt(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn versions_receipt_binds_current_run() {
    let home = ThrowawayHome::new().unwrap();
    let mut documents = Vec::new();
    for (seed, dirty) in [(1, false), (2, true)] {
        let (mut observations, git) = synthetic(seed, dirty);
        // Repeated observations from independent test binaries are permitted
        // only when every field agrees.
        observations.extend(observations.clone());
        let path = home.root().join(format!("run-{seed}.json"));
        let report = write_run(
            &format!("{LIVE}: test\n"),
            &output(&observations),
            true,
            Ok(git.clone()),
            &path,
        );
        assert!(report.passed, "{:?}", report.failures);
        let document = read_receipt(&path);
        assert_eq!(
            document["description"],
            "Version evidence only. The bundle lab CID and any separate signed record give zero admission or permission credit. Runtime decides admission; resource authority requires a Runtime grant for the requesting session. Only the observed Runtime journey supplies that evidence."
        );
        assert_eq!(document["repository"], serde_json::to_value(git).unwrap());
        assert_eq!(document["runtime_sha256"], sha256(&[seed, 1]));
        assert_eq!(document["localhost_provider_sha256"], sha256(&[seed, 2]));
        assert_eq!(
            document["probes"][0]["component_sha256"],
            sha256(&[seed, 3])
        );
        assert_eq!(
            document["probes"][0]["bundle_lab_cid"],
            synthetic_bundle_cid(&[seed, 4])
        );
        assert_eq!(document["probes"][0]["effect"], "default");
        assert_eq!(document["probes"].as_array().unwrap().len(), 1);
        assert_eq!(document["identity_status"], "complete");
        assert_eq!(document["suite_outcome"], "PASS");
        assert_eq!(document["command_success"], true);
        assert_eq!(document["report"]["table"], report.table);
        assert_eq!(
            document["report"]["sha256"],
            sha256(report.table.as_bytes())
        );
        assert_eq!(document["missing_or_invalid"], serde_json::json!([]));
        documents.push(document);
    }
    // Exercise the actual CLI once as well: it owns the real Git query and exit.
    let (observations, _) = synthetic(3, false);
    let listed_path = home.root().join("list");
    let results_path = home.root().join("results");
    let receipt_path = home.root().join("cli-receipt.json");
    fs::write(&listed_path, format!("{LIVE}: test\n")).unwrap();
    fs::write(&results_path, output(&observations)).unwrap();
    let command = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_report"))
            .arg(&listed_path)
            .arg(&results_path)
            .arg("0")
            .arg(&receipt_path)
            .output()
            .unwrap()
    };
    let result = command();
    assert!(result.status.success());
    let cli = read_receipt(&receipt_path);
    assert_eq!(
        cli["repository"],
        serde_json::to_value(GitIdentity::read(&agent_conformance::build::repository()).unwrap())
            .unwrap()
    );
    assert_eq!(cli["runtime_sha256"], sha256(&[3, 1]));
    let printed = String::from_utf8(result.stdout).unwrap();
    assert!(printed.starts_with(cli["report"]["table"].as_str().unwrap()));
    assert!(printed.contains(&format!(
        "versions receipt: {}",
        receipt_path
            .strip_prefix(agent_conformance::build::lane())
            .unwrap()
            .display()
    )));
    let collision = command();
    assert!(!collision.status.success());
    assert_eq!(
        String::from_utf8(collision.stderr).unwrap(),
        "versions receipt failure: receipt write failed: AlreadyExists\n"
    );
    assert_eq!(read_receipt(&receipt_path), cli);
    assert_ne!(documents[0]["repository"], documents[1]["repository"]);
    assert_ne!(documents[0]["probes"], documents[1]["probes"]);
    home.finish().unwrap();
}

#[test]
fn versions_receipt_rejects_incomplete_identity() {
    let home = ThrowawayHome::new().unwrap();
    let (observations, git) = synthetic(1, true);
    let listed = format!("{LIVE}: test\n");
    let mut serial = 0;
    let mut refusal = |list: &str, out: &str, git, reason: &str| {
        serial += 1;
        let path = home.root().join(format!("refusal-{serial}.json"));
        let report = write_run(list, out, true, git, &path);
        assert!(!report.passed, "accepted: {reason}");
        assert!(
            report.failures.iter().any(|failure| failure == reason),
            "expected {reason}; got {:?}",
            report.failures
        );
        assert!(report.table.contains("versions_receipt (A14) | FAIL\n"));
        let document = read_receipt(&path);
        assert_eq!(document["identity_status"], "incomplete");
        assert_eq!(document["command_success"], false);
        assert!(document["missing_or_invalid"]
            .as_array()
            .unwrap()
            .contains(&Value::from(reason)));
    };
    for (index, reason) in [
        (0, "missing Runtime SHA-256"),
        (1, "missing localhost-provider SHA-256"),
        (2, "missing launched probe identity: default"),
    ] {
        let mut missing = observations.clone();
        missing.remove(index);
        refusal(&listed, &output(&missing), Ok(git.clone()), reason);
    }
    let mut build_only = observations.clone();
    let Observation::Launched { probe } = &observations[2] else {
        unreachable!()
    };
    build_only[2] = Observation::BuildOnly {
        probe: probe.clone(),
    };
    refusal(
        &listed,
        &output(&build_only),
        Ok(git.clone()),
        "missing launched probe identity: default",
    );
    refusal(
        &format!("{listed}ungranted_effect_is_refused: test\n"),
        &format!(
            "{}test ungranted_effect_is_refused ... ok\n",
            output(&observations)
        ),
        Ok(git.clone()),
        "missing launched probe identity: read",
    );
    let mut malformed_cid = synthetic_bundle_cid(&[1, 4]);
    malformed_cid.pop().unwrap();
    malformed_cid.push('X');
    for (field, value, reason) in [
        ("effect", "", "malformed probe effect"),
        (
            "component_sha256",
            "short",
            "malformed component SHA-256: default",
        ),
        (
            "bundle_lab_cid",
            "sha256:wrong",
            "malformed bundle lab CID: default",
        ),
        (
            "bundle_lab_cid",
            malformed_cid.as_str(),
            "malformed bundle lab CID: default",
        ),
    ] {
        let mut bad = serde_json::to_value(&observations[2]).unwrap();
        bad["probe"][field] = value.into();
        refusal(
            &listed,
            &format!("{}{PREFIX}{bad}\n", output(&observations)),
            Ok(git.clone()),
            reason,
        );
    }
    for field in ["component_sha256", "bundle_lab_cid", "effect"] {
        let mut bad = serde_json::to_value(&observations[2]).unwrap();
        bad["probe"].as_object_mut().unwrap().remove(field);
        refusal(
            &listed,
            &format!("{}{PREFIX}{bad}\n", output(&observations)),
            Ok(git.clone()),
            "malformed identity observation",
        );
    }
    for bad in [
        "not-json",
        r#"{"kind":"native","role":"elastos"}"#,
        r#"{"kind":"native","role":"elastos","sha256":"short"}"#,
        r#"{"kind":"native","role":"unknown","sha256":"short"}"#,
    ] {
        let reason = if bad.contains("unknown") {
            "malformed native role"
        } else if bad.contains("short") {
            "malformed elastos SHA-256"
        } else {
            "malformed identity observation"
        };
        refusal(
            &listed,
            &format!("{}{PREFIX}{bad}\n", output(&observations)),
            Ok(git.clone()),
            reason,
        );
    }
    for (index, reason) in [
        (0, "conflicting elastos SHA-256"),
        (1, "conflicting localhost-provider SHA-256"),
        (2, "conflicting probe identity: default"),
    ] {
        let (other, _) = synthetic(2, false);
        refusal(
            &listed,
            &format!("{}{}\n", output(&observations), other[index].line()),
            Ok(git.clone()),
            reason,
        );
    }
    let mut changed_manifest = probe.clone();
    changed_manifest.bundle_lab_cid = synthetic_bundle_cid(b"changed synthetic manifest");
    refusal(
        &listed,
        &format!(
            "{}{}\n",
            output(&observations),
            Observation::BuildOnly {
                probe: changed_manifest
            }
            .line()
        ),
        Ok(git.clone()),
        "conflicting probe identity: default",
    );
    for reason in ["Git commit query failed", "Git dirty-state query failed"] {
        refusal(&listed, &output(&observations), Err(reason), reason);
    }
    refusal(
        &listed,
        &output(&observations),
        Ok(GitIdentity {
            commit: "short".into(),
            dirty: true,
        }),
        "malformed Git commit",
    );
    assert_eq!(
        GitIdentity::read(&home.root().join("absent-repository")),
        Err("Git commit query failed")
    );

    let path = home.root().join("VERSIONS.json");
    let first = write_run(
        &listed,
        &output(&observations),
        true,
        Ok(git.clone()),
        &path,
    );
    assert!(first.passed);
    let original = fs::read(&path).unwrap();
    let repeated = write_run(
        &listed,
        &output(&observations),
        true,
        Ok(git.clone()),
        &path,
    );
    assert!(!repeated.passed);
    assert!(!repeated.receipt_written);
    assert_eq!(repeated.failures, ["receipt write failed: AlreadyExists"]);
    assert!(repeated.table.contains("versions_receipt (A14) | FAIL\n"));
    assert_eq!(fs::read(&path).unwrap(), original);
    let missing_parent = write_run(
        &listed,
        &output(&observations),
        true,
        Ok(git.clone()),
        &home.root().join("absent/VERSIONS.json"),
    );
    assert!(!missing_parent.passed);
    assert_eq!(missing_parent.failures, ["receipt write failed: NotFound"]);
    let symlink = home.root().join("receipt-link");
    std::os::unix::fs::symlink(&path, &symlink).unwrap();
    let refused_link = write_run(&listed, &output(&observations), true, Ok(git), &symlink);
    assert_eq!(
        refused_link.failures,
        ["receipt write failed: AlreadyExists"]
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    home.finish().unwrap();
}

#[test]
fn versions_receipt_uses_the_staged_bundle_identity() {
    let mut receipts = Vec::new();
    for manifest in [MANIFEST.to_vec(), [MANIFEST, b"\n"].concat()] {
        let home = ThrowawayHome::new().unwrap();
        // Deliberately not live WASM: this checks serialization, not admission.
        let staged =
            stage_probe(&home, b"synthetic receipt component", &manifest, "default").unwrap();
        let oracle = capsule_identity::checked_bundle(&staged.path).unwrap();
        let (mut observations, git) = synthetic(1, false);
        observations[2] = Observation::Launched {
            probe: staged.identity.clone(),
        };
        observations.push(Observation::BuildOnly {
            probe: staged.identity,
        });
        let path = home.root().join("VERSIONS.json");
        let report = write_run(
            &format!("{LIVE}: test\n"),
            &output(&observations),
            true,
            Ok(git),
            &path,
        );
        assert!(report.passed, "{:?}", report.failures);
        let receipt = read_receipt(&path);
        assert_eq!(
            receipt["probes"][0]["bundle_lab_cid"],
            oracle.cid().to_string()
        );
        assert_eq!(
            receipt["probes"][0]["component_sha256"],
            sha256(b"synthetic receipt component")
        );
        assert_eq!(receipt["build_only_probes"], receipt["probes"]);
        receipts.push(receipt);
        home.finish().unwrap();
    }
    assert_ne!(
        receipts[0]["probes"][0]["bundle_lab_cid"],
        receipts[1]["probes"][0]["bundle_lab_cid"]
    );
    assert_eq!(
        receipts[0]["probes"][0]["component_sha256"],
        receipts[1]["probes"][0]["component_sha256"]
    );
}

#[test]
fn run_table_grades_skipped_only_with_failed_test() {
    let marker = "SKIPPED case: loopback bind refused\n";
    for cargo_ok in [false, true] {
        let (text, passed) = table(
            "case: test\n",
            &format!("{marker}test case ... FAILED\n"),
            cargo_ok,
        );
        assert!(!passed);
        assert!(text.contains("case | SKIPPED (loopback bind refused)\n"));
    }
    for result in ["ok", "ignored, blocked: RT3", "unknown", ""] {
        let (text, passed) = table(
            "case: test\n",
            &format!("{marker}test case ... {result}\n"),
            true,
        );
        assert!(!passed);
        assert!(text.contains("case | FAIL\n"));
    }
    for output in [
        marker.to_owned(),
        format!("{marker}{marker}test case ... FAILED\n"),
        "SKIPPED case: \ntest case ... FAILED\n".into(),
        "test case ... FAILED\nRuntime refusal\n".into(),
    ] {
        let (text, passed) = table("case: test\n", &output, false);
        assert!(!passed);
        assert!(text.contains("case | FAIL\n"));
    }
    assert!(table("", &format!("{marker}test case ... FAILED\n"), false)
        .0
        .contains("case | FAIL\n"));
}

#[test]
fn skipped_report_keeps_a_nonzero_exit() {
    let home = ThrowawayHome::new().unwrap();
    let (observations, git) = synthetic(1, true);
    let listed = format!("{LIVE}: test\n");
    let output = format!(
        "SKIPPED {LIVE}: loopback bind refused: PermissionDenied\n{}",
        output(&observations).replace(" ... ok", " ... FAILED")
    );
    let memory = agent_conformance::report::render_run(&listed, &output, false, Ok(git));
    assert!(!memory.passed);
    assert!(memory.table.contains(&format!(
        "{LIVE} | SKIPPED (loopback bind refused: PermissionDenied)\n"
    )));
    let document: Value = serde_json::from_slice(&memory.receipt_bytes).unwrap();
    assert_eq!(document["command_success"], false);
    assert_eq!(document["report"]["table"], memory.table);
    let list_path = home.root().join("list");
    let results_path = home.root().join("results");
    fs::write(&list_path, listed).unwrap();
    fs::write(&results_path, output).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_report"))
        .arg(list_path)
        .arg(results_path)
        .arg("101")
        .arg(home.root().join("VERSIONS.json"))
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .starts_with(&memory.table));
    home.finish().unwrap();
}

#[test]
fn host_key_receipt_requires_this_launched_bundle() {
    use agent_conformance::report::render_run;
    let (mut observations, git) = synthetic(1, true);
    let name = "host_key_read_is_refused";
    let listed = format!("{name}: test\n");
    let render = |observations: &[Observation]| {
        render_run(
            &listed,
            &output(observations).replace(LIVE, name),
            true,
            Ok(git.clone()),
        )
    };
    let missing = render(&observations);
    assert!(!missing.passed);
    assert!(missing
        .failures
        .contains(&"missing launched probe identity: host-key-read".into()));
    let probe = ProbeIdentity {
        effect: "host-key-read".into(),
        component_sha256: sha256(b"host-key component"),
        bundle_lab_cid: synthetic_bundle_cid(b"host-key bundle"),
    };
    observations.push(Observation::BuildOnly {
        probe: probe.clone(),
    });
    assert!(
        !render(&observations).passed,
        "building alone supplies zero launch evidence"
    );
    observations.push(Observation::Launched {
        probe: probe.clone(),
    });
    let complete = render(&observations);
    assert!(complete.passed);
    let receipt: Value = serde_json::from_slice(&complete.receipt_bytes).unwrap();
    let recorded = receipt["probes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["effect"] == "host-key-read")
        .unwrap();
    assert_eq!(*recorded, serde_json::to_value(probe).unwrap());
}

#[test]
fn cleanup_report_keeps_scope_and_grant_blocker() {
    let listed = "granted_read_succeeds: test\nrun_leaves_no_live_grant: test\n";
    let results = "test granted_read_succeeds ... ok\ntest run_leaves_no_live_grant ... ignored, blocked: AC-021-GRANTS\n";
    let (text, passed) = table(listed, results, true);
    assert!(passed);
    assert!(text.contains("granted_read_succeeds | PASS | cleanup census, lab half of A10/A11/A12; cancel and kill-worker journeys not yet included"));
    assert!(text.contains("run_leaves_no_live_grant | BLOCKED (AC-021-GRANTS) | cleanup census"));
    let (text, passed) = table(listed, &results.replace("... ok", "... FAILED"), false);
    assert!(!passed);
    assert!(text.contains("granted_read_succeeds | FAIL | cleanup census"));
    let skipped = format!(
        "SKIPPED granted_read_succeeds: prerequisite unavailable\n{}",
        results.replace("... ok", "... FAILED")
    );
    let (text, passed) = table(listed, &skipped, false);
    assert!(!passed);
    assert!(text
        .contains("granted_read_succeeds | SKIPPED (prerequisite unavailable) | cleanup census"));
}

#[test]
fn instance_receipt_requires_both_launches_and_scope() {
    use agent_conformance::report::render_run;
    let (mut observations, git) = synthetic(1, true);
    for effect in ["instance-1", "instance-2"] {
        observations.push(Observation::Launched {
            probe: ProbeIdentity {
                effect: effect.into(),
                component_sha256: sha256(effect.as_bytes()),
                bundle_lab_cid: synthetic_bundle_cid(effect.as_bytes()),
            },
        });
    }
    for name in [
        "two_instances_overlap_with_separate_grants",
        "instance_grant_does_not_authorise_sibling",
    ] {
        let render = |observations: &[Observation]| {
            render_run(
                &format!("{name}: test\n"),
                &output(observations).replace(LIVE, name),
                true,
                Ok(git.clone()),
            )
        };
        let complete = render(&observations);
        assert!(complete.passed);
        let scope = "process-isolation lab half of A3, A6 and A9";
        assert!(complete.table.contains(&format!("{name} | PASS | {scope}")));
        let receipt: Value = serde_json::from_slice(&complete.receipt_bytes).unwrap();
        assert_eq!(receipt["instance_grants_scope"], scope);
        for missing in ["instance-1", "instance-2"] {
            let changed: Vec<_> = observations.iter().filter(|observation| {
                !matches!(observation, Observation::Launched { probe } if probe.effect == missing)
            }).cloned().collect();
            let report = render(&changed);
            assert!(
                !report.passed,
                "each launched instance identity is required"
            );
            assert!(report
                .failures
                .contains(&format!("missing launched probe identity: {missing}")));
        }
    }
}
