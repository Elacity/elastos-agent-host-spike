#!/usr/bin/env python3
"""Break each check of the P4b bundle tool, see its test fail, restore it.

Usage: RUST_TEST_THREADS=2 python3 -I falsify-bundle.py

Each falsifier replaces exact text in one file under bundle/src (every piece
must occur once), rebuilds the tests (a mutant that does not compile proves
nothing, so the run stops), runs the named tests, and requires them to FAIL.
The file is restored from its saved bytes afterwards, also on error or Ctrl-C.
"""
import os
import pathlib
import subprocess

BUNDLE = pathlib.Path(__file__).resolve().parent / "bundle"

# (name, file under bundle/src, [(exact old text, new text)], tests that must fail)
CASES = [
    # The listing.
    ("non-NFC names are listed", "listing.rs",
     [("if !name.is_ascii() && !is_nfc(name) {", "if false && !name.is_ascii() && !is_nfc(name) {")],
     ["the_listing_takes_ascii_or_nfc_names_only"]),
    ("case folding is plain lower-casing", "listing.rs",
     [("folded.insert(caseless::default_case_fold_str(path), path)", "folded.insert(path.to_lowercase(), path)")],
     ["names_must_be_unique_under_case_folding"]),
    ("the walk follows symlinks", "listing.rs",
     [("let meta = std::fs::symlink_metadata(&path)", "let meta = std::fs::metadata(&path)")],
     ["the_listing_refuses_symlinks_and_special_files"]),
    ("special files are skipped, not refused", "listing.rs",
     [("return Err(Refusal::SpecialFile(relative));", "continue;")],
     ["the_listing_refuses_symlinks_and_special_files"]),
    ("control characters and backslashes are allowed", "listing.rs",
     [("if name.contains(['/', '\\\\']) || name.chars().any(char::is_control) {", "if name.contains('/') {")],
     ["the_listing_refuses_control_characters_and_backslashes"]),
    ("a closure needs no manifest", "listing.rs",
     [("let manifest = manifest.ok_or(Refusal::ManifestMissing)?;", "let manifest = manifest.unwrap_or_default();")],
     ["the_listing_refuses_a_closure_with_no_manifest"]),
    ("the listing keeps walk order", "listing.rs",
     [("    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));\n", "")],
     ["the_listing_is_sorted_by_path_bytes_not_by_walk_order"]),
    # The claim and its signature.
    ("the claim's CID is not checked", "admit.rs",
     [("if computed != claimed.cid {", "if false && computed != claimed.cid {")],
     ["admission_refuses_a_closure_that_is_not_the_claimed_cid"]),
    ("the claim's signature is not checked", "admit.rs",
     [("    claim.verify()?;\n", "    let _ = claim.verify();\n")],
     ["admission_refuses_a_claim_its_publisher_did_not_sign"]),
    ("signatures carry no domain", "sign.rs",
     [("hasher.update(domain.as_bytes());", "let _ = domain;")],
     ["admission_refuses_a_claim_its_publisher_did_not_sign"]),
    ("the claim need not match the manifest", "admit.rs",
     [("if in_manifest != Some(value.as_str()) {", "if false && in_manifest != Some(value.as_str()) {")],
     ["admission_refuses_a_claim_that_is_not_what_the_manifest_says"]),
    ("a claim takes unknown fields", "claim.rs",
     [("#[serde(deny_unknown_fields)]\npub struct Claim {", "pub struct Claim {")],
     ["a_claim_parses_strictly"]),
    ("a claim takes another schema", "claim.rs",
     [("if claim.schema != CLAIM_SCHEMA {", "if false && claim.schema != CLAIM_SCHEMA {")],
     ["a_claim_parses_strictly"]),
    # The trust policy.
    ("the policy is checked against the DID it names, not the pinned root", "policy.rs",
     [("if self.signer_did != release_root_did {", "if false && self.signer_did != release_root_did {"),
      ("        sign::verify(\n            release_root_did,", "        sign::verify(\n            &self.signer_did,")],
     ["the_release_policy_must_be_signed_by_the_pinned_root"]),
    ("the policy signature is not checked", "policy.rs",
     [("        .map_err(Refusal::PolicySignatureInvalid)?;\n        Ok(&self.policy)",
       "        .ok();\n        Ok(&self.policy)")],
     ["the_release_policy_must_be_signed_by_the_pinned_root"]),
    ("dev keys outside dev mode", "policy.rs",
     [("if !local.dev_mode {", "if false && !local.dev_mode {")],
     ["local_config_adds_a_dev_key_only_in_dev_mode"]),
    ("a dev key may be a release key", "policy.rs",
     [("if known || policy.revoked_dids.contains(&key.did) {", "if false && known {")],
     ["a_dev_key_cannot_stand_in_for_a_release_key"]),
    ("local config takes more than dev keys", "policy.rs",
     [("#[serde(deny_unknown_fields)]\npub struct LocalConfig {", "pub struct LocalConfig {")],
     ["local_config_adds_a_dev_key_only_in_dev_mode"]),
    ("revoked CIDs admit", "admit.rs",
     [("if policy.revoked_cids.contains(&claimed.cid) {", "if false && policy.revoked_cids.contains(&claimed.cid) {")],
     ["admission_refuses_a_revoked_publisher_or_a_revoked_cid"]),
    ("revoked publishers admit", "admit.rs",
     [("if policy.revoked_dids.contains(&claimed.publisher_did) {",
       "if false && policy.revoked_dids.contains(&claimed.publisher_did) {")],
     ["admission_refuses_a_revoked_publisher_or_a_revoked_cid"]),
    ("any publisher is trusted", "admit.rs",
     [(".find(|entry| entry.did == claimed.publisher_did)", ".find(|_| true)")],
     ["admission_refuses_an_untrusted_publisher_or_a_role_it_may_not_ship"]),
    ("a publisher may ship any role", "admit.rs",
     [("let role_allowed = entry.roles.contains(&claimed.role);", "let role_allowed = true;")],
     ["admission_refuses_an_untrusted_publisher_or_a_role_it_may_not_ship"]),
    ("a publisher may ship any name", "admit.rs",
     [(".is_none_or(|names| names.contains(&claimed.name));", ".is_none_or(|_| true);")],
     ["admission_refuses_an_untrusted_publisher_or_a_role_it_may_not_ship",
      "local_config_adds_a_dev_key_only_in_dev_mode"]),
    # Policy rollback and expiry.
    ("an older policy is accepted after a newer one", "policy.rs",
     [("Some((seen, _)) if policy.sequence < seen => {", "Some((seen, _)) if false && policy.sequence < seen => {")],
     ["an_older_policy_cannot_be_replayed_after_a_revocation"]),
    ("two policies may share a sequence", "policy.rs",
     [("if policy.sequence == seen && seen_sha256 != sha256 =>", "if false && seen_sha256 != sha256 =>")],
     ["one_sequence_names_one_policy"]),
    ("the floor is never written", "policy.rs",
     [("_ => floor.raise(policy.sequence, &sha256)?,", "_ => {}")],
     ["an_older_policy_cannot_be_replayed_after_a_revocation"]),
    ("a refused policy moves the floor", "policy.rs",
     [("    let policy = release.verify(release_root_did)?;\n    if now >= policy.expires_at {\n",
       "    let policy = release.verify(release_root_did)?;\n    let _ = floor.raise(policy.sequence, \"moved\");\n    if now >= policy.expires_at {\n")],
     ["a_policy_that_is_refused_does_not_move_the_floor"]),
    ("a floor that does not parse counts as none", "policy.rs",
     [("        let record: FloorRecord = serde_json::from_slice(&bytes)\n            .map_err(|err| Refusal::Io(format!(\"{}: {err}\", self.path.display())))?;",
       "        let Ok(record) = serde_json::from_slice::<FloorRecord>(&bytes) else {\n            return Ok(None);\n        };")],
     ["a_policy_floor_that_does_not_parse_is_refused"]),
    ("an expired policy loads", "policy.rs",
     [("    if now >= policy.expires_at {", "    if false && now >= policy.expires_at {")],
     ["an_expired_policy_is_refused_at_load_and_at_admission"]),
    ("an expired policy admits", "admit.rs",
     [("    if now >= policy.expires_at {", "    if false && now >= policy.expires_at {")],
     ["an_expired_policy_is_refused_at_load_and_at_admission"]),
    ("a release policy may run forever", "policy.rs",
     [("if policy.expires_at > now.saturating_add(MAX_POLICY_LIFETIME_SECS) {",
       "if false && policy.expires_at > now.saturating_add(MAX_POLICY_LIFETIME_SECS) {")],
     ["a_release_policy_runs_at_most_90_days"]),
    ("the policy cap refuses exactly 90 days", "policy.rs",
     [("if policy.expires_at > now.saturating_add(MAX_POLICY_LIFETIME_SECS) {",
       "if policy.expires_at >= now.saturating_add(MAX_POLICY_LIFETIME_SECS) {")],
     ["a_release_policy_runs_at_most_90_days"]),
    # Dev keys: named capsules and an expiry.
    ("a dev key may run forever", "policy.rs",
     [("if key.expires_at > now.saturating_add(MAX_DEV_KEY_LIFETIME_SECS) {",
       "if false && key.expires_at > now.saturating_add(MAX_DEV_KEY_LIFETIME_SECS) {")],
     ["a_dev_key_runs_at_most_30_days"]),
    ("the dev key cap refuses exactly 30 days", "policy.rs",
     [("if key.expires_at > now.saturating_add(MAX_DEV_KEY_LIFETIME_SECS) {",
       "if key.expires_at >= now.saturating_add(MAX_DEV_KEY_LIFETIME_SECS) {")],
     ["a_dev_key_runs_at_most_30_days"]),
    ("a dev key may ship a whole role", "policy.rs",
     [("if key.names.is_empty() {", "if false && key.names.is_empty() {")],
     ["a_dev_key_names_its_capsules_and_expires"]),
    ("an expired dev key loads", "policy.rs",
     [("if now >= key.expires_at {", "if false && now >= key.expires_at {")],
     ["a_dev_key_names_its_capsules_and_expires"]),
    ("an expired dev key admits", "admit.rs",
     [("entry.expires_at.filter(|expires_at| now >= *expires_at)", "entry.expires_at.filter(|_| false)")],
     ["a_dev_key_names_its_capsules_and_expires"]),
    # The inventory.
    ("a lower version admits", "admit.rs",
     [("if installed_version > offered {", "if false && installed_version > offered {")],
     ["admission_refuses_a_lower_version_of_an_installed_name"]),
    ("one version may have two CIDs", "admit.rs",
     [("if installed_version == offered && current.cid != claimed.cid {", "if false {")],
     ["one_version_of_a_name_has_one_cid"]),
    # Staging and load.
    ("the staged copy is not checked against the CID", "admit.rs",
     [("    let computed = cid_of(&copied);\n    if computed != cid {",
       "    let computed = cid_of(&copied);\n    if false && computed != cid {")],
     ["admit::tests::a_source_changed_after_verification_is_not_staged"]),
    ("the staged copy is left writable", "admit.rs",
     [("    seal(staging)\n}", "    let _ = seal;\n    Ok(())\n}")],
     ["admission_stages_a_read_only_copy_by_cid_and_loads_only_from_it"]),
    ("load does not check the copy is read-only", "admit.rs",
     [("    check_read_only(&path, &path)?;\n", "")],
     ["load_refuses_a_staged_copy_that_is_writable"]),
    ("load does not re-hash the copy", "admit.rs",
     [("    let computed = cid_of(&entries);\n    if computed != cid {",
       "    let computed = cid_of(&entries);\n    if false && computed != cid {")],
     ["load_refuses_a_staged_copy_that_no_longer_hashes_to_its_cid"]),
    ("load takes any path", "admit.rs",
     [("    check_cid_form(cid)?;\n", "")],
     ["load_takes_only_a_cid"]),
    # The core by CID.
    ("a requirement with no CID is skipped", "admit.rs",
     [("return Err(Refusal::CoreUnpinned(name));", "continue;")],
     ["a_surface_resolves_its_core_by_cid_only"]),
    ("the core is found by name", "admit.rs",
     [(".find(|core| core.cid == cid && core.name == name)", ".find(|core| core.name == name)")],
     ["a_surface_resolves_its_core_by_cid_only"]),
    # Provenance.
    ("provenance for another CID verifies", "provenance.rs",
     [("if self.provenance.cid != cid {", "if false && self.provenance.cid != cid {")],
     ["provenance_is_a_separate_record_that_names_the_cid"]),
]


def env():
    environment = dict(os.environ)
    environment.setdefault("RUST_TEST_THREADS", "2")
    return environment


def cargo(*args):
    return subprocess.run(["cargo", "test", "-q", *args], cwd=BUNDLE, env=env(), capture_output=True, text=True)


def tests_fail(filters):
    build = cargo("--no-run")
    if build.returncode != 0:
        print(build.stderr[-3000:])
        raise SystemExit("a falsifier does not compile")
    for name in filters:
        result = cargo("--", "--exact", name)
        ran = "1 passed" in result.stdout or "1 failed" in result.stdout
        if not ran:
            raise SystemExit(f"no test named {name}")
        if result.returncode == 0:
            return False
    return True


def main():
    missed = []
    for name, relative, replacements, filters in CASES:
        path = BUNDLE / "src" / relative
        saved = path.read_bytes()
        text = saved.decode()
        for old, _ in replacements:
            if text.count(old) != 1:
                raise SystemExit(f"{name}: expected the text once in {relative}, found {text.count(old)}")
        try:
            for old, new in replacements:
                text = text.replace(old, new)
            path.write_text(text)
            caught = tests_fail(filters)
        finally:
            path.write_bytes(saved)
        print(f"{'caught' if caught else 'MISSED'}: {name} -> {', '.join(filters)}", flush=True)
        if not caught:
            missed.append(name)
    if missed:
        raise SystemExit(f"{len(missed)} falsifier(s) not caught: {missed}")
    print(f"all {len(CASES)} bundle falsifiers caught")


if __name__ == "__main__":
    main()
