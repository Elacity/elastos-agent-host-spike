#!/usr/bin/env python3
"""Break each check of the Bus v2 proof once, see its test fail, restore it.

Usage: python3 -I falsify.py [--check] [name-part ...]

Each falsifier replaces exact text in one file (each piece must occur once),
rebuilds what it touched (a mutant that does not compile stops the run), runs
the named tests and requires them to FAIL. The file is restored from its saved
bytes afterwards, also on error or Ctrl-C. --check only confirms the anchors.
Name parts run only the falsifiers whose name contains one of them.
"""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
GUESTS = ["-p", "bus2-photo-guest", "-p", "bus2-resident-guest", "-p", "bus2-busy-guest"]

# (name, file, [(old, new)], [(test target, test name)])
CASES = [
    # Proof 5: admission.
    (
        "wasi imports are allowed",
        "host/src/admission.rs",
        [("        if name.starts_with(\"wasi:\") {\n            return Err(Refusal::WasiImport(name.clone()));\n        }",
          "        if name.starts_with(\"wasi:\") {\n            continue;\n        }")],
        [("admission", "any_wasi_import_is_refused")],
    ),
    (
        "admit compiles without checking imports",
        "host/src/admission.rs",
        [("    check_imports(bytes)?;\n", "    let _ = check_imports(bytes);\n")],
        [("admission", "any_wasi_import_is_refused")],
    ),
    (
        "bus v1 and v2 may be mixed",
        "host/src/admission.rs",
        [("if let (Some(v1), Some(v2)) = (v1, v2) {", "if let (Some(v1), Some(v2), true) = (v1, v2, false) {")],
        [("admission", "bus_v1_and_v2_together_are_refused")],
    ),
    (
        "any bus version is accepted",
        "host/src/admission.rs",
        [("            Some((interface, BUS_V2)) => {", "            Some((interface, _)) => {")],
        [("admission", "anything_outside_bus_v2_is_refused")],
    ),
    (
        "any bus v2 interface is accepted",
        "host/src/admission.rs",
        [("if !V2_INTERFACES.contains(&interface) {", "if false && !V2_INTERFACES.contains(&interface) {")],
        [("admission", "a_bus_v2_interface_outside_the_world_is_refused")],
    ),
    (
        "a core module passes as a component",
        "host/src/admission.rs",
        [("if depth == 0 && encoding != Encoding::Component =>", "if false && depth == 0 && encoding != Encoding::Component =>")],
        [("admission", "core_modules_are_refused")],
    ),
    (
        "a core module import is judged by its name only",
        "host/src/admission.rs",
        [("if matches!(import.ty, ComponentTypeRef::Module(_)) {", "if false && matches!(import.ty, ComponentTypeRef::Module(_)) {")],
        [("admission", "core_modules_are_refused")],
    ),
    # Proof 1: lifecycle and endings.
    (
        "the host never closes the events stream",
        "host/src/run.rs",
        [("        let drive = drive(Events(sender));\n", "        let _open = sender.clone();\n        let drive = drive(Events(sender));\n")],
        [("lifecycle", "a_resident_guest_handles_events_and_stops_when_they_close")],
    ),
    (
        "no cancel after the grace period",
        "host/src/run.rs",
        [("() = tokio::time::sleep(grace), if closed => {", "() = tokio::time::sleep(grace), if false => {")],
        [("lifecycle", "a_guest_that_does_not_return_is_cancelled_after_the_grace_period")],
    ),
    (
        "no epoch deadline",
        "host/src/run.rs",
        [("        if ticks > max_ticks {", "        if false && ticks > max_ticks {")],
        [("lifecycle", "a_guest_that_never_awaits_is_ended_at_the_epoch_deadline")],
    ),
    (
        "the deadline is recorded as a generic trap",
        "host/src/run.rs",
        [("        return Ending::EpochDeadline;", "        return Ending::Trapped(\"deadline\".into());")],
        [("lifecycle", "a_guest_that_never_awaits_is_ended_at_the_epoch_deadline")],
    ),
    (
        "fuel is not refilled at each tick",
        "host/src/run.rs",
        [("        context.set_fuel(fuel)?;\n", "")],
        [("lifecycle", "a_busy_guest_that_yields_each_slice_can_still_be_cancelled"),
         ("fairness", "a_busy_guest_does_not_starve_a_second_guest")],
    ),
    (
        "a running guest does not yield by fuel",
        "host/src/run.rs",
        [("    store.fuel_async_yield_interval(Some(limits.fuel_slice))?;\n", "")],
        [("lifecycle", "a_busy_guest_that_yields_each_slice_can_still_be_cancelled")],
    ),
    (
        "running out of fuel is recorded as a generic trap",
        "host/src/run.rs",
        [("        return Ending::FuelExhausted;", "        return Ending::Trapped(\"fuel\".into());")],
        [("lifecycle", "a_guest_that_uses_up_a_slice_of_fuel_is_ended")],
    ),
    (
        "an early return is recorded as stopped",
        "host/src/run.rs",
        [("Ok(Ok(())) if closed => Ending::Stopped,", "Ok(Ok(())) if true => Ending::Stopped,")],
        [("lifecycle", "a_guest_that_returns_before_the_close_is_recorded_as_returned")],
    ),
    (
        "the guest stops on stop-requested",
        "guests/resident/src/lib.rs",
        [("                Event::StopRequested | Event::GrantRevoked(_) => {}", "                Event::StopRequested => return Ok(()),\n                Event::GrantRevoked(_) => {}")],
        [("lifecycle", "stop_requested_adds_nothing_the_close_cannot_do")],
    ),
    (
        "a trap during instantiation is returned as a bare error",
        "host/src/run.rs",
        [("""        Err(error) => {
            return Ok(Outcome {
                ending: ending_of_trap(error),
                started: false,
                state: store.into_data(),
            })
        }""", """        Err(error) => return Err(error),""")],
        [("lifecycle", "a_trap_during_instantiation_is_a_named_ending")],
    ),
    (
        "start-up is paid from the run's budget",
        "host/src/run.rs",
        [("    store.set_fuel(limits.instantiate_fuel)?;", "    store.set_fuel(limits.fuel_per_tick)?;")],
        [("lifecycle", "start_up_has_its_own_fuel_budget")],
    ),
    # Proof 2: streaming a read with a cap.
    (
        "an object over the cap is not refused before streaming",
        "host/src/objects.rs",
        [("    if object.bytes.len() > cap {", "    if false && object.bytes.len() > cap {")],
        [("streaming", "an_object_over_the_cap_is_refused_before_any_byte_is_sent")],
    ),
    (
        "a read that passes the cap ends short with ok (truncation)",
        "host/src/objects.rs",
        [("""                Err(BusError::Invalid(format!(
                    "object grew past the cap of {cap} bytes while it was read"
                ))),""", """                Ok(()),""")],
        [("streaming", "an_object_that_grows_past_the_cap_is_refused_and_nothing_partial_is_used")],
    ),
    (
        "the host ignores the guest's cap",
        "host/src/objects.rs",
        [("        guest_cap.min(state.max_read_bytes)", "        state.max_read_bytes")],
        [("streaming", "an_object_over_the_cap_is_refused_before_any_byte_is_sent")],
    ),
    (
        "the host has no cap of its own",
        "host/src/objects.rs",
        [("        guest_cap.min(state.max_read_bytes)", "        guest_cap")],
        [("streaming", "the_host_cap_applies_whatever_the_guest_asks_for")],
    ),
    (
        "the provider skips the grant's resource check",
        "host/src/objects.rs",
        [("    if grant.resource != request.resource {", "    if false && grant.resource != request.resource {")],
        [("streaming", "the_provider_refuses_a_read_without_the_right_grant_or_params")],
    ),
    (
        "a grant is issued without a policy",
        "host/src/objects.rs",
        [("    if !allowed || actions.is_empty() {", "    if false {")],
        [("streaming", "a_guest_gets_no_grant_the_policy_does_not_allow")],
    ),
    (
        "the guest uses the bytes without waiting for the trailing future",
        "guests/photo/src/lib.rs",
        [("    trailer.await?;\n", "    let _ = trailer;\n")],
        [("streaming", "an_object_that_grows_past_the_cap_is_refused_and_nothing_partial_is_used")],
    ),
    (
        "the guest does not count what arrives",
        "guests/photo/src/lib.rs",
        [("        if bytes.len() + chunk.len() > MAX_PHOTO_BYTES {", "        if false && bytes.len() + chunk.len() > MAX_PHOTO_BYTES {")],
        [("streaming", "a_guest_refuses_more_bytes_than_it_asked_for_even_if_they_arrive")],
    ),
    # Proof 3: ui.present.
    (
        "a document may carry unknown keys",
        "host/src/ui.rs",
        [("#[serde(deny_unknown_fields)]\nstruct Document {", "struct Document {")],
        [("ui", "a_document_that_is_not_the_one_format_is_refused")],
    ),
    (
        "an image may be named by a URI",
        "host/src/ui.rs",
        [('["html", "src", "url", "uri", "href", "bytes", "data"]', '["html", "src", "url", "href", "bytes", "data"]')],
        [("ui", "an_image_by_uri_or_bytes_is_refused")],
    ),
    (
        "scripts and handlers are not named as such",
        "host/src/ui.rs",
        [('    if lower == "script" || lower.starts_with("on") {', '    if false {')],
        [("ui", "a_document_with_script_or_handlers_is_refused")],
    ),
    (
        "an image may use any grant",
        "host/src/ui.rs",
        [("                    .find(|grant| grant.id == id)", "                    .find(|_| true)")],
        [("ui", "an_image_needs_a_held_unrevoked_read_grant_on_an_image")],
    ),
    (
        "a revoked grant still draws",
        "host/src/ui.rs",
        [("                if state.revoked.contains(&id) {", "                if false && state.revoked.contains(&id) {")],
        [("ui", "an_image_needs_a_held_unrevoked_read_grant_on_an_image")],
    ),
    (
        "an image grant may point at any object",
        "host/src/ui.rs",
        [("                if !is_image(&object.bytes) {", "                if false && !is_image(&object.bytes) {")],
        [("ui", "an_image_needs_a_held_unrevoked_read_grant_on_an_image")],
    ),
    (
        "any media type is taken",
        "host/src/ui.rs",
        [("    if media_type != UI_MEDIA_TYPE {", "    if false && media_type != UI_MEDIA_TYPE {")],
        [("ui", "a_document_that_is_not_the_one_format_is_refused")],
    ),
    # Proof 4: credentials.
    (
        "the guest skips the signature check",
        "guests/photo/src/lib.rs",
        [("    key.verify_strict(\n        signed_message(CREDENTIAL_KIND, &subject).as_bytes(),\n        &signature,\n    )\n",
          "    let _ = (&key, &signature);\n    Ok::<(), ed25519_dalek::SignatureError>(())\n")],
        [("credentials", "another_signer_or_another_key_is_refused")],
    ),
    (
        "the guest does not check the signer",
        "guests/photo/src/lib.rs",
        [("    if credential.signer != PINNED_SIGNER {", "    if false && credential.signer != PINNED_SIGNER {")],
        [("credentials", "another_signer_or_another_key_is_refused")],
    ),
    (
        "the guest does not match the SHA-256 to the bytes it read",
        "guests/photo/src/lib.rs",
        [("    if credential.subject_sha256 != subject {", "    if false && credential.subject_sha256 != subject {")],
        [("credentials", "a_credential_for_other_bytes_is_refused")],
    ),
    (
        "the signed message leaves out the kind",
        "guests/photo/src/lib.rs",
        [('    format!("{CREDENTIAL_TAG}\\n{kind}\\n{subject_sha256}")', '    let _ = kind;\n    format!("{CREDENTIAL_TAG}\\n{subject_sha256}")')],
        [("credentials", "a_pinned_key_signature_over_the_same_hash_without_this_tag_and_kind_is_refused")],
    ),
    (
        "the signed message is the bare hash",
        "guests/photo/src/lib.rs",
        [('    format!("{CREDENTIAL_TAG}\\n{kind}\\n{subject_sha256}")', '    let _ = kind;\n    subject_sha256.to_string()')],
        [("credentials", "a_pinned_key_signature_over_the_same_hash_without_this_tag_and_kind_is_refused")],
    ),
    (
        "a frame is drawn before the credential check",
        "guests/photo/src/lib.rs",
        [("                check_credential(&read.bytes)?;\n                draw(&read).await?;", "                draw(&read).await?;\n                check_credential(&read.bytes)?;")],
        [("credentials", "another_signer_or_another_key_is_refused")],
    ),
    (
        "more than one credential of the kind is taken",
        "guests/photo/src/lib.rs",
        [("    if candidates.next().is_some() {", "    if false && candidates.next().is_some() {")],
        [("credentials", "no_credential_or_another_kind_is_refused")],
    ),
    (
        "the host grants on a credential",
        "host/src/objects.rs",
        [("    if !allowed || actions.is_empty() {", "    if !(allowed || !state.credentials.is_empty()) || actions.is_empty() {")],
        [("credentials", "a_good_credential_grants_nothing")],
    ),
    # Proof 6: fairness.
    (
        "a running guest never yields (no fuel slices, no epoch yield)",
        "host/src/run.rs",
        [("    store.fuel_async_yield_interval(Some(limits.fuel_slice))?;\n", ""),
         ("            UpdateDeadline::Yield(1)\n", "            UpdateDeadline::Continue(1)\n")],
        [("fairness", "a_busy_guest_does_not_starve_a_second_guest")],
    ),
]


def run(args):
    environment = dict(os.environ)
    environment.setdefault("RUST_TEST_THREADS", "2")
    return subprocess.run(args, cwd=ROOT, env=environment, capture_output=True, text=True)


def build(relative):
    if relative.startswith("guests/"):
        result = run(["cargo", "build", "--locked", "--release", "--target", "wasm32-unknown-unknown", *GUESTS])
    else:
        result = run(["cargo", "test", "--locked", "-p", "bus2-host", "--no-run"])
    if result.returncode != 0:
        print(result.stderr[-3000:])
        raise SystemExit("a falsifier does not compile")


def tests_fail(tests):
    for target, name in tests:
        result = run(["cargo", "test", "--locked", "-p", "bus2-host", "--test", target, "--", "--exact", name])
        if "1 passed" not in result.stdout and "1 failed" not in result.stdout:
            raise SystemExit(f"no test {target}::{name}\n{result.stdout[-1500:]}{result.stderr[-1500:]}")
        if result.returncode == 0:
            return False
    return True


def main():
    args = sys.argv[1:]
    check_only = "--check" in args
    parts = [arg for arg in args if arg != "--check"]
    missed = []
    selected = 0
    for name, relative, replacements, tests in CASES:
        path = ROOT / relative
        saved = path.read_bytes()
        text = saved.decode()
        for old, _ in replacements:
            if text.count(old) != 1:
                raise SystemExit(f"{name}: expected the text once in {relative}, found {text.count(old)}")
        if check_only or (parts and not any(part in name for part in parts)):
            continue
        selected += 1
        try:
            for old, new in replacements:
                text = text.replace(old, new)
            path.write_text(text)
            build(relative)
            caught = tests_fail(tests)
        finally:
            path.write_bytes(saved)
            if relative.startswith("guests/"):
                build(relative)
        print(f"{'caught' if caught else 'MISSED'}: {name}", flush=True)
        if not caught:
            missed.append(name)
    if check_only:
        print(f"all {len(CASES)} anchors found once")
        return
    if missed:
        raise SystemExit(f"{len(missed)} falsifier(s) not caught: {missed}")
    print(f"all {selected} falsifiers caught")


if __name__ == "__main__":
    main()
