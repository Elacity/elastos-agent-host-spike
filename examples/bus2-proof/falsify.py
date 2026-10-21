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
        [("lifecycle", "a_busy_guest_that_yields_each_slice_can_still_be_cancelled")],
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
