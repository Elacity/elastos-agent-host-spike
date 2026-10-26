"""The installed demo refuses to run unless its versions match VERSIONS.json.

Every fixture here is synthetic and lives in a temporary folder. None of it is
live evidence for A14; the real run is RUNBOOK.md on the Mac.
"""

import contextlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

LANE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LANE))

import demo  # noqa: E402

COMMIT = "c" * 40
TREE = "e" * 40
CLEAN = demo.Checkout(COMMIT, TREE, True)
RUNTIME = b"runtime bytes"
PROVIDER = b"provider bytes"
PROBE = {
    "effect": "host-key-read",
    "component_sha256": "a" * 64,
    "bundle_lab_cid": "lab-cid:sha256:" + "b" * 64,
}
SUITES = demo.suites_here(demo.load_journeys()[2], "Darwin")
PACKAGES = {
    "runtime-compute": "elastos/crates/elastos-compute",
    "runtime-server": "elastos/crates/elastos-server",
    "agent-conformance": "lab/agent-conformance",
    "did-provider": "capsules/did-provider",
    "wallet-provider": "capsules/wallet-provider",
    "model-provider": "capsules/model-provider",
}
PROVIDER_SUITES = ("did-provider", "wallet-provider", "model-provider")


def sha(data):
    return demo.sha256_bytes(data)


def receipt_for(runtime=RUNTIME, provider=PROVIDER, commit=COMMIT):
    table = (
        "test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\n"
        "host_key_read_is_refused | PASS\n"
        "versions_receipt (A14) | PASS\n"
    )
    return {
        "schema": demo.RECEIPT_SCHEMA,
        "description": "Version evidence only.",
        "identity_status": "complete",
        "repository": {"commit": commit, "dirty": False},
        "runtime_sha256": sha(runtime),
        "localhost_provider_sha256": sha(provider),
        "probes": [dict(PROBE)],
        "build_only_probes": [],
        "missing_or_invalid": [],
        "cargo_success": True,
        "suite_outcome": "BLOCKED",
        "command_success": True,
        "report": {"table": table, "sha256": sha(table.encode())},
    }


def encode(receipt):
    return (json.dumps(receipt, indent=2) + "\n").encode()


def artifacts_for(repo, suite):
    """Cargo's artifact messages for one suite: its test executable and, for providers, its binary."""
    package = repo / PACKAGES[suite]
    found = [
        {
            "reason": "compiler-artifact",
            "package_id": suite,
            "target": {"kind": ["test"], "name": suite},
            "profile": {"test": True},
            "executable": str(repo / "target-build" / "debug" / "deps" / f"{suite}-test"),
            "manifest_path": str(package / "Cargo.toml"),
        }
    ]
    if suite in PROVIDER_SUITES:
        found.append(
            {
                "reason": "compiler-artifact",
                "package_id": suite,
                "target": {"kind": ["bin"], "name": suite},
                "profile": {"test": False},
                "executable": str(package / "target" / "debug" / suite),
                "manifest_path": str(package / "Cargo.toml"),
            }
        )
    return found


class Fixture:
    """A checkout, its Cargo builds, one lab/agent-conformance build and one matching install."""

    def __init__(self, root):
        self.root = root
        self.layout = demo.Layout(root / "repo", root / "home" / "current")
        repo = self.layout.repo
        build = self.layout.runtime_build
        build.mkdir(parents=True)
        (build / "elastos").write_bytes(RUNTIME)
        (build / "localhost-provider").write_bytes(PROVIDER)
        self.layout.agent_host_wasm.parent.mkdir(parents=True)
        self.layout.agent_host_wasm.write_bytes(b"\0asm agent-host")
        for suite in SUITES:
            for artifact in artifacts_for(repo, suite):
                path = Path(artifact["executable"])
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"{artifact['target']['name']} {artifact['target']['kind'][0]}".encode())
                Path(artifact["manifest_path"]).parent.mkdir(parents=True, exist_ok=True)
        self.receipt = receipt_for()
        self.source = root / "VERSIONS.json"
        self.source.write_bytes(encode(self.receipt))

    def steps(self):
        recorded = {}
        for suite in SUITES:
            recorded[suite], problems = demo.record_executables(suite, artifacts_for(self.layout.repo, suite), self.layout.repo)
            assert problems == [], problems
        return recorded

    def install(self):
        problems = demo.write_install(self.layout, encode(self.receipt), self.source, CLEAN, self.steps())
        assert problems == [], problems
        return self

    def gate(self, checkout=CLEAN):
        return demo.version_gate(self.layout, checkout, SUITES)

    def installed(self, *parts):
        return self.layout.install.joinpath(*parts)

    def record(self):
        return json.loads(self.installed("INSTALL.json").read_text())

    def write_record(self, record):
        self.installed("INSTALL.json").write_text(json.dumps(record))

    def step(self, suite):
        return self.record()["steps"][suite]

    def change_receipt(self, change):
        """Edit the installed receipt and re-pin it, so only its content is wrong."""
        receipt = json.loads(self.installed("VERSIONS.json").read_bytes())
        change(receipt)
        data = encode(receipt)
        self.installed("VERSIONS.json").write_bytes(data)
        record = self.record()
        record["versions_sha256"] = sha(data)
        self.write_record(record)


def append_byte(path):
    with path.open("ab") as handle:
        handle.write(b"!")


class TempCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="demo-a14-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fx = Fixture(self.tmp)

    def assertNamed(self, problems, *words):
        self.assertTrue(
            any(all(word in problem for word in words) for problem in problems),
            f"no problem names {words}: {problems}",
        )


class VersionGate(TempCase):
    def setUp(self):
        super().setUp()
        self.fx.install()

    def test_matching_install_is_allowed(self):
        self.assertEqual(self.fx.gate(), [])

    def test_changed_installed_runtime_is_refused(self):
        append_byte(self.fx.installed("bin", "elastos"))
        problems = self.fx.gate()
        self.assertNamed(
            problems,
            "installed elastos differs from VERSIONS.json runtime_sha256",
            sha(RUNTIME + b"!"),
            sha(RUNTIME),
        )

    def test_changed_installed_provider_is_refused(self):
        append_byte(self.fx.installed("bin", "localhost-provider"))
        self.assertNamed(
            self.fx.gate(), "installed localhost-provider differs from VERSIONS.json localhost_provider_sha256"
        )

    def test_missing_installed_component_is_refused(self):
        self.fx.installed("bin", "localhost-provider").unlink()
        self.assertNamed(self.fx.gate(), "installed localhost-provider is missing")

    def test_runtime_the_journeys_launch_must_match(self):
        append_byte(self.fx.layout.runtime_build / "elastos")
        self.assertNamed(self.fx.gate(), "the elastos the journeys launch differs", sha(RUNTIME))

    def test_changed_agent_host_component_is_refused(self):
        append_byte(self.fx.layout.agent_host_wasm)
        self.assertNamed(self.fx.gate(), "the agent-host component the journeys load differs")

    def test_swapped_receipt_is_refused(self):
        other = encode(receipt_for(runtime=b"another runtime"))
        self.fx.installed("VERSIONS.json").write_bytes(other)
        problems = self.fx.gate()
        self.assertNamed(problems, "the installed VERSIONS.json changed after install", sha(other))
        self.assertNamed(problems, "installed elastos differs")

    def test_receipt_from_another_commit_is_refused(self):
        other = demo.Checkout("d" * 40, TREE, True)
        self.assertNamed(
            self.fx.gate(other), f"this checkout is at commit {'d' * 40}; VERSIONS.json was made at {COMMIT}"
        )

    def test_dirty_checkout_is_refused(self):
        self.assertNamed(self.fx.gate(demo.Checkout(COMMIT, TREE, False)), "this checkout has local changes")

    def test_git_failure_is_refused(self):
        failed = demo.Checkout(None, None, False, "Git query failed: git rev-parse exited 128")
        self.assertNamed(self.fx.gate(failed), "Git query failed")

    def test_incomplete_or_failed_receipt_is_refused(self):
        def table(text):
            def change(receipt):
                receipt["report"] = {"table": text, "sha256": sha(text.encode())}

            return change

        cases = {
            "identity_status": (lambda r: r.update(identity_status="incomplete"), "identity_status"),
            "command_success": (lambda r: r.update(command_success=False), "failed agent-conformance run"),
            "missing_or_invalid": (
                lambda r: r.update(missing_or_invalid=["missing Runtime SHA-256"]),
                "missing or invalid identities",
            ),
            "dirty": (lambda r: r["repository"].update(dirty=True), "local changes"),
            "commit": (lambda r: r["repository"].update(commit="main"), "no valid repository commit"),
            "schema": (lambda r: r.update(schema="agent-conformance.versions/v0"), "schema"),
            "runtime": (lambda r: r.update(runtime_sha256="ABC"), "no valid runtime_sha256"),
            "provider": (lambda r: r.pop("localhost_provider_sha256"), "no valid localhost_provider_sha256"),
            "a14_row": (table("versions_receipt (A14) | FAIL\n"), "versions_receipt (A14) | PASS"),
            "table_hash": (lambda r: r["report"].update(sha256="0" * 64), "does not match its SHA-256"),
            "probes": (lambda r: r.update(probes=[PROBE, PROBE]), "one probe effect twice"),
            "malformed_probe": (lambda r: r.update(probes=[{"effect": "x"}]), "probes are malformed"),
        }
        for name, (change, words) in cases.items():
            with self.subTest(name):
                fx = Fixture(self.tmp / name).install()
                self.assertEqual(fx.gate(), [])
                fx.change_receipt(change)
                self.assertNamed(fx.gate(), words)

    def test_unreadable_install_is_refused(self):
        self.fx.installed("INSTALL.json").write_text("{not json")
        self.assertNamed(self.fx.gate(), "INSTALL.json cannot be read")
        self.fx.installed("INSTALL.json").write_text(json.dumps({"schema": "other"}))
        self.assertNamed(self.fx.gate(), "not a demo-a14 install record")

    def test_missing_install_is_refused(self):
        shutil.rmtree(self.fx.layout.install)
        self.assertNamed(self.fx.gate(), "no installed demo", "install.sh")


class StepBinaries(TempCase):
    """The Cargo-built A1, A2 and C executables are bound by hash, not only by the commit."""

    def setUp(self):
        super().setUp()
        self.fx.install()

    def test_changed_step_executable_is_refused(self):
        path = Path(self.fx.step("runtime-server")["test"]["path"])
        append_byte(path)
        self.assertNamed(
            self.fx.gate(), "the runtime-server test executable differs from its hash in INSTALL.json", str(path)
        )

    def test_changed_provider_binary_is_refused(self):
        path = Path(self.fx.step("did-provider")["bins"]["did-provider"]["path"])
        append_byte(path)
        self.assertNamed(self.fx.gate(), "the did-provider binary did-provider differs from its hash in INSTALL.json")

    def test_step_path_outside_the_repository_is_refused(self):
        record = self.fx.record()
        outside = self.tmp / "elsewhere" / "test"
        outside.parent.mkdir()
        outside.write_bytes(b"anything")
        record["steps"]["runtime-compute"]["test"].update(path=str(outside), sha256=sha(b"anything"))
        self.fx.write_record(record)
        self.assertNamed(self.fx.gate(), "the runtime-compute test executable is outside the repository")

    def test_install_without_step_bindings_is_refused(self):
        record = self.fx.record()
        del record["steps"]
        self.fx.write_record(record)
        self.assertNamed(self.fx.gate(), "INSTALL.json binds no executables for runtime-compute")


def libtest(names, captured=None, verdict="ok"):
    captured = captured or {}
    lines = [f"running {len(names)} tests", *(f"test {name} ... {verdict}" for name in names), ""]
    lines += ["successes:", ""]
    for name in names:
        lines += [f"---- {name} stdout ----", *captured.get(name, []), ""]
    lines += ["", "successes:", *(f"    {name}" for name in names), ""]
    lines += [f"test result: ok. {len(names)} passed; 0 failed; 0 ignored"]
    return "\n".join(lines) + "\n"


def identity(observation):
    return demo.IDENTITY_PREFIX + json.dumps(observation)


def requested(args):
    tail = args[args.index("--") + 1:] if "--" in args else args[1:]
    return [arg for arg in tail if not arg.startswith("--")]


class FakeCargo:
    """Answers each suite with libtest text; records every command it is given."""

    def __init__(self, fx, a8_lines=None, during=None, running=None):
        self.fx = fx
        self.calls = []
        self.during = during
        self.running = running
        receipt = fx.receipt
        native = [
            {"kind": "native", "role": "elastos", "sha256": receipt["runtime_sha256"]},
            {"kind": "native", "role": "localhost-provider", "sha256": receipt["localhost_provider_sha256"]},
            {"kind": "launched", "probe": dict(PROBE)},
        ]
        self.a8 = a8_lines if a8_lines is not None else [identity(item) for item in native]

    def __call__(self, args, cwd, env, log, timeout):
        self.calls.append((args, cwd, env))
        if self.during:
            self.during()
        text = libtest(requested(args), {"host_key_read_is_refused": self.a8})
        if args[0] == "cargo":
            ran = self.running or self.fx.step("agent-conformance")["test"]["path"]
            text = f"   Compiling nothing\n     Running tests/effects.rs ({ran})\n" + text
        return 0, text


def journey_names(calls):
    return {name for args, _, _ in calls for name in requested(args)}


class RunBinding(TempCase):
    def setUp(self):
        super().setUp()
        self.fx.install()

    def run_demo(self, host_os="Darwin", runner=None):
        runner = runner or FakeCargo(self.fx)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = demo.run_demo(self.fx.layout, host_os, runner=runner, read=lambda repo: CLEAN)
        return code, out.getvalue(), runner

    def test_refused_run_starts_no_journey(self):
        append_byte(self.fx.installed("bin", "elastos"))
        code, out, runner = self.run_demo()
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertEqual(runner.calls, [])
        self.assertIn("REFUSED: the installed versions do not match VERSIONS.json. No journey was run.", out)
        self.assertIn("installed elastos differs from VERSIONS.json runtime_sha256", out)
        summaries = list((self.fx.layout.install.parent / "runs").glob("*/summary.txt"))
        self.assertEqual(len(summaries), 1, summaries)
        self.assertIn(str(summaries[0]), out)
        self.assertIn("REFUSED:", summaries[0].read_text())
        pointer = demo.this_run_pointer(self.fx.layout).read_text(encoding="utf-8").strip()
        self.assertEqual(Path(pointer) / "summary.txt", summaries[0])

    def test_run_without_install_names_it(self):
        shutil.rmtree(self.fx.layout.install)
        code, out, runner = self.run_demo()
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertEqual(runner.calls, [])
        self.assertIn("REFUSED: the demo is not installed. No journey was run.", out)
        summaries = list((self.fx.layout.install.parent / "runs").glob("*/summary.txt"))
        self.assertEqual(len(summaries), 1, summaries)
        self.assertIn(str(summaries[0]), out)
        self.assertIn("the demo is not installed", summaries[0].read_text())

    def test_matching_run_walks_every_step(self):
        code, out, runner = self.run_demo()
        _, _, steps = demo.load_journeys()
        self.assertEqual(journey_names(runner.calls), {step.test for step in steps})
        self.assertIn("versions bound after the run: yes", out)
        self.assertIn("A14: PASS.", out)
        self.assertEqual(code, demo.EXIT_PASS)
        pointer = demo.this_run_pointer(self.fx.layout).read_text(encoding="utf-8").strip()
        summary = Path(pointer) / "summary.txt"
        self.assertTrue(summary.is_file(), pointer)
        self.assertIn("A14: PASS.", summary.read_text(encoding="utf-8"))
        for step in steps:
            word = "PASS" if step.expect == "pass" else "REFUSED"
            self.assertIn(f"  {step.id:<10} {word:<8} {step.title}", out)

    def test_pass_writes_a14_pass_in_this_runs_summary(self):
        """Pins A14: PASS. to summary.txt. Removing write_summary on the PASS path fails this."""
        code, out, _ = self.run_demo()
        self.assertEqual(code, demo.EXIT_PASS, out)
        self.assertTrue(
            demo.this_run_pointer(self.fx.layout).is_file(),
            "this-run pointer missing; the PASS path must name this run",
        )
        pointer = demo.this_run_pointer(self.fx.layout).read_text(encoding="utf-8").strip()
        summary = Path(pointer) / "summary.txt"
        self.assertTrue(summary.is_file(), f"summary.txt missing at {summary}")
        text = summary.read_text(encoding="utf-8")
        self.assertIn("A14: PASS.", text)
        self.assertEqual(summary.name, "summary.txt")

    def test_run_executes_the_recorded_files(self):
        code, out, runner = self.run_demo()
        self.assertEqual(code, demo.EXIT_PASS, out)
        ran = {}
        for args, cwd, env in runner.calls:
            ran[args[0]] = (str(cwd), env.get("CARGO_MANIFEST_DIR"))
        for suite in SUITES:
            test = self.fx.step(suite)["test"]
            if suite == "agent-conformance":
                self.assertIn("cargo", ran)
                self.assertNotIn(test["path"], ran)
            else:
                self.assertEqual(ran.get(test["path"]), (test["cwd"], test["cwd"]), suite)
        self.assertIn("  steps    6 test executables and 3 provider binaries match their hashes in INSTALL.json", out)

    def test_executable_changed_before_its_suite_is_not_run(self):
        target = Path(self.fx.step("did-provider")["test"]["path"])
        code, out, runner = self.run_demo(runner=FakeCargo(self.fx, during=lambda: target.exists() and append_byte(target)))
        did = {step.test for step in demo.load_journeys()[2] if step.suite == "did-provider"}
        self.assertFalse(any(str(target) == args[0] for args, _, _ in runner.calls))
        self.assertEqual(code, demo.EXIT_FAIL)
        self.assertIn("Refusing did-provider under its confine.sb: it would not run the bytes this install recorded.", out)
        self.assertIn("refused before running: the did-provider test executable differs", out)
        self.assertIn("versions bound after the run: no", out)
        self.assertTrue(did)

    def test_a8_refuses_when_the_launched_copy_differs(self):
        launched = self.fx.layout.runtime_build / "elastos"
        tampered = []

        def tamper():
            if not tampered:
                tampered.append(True)
                append_byte(launched)

        code, out, runner = self.run_demo(runner=FakeCargo(self.fx, during=tamper))
        self.assertFalse(any(args[0] == "cargo" for args, _, _ in runner.calls))
        self.assertEqual(code, demo.EXIT_FAIL)
        self.assertIn(
            "  A8         FAIL     A capsule cannot read a host SSH key",
            out,
        )
        self.assertIn(
            "refused before running: the elastos that real elastos binary through lab/agent-conformance "
            "launches differs from the installed copy",
            out,
        )

    def test_a8_cargo_must_run_the_recorded_executable(self):
        code, out, _ = self.run_demo(runner=FakeCargo(self.fx, running="/somewhere/else/effects-0"))
        self.assertEqual(code, demo.EXIT_FAIL)
        self.assertIn("cargo ran ['/somewhere/else/effects-0'], not the recorded test executable", out)

    def test_journey_identity_that_differs_fails_the_run(self):
        lines = [
            identity({"kind": "native", "role": "elastos", "sha256": "f" * 64}),
            identity({"kind": "native", "role": "localhost-provider", "sha256": sha(PROVIDER)}),
            identity({"kind": "launched", "probe": dict(PROBE)}),
        ]
        code, out, _ = self.run_demo(runner=FakeCargo(self.fx, a8_lines=lines))
        self.assertEqual(code, demo.EXIT_FAIL)
        self.assertIn("versions bound after the run: no", out)
        self.assertIn(f"a journey ran elastos with SHA-256 {'f' * 64}", out)
        self.assertIn("A14: FAIL.", out)

    def test_journey_probe_that_differs_fails_the_run(self):
        probe = dict(PROBE, component_sha256="9" * 64)
        lines = [identity({"kind": "launched", "probe": probe})]
        code, out, _ = self.run_demo(runner=FakeCargo(self.fx, a8_lines=lines))
        self.assertEqual(code, demo.EXIT_FAIL)
        self.assertIn("a journey printed probe 'host-key-read' as component " + "9" * 64, out)

    def test_missing_required_identity_fails_the_run(self):
        code, out, _ = self.run_demo(runner=FakeCargo(self.fx, a8_lines=[]))
        self.assertEqual(code, demo.EXIT_FAIL)
        self.assertIn("printed no native:elastos identity, so it is not bound", out)

    def test_install_changed_during_run_fails(self):
        changed = []

        def tamper():
            if not changed:
                changed.append(True)
                append_byte(self.fx.installed("bin", "localhost-provider"))

        code, out, _ = self.run_demo(runner=FakeCargo(self.fx, during=tamper))
        self.assertEqual(code, demo.EXIT_FAIL)
        self.assertIn("versions bound after the run: no", out)
        self.assertIn("installed localhost-provider differs", out)


class NeverPassWithoutARun(TempCase):
    def setUp(self):
        super().setUp()
        self.fx.install()
        _, self.suites, self.steps = demo.load_journeys()

    def test_macos_steps_do_not_run_off_macos(self):
        runner = FakeCargo(self.fx)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = demo.run_demo(self.fx.layout, "Linux", runner=runner, read=lambda repo: CLEAN)
        macos = {step.test for step in self.steps if step.platform == "macos"}
        anywhere = {step.test for step in self.steps if step.platform == "any"}
        self.assertTrue(macos and anywhere)
        self.assertEqual(journey_names(runner.calls), anywhere)
        self.assertEqual(code, demo.EXIT_NOT_RUN)
        text = out.getvalue()
        self.assertIn("A14: NOT RUN.", text)
        for step in self.steps:
            if step.platform == "macos":
                self.assertIn(f"  {step.id:<10} NOT RUN  {step.title}", text)

    def test_skip_line_is_not_run(self):
        step = next(step for step in self.steps if step.suite == "did-provider" and step.platform == "macos")
        skip = "SKIP did-provider confinement test: /usr/bin/sandbox-exec is absent"
        results, sections = demo.parse_libtest(libtest([step.test], {step.test: [skip]}))
        outcome = demo.grade(step, results, sections, 0, "Darwin", self.suites, "log")
        self.assertEqual(outcome.status, "NOT RUN")
        self.assertIn(skip, outcome.detail)

    def test_failed_or_missing_result_fails(self):
        step = self.steps[0]
        failed = libtest([step.test], {step.test: ["thread 't' panicked at src/x.rs:1:1:", "imports differ"]}, "FAILED")
        results, sections = demo.parse_libtest(failed)
        self.assertEqual(demo.grade(step, results, sections, 101, "Darwin", self.suites, "log").detail, "imports differ")
        outcome = demo.grade(step, {}, {}, 101, "Darwin", self.suites, "log")
        self.assertEqual(outcome.status, "FAIL")
        self.assertIn("no result for this test (cargo exit 101)", outcome.detail)

    def test_split_result_line_uses_the_final_list(self):
        text = "test a::b ... child output\nok\n\nsuccesses:\n    a::b\n\ntest result: ok. 1 passed\n"
        results, _ = demo.parse_libtest(text)
        self.assertEqual(results, {"a::b": ["ok"]})

    def test_journeys_name_each_check(self):
        checks, suites, steps = demo.load_journeys()
        self.assertEqual(
            list(checks), ["A1", "A2", "A8", "C1", "C2", "C3", "C4", "C5", "C6", "C7"]
        )
        for check in checks:
            self.assertTrue(any(step.check == check for step in steps), check)
        self.assertIn("launched:host-key-read", suites["agent-conformance"]["identities"])
        self.assertEqual(suites["agent-conformance"]["launches"], ["elastos", "localhost-provider"])

    def test_every_named_test_exists_in_its_suite(self):
        _, suites, steps = demo.load_journeys()
        for step in steps:
            with self.subTest(step.id):
                name = step.test.rsplit("::", 1)[-1]
                pattern = re.compile(rf"^\s*(?:async\s+)?fn {re.escape(name)}\(\)", re.MULTILINE)
                found = [
                    path
                    for path in (demo.REPO / suites[step.suite]["source"]).rglob("*.rs")
                    if pattern.search(path.read_text(encoding="utf-8", errors="replace"))
                ]
                self.assertTrue(found, f"{step.id}: no fn {name}() under {suites[step.suite]['source']}")


class InstallBinding(TempCase):
    def install(self, host_os="Darwin", receipt=None, artifacts=None, sign=False, ready=None):
        calls, built = [], []

        def fake(args, cwd, env=None):
            calls.append(args)
            return 0, []

        def builder(args, cwd, env):
            built.append(args)
            suite = next(name for name in SUITES if demo.load_journeys()[1][name]["cargo"] == args[1:-1])
            return 0, (artifacts or artifacts_for)(self.fx.layout.repo, suite)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = demo.install(
                self.fx.layout,
                host_os,
                str(receipt or self.fx.source),
                read=lambda repo: CLEAN,
                runner=fake,
                builder=builder,
                sign=sign,
                ready=ready or (lambda layout, host_os: []),
            )
        return code, out.getvalue(), calls, built

    def fetched_only(self, calls):
        return [args[:2] for args in calls] == [["cargo", "fetch"]] * len(demo.FETCH)

    def test_install_pins_files_the_run_accepts(self):
        code, out, calls, built = self.install()
        self.assertEqual(code, demo.EXIT_PASS, out)
        self.assertEqual(self.fx.gate(), [])
        fetches = len(demo.FETCH)
        self.assertTrue(self.fetched_only(calls[:fetches]))
        self.assertEqual(calls[fetches:], [["bash", str(self.fx.layout.repo / "examples" / "agent-host" / "build.sh")]])
        self.assertEqual(len(built), len(SUITES))
        self.assertTrue(all(args[-1] == "--no-run" for args in built))
        self.assertEqual(sorted(self.fx.record()["steps"]), sorted(SUITES))

    def test_install_refuses_a_receipt_that_does_not_match_the_build(self):
        append_byte(self.fx.layout.runtime_build / "elastos")
        code, out, calls, built = self.install()
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertTrue(self.fetched_only(calls), calls)
        self.assertEqual(built, [])
        self.assertFalse(self.fx.layout.install.exists())
        self.assertIn("the elastos lab/agent-conformance built differs from VERSIONS.json runtime_sha256", out)

    def test_install_refuses_a_receipt_from_another_commit(self):
        other = self.tmp / "other.json"
        other.write_bytes(encode(receipt_for(commit="d" * 40)))
        code, out, calls, built = self.install(receipt=other)
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertTrue(self.fetched_only(calls), calls)
        self.assertEqual(built, [])
        self.assertIn(f"VERSIONS.json was made at {'d' * 40}; this checkout is at {COMMIT}", out)

    def test_install_refuses_off_macos_without_a_receipt(self):
        calls = []
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = demo.install(
                self.fx.layout,
                "Linux",
                None,
                read=lambda repo: CLEAN,
                runner=calls.append,
                ready=lambda layout, host_os: [],
            )
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertEqual(calls, [])
        self.assertIn("runs on macOS only", out.getvalue())

    def test_install_refuses_unclear_test_executables(self):
        def twice(repo, suite):
            found = artifacts_for(repo, suite)
            return found + [dict(found[0], executable=found[0]["executable"] + "-again")]

        code, out, _, _ = self.install(artifacts=twice)
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertIn("Cargo built 2 test executables for runtime-compute; the run needs exactly one", out)
        self.assertFalse(self.fx.layout.install.exists())

        def outside(repo, suite):
            return [dict(artifacts_for(repo, suite)[0], executable=str(self.tmp / "elsewhere"))]

        code, out, _, _ = self.install(artifacts=outside)
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertIn("the runtime-compute test executable is outside the repository", out)

    def test_install_sign_turns_signing_on(self):
        code, out, _, _ = self.install(sign=True)
        self.assertEqual(code, demo.EXIT_PASS, out)
        self.assertTrue(self.fx.layout.signing_key.is_file())
        for name in demo.SIGNED:
            self.assertTrue(self.fx.installed(name + ".sig").is_file(), name)
        self.assertEqual(self.fx.gate(), [])
        self.assertIn("does not prove who published them", out)

    def test_install_sign_on_linux_without_receipt_does_not_write_the_key(self):
        calls = []
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = demo.install(
                self.fx.layout,
                "Linux",
                None,
                read=lambda repo: CLEAN,
                runner=calls.append,
                sign=True,
                ready=lambda layout, host_os: [],
            )
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertEqual(calls, [])
        self.assertFalse(self.fx.layout.signing_key.exists())
        self.assertFalse(self.fx.layout.signing_key.parent.exists())
        self.assertIn("no VERSIONS.json for this machine", out.getvalue())
        self.assertNotIn("Signing is on", out.getvalue())

    def test_install_refuses_before_fetch_when_the_machine_is_not_ready(self):
        def ready(layout, host_os):
            return ["this shell is Rosetta (sysctl.proc_translated=1); open a native arm64 Terminal"]

        code, out, calls, built = self.install(sign=True, ready=ready)
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertEqual(calls, [])
        self.assertEqual(built, [])
        self.assertFalse(self.fx.layout.signing_key.exists())
        self.assertFalse(self.fx.layout.install.exists())
        self.assertIn("REFUSED: this machine is not ready.", out)
        self.assertIn("open a native arm64 Terminal", out)
        summaries = list((self.fx.layout.install.parent / "runs").glob("*/summary.txt"))
        self.assertEqual(len(summaries), 1, summaries)
        self.assertIn("this machine is not ready", summaries[0].read_text())
        pointer = demo.this_run_pointer(self.fx.layout).read_text(encoding="utf-8").strip()
        self.assertEqual(Path(pointer) / "summary.txt", summaries[0])

    def test_install_default_ready_runs_preflight(self):
        """Skipping step 2 still runs the full preflight list. machine_problems alone is empty here."""
        (self.fx.layout.repo / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.91.0"\n')
        rustup = self.tmp / "rustup-default-ready"
        env = {"RUSTUP_HOME": str(rustup), "CARGO_HOME": str(self.tmp / "cargo-default-ready")}
        root = demo.toolchain_root(self.fx.layout.repo, "Darwin", "arm64", env)
        (root / "bin").mkdir(parents=True)
        (root / "bin" / "rustc").write_text("rustc\n")
        (root / "bin" / "rustc").chmod(0o755)
        (root / "lib" / "rustlib" / "wasm32-unknown-unknown").mkdir(parents=True)
        machine_ok = demo.machine_problems(
            self.fx.layout,
            "Darwin",
            env=env,
            disk_free=lambda path: demo.NEED_FREE,
            translated="0",
            present=lambda path: True,
            machine="arm64",
        )
        self.assertEqual(machine_ok, [], machine_ok)
        calls = []
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = demo.install(
                self.fx.layout,
                "Darwin",
                str(self.fx.source),
                read=lambda repo: CLEAN,
                runner=lambda *a, **k: calls.append(a) or (0, []),
                sign=True,
            )
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertEqual(calls, [])
        self.assertFalse(self.fx.layout.signing_key.exists())
        self.assertIn("preflight.sh is missing", out.getvalue())
        summaries = list((self.fx.layout.install.parent / "runs").glob("*/summary.txt"))
        self.assertEqual(len(summaries), 1, summaries)

    def test_failed_write_after_sign_removes_only_this_runs_key(self):
        def boom(*args, **kwargs):
            return ["disk full"]

        with mock.patch.object(demo, "write_install", boom):
            code, out, calls, built = self.install(sign=True)
        self.assertEqual(code, demo.EXIT_REFUSED, out)
        self.assertTrue(calls)
        self.assertTrue(built)
        self.assertFalse(self.fx.layout.signing_key.exists())
        self.assertFalse(self.fx.layout.signing_key.parent.exists())
        self.assertIn("Removed the signing key this run created, because the install write failed.", out)
        self.assertIn("disk full", out)
        summaries = list((self.fx.layout.install.parent / "runs").glob("*/summary.txt"))
        self.assertEqual(len(summaries), 1, summaries)
        self.assertIn("Removed the signing key this run created", summaries[0].read_text())

    def test_failed_write_keeps_a_preexisting_key(self):
        self.assertEqual(demo.make_signing_key(self.fx.layout), [])
        self.assertTrue(self.fx.layout.signing_key.is_file())

        def boom(*args, **kwargs):
            return ["disk full"]

        with mock.patch.object(demo, "write_install", boom):
            code, out, _, _ = self.install(sign=True)
        self.assertEqual(code, demo.EXIT_REFUSED, out)
        self.assertTrue(self.fx.layout.signing_key.is_file())
        self.assertNotIn("Removed the signing key this run created", out)


class Signing(TempCase):
    """An optional ed25519 signature by this machine's demo key over both receipt files."""

    def setUp(self):
        super().setUp()
        self.assertIsNotNone(shutil.which("ssh-keygen"), "the signing tests need ssh-keygen")
        self.assertEqual(demo.make_signing_key(self.fx.layout), [])
        self.fx.install()

    def test_signed_install_is_allowed(self):
        self.assertEqual(self.fx.gate(), [])
        for name in demo.SIGNED:
            self.assertTrue(self.fx.installed(name + ".sig").read_bytes().startswith(b"-----BEGIN SSH SIGNATURE-----"))

    def test_signing_key_is_private_and_outside_the_repository(self):
        key = self.fx.layout.signing_key
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(key.parent.stat().st_mode), 0o700)
        self.assertEqual(key.parent.parent, self.fx.layout.install.parent)
        self.assertNotIn(self.fx.layout.repo, key.parents)
        self.assertNotIn(demo.REPO, key.parents)

    def test_tampered_signed_receipt_is_refused(self):
        self.fx.change_receipt(lambda r: r.update(description="changed after signing"))
        self.assertEqual(demo.sign_file(self.fx.layout, self.fx.installed("INSTALL.json")), [])
        problems = self.fx.gate()
        self.assertNamed(problems, "VERSIONS.json signature does not verify with this machine's demo key")
        self.assertFalse(any(problem.startswith("INSTALL.json signature") for problem in problems), problems)

    def test_tampered_signed_install_record_is_refused(self):
        append_byte(self.fx.layout.agent_host_wasm)
        append_byte(self.fx.installed(demo.AGENT_HOST))
        record = self.fx.record()
        record["components"]["agent-host"]["sha256"] = demo.sha256_file(self.fx.layout.agent_host_wasm)
        self.fx.write_record(record)
        self.assertEqual(
            self.fx.gate(),
            ["INSTALL.json signature does not verify with this machine's demo key: "
             "the file changed after signing, or another key signed it"],
        )

    def test_unsigned_receipt_is_refused_when_signing_is_on(self):
        self.fx.installed("VERSIONS.json.sig").unlink()
        self.assertNamed(self.fx.gate(), "VERSIONS.json is unsigned, but signing is on")

    def test_signature_from_another_key_is_refused(self):
        other = demo.Layout(self.fx.layout.repo, self.tmp / "other-home" / "current")
        self.assertEqual(demo.make_signing_key(other), [])
        self.assertEqual(demo.sign_file(other, self.fx.installed("VERSIONS.json")), [])
        self.assertNamed(self.fx.gate(), "VERSIONS.json signature does not verify with this machine's demo key")

    def test_run_states_what_the_signature_proves(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = demo.run_demo(self.fx.layout, "Darwin", runner=FakeCargo(self.fx), read=lambda repo: CLEAN)
        self.assertEqual(code, demo.EXIT_PASS, out.getvalue())
        self.assertIn(
            "  signature  valid for both receipt files; it proves VERSIONS.json and INSTALL.json are unchanged "
            "since install on this machine; it does not prove who published them",
            out.getvalue(),
        )

    def test_signing_off_needs_no_signature(self):
        plain = Fixture(self.tmp / "plain").install()
        self.assertFalse(plain.installed("VERSIONS.json.sig").exists())
        self.assertEqual(plain.gate(), [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            demo.run_demo(plain.layout, "Darwin", runner=FakeCargo(plain), read=lambda repo: CLEAN)
        self.assertIn("  signature  off (install with --sign to turn it on)", out.getvalue())

    def test_demo_folder_inside_the_repository_is_refused(self):
        with mock.patch.dict(os.environ, {"DEMO_A14_HOME": str(demo.REPO / "lab" / "demo-a14" / "home")}):
            with self.assertRaises(ValueError):
                demo.demo_home("Darwin", demo.REPO)


class MachineReady(TempCase):
    """The install checks the Mac before cargo fetch and before it writes a key."""

    def setUp(self):
        super().setUp()
        (self.fx.layout.repo / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.91.0"\n')
        self.rustup = self.tmp / "rustup"
        self.ready_env = {"RUSTUP_HOME": str(self.rustup), "CARGO_HOME": str(self.tmp / "cargo")}

    def toolchain(self, host_os="Darwin", machine="arm64", wasm=True):
        root = demo.toolchain_root(self.fx.layout.repo, host_os, machine, self.ready_env)
        (root / "bin").mkdir(parents=True)
        (root / "bin" / "rustc").write_text("rustc\n")
        (root / "bin" / "rustc").chmod(0o755)
        if wasm:
            (root / "lib" / "rustlib" / "wasm32-unknown-unknown").mkdir(parents=True)
        return root

    def problems(self, host_os="Darwin", machine="arm64", **kwargs):
        kwargs.setdefault("env", self.ready_env)
        kwargs.setdefault("disk_free", lambda path: demo.NEED_FREE)
        kwargs.setdefault("translated", "0")
        kwargs.setdefault("present", lambda path: True)
        return demo.machine_problems(self.fx.layout, host_os, machine=machine, **kwargs)

    def test_ready_mac_is_allowed(self):
        self.toolchain()
        self.assertEqual(self.problems(), [])

    def test_rosetta_is_refused(self):
        self.toolchain()
        self.assertNamed(
            self.problems(translated="1"),
            "this shell is Rosetta (sysctl.proc_translated=1); open a native arm64 Terminal",
        )

    def test_non_arm64_mac_is_refused(self):
        self.toolchain(machine="x86_64")
        self.assertNamed(
            self.problems(machine="x86_64"),
            "architecture is x86_64",
            "open a native arm64 Terminal",
        )

    def test_outside_cargo_target_dir_is_refused(self):
        self.toolchain()
        env = {**self.ready_env, "CARGO_TARGET_DIR": str(self.tmp / "elsewhere")}
        self.assertNamed(self.problems(env=env), "CARGO_TARGET_DIR=", "outside the repository")

    def test_relative_cargo_target_dir_is_allowed(self):
        self.toolchain()
        env = {**self.ready_env, "CARGO_TARGET_DIR": "target-outside-name-only"}
        self.assertEqual(self.problems(env=env), [])

    def test_relative_cargo_target_dir_outside_the_repo_is_refused(self):
        self.toolchain()
        env = {**self.ready_env, "CARGO_TARGET_DIR": "../elsewhere"}
        self.assertNamed(self.problems(env=env), "CARGO_TARGET_DIR=../elsewhere", "outside the repository")
        self.assertFalse(demo.resolved_under(self.fx.layout.repo, "../elsewhere"))

    def test_space_in_home_is_refused(self):
        self.toolchain()
        self.assertNamed(self.problems(home=self.tmp / "User Name"), "HOME contains a space")

    def test_space_in_checkout_is_refused(self):
        self.toolchain()
        spaced = demo.Layout(self.tmp / "my repo", self.fx.layout.install)
        (spaced.repo / "rust-toolchain.toml").parent.mkdir(parents=True, exist_ok=True)
        (spaced.repo / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.91.0"\n')
        problems = demo.machine_problems(
            spaced,
            "Darwin",
            env=self.ready_env,
            disk_free=lambda path: demo.NEED_FREE,
            translated="0",
            present=lambda path: True,
            machine="arm64",
        )
        self.assertTrue(
            any("the checkout path contains a space" in problem for problem in problems),
            problems,
        )

    def test_missing_wasm_target_is_refused(self):
        self.toolchain(wasm=False)
        self.assertNamed(self.problems(), "wasm32-unknown-unknown is not installed for 1.91.0")

    def test_missing_sandbox_exec_is_refused(self):
        self.toolchain()
        self.assertNamed(
            self.problems(present=lambda path: path != "/usr/bin/sandbox-exec"),
            "/usr/bin/sandbox-exec is missing",
        )

    def test_low_disk_is_refused(self):
        self.toolchain()
        self.assertNamed(
            self.problems(disk_free=lambda path: demo.NEED_FREE - 1),
            "free space for the checkout",
            "the runbook asks for 40 GB",
        )

    def test_machine_problems_does_not_start_rustup(self):
        self.toolchain(wasm=False)
        started = []

        def fake_run(*args, **kwargs):
            started.append(args[0] if args else kwargs.get("args"))
            raise AssertionError("machine_problems must not start a process to see if a toolchain exists")

        with mock.patch.object(demo.subprocess, "run", fake_run):
            problems = self.problems(translated="0")
        self.assertNamed(problems, "wasm32-unknown-unknown")
        self.assertEqual(started, [])


class SuiteEnvironment(unittest.TestCase):
    def test_suite_env_forces_cargo_term_color_never(self):
        with mock.patch.dict(os.environ, {"CARGO_TERM_COLOR": "always"}, clear=False):
            env = demo.suite_env({"env": {}, "env_paths": {}}, Path("/tmp/repo"))
        self.assertEqual(env["CARGO_TERM_COLOR"], "never")


class RunbookMorningSteps(unittest.TestCase):
    def setUp(self):
        self.text = (LANE / "RUNBOOK.md").read_text(encoding="utf-8")

    def test_runbook_stays_on_the_demo_branch(self):
        self.assertIn("cursor/demo-a14-installed-demo-83e1", self.text)
        self.assertNotIn("git checkout spike/agent-host", self.text)
        self.assertNotIn("git checkout cursor/demo-a14-installed-demo-83e1", self.text)
        self.assertIn("/Users/sash/code/wt-agent-host", self.text)
        self.assertIn("~/code/elastos-agent-host-spike", self.text)
        self.assertIn("lab/demo-a14/preflight.sh", self.text)
        self.assertIn("git clone", self.text)
        self.assertIn("A zip from a browser", self.text)

    def test_runbook_uses_a_fresh_clone(self):
        self.assertIn('git clone --branch "$branch" "$url" "$dest"', self.text)
        self.assertIn("$HOME/a14-run-", self.text)
        self.assertIn('if [ -e "$dest" ]', self.text)
        self.assertIn("already exists", self.text)
        self.assertIn("never reuses a folder", self.text)
        self.assertIn("\ntest -f lab/demo-a14/install.sh\n", self.text)
        self.assertIn("\nset -euo pipefail\n", self.text)
        self.assertNotIn("cd /path/to/your/clone", self.text)
        self.assertNotIn("git checkout cursor/demo-a14-installed-demo-83e1", self.text)
        self.assertNotIn("git fetch origin cursor/demo-a14-installed-demo-83e1", self.text)

    def test_existing_destination_is_refused(self):
        dest = Path(tempfile.mkdtemp(prefix="a14-dest-"))
        self.addCleanup(shutil.rmtree, dest, True)
        script = (
            "set -euo pipefail\n"
            f'dest="{dest}"\n'
            'if [ -e "$dest" ]; then\n'
            "  printf 'REFUSED: %s already exists. This runbook never reuses a folder.\\n' \"$dest\" >&2\n"
            "  exit 3\n"
            "fi\n"
            "exit 0\n"
        )
        done = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
        self.assertIn("already exists", done.stderr)
        missing = dest / "no-such-install"
        script = (
            "set -euo pipefail\n"
            f'cd "{demo.REPO}"\n'
            f'test -f "{missing}"\n'
            "printf still-running\\n"
        )
        done = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn("still-running", done.stdout)

    def test_runbook_step_5_opens_only_a_real_path(self):
        self.assertIn(
            'test -n "$run" && test -d "$run" && test -f "$run/summary.txt" && open "$run/summary.txt"',
            self.text,
        )
        self.assertIn('sed -n \'1p\' "$demo_home/this-run"', self.text)
        self.assertNotIn(
            'open "$(ls -dt ~/Library/Application\\ Support/elastos-demo-a14/runs/*/',
            self.text,
        )
        self.assertNotIn("ls -dt", self.text)


class PreflightScript(unittest.TestCase):
    def test_preflight_names_linux_on_this_machine(self):
        done = subprocess.run(
            ["sh", str(LANE / "preflight.sh"), str(demo.REPO)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("preflight: FAIL", done.stdout)
        self.assertIn("operating system is Linux", done.stdout)
        self.assertIn("architecture is", done.stdout)
        self.assertNotIn("lab/demo-a14/install.sh is not in this checkout", done.stdout)

    def test_preflight_refuses_relative_cargo_target_dir_outside_the_repo(self):
        env = dict(os.environ)
        env["CARGO_TARGET_DIR"] = "../elsewhere"
        done = subprocess.run(
            ["sh", str(LANE / "preflight.sh"), str(demo.REPO)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("CARGO_TARGET_DIR=../elsewhere is outside the repository", done.stdout)

    def test_preflight_reports_quarantine_and_does_not_strip_it(self):
        text = (LANE / "preflight.sh").read_text(encoding="utf-8")
        self.assertIn('  if [ "$os" = Darwin ] && command -v xattr >/dev/null 2>&1; then\n', text)
        self.assertIn("xattr -p com.apple.quarantine", text)
        self.assertIn("com.apple.quarantine", text)
        self.assertNotIn("xattr -d", text)
        self.assertNotIn("xattr -c", text)
        self.assertNotIn("if false &&", text)
        for rel in (
            "lab/demo-a14/install.sh",
            "lab/demo-a14/run.sh",
            "lab/demo-a14/demo.py",
            "lab/demo-a14/preflight.sh",
            "lab/demo-a14/journeys.json",
            "lab/demo-a14/RUNBOOK.md",
        ):
            self.assertIn(rel, text)


class CheckoutIdentity(unittest.TestCase):
    def test_untracked_file_makes_the_checkout_dirty(self):
        repo = Path(tempfile.mkdtemp(prefix="demo-a14-git-"))
        self.addCleanup(shutil.rmtree, repo, True)

        def git(*args):
            subprocess.run(
                ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                cwd=repo,
                check=True,
                capture_output=True,
            )

        git("init", "-q")
        (repo / "a.txt").write_text("a\n")
        git("add", "a.txt")
        git("commit", "-q", "-m", "a")
        clean = demo.read_checkout(repo)
        self.assertTrue(clean.clean)
        self.assertTrue(demo.is_hex(clean.commit, 40) or demo.is_hex(clean.commit, 64))
        (repo / "b.txt").write_text("b\n")
        self.assertFalse(demo.read_checkout(repo).clean)


if __name__ == "__main__":
    unittest.main()
