"""The installed demo refuses to run unless its versions match VERSIONS.json.

Every fixture here is synthetic and lives in a temporary folder. None of it is
live evidence for A14; the real run is RUNBOOK.md on the Mac.
"""

import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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


class Fixture:
    """A checkout, one lab/agent-conformance build and one matching install."""

    def __init__(self, root):
        self.root = root
        self.layout = demo.Layout(root / "repo", root / "home" / "current")
        build = self.layout.runtime_build
        build.mkdir(parents=True)
        (build / "elastos").write_bytes(RUNTIME)
        (build / "localhost-provider").write_bytes(PROVIDER)
        self.layout.agent_host_wasm.parent.mkdir(parents=True)
        self.layout.agent_host_wasm.write_bytes(b"\0asm agent-host")
        self.receipt = receipt_for()
        self.source = root / "VERSIONS.json"
        self.source.write_bytes(encode(self.receipt))

    def install(self):
        problems = demo.write_install(self.layout, encode(self.receipt), self.source, CLEAN)
        assert problems == [], problems
        return self

    def gate(self, checkout=CLEAN):
        return demo.version_gate(self.layout, checkout)

    def installed(self, *parts):
        return self.layout.install.joinpath(*parts)

    def change_receipt(self, change):
        """Edit the installed receipt and re-pin it, so only its content is wrong."""
        receipt = json.loads(self.installed("VERSIONS.json").read_bytes())
        change(receipt)
        data = encode(receipt)
        self.installed("VERSIONS.json").write_bytes(data)
        record = json.loads(self.installed("INSTALL.json").read_text())
        record["versions_sha256"] = sha(data)
        self.installed("INSTALL.json").write_text(json.dumps(record))


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


class FakeCargo:
    """Answers each suite with libtest text; records every command it is given."""

    def __init__(self, receipt, a8_lines=None, during=None):
        self.calls = []
        self.during = during
        native = [
            {"kind": "native", "role": "elastos", "sha256": receipt["runtime_sha256"]},
            {"kind": "native", "role": "localhost-provider", "sha256": receipt["localhost_provider_sha256"]},
            {"kind": "launched", "probe": dict(PROBE)},
        ]
        self.a8 = a8_lines if a8_lines is not None else [identity(item) for item in native]

    def __call__(self, args, cwd, env, log, timeout):
        self.calls.append(args)
        if self.during:
            self.during()
        names = [arg for arg in args[args.index("--") + 1:] if not arg.startswith("--")]
        return 0, libtest(names, {"host_key_read_is_refused": self.a8})


def journey_names(calls):
    return {arg for args in calls for arg in args[args.index("--") + 1:] if not arg.startswith("--")}


class RunBinding(TempCase):
    def setUp(self):
        super().setUp()
        self.fx.install()

    def run_demo(self, host_os="Darwin", runner=None):
        runner = runner or FakeCargo(self.fx.receipt)
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
        self.assertFalse((self.fx.layout.install.parent / "runs").exists())

    def test_matching_run_walks_every_step(self):
        code, out, runner = self.run_demo()
        _, _, steps = demo.load_journeys()
        self.assertEqual(journey_names(runner.calls), {step.test for step in steps})
        self.assertIn("versions bound after the run: yes", out)
        self.assertIn("A14: PASS.", out)
        self.assertEqual(code, demo.EXIT_PASS)
        for step in steps:
            word = "PASS" if step.expect == "pass" else "REFUSED"
            self.assertIn(f"  {step.id:<10} {word:<8} {step.title}", out)

    def test_journey_identity_that_differs_fails_the_run(self):
        lines = [
            identity({"kind": "native", "role": "elastos", "sha256": "f" * 64}),
            identity({"kind": "native", "role": "localhost-provider", "sha256": sha(PROVIDER)}),
            identity({"kind": "launched", "probe": dict(PROBE)}),
        ]
        code, out, _ = self.run_demo(runner=FakeCargo(self.fx.receipt, a8_lines=lines))
        self.assertEqual(code, demo.EXIT_FAIL)
        self.assertIn("versions bound after the run: no", out)
        self.assertIn(f"a journey ran elastos with SHA-256 {'f' * 64}", out)
        self.assertIn("A14: FAIL.", out)

    def test_journey_probe_that_differs_fails_the_run(self):
        probe = dict(PROBE, component_sha256="9" * 64)
        lines = [identity({"kind": "launched", "probe": probe})]
        code, out, _ = self.run_demo(runner=FakeCargo(self.fx.receipt, a8_lines=lines))
        self.assertEqual(code, demo.EXIT_FAIL)
        self.assertIn("a journey printed probe 'host-key-read' as component " + "9" * 64, out)

    def test_missing_required_identity_fails_the_run(self):
        code, out, _ = self.run_demo(runner=FakeCargo(self.fx.receipt, a8_lines=[]))
        self.assertEqual(code, demo.EXIT_FAIL)
        self.assertIn("printed no native:elastos identity, so it is not bound", out)

    def test_install_changed_during_run_fails(self):
        changed = []

        def tamper():
            if not changed:
                changed.append(True)
                append_byte(self.fx.installed("bin", "localhost-provider"))

        code, out, _ = self.run_demo(runner=FakeCargo(self.fx.receipt, during=tamper))
        self.assertEqual(code, demo.EXIT_FAIL)
        self.assertIn("versions bound after the run: no", out)
        self.assertIn("installed localhost-provider differs", out)


class NeverPassWithoutARun(TempCase):
    def setUp(self):
        super().setUp()
        self.fx.install()
        _, self.suites, self.steps = demo.load_journeys()

    def test_macos_steps_do_not_run_off_macos(self):
        runner = FakeCargo(self.fx.receipt)
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


class InstallBinding(TempCase):
    def install(self, host_os="Darwin", receipt=None, runner=None):
        calls = []

        def fake(args, cwd, env=None):
            calls.append(args)
            return 0, []

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = demo.install(
                self.fx.layout,
                host_os,
                str(receipt or self.fx.source),
                read=lambda repo: CLEAN,
                runner=runner or fake,
            )
        return code, out.getvalue(), calls

    def fetched_only(self, calls):
        return [args[:2] for args in calls] == [["cargo", "fetch"]] * len(demo.FETCH)

    def test_install_pins_files_the_run_accepts(self):
        code, out, calls = self.install()
        self.assertEqual(code, demo.EXIT_PASS, out)
        self.assertEqual(demo.version_gate(self.fx.layout, CLEAN), [])
        fetches = len(demo.FETCH)
        self.assertTrue(self.fetched_only(calls[:fetches]))
        self.assertEqual(calls[fetches][-1], str(self.fx.layout.repo / "examples" / "agent-host" / "build.sh"))
        self.assertTrue(calls[fetches + 1:])
        self.assertTrue(all(args[-1] == "--no-run" for args in calls[fetches + 1:]))

    def test_install_refuses_a_receipt_that_does_not_match_the_build(self):
        append_byte(self.fx.layout.runtime_build / "elastos")
        code, out, calls = self.install()
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertTrue(self.fetched_only(calls), calls)
        self.assertFalse(self.fx.layout.install.exists())
        self.assertIn("the elastos lab/agent-conformance built differs from VERSIONS.json runtime_sha256", out)

    def test_install_refuses_a_receipt_from_another_commit(self):
        other = self.tmp / "other.json"
        other.write_bytes(encode(receipt_for(commit="d" * 40)))
        code, out, calls = self.install(receipt=other)
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertTrue(self.fetched_only(calls), calls)
        self.assertIn(f"VERSIONS.json was made at {'d' * 40}; this checkout is at {COMMIT}", out)

    def test_install_refuses_off_macos_without_a_receipt(self):
        calls = []
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = demo.install(self.fx.layout, "Linux", None, read=lambda repo: CLEAN, runner=calls.append)
        self.assertEqual(code, demo.EXIT_REFUSED)
        self.assertEqual(calls, [])
        self.assertIn("runs on macOS only", out.getvalue())


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
