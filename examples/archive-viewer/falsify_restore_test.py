#!/usr/bin/env python3
"""Check interrupted-plant recovery and falsify it with the kit; Cargo stays idle."""
import os
import pathlib
import selectors
import signal
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from falsify import SNAPSHOT_FILES, kit, restore_interrupted_plants  # noqa: E402


class RestoreTests(unittest.TestCase):
    def run_verify_steps(self, root, script, ending, stop_signal=None):
        # Execute the actual recovery, snapshot and traps, with no Cargo or
        # recursive self-test. Only the work between setup and exit is a stub.
        start = script.index('(\n    cd "${VIEWER_DIR}"')
        end = script.index('python3 -I "${REPO_ROOT}/examples/capsule-kit/scripts/check-manifest.py"')
        harness = 'set -euo pipefail\nVIEWER_DIR="$1"\n' + script[start:end]
        harness += (
            'host_log="${VIEWER_DIR}/host.log"\n'
            'runtime_log="${VIEWER_DIR}/runtime.log"\n'
            'touch "$host_log" "$runtime_log"\n'
        ) + ending
        with subprocess.Popen(
            ["bash", "-c", harness, "verify-restore-test", str(root)],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, start_new_session=True,
        ) as process:
            try:
                if stop_signal is not None:
                    with selectors.DefaultSelector() as ready:
                        ready.register(process.stdout, selectors.EVENT_READ)
                        self.assertTrue(ready.select(timeout=10), "plant did not start")
                    self.assertEqual(process.stdout.readline().strip(), "planted")
                    os.killpg(process.pid, stop_signal)
                output, _ = process.communicate(timeout=10)
                return process.returncode, output
            finally:
                # Also reap the sleeping child when an assertion fails.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate(timeout=10)

    def test_a_killed_falsifier_does_not_stay_planted(self):
        """a killed falsifier does not stay planted"""
        script = (HERE / "verify.sh").read_text()
        restore = script.index("restore_interrupted_plants()")
        self.assertLess(restore, script.index("cargo test"))
        self.assertLess(
            script.index('python3 -I "${VIEWER_DIR}/falsify_restore_test.py"\n'),
            script.index('python3 -I "${VIEWER_DIR}/falsify_restore_test.py" --falsify'),
        )
        self.assertLess(
            script.index('python3 -I "${VIEWER_DIR}/falsify_restore_test.py" --falsify'),
            restore,
        )
        originals = {name: f"clean {name}\n".encode() for name in SNAPSHOT_FILES}
        originals["src/preview.rs"] = b"if consumed != data.len() || produced != declared {\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve() / "archive-viewer"
            root.mkdir()
            # The copied module's default HERE is this isolated fixture; its
            # kit import still uses the existing runner, without copying it.
            (root / "falsify.py").write_bytes((HERE / "falsify.py").read_bytes())
            (root.parent / "capsule-kit").symlink_to(HERE.parent / "capsule-kit")
            snapshot = root / ".verify-snapshot"
            (root / "src").mkdir()
            (snapshot / "src").mkdir(parents=True)
            for name, data in originals.items():
                (snapshot / name).write_bytes(data)
                (root / name).write_bytes(b"planted\n")
            (root / "src/preview.rs").write_bytes(
                originals["src/preview.rs"].replace(b"produced != declared", b"produced > declared")
            )
            (snapshot / "INCOMPLETE").touch()
            restore_interrupted_plants(root)
            for name, data in originals.items():
                self.assertEqual((root / name).read_bytes(), data)
            self.assertFalse(snapshot.exists())

            # An unstamped snapshot leaves the current sources alone.
            (snapshot / "src").mkdir(parents=True)
            for name, data in originals.items():
                (snapshot / name).write_bytes(data)
                (root / name).write_bytes(b"current\n")
            restore_interrupted_plants(root)
            self.assertTrue(snapshot.exists())
            for name in SNAPSHOT_FILES:
                self.assertEqual((root / name).read_bytes(), b"current\n")

            # Check the complete saved set before restoring any source.
            (snapshot / "INCOMPLETE").touch()
            for missing in SNAPSHOT_FILES:
                with self.subTest(missing=missing):
                    (snapshot / missing).unlink()
                    with self.assertRaises(SystemExit) as refusal:
                        restore_interrupted_plants(root)
                    self.assertEqual(
                        str(refusal.exception),
                        f"cannot restore interrupted falsifier: missing snapshot file {snapshot / missing}",
                    )
                    self.assertTrue((snapshot / "INCOMPLETE").exists())
                    for name in SNAPSHOT_FILES:
                        self.assertEqual((root / name).read_bytes(), b"current\n")
                    (snapshot / missing).write_bytes(originals[missing])

            # The real preamble must stop before any work on an incomplete
            # snapshot. Its trap must leave all recovery bytes in place.
            missing = SNAPSHOT_FILES[-1]
            (snapshot / missing).unlink()
            code, output = self.run_verify_steps(root, script, "echo work-started\n")
            self.assertEqual(code, 1, output)
            self.assertEqual(
                output.strip(),
                f"cannot restore interrupted falsifier: missing snapshot file {snapshot / missing}",
            )
            self.assertTrue((snapshot / "INCOMPLETE").exists())
            for name in SNAPSHOT_FILES:
                self.assertEqual((root / name).read_bytes(), b"current\n")
            (snapshot / missing).write_bytes(originals[missing])
            restore_interrupted_plants(root)

            plant = """python3 -I - <<'PY'
import pathlib
import signal

# A background supervisor can pass ignored signals through bash and exec.
# This planted child must terminate when the test signals its process group.
for stop_signal in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(stop_signal, signal.SIG_DFL)

preview = pathlib.Path("src/preview.rs")
preview.write_bytes(preview.read_bytes().replace(b"produced != declared", b"produced > declared"))
print("planted", flush=True)
signal.pause()
PY
"""
            for stop_signal in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGKILL):
                code, output = self.run_verify_steps(root, script, plant, stop_signal)
                expected = -signal.SIGKILL if stop_signal == signal.SIGKILL else 128 + stop_signal
                self.assertEqual(code, expected, output)
                self.assertIn(b"produced > declared", (root / "src/preview.rs").read_bytes())
                self.assertTrue((snapshot / "INCOMPLETE").is_file())
                for name, data in originals.items():
                    self.assertTrue((snapshot / name).is_file(), f"missing saved {name}")
                    self.assertEqual((snapshot / name).read_bytes(), data)
                if stop_signal != signal.SIGKILL:
                    self.assertFalse((root / "host.log").exists())
                    self.assertFalse((root / "runtime.log").exists())
                restore_interrupted_plants(root)
                for name, data in originals.items():
                    self.assertEqual((root / name).read_bytes(), data)
                self.assertFalse(snapshot.exists())

            # Failure retains the snapshot; the next successful run restores
            # it before work and removes it only at the real completion line.
            code, output = self.run_verify_steps(root, script, "exit 1\n")
            self.assertEqual(code, 1, output)
            self.assertTrue((snapshot / "INCOMPLETE").exists())
            (root / "src/preview.rs").write_bytes(b"planted\n")
            finish = script[script.index('echo "archive-viewer verification: OK"'):]
            code, output = self.run_verify_steps(root, script, finish)
            self.assertEqual(code, 0, output)
            for name, data in originals.items():
                self.assertEqual((root / name).read_bytes(), data)
            self.assertFalse(snapshot.exists())
            self.assertFalse((root / "host.log").exists())
            self.assertFalse((root / "runtime.log").exists())


def test_fails(name):
    result = kit.run([sys.executable, "-I", __file__, "-v", name], HERE)
    output = result.stderr
    if "Ran 1 test in " not in output or "ERROR:" in output:
        raise SystemExit(f"the restore test did not run cleanly:\n{output}")
    return result.returncode != 0 and "FAILED (failures=1)" in output


if __name__ == "__main__":
    if "--falsify" in sys.argv[1:]:
        cases = [(
            "a killed falsifier stays planted",
            HERE / "falsify.py",
            [(
                "def restore_interrupted_plants(root=HERE):\n",
                "def restore_interrupted_plants(root=HERE):\n    return\n",
            )],
            ["RestoreTests.test_a_killed_falsifier_does_not_stay_planted"],
        )]
        for name, old, new in (
            ("a signal deletes the recovery snapshot",
             "    if [[ $verification_complete -eq 1 ]]; then\n",
             "    if true; then\n"),
            ("the clean source bytes are never saved",
             "    saved.write_bytes(pathlib.Path(name).read_bytes())\n",
             "    pass\n"),
            ("the snapshot is never stamped",
             '(snapshot / "INCOMPLETE").touch()\n', "pass\n"),
            ("a successful verification keeps its snapshot",
             "\nverification_complete=1\n", "\n# completion omitted\n"),
        ):
            cases.append((name, HERE / "verify.sh", [(old, new)],
                          ["RestoreTests.test_a_killed_falsifier_does_not_stay_planted"]))
        kit.main([(cases, None, test_fails, None, True)], args=[],
                 done=f"all {len(cases)} archive restore falsifiers caught")
    else:
        unittest.main(verbosity=2)
