#!/usr/bin/env python3
"""Check snapshot recovery and falsify it with the kit runner; Cargo stays idle."""
import os
import pathlib
import re
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from falsify import SNAPSHOT_FILES, kit  # noqa: E402

CLEAN_PREVIEW = b"if consumed != data.len() || produced != declared {\n"
PLANTED_PREVIEW = CLEAN_PREVIEW.replace(b"produced != declared", b"produced > declared")


def snapshot_shell():
    """Use the actual shell functions, without running the verification gates."""
    source = (HERE / "verify.sh").read_text()
    functions = []
    for name in ("snapshot_cleanup", "install_snapshot_traps"):
        match = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", source, re.M | re.S)
        if match is None:
            raise AssertionError(f"verify.sh is missing {name}")
        functions.append(match.group())
    return '''set -euo pipefail
VIEWER_DIR="$1"
snapshot_keep=0
host_log="$VIEWER_DIR/host.log"
runtime_log="$VIEWER_DIR/runtime.log"
touch "$host_log" "$runtime_log"
''' + "\n".join(functions) + "\n"


def restore(root):
    return subprocess.run(
        [sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
         "from falsify import restore_interrupted_plants; "
         "restore_interrupted_plants(sys.argv[2])", str(HERE), str(root)],
        capture_output=True, text=True, timeout=2,
    )


class RestoreTests(unittest.TestCase):
    def test_a_normal_failure_removes_the_snapshot(self):
        """a normal failure removes the snapshot"""
        for command, code in (("false", 1), ("exit 1", 1), ("exit 0", 0)):
            with tempfile.TemporaryDirectory() as folder:
                root = pathlib.Path(folder)
                script = snapshot_shell() + '''install_snapshot_traps
mkdir -p "$VIEWER_DIR/.verify-snapshot"
touch "$VIEWER_DIR/.verify-snapshot/INCOMPLETE"
''' + command
                started = time.monotonic()
                result = subprocess.run(
                    ["bash", "-c", script, "snapshot-test", folder],
                    capture_output=True, text=True, timeout=2,
                )
                self.assertLess(time.monotonic() - started, 2)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertFalse((root / ".verify-snapshot").exists())
                self.assertFalse((root / "host.log").exists())
                self.assertFalse((root / "runtime.log").exists())

    def test_a_signal_keeps_the_clean_snapshot(self):
        """a signal keeps the clean snapshot"""
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            script = snapshot_shell() + '''install_snapshot_traps
mkdir -p "$VIEWER_DIR/src" "$VIEWER_DIR/.verify-snapshot/src"
printf '%s\n' 'if consumed != data.len() || produced != declared {' > "$VIEWER_DIR/src/preview.rs"
cp "$VIEWER_DIR/src/preview.rs" "$VIEWER_DIR/.verify-snapshot/src/preview.rs"
touch "$VIEWER_DIR/.verify-snapshot/INCOMPLETE"
echo planted
sleep 30 &
wait "$!"
'''
            process = subprocess.Popen(
                ["bash", "-c", script, "snapshot-test", folder],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                start_new_session=True,
            )
            try:
                while True:
                    ready, _, _ = select.select([process.stdout], [], [], 2)
                    self.assertTrue(ready, "the signal fixture did not reach planted")
                    line = process.stdout.readline()
                    self.assertTrue(line, "the signal fixture exited before planted")
                    if line.strip() == "planted":
                        break
                os.killpg(process.pid, signal.SIGTERM)
                self.assertEqual(process.wait(timeout=3), 143)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
                process.stdout.close()
            snapshot = root / ".verify-snapshot"
            self.assertTrue((snapshot / "INCOMPLETE").is_file())
            self.assertEqual((snapshot / "src/preview.rs").read_bytes(), CLEAN_PREVIEW)
            self.assertEqual((root / "src/preview.rs").read_bytes(), CLEAN_PREVIEW)
            self.assertFalse((root / "host.log").exists())
            self.assertFalse((root / "runtime.log").exists())

    def test_a_killed_falsifier_does_not_stay_planted(self):
        """a killed falsifier does not stay planted"""
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            snapshot = root / ".verify-snapshot"
            clean = {name: (CLEAN_PREVIEW if name == "src/preview.rs" else
                            f"clean {name}\n".encode()) for name in SNAPSHOT_FILES}
            planted = {name: (PLANTED_PREVIEW if name == "src/preview.rs" else
                              f"planted {name}\n".encode()) for name in SNAPSHOT_FILES}
            for name in SNAPSHOT_FILES:
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(planted[name])
                (snapshot / name).parent.mkdir(parents=True, exist_ok=True)
                (snapshot / name).write_bytes(clean[name])

            # Saved bytes without the stamp leave newer source alone.
            result = restore(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual({name: (root / name).read_bytes() for name in SNAPSHOT_FILES}, planted)
            self.assertTrue(snapshot.is_dir())

            (snapshot / "INCOMPLETE").touch()
            # Every missing file refuses before any source file is copied.
            for missing in SNAPSHOT_FILES:
                (snapshot / missing).unlink()
                result = restore(root)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(str(snapshot / missing), result.stderr)
                self.assertTrue((snapshot / "INCOMPLETE").is_file())
                self.assertEqual({name: (root / name).read_bytes() for name in SNAPSHOT_FILES}, planted)
                (snapshot / missing).write_bytes(clean[missing])

            result = restore(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual({name: (root / name).read_bytes() for name in SNAPSHOT_FILES}, clean)
            self.assertFalse(snapshot.exists())


def failing_tests(*names):
    result = kit.run([sys.executable, "-I", __file__, "-v", *names], HERE)
    output = result.stderr
    count = len(names) if names else 3
    if f"Ran {count} test" not in output or "ERROR:" in output:
        raise SystemExit(f"the restore tests did not run cleanly:\n{output}")
    failed = set(re.findall(r"^FAIL: (\w+) \(__main__\.(\w+)(?:\.\w+)?\)$", output, re.M))
    if result.returncode != (1 if failed else 0):
        raise SystemExit(f"the restore tests did not report their failures:\n{output}")
    return {f"{group}.{name}" for name, group in failed}


def test_fails(name):
    return failing_tests(name) == {name}


if __name__ == "__main__":
    if "--falsify" in sys.argv[1:]:
        cases = [(
            "an interrupted plant is left in the source",
            HERE / "falsify.py",
            [("def restore_interrupted_plants(root=HERE):\n",
              "def restore_interrupted_plants(root=HERE):\n    return\n")],
            ["RestoreTests.test_a_killed_falsifier_does_not_stay_planted"],
        )]
        kit.main([(cases, None, test_fails, None, True, failing_tests)], args=[],
                 done="all 1 archive restore falsifiers caught")
    else:
        unittest.main(verbosity=2)
