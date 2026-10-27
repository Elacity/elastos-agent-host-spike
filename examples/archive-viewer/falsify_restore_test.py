#!/usr/bin/env python3
"""Check interrupted-plant recovery and falsify it with the kit; Cargo stays idle."""
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from falsify import SNAPSHOT_FILES, kit, restore_interrupted_plants  # noqa: E402


class RestoreTests(unittest.TestCase):
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
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            root = pathlib.Path(temporary)
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
                    with self.assertRaisesRegex(SystemExit, "missing snapshot file"):
                        restore_interrupted_plants(root)
                    self.assertTrue((snapshot / "INCOMPLETE").exists())
                    for name in SNAPSHOT_FILES:
                        self.assertEqual((root / name).read_bytes(), b"current\n")
                    (snapshot / missing).write_bytes(originals[missing])


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
        kit.main([(cases, None, test_fails, None, True)], args=[],
                 done="all 1 archive restore falsifiers caught")
    else:
        unittest.main(verbosity=2)
