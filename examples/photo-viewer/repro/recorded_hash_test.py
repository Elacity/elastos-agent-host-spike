#!/usr/bin/env python3
"""Check the hash record and artifact comparison without Cargo or Docker."""
import hashlib
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
EXAMPLES = HERE.parent.parent
KIT = EXAMPLES / "capsule-kit"
RECORD = KIT / "repro" / "recorded-hashes.txt"
CHECK = KIT / "repro" / "check-recorded-hash.py"
README = HERE / "README.md"
sys.path.insert(0, str(KIT / "falsify"))
import falsify_kit as kit  # noqa: E402

TEST = "RecordedHashTests.test_the_recorded_hash_check_compares_the_artifact"
CASES = [
    (
        "the recorded hash check accepts changed bytes",
        CHECK,
        [("if computed != recorded:", "if False and computed != recorded:")],
        [TEST],
    ),
    (
        "the repro readme repeats the photo hash",
        README, [], [TEST],
        [(README, "\n053b198d14e0b2abf1a2d911f3513e2d5bc9280b7202af806f56c71b86529cfc\n")],
    ),
]


class RecordedHashTests(unittest.TestCase):
    def check_result(self, name, artifact, record, code, reason=""):
        command = [sys.executable, "-I", str(CHECK), name, str(artifact)]
        if record is not None:
            command.extend(["--record", str(record)])
        result = kit.run(command, HERE)
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, reason)

    def test_the_recorded_hash_check_compares_the_artifact(self):
        """the recorded hash check compares the artifact"""
        lines = [line for line in RECORD.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(len(lines), 2)
        for name, line in zip(("photo-viewer", "docs-viewer"), lines):
            self.assertRegex(line, rf"\A{name} [0-9a-f]{{64}}\Z")
        hashes = [line.split()[1] for line in lines]
        self.assertEqual(CASES[1][4][0][1], f"\n{hashes[0]}\n",
                         "update the stale photo-hash plant from the record")
        for folder in ("photo-viewer", "docs-viewer", "capsule-kit"):
            for path in (EXAMPLES / folder).rglob("*.md"):
                text = path.read_text()
                for value in hashes:
                    self.assertNotIn(value, text,
                                     f"{path}: refer to recorded-hashes.txt instead")

        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            root = pathlib.Path(temporary)
            artifact = root / "artifact.bin"
            record = root / "hashes.txt"
            original = b"artifact\x00"
            changed = b"artifact\x01"
            recorded = hashlib.sha256(original).hexdigest()
            computed = hashlib.sha256(changed).hexdigest()
            record.write_text(f"# Temporary test record\n\nphoto-viewer {recorded}\n")
            artifact.write_bytes(original)
            self.check_result("photo-viewer", artifact, record, 0)
            artifact.write_bytes(changed)
            self.check_result("photo-viewer", artifact, record, 1,
                              f"recorded hash for photo-viewer is {recorded}; "
                              f"this artifact hashes to {computed}\n")
            self.check_result("unknown", artifact, record, 1,
                              "no recorded hash for unknown\n")
            self.check_result("unknown", artifact, None, 1,
                              "no recorded hash for unknown\n")
            artifact.unlink()
            self.check_result("photo-viewer", artifact, record, 1,
                              f"artifact is absent: {artifact}\n")


def test_fails(name):
    result = kit.run([sys.executable, "-I", __file__, "-v", name], HERE)
    output = result.stderr
    if "Ran 1 test in " not in output or "ERROR:" in output:
        raise SystemExit(f"the recorded hash test did not run cleanly:\n{output}")
    return result.returncode != 0 and "FAILED (failures=1)" in output


if __name__ == "__main__":
    if "--falsify" in sys.argv[1:]:
        kit.main([(CASES, None, test_fails, None, True)], args=[],
                 done="all 2 recorded hash falsifiers caught")
    else:
        unittest.main(verbosity=2)
