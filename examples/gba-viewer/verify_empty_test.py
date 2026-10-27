#!/usr/bin/env python3
"""Check the empty-folder gate and falsify its refusal without starting Cargo."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE.parent / "capsule-kit" / "falsify"))
import falsify_kit as kit  # noqa: E402


def walk(script, cwd, tools):
    return subprocess.run(
        ["/bin/bash", str(script)], cwd=cwd,
        env={"PATH": f"{tools}{os.pathsep}{os.defpath}"},
        capture_output=True, text=True, timeout=10,
    )


class EmptyTests(unittest.TestCase):
    def test_an_empty_gba_folder_passes_and_a_viewer_source_is_refused(self):
        """an empty gba folder passes and a viewer source is refused"""
        with tempfile.TemporaryDirectory(prefix="gba-empty-") as temporary:
            root = pathlib.Path(temporary)
            tools = root / "bin"
            tools.mkdir()
            # Stub only recursive self-checks; every invocation runs the real walk.
            python = tools / "python3"
            python.write_text("#!/bin/sh\nexit 0\n")
            python.chmod(0o755)
            folder = root / "viewer"
            folder.mkdir()
            result = walk(HERE / "verify.sh", root, tools)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "gba-viewer: no viewer sources\n")
            self.assertEqual(result.stderr, "")

            script = folder / "verify.sh"
            shutil.copyfile(HERE / "verify.sh", script)
            shutil.copyfile(HERE / ".gitignore", folder / ".gitignore")
            (folder / "verify_empty_test.py").touch()
            result = walk(script, HERE, tools)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "gba-viewer: no viewer sources\n")
            self.assertEqual(result.stderr, "")

            for name in ("capsule.json", ".hidden-source", "source with spaces"):
                source = folder / name
                source.touch()
                result = walk(script, HERE, tools)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr, f"gba-viewer has no viewer yet; refusing {name}\n",
                )
                source.unlink()

            # Even an empty directory, or one with an allowed filename, is source.
            (folder / "verify_empty_test.py").unlink()
            for name in ("src", "verify_empty_test.py"):
                source = folder / name
                source.mkdir()
                result = walk(script, HERE, tools)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr, f"gba-viewer has no viewer yet; refusing {name}\n",
                )
                source.rmdir()


def test_fails(name):
    result = kit.run([sys.executable, "-I", __file__, "-v", name], HERE)
    output = result.stderr
    if "Ran 1 test in " not in output or "ERROR:" in output:
        raise SystemExit(f"the empty-folder test did not run cleanly:\n{output}")
    return result.returncode != 0 and "FAILED (failures=1)" in output


if __name__ == "__main__":
    if "--falsify" in sys.argv[1:]:
        cases = [(
            "a viewer source is accepted by the empty-folder gate",
            HERE / "verify.sh",
            [("    exit 1\n", "    exit 0\n")],
            ["EmptyTests.test_an_empty_gba_folder_passes_and_a_viewer_source_is_refused"],
        )]
        kit.main([(cases, None, test_fails, None, True)], args=[],
                 done="all 1 gba empty-folder falsifiers caught")
    else:
        unittest.main(verbosity=2)
