#!/usr/bin/env python3
"""scripts/build.sh hands a capsule's container recipe the capsule folder.

Usage: build_entry_test.py

A probe capsule has no build.sh, only repro/build-in-container.sh, which prints
the argument it got and exits: no container and no Cargo run. The recipe must
receive the capsule folder relative to the repository root, the form the kit's
container builder uses inside the mounted checkout.
"""
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
KIT = HERE.parent
REPO = KIT.parent.parent
BUILD = KIT / "scripts" / "build.sh"


def main():
    with tempfile.TemporaryDirectory(dir=KIT) as temporary:
        capsule = pathlib.Path(temporary)
        (capsule / "capsule.json").write_text(
            '{"schema": "elastos.capsule/v1", "name": "probe"}\n')
        recipe = capsule / "repro" / "build-in-container.sh"
        recipe.parent.mkdir()
        recipe.write_text('#!/usr/bin/env bash\nprintf "recipe-arg:%s\\n" "$1"\n')
        recipe.chmod(0o755)
        expected = capsule.relative_to(REPO).as_posix()
        result = subprocess.run([str(BUILD), str(capsule)], capture_output=True, text=True)
        if result.returncode != 0:
            raise SystemExit(f"build.sh refused the probe capsule:\n{result.stderr}")
        if f"recipe-arg:{expected}\n" not in result.stdout:
            raise SystemExit(f"the container recipe did not get the capsule folder "
                             f"({expected}):\n{result.stdout}{result.stderr}")
        print(f"the container recipe got the capsule folder: {expected}")


if __name__ == "__main__":
    main()
