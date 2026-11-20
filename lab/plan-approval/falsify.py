#!/usr/bin/env python3
"""Run each plan-approval plant against its named test, then restore source."""

import json
import pathlib
import subprocess
import sys


LANE = pathlib.Path(__file__).resolve().parent


def main():
    plants = json.loads((LANE / "falsifiers.json").read_text())["falsifiers"]
    for plant in plants:
        source = (LANE / plant["file"]).resolve()
        original = source.read_text()
        old, new = plant["old"], plant["new"]
        if original.count(old) != 1:
            raise SystemExit(f"{plant['id']}: expected one original binding rule")
        try:
            source.write_text(original.replace(old, new, 1))
            result = subprocess.run(
                ["cargo", "test", "--locked", "--lib", plant["test"],
                 "--", "--exact", "--nocapture"],
                cwd=LANE, capture_output=True, text=True, check=False,
            )
        finally:
            source.write_text(original)
        failure = f"test {plant['test']} ... FAILED"
        if result.returncode == 0 or failure not in result.stdout:
            raise SystemExit(
                f"{plant['id']}: named test did not fail under the plant\n"
                f"{result.stdout}\n{result.stderr}"
            )
        print(f"{plant['id']}: CAUGHT by {plant['test']}")
    restored = subprocess.run(["cargo", "test", "--locked", "--lib",
                               "a_grant_bound_to_one_plan_is_refused_for_another_plan",
                               "--", "--exact"], cwd=LANE, check=False)
    if restored.returncode:
        raise SystemExit("restored binding journey failed")


if __name__ == "__main__":
    main()
