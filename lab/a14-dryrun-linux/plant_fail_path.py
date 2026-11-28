#!/usr/bin/env python3
"""Run the FAIL-path demo fixture and prove A14: PASS. is absent from that run."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_tests(path: Path):
    spec = importlib.util.spec_from_file_location("demo_a14_tests", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    tests_py = Path.cwd() / "tests" / "test_version_binding.py"
    if not tests_py.is_file():
        tests_py = Path("lab/demo-a14/tests/test_version_binding.py")
    module = load_tests(tests_py.resolve())
    case = module.RunBinding("test_executable_changed_before_its_suite_is_not_run")
    case.setUp()
    try:
        target = module.Path(case.fx.step("did-provider")["test"]["path"])

        def during():
            if target.exists():
                module.append_byte(target)

        code, out, _ = case.run_demo(runner=module.FakeCargo(case.fx, during=during))
        pointer = Path(module.demo.this_run_pointer(case.fx.layout).read_text(encoding="utf-8").strip())
        summary = (pointer / "summary.txt").read_text(encoding="utf-8")
        print(f"exit {code}")
        print(f"stdout_has_PASS {'A14: PASS.' in out}")
        print(f"summary_has_PASS {'A14: PASS.' in summary}")
        print(f"summary_has_FAIL {'A14: FAIL.' in summary}")
        print(f"pointer {pointer / 'summary.txt'}")
        ok = (
            code == module.demo.EXIT_FAIL
            and "A14: PASS." not in out
            and "A14: PASS." not in summary
            and "A14: FAIL." in summary
        )
        return 0 if ok else 1
    finally:
        case.tearDown()


if __name__ == "__main__":
    sys.exit(main())
