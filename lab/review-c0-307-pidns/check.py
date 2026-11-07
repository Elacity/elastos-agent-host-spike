#!/usr/bin/env python3
"""Cheap detectors for this review. They read evidence/ and FCL_SRC."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REVIEW = Path(__file__).resolve().parent
FCL = Path(
    os.environ.get("FCL_SRC", "/tmp/fcl-637345ac/lab/fail-closed-linux")
)


def ok(name: str, cond: bool, detail: str) -> bool:
    print(f"{'PASS' if cond else 'FAIL'}  {name}  {detail}")
    return cond


def main() -> int:
    lib = (FCL / "src/lib.rs").read_text()
    real = (FCL / "src/real.rs").read_text()
    results = []

    confine_at = lib.find("pub fn confine<")
    and_exec_at = lib.find("pub fn confine_and_exec<")
    results.append(
        ok(
            "order.unshare-before-caps",
            lib.find("unshare_pid_namespace()", confine_at)
            < lib.find("last_capability()", confine_at),
            "unshare_pid is inside confine, before cap drop",
        )
    )
    results.append(
        ok(
            "order.detach-after-confine",
            lib.find("confine(kernel, plan)?", and_exec_at)
            < lib.find("detach_into_pid_namespace()", and_exec_at)
            < lib.find("exec(plan)", and_exec_at),
            "reaper forks run after confine returns",
        )
    )
    results.append(
        ok(
            "pipe.empty-is-start",
            "if got == 0 && read_error.is_none()" in real
            and "return Ok(pid as u32)" in real,
            "spawn_confined treats an empty fault pipe as a start",
        )
    )
    results.append(
        ok(
            "pipe.close-then-reap",
            real.find("close_fault_write(self)")
            < real.find("reap_forever(init)"),
            "helper closes the fault write end before it waits",
        )
    )
    results.append(
        ok(
            "policy.abi5-launches",
            "assert_eq!(missing_required_mask(5), None)" in lib
            or " (5, None, true)" in lib,
            "file-profile policy launches on reported ABI 5",
        )
    )

    test = REVIEW / "evidence" / "cargo-test.txt"
    text = test.read_text() if test.is_file() else ""
    results.append(
        ok(
            "rerun.counts",
            "6 passed; 0 failed; 0 ignored" in text
            and "14 passed; 0 failed; 0 ignored" in text
            and "13 passed; 0 failed; 0 ignored" in text,
            "lib 6 / simulated 14 / real_kernel 13, 0 ignored",
        )
    )
    falsify = REVIEW / "evidence" / "falsify.txt"
    ftext = falsify.read_text() if falsify.is_file() else ""
    results.append(
        ok(
            "rerun.falsify",
            "falsifiers: 19/19 caught; controls: 1/1 survived" in ftext,
            "19/19 caught, control survived",
        )
    )

    attack = REVIEW / "evidence" / "pidns-attack.json"
    if attack.is_file():
        data = json.loads(attack.read_text())
        results.append(
            ok(
                "pidns.helper-in-host-ns",
                data["tree"]["helper_shares_host_pid_ns"] is True,
                "helper stays in the host PID namespace",
            )
        )
        results.append(
            ok(
                "pidns.sigkill-helper",
                data["sigkill_helper"]["after_sigkill_helper"]["provider_alive"]
                is True,
                "SIGKILL of launch pid left the provider alive",
            )
        )
    else:
        results.append(ok("pidns.live", False, "pidns-attack.json missing"))

    failed = sum(1 for row in results if not row)
    print(f"summary  {len(results) - failed} passed {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
