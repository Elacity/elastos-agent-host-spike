#!/usr/bin/env python3
"""Unit tests for the review grader and skip detector."""

import tempfile
import unittest
from pathlib import Path

from check import grade, parse_ops
from run import source_skip_pass


class GradeTests(unittest.TestCase):
    def test_missing_row_is_an_escape(self):
        ok, holes = grade("op=storage-write result=ok reason=x\n")
        self.assertFalse(ok)
        self.assertTrue(any(h.startswith("socket-inet: missing") for h in holes))

    def test_ok_on_must_deny_is_an_escape(self):
        body = "".join(
            f"op={name} result=refused errno=1 reason=x\n"
            for name in (
                "socket-inet",
                "socket-unix",
                "abstract-unix",
                "ptrace",
                "proc-self-mem",
                "unshare-user",
                "unshare-net",
                "setns",
                "keyctl",
                "bpf",
                "io-uring",
                "perf-event-open",
                "userfaultfd",
                "pidfd-open",
                "process-vm-readv",
                "open-by-handle-at",
                "mount",
                "dev-null",
                "dev-zero",
                "dev-kcore",
                "sys-kernel",
                "signal-host",
                "make-sym",
                "make-fifo",
                "make-sock",
                "make-char",
                "dotdot",
                "dotdot-walk",
                "refer",
                "x32-socket",
                "unknown-syscall",
                "exec-unbound",
            )
        )
        ok, holes = grade(body)
        self.assertTrue(ok, holes)
        ok, holes = grade(body.replace("op=io-uring result=refused errno=1 reason=x",
                                       "op=io-uring result=ok reason=planted"))
        self.assertFalse(ok)
        self.assertEqual(holes, ["io-uring: ok (planted)"])

    def test_parse_errno(self):
        ops = parse_ops("op=socket-inet result=refused errno=1 reason=seccomp\n")
        self.assertEqual(ops["socket-inet"].errno, 1)


class SkipTests(unittest.TestCase):
    def test_early_return_is_a_skip_pass(self):
        root = Path(tempfile.mkdtemp())
        tests = root / "lab/linux-confine/tests"
        tests.mkdir(parents=True)
        (tests / "aarch64.rs").write_text(
            'eprintln!("aarch64 cross compiler is absent. NOT RUN");\n        return;\n'
            'eprintln!("qemu-aarch64 is absent");\n        return;\n'
        )
        self.assertEqual(len(source_skip_pass(root)), 2)

    def test_honest_not_run_without_return_is_clean(self):
        root = Path(tempfile.mkdtemp())
        tests = root / "lab/linux-confine/tests"
        tests.mkdir(parents=True)
        (tests / "aarch64.rs").write_text(
            'panic!("aarch64 cross compiler is absent. NOT RUN");\n'
        )
        self.assertEqual(source_skip_pass(root), [])


if __name__ == "__main__":
    unittest.main()
