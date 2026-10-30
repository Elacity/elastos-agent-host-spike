"""Grade one probe report. A success on a must-deny row is an escape."""

from __future__ import annotations

from dataclasses import dataclass

# Rows the C9 Linux map must refuse. A result=ok is a hole the probe can see.
MUST_DENY = (
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

# The short probe filter refuses these. The provider filter may allow them.
FILTER_SPLIT = ("socketpair", "clone-process")


@dataclass
class Op:
    name: str
    result: str
    errno: int | None
    reason: str
    raw: str


def parse_ops(text: str) -> dict[str, Op]:
    ops: dict[str, Op] = {}
    for raw in text.splitlines():
        if not raw.startswith("op="):
            continue
        rest = raw[3:]
        if " result=" not in rest:
            continue
        name, rest = rest.split(" result=", 1)
        errno = None
        if " errno=" in rest:
            result, rest = rest.split(" errno=", 1)
            errno_text, reason = rest.split(" reason=", 1)
            try:
                errno = int(errno_text)
            except ValueError:
                errno = None
        else:
            result, reason = rest.split(" reason=", 1)
        ops[name] = Op(name, result, errno, reason, raw)
    return ops


def escapes(ops: dict[str, Op], extra_deny: tuple[str, ...] = ()) -> list[str]:
    names = MUST_DENY + extra_deny
    found = []
    for name in names:
        op = ops.get(name)
        if op is None:
            found.append(f"{name}: missing")
            continue
        if op.result == "ok":
            found.append(f"{name}: ok ({op.reason})")
    return found


def grade(text: str, extra_deny: tuple[str, ...] = ()) -> tuple[bool, list[str]]:
    """True when every must-deny row is present and not ok."""
    holes = escapes(parse_ops(text), extra_deny)
    return (not holes, holes)
