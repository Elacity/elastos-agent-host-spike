"""Parse launcher and extra-probe lines. A result=ok on a must-deny row is a hole."""

from __future__ import annotations

from dataclasses import dataclass


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


def parse_enforced(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("enforced "):
            return line
    return None
