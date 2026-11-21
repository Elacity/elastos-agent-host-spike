"""Accepted named rights: owner-approved allows on the live model profile only.

A probe that sees an allow on a real profile records a CRITICAL finding
(README guard c). Four model-provider allows are not escapes: the owner
approved them as named rights for the model helper only, pinned to the M1a
lab measurements. Each entry below names its finding id, its decision line
and its measurement, the exact profile lines it accepts, and the exact probe
line those lines may produce.

``accepted`` returns the right only for a launch of the live
``capsules/model-provider/confine.sb`` (never a temp copy, never the wallet
or did profile) and only when ``require`` passes. ``require`` refuses a
profile that carries a named line other than exactly once, any further allow
of the same operation, and any probe line other than the measured one. A
refused right falls back to the ordinary CRITICAL path, and the probe's
``test_model_allows_only_named_rights`` fails the gate.

This module carries no test: its name does not match ``test*.py``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

import sbx

# lab/redteam/py/named_rights.py -> parents[3] is the repo root. Same rule as sbx.
LIVE_MODEL_SB = Path(__file__).resolve().parents[3] / "capsules/model-provider/confine.sb"

DECISIONS = "~/Sparks/office/DECISIONS.md"
EVIDENCE = "~/Sparks/office/evidence/b3-m1a-rights/probe"

URANDOM_READ = '(allow file-read* (literal "/dev/urandom"))'
NULL_READ_WRITE_DATA = '(allow file-read* file-write-data (literal "/dev/null"))'
GPU_CLIENTS = (
    '(allow iokit-open-user-client (iokit-user-client-class "AGXDeviceUserClient")'
    ' (iokit-user-client-class "IOSurfaceRootUserClient"))'
)


@dataclass(frozen=True)
class NamedRight:
    finding: str
    name: str
    forms: tuple
    family: re.Pattern
    observed: re.Pattern
    decision: str
    measurement: str

    def label(self) -> str:
        return (
            f"accepted named right {self.name} ({self.finding}); "
            f"decision: {self.decision}; measurement: {self.measurement}"
        )


class NamedRightExceeded(AssertionError):
    """The model profile or the probe line goes beyond the named right."""


RIGHTS = {
    "CRITICAL-cc-model-confine-051": NamedRight(
        finding="CRITICAL-cc-model-confine-051",
        name="model-engine-process",
        forms=("(allow process-fork)",),
        family=re.compile(r"^\(allow\b.*\bprocess(?:-fork\b|\*)"),
        observed=re.compile(r"fork=[1-9][0-9]* errno=0\n"),
        decision=(
            f"{DECISIONS}:4497, 20 Nov 2026 about 21:20, Sash: the model helper's "
            "launch inputs, 'start its own engine process' "
            "(evidence/b3-m1a/DECISION-launch-inputs.md)"
        ),
        measurement=(
            f"{EVIDENCE}/macos-report.md:58 row X2 and PROOFS.txt:14-18 "
            "(without process-fork the engine never starts)"
        ),
    ),
    "CRITICAL-cc-model-confine-064": NamedRight(
        finding="CRITICAL-cc-model-confine-064",
        name="model-gpu",
        forms=(GPU_CLIENTS,),
        family=re.compile(r"^\(allow\b.*\biokit-open"),
        observed=re.compile(
            r"smc match=1 kr=-536870174 surface match=1 kr=0 "
            r"display match=1 kr=-536870174 report match=1 kr=-536870174\n"
        ),
        decision=(
            f"{DECISIONS}:4468, 20 Nov 2026 about 01:45, Sash: the GPU right for the "
            "model helper, 'a narrow, named right that covers only that GPU access, "
            "measured in the lab test and nothing wider'"
        ),
        measurement=(
            f"{EVIDENCE}/macos-report.md:61 row X5 and PROOFS.txt:38-41 "
            "(control-no-iokit.log: 'failed to create command queue')"
        ),
    ),
    # Device reads: /dev/urandom and the read half of the /dev/null line.
    "CRITICAL-cc-model-confine-059": NamedRight(
        finding="CRITICAL-cc-model-confine-059",
        name="model-device-reads",
        forms=(URANDOM_READ, NULL_READ_WRITE_DATA),
        family=re.compile(r"^\(allow\b(?=.*\bfile-read)(?:.*/dev\b|[^()]*\)$)"),
        observed=re.compile(r"urandom fd=3 n=16 errno=0 null fd=3 errno=0\n"),
        decision=(
            f"{DECISIONS}:4525-4526, 21 Nov 2026 about 13:55, Sash: 'yes approve the "
            "device permissions', model helper only: read /dev/urandom, read /dev/null"
        ),
        measurement=(
            f"{EVIDENCE}/PROOFS.txt:68-72 (row 2 device reads; "
            "minus-engine-alias-seed failed; proofs/dev-null-read.txt)"
        ),
    ),
    # Device write: /dev/null only. Any other /dev write is beyond it.
    "CRITICAL-cc-model-confine-069": NamedRight(
        finding="CRITICAL-cc-model-confine-069",
        name="model-null-write",
        forms=(NULL_READ_WRITE_DATA,),
        family=re.compile(r"^\(allow\b(?=.*\bfile-write)(?:.*/dev\b|[^()]*\)$)"),
        observed=re.compile(
            r"nullw fd=3 n=1 errno=0 zerow fd=-1 n=-1 errno=1 "
            r"randw fd=-1 n=-1 errno=1 nullrw fd=3 n=1 errno=0 "
            r"zerorw fd=-1 n=-1 errno=1\n"
        ),
        decision=(
            f"{DECISIONS}:4525-4526, 21 Nov 2026 about 13:55, Sash: 'yes approve the "
            "device permissions', model helper only: write /dev/null, no other /dev node"
        ),
        measurement=(
            f"{EVIDENCE}/PROOFS.txt:70-71 (row 2; minus-guard-stdio-sinks failed)"
        ),
    ),
}


def allow_lines(text):
    """Each non-comment line of a profile, stripped."""
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith(";"):
            lines.append(line)
    return lines


def require(right, text, stdout):
    """Raise ``NamedRightExceeded`` unless ``text`` and ``stdout`` stay inside ``right``.

    Each named line occurs exactly once as a whole line, no other line allows
    the same operation, and the probe printed exactly the measured line.
    """
    lines = allow_lines(text)
    for form in right.forms:
        count = lines.count(form)
        if count != 1:
            raise NamedRightExceeded(
                f"{right.name}: the named form occurs {count} times, not once: {form}"
            )
    wider = [
        line for line in lines if line not in right.forms and right.family.search(line)
    ]
    if wider:
        raise NamedRightExceeded(
            f"{right.name}: allow beyond the named right: " + "; ".join(wider)
        )
    if right.observed.fullmatch(stdout or "") is None:
        raise NamedRightExceeded(
            f"{right.name}: probe line {stdout!r} is not the measured line"
        )
    return right


def accepted(finding, profile_path, result):
    """The named right for this allow on the live model profile, else None.

    ``result`` must be a launch of that live file: its argv names the
    resolved ``capsules/model-provider/confine.sb``.
    """
    right = RIGHTS.get(finding)
    if right is None:
        return None
    path = Path(profile_path)
    if not path.is_file() or path.resolve() != LIVE_MODEL_SB:
        return None
    argv = [str(arg) for arg in (result.argv or [])]
    if not any(Path(arg).is_absolute() and Path(arg).resolve() == LIVE_MODEL_SB for arg in argv):
        return None
    try:
        return require(right, path.read_text(encoding="utf-8"), result.stdout)
    except NamedRightExceeded:
        return None


def mark_named(case_cls, method_name, right, profile_path, probe, classify, allow="allow"):
    """Replace one model deny test with the named-right check for this run.

    The replacement launches the probe again through ``sandbox-exec`` on the
    live profile, requires an allow, and requires that allow to stay inside
    ``right``. Its docstring names the finding id, the decision line and the
    measurement. A class cleanup restores the deny test, the same way
    ``mark_expected`` restores a recorded escape. ``allow`` is the outcome the
    probe's classifier gives the measured line.
    """
    original = getattr(case_cls, method_name)

    def named(self):
        result = probe(profile_path)
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(os.fspath(profile_path), result.argv)
        self.assertEqual(classify(result), allow)
        require(right, Path(profile_path).read_text(encoding="utf-8"), result.stdout)

    named.__name__ = method_name
    named.__qualname__ = f"{case_cls.__name__}.{method_name}"
    named.__doc__ = f"The live model profile allows this as an {right.label()}."
    setattr(case_cls, method_name, named)
    case_cls.addClassCleanup(setattr, case_cls, method_name, original)


def strip_named_forms(right, text):
    """``text`` with each named line removed once, for a temp plant baseline."""
    lines = text.splitlines(keepends=True)
    kept = [line for line in lines if line.strip() not in right.forms]
    if len(lines) - len(kept) != len(right.forms):
        raise NamedRightExceeded(f"{right.name}: the named forms are not one line each")
    return "".join(kept)
