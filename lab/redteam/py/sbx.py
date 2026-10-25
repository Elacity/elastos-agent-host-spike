"""One direct seatbelt runner for the red-team lane (P10: the single copy).

``run()`` launches ``/usr/bin/sandbox-exec`` with the three canonical
parameters the Runtime substitutes for every file-profile provider --
``PROVIDER_EXECUTABLE``, ``STORAGE_ROOT``, ``STORAGE_PARENT`` -- plus a profile
file and an arbitrary program to run under it.

The *pinned* executable (what the profile's ``process-exec`` literal is bound
to) is a separate argument from the *launched* program, so a probe can try to
exec a different binary than the Runtime named. Every other probe passes the
same path for both.

This module carries no test: its name does not match ``test*.py`` and unittest
discovery skips it. The attack and control tests import it; sibling tasks
002/003 do not (one copy only -- a later provider-confine task reuses this
runner rather than growing a second one).
"""

from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SANDBOX_EXEC = "/usr/bin/sandbox-exec"

# The one launch contract (capsules/wallet-provider/tests/confine.rs,
# CANONICAL_PARAMS): the Runtime binds exactly these three ``-D`` names, no
# provider-specific fourth. A probe that bound a different name would be
# testing a profile the Runtime never launches.
CANONICAL_PARAMS = ("PROVIDER_EXECUTABLE", "STORAGE_ROOT", "STORAGE_PARENT")

# ``python3 -I`` runs the gate, so the current directory is neither importable
# nor reliable: find the repo and the profile under test from this file alone.
# lab/redteam/py/sbx.py -> parents[3] is the repo root.
REPO_ROOT = Path(__file__).resolve().parents[3]
WALLET_CONFINE_SB = REPO_ROOT / "capsules" / "wallet-provider" / "confine.sb"


def sandbox_exec_available() -> bool:
    """True when this machine can run a seatbelt profile at all (macOS only)."""
    return os.path.isfile(SANDBOX_EXEC) and os.access(SANDBOX_EXEC, os.X_OK)


@dataclass
class Result:
    """The outcome of one confined launch.

    Carries enough for a caller to tell a seatbelt *denial* from a *harness
    error* (a missing fixture, an unreadable or malformed profile, a usage
    mistake) and to record an exact repro line in a finding.
    """

    exit_code: int
    stdout: str
    stderr: str
    argv: list = field(default_factory=list)

    @property
    def command(self) -> str:
        """The exact ``sandbox-exec`` command line, for a finding's repro."""
        return " ".join(shlex.quote(str(a)) for a in self.argv)


def run(
    *,
    pinned_exe,
    launch_exe,
    args=(),
    storage_root,
    storage_parent,
    profile=WALLET_CONFINE_SB,
    stdin: str | None = None,
    timeout: float = 30.0,
) -> Result:
    """Run ``launch_exe`` + ``args`` under ``profile`` with the pinned exec set.

    All paths are passed to ``sandbox-exec`` as given; callers resolve them
    (``os.path.realpath``) so the kernel's resolved-path check matches the
    profile's literals, exactly as the Runtime's own launcher does.

    ``pinned_exe`` is bound to ``PROVIDER_EXECUTABLE`` (the profile's
    ``process-exec`` literal); ``launch_exe`` is the program actually started.
    They differ only for the foreign-exec probe.
    """
    argv = [
        SANDBOX_EXEC,
        "-D",
        f"PROVIDER_EXECUTABLE={os.fspath(pinned_exe)}",
        "-D",
        f"STORAGE_ROOT={os.fspath(storage_root)}",
        "-D",
        f"STORAGE_PARENT={os.fspath(storage_parent)}",
        "-f",
        os.fspath(profile),
        os.fspath(launch_exe),
        *[os.fspath(a) for a in args],
    ]
    completed = subprocess.run(
        argv,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return Result(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        argv=argv,
    )
