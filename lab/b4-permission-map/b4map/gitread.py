"""Read pinned Linux lab files with git show. Fail closed if a pin is missing."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


class RepoReadError(RuntimeError):
    """A pinned Linux source cannot be read."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[1]


def repo_root() -> Path:
    return lab_root().parents[1]


def load_pins(path: Path | None = None) -> dict:
    pin_path = path or lab_root() / "pins.json"
    return json.loads(pin_path.read_text())


def read_pinned(sha: str, rel: str, root: Path | None = None) -> str:
    """Return the file at ``sha:rel``. Raise RepoReadError if git cannot."""
    cwd = root or repo_root()
    result = subprocess.run(
        ["git", "show", f"{sha}:{rel}"],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "git show failed").strip()
        raise RepoReadError(f"cannot read {rel} at {sha}: {err}")
    return result.stdout


def locate_line(text: str, needle: str) -> int | None:
    """1-based line of the first line that contains ``needle``."""
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    return None
