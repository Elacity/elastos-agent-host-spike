"""Work-dir ownership. The pack writes and deletes only inside one home folder."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


class PathRefusal(Exception):
    """A path is outside the allowed work dir or home."""


def env_home() -> Path:
    raw = os.environ.get("HOME")
    if not raw:
        raise PathRefusal("HOME is unset")
    return Path(raw)


def resolve(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def has_space(label: str, path: str) -> str | None:
    if " " in path:
        return f"{label} contains a space ({path})"
    return None


def is_inside(path: Path, root: Path) -> bool:
    try:
        inner = resolve(path)
        outer = resolve(root)
    except OSError:
        return False
    return inner == outer or outer in inner.parents


def require_inside(path: Path, root: Path, what: str) -> Path:
    inner = resolve(path)
    if not is_inside(inner, root):
        raise PathRefusal(f"{what} is outside the work dir ({inner})")
    return inner


def require_under_home(path: Path, home: Path, what: str) -> Path:
    inner = resolve(path)
    if not is_inside(inner, home):
        raise PathRefusal(f"{what} is outside HOME ({inner})")
    return inner


def remove_inside(path: Path, work: Path) -> None:
    """Delete only a path that resolves inside the work dir."""
    inner = require_inside(path, work, "delete")
    if inner == resolve(work):
        raise PathRefusal("refuses to delete the work dir itself")
    if inner.is_dir() and not inner.is_symlink():
        shutil.rmtree(inner)
    elif inner.exists() or inner.is_symlink():
        inner.unlink()
