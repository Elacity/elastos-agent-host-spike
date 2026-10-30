"""Keep #343's runner off the shared /tmp/elastos/storage tree."""

from __future__ import annotations

import re
from pathlib import Path

from catalog import Row

SHARED_STORAGE = "/tmp/elastos/storage"
REDIRECT_ENVS = ("ELASTOS_TMP_ROOT", "ELASTOS_STORAGE_ROOT", "A12_TEMP_ROOT")
_REDIRECT_RE = re.compile(
    r'env::var\(\s*"(?:' + "|".join(REDIRECT_ENVS) + r')"\s*\)'
)

UNREDIRECTABLE = (
    "A12_SHARED_TMP_UNREDIRECTABLE: runner hardcodes /tmp/elastos/storage "
    "and has no env redirect"
)


def row_needs_isolation(row: Row) -> bool:
    if row.pr == 343:
        return True
    for cmd in row.commands:
        if any("a6-a12-evidence-fix" in part for part in cmd):
            return True
    return False


def redirect_reason_from_text(text: str) -> str | None:
    """None when the runner will not touch shared storage, or can be redirected."""
    if SHARED_STORAGE not in text and "/tmp/elastos" not in text:
        return None
    if _REDIRECT_RE.search(text):
        return None
    return UNREDIRECTABLE


def isolation_env(work: Path) -> dict[str, str]:
    root = work / "isolated-tmp"
    storage = root / "elastos" / "storage"
    return {
        "ELASTOS_TMP_ROOT": str(root),
        "ELASTOS_STORAGE_ROOT": str(storage),
        "ELASTOS_DATA_DIR": str(root / "elastos"),
        "A12_TEMP_ROOT": str(root),
    }


def inspect_runner(checkout: Path) -> str | None:
    folder = checkout / "lab" / "a6-a12-evidence-fix"
    if not folder.is_dir():
        return (
            "A12_SHARED_TMP_UNREDIRECTABLE: lab/a6-a12-evidence-fix runner is missing"
        )
    chunks: list[str] = []
    for path in sorted(folder.rglob("*")):
        if path.suffix in {".rs", ".sh", ".toml"} and path.is_file():
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return redirect_reason_from_text("\n".join(chunks))
