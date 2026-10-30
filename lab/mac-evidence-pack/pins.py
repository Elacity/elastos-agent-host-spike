"""Load the labelled row -> branch + SHA pin file."""

from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_PINS = HERE / "pins.ini"

MARKER_NAME = ".mac-evidence-pack-owned"
MARKER_TEXT = "mac-evidence-pack-owned-clone\n"

REMOTE = "https://github.com/Elacity/elastos-agent-host-spike.git"
PACK_BRANCH = "cursor/mac-evidence-pack-be32"
PACK_CLONE_NAME = "pack-clone"


@dataclass(frozen=True)
class Pin:
    id: str
    branch: str
    sha: str
    pr: int
    status: str
    reason: str = ""


@dataclass(frozen=True)
class PackPin:
    branch: str
    remote: str


def _norm_status(raw: str) -> str:
    return raw.strip().upper().replace(" ", "_").replace("-", "_")


def load_pin_file(path: Path | None = None) -> tuple[PackPin, dict[str, Pin]]:
    source = path or DEFAULT_PINS
    parser = configparser.ConfigParser(interpolation=None)
    read = parser.read(source, encoding="utf-8")
    if not read:
        raise FileNotFoundError(f"pin file missing: {source}")
    pack = PackPin(
        branch=parser.get("pack", "branch", fallback=PACK_BRANCH),
        remote=parser.get("pack", "remote", fallback=REMOTE),
    )
    rows: dict[str, Pin] = {}
    for name in parser.sections():
        if name == "pack":
            continue
        rows[name] = Pin(
            id=name,
            branch=parser.get(name, "branch"),
            sha=parser.get(name, "sha", fallback="").strip(),
            pr=parser.getint(name, "pr"),
            status=_norm_status(parser.get(name, "status", fallback="ok")),
            reason=parser.get(name, "reason", fallback="").strip(),
        )
    return pack, rows


def pin_block_reason(pin: Pin) -> str | None:
    """Named FAIL reason when this pin must not run. None means the SHA may be used."""
    status = _norm_status(pin.status)
    if status == "MISSING" or not pin.sha:
        return f"PIN_MISSING: row {pin.id} has no usable SHA"
    if len(pin.sha) != 40 or any(ch not in "0123456789abcdef" for ch in pin.sha.lower()):
        return f"PIN_MISSING: row {pin.id} SHA is not a full commit"
    if status == "NEEDS_REPIN":
        detail = pin.reason or "pin is marked NEEDS_REPIN"
        return f"PIN_NEEDS_REPIN: {detail}"
    if status == "SUPERSEDED":
        detail = pin.reason or "pin is marked superseded"
        return f"PIN_SUPERSEDED: {detail}"
    if status != "OK":
        return f"PIN_UNKNOWN_STATUS: row {pin.id} status {pin.status!r}"
    return None


def default_pack_clone(home: Path) -> Path:
    return home / "mac-evidence-pack" / PACK_CLONE_NAME


def marker_path(repo: Path) -> Path:
    return repo / MARKER_NAME


def is_pack_owned(repo: Path) -> bool:
    path = marker_path(repo)
    try:
        return path.is_file() and path.read_text(encoding="utf-8") == MARKER_TEXT
    except OSError:
        return False


def write_marker(repo: Path) -> None:
    marker_path(repo).write_text(MARKER_TEXT, encoding="utf-8")
