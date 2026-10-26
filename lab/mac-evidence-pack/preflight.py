"""Host checks that run before any row. Logic is fixture-testable."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from paths import has_space

# 14 GiB in 1 KiB blocks: 12 GiB for Runtime builds plus 2 GiB free.
MIN_FREE_KIB = 14 * 1024 * 1024


@dataclass(frozen=True)
class Facts:
    os_name: str
    machine: str
    translated: str
    uid: int
    sudo_present: bool
    macos_version: str
    home: str
    work: str
    cargo_home: str
    rustc_path: str
    cargo_path: str
    xcode_path: str
    sandbox_exec: bool
    free_kib: int | None
    python3: str
    git: str


def facts_from_dict(data: dict) -> Facts:
    return Facts(
        os_name=str(data["os_name"]),
        machine=str(data["machine"]),
        translated=str(data.get("translated", "0")),
        uid=int(data["uid"]),
        sudo_present=bool(data["sudo_present"]),
        macos_version=str(data.get("macos_version", "")),
        home=str(data["home"]),
        work=str(data["work"]),
        cargo_home=str(data["cargo_home"]),
        rustc_path=str(data.get("rustc_path", "")),
        cargo_path=str(data.get("cargo_path", "")),
        xcode_path=str(data.get("xcode_path", "")),
        sandbox_exec=bool(data.get("sandbox_exec", False)),
        free_kib=None if data.get("free_kib") is None else int(data["free_kib"]),
        python3=str(data.get("python3", "")),
        git=str(data.get("git", "")),
    )


def load_facts(path: Path) -> Facts:
    return facts_from_dict(json.loads(path.read_text(encoding="utf-8")))


def dump_facts(facts: Facts) -> str:
    return json.dumps(asdict(facts), indent=2) + "\n"


def _cmd_text(argv: list[str]) -> str:
    try:
        return subprocess.check_output(argv, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def _free_kib(path: Path) -> int | None:
    try:
        usage = os.statvfs(path)
    except OSError:
        return None
    return (usage.f_bavail * usage.f_frsize) // 1024


def _sudo_present() -> bool:
    return any(
        os.environ.get(name)
        for name in ("SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND")
    )


def collect_facts(*, home: Path, work: Path) -> Facts:
    os_name = platform.system()
    machine = os.uname().machine
    translated = "0"
    macos_version = ""
    xcode_path = ""
    if os_name == "Darwin":
        translated = _cmd_text(["sysctl", "-n", "sysctl.proc_translated"]) or "0"
        macos_version = _cmd_text(["sw_vers", "-productVersion"])
        xcode_path = _cmd_text(["xcode-select", "-p"])
    cargo_home = os.environ.get("CARGO_HOME") or str(home / ".cargo")
    space_path = work if work.exists() else home
    sandbox = Path("/usr/bin/sandbox-exec")
    return Facts(
        os_name=os_name,
        machine=machine,
        translated=translated,
        uid=os.getuid(),
        sudo_present=_sudo_present(),
        macos_version=macos_version,
        home=str(home),
        work=str(work),
        cargo_home=cargo_home,
        rustc_path=shutil.which("rustc") or "",
        cargo_path=shutil.which("cargo") or "",
        xcode_path=xcode_path,
        sandbox_exec=sandbox.is_file() and os.access(sandbox, os.X_OK),
        free_kib=_free_kib(space_path),
        python3=shutil.which("python3") or "",
        git=shutil.which("git") or "",
    )


def problems(facts: Facts) -> list[str]:
    """Return one reason per gap. Empty means the live rows may start."""
    out: list[str] = []
    if facts.uid == 0:
        out.append("refuses to run as uid 0")
    if facts.sudo_present:
        out.append("refuses to run when a SUDO_* variable is set")
    if facts.os_name != "Darwin":
        out.append(
            f"operating system is {facts.os_name}; live rows need macOS"
        )
    if facts.translated == "1":
        out.append(
            "this shell is Rosetta (sysctl.proc_translated=1); open a native arm64 Terminal"
        )
    if facts.machine != "arm64":
        out.append(
            f"architecture is {facts.machine}; native Apple Silicon (arm64) is required"
        )
    if facts.os_name == "Darwin" and not facts.macos_version:
        out.append("macOS version could not be read (sw_vers -productVersion)")
    if facts.os_name == "Darwin" and not facts.xcode_path:
        out.append("Xcode command line tools are missing; run xcode-select --install")
    if not facts.cargo_path:
        out.append("cargo is not on PATH")
    if not facts.rustc_path:
        out.append("rustc is not on PATH")
    if not facts.git:
        out.append("git is not on PATH")
    if not facts.python3:
        out.append("python3 is not on PATH")
    if facts.os_name == "Darwin" and not facts.sandbox_exec:
        out.append("/usr/bin/sandbox-exec is missing; C3, C4, C6 and C7 need it")
    for label, path in (
        ("HOME", facts.home),
        ("the work dir", facts.work),
        ("CARGO_HOME", facts.cargo_home),
        ("the rustc path", facts.rustc_path),
    ):
        if path:
            hit = has_space(label, path)
            if hit:
                out.append(hit)
    if facts.free_kib is None:
        out.append("free disk could not be read")
    elif facts.free_kib < MIN_FREE_KIB:
        gib = facts.free_kib / (1024 * 1024)
        out.append(
            f"free disk is {gib:.1f} GiB; the pack asks for 14 GiB (12 GiB builds plus 2 GiB free)"
        )
    return out


def format_report(facts: Facts, gaps: list[str]) -> str:
    lines = [
        f"os: {facts.os_name}",
        f"macOS: {facts.macos_version or 'n/a'}",
        f"machine: {facts.machine}",
        f"translated: {facts.translated}",
        f"uid: {facts.uid}",
        f"home: {facts.home}",
        f"work: {facts.work}",
        f"cargo: {facts.cargo_path or 'missing'}",
        f"rustc: {facts.rustc_path or 'missing'}",
        f"xcode: {facts.xcode_path or 'missing'}",
        f"sandbox-exec: {facts.sandbox_exec}",
        f"free_kib: {facts.free_kib}",
    ]
    if gaps:
        for gap in gaps:
            lines.append(f"missing: {gap}")
        lines.append("preflight: FAIL")
    else:
        lines.append("preflight: OK")
    return "\n".join(lines) + "\n"
