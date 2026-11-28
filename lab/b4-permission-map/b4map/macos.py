"""Parse Seatbelt oracles and the existing declared-rights files."""

from __future__ import annotations

import json
from pathlib import Path

from .catalog import (
    CONTRACT_RIGHT_IDS,
    DECLARED_RIGHTS_ROLE,
    PLATFORM_BASELINE_IDS,
    SHARED_RULES,
    STARTUP_RULES,
)


class MacosParseError(ValueError):
    """A macOS profile or declared-rights file is not the C8 template."""


def strip_comment(line: str) -> str:
    trimmed = line.lstrip()
    if trimmed.startswith(";;"):
        return ""
    cut = line.find(";;")
    if cut < 0:
        return line
    return line[:cut]


def take_form(line: str) -> str | None:
    start = line.find("(")
    if start < 0:
        return None
    depth = 0
    for offset, char in enumerate(line[start:], start=start):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return line[start : offset + 1]
    return None


def parse_profile(text: str, rel: str) -> dict:
    """Return the oracle forms with 1-based lines.

    A form that does not close on its line is refused. The three oracles in
    this repo keep one form per line, which is what the Linux parser in
    draft PR #296 also reads.
    """
    version = None
    deny_default = None
    deny_network = None
    allows: list[dict] = []
    denials: list[dict] = []
    for index, raw in enumerate(text.splitlines(), start=1):
        line = strip_comment(raw).strip()
        if not line:
            continue
        form = take_form(line)
        if form is None:
            raise MacosParseError(f"{rel}:{index}: not a profile form")
        if "(" in line[line.find(form) + len(form) :]:
            raise MacosParseError(f"{rel}:{index}: more than one form on the line")
        if form.startswith("(version "):
            version = {"form": form, "file": rel, "line": index}
        elif form == "(deny default)":
            deny_default = {"form": form, "file": rel, "line": index}
        elif form == "(deny network*)":
            deny_network = {"form": form, "file": rel, "line": index}
        elif form == "(allow default)":
            raise MacosParseError(f"{rel}:{index}: the profile grants allow default")
        elif form.startswith("(allow "):
            allows.append({"form": form, "file": rel, "line": index})
        elif form.startswith("(deny "):
            denials.append({"form": form, "file": rel, "line": index})
        else:
            raise MacosParseError(f"{rel}:{index}: unknown profile form: {form}")
    if version is None:
        raise MacosParseError(f"{rel}: the profile has no version")
    if deny_default is None:
        raise MacosParseError(f"{rel}: the profile has no deny default")
    if deny_network is None:
        raise MacosParseError(f"{rel}: the profile has no network denial")
    return {
        "file": rel,
        "version": version,
        "deny_default": deny_default,
        "deny_network": deny_network,
        "allows": allows,
        "denials": denials,
    }


def _find_allow(profile: dict, form: str) -> dict | None:
    for allow in profile["allows"]:
        if allow["form"] == form:
            return allow
    return None


def parse_declared_rights(text: str, rel: str, provider: str) -> dict:
    """Read one C8 declared-rights file. Refuse a second template."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as err:
        raise MacosParseError(f"{rel}: invalid JSON: {err}") from err
    if data.get("role") != DECLARED_RIGHTS_ROLE:
        raise MacosParseError(f"{rel}: role is not the C8 lab stand-in sentence")
    if data.get("provider") != provider:
        raise MacosParseError(f"{rel}: provider {data.get('provider')!r} is not {provider}")
    rights = data.get("rights")
    if not isinstance(rights, list):
        raise MacosParseError(f"{rel}: rights must be a list")
    claimed = {}
    for entry in rights:
        ident = entry.get("id")
        if ident not in CONTRACT_RIGHT_IDS:
            raise MacosParseError(
                f"{rel}: {ident!r} is not a C8 contract right "
                f"{list(CONTRACT_RIGHT_IDS)}"
            )
        if ident in claimed:
            raise MacosParseError(f"{rel}: right {ident} is declared twice")
        claimed[ident] = list(entry.get("rules") or [])
    for ident in CONTRACT_RIGHT_IDS:
        if ident not in claimed:
            raise MacosParseError(f"{rel}: missing C8 contract right {ident}")
    baseline = data.get("platform_baseline") or {}
    base_rules = {}
    for entry in baseline.get("rules") or []:
        ident = entry.get("id")
        if ident not in PLATFORM_BASELINE_IDS:
            raise MacosParseError(
                f"{rel}: {ident!r} is not a C8 platform-baseline id "
                f"{list(PLATFORM_BASELINE_IDS)}"
            )
        base_rules[ident] = list(entry.get("rules") or [])
    for ident in PLATFORM_BASELINE_IDS:
        if ident not in base_rules:
            raise MacosParseError(f"{rel}: missing C8 platform-baseline id {ident}")
    return {
        "file": rel,
        "provider": provider,
        "rights": claimed,
        "platform_baseline": base_rules,
        "status": baseline.get("status"),
    }


def macos_sides(profile: dict, declared: dict, provider: str) -> dict:
    """Map each comparison right to the macOS rule that holds it."""
    deny = profile["deny_default"]
    net = profile["deny_network"]
    root_form = (
        STARTUP_RULES["startup-root-directory-model"]
        if provider == "model-provider"
        else STARTUP_RULES["startup-root-directory"]
    )
    exec_allow = _find_allow(profile, SHARED_RULES["bound-executable"])
    storage_root = _find_allow(profile, SHARED_RULES["storage.root"])
    storage_parent = _find_allow(profile, SHARED_RULES["storage.parent"])
    root_read = _find_allow(profile, root_form)
    sysctl = _find_allow(profile, STARTUP_RULES["startup-sysctl"])
    extra_allows = [
        allow
        for allow in profile["allows"]
        if allow["form"]
        not in {
            SHARED_RULES["bound-executable"],
            SHARED_RULES["storage.root"],
            SHARED_RULES["storage.parent"],
            STARTUP_RULES["startup-root-directory"],
            STARTUP_RULES["startup-root-directory-model"],
            STARTUP_RULES["startup-sysctl"],
        }
    ]
    network_allow = next(
        (allow for allow in profile["allows"] if "network" in allow["form"]),
        None,
    )

    def allow_side(found: dict | None, expected: str) -> dict:
        if found is None:
            return {
                "verdict": "missing",
                "rule": expected,
                "file": profile["file"],
                "line": None,
                "note": "the oracle does not hold this allow",
            }
        return {
            "verdict": "allow",
            "rule": found["form"],
            "file": found["file"],
            "line": found["line"],
        }

    def deny_side(cell: dict, note: str) -> dict:
        return {
            "verdict": "deny",
            "rule": cell["form"],
            "file": cell["file"],
            "line": cell["line"],
            "note": note,
        }

    sides = {
        "bound-executable": allow_side(exec_allow, SHARED_RULES["bound-executable"]),
        "storage.root": allow_side(storage_root, SHARED_RULES["storage.root"]),
        "storage.parent": allow_side(storage_parent, SHARED_RULES["storage.parent"]),
        "startup-root-directory": allow_side(root_read, root_form),
        "startup-sysctl": allow_side(sysctl, STARTUP_RULES["startup-sysctl"]),
        "outside.read": deny_side(
            deny, "no allow names a path outside STORAGE_ROOT"
        ),
        "outside.write": deny_side(
            deny, "no allow writes outside STORAGE_ROOT"
        ),
        "network": deny_side(net, "explicit network denial"),
        "unix-socketpair": deny_side(
            net, "macOS counts a Unix-domain pair under network*"
        ),
        "exec.other": deny_side(
            deny, "only PROVIDER_EXECUTABLE has process-exec"
        ),
        "signal.host": deny_side(deny, "no signal-outbound grant"),
        "device.ioctl": deny_side(deny, "no file-ioctl grant"),
    }
    if network_allow is not None:
        sides["network"] = {
            "verdict": "allow",
            "rule": network_allow["form"],
            "file": network_allow["file"],
            "line": network_allow["line"],
            "note": "the profile grants a network allow",
        }
        sides["unix-socketpair"] = {
            "verdict": "allow",
            "rule": network_allow["form"],
            "file": network_allow["file"],
            "line": network_allow["line"],
            "note": "a network allow also covers a Unix-domain pair",
        }
    sides["_extra_allows"] = extra_allows
    sides["_declared"] = declared
    return sides


def parse_operations_table(text: str, rel: str) -> list[dict]:
    """Read the CONFINEMENT.md operations table. It is evidence, not a grant."""
    heading = "## Operations and the rights they need"
    start = text.find(heading)
    if start < 0:
        return []
    rows = []
    for raw in text[start:].splitlines():
        if not raw.startswith("| ") or raw.startswith("| ---") or raw.startswith("| Operation"):
            if rows and raw.startswith("## "):
                break
            continue
        cells = [cell.strip() for cell in raw.strip("|").split("|")]
        if len(cells) < 7:
            continue
        rows.append(
            {
                "operation": cells[0],
                "right": cells[3],
                "macos": cells[5],
                "linux": cells[6],
                "file": rel,
            }
        )
    return rows


def load_provider_macos(root: Path, provider: str, profile_override: Path | None = None) -> tuple[dict, dict, dict, list[dict]]:
    profile_rel = f"capsules/{provider}/confine.sb"
    declared_rel = f"capsules/{provider}/tests/fixtures/confine/declared-rights.json"
    if profile_override is not None:
        profile_text = profile_override.read_text()
        profile_rel = str(profile_override)
    else:
        profile_text = (root / profile_rel).read_text()
    declared_text = (root / declared_rel).read_text()
    profile = parse_profile(profile_text, profile_rel)
    declared = parse_declared_rights(declared_text, declared_rel, provider)
    ops_rel = f"capsules/{provider}/CONFINEMENT.md"
    ops_path = root / ops_rel
    operations = parse_operations_table(ops_path.read_text(), ops_rel) if ops_path.is_file() else []
    return profile, declared, macos_sides(profile, declared, provider), operations
