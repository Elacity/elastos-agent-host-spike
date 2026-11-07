"""Load the proposed unified baseline and score each platform against it."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from .catalog import COMPARISON_RIGHTS, NOT_RUN
from .gitread import lab_root

PLATFORMS = ("macos", "linux-confine", "fail-closed-linux")
SIDE_KEYS = {
    "macos": "macos",
    "linux-confine": "linux_confine",
    "fail-closed-linux": "fail_closed_linux",
}
STATUSES = ("CONFORMS", "MUST CHANGE", "OPEN DECISION")
PROPOSED = ("allow", "deny")
REQUIRED_RIGHT_IDS = tuple(spec["id"] for spec in COMPARISON_RIGHTS)


class BaselineError(ValueError):
    """The proposed baseline is not a valid unified model."""


def baseline_path(path: Path | None = None) -> Path:
    return path or (lab_root() / "baseline.json")


def load_baseline(path: Path | None = None) -> dict:
    pin = baseline_path(path)
    try:
        data = json.loads(pin.read_text())
    except json.JSONDecodeError as err:
        raise BaselineError(f"{pin}: invalid JSON: {err}") from err
    return validate_baseline(data, rel=str(pin))


def validate_baseline(data: dict, rel: str = "baseline.json") -> dict:
    if data.get("role") != "proposed unified baseline, not a grant and not applied":
        raise BaselineError(f"{rel}: role is not the proposed-baseline sentence")
    execution = data.get("execution") or {}
    for key, expected in (
        ("linux_x86_64", NOT_RUN["linux_x86_64_execution"]),
        ("jetson_aarch64", NOT_RUN["jetson_aarch64_execution"]),
        ("macos", NOT_RUN["macos_execution"]),
    ):
        if execution.get(key) != expected:
            raise BaselineError(f"{rel}: execution.{key} must stay {expected}")
    rights = data.get("rights")
    if not isinstance(rights, list):
        raise BaselineError(f"{rel}: rights must be a list")
    seen: dict[str, dict] = {}
    for entry in rights:
        ident = entry.get("id")
        if ident not in REQUIRED_RIGHT_IDS:
            raise BaselineError(f"{rel}: {ident!r} is not a comparison right")
        if ident in seen:
            raise BaselineError(f"{rel}: right {ident} is declared twice")
        if entry.get("proposed") not in PROPOSED:
            raise BaselineError(f"{rel}: {ident} proposed must be allow or deny")
        if not isinstance(entry.get("open_decision"), bool):
            raise BaselineError(f"{rel}: {ident} open_decision must be a bool")
        if not isinstance(entry.get("rationale"), str) or not entry["rationale"].strip():
            raise BaselineError(f"{rel}: {ident} needs a security rationale")
        change = entry.get("change")
        if not isinstance(change, dict) or any(name not in change for name in PLATFORMS):
            raise BaselineError(
                f"{rel}: {ident} change must name macos, linux-confine, and fail-closed-linux"
            )
        if ident == "storage.parent" and entry.get("declared_as") != "STORAGE_PARENT":
            raise BaselineError(f"{rel}: storage.parent must declare STORAGE_PARENT")
        seen[ident] = entry
    missing = [ident for ident in REQUIRED_RIGHT_IDS if ident not in seen]
    if missing:
        raise BaselineError(f"{rel}: missing rights {missing}")
    return data


def apply_overlay(baseline: dict, overlay: dict) -> dict:
    """Return a copy with one right's proposed polarity replaced."""
    planted = copy.deepcopy(baseline)
    ident = overlay.get("right")
    if ident not in REQUIRED_RIGHT_IDS:
        raise BaselineError(f"overlay right {ident!r} is not a comparison right")
    if overlay.get("proposed") not in PROPOSED:
        raise BaselineError("overlay proposed must be allow or deny")
    for entry in planted["rights"]:
        if entry["id"] == ident:
            entry["proposed"] = overlay["proposed"]
            if "open_decision" in overlay:
                entry["open_decision"] = bool(overlay["open_decision"])
            return planted
    raise BaselineError(f"overlay right {ident} is missing from the baseline")


def load_planted_baseline(plant_dir: Path, committed: dict | None = None) -> dict:
    """Load a planted baseline from overlay.json or a full baseline.json."""
    committed = committed if committed is not None else load_baseline()
    overlay = plant_dir / "overlay.json"
    full = plant_dir / "baseline.json"
    if overlay.is_file():
        data = json.loads(overlay.read_text())
        return apply_overlay(committed, data)
    if full.is_file():
        return load_baseline(full)
    raise BaselineError(f"{plant_dir} holds neither overlay.json nor baseline.json")


def matches_proposal(verdict: str, proposed: str) -> bool:
    """A missing grant matches deny. partial does not."""
    if proposed == "allow":
        return verdict == "allow"
    if proposed == "deny":
        return verdict in {"deny", "missing"}
    raise BaselineError(f"unknown proposed polarity {proposed!r}")


def score_platform(open_decision: bool, verdict: str, proposed: str) -> str:
    if open_decision:
        return "OPEN DECISION"
    if matches_proposal(verdict, proposed):
        return "CONFORMS"
    return "MUST CHANGE"


def baseline_index(baseline: dict) -> dict[str, dict]:
    return {entry["id"]: entry for entry in baseline["rights"]}


def score_sides(spec: dict, macos: dict, linux_c9: dict, linux_c0: dict) -> dict:
    sides = {
        "macos": macos,
        "linux-confine": linux_c9,
        "fail-closed-linux": linux_c0,
    }
    scores = {}
    matches = {}
    for name, side in sides.items():
        verdict = side["verdict"]
        matches[name] = matches_proposal(verdict, spec["proposed"])
        scores[name] = score_platform(spec["open_decision"], verdict, spec["proposed"])
    return {
        "proposed": spec["proposed"],
        "open_decision": spec["open_decision"],
        "rationale": spec["rationale"],
        "change": spec["change"],
        "declared_as": spec.get("declared_as"),
        "macos": scores["macos"],
        "linux_confine": scores["linux-confine"],
        "fail_closed_linux": scores["fail-closed-linux"],
        "matches_proposal": matches,
    }


def score_report(report: dict, baseline: dict) -> dict:
    """Attach per-right baseline scores and a flat score list."""
    index = baseline_index(baseline)
    rows = []
    for provider, table in report["providers"].items():
        for entry in table["rights"]:
            spec = index[entry["id"]]
            scored = score_sides(
                spec, entry["macos"], entry["linux_confine"], entry["fail_closed_linux"]
            )
            entry["baseline"] = scored
            for platform in PLATFORMS:
                key = SIDE_KEYS[platform]
                rows.append(
                    {
                        "provider": provider,
                        "right": entry["id"],
                        "platform": platform,
                        "status": scored[key],
                        "proposed": spec["proposed"],
                        "open_decision": spec["open_decision"],
                        "verdict": entry[key]["verdict"],
                        "matches_proposal": scored["matches_proposal"][platform],
                    }
                )
    report["baseline"] = {
        "role": baseline["role"],
        "fail_closed": baseline["fail_closed"],
        "owners": list(baseline.get("owners") or []),
        "rights": baseline["rights"],
        "scores": rows,
        "counts": _counts(rows),
    }
    return report


def _counts(rows: list[dict]) -> dict[str, int]:
    counts = {name: 0 for name in STATUSES}
    for row in rows:
        counts[row["status"]] += 1
    return counts


def score_ids(report: dict) -> list[str]:
    return [
        f"{row['provider']}/{row['right']}/{row['platform']}={row['status']}"
        for row in report.get("baseline", {}).get("scores", [])
    ]


def planted_network_allow_caught(report: dict) -> bool:
    """A looser baseline that proposes network allow must force MUST CHANGE."""
    return any(
        row["right"] == "network" and row["status"] == "MUST CHANGE"
        for row in report.get("baseline", {}).get("scores", [])
    )
