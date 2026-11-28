"""Build per-provider tables and the mismatch list."""

from __future__ import annotations

from pathlib import Path

from .baseline import load_baseline, score_report
from .catalog import COMPARISON_RIGHTS, NOT_RUN, PROVIDERS
from .linux import fail_closed_sides, linux_confine_sides, load_linux
from .macos import load_provider_macos


def _polarity(verdict: str) -> str:
    if verdict == "allow":
        return "allow"
    if verdict == "deny":
        return "deny"
    return "unenforced"


def classify_mismatch(macos: dict, linux_c9: dict, linux_c0: dict) -> list[dict]:
    """Return zero or more mismatch records for one right.

    A mismatch is a right allowed on one side and denied on the other, or
    enforced on one side and missing on the other. `partial` is unenforced
    when compared with `allow` or `deny`.
    """
    found = []
    mac = macos["verdict"]
    c9 = linux_c9["verdict"]
    c0 = linux_c0["verdict"]
    mac_p = _polarity(mac)
    c9_p = _polarity(c9)
    c0_p = _polarity(c0)

    def row(kind: str, left: str, right: str, why: str) -> dict:
        return {"kind": kind, "left": left, "right": right, "why": why}

    if mac_p == "allow" and c9_p == "deny":
        found.append(row("polarity", "macos", "linux-confine", "allowed on macOS, denied on Linux #296"))
    if mac_p == "deny" and c9_p == "allow":
        found.append(row("polarity", "macos", "linux-confine", "denied on macOS, allowed on Linux #296"))
    if mac_p == "allow" and c0_p == "deny":
        found.append(row("polarity", "macos", "fail-closed-linux", "allowed on macOS, denied on Linux #307"))
    if mac_p == "deny" and c0_p == "allow":
        found.append(row("polarity", "macos", "fail-closed-linux", "denied on macOS, allowed on Linux #307"))
    if mac_p in {"allow", "deny"} and c9_p == "unenforced":
        found.append(
            row(
                "coverage",
                "macos",
                "linux-confine",
                f"{mac} on macOS, {c9} on Linux #296",
            )
        )
    if mac_p in {"allow", "deny"} and c0_p == "unenforced":
        found.append(
            row(
                "coverage",
                "macos",
                "fail-closed-linux",
                f"{mac} on macOS, {c0} on Linux #307",
            )
        )
    if c9_p == "allow" and c0_p == "deny":
        found.append(row("linux-split", "linux-confine", "fail-closed-linux", "allowed on #296, denied on #307"))
    if c9_p == "deny" and c0_p == "allow":
        found.append(row("linux-split", "linux-confine", "fail-closed-linux", "denied on #296, allowed on #307"))
    if c9_p in {"allow", "deny"} and c0_p == "unenforced":
        found.append(
            row(
                "linux-split",
                "linux-confine",
                "fail-closed-linux",
                f"{c9} on #296, {c0} on #307",
            )
        )
    if c0_p in {"allow", "deny"} and c9_p == "unenforced":
        found.append(
            row(
                "linux-split",
                "fail-closed-linux",
                "linux-confine",
                f"{c0} on #307, {c9} on #296",
            )
        )
    return found


def _cite(side: dict) -> str:
    line = side.get("line")
    loc = f"{side['file']}:{line}" if line else side["file"]
    return loc


def suggest_fix(right_id: str, mismatches: list[dict], macos: dict, linux_c9: dict, linux_c0: dict) -> str:
    """One suggested fix. This lab does not apply it."""
    kinds = {item["kind"] for item in mismatches}
    if right_id == "unix-socketpair":
        return (
            "Pick one declared right for AF_UNIX socketpair. Either add a named "
            "macOS network exception that the C8 contract accepts, or drop the "
            "#296 AF_UNIX exception so both Linux labs deny the pair like "
            f"{_cite(macos)} and {_cite(linux_c0)}."
        )
    if right_id == "signal.host":
        return (
            "Give the C0 guard the same carrier #296 already uses: a PID "
            f"namespace that contains the provider ({_cite(linux_c9)}). "
            "LANDLOCK_SCOPE_SIGNAL at ABI 6 is not a substitute for a host "
            "pid that still exists in the same namespace."
        )
    if right_id == "storage.parent":
        return (
            "Either drop the STORAGE_PARENT literal read from the C8 storage "
            "right once a named test shows each provider starts without it, "
            "or teach the Linux labs one private-parent mount for every "
            f"provider, not only wallet ({_cite(linux_c9)})."
        )
    if right_id == "startup-root-directory":
        return (
            "Keep the macOS baseline only while a named test needs `/`. If "
            "the Linux loader starts without that rule, move the baseline "
            "to a Linux-only loader grant and stop claiming one right."
        )
    if right_id == "startup-sysctl":
        return (
            "Name the Linux syscalls that stand in for sysctl-read (uname "
            "and the loader set) in the C8 baseline, or drop the macOS "
            "sysctl-read once a named test shows the loader starts without it."
        )
    if "linux-split" in kinds and "polarity" not in kinds:
        return (
            "Make #296 and #307 grant or deny this right with the same "
            "mechanism before B4 can close."
        )
    if "polarity" in kinds:
        return (
            f"Change the granting side at {_cite(macos) if macos['verdict'] == 'allow' else _cite(linux_c9)} "
            "or the denying side so both platforms match the declared right."
        )
    return (
        "Add the missing mechanism on the side that reports missing, or drop "
        "the right from the declared set so both platforms omit it."
    )


def build_provider(
    provider: str,
    macos_sides: dict,
    c9: dict,
    c0: dict,
    c9_parsed: dict,
    c0_parsed: dict,
    declared_file: str,
    profile_file: str,
    operations: list[dict],
) -> dict:
    rights = []
    mismatches = []
    c9_sides = linux_confine_sides(c9_parsed, provider)
    c0_sides = fail_closed_sides(c0_parsed, provider)
    for spec in COMPARISON_RIGHTS:
        ident = spec["id"]
        macos = macos_sides[ident]
        linux_c9 = c9_sides[ident]
        linux_c0 = c0_sides[ident]
        found = classify_mismatch(macos, linux_c9, linux_c0)
        entry = {
            "id": ident,
            "title": spec["title"],
            "declared": spec["declared"],
            "kind": spec["kind"],
            "macos": macos,
            "linux_confine": linux_c9,
            "fail_closed_linux": linux_c0,
            "match": not found,
            "mismatches": found,
        }
        if spec.get("implied_by"):
            entry["implied_by"] = spec["implied_by"]
        rights.append(entry)
        for item in found:
            mismatches.append(
                {
                    "provider": provider,
                    "right": ident,
                    "title": spec["title"],
                    "kind": item["kind"],
                    "left": item["left"],
                    "right_lab": item["right"],
                    "why": item["why"],
                    "macos": macos,
                    "linux_confine": linux_c9,
                    "fail_closed_linux": linux_c0,
                    "fix": suggest_fix(ident, found, macos, linux_c9, linux_c0),
                }
            )
    return {
        "provider": provider,
        "declared_rights": declared_file,
        "macos_profile": profile_file,
        "linux_confine": {"pr": 296, "sha": c9["sha"]},
        "fail_closed_linux": {"pr": 307, "sha": c0["sha"]},
        "status": NOT_RUN,
        "operations_table": operations,
        "rights": rights,
        "mismatches": mismatches,
    }


def build_report(
    root: Path,
    pins: dict,
    profile_overrides: dict[str, Path] | None = None,
    baseline: dict | None = None,
) -> dict:
    c9_parsed, c0_parsed = load_linux(pins, root)
    providers = {}
    mismatches = []
    overrides = profile_overrides or {}
    for provider in PROVIDERS:
        profile, declared, sides, operations = load_provider_macos(
            root, provider, overrides.get(provider)
        )
        table = build_provider(
            provider,
            sides,
            c9_parsed,
            c0_parsed,
            c9_parsed,
            c0_parsed,
            declared["file"],
            profile["file"],
            operations,
        )
        providers[provider] = table
        mismatches.extend(table["mismatches"])
    report = {
        "status": NOT_RUN,
        "pins": {
            "linux_confine": pins["linux_confine"],
            "fail_closed_linux": pins["fail_closed_linux"],
        },
        "providers": providers,
        "mismatches": mismatches,
        "linux_confine": {
            "pr": 296,
            "sha": c9_parsed["sha"],
            "unshare": c9_parsed["unshare"],
            "socketpair_unix": c9_parsed["socketpair_unix"],
            "pid_ns": c9_parsed["pid_ns"],
        },
        "fail_closed_linux": {
            "pr": 307,
            "sha": c0_parsed["sha"],
            "unshare_user_only": c0_parsed["unshare_user_only"],
            "socketpair_denied": c0_parsed["socketpair_denied"],
            "pid_gap": c0_parsed["pid_gap"],
        },
    }
    return score_report(report, baseline if baseline is not None else load_baseline())


def mismatch_ids(report: dict) -> list[str]:
    return [
        f"{item['provider']}/{item['right']}/{item['kind']}/{item['left']}->{item['right_lab']}"
        for item in report["mismatches"]
    ]
