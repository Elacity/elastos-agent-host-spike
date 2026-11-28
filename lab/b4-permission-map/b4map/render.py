"""Write the machine-readable tables, MISMATCHES.md, and BASELINE.md."""

from __future__ import annotations

import json
from pathlib import Path

from .baseline import score_ids
from .catalog import PROVIDERS

PLATFORM_LABEL = {
    "macos": "macOS profile",
    "linux-confine": "#296",
    "fail-closed-linux": "#307",
}


def _loc(side: dict) -> str:
    line = side.get("line")
    if line:
        return f"{side['file']}:{line}"
    return side["file"]


def _side_line(label: str, side: dict) -> str:
    note = side.get("note") or ""
    rule = side.get("rule") or ""
    extra = f" — {note}" if note else ""
    return f"- {label}: `{_loc(side)}` `{rule}` **{side['verdict']}**{extra}"


def render_mismatches(report: dict) -> str:
    lines = [
        "# B4 permission mismatches",
        "",
        "Static source comparison. The checker reads the macOS oracles and the",
        "pinned Linux labs. It starts no provider.",
        "",
        f"- Linux x86-64 execution: **{report['status']['linux_x86_64_execution']}**",
        f"- Jetson aarch64 execution: **{report['status']['jetson_aarch64_execution']}**",
        f"- macOS execution: **{report['status']['macos_execution']}**",
        "",
        "Linux sources:",
        "",
        f"- draft PR #296 `lab/linux-confine` at `{report['linux_confine']['sha']}`",
        f"- draft PR #307 `lab/fail-closed-linux` at `{report['fail_closed_linux']['sha']}`",
        "",
        f"Mismatch rows: **{len(report['mismatches'])}**.",
        "",
        "Suggested fixes stay in this file. This lab does not edit",
        "`capsules/`, `lab/linux-confine/`, or `lab/fail-closed-linux/`.",
        "",
        "The proposed unified baseline is `baseline.json`. Scores against",
        "that file (CONFORMS / MUST CHANGE / OPEN DECISION) are `BASELINE.md`.",
        "",
    ]
    by_provider: dict[str, list[dict]] = {name: [] for name in PROVIDERS}
    for item in report["mismatches"]:
        by_provider[item["provider"]].append(item)
    for provider in PROVIDERS:
        lines.append(f"## {provider}")
        lines.append("")
        rows = by_provider[provider]
        if not rows:
            lines.append("No mismatch.")
            lines.append("")
            continue
        seen = set()
        for item in rows:
            key = item["right"]
            if key in seen:
                continue
            seen.add(key)
            group = [row for row in rows if row["right"] == key]
            kinds = ", ".join(row["kind"] for row in group)
            lines.append(f"### `{item['right']}` — {item['title']}")
            lines.append("")
            lines.append(f"Kinds: {kinds}.")
            lines.append("")
            for row in group:
                lines.append(f"- {row['why']}")
            lines.append("")
            lines.append(_side_line("macOS", item["macos"]))
            lines.append(_side_line("Linux #296", item["linux_confine"]))
            lines.append(_side_line("Linux #307", item["fail_closed_linux"]))
            lines.append("")
            lines.append(f"Suggested fix (not applied): {item['fix']}")
            lines.append("")
    lines.append("## What matched")
    lines.append("")
    matched = []
    first = next(iter(report["providers"].values()))
    for index, entry in enumerate(first["rights"]):
        if all(report["providers"][name]["rights"][index]["match"] for name in PROVIDERS):
            matched.append(f"`{entry['id']}` {entry['macos']['verdict']}")
    if matched:
        lines.append("These rows match on macOS, #296, and #307: " + ", ".join(matched) + ".")
    else:
        lines.append("No comparison right matches on every provider.")
    lines.append("")
    return "\n".join(lines)


def _who_changes(entry: dict, spec: dict) -> str:
    sides = []
    matches = spec["matches_proposal"]
    for platform, label in PLATFORM_LABEL.items():
        action = spec["change"][platform]
        if matches[platform] or action == "none":
            continue
        sides.append(f"{label}: {action}")
    return "; ".join(sides) if sides else "none"


def render_baseline(report: dict) -> str:
    baseline = report["baseline"]
    counts = baseline["counts"]
    first = next(iter(report["providers"].values()))
    lines = [
        "# B4 proposed unified baseline",
        "",
        "One polarity per right for macOS and both Linux labs. This is a",
        "proposal. The checker scores each platform against `baseline.json`.",
        "It starts no provider and it does not edit a profile.",
        "",
        f"- Linux x86-64 execution: **{report['status']['linux_x86_64_execution']}**",
        f"- Jetson aarch64 execution: **{report['status']['jetson_aarch64_execution']}**",
        f"- macOS execution: **{report['status']['macos_execution']}**",
        "",
        baseline["fail_closed"],
        "",
        "Owners: " + ", ".join(baseline["owners"]) + ".",
        "",
        "## Per-right decision",
        "",
        "| Right | Proposed | Decision | macOS | #296 | #307 | Who changes if the proposal is adopted |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for entry in first["rights"]:
        spec = entry["baseline"]
        decision = "OPEN DECISION" if spec["open_decision"] else "proposed"
        lines.append(
            "| `{id}` | {proposed} | {decision} | {macos} | {c9} | {c0} | {who} |".format(
                id=entry["id"],
                proposed=spec["proposed"],
                decision=decision,
                macos=spec["macos"],
                c9=spec["linux_confine"],
                c0=spec["fail_closed_linux"],
                who=_who_changes(entry, spec).replace("|", "/"),
            )
        )
    lines.extend(
        [
            "",
            "Scores above are did-provider. wallet and model use the same",
            "proposed polarity. `storage.parent` on #296 is missing for did and",
            "model, and partial (private remount) for wallet.",
            "",
            "## Counts",
            "",
            f"- CONFORMS: **{counts['CONFORMS']}**",
            f"- MUST CHANGE: **{counts['MUST CHANGE']}**",
            f"- OPEN DECISION: **{counts['OPEN DECISION']}**",
            f"- Inter-platform mismatch rows: **{len(report['mismatches'])}**",
            "",
            "Counts are provider × right × platform (3 × 12 × 3 = 108).",
            "",
            "## Rationale",
            "",
        ]
    )
    seen = set()
    for spec in baseline["rights"]:
        if spec["id"] in seen:
            continue
        seen.add(spec["id"])
        decision = "OPEN DECISION" if spec["open_decision"] else "proposed"
        lines.append(f"### `{spec['id']}` — {spec['title']}")
        lines.append("")
        lines.append(f"Proposed **{spec['proposed']}** ({decision}).")
        lines.append("")
        lines.append(spec["rationale"])
        lines.append("")
        lines.append(
            "- macOS profile: "
            + spec["change"]["macos"]
            + "; #296: "
            + spec["change"]["linux-confine"]
            + "; #307: "
            + spec["change"]["fail-closed-linux"]
        )
        lines.append("")
    lines.append("## Scores by provider")
    lines.append("")
    by_provider: dict[str, list[dict]] = {name: [] for name in PROVIDERS}
    for row in baseline["scores"]:
        by_provider[row["provider"]].append(row)
    for provider in PROVIDERS:
        lines.append(f"### {provider}")
        lines.append("")
        lines.append("| Right | macOS | #296 | #307 |")
        lines.append("| --- | --- | --- | --- |")
        grouped: dict[str, dict[str, str]] = {}
        for row in by_provider[provider]:
            grouped.setdefault(row["right"], {})[row["platform"]] = row["status"]
        for right_id, statuses in grouped.items():
            lines.append(
                f"| `{right_id}` | {statuses['macos']} | {statuses['linux-confine']} | {statuses['fail-closed-linux']} |"
            )
        lines.append("")
    lines.append("score_ids:")
    lines.append("")
    for ident in score_ids(report):
        lines.append(f"- `{ident}`")
    lines.append("")
    return "\n".join(lines)


def write_outputs(lab_root: Path, report: dict) -> None:
    tables = lab_root / "tables"
    tables.mkdir(exist_ok=True)
    for provider, table in report["providers"].items():
        path = tables / f"{provider}.json"
        path.write_text(json.dumps(table, indent=2, sort_keys=True) + "\n")
    (lab_root / "MISMATCHES.md").write_text(render_mismatches(report))
    (lab_root / "BASELINE.md").write_text(render_baseline(report))


def load_committed_tables(lab_root: Path) -> dict[str, str]:
    tables = lab_root / "tables"
    return {
        provider: (tables / f"{provider}.json").read_text()
        for provider in PROVIDERS
    }
