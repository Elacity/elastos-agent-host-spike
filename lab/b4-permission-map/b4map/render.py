"""Write the machine-readable tables and MISMATCHES.md."""

from __future__ import annotations

import json
from pathlib import Path

from .catalog import PROVIDERS


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


def write_outputs(lab_root: Path, report: dict) -> None:
    tables = lab_root / "tables"
    tables.mkdir(exist_ok=True)
    for provider, table in report["providers"].items():
        path = tables / f"{provider}.json"
        path.write_text(json.dumps(table, indent=2, sort_keys=True) + "\n")
    (lab_root / "MISMATCHES.md").write_text(render_mismatches(report))


def load_committed_tables(lab_root: Path) -> dict[str, str]:
    tables = lab_root / "tables"
    return {
        provider: (tables / f"{provider}.json").read_text()
        for provider in PROVIDERS
    }
