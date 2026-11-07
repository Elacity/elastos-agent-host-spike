#!/usr/bin/env python3
"""Regenerate the B4 tables and list mismatches. Static only."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent
if str(LAB) not in sys.path:
    sys.path.insert(0, str(LAB))

from b4map.baseline import (
    BaselineError,
    load_baseline,
    load_planted_baseline,
    planted_network_allow_caught,
    score_ids,
)
from b4map.catalog import PROVIDERS
from b4map.compare import build_report, mismatch_ids
from b4map.gitread import load_pins, repo_root
from b4map.render import render_baseline, render_mismatches, write_outputs


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the committed tables, MISMATCHES.md, or BASELINE.md are stale",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="write tables/*.json, MISMATCHES.md, and BASELINE.md",
    )
    parser.add_argument(
        "--plant",
        metavar="DIR",
        help="compare a copied profile in DIR (must hold confine.sb) and require a CATCH",
    )
    parser.add_argument(
        "--plant-baseline",
        metavar="DIR",
        help="score platforms against a planted baseline in DIR and require a CATCH",
    )
    parser.add_argument(
        "--provider",
        choices=PROVIDERS,
        default="did-provider",
        help="provider for --plant (default did-provider)",
    )
    return parser.parse_args(argv)


def planted_network_caught(report: dict, provider: str) -> bool:
    return any(
        item["provider"] == provider
        and item["right"] == "network"
        and item["kind"] == "polarity"
        and item["macos"]["verdict"] == "allow"
        for item in report["mismatches"]
    )


def committed_is_stale(lab: Path, report: dict) -> list[str]:
    stale = []
    for provider, table in report["providers"].items():
        path = lab / "tables" / f"{provider}.json"
        generated = json.dumps(table, indent=2, sort_keys=True) + "\n"
        if not path.is_file() or path.read_text() != generated:
            stale.append(f"tables/{provider}.json")
    generated_md = render_mismatches(report)
    if not (lab / "MISMATCHES.md").is_file() or (lab / "MISMATCHES.md").read_text() != generated_md:
        stale.append("MISMATCHES.md")
    generated_base = render_baseline(report)
    if not (lab / "BASELINE.md").is_file() or (lab / "BASELINE.md").read_text() != generated_base:
        stale.append("BASELINE.md")
    return stale


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = repo_root()
    pins = load_pins()
    overrides = None
    baseline = None
    if args.plant:
        plant = Path(args.plant)
        if not plant.is_absolute():
            plant = root / plant
        profile = plant / "confine.sb"
        if not profile.is_file():
            print(f"plant {profile} is missing", file=sys.stderr)
            return 2
        overrides = {args.provider: profile}
    if args.plant_baseline:
        plant = Path(args.plant_baseline)
        if not plant.is_absolute():
            plant = root / plant
        try:
            baseline = load_planted_baseline(plant, load_baseline())
        except (BaselineError, OSError, json.JSONDecodeError) as err:
            print(f"planted baseline {plant} is unreadable: {err}", file=sys.stderr)
            return 2
    report = build_report(root, pins, overrides, baseline)
    ids = mismatch_ids(report)
    base_ids = score_ids(report)
    if args.plant:
        if planted_network_caught(report, args.provider):
            print(f"F-B4-MACOS-NETWORK-ALLOW CAUGHT ({args.provider}/network/polarity)")
            return 0
        print("F-B4-MACOS-NETWORK-ALLOW SURVIVED")
        print("mismatches:", ", ".join(ids) or "(none)")
        return 1
    if args.plant_baseline:
        if planted_network_allow_caught(report):
            print("F-B4-BASELINE-NETWORK-ALLOW CAUGHT (network/MUST CHANGE)")
            return 0
        print("F-B4-BASELINE-NETWORK-ALLOW SURVIVED")
        print("baseline_ids:", ", ".join(base_ids) or "(none)")
        return 1
    if args.write:
        write_outputs(LAB, report)
    if args.check:
        stale = committed_is_stale(LAB, report)
        if stale:
            print("stale:", ", ".join(stale), file=sys.stderr)
            return 1
        print("tables, MISMATCHES.md, and BASELINE.md match the sources")
    print(render_mismatches(report), end="")
    print()
    print(render_baseline(report), end="")
    print()
    print(f"mismatch_ids={json.dumps(ids)}")
    print(f"baseline_ids={json.dumps(base_ids)}")
    print(f"baseline_counts={json.dumps(report['baseline']['counts'])}")
    print("linux_x86_64_execution=NOT RUN")
    print("jetson_aarch64_execution=NOT RUN")
    print("macos_execution=NOT RUN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
