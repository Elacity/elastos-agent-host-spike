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

from b4map.catalog import PROVIDERS
from b4map.compare import build_report, mismatch_ids
from b4map.gitread import load_pins, repo_root
from b4map.render import render_mismatches, write_outputs


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the committed tables or MISMATCHES.md are stale",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="write tables/*.json and MISMATCHES.md",
    )
    parser.add_argument(
        "--plant",
        metavar="DIR",
        help="compare a copied profile in DIR (must hold confine.sb) and require a CATCH",
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
    from b4map.render import render_mismatches as render

    stale = []
    for provider, table in report["providers"].items():
        path = lab / "tables" / f"{provider}.json"
        generated = json.dumps(table, indent=2, sort_keys=True) + "\n"
        if not path.is_file() or path.read_text() != generated:
            stale.append(f"tables/{provider}.json")
    mismatches = lab / "MISMATCHES.md"
    generated_md = render(report)
    if not mismatches.is_file() or mismatches.read_text() != generated_md:
        stale.append("MISMATCHES.md")
    return stale


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = repo_root()
    pins = load_pins()
    overrides = None
    if args.plant:
        plant = Path(args.plant)
        if not plant.is_absolute():
            plant = root / plant
        profile = plant / "confine.sb"
        if not profile.is_file():
            print(f"plant {profile} is missing", file=sys.stderr)
            return 2
        overrides = {args.provider: profile}
    report = build_report(root, pins, overrides)
    ids = mismatch_ids(report)
    if args.plant:
        if planted_network_caught(report, args.provider):
            print(f"F-B4-MACOS-NETWORK-ALLOW CAUGHT ({args.provider}/network/polarity)")
            return 0
        print("F-B4-MACOS-NETWORK-ALLOW SURVIVED")
        print("mismatches:", ", ".join(ids) or "(none)")
        return 1
    if args.write:
        write_outputs(LAB, report)
    if args.check:
        stale = committed_is_stale(LAB, report)
        if stale:
            print("stale:", ", ".join(stale), file=sys.stderr)
            return 1
        print("tables and MISMATCHES.md match the sources")
    print(render_mismatches(report), end="")
    print()
    print(f"mismatch_ids={json.dumps(ids)}")
    print("linux_x86_64_execution=NOT RUN")
    print("jetson_aarch64_execution=NOT RUN")
    print("macos_execution=NOT RUN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
