"""Static macOS / Linux permission map for M1 check B4."""

from .baseline import load_baseline, score_ids
from .catalog import COMPARISON_RIGHTS, PROVIDERS
from .compare import build_report, mismatch_ids
from .gitread import RepoReadError, load_pins, read_pinned
from .macos import parse_declared_rights, parse_profile
from .render import render_baseline, render_mismatches, write_outputs

__all__ = [
    "COMPARISON_RIGHTS",
    "PROVIDERS",
    "RepoReadError",
    "build_report",
    "load_baseline",
    "load_pins",
    "mismatch_ids",
    "parse_declared_rights",
    "parse_profile",
    "read_pinned",
    "render_baseline",
    "render_mismatches",
    "score_ids",
    "write_outputs",
]
