"""Static macOS / Linux permission map for M1 check B4."""

from .catalog import COMPARISON_RIGHTS, PROVIDERS
from .compare import build_report, mismatch_ids
from .gitread import RepoReadError, load_pins, read_pinned
from .macos import parse_declared_rights, parse_profile
from .render import render_mismatches, write_outputs

__all__ = [
    "COMPARISON_RIGHTS",
    "PROVIDERS",
    "RepoReadError",
    "build_report",
    "load_pins",
    "mismatch_ids",
    "parse_declared_rights",
    "parse_profile",
    "read_pinned",
    "render_mismatches",
    "write_outputs",
]
