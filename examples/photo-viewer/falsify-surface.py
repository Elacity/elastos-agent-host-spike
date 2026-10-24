#!/usr/bin/env python3
"""Break each rule of the Photos surface page, see its test fail, restore it.

Usage: python3 -I falsify-surface.py [--check]

Each falsifier replaces exact text in surface/browser/photos.js (it must occur
once), runs the named node tests, and requires them to FAIL. The file is
restored from its saved bytes afterwards, also on error or Ctrl-C. --check
only confirms every anchor occurs once. The runner is the capsule kit's
(examples/capsule-kit/falsify).
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "capsule-kit" / "falsify"))
import falsify_kit as kit  # noqa: E402

SURFACE = pathlib.Path(__file__).resolve().parent / "surface"
PAGE = SURFACE / "browser" / "photos.js"
TESTS = SURFACE / "photos.test.mjs"

# (name, exact old text, new text, tests that must fail)
CASES = [
    (
        "a position that is not a whole number is asked for",
        "if (!isPosition(order) || seen.has(order)) {",
        "if (seen.has(order)) {",
        ["it never requests a path"],
    ),
    (
        "a skipped message is shown as markup",
        "line.textContent = skip.order === null",
        "line.innerHTML = skip.order === null",
        ["it shows skipped items as text", "the page has no way to hold or reach anything else"],
    ),
    (
        "a skipped message is not cut short",
        "return text.length > MAX_MESSAGE_CHARS ?",
        "return false && text.length > MAX_MESSAGE_CHARS ?",
        ["it shows skipped items as text"],
    ),
    (
        "requests carry cookies",
        'credentials: "omit",',
        'credentials: "include",',
        ["it makes no request other than the two routes"],
    ),
    (
        "requests are made without a launch token",
        "  if (!token) {\n",
        "  if (false) {\n",
        ["without a launch token it asks for nothing"],
    ),
    (
        "a type the core does not allow is shown",
        "if (!IMAGE_TYPES.includes(item.mime)) {",
        "if (false) {",
        ["a playlist that is not one is refused"],
    ),
    (
        "the playlist schema is not checked",
        'if (!value || typeof value !== "object" || value.schema !== PLAYLIST_SCHEMA) {',
        'if (!value || typeof value !== "object") {',
        ["a playlist that is not one is refused"],
    ),
    (
        "a playlist of any length is taken",
        "if (items.length > MAX_ITEMS) {",
        "if (false) {",
        ["a playlist that is not one is refused"],
    ),
    (
        "a duration outside the core's bounds is kept",
        "durationMs: Math.min(MAX_DURATION_MS, Math.max(MIN_DURATION_MS, duration)),",
        "durationMs: duration,",
        ["each photo shows for its duration"],
    ),
    (
        "pause does not stop the slideshow",
        "if (state.playing && slide && state.slides.length > 1) {",
        "if (slide && state.slides.length > 1) {",
        ["each photo shows for its duration"],
    ),
    (
        "a slow earlier answer replaces a later choice",
        "      if (ticket !== state.shown) return; // a later choice won\n",
        "",
        ["a slow answer for an earlier choice does not replace a later one"],
    ),
    (
        "old photo URLs are never released",
        "      if (state.url) env.URL.revokeObjectURL(state.url);\n",
        "",
        ["it renders only playlist items"],
    ),
    (
        "an unreadable refusal shows no text",
        "shortText(reason || null,",
        "shortText(reason,",
        ["a refusal is shown as its text"],
    ),
]


def test_fails(name):
    return kit.node_test_fails(TESTS, name)


def main():
    cases = [(name, PAGE, [(old, new)], tests) for name, old, new, tests in CASES]
    kit.main([(cases, None, test_fails, None, True)], done=f"all {len(CASES)} surface falsifiers caught")


if __name__ == "__main__":
    main()
