#!/usr/bin/env python3
"""Break each rule of the Documents surface page, see its test fail, restore it.

Usage: python3 -I falsify-surface.py [--check]

The page rules live in two files: the page glue in surface/browser/reader.js,
and the docs-model renderer's rules in the kit's one owner,
examples/capsule-kit/surface/docs-render.js. A renderer mutant is written to
the owner and then copied to the page's shipped browser/docs-render.js, as the
build does, so the page tests see it and the copy stays pinned to the owner.
The drift case edits only the shipped copy, and only its own test must fail.

Each falsifier replaces exact text (it must occur once), runs the named node
tests, and requires them to FAIL. The files are restored from their saved
bytes afterwards, also on error or Ctrl-C. --check only confirms every anchor
occurs once.

The runner is the capsule kit's (examples/capsule-kit/falsify).
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "capsule-kit" / "falsify"))
import falsify_kit as kit  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
SURFACE = pathlib.Path(__file__).resolve().parent / "surface"
PAGE = SURFACE / "browser" / "reader.js"
OWNER = REPO / "capsule-kit" / "surface" / "docs-render.js"
COPY = SURFACE / "browser" / "docs-render.js"
TESTS = SURFACE / "reader.test.mjs"

DRIFT = "the shipped renderer matches the kit owner"

# Page-glue rules: (name, exact old text, new text, tests that must fail)
PAGE_CASES = [
    (
        "a title is shown as markup",
        "        button.textContent = document.title;",
        "        button.innerHTML = document.title;",
        ["markup in a document stays text"],
    ),
    (
        "a skipped message is shown as markup",
        "line.textContent = skip.order === null",
        "line.innerHTML = skip.order === null",
        ["markup in a document stays text"],
    ),
    (
        "an unreadable refusal shows no text",
        "cut(reason || null, MAX_MESSAGE_CHARS,",
        "cut(reason, MAX_MESSAGE_CHARS,",
        ["a refusal is shown as its text"],
    ),
    (
        "requests carry cookies",
        'credentials: "omit",',
        'credentials: "include",',
        ["it makes one request"],
    ),
    (
        "requests are made without a launch token",
        "  if (!token) {\n",
        "  if (false) {\n",
        ["without a launch token it asks for nothing"],
    ),
    (
        "the pages schema is not checked",
        'if (!value || typeof value !== "object" || value.schema !== PAGES_SCHEMA) {',
        'if (!value || typeof value !== "object") {',
        ["pages that are not ones are refused"],
    ),
    (
        "any number of documents is taken",
        "  if (documentsIn.length > MAX_DOCUMENTS) {",
        "  if (false) {",
        ["pages that are not ones are refused"],
    ),
    (
        "any number of blocks is taken",
        "    if (!blocksIn || blocksIn.length > MAX_BLOCKS) {",
        "    if (!blocksIn) {",
        ["a document with a block it cannot read is not shown"],
    ),
    (
        "a document keeps its uri",
        "    documents.push({ order, title:",
        "    documents.push({ order, uri: document.uri, title:",
        ["it never requests a path"],
    ),
]

# Renderer rules: the anchors are in the kit's one owner.
RENDER_CASES = [
    (
        "a span is shown as markup",
        "      element.textContent = span.text;",
        "      element.innerHTML = span.text;",
        ["markup in a document stays text", "the page has no way to hold or reach anything else"],
    ),
    (
        "code is shown as markup",
        "      code.textContent = block.text;",
        "      code.innerHTML = block.text;",
        ["markup in a document stays text"],
    ),
    (
        "a text is not cut short",
        "  return text.length > chars ?",
        "  return false && text.length > chars ?",
        ["a refusal is shown as its text"],
    ),
    (
        "an unknown block kind is drawn",
        "    default:\n      return null;",
        '    default:\n      return { kind: "rule" };',
        ["a document with a block it cannot read is not shown"],
    ),
    (
        "an unknown style becomes its own element",
        '    tag: styleTag(span && span.style),',
        '    tag: (span && span.style) || "span",',
        ["an unknown style is plain"],
    ),
    (
        "a style is looked up through the prototype",
        '  return typeof style === "string" && Object.hasOwn(STYLES, style) ? STYLES[style] : "span";',
        '  return STYLES[style] || "span";',
        ["a style named after an inherited property is plain"],
    ),
    (
        "a heading level is not kept within 1 to 6",
        "level: Math.min(6, Math.max(1, block.level)),",
        "level: block.level,",
        ["an unknown style is plain and a heading level stays within 1 to 6"],
    ),
]

# The one-owner rule: one byte of the shipped copy differs from the owner.
DRIFT_CASES = [
    (
        DRIFT,
        "export const MAX_BLOCKS = 512;",
        "export const MAX_BLOCKS = 512 ;",
        [DRIFT],
    ),
]


def test_fails(name):
    return kit.node_test_fails(TESTS, name)


def sync_copy():
    """The build's copy step: the shipped file is the owner's bytes."""
    COPY.write_bytes(OWNER.read_bytes())


def main():
    page = [(name, PAGE, [(old, new)], tests) for name, old, new, tests in PAGE_CASES]
    render = [
        (name, OWNER, [(old, new)], tests, [(COPY, "")])
        for name, old, new, tests in RENDER_CASES
    ]
    drift = [(name, COPY, [(old, new)], tests) for name, old, new, tests in DRIFT_CASES]
    kit.main(
        [
            (page, None, test_fails, None, True),
            (render, sync_copy, test_fails, None, True),
            (drift, None, test_fails, None, True),
        ],
        done=f"all {len(page) + len(render) + len(drift)} surface falsifiers caught",
    )


if __name__ == "__main__":
    main()
