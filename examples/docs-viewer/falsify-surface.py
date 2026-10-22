#!/usr/bin/env python3
"""Break each rule of the Documents surface page, see its test fail, restore it.

Usage: python3 -I falsify-surface.py [--check]

Each falsifier replaces exact text in surface/browser/reader.js (it must occur
once), runs the named node tests, and requires them to FAIL. The file is
restored from its saved bytes afterwards, also on error or Ctrl-C. --check
only confirms every anchor occurs once.

The runner is the capsule kit's (examples/capsule-kit/falsify).
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "capsule-kit" / "falsify"))
import falsify_kit as kit  # noqa: E402

SURFACE = pathlib.Path(__file__).resolve().parent / "surface"
PAGE = SURFACE / "browser" / "reader.js"
TESTS = SURFACE / "reader.test.mjs"

# (name, exact old text, new text, tests that must fail)
CASES = [
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
        "a text is not cut short",
        "  return text.length > chars ?",
        "  return false && text.length > chars ?",
        ["a refusal is shown as its text"],
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
    (
        "a document keeps its uri",
        "    documents.push({ order, title:",
        "    documents.push({ order, uri: document.uri, title:",
        ["it never requests a path"],
    ),
]


def tests_fail(names):
    return any(kit.node_test_fails(TESTS, name) for name in names)


def main():
    cases = [(name, PAGE, [(old, new)], tests) for name, old, new, tests in CASES]
    kit.main([(cases, tests_fail, None, True)], done=f"all {len(CASES)} surface falsifiers caught")


if __name__ == "__main__":
    main()
