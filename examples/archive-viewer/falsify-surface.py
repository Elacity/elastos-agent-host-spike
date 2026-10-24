#!/usr/bin/env python3
"""Break each rule of the Archive surface page, see its test fail, restore it.

Usage: python3 -I falsify-surface.py [--check]

The page's own rules live in surface/browser/reader.js; the documents model's
block rules are the capsule kit's one owner (examples/capsule-kit/surface/
docs-render.js), drawn here through the page's shipped copy, so those rules
are tested by the documents viewer and by the drift case. The drift case edits
only the shipped copy, and only its own test must fail.

Each falsifier replaces exact text (it must occur once), runs the named node
tests, and requires them to FAIL. The file is restored from its saved bytes
afterwards, also on error or Ctrl-C. --check only confirms every anchor
occurs once.

F37 is "a path is drawn as markup", F38 is "an image entry is drawn", and F39
is "an inherited property name picks a kind"; the rest cover the page's other
rules. The runner is the capsule kit's (examples/capsule-kit/falsify).
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "capsule-kit" / "falsify"))
import falsify_kit as kit  # noqa: E402

SURFACE = pathlib.Path(__file__).resolve().parent / "surface"
PAGE = SURFACE / "browser" / "reader.js"
COPY = SURFACE / "browser" / "docs-render.js"
TESTS = SURFACE / "reader.test.mjs"

FORBIDDEN = "the page has no way to hold or reach anything else"
DRIFT = "the shipped renderer matches the kit owner"

# (name, exact old text, new text, tests that must fail[, appends])
CASES = [
    # F37: a path is drawn as markup.
    (
        "F37 an entry path is drawn as markup",
        "  path.textContent = entry.path;",
        "  path.innerHTML = entry.path;",
        ["an entry path is text", FORBIDDEN],
    ),
    # F38: an image entry is drawn.
    (
        "F38 an image entry is drawn",
        '  const facts = doc.createElement("span");',
        '  if (entry.path.endsWith(".png")) {\n'
        '    const picture = doc.createElement("img");\n'
        "    picture.src = entry.path;\n"
        "    row.appendChild(picture);\n"
        "  }\n"
        '  const facts = doc.createElement("span");',
        ["the page draws no image on bus v1", FORBIDDEN],
    ),
    # F39: the kind is looked up through the prototype.
    (
        "F39 an inherited property name picks a kind",
        '  return typeof kind === "string" && Object.hasOwn(KINDS, kind) ? KINDS[kind] : "Other";',
        '  return KINDS[kind] || "Other";',
        ["a kind named after an inherited property is not drawn"],
    ),
    (
        "F39b a view key is read through the prototype",
        "  return Object.hasOwn(Object(value), key) ? value[key] : undefined;",
        "  return key in Object(value) ? value[key] : undefined;",
        ["a view key named after an inherited property is not read"],
    ),
    # P10: one owner for the block rules, and this page ships its copy.
    (
        "a second copy of a renderer rule is added",
        "const MAX_PATH_CHARS = 20000;",
        "const MAX_PATH_CHARS = 20000;",
        ["the page keeps the renderer in one place"],
        [(PAGE, "\n\nfunction styleTag(style) {\n  return style;\n}\n")],
    ),
    (
        "a blank refusal reason is kept",
        "cut(reason.trim() || null, MAX_MESSAGE_CHARS,",
        "cut(reason || null, MAX_MESSAGE_CHARS,",
        ["a blank refusal reason is not shown as blank"],
    ),
    (
        "a blank skip message stays blank",
        '      message: message.trim() ? message : "Not shown.",',
        "      message,",
        ["a skipped preview with a blank message still explains why"],
    ),
    (
        "a skip reason is dropped",
        '      const reason = skip.reason ? ` (${skip.reason})` : "";',
        '      const reason = "";',
        ["a skipped preview with a blank message still explains why"],
    ),
    (
        "a malformed refusal field is ignored",
        '    if (!refusedIn || typeof refusedIn !== "object" || Array.isArray(refusedIn)) {\n'
        '      throw new Error("These are not Archive views.");\n'
        "    }",
        "    if (false) {\n"
        '      throw new Error("These are not Archive views.");\n'
        "    }",
        ["a malformed refusal field rejects the view"],
    ),
    (
        "any number of preview blocks is taken",
        "  if (!isCount(index) || !Array.isArray(blocksIn) || blocksIn.length > MAX_BLOCKS) return null;",
        "  if (!isCount(index) || !Array.isArray(blocksIn)) return null;",
        ["a preview with more blocks than the model allows is not shown"],
    ),
    (
        "a refused archive still draws its content",
        "      if (read.refused) {\n"
        "        state.entries = [];\n"
        "        state.previews = [];\n"
        "        setStatus(read.refused.message);\n"
        "        return;\n"
        "      }",
        "      if (false) {\n"
        "        state.entries = [];\n"
        "        state.previews = [];\n"
        "        setStatus(read.refused.message);\n"
        "        return;\n"
        "      }",
        [
            "a refused archive is shown with its reason and lists no entry",
            "a refused archive without a reason still says why",
        ],
    ),
    (
        "an empty refusal reason stays empty",
        '    refused = { message: reason.trim() ? reason : "This archive could not be read." };',
        "    refused = { message: reason };",
        [
            "a refused archive without a reason still says why",
            "a refused archive with a blank reason still says why",
        ],
    ),
    (
        "the view schema is not checked",
        '  if (!value || typeof value !== "object" || own(value, "schema") !== VIEW_SCHEMA) {',
        '  if (!value || typeof value !== "object") {',
        ["views that are not ones are refused", "a view that is not one is not drawn"],
    ),
    (
        "any number of entries is taken",
        "  if (Array.isArray(entriesIn) && entriesIn.length > MAX_ENTRIES) {",
        "  if (false) {",
        ["views that are not ones are refused"],
    ),
    (
        "any number of previews is taken",
        "  if (Array.isArray(previewsIn) && previewsIn.length > MAX_PREVIEWS) {",
        "  if (false) {",
        ["views that are not ones are refused"],
    ),
    (
        "a malformed entries field is taken",
        "  if (entriesIn !== undefined && !Array.isArray(entriesIn)) {",
        "  if (false) {",
        ["views that are not ones are refused"],
    ),
    (
        "a malformed previews field is taken",
        "  if (previewsIn !== undefined && !Array.isArray(previewsIn)) {",
        "  if (false) {",
        ["views that are not ones are refused"],
    ),
    (
        "an unreadable entry is drawn",
        "    if (read) entries.push(read);",
        "    if (true) entries.push(read);",
        ["an unreadable entry or preview is not shown, and the rest are"],
    ),
    (
        "an unreadable preview is drawn",
        "    if (read) previews.push(read);",
        "    if (true) previews.push(read);",
        ["an unreadable entry or preview is not shown, and the rest are"],
    ),
    (
        "an unreadable refusal shows no text",
        "cut(reason.trim() || null, MAX_MESSAGE_CHARS,",
        "cut(reason, MAX_MESSAGE_CHARS,",
        ["a refusal is shown as its text"],
    ),
    (
        "requests carry cookies",
        '        credentials: "omit",',
        '        credentials: "include",',
        ["it makes one request"],
    ),
    (
        "requests are made without a launch token",
        "  if (!token) {\n",
        "  if (false) {\n",
        ["without a launch token it asks for nothing"],
    ),
    (
        "an entry keeps its uri",
        '    path: cut(own(entry, "path"), MAX_PATH_CHARS, ""),',
        '    uri: own(entry, "uri"),\n    path: cut(own(entry, "path"), MAX_PATH_CHARS, ""),',
        ["it never requests an entry"],
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


def main():
    page = [
        (case[0], PAGE, [(case[1], case[2])], case[3]) + ((case[4],) if len(case) > 4 else ())
        for case in CASES
    ]
    drift = [(name, COPY, [(old, new)], tests) for name, old, new, tests in DRIFT_CASES]
    kit.main(
        [(page, None, test_fails, None, True), (drift, None, test_fails, None, True)],
        done=f"all {len(page) + len(drift)} surface falsifiers caught",
    )


if __name__ == "__main__":
    main()
