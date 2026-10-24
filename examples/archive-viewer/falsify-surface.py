#!/usr/bin/env python3
"""Break each rule of the Archive surface page, see its test fail, restore it.

Usage: python3 -I falsify-surface.py [--check]

Each falsifier replaces exact text in surface/browser/reader.js (it must occur
once), runs the named node tests, and requires them to FAIL. The file is
restored from its saved bytes afterwards, also on error or Ctrl-C. --check
only confirms every anchor occurs once.

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
TESTS = SURFACE / "reader.test.mjs"

# (name, exact old text, new text, tests that must fail)
CASES = [
    # F37: a path is drawn as markup.
    (
        "F37 an entry path is drawn as markup",
        "  path.textContent = entry.path;",
        "  path.innerHTML = entry.path;",
        ["an entry path is text", "the page has no way to hold or reach anything else"],
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
        ["the page draws no image on bus v1", "the page has no way to hold or reach anything else"],
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
    (
        "a span style is looked up through the prototype",
        '  return typeof style === "string" && Object.hasOwn(STYLES, style) ? STYLES[style] : "span";',
        "  return STYLES[style] || \"span\";",
        ["a style named after an inherited property is plain"],
    ),
    (
        "code is shown as markup",
        "      code.textContent = block.text;",
        "      code.innerHTML = block.text;",
        ["it draws the documents model's blocks with text only", "the page has no way to hold or reach anything else"],
    ),
    (
        "a heading level is not kept within 1 to 6",
        '      return { kind: "heading", level: Math.min(6, Math.max(1, block.level)), spans };',
        '      return { kind: "heading", level: block.level, spans };',
        ["an unknown style is plain and a heading level stays within 1 to 6"],
    ),
    (
        "a heading is drawn at a fixed level",
        '      return spansInto(doc.createElement(`h${block.level}`), block.spans);',
        '      return spansInto(doc.createElement("h2"), block.spans);',
        ["the previews follow the documents page rules", "the block functions are the documents page's own"],
    ),
    (
        "a heading level is normalized differently",
        '      return { kind: "heading", level: Math.min(6, Math.max(1, block.level)), spans };',
        '      return { kind: "heading", level: Math.min(6, Math.max(1, block.level === 3 ? 4 : block.level)), spans };',
        ["the previews follow the documents page rules", "the block functions are the documents page's own"],
    ),
    (
        "a blank refusal reason is kept",
        "        const error = new Error(cut(reason.trim() || null, MAX_MESSAGE_CHARS,",
        "        const error = new Error(cut(reason || null, MAX_MESSAGE_CHARS,",
        ["a blank refusal reason is not shown as blank"],
    ),
    (
        "a style name is added to the table",
        'const STYLES = { plain: "span", strong: "strong", em: "em", code: "code" };',
        'const STYLES = { plain: "span", strong: "strong", em: "em", code: "code", mark: "mark" };',
        ["the block functions are the documents page's own"],
    ),
    (
        "the text cap differs",
        "const MAX_TEXT_CHARS = 20000;",
        "const MAX_TEXT_CHARS = 20001;",
        ["the block functions are the documents page's own", "the previews follow the documents page rules"],
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
        "the block kind is own-property only",
        "  switch (block && block.kind) {",
        '  switch (own(block, "kind")) {',
        ["the previews follow the documents page rules", "the block functions are the documents page's own"],
    ),
    (
        "a span style is own-property only",
        "    tag: styleTag(span && span.style),",
        '    tag: styleTag(own(span, "style")),',
        ["the previews follow the documents page rules", "the block functions are the documents page's own"],
    ),
    (
        "a malformed refusal field is ignored",
        "    if (!refusedIn || typeof refusedIn !== \"object\" || Array.isArray(refusedIn)) {\n"
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
        "the span cap is not checked",
        "  if (!Array.isArray(spans) || spans.length > MAX_SPANS) return null;",
        "  if (!Array.isArray(spans)) return null;",
        ["a preview with more spans than the model allows is not shown", "the previews follow the documents page rules"],
    ),
    (
        "the list item cap is not checked",
        "      if (!Array.isArray(block.items) || block.items.length > MAX_ITEMS) return null;",
        "      if (!Array.isArray(block.items)) return null;",
        ["a preview with more list items than the model allows is not shown", "the previews follow the documents page rules"],
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
        ["a refused archive is shown with its reason and lists no entry",
         "a refused archive without a reason still says why"],
    ),
    (
        "an empty refusal reason stays empty",
        '    refused = { message: reason.trim() ? reason : "This archive could not be read." };',
        "    refused = { message: reason };",
        ["a refused archive without a reason still says why",
         "a refused archive with a blank reason still says why"],
    ),
    (
        "an unknown block kind is drawn",
        "    default:\n      return null;",
        '    default:\n      return { kind: "rule" };',
        ["an unreadable entry or preview is not shown, and the rest are"],
    ),
    (
        "the view schema is not checked",
        '  if (!value || typeof value !== "object" || own(value, "schema") !== VIEW_SCHEMA) {',
        '  if (!value || typeof value !== "object") {',
        ["views that are not ones are refused", "a view that is not one is not drawn"],
    ),
    (
        "any number of entries is taken",
        "  if (Array.isArray(entriesIn) ? entriesIn.length > MAX_ENTRIES : entriesIn !== undefined) {",
        "  if (false) {",
        ["views that are not ones are refused"],
    ),
    (
        "any number of previews is taken",
        "  if (Array.isArray(previewsIn) ? previewsIn.length > MAX_PREVIEWS : previewsIn !== undefined) {",
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
        "a text is not cut short",
        "  return text.length > chars ?",
        "  return false && text.length > chars ?",
        ["a refusal is shown as its text"],
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
        '    path: cut(own(entry, "path"), MAX_TEXT_CHARS, ""),',
        '    uri: own(entry, "uri"),\n    path: cut(own(entry, "path"), MAX_TEXT_CHARS, ""),',
        ["it never requests an entry"],
    ),
]


def test_fails(name):
    return kit.node_test_fails(TESTS, name)


def main():
    cases = [(name, PAGE, [(old, new)], tests) for name, old, new, tests in CASES]
    kit.main([(cases, None, test_fails, None, True)], done=f"all {len(CASES)} surface falsifiers caught")


if __name__ == "__main__":
    main()
