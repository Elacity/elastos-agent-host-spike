#!/usr/bin/env python3
"""Break each refusal, see its test fail, restore it.

Usage: python3 -I falsify.py [--runtime] [--check] [name-part ...]
       --runtime  also rebuild the component once per runtime falsifier and
                  run host-test
       --check    only confirm every anchor occurs exactly once

Each falsifier replaces one exact text, requires the mutant to compile, runs
the named tests, and requires them to FAIL. The file is restored from its
saved bytes afterwards, also on error or Ctrl-C. The script exits non-zero if
any falsifier is not caught or its text is not found exactly once.

Copied from examples/photo-viewer/falsify.py, with two changes: a test names
its package (the core or the model), and --check and name filters.
"""
import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent

# (name, file, exact old text, new text, [(package, test name)])
# package "core" is the docs-viewer guest, "model" is docs-model.
GUEST = [
    # Authority failures stop the run.
    (
        "shelf read without a grant",
        "src/lib.rs",
        'let shelf_grant = grant(bus, SHELF_URI, "read", "read the shelf to show")?;',
        'let shelf_grant = grant(bus, SHELF_URI, "read", "read the shelf to show").unwrap_or_default();',
        [("core", "shelf_without_a_read_grant_stops_before_any_read")],
    ),
    (
        "document read without a grant",
        "src/lib.rs",
        'let item_grant = grant(bus, uri, "read", "read a document on the shelf")?;',
        'let item_grant = grant(bus, uri, "read", "read a document on the shelf").unwrap_or_default();',
        [("core", "document_without_a_read_grant_stops_the_run_and_is_not_skipped")],
    ),
    (
        "pages write without a grant",
        "src/lib.rs",
        'let write_grant = grant(bus, PAGES_URI, "write", "write the checked pages")?;',
        'let write_grant = grant(bus, PAGES_URI, "write", "write the checked pages").unwrap_or_default();',
        [("core", "pages_without_a_write_grant_stops_and_is_not_written")],
    ),
    (
        "provider error on a head read skipped instead of stopping",
        "src/lib.rs",
        "let head = read_at(bus, uri, &item_grant, 0, HEAD_BYTES)?;",
        "let head = read_at(bus, uri, &item_grant, 0, HEAD_BYTES).unwrap_or_default();",
        [("core", "a_provider_error_stops_the_run_and_is_not_skipped")],
    ),
    (
        "provider status ignored",
        "src/bus.rs",
        'Some("ok") if parsed.has_data => Ok(parsed),',
        '_ if parsed.has_data => Ok(parsed),',
        [("core", "an_error_answer_that_also_carries_data_is_still_an_error")],
    ),
    (
        "a read answer longer than asked is taken",
        "src/bus.rs",
        "    if content.len() as u64 > length {",
        "    if false && content.len() as u64 > length {",
        [("core", "a_read_answer_longer_than_asked_is_refused")],
    ),
    (
        "unknown shelf fields allowed",
        "src/shelf.rs",
        '.find(|key| !matches!(key.as_str(), "schema" | "items"))',
        '.find(|key| !matches!(key.as_str(), "schema" | "items" | "x"))',
        [("core", "malformed_shelves_stop_before_any_document_is_read")],
    ),
    (
        "dot-dot segments allowed",
        "src/shelf.rs",
        '.any(|part| part.is_empty() || part == "." || part == "..")',
        '.any(|part| part.is_empty() || part == ".")',
        [("core", "malformed_shelves_stop_before_any_document_is_read")],
    ),
    # Content failures skip the document.
    (
        "content failure stops the run instead of skipping",
        "src/lib.rs",
        "match check_item(bus, order, uri, &mut budget)? {",
        "match check_item(bus, order, uri, &mut budget)?.map_err(|_| Refusal::ShelfTooLarge).map(Ok)? {",
        [("core", "content_failures_are_skipped_and_listed_and_the_rest_are_shown_in_order")],
    ),
    (
        "a name that is not a document is read as text",
        "src/lib.rs",
        "let Some(kind) = Kind::from_name(uri) else {",
        "let Some(kind) = Kind::from_name(uri).or(Some(Kind::Text)) else {",
        [("core", "content_failures_are_skipped_and_listed_and_the_rest_are_shown_in_order")],
    ),
    (
        "the head is not checked before reading on",
        "src/lib.rs",
        "if let Err(err) = text::check_head(&head, more) {",
        "if let (false, Err(err)) = (true, text::check_head(&head, more)) {",
        [("core", "a_binary_head_and_an_oversize_document_are_found_without_reading_the_body")],
    ),
    (
        "oversize found by reading the body",
        "src/lib.rs",
        "if !read_at(bus, uri, &item_grant, MAX_DOCUMENT_BYTES, 1)?.is_empty() {",
        "if false && !read_at(bus, uri, &item_grant, MAX_DOCUMENT_BYTES, 1)?.is_empty() {",
        [("core", "a_binary_head_and_an_oversize_document_are_found_without_reading_the_body")],
    ),
    (
        "the shelf budget is found by reading the body",
        "src/lib.rs",
        "if left < MAX_DOCUMENT_BYTES && !read_at(bus, uri, &item_grant, left, 1)?.is_empty() {",
        "if false && !read_at(bus, uri, &item_grant, left, 1)?.is_empty() {",
        [("core", "a_shelf_stops_taking_documents_at_its_budget_without_reading_the_one_that_would_pass_it")],
    ),
    (
        "a document read in full does not count toward the budget",
        "src/lib.rs",
        "    budget.read -= bytes.len() as u64;",
        "    let _ = bytes.len();",
        [
            ("core", "a_shelf_stops_taking_documents_at_its_budget_without_reading_the_one_that_would_pass_it"),
            ("core", "a_document_skipped_after_it_was_read_still_counts_toward_the_shelf_budget"),
        ],
    ),
    (
        "the whole document is not checked as text",
        "src/lib.rs",
        "let text = match text::check_whole(&bytes) {",
        "let text = match Ok::<&str, TextError>(std::str::from_utf8(&bytes).unwrap_or(\"\")) {",
        [("core", "content_failures_are_skipped_and_listed_and_the_rest_are_shown_in_order")],
    ),
    (
        "a document that is too long is shown empty",
        "src/lib.rs",
        "Err(ModelError::TooLong) => return Ok(Err(Skip::TooLong)),",
        "Err(ModelError::TooLong) => Vec::new(),",
        [("core", "content_failures_are_skipped_and_listed_and_the_rest_are_shown_in_order")],
    ),
    (
        "a shelf may show more than its cap",
        "src/lib.rs",
        "    if size > budget.shown {",
        "    if false && size > budget.shown {",
        [("core", "a_document_that_renders_past_what_a_shelf_may_show_is_skipped")],
    ),
    (
        "the write body does not say append",
        "src/bus.rs",
        'body.push_str(r#"{"append":false,"content":["#);',
        'body.push_str(r#"{"content":["#);',
        [("core", "the_write_body_is_the_json_the_provider_takes"), ("core", "a_shelf_is_read_and_its_pages_are_written")],
    ),
    # The model: what counts as text, and what a block may hold.
    (
        "control characters count as text",
        "model/src/text.rs",
        "!c.is_control() || matches!(c, '\\t' | '\\n' | '\\r')",
        "!c.is_control() || matches!(c, '\\t' | '\\n' | '\\r' | '\\0')",
        [("model", "text_is_utf8_with_no_control_character_but_tab_and_line_ends")],
    ),
    (
        "a UTF-16 head is read as UTF-8",
        "model/src/text.rs",
        "    if other_encoding(head) {",
        "    if false && other_encoding(head) {",
        [("model", "a_head_may_end_inside_a_character_only_if_the_document_goes_on")],
    ),
    (
        "a head may end inside a character when the document does not go on",
        "model/src/text.rs",
        "Err(err) if more && err.error_len().is_none() => {",
        "Err(err) if err.error_len().is_none() => {",
        [("model", "a_head_may_end_inside_a_character_only_if_the_document_goes_on")],
    ),
    (
        "no cap on blocks",
        "model/src/lib.rs",
        "    if blocks.len() >= MAX_BLOCKS {",
        "    if false && blocks.len() >= MAX_BLOCKS {",
        [("model", "too_many_blocks_spans_or_items_is_too_long")],
    ),
    (
        "no cap on spans",
        "model/src/markdown.rs",
        "        if self.spans.len() >= MAX_SPANS {",
        "        if false && self.spans.len() >= MAX_SPANS {",
        [("model", "too_many_blocks_spans_or_items_is_too_long")],
    ),
    (
        "an image keeps its source",
        "model/src/markdown.rs",
        'spans.plain_str(&format!("[image: {label}]"));',
        'spans.plain_str(&format!("[image: {label}]({})", "src"));',
        [("model", "links_and_images_become_text_and_html_stays_text")],
    ),
]

RUNTIME = [
    (
        "a name that is not a document is read (in the component)",
        "src/lib.rs",
        "let Some(kind) = Kind::from_name(uri) else {",
        "let Some(kind) = Kind::from_name(uri).or(Some(Kind::Text)) else {",
        ["content_failures_are_skipped_and_listed_through_the_runtime"],
    ),
    (
        "document read without a grant (in the component)",
        "src/lib.rs",
        'let item_grant = grant(bus, uri, "read", "read a document on the shelf")?;',
        'let item_grant = grant(bus, uri, "read", "read a document on the shelf").unwrap_or_default();',
        ["no_grant_stops_the_run_through_the_runtime"],
    ),
    (
        "pages written as a string (in the component)",
        "src/lib.rs",
        "    bus::write_bytes(bus, PAGES_URI, &write_grant, text.as_bytes()).map_err(|error| {",
        "    bus::write_string(bus, PAGES_URI, &write_grant, &text).map_err(|error| {",
        ["a_shelf_is_shown_and_its_pages_are_written"],
    ),
    (
        "a closer is found by scanning, not by the index (in the component)",
        "model/src/markdown.rs",
        "        let close = Index::at(&self.next_bracket, start + 1);",
        "        let close = (start + 1..self.len).find(|&i| chars[i] == ']').unwrap_or(self.len);",
        ["worst_case_shelves_stay_under_80_percent_of_the_runtime_fuel"],
    ),
]

# The string write the "pages written as a string" mutant calls; it exists
# only while that mutant is in place.
WRITE_STRING = '''
pub fn write_string(bus: &mut dyn Bus, uri: &str, grant: &str, content: &str) -> Result<(), CallError> {
    let body = serde_json::json!({ "path": uri, "content": content }).to_string();
    let reply = bus.invoke(uri, "write", body.as_bytes(), grant).map_err(CallError::Bus)?;
    ok_reply(&reply).map(|_| ())
}
'''


def env():
    environment = dict(os.environ)
    environment.setdefault("RUST_TEST_THREADS", "2")
    return environment


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, env=env(), capture_output=True, text=True)


def guest_tests_fail(tests):
    # A mutant that does not compile proves nothing.
    build = run(["cargo", "test", "--locked", "--workspace", "--lib", "--no-run"], HERE)
    if build.returncode != 0:
        print(build.stderr[-2000:])
        raise SystemExit("a falsifier does not compile")
    for package, name in tests:
        crate = {"core": "docs-viewer", "model": "docs-model"}[package]
        result = run(
            ["cargo", "test", "--locked", "-p", crate, "--lib", "--", "--exact", f"tests::{name}"], HERE
        )
        if "1 passed" not in result.stdout and "1 failed" not in result.stdout:
            raise SystemExit(f"no test {crate} tests::{name}\n{result.stdout[-1500:]}")
        if result.returncode == 0:
            return False
    return True


def runtime_tests_fail(tests):
    build = run([str(HERE / "build.sh")], HERE)
    if build.returncode != 0:
        print(build.stderr[-2000:])
        raise SystemExit("component build failed under a falsifier")
    for name in tests:
        result = run(
            ["cargo", "test", "--locked", "--test", "component", "--", "--exact", name],
            HERE / "host-test",
        )
        if "1 passed" not in result.stdout and "1 failed" not in result.stdout:
            raise SystemExit(f"no host test {name}\n{result.stdout[-1500:]}")
        if result.returncode == 0:
            return False
    return True


def check(cases):
    for name, relative, old, _new, _tests in cases:
        text = (HERE / relative).read_text()
        if text.count(old) != 1:
            raise SystemExit(f"{name}: expected the text once in {relative}, found {text.count(old)}")


def falsify(cases, failing, parts):
    missed = []
    for name, relative, old, new, tests in cases:
        if parts and not any(part in name for part in parts):
            continue
        path = HERE / relative
        saved = path.read_bytes()
        bus = HERE / "src/bus.rs"
        saved_bus = bus.read_bytes()
        try:
            path.write_text(saved.decode().replace(old, new))
            if "write_string" in new:
                bus.write_text(bus.read_text() + WRITE_STRING)
            caught = failing(tests)
        finally:
            path.write_bytes(saved)
            bus.write_bytes(saved_bus)
        print(f"{'caught' if caught else 'MISSED'}: {name}", flush=True)
        if not caught:
            missed.append(name)
    return missed


def main():
    args = sys.argv[1:]
    parts = [arg for arg in args if not arg.startswith("--")]
    check(GUEST)
    check(RUNTIME)
    if "--check" in args:
        print(f"all {len(GUEST) + len(RUNTIME)} anchors found once")
        return
    missed = falsify(GUEST, guest_tests_fail, parts)
    if "--runtime" in args:
        try:
            missed += falsify(RUNTIME, runtime_tests_fail, parts)
        finally:
            # Leave the unmutated component in place.
            if run([str(HERE / "build.sh")], HERE).returncode != 0:
                raise SystemExit("restoring the component build failed")
    if missed:
        raise SystemExit(f"{len(missed)} falsifier(s) not caught: {missed}")
    print("all falsifiers caught")


if __name__ == "__main__":
    main()
