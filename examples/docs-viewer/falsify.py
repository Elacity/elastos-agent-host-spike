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
        "let head = read_counted(bus, uri, &item_grant, &mut budget.read, 0, ask)?;",
        "let head = read_counted(bus, uri, &item_grant, &mut budget.read, 0, ask).unwrap_or_default();",
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
        "        if !past.is_empty() {\n            return Ok(Err(Skip::Oversize));",
        "        if false && !past.is_empty() {\n            return Ok(Err(Skip::Oversize));",
        [("core", "a_binary_head_and_an_oversize_document_are_found_without_reading_the_body")],
    ),
    (
        "the shelf budget is found by reading the body",
        "src/lib.rs",
        "        if left < MAX_DOCUMENT_BYTES {",
        "        if false {",
        [("core", "a_document_skipped_after_it_was_read_still_counts_toward_the_shelf_budget")],
    ),
    (
        "a document read in full does not count toward the budget",
        "src/lib.rs",
        "&mut budget.read, offset, ask)?;",
        "&mut { u64::MAX }, offset, ask)?;",
        [
            ("core", "a_shelf_stops_taking_documents_at_its_budget_without_reading_the_one_that_would_pass_it"),
            ("core", "a_document_skipped_after_it_was_read_still_counts_toward_the_shelf_budget"),
        ],
    ),
    (
        "a head is not counted toward the budget",
        "src/lib.rs",
        "&mut budget.read, 0, ask)?;",
        "&mut { u64::MAX }, 0, ask)?;",
        [
            ("core", "a_short_document_that_is_not_text_still_counts_toward_the_shelf_budget"),
            ("core", "no_shelf_reads_more_than_its_budget"),
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
        "    if size > budget.written {",
        "    if false && size > budget.written {",
        [("core", "a_document_that_renders_past_what_a_shelf_may_show_is_skipped")],
    ),
    (
        "the pages cap counts only the blocks",
        "src/lib.rs",
        "    let size = entry.len() as u64 + 1;",
        "    let size = rendered.len() as u64;",
        [
            ("core", "a_document_whose_blocks_fit_but_whose_pages_would_not_is_skipped"),
            ("core", "no_pages_are_longer_than_their_cap"),
        ],
    ),
    (
        "a skipped entry takes nothing from the pages",
        "src/lib.rs",
        "                budget.written -= entry.len() as u64 + 1;",
        "                let _ = entry.len();",
        [("core", "no_pages_are_longer_than_their_cap")],
    ),
    (
        "no room is held back for entries skipped later",
        "src/lib.rs",
        "        written: MAX_PAGES_BYTES.saturating_sub(frame + held.iter().sum::<u64>()),",
        "        written: MAX_PAGES_BYTES.saturating_sub(frame + held.iter().sum::<u64>()) + held.iter().sum::<u64>(),",
        [("core", "no_pages_are_longer_than_their_cap")],
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

# The bundle: what this app adds to the bundle tool (whose own checks have
# their falsifiers in examples/photo-viewer/falsify-bundle.py).
BUNDLE = [
    (
        "the page ships its whole source folder",
        "bundle-test/tests/bundle.rs",
        "        let folder = Path::new(&entrypoint).parent().unwrap();",
        '        let folder = Path::new("");',
        ["each_capsule_ships_only_what_it_runs_from"],
    ),
    (
        "the surface ships without its core's CID",
        "bundle-test/tests/bundle.rs",
        '            requirement["cid"] = json!(cid);',
        "            let _ = cid;",
        ["the_surface_names_its_core_by_cid_and_nothing_else_selects_it"],
    ),
]

# The Bus v2 reader (bus2/), in the Bus v2 proof's stub host.
BUS2 = [
    (
        "the reader does not count what arrives",
        "bus2/guests/docs/src/lib.rs",
        "        if bytes.len() + chunk.len() > MAX_DOCUMENT_BYTES {",
        "        if false && bytes.len() + chunk.len() > MAX_DOCUMENT_BYTES {",
        ["the_reader_refuses_more_bytes_than_it_asked_for_even_if_they_arrive"],
    ),
    (
        "the reader uses the bytes before the trailing future",
        "bus2/guests/docs/src/lib.rs",
        "    match trailer.await {",
        "    let _ = trailer;\n    match Ok::<(), BusError>(()) {",
        ["nothing_partial_is_shown_when_a_read_fails_at_the_end"],
    ),
    (
        "a refused grant is shown as a frame instead of ending the run",
        "bus2/guests/docs/src/lib.rs",
        "    let bytes = match read_document(uri).await? {",
        "    let bytes = match read_document(uri).await.unwrap_or_else(|e| Err(reason(&e))) {",
        ["a_refused_grant_ends_the_run_with_its_reason"],
    ),
    (
        "a frame is not cut to what a frame holds",
        "bus2/guests/docs/src/lib.rs",
        "        if nodes.len() == MAX_NODES - 1 || size + node_size + RESERVE > MAX_FRAME_BYTES {",
        "        if false {",
        ["a_long_document_is_cut_to_one_frame_and_the_frame_says_so"],
    ),
    (
        "text in a frame is not escaped",
        "bus2/guests/docs/src/lib.rs",
        "        docs_model::write_str(&mut out, node);",
        r'        out.extend_from_slice(format!("\"{node}\"").as_bytes());',
        ["markup_in_a_document_is_text_in_the_frame"],
    ),
    (
        "the reader keeps running after its events close",
        "bus2/guests/docs/src/lib.rs",
        "        Ok(())\n    }\n}\n\nexport!(Reader);",
        "        loop {\n            core::hint::black_box(0u8);\n        }\n    }\n}\n\nexport!(Reader);",
        ["a_resident_reader_shows_each_document_it_is_sent_and_stops_when_its_events_close"],
    ),
    (
        "the reader reads a name that is not a document",
        "bus2/guests/docs/src/lib.rs",
        "    let Some(kind) = Kind::from_name(uri) else {",
        "    let Some(kind) = Kind::from_name(uri).or(Some(Kind::Text)) else {",
        ["a_document_not_shown_gets_a_frame_that_says_so_and_the_reader_goes_on"],
    ),
]

BUS2_GUESTS = ["-p", "docs-bus2-guest", "-p", "docs-bus2-busy-guest"]

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


def bundle_tests_fail(tests):
    for name in tests:
        result = run(
            ["cargo", "test", "--locked", "--test", "bundle", "--", "--exact", name],
            HERE / "bundle-test",
        )
        if "1 passed" not in result.stdout and "1 failed" not in result.stdout:
            raise SystemExit(f"no bundle test {name}\n{result.stdout[-1500:]}{result.stderr[-1500:]}")
        if result.returncode == 0:
            return False
    return True


def build_bus2_guests():
    # From bus2/, so rustup picks its toolchain (Rust 1.95.0).
    return run(
        ["cargo", "build", "--locked", "--release", "--target", "wasm32-unknown-unknown", *BUS2_GUESTS],
        HERE / "bus2",
    )


def bus2_tests_fail(tests):
    build = build_bus2_guests()
    if build.returncode != 0:
        print(build.stderr[-2000:])
        raise SystemExit("a Bus v2 falsifier does not compile")
    for name in tests:
        result = run(
            ["cargo", "test", "--locked", "-p", "docs-bus2-host-test", "--test", "docs", "--", "--exact", name],
            HERE / "bus2",
        )
        if "1 passed" not in result.stdout and "1 failed" not in result.stdout:
            raise SystemExit(f"no Bus v2 test {name}\n{result.stdout[-1500:]}{result.stderr[-1500:]}")
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
    check(BUNDLE)
    check(BUS2)
    if "--check" in args:
        print(f"all {len(GUEST) + len(RUNTIME) + len(BUNDLE) + len(BUS2)} anchors found once")
        return
    missed = falsify(GUEST, guest_tests_fail, parts)
    missed += falsify(BUNDLE, bundle_tests_fail, parts)
    try:
        missed += falsify(BUS2, bus2_tests_fail, parts)
    finally:
        # Leave the unmutated guests in place.
        if build_bus2_guests().returncode != 0:
            raise SystemExit("restoring the Bus v2 guest build failed")
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
