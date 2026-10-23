#!/usr/bin/env python3
"""Break each check of the capsule kit's guest crate, see its test fail, restore it.

Usage: RUST_TEST_THREADS=2 python3 -I falsify.py [--check] [name-part ...]

Each falsifier replaces exact text in one file under src/ (it must occur
once), rebuilds the tests (a mutant that does not compile proves nothing, so
the run stops), runs every named test, and requires every one to FAIL. The
file is restored from its saved bytes afterwards, also on error or Ctrl-C.
The runner is the kit's own (examples/capsule-kit/falsify).

The photo and documents viewers also break this crate's code in their own
falsify scripts, where their own tests must notice (the image checks, the
URI check, the write).
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "falsify"))
import falsify_kit as kit  # noqa: E402

# (name, file under src/, exact old text, new text, tests that must fail)
CASES = [
    # The Bus answers.
    ("provider status ignored", "bus.rs",
     'Some("ok") if parsed.has_data => Ok(parsed),',
     '_ if parsed.has_data => Ok(parsed),',
     ["an_error_answer_that_also_carries_data_is_still_an_error"]),
    ("a read answer longer than asked is taken", "bus.rs",
     "    if content.len() as u64 > length {",
     "    if false && content.len() as u64 > length {",
     ["a_read_answer_longer_than_asked_is_refused"]),
    ("an answer with no data is taken", "bus.rs",
     'Some("ok") => Err(CallError::Shape("provider answer has no data".into())),',
     'Some("ok") => Ok(parsed),',
     ["a_write_answer_without_data_is_refused"]),
    # The write.
    ("the write does not say append", "bus.rs",
     'body.push_str(r#"{"append":false,"content":["#);',
     'body.push_str(r#"{"content":["#);',
     ["the_write_body_is_the_json_the_provider_takes", "the_write_is_one_byte_array_with_append_false"]),
    ("the write drops a digit of 100", "bus.rs",
     "        if *byte >= 100 {",
     "        if *byte > 100 {",
     ["the_write_body_is_the_json_the_provider_takes"]),
    # The refusals and their bus-error.
    ("a refused grant is not denied", "read.rs",
     "            Refusal::NoGrant { .. } => BusFailure::Denied(message),",
     "            Refusal::NoGrant { .. } => BusFailure::Internal(message),",
     ["every_refusal_names_the_app_and_maps_to_its_bus_error"]),
    ("a malformed answer is invalid, not internal", "read.rs",
     "                CallError::Bus(BusFailure::Internal(_)) | CallError::Shape(_) => {\n                    BusFailure::Internal(message)",
     "                CallError::Bus(BusFailure::Internal(_)) | CallError::Shape(_) => {\n                    BusFailure::Invalid(message)",
     ["every_refusal_names_the_app_and_maps_to_its_bus_error", "an_answer_without_byte_content_stops_the_run"]),
    ("a refusal does not name its app", "read.rs",
     "        let name = app.name;",
     '        let name = "app";',
     ["every_refusal_names_the_app_and_maps_to_its_bus_error"]),
    ("a refused grant is taken as granted", "read.rs",
     "    bus.request(resource, action, reason)\n        .map_err(",
     "    bus.request(resource, action, reason)\n        .or_else(|_| Ok::<String, BusFailure>(String::new()))\n        .map_err(",
     ["a_refused_grant_is_no_grant_for_that_resource"]),
    # The reads.
    ("a bounded read refuses an exact fit", "read.rs",
     "        if bytes.len() as u64 > limit {",
     "        if bytes.len() as u64 >= limit {",
     ["a_bounded_read_takes_an_exact_fit_and_refuses_one_byte_more"]),
    ("a bounded read starts again from the start", "read.rs",
     "        let chunk = read_at(bus, uri, grant, offset, ask)?;",
     "        let chunk = read_at(bus, uri, grant, 0, ask)?;",
     ["a_bounded_read_goes_on_from_what_it_was_given"]),
    ("a counted read is not counted", "read.rs",
     "    *left -= bytes.len() as u64;",
     "    let _ = bytes.len();",
     ["a_counted_read_takes_what_it_returned_off_the_budget"]),
    ("a counted read takes what it asked for, not what came", "read.rs",
     "    *left -= bytes.len() as u64;",
     "    *left -= length;",
     ["a_counted_read_takes_what_it_returned_off_the_budget"]),
    ("a counted read may ask past what is left", "read.rs",
     '    assert!(length <= *left, "a read past what the run may read");\n',
     "",
     ["a_counted_read_never_asks_past_what_is_left"]),
    # The URI check.
    ("any prefix is taken", "uri.rs",
     "    let Some(relative) = uri.strip_prefix(prefix) else {",
     "    let Some(relative) = Some(uri) else {",
     ["an_input_uri_names_one_object_under_its_folder"]),
    ("dot-dot segments allowed", "uri.rs",
     '.any(|part| part.is_empty() || part == "." || part == "..")',
     '.any(|part| part.is_empty() || part == ".")',
     ["an_input_uri_names_one_object_under_its_folder"]),
    ("a query is allowed", "uri.rs",
     "if relative.contains(['?', '#', '\\\\'])",
     "if relative.contains(['#', '\\\\'])",
     ["an_input_uri_names_one_object_under_its_folder"]),
    # The text checks.
    ("control characters count as text", "text.rs",
     "!c.is_control() || matches!(c, '\\t' | '\\n' | '\\r')",
     "!c.is_control() || matches!(c, '\\t' | '\\n' | '\\r' | '\\0')",
     ["text_is_utf8_with_no_control_character_but_tab_and_line_ends"]),
    ("a UTF-16 head is read as UTF-8", "text.rs",
     "    if other_encoding(head) {",
     "    if false && other_encoding(head) {",
     ["a_head_may_end_inside_a_character_only_if_the_document_goes_on"]),
    ("a head may end inside a character when the document does not go on", "text.rs",
     "Err(err) if more && err.error_len().is_none() => {",
     "Err(err) if err.error_len().is_none() => {",
     ["a_head_may_end_inside_a_character_only_if_the_document_goes_on"]),
    # The fake Runtime checks bodies as the localhost provider does.
    ("the fake takes unknown fields", "fake.rs",
     "    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {",
     "    if let Some(key) = object.keys().find(|_| false) {",
     ["the_fake_refuses_bodies_the_localhost_provider_refuses"]),
]


def build():
    kit.cargo_compiles(HERE, ["--lib"])


def test_fails(name):
    return kit.cargo_test_fails(HERE, ["--lib"], f"tests::{name}")


def main():
    cases = [(name, HERE / "src" / relative, [(old, new)], tests) for name, relative, old, new, tests in CASES]
    kit.main([(cases, build, test_fails, None, True)], done=f"all {len(CASES)} kit guest falsifiers caught")


if __name__ == "__main__":
    main()
