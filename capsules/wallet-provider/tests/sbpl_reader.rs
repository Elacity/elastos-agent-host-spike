/// Shared fail-closed SBPL reader. Model, wallet, and did compile this file
/// through `include!`. Review extract.py still reads the same function text
/// from wallet and did `confine.rs`, so those copies must stay byte-identical
/// to this file's functions. No shipped `confine.sb` uses a `#\` character
/// literal; every `#\` form is refused. The grammar names only `#t`, `#f`,
/// and `#include` as hash tokens.
pub fn profile_holds_scheme_comment(profile: &str) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = profile_characters(profile);
    }))
    .is_err()
}

fn profile_characters(profile: &str) -> Vec<(char, bool)> {
    let mut characters = Vec::new();
    let mut chars = profile.chars().peekable();
    let mut in_string = false;
    let mut at_token_boundary = true;
    while let Some(ch) = chars.next() {
        let allowed = ch == '\t' || ch == '\n' || (ch >= ' ' && ch <= '~');
        assert!(
            allowed,
            "the profile must refuse a non-ASCII or format character: {profile}"
        );
        if in_string {
            if ch == '\\' {
                let Some(esc) = chars.next() else {
                    panic!("the profile must not end early: unclosed string in {profile}");
                };
                let esc_allowed = esc == '\\' || esc == '"' || esc == 'n' || esc == 't';
                assert!(
                    esc_allowed,
                    "the profile must refuse unknown string escape \\{esc}: {profile}"
                );
                characters.push(('\\', true));
                characters.push((esc, true));
                continue;
            }
            if ch == '"' {
                in_string = false;
                at_token_boundary = true;
                characters.push((ch, true));
                continue;
            }
            characters.push((ch, true));
            continue;
        }
        if ch == ';' {
            loop {
                match chars.peek().copied() {
                    None => break,
                    Some('\n') => {
                        let nl = chars.next().expect("peeked newline");
                        characters.push((nl, false));
                        at_token_boundary = true;
                        break;
                    }
                    Some(next) => {
                        let next_ok = next == '\t' || (next >= ' ' && next <= '~');
                        assert!(
                            next_ok,
                            "the profile must refuse a non-ASCII or format character: {profile}"
                        );
                        chars.next();
                    }
                }
            }
            continue;
        }
        if ch == '#' {
            if !at_token_boundary {
                panic!(
                    "the profile must refuse Scheme comment form #; or #| or other reader form: {profile}"
                );
            }
            if chars.peek() == Some(&'\\') {
                panic!("the profile must refuse a Scheme character literal #\\: {profile}");
            }
            let mut token = String::from("#");
            while let Some(&next) = chars.peek() {
                let symbol = next.is_ascii_alphanumeric()
                    || next == '*'
                    || next == '_'
                    || next == '-'
                    || next == '+'
                    || next == '.'
                    || next == '/'
                    || next == '%';
                if !symbol {
                    break;
                }
                token.push(chars.next().expect("peeked hash-token character"));
            }
            match token.as_str() {
                "#t" | "#f" | "#include" => {
                    for part in token.chars() {
                        characters.push((part, false));
                    }
                    at_token_boundary = false;
                    continue;
                }
                _ => {
                    panic!(
                        "the profile must refuse Scheme comment form #; or #| or other reader form: {profile}"
                    );
                }
            }
        }
        if ch == '"' {
            in_string = true;
            at_token_boundary = false;
            characters.push((ch, true));
            continue;
        }
        if ch == ' ' || ch == '\t' || ch == '\n' {
            characters.push((ch, false));
            at_token_boundary = true;
            continue;
        }
        if ch == '(' || ch == ')' {
            characters.push((ch, false));
            at_token_boundary = true;
            continue;
        }
        let symbol = ch.is_ascii_alphanumeric()
            || ch == '*'
            || ch == '_'
            || ch == '-'
            || ch == '+'
            || ch == '.'
            || ch == '/'
            || ch == '%';
        assert!(
            symbol,
            "the profile must refuse a character the grammar does not name {ch:?}: {profile}"
        );
        characters.push((ch, false));
        at_token_boundary = false;
    }
    assert!(
        !in_string,
        "the profile must not end early: unclosed string in {profile}"
    );
    characters
}

#[allow(dead_code)]
fn push_separator(current: &mut String) {
    if !current.is_empty() && !current.ends_with('(') {
        current.push(' ');
    }
}

#[allow(dead_code)]
fn profile_forms(profile: &str) -> Vec<String> {
    let mut forms = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut space_due = false;
    for (ch, in_string) in profile_characters(profile) {
        if in_string {
            if space_due {
                push_separator(&mut current);
            }
            space_due = false;
            current.push(ch);
            continue;
        }
        if depth == 0 && (ch.is_whitespace() || ch == '(') && !current.is_empty() {
            forms.push(std::mem::take(&mut current));
        }
        match ch {
            _ if ch.is_whitespace() => space_due = true,
            '(' | ')' => {
                if space_due {
                    push_separator(&mut current);
                }
                space_due = false;
                current.push(ch);
                if ch == '(' {
                    depth += 1;
                } else {
                    depth = depth.saturating_sub(1);
                    if depth == 0 && !current.is_empty() {
                        forms.push(std::mem::take(&mut current));
                    }
                }
            }
            _ => {
                if space_due {
                    push_separator(&mut current);
                }
                space_due = false;
                current.push(ch);
            }
        }
    }
    if depth == 0 && !current.is_empty() {
        forms.push(std::mem::take(&mut current));
    }
    assert!(
        current.is_empty(),
        "the profile must not end early: unclosed form {current}"
    );
    forms
}

#[test]
fn shared_sbpl_reader_refuses_every_hash_backslash_character_literal() {
    for extra in [
        r"#\;",
        r"#\; x (allow file*)",
        r#"#\; "x" (allow file*)"#,
        r"#\; 1 (allow file*)",
        r"#\;(allow file*)",
        r"#\;(version 0)(allow file*)",
    ] {
        assert!(
            profile_holds_scheme_comment(extra),
            "every #\\ character literal must be refused: {extra}"
        );
    }
}

#[test]
fn shared_sbpl_reader_refuses_non_ascii_inside_a_string() {
    assert!(
        profile_holds_scheme_comment("\"a\u{200b}b\""),
        "only the non-ASCII check refuses a zero-width space inside a string"
    );
}

#[test]
fn shared_sbpl_reader_refuses_unknown_string_escape() {
    assert!(
        profile_holds_scheme_comment(r#""foo\r""#),
        "an unknown string escape must be refused"
    );
}

#[test]
fn shared_sbpl_reader_refuses_carriage_return_inside_a_string() {
    assert!(
        profile_holds_scheme_comment("\"a\rb\""),
        "a carriage return inside a string must be refused"
    );
}

#[test]
fn shared_sbpl_reader_refuses_hash_mid_token() {
    assert!(
        profile_holds_scheme_comment("abc#t"),
        "a # after a symbol must be refused"
    );
}
