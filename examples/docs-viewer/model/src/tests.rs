use crate::markdown::{inline, parse};
use crate::text::{check_head, check_whole, TextError};
use crate::*;

fn plain(text: &str) -> Span {
    Span::plain(text)
}

fn styled(style: Style, text: &str) -> Span {
    Span {
        style,
        text: text.into(),
    }
}

fn para(text: &str) -> Block {
    Block::Paragraph {
        spans: vec![plain(text)],
    }
}

#[test]
fn text_is_utf8_with_no_control_character_but_tab_and_line_ends() {
    assert_eq!(check_whole(b"a\tb\r\nc\n"), Ok("a\tb\r\nc\n"));
    assert_eq!(
        check_whole("caf\u{e9} \u{1f600}".as_bytes()),
        Ok("caf\u{e9} \u{1f600}")
    );
    assert_eq!(
        check_whole(b"\xEF\xBB\xBFtitle"),
        Ok("title"),
        "a UTF-8 BOM goes"
    );
    assert_eq!(check_whole(b"a\0b"), Err(TextError::Control));
    assert_eq!(check_whole(b"a\x1bb"), Err(TextError::Control), "escape");
    assert_eq!(check_whole(b"a\x0cb"), Err(TextError::Control), "form feed");
    assert_eq!(
        check_whole("a\u{85}b".as_bytes()),
        Err(TextError::Control),
        "C1"
    );
    assert_eq!(check_whole(b"a\xffb"), Err(TextError::NotUtf8));
    assert_eq!(check_whole(b"\xFF\xFEa\0"), Err(TextError::OtherEncoding));
    assert_eq!(check_whole(b"\xFE\xFF\0a"), Err(TextError::OtherEncoding));
    assert_eq!(
        check_whole(b"\x00\x00\xFE\xFF"),
        Err(TextError::OtherEncoding)
    );
}

#[test]
fn a_head_may_end_inside_a_character_only_if_the_document_goes_on() {
    let text = "ab\u{e9}".as_bytes();
    let cut = &text[..text.len() - 1];
    assert_eq!(check_head(cut, true), Ok(()));
    assert_eq!(check_head(cut, false), Err(TextError::NotUtf8));
    assert_eq!(
        check_head(b"a\xffb", true),
        Err(TextError::NotUtf8),
        "bad in the middle"
    );
    assert_eq!(check_head(b"ab\0", true), Err(TextError::Control));
    assert_eq!(
        check_head(b"\xFF\xFEa", true),
        Err(TextError::OtherEncoding)
    );
}

#[test]
fn the_kind_comes_from_the_name() {
    assert_eq!(Kind::from_name("Notes.MD"), Some(Kind::Markdown));
    assert_eq!(Kind::from_name("a.markdown"), Some(Kind::Markdown));
    assert_eq!(Kind::from_name("a.txt"), Some(Kind::Text));
    assert_eq!(Kind::from_name("a.html"), None);
    assert_eq!(Kind::from_name("a.md.exe"), None);
    assert_eq!(Kind::from_name("md"), None);
}

#[test]
fn markdown_blocks() {
    let doc = "# Title #\n\nFirst line\nsecond line.\n\n## Sub\n\n- one\n- two\n  more\n\n1. a\n2) b\n\n> quoted\n> on\n\n---\n\n```rust\nfn x() {}\n\n# not a heading\n```\n\nSetext\n===\n";
    assert_eq!(
        parse(doc).unwrap(),
        vec![
            Block::Heading {
                level: 1,
                spans: vec![plain("Title")]
            },
            para("First line second line."),
            Block::Heading {
                level: 2,
                spans: vec![plain("Sub")]
            },
            Block::List {
                ordered: false,
                items: vec![vec![plain("one")], vec![plain("two more")]]
            },
            Block::List {
                ordered: true,
                items: vec![vec![plain("a")], vec![plain("b")]]
            },
            Block::Quote {
                spans: vec![plain("quoted on")]
            },
            Block::Rule,
            Block::Code {
                text: "fn x() {}\n\n# not a heading".into()
            },
            Block::Heading {
                level: 1,
                spans: vec![plain("Setext")]
            },
        ]
    );
}

#[test]
fn an_unclosed_fence_runs_to_the_end_and_a_heading_needs_a_space() {
    assert_eq!(
        parse("~~~\nkept\n").unwrap(),
        vec![Block::Code {
            text: "kept".into()
        }]
    );
    assert_eq!(parse("#tag").unwrap(), vec![para("#tag")]);
    assert_eq!(parse("####### seven").unwrap(), vec![para("####### seven")]);
}

#[test]
fn inline_styles_do_not_nest() {
    assert_eq!(
        inline("a **b** *c* `d` __e__ _f_").unwrap(),
        vec![
            plain("a "),
            styled(Style::Strong, "b"),
            plain(" "),
            styled(Style::Em, "c"),
            plain(" "),
            styled(Style::Code, "d"),
            plain(" "),
            styled(Style::Strong, "e"),
            plain(" "),
            styled(Style::Em, "f"),
        ]
    );
    assert_eq!(
        inline("`**not bold**`").unwrap(),
        vec![styled(Style::Code, "**not bold**")]
    );
    assert_eq!(
        inline("snake_case_name").unwrap(),
        vec![plain("snake_case_name")]
    );
    assert_eq!(inline("2 * 3 * 4").unwrap(), vec![plain("2 * 3 * 4")]);
    assert_eq!(inline(r"\*literal\*").unwrap(), vec![plain("*literal*")]);
    assert_eq!(inline("**open").unwrap(), vec![plain("**open")]);
}

#[test]
fn links_and_images_become_text_and_html_stays_text() {
    assert_eq!(
        inline("see [the docs](https://example.com/a) now").unwrap(),
        vec![plain("see the docs (https://example.com/a) now")]
    );
    assert_eq!(
        inline("![a cat](cat.png)").unwrap(),
        vec![plain("[image: a cat]")]
    );
    assert_eq!(
        inline("<https://example.com>").unwrap(),
        vec![plain("https://example.com")]
    );
    let hostile = r#"<img src=x onerror="alert(1)"><script>alert(2)</script>"#;
    assert_eq!(inline(hostile).unwrap(), vec![plain(hostile)]);
    assert_eq!(
        parse("[x](javascript:alert(1))").unwrap(),
        vec![para("x (javascript:alert(1))")],
        "a target is only ever text"
    );
}

#[test]
fn plain_text_keeps_its_lines() {
    assert_eq!(
        blocks(Kind::Text, "# not markdown\nline two\n\n\npara two  \n").unwrap(),
        vec![para("# not markdown\nline two"), para("para two")]
    );
}

#[test]
fn too_many_blocks_spans_or_items_is_too_long() {
    let many = "x\n\n".repeat(MAX_BLOCKS + 1);
    assert_eq!(parse(&many), Err(ModelError::TooLong));
    assert_eq!(
        parse(&"x\n\n".repeat(MAX_BLOCKS)).unwrap().len(),
        MAX_BLOCKS
    );
    let spans = "`a` ".repeat(MAX_SPANS);
    assert_eq!(inline(&spans), Err(ModelError::TooLong));
    let items = "- a\n".repeat(MAX_LIST_ITEMS + 1);
    assert_eq!(parse(&items), Err(ModelError::TooLong));
}

#[test]
fn the_title_is_the_first_heading_or_line_cut_short() {
    let doc = parse("intro line\nmore\n\n## Real title").unwrap();
    assert_eq!(title(&doc, "x.md"), "Real title");
    assert_eq!(title(&parse("intro line").unwrap(), "x.md"), "intro line");
    assert_eq!(title(&[], "x.md"), "x.md");
    let long = "y".repeat(MAX_TITLE_CHARS + 5);
    let cut = title(&parse(&format!("# {long}")).unwrap(), "x.md");
    assert_eq!(cut.chars().count(), MAX_TITLE_CHARS + 1);
    assert!(cut.ends_with('…'));
}

#[test]
fn blocks_as_json_have_one_shape_each() {
    let json = block_json(&Block::List {
        ordered: true,
        items: vec![vec![styled(Style::Code, "a")]],
    });
    assert_eq!(
        json.to_string(),
        r#"{"items":[[{"style":"code","text":"a"}]],"kind":"list","ordered":true}"#
    );
    assert_eq!(block_json(&Block::Rule).to_string(), r#"{"kind":"rule"}"#);
}

#[test]
fn openers_that_never_close_stay_text() {
    for hostile in [
        "*a ".repeat(2000),
        "_a ".repeat(2000),
        "**a ".repeat(2000),
        "[".repeat(5000),
        "[a](".repeat(2000),
        "<a".repeat(3000),
        "<ab:".repeat(2000),
        // Runs of backticks of distinct lengths: none closes another.
        (1..120).map(|n| format!("{} x ", "`".repeat(n))).collect(),
    ] {
        let spans = inline(&hostile).unwrap();
        let text: String = spans.iter().map(|span| span.text.as_str()).collect();
        assert_eq!(text, hostile, "nothing is lost or added");
        assert!(
            spans.iter().all(|span| span.style == Style::Plain),
            "{}",
            &hostile[..12]
        );
    }
}

#[test]
fn write_block_writes_the_same_bytes_as_block_json() {
    let doc = "# H \"q\" \\ \t\n\npara *em* **st** `co\u{1}de`\n\n- a\n- b\n\n1. c\n\n> q\n\n---\n\n```\nx\ty\n```\n";
    for block in parse(doc).unwrap() {
        let mut out = Vec::new();
        write_block(&mut out, &block);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            block_json(&block).to_string()
        );
    }
}
