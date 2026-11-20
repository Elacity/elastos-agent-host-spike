//! A small markdown reader: enough for notes and READMEs, nothing that can
//! reach out.
//!
//! Blocks: ATX headings (`#` to `######`), setext headings (`===`, `---` under
//! a paragraph), paragraphs, fenced code (```` ``` ```` or `~~~`), block quotes
//! (`>`), flat lists (`-`, `*`, `+`, `1.`, `1)`), and rules (`---`, `***`,
//! `___`). Inline: code spans, strong (`**`, `__`), emphasis (`*`, `_`) and
//! backslash escapes. A link `[label](target)` keeps its label and shows its
//! target as text, `label (target)`; an image `![alt](src)` becomes the text
//! `[image: alt]`; an autolink `<scheme:...>` is text. HTML is text. Anything
//! else (tables, nested lists, indented code) is read as paragraph text.

use crate::{push, Block, ModelError, Span, Style, MAX_LIST_ITEMS, MAX_SPANS};

/// Parses a whole document.
pub fn parse(text: &str) -> Result<Vec<Block>, ModelError> {
    let mut parser = Parser::default();
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        index += 1;
        if let Some(fence) = fence_open(line) {
            parser.flush_all()?;
            let mut code = Vec::new();
            while index < lines.len() {
                let inner = lines[index];
                index += 1;
                if fence_closes(inner, fence) {
                    break;
                }
                code.push(inner);
            }
            parser.block(Block::Code {
                text: code.join("\n"),
            })?;
            continue;
        }
        parser.line(line)?;
    }
    parser.flush_all()?;
    Ok(parser.blocks)
}

#[derive(Default)]
struct Parser {
    blocks: Vec<Block>,
    paragraph: Vec<String>,
    quote: Vec<String>,
    /// An open list: ordered or not, and its items' source text.
    list: Option<(bool, Vec<String>)>,
    /// A blank line since the last list item.
    list_gap: bool,
}

impl Parser {
    fn block(&mut self, block: Block) -> Result<(), ModelError> {
        push(&mut self.blocks, block)
    }

    fn flush_paragraph(&mut self) -> Result<(), ModelError> {
        if self.paragraph.is_empty() {
            return Ok(());
        }
        let text = self.paragraph.join(" ");
        self.paragraph.clear();
        let spans = inline(&text)?;
        self.block(Block::Paragraph { spans })
    }

    fn flush_quote(&mut self) -> Result<(), ModelError> {
        if self.quote.is_empty() {
            return Ok(());
        }
        let text = self.quote.join(" ");
        self.quote.clear();
        let spans = inline(&text)?;
        self.block(Block::Quote { spans })
    }

    fn flush_list(&mut self) -> Result<(), ModelError> {
        self.list_gap = false;
        let Some((ordered, items)) = self.list.take() else {
            return Ok(());
        };
        let items = items
            .iter()
            .map(|item| inline(item))
            .collect::<Result<Vec<_>, _>>()?;
        self.block(Block::List { ordered, items })
    }

    fn flush_all(&mut self) -> Result<(), ModelError> {
        self.flush_paragraph()?;
        self.flush_quote()?;
        self.flush_list()
    }

    fn line(&mut self, line: &str) -> Result<(), ModelError> {
        if line.trim().is_empty() {
            self.flush_paragraph()?;
            self.flush_quote()?;
            if self.list.is_some() {
                self.list_gap = true;
            }
            return Ok(());
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();

        // An indented line right after a list item continues it.
        if indent >= 2 && self.list.is_some() && !self.list_gap && list_item(line).is_none() {
            self.continue_item(trimmed);
            return Ok(());
        }
        if indent <= 3 {
            if let Some(level) = setext(trimmed).filter(|_| !self.paragraph.is_empty()) {
                let text = self.paragraph.join(" ");
                self.paragraph.clear();
                let spans = inline(&text)?;
                return self.block(Block::Heading { level, spans });
            }
            if let Some((level, text)) = atx(trimmed) {
                self.flush_all()?;
                let spans = inline(text)?;
                return self.block(Block::Heading { level, spans });
            }
            if is_rule(trimmed) {
                self.flush_all()?;
                return self.block(Block::Rule);
            }
            if let Some(rest) = trimmed.strip_prefix('>') {
                self.flush_paragraph()?;
                self.flush_list()?;
                let rest = rest.strip_prefix(' ').unwrap_or(rest).trim();
                if !rest.is_empty() {
                    self.quote.push(rest.to_string());
                }
                return Ok(());
            }
            if let Some((ordered, rest)) = list_item(line) {
                self.flush_paragraph()?;
                self.flush_quote()?;
                if self.list.as_ref().is_some_and(|(kind, _)| *kind != ordered) {
                    self.flush_list()?;
                }
                let (_, items) = self.list.get_or_insert_with(|| (ordered, Vec::new()));
                if items.len() >= MAX_LIST_ITEMS {
                    return Err(ModelError::TooLong);
                }
                items.push(rest.trim().to_string());
                self.list_gap = false;
                return Ok(());
            }
        }
        // A line after a list item, with no blank line between, continues it.
        if self.list.is_some() && !self.list_gap {
            self.continue_item(trimmed);
            return Ok(());
        }
        self.flush_quote()?;
        self.flush_list()?;
        self.paragraph.push(trimmed.to_string());
        Ok(())
    }

    fn continue_item(&mut self, text: &str) {
        if let Some((_, items)) = self.list.as_mut() {
            if let Some(last) = items.last_mut() {
                if !last.is_empty() {
                    last.push(' ');
                }
                last.push_str(text);
            }
        }
    }
}

/// A fence: its character and length, if `line` opens one.
fn fence_open(line: &str) -> Option<(char, usize)> {
    let trimmed = line.trim_start();
    if line.len() - trimmed.len() > 3 {
        return None;
    }
    let first = trimmed.chars().next()?;
    if first != '`' && first != '~' {
        return None;
    }
    let run = trimmed.chars().take_while(|c| *c == first).count();
    // A backtick fence's info string may not contain a backtick.
    if run < 3 || (first == '`' && trimmed[run..].contains('`')) {
        return None;
    }
    Some((first, run))
}

fn fence_closes(line: &str, (fence, length): (char, usize)) -> bool {
    let trimmed = line.trim();
    trimmed.chars().count() >= length && trimmed.chars().all(|c| c == fence)
}

fn atx(trimmed: &str) -> Option<(u8, &str)> {
    let level = trimmed.chars().take_while(|c| *c == '#').count();
    if !(1..=6).contains(&level) {
        return None;
    }
    let rest = &trimmed[level..];
    if !rest.is_empty() && !rest.starts_with([' ', '\t']) {
        return None;
    }
    let mut text = rest.trim();
    // A closing run of `#` goes, if a space comes before it.
    let without = text.trim_end_matches('#');
    if without.is_empty() || without.ends_with([' ', '\t']) {
        text = without.trim_end();
    }
    Some((level as u8, text))
}

fn setext(trimmed: &str) -> Option<u8> {
    if !trimmed.is_empty() && trimmed.chars().all(|c| c == '=') {
        Some(1)
    } else if !trimmed.is_empty() && trimmed.chars().all(|c| c == '-') {
        Some(2)
    } else {
        None
    }
}

fn is_rule(trimmed: &str) -> bool {
    let marks: Vec<char> = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    marks.len() >= 3 && matches!(marks[0], '-' | '*' | '_') && marks.iter().all(|c| *c == marks[0])
}

/// A list item: ordered or not, and the text after its marker.
fn list_item(line: &str) -> Option<(bool, &str)> {
    let trimmed = line.trim_start();
    if line.len() - trimmed.len() > 3 {
        return None;
    }
    for marker in ["- ", "* ", "+ "] {
        if let Some(rest) = trimmed.strip_prefix(marker) {
            return Some((false, rest));
        }
    }
    let digits = trimmed.chars().take_while(char::is_ascii_digit).count();
    if (1..=9).contains(&digits) {
        let rest = &trimmed[digits..];
        for marker in [". ", ") "] {
            if let Some(rest) = rest.strip_prefix(marker) {
                return Some((true, rest));
            }
        }
    }
    None
}

/// Inline text into spans. Spans do not nest: what is inside a code span,
/// a strong or an emphasis is shown as it is.
///
/// Linear in the text: every closer is found through an index built once,
/// so text full of openers that never close costs no more than plain text.
pub fn inline(text: &str) -> Result<Vec<Span>, ModelError> {
    let chars: Vec<char> = text.chars().collect();
    let index = Index::new(&chars);
    let mut spans = Spans::default();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && chars.get(i + 1).is_some_and(char::is_ascii_punctuation) {
            spans.plain(chars[i + 1]);
            i += 2;
            continue;
        }
        if c == '`' {
            let run = run_of(&chars, i, '`');
            if let Some(end) = index.code_end(i, run) {
                let inner: String = chars[i + run..end].iter().collect();
                let inner = match inner.strip_prefix(' ').and_then(|s| s.strip_suffix(' ')) {
                    Some(stripped) if !stripped.trim().is_empty() => stripped.to_string(),
                    _ => inner,
                };
                spans.styled(Style::Code, inner)?;
                i = end + run;
            } else {
                for _ in 0..run {
                    spans.plain('`');
                }
                i += run;
            }
            continue;
        }
        if c == '!' && chars.get(i + 1) == Some(&'[') {
            if let Some((close, end)) = index.link(&chars, i + 1) {
                let label: String = chars[i + 2..close].iter().collect();
                spans.plain_str(&format!("[image: {label}]"));
                i = end + 1;
                continue;
            }
        }
        if c == '[' {
            if let Some((close, end)) = index.link(&chars, i) {
                let label: String = chars[i + 1..close].iter().collect();
                let target: String = chars[close + 2..end].iter().collect();
                spans.plain_str(&label);
                if !target.trim().is_empty() {
                    spans.plain_str(&format!(" ({})", target.trim()));
                }
                i = end + 1;
                continue;
            }
        }
        if c == '<' {
            if let Some(end) = index.autolink_end(&chars, i) {
                let inner: String = chars[i + 1..end].iter().collect();
                spans.plain_str(&inner);
                i = end + 1;
                continue;
            }
        }
        if c == '*' || c == '_' {
            let run = run_of(&chars, i, c);
            let width = if run >= 2 { 2 } else { 1 };
            if let Some(end) = index.emphasis_end(&chars, i, c, width) {
                let inner: String = chars[i + width..end].iter().collect();
                let style = if width == 2 { Style::Strong } else { Style::Em };
                spans.styled(style, inner)?;
                i = end + width;
                continue;
            }
            for _ in 0..run {
                spans.plain(c);
            }
            i += run;
            continue;
        }
        spans.plain(c);
        i += 1;
    }
    spans.finish()
}

#[derive(Default)]
struct Spans {
    spans: Vec<Span>,
    plain: String,
}

impl Spans {
    fn plain(&mut self, c: char) {
        self.plain.push(c);
    }

    fn plain_str(&mut self, text: &str) {
        self.plain.push_str(text);
    }

    fn take_plain(&mut self) -> Result<(), ModelError> {
        if !self.plain.is_empty() {
            let text = std::mem::take(&mut self.plain);
            self.push(Span::plain(text))?;
        }
        Ok(())
    }

    fn push(&mut self, span: Span) -> Result<(), ModelError> {
        if self.spans.len() >= MAX_SPANS {
            return Err(ModelError::TooLong);
        }
        self.spans.push(span);
        Ok(())
    }

    fn styled(&mut self, style: Style, text: String) -> Result<(), ModelError> {
        self.take_plain()?;
        self.push(Span { style, text })
    }

    fn finish(mut self) -> Result<Vec<Span>, ModelError> {
        self.take_plain()?;
        Ok(self.spans)
    }
}

fn run_of(chars: &[char], start: usize, c: char) -> usize {
    chars[start..].iter().take_while(|x| **x == c).count()
}

/// The longest scheme an autolink may have, as in CommonMark.
const MAX_SCHEME: usize = 32;

/// Where each closer is, built in one pass from the end. `next_*[i]` is the
/// first position at or after `i`, or the text's length when there is none.
struct Index {
    len: usize,
    next_bracket: Vec<usize>,
    next_paren: Vec<usize>,
    next_angle_or_space: Vec<usize>,
    /// For `*`, `**`, `_`, `__`: the next position a closer of that kind may
    /// start at.
    next_closer: [Vec<usize>; 4],
    /// For each length, the start of every maximal run of backticks of that
    /// length, in order.
    backtick_runs: std::collections::BTreeMap<usize, Vec<usize>>,
}

const CLOSERS: [(char, usize); 4] = [('*', 1), ('*', 2), ('_', 1), ('_', 2)];

impl Index {
    fn new(chars: &[char]) -> Index {
        let len = chars.len();
        let next = |found: &dyn Fn(usize) -> bool| -> Vec<usize> {
            let mut next = vec![len; len + 1];
            for i in (0..len).rev() {
                next[i] = if found(i) { i } else { next[i + 1] };
            }
            next
        };
        let closes = |c: char, width: usize, i: usize| -> bool {
            i >= 1
                && i + width <= len
                && chars[i..i + width].iter().all(|x| *x == c)
                && !chars[i - 1].is_whitespace()
                && chars.get(i + width) != Some(&c)
                && !(c == '_' && chars.get(i + width).is_some_and(|x| x.is_alphanumeric()))
        };
        let mut backtick_runs: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
        let mut i = 0;
        while i < len {
            if chars[i] == '`' {
                let run = run_of(chars, i, '`');
                backtick_runs.entry(run).or_default().push(i);
                i += run;
            } else {
                i += 1;
            }
        }
        Index {
            len,
            next_bracket: next(&|i| chars[i] == ']'),
            next_paren: next(&|i| chars[i] == ')'),
            next_angle_or_space: next(&|i| chars[i] == '>' || chars[i].is_whitespace()),
            next_closer: CLOSERS.map(|(c, width)| next(&|i| closes(c, width, i))),
            backtick_runs,
        }
    }

    fn at(next: &[usize], i: usize) -> usize {
        next[i.min(next.len() - 1)]
    }

    /// The start of the next run of exactly `run` backticks after `start`.
    fn code_end(&self, start: usize, run: usize) -> Option<usize> {
        let starts = self.backtick_runs.get(&run)?;
        let after = starts.partition_point(|&s| s <= start);
        starts.get(after).copied()
    }

    /// `[label](target)` at `start`: the positions of `]` and `)`.
    fn link(&self, chars: &[char], start: usize) -> Option<(usize, usize)> {
        let close = Index::at(&self.next_bracket, start + 1);
        if close >= self.len || chars.get(close + 1) != Some(&'(') {
            return None;
        }
        let end = Index::at(&self.next_paren, close + 2);
        (end < self.len).then_some((close, end))
    }

    /// `<scheme:rest>` at `start`, with no space inside: the position of `>`.
    fn autolink_end(&self, chars: &[char], start: usize) -> Option<usize> {
        let end = Index::at(&self.next_angle_or_space, start + 1);
        if end >= self.len || chars[end] != '>' {
            return None;
        }
        // The scheme is short, so finding its `:` is bounded.
        let limit = end.min(start + 2 + MAX_SCHEME);
        let colon = (start + 1..limit).find(|&i| chars[i] == ':')?;
        let scheme = &chars[start + 1..colon];
        let scheme_ok = scheme.len() >= 2
            && scheme[0].is_ascii_alphabetic()
            && scheme
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
        (scheme_ok && colon + 1 < end).then_some(end)
    }

    /// The closer of an emphasis of `width` `c`s opened at `start`, if any.
    /// The opener must be followed by a non-space, the closer preceded by
    /// one, and `_` does not open or close inside a word.
    fn emphasis_end(&self, chars: &[char], start: usize, c: char, width: usize) -> Option<usize> {
        let after = *chars.get(start + width)?;
        if after.is_whitespace() || after == c {
            return None;
        }
        if c == '_' && start > 0 && chars[start - 1].is_alphanumeric() {
            return None;
        }
        let kind = CLOSERS.iter().position(|kind| *kind == (c, width))?;
        let end = Index::at(&self.next_closer[kind], start + width + 1);
        (end < self.len).then_some(end)
    }
}
