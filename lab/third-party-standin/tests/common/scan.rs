//! Production source inventories.
//!
//! Comments and string literals are blanked before a count, so a note cannot
//! change a row. Test files, `#[cfg(test)]` modules, `#[test]` functions, and
//! `#[cfg(test)]` statements are not production.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::{join, repo_root, server_file, walk_text_files};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Site {
    pub file: String,
    pub function: String,
    pub label: String,
    pub count: u32,
}

impl Site {
    fn new(file: &str, function: &str, label: &str, count: u32) -> Self {
        Self {
            file: file.to_string(),
            function: function.to_string(),
            label: label.to_string(),
            count,
        }
    }
}

pub fn sites_json(sites: &[Site]) -> Value {
    Value::Array(
        sites
            .iter()
            .map(|site| {
                json!({
                    "file": site.file,
                    "function": site.function,
                    "label": site.label,
                    "count": site.count,
                })
            })
            .collect(),
    )
}

struct Item {
    name: String,
    keyword_at: usize,
    body_start: usize,
    body_end: usize,
    test_item: bool,
    excluded: Vec<(usize, usize)>,
}

pub fn registration_sites() -> Vec<Site> {
    let register = join(&["reg", "ister"]);
    let sub = join(&["register_sub_", "provider"]);
    let runtime = join(&["register_runtime_", "provider_target"]);
    let mut counts: BTreeMap<(String, String, String), u32> = BTreeMap::new();
    for (file, source) in production_sources() {
        let blank = blank_source(&source);
        let fns = production_fns(&blank);
        for method in [&register, &sub, &runtime] {
            for (function, _) in method_calls(&blank, &fns, method, true) {
                *counts
                    .entry((file.clone(), function, method.clone()))
                    .or_insert(0) += 1;
            }
        }
    }
    counts
        .into_iter()
        .map(|((file, function, label), count)| Site::new(&file, &function, &label, count))
        .collect()
}

pub fn provides_readers() -> Vec<Site> {
    let mut counts: BTreeMap<(String, String), u32> = BTreeMap::new();
    for (file, source) in production_sources() {
        let blank = blank_source(&source);
        let fns = production_fns(&blank);
        let impls = manifest_impl_bodies(&blank, &fns);
        for (function, _) in field_calls(&blank, &fns, "provides", |receiver, at| match receiver {
            Some("manifest") => true,
            Some("self") => impls.iter().any(|(start, end)| at >= *start && at < *end),
            _ => false,
        }) {
            *counts.entry((file.clone(), function)).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .map(|((file, function), count)| Site::new(&file, &function, "manifest.provides", count))
        .collect()
}

pub fn ident_inventory(relative: &str, ident: &str) -> Vec<Site> {
    let source = server_file(relative);
    let blank = blank_source(&source);
    let fns = production_fns(&blank);
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for at in ident_positions(&blank, ident) {
        if preceded_by_keyword(&blank, at, "const") || preceded_by_keyword(&blank, at, "fn") {
            continue;
        }
        let Some(item) = enclosing(&fns, at) else {
            continue;
        };
        if item
            .excluded
            .iter()
            .any(|(start, end)| at >= *start && at < *end)
        {
            continue;
        }
        *counts.entry(item.name.clone()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(function, count)| Site::new(relative, &function, ident, count))
        .collect()
}

pub fn repo_call_inventory(name: &str) -> Vec<Site> {
    let mut counts: BTreeMap<(String, String), u32> = BTreeMap::new();
    for (file, source) in production_sources() {
        let blank = blank_source(&source);
        let fns = production_fns(&blank);
        for (function, _) in method_calls(&blank, &fns, name, false) {
            *counts.entry((file.clone(), function)).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .map(|((file, function), count)| Site::new(&file, &function, name, count))
        .collect()
}

pub fn call_inventory(relative: &str, name: &str) -> Vec<Site> {
    let source = server_file(relative);
    let blank = blank_source(&source);
    let fns = production_fns(&blank);
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for (function, _) in method_calls(&blank, &fns, name, false) {
        *counts.entry(function).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(function, count)| Site::new(relative, &function, name, count))
        .collect()
}

/// Production calls of `name` whose final argument is recorded in the label.
pub fn call_with_last_arg(relative: &str, name: &str) -> Vec<Site> {
    let source = server_file(relative);
    let blank = blank_source(&source);
    let fns = production_fns(&blank);
    let mut counts: BTreeMap<(String, String), u32> = BTreeMap::new();
    for (function, at) in method_calls(&blank, &fns, name, false) {
        let label = format!("{name}({})", last_argument(&blank, at + name.len()));
        *counts.entry((function, label)).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|((function, label), count)| Site::new(relative, &function, &label, count))
        .collect()
}

pub fn field_reads(relative: &str, field: &str) -> Vec<Site> {
    let source = server_file(relative);
    let blank = blank_source(&source);
    let fns = production_fns(&blank);
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for (function, _) in field_calls(&blank, &fns, field, |_, _| true) {
        *counts.entry(function).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(function, count)| Site::new(relative, &function, field, count))
        .collect()
}

pub fn const_expression(relative: &str, name: &str) -> String {
    let source = server_file(relative);
    let blank = blank_source(&source);
    let marker = format!("const {name}");
    let at = blank
        .find(&marker)
        .unwrap_or_else(|| panic!("missing const {name}"));
    let after = &blank[at + marker.len()..];
    let eq = after
        .find('=')
        .unwrap_or_else(|| panic!("const {name} has no value"));
    let tail = &after[eq + 1..];
    let end = tail
        .find(';')
        .unwrap_or_else(|| panic!("const {name} has no end"));
    tail[..end].split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn action_variant_counts(relative: &str, function: &str) -> BTreeMap<String, u32> {
    let source = server_file(relative);
    let blank = blank_source(&source);
    let fns = production_fns(&blank);
    let item = fns
        .iter()
        .find(|item| item.name == function && !item.test_item)
        .unwrap_or_else(|| panic!("missing production fn {function}"));
    let body = &blank[item.body_start..item.body_end];
    let mut counts = BTreeMap::new();
    for variant in ["Admin", "Delete", "Execute", "Message", "Read", "Write"] {
        let needle = format!("Action::{variant}");
        let mut count = 0u32;
        let mut from = 0usize;
        while let Some(found) = body[from..].find(&needle) {
            let at = item.body_start + from + found;
            let excluded = item
                .excluded
                .iter()
                .any(|(start, end)| at >= *start && at < *end);
            if !excluded {
                count += 1;
            }
            from += found + needle.len();
        }
        if count > 0 {
            counts.insert(variant.to_string(), count);
        }
    }
    counts
}

pub fn validate_fns_mention(relative: &str, ident: &str) -> Vec<Site> {
    let source = server_file(relative);
    let blank = blank_source(&source);
    // Strings stay visible: a validator that reads a limit key by name is a
    // reader even when the key is a string literal. Comments stay blank.
    let visible = blank_code(&source, false);
    let fns = production_fns(&blank);
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for at in ident_positions(&visible, ident) {
        let Some(item) = enclosing(&fns, at) else {
            continue;
        };
        if !item.name.contains("validate") {
            continue;
        }
        if item
            .excluded
            .iter()
            .any(|(start, end)| at >= *start && at < *end)
        {
            continue;
        }
        *counts.entry(item.name.clone()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(function, count)| Site::new(relative, &function, ident, count))
        .collect()
}

pub fn manifest_struct_fields(relative: &str) -> Vec<String> {
    let source = server_file(relative);
    let blank = blank_source(&source);
    let mut names = Vec::new();
    let mut from = 0usize;
    while let Some(found) = blank[from..].find("struct ") {
        let at = from + found;
        // "struct" itself ends in an ident character. Check the byte before the keyword.
        if preceded_by_ident(&blank, at) {
            from = at + "struct ".len();
            continue;
        }
        let name_at = skip_ws(&blank, at + "struct".len());
        let Some((struct_name, name_end)) = read_ident(&blank, name_at) else {
            from = at + "struct ".len();
            continue;
        };
        if !is_item_keyword(&blank, at) {
            from = name_end;
            continue;
        }
        if let Some((body_start, body_end)) = item_body_span(&blank, name_end) {
            for field in struct_field_names(&blank[body_start..body_end]) {
                names.push(format!("{struct_name}.{field}"));
            }
            from = body_end;
        } else {
            from = name_end;
        }
    }
    names.sort();
    names.dedup();
    names
}

pub fn register_signature_returns_nothing(source: &str) -> bool {
    let needle = join(&["fn register(&self, provider:"]);
    let Some(at) = source.find(&needle) else {
        return false;
    };
    let after = &source[at + needle.len()..];
    let end = after.find('{').unwrap_or(after.len());
    !after[..end].contains("->")
}

pub fn production_sources() -> Vec<(String, String)> {
    let root = repo_root().join("elastos/crates");
    let mut found = Vec::new();
    for (path, text) in walk_text_files(&root) {
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let rel = path
            .strip_prefix(repo_root())
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_path(&rel) {
            continue;
        }
        found.push((rel, text));
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

fn is_test_path(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split('/').collect();
    if parts
        .iter()
        .any(|part| *part == "tests" || part.ends_with("_tests"))
    {
        return true;
    }
    matches!(
        parts.last().copied(),
        Some(name) if name == "tests.rs" || name.ends_with("_tests.rs") || name.ends_with("_test.rs")
    )
}

fn production_fns(blank: &str) -> Vec<Item> {
    let macros = macro_ranges(blank);
    let mut fns = Vec::new();
    for at in keyword_positions(blank, "fn") {
        if inside(at, &macros) || !fn_item_at(blank, at) {
            continue;
        }
        let name_at = skip_ws(blank, at + 2);
        let Some((name, name_end)) = read_ident(blank, name_at) else {
            continue;
        };
        let Some((body_start, body_end)) = item_body_span(blank, name_end) else {
            continue;
        };
        let (attrs, _) = leading_attrs(blank, at);
        fns.push(Item {
            name,
            keyword_at: at,
            body_start,
            body_end,
            test_item: attrs_mark_test(&attrs),
            excluded: Vec::new(),
        });
    }
    let test_ranges = test_container_ranges(blank, &fns, &macros);
    for item in &mut fns {
        if inside(item.keyword_at, &test_ranges) {
            item.test_item = true;
        }
        if !item.test_item {
            item.excluded = cfg_test_statements(blank, item.body_start, item.body_end);
        }
    }
    fns
}

fn manifest_impl_bodies(blank: &str, fns: &[Item]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for at in keyword_positions(blank, "impl") {
        if fns
            .iter()
            .any(|item| at > item.body_start && at < item.body_end)
        {
            continue;
        }
        if !is_item_keyword(blank, at) {
            continue;
        }
        let header_end = skip_ws(blank, at + "impl".len());
        let Some((body_start, body_end)) = item_body_span(blank, header_end) else {
            continue;
        };
        let header = &blank[at..body_start];
        if ident_positions(header, "CapsuleManifest").is_empty() {
            continue;
        }
        ranges.push((body_start, body_end));
    }
    ranges
}

fn test_container_ranges(
    blank: &str,
    fns: &[Item],
    macros: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for keyword in ["mod", "impl"] {
        for at in keyword_positions(blank, keyword) {
            if inside(at, macros)
                || fns
                    .iter()
                    .any(|item| at > item.body_start && at < item.body_end)
            {
                continue;
            }
            if !is_item_keyword(blank, at) {
                continue;
            }
            let (attrs, _) = leading_attrs(blank, at);
            let name_at = skip_ws(blank, at + keyword.len());
            let named = read_ident(blank, name_at);
            let module_named_tests =
                keyword == "mod" && named.as_ref().is_some_and(|(name, _)| name == "tests");
            if !attrs_mark_test(&attrs) && !module_named_tests {
                continue;
            }
            let scan_from = named.map(|(_, end)| end).unwrap_or(name_at);
            if let Some((body_start, body_end)) = item_body_span(blank, scan_from) {
                ranges.push((body_start, body_end));
            }
        }
    }
    ranges
}

fn method_calls(
    blank: &str,
    fns: &[Item],
    method: &str,
    registry_only: bool,
) -> Vec<(String, usize)> {
    let mut found = Vec::new();
    for at in ident_positions(blank, method) {
        if preceded_by_keyword(blank, at, "fn") || !is_call(blank, at + method.len()) {
            continue;
        }
        let Some(item) = enclosing(fns, at) else {
            continue;
        };
        if item
            .excluded
            .iter()
            .any(|(start, end)| at >= *start && at < *end)
        {
            continue;
        }
        if registry_only && !registry_method(blank, at, method) {
            continue;
        }
        found.push((item.name.clone(), at));
    }
    found
}

fn field_calls(
    blank: &str,
    fns: &[Item],
    field: &str,
    keep: impl Fn(Option<&str>, usize) -> bool,
) -> Vec<(String, usize)> {
    let mut found = Vec::new();
    for at in ident_positions(blank, field) {
        let before = skip_ws_back(blank, at);
        if before == 0 || blank.as_bytes()[before - 1] != b'.' {
            continue;
        }
        let receiver = receiver_ident(blank, before - 1);
        if !keep(receiver.as_deref(), at) {
            continue;
        }
        let Some(item) = enclosing(fns, at) else {
            continue;
        };
        if item
            .excluded
            .iter()
            .any(|(start, end)| at >= *start && at < *end)
        {
            continue;
        }
        found.push((item.name.clone(), at));
    }
    found
}

fn registry_method(blank: &str, name_at: usize, method: &str) -> bool {
    if method != "register" && !method.starts_with("register") {
        return false;
    }
    if method != "register" {
        return true;
    }
    let before = skip_ws_back(blank, name_at);
    let bytes = blank.as_bytes();
    if before >= 2 && &bytes[before - 2..before] == b"::" {
        return receiver_ident(blank, before - 2)
            .is_some_and(|name| name.to_ascii_lowercase().contains("registry") || name == "Self");
    }
    if before > 0 && bytes[before - 1] == b'.' {
        return receiver_ident(blank, before - 1)
            .is_some_and(|name| name.to_ascii_lowercase().contains("registry"));
    }
    false
}

fn enclosing(fns: &[Item], at: usize) -> Option<&Item> {
    let innermost = fns
        .iter()
        .filter(|item| at >= item.body_start && at < item.body_end)
        .min_by_key(|item| item.body_end - item.body_start)?;
    if innermost.test_item {
        None
    } else {
        Some(innermost)
    }
}

fn last_argument(blank: &str, name_end: usize) -> String {
    let open = skip_ws(blank, name_end);
    let bytes = blank.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return String::new();
    }
    let mut depth = 0i32;
    let mut arg_start = open + 1;
    let mut previous = String::new();
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    let last = blank[arg_start..i]
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                    if last.is_empty() {
                        return previous;
                    }
                    return last;
                }
            }
            b',' if depth == 1 => {
                previous = blank[arg_start..i]
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                arg_start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    String::new()
}

fn cfg_test_statements(blank: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let bytes = blank.as_bytes();
    let mut ranges = Vec::new();
    let mut i = start;
    while i + 1 < end {
        if bytes[i] == b'#' && bytes[i + 1] == b'[' {
            let Some(attr_end) = match_forward(blank, i + 1, b'[', b']') else {
                i += 1;
                continue;
            };
            if attrs_mark_test(&blank[i..attr_end]) {
                let stmt_end = statement_end(blank, attr_end, end);
                ranges.push((i, stmt_end));
                i = stmt_end;
                continue;
            }
            i = attr_end;
            continue;
        }
        i += 1;
    }
    ranges
}

fn statement_end(blank: &str, mut i: usize, limit: usize) -> usize {
    i = skip_ws(blank, i).min(limit);
    let bytes = blank.as_bytes();
    let mut paren = 0i32;
    let mut bracket = 0i32;
    let mut brace = 0i32;
    let mut saw_brace = false;
    while i < limit && i < bytes.len() {
        match bytes[i] {
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => {
                brace += 1;
                saw_brace = true;
            }
            b'}' => {
                brace -= 1;
                if saw_brace && brace == 0 && paren == 0 && bracket == 0 {
                    return i + 1;
                }
            }
            b';' if paren == 0 && brace == 0 && bracket == 0 => return i + 1,
            _ => {}
        }
        i += 1;
    }
    i
}

fn fn_item_at(blank: &str, at: usize) -> bool {
    let next = skip_ws(blank, at + 2);
    read_ident(blank, next).is_some()
}

fn is_item_keyword(blank: &str, keyword_at: usize) -> bool {
    let (attrs, cursor) = leading_attrs(blank, keyword_at);
    let _ = attrs;
    let before = skip_ws_back(blank, cursor);
    if before == 0 {
        return true;
    }
    matches!(blank.as_bytes()[before - 1], b'}' | b';' | b'{' | b']')
}

fn leading_attrs(blank: &str, keyword_at: usize) -> (String, usize) {
    let mut cursor = keyword_at;
    loop {
        let trimmed = skip_ws_back(blank, cursor);
        if let Some(next) = strip_qualifier(blank, trimmed) {
            cursor = next;
            continue;
        }
        cursor = trimmed;
        break;
    }
    let mut attrs = String::new();
    loop {
        cursor = skip_ws_back(blank, cursor);
        if cursor == 0 || blank.as_bytes()[cursor - 1] != b']' {
            break;
        }
        let Some(open) = match_backward(blank, cursor - 1, b'[', b']') else {
            break;
        };
        let hash_end = skip_ws_back(blank, open);
        if hash_end == 0 || blank.as_bytes()[hash_end - 1] != b'#' {
            break;
        }
        attrs.insert_str(0, &blank[hash_end - 1..cursor]);
        cursor = hash_end - 1;
    }
    (attrs, cursor)
}

fn strip_qualifier(blank: &str, end: usize) -> Option<usize> {
    if end == 0 {
        return None;
    }
    let bytes = blank.as_bytes();
    if bytes[end - 1] == b')' {
        let open = match_backward(blank, end - 1, b'(', b')')?;
        let ident_end = skip_ws_back(blank, open);
        if ident_ending(blank, ident_end) == Some("pub") {
            return Some(ident_end - 3);
        }
        return None;
    }
    if bytes[end - 1] == b'"' {
        let mut quote = end - 1;
        while quote > 0 && bytes[quote - 1] != b'"' {
            quote -= 1;
        }
        if quote == 0 {
            return None;
        }
        let ident_end = skip_ws_back(blank, quote - 1);
        if ident_ending(blank, ident_end) == Some("extern") {
            return Some(ident_end - "extern".len());
        }
        return None;
    }
    let ident = ident_ending(blank, end)?;
    if matches!(ident, "async" | "unsafe" | "const" | "pub") {
        return Some(end - ident.len());
    }
    None
}

fn attrs_mark_test(attrs: &str) -> bool {
    let compact: String = attrs.chars().filter(|ch| !ch.is_whitespace()).collect();
    let compact = compact.replace("not(test)", "");
    if compact.contains("#[test]")
        || compact.contains("#[tokio::test")
        || compact.contains("#[rstest")
    {
        return true;
    }
    compact.contains("cfg(") && has_word(&compact, "test")
}

fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(at, _)| {
        let before = at == 0 || !is_ident_char(text.as_bytes()[at - 1]);
        let after_at = at + word.len();
        let after = after_at >= text.len() || !is_ident_char(text.as_bytes()[after_at]);
        before && after
    })
}

fn item_body_span(blank: &str, from: usize) -> Option<(usize, usize)> {
    let bytes = blank.as_bytes();
    let mut i = from;
    let mut paren = 0i32;
    let mut bracket = 0i32;
    let mut angle = 0i32;
    while i < bytes.len() {
        if bytes[i] == b'-' && bytes.get(i + 1) == Some(&b'>') {
            i += 2;
            continue;
        }
        if bytes[i] == b'=' && bytes.get(i + 1) == Some(&b'>') {
            i += 2;
            continue;
        }
        match bytes[i] {
            b'<' => angle += 1,
            b'>' => angle = angle.saturating_sub(1),
            b'(' => paren += 1,
            b')' => paren = paren.saturating_sub(1),
            b'[' => bracket += 1,
            b']' => bracket = bracket.saturating_sub(1),
            b'{' if paren == 0 && bracket == 0 && angle == 0 => {
                let end = match_forward(blank, i, b'{', b'}')?;
                return Some((i, end));
            }
            b';' if paren == 0 && bracket == 0 && angle == 0 => return None,
            _ => {}
        }
        i += 1;
    }
    None
}

fn macro_ranges(blank: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for at in ident_positions(blank, "macro_rules") {
        let bang = skip_ws(blank, at + "macro_rules".len());
        if blank.as_bytes().get(bang) != Some(&b'!') {
            continue;
        }
        let mut i = bang + 1;
        while i < blank.len() {
            let ch = blank.as_bytes()[i];
            if ch == b'{' || ch == b'(' || ch == b'[' {
                let close = match ch {
                    b'{' => b'}',
                    b'(' => b')',
                    _ => b']',
                };
                if let Some(end) = match_forward(blank, i, ch, close) {
                    ranges.push((at, end));
                }
                break;
            }
            i += 1;
        }
    }
    ranges
}

fn struct_field_names(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut names = Vec::new();
    let mut i = 0usize;
    let mut depth = 0i32;
    while i < bytes.len() {
        match bytes[i] {
            b'{' | b'(' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b')' | b']' => {
                depth -= 1;
                i += 1;
            }
            b'p' if depth == 1 && body[i..].starts_with("pub") => {
                let after_pub = i + 3;
                if after_pub >= bytes.len() || is_ident_char(bytes[after_pub]) {
                    i += 1;
                    continue;
                }
                let mut name_at = skip_ws(body, after_pub);
                if bytes.get(name_at) == Some(&b'(') {
                    if let Some(end) = match_forward(body, name_at, b'(', b')') {
                        name_at = skip_ws(body, end);
                    }
                }
                if let Some((name, name_end)) = read_ident(body, name_at) {
                    if !matches!(
                        name.as_str(),
                        "struct" | "enum" | "fn" | "type" | "const" | "use" | "mod" | "trait"
                    ) {
                        names.push(name);
                    }
                    i = name_end;
                    continue;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    names
}

fn keyword_positions(blank: &str, keyword: &str) -> Vec<usize> {
    ident_positions(blank, keyword)
}

fn ident_positions(blank: &str, ident: &str) -> Vec<usize> {
    let bytes = blank.as_bytes();
    let needle = ident.as_bytes();
    let mut found = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle
            && (i == 0 || !is_ident_char(bytes[i - 1]))
            && (i + needle.len() == bytes.len() || !is_ident_char(bytes[i + needle.len()]))
        {
            found.push(i);
        }
        i += 1;
    }
    found
}

fn preceded_by_keyword(blank: &str, at: usize, keyword: &str) -> bool {
    ident_ending(blank, skip_ws_back(blank, at)) == Some(keyword)
}

fn preceded_by_ident(blank: &str, at: usize) -> bool {
    at > 0 && is_ident_char(blank.as_bytes()[at - 1])
}

fn is_call(blank: &str, name_end: usize) -> bool {
    blank.as_bytes().get(skip_ws(blank, name_end)) == Some(&b'(')
}

fn receiver_ident(blank: &str, dot_or_colon: usize) -> Option<String> {
    let end = skip_ws_back(blank, dot_or_colon);
    ident_ending(blank, end).map(str::to_string)
}

fn ident_ending(blank: &str, end: usize) -> Option<&str> {
    if end == 0 || !is_ident_char(blank.as_bytes()[end - 1]) {
        return None;
    }
    let bytes = blank.as_bytes();
    let mut start = end;
    while start > 0 && is_ident_char(bytes[start - 1]) {
        start -= 1;
    }
    Some(&blank[start..end])
}

fn read_ident(blank: &str, at: usize) -> Option<(String, usize)> {
    let bytes = blank.as_bytes();
    if at >= bytes.len() || !is_ident_start(bytes[at]) {
        return None;
    }
    let mut end = at + 1;
    while end < bytes.len() && is_ident_char(bytes[end]) {
        end += 1;
    }
    Some((blank[at..end].to_string(), end))
}

fn inside(at: usize, ranges: &[(usize, usize)]) -> bool {
    ranges.iter().any(|(start, end)| at >= *start && at < *end)
}

fn skip_ws(blank: &str, mut i: usize) -> usize {
    let bytes = blank.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn skip_ws_back(blank: &str, mut i: usize) -> usize {
    let bytes = blank.as_bytes();
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    i
}

fn match_forward(blank: &str, open: usize, left: u8, right: u8) -> Option<usize> {
    let bytes = blank.as_bytes();
    if bytes.get(open) != Some(&left) {
        return None;
    }
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        if bytes[i] == left {
            depth += 1;
        } else if bytes[i] == right {
            depth -= 1;
            if depth == 0 {
                return Some(i + 1);
            }
        }
        i += 1;
    }
    None
}

fn match_backward(blank: &str, close: usize, left: u8, right: u8) -> Option<usize> {
    let bytes = blank.as_bytes();
    if bytes.get(close) != Some(&right) {
        return None;
    }
    let mut depth = 0i32;
    let mut i = close;
    loop {
        if bytes[i] == right {
            depth += 1;
        } else if bytes[i] == left {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

pub fn blank_source(src: &str) -> String {
    blank_code(src, true)
}

fn blank_code(src: &str, blank_strings: bool) -> String {
    let mut bytes = src.as_bytes().to_vec();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                bytes[i] = b' ';
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            blank_block_comment(&mut bytes, &mut i);
            continue;
        }
        if let Some(end) = string_end(&bytes, i) {
            if blank_strings {
                blank_keep_newlines(&mut bytes, i, end);
            }
            i = end;
            continue;
        }
        i += 1;
    }
    String::from_utf8(bytes).expect("blanked rust stays utf-8")
}

fn blank_block_comment(bytes: &mut [u8], i: &mut usize) {
    let mut depth = 1i32;
    bytes[*i] = b' ';
    bytes[*i + 1] = b' ';
    *i += 2;
    while *i < bytes.len() && depth > 0 {
        if bytes[*i] == b'/' && bytes.get(*i + 1) == Some(&b'*') {
            depth += 1;
            bytes[*i] = b' ';
            bytes[*i + 1] = b' ';
            *i += 2;
            continue;
        }
        if bytes[*i] == b'*' && bytes.get(*i + 1) == Some(&b'/') {
            depth -= 1;
            bytes[*i] = b' ';
            bytes[*i + 1] = b' ';
            *i += 2;
            continue;
        }
        if bytes[*i] != b'\n' {
            bytes[*i] = b' ';
        }
        *i += 1;
    }
}

fn blank_keep_newlines(bytes: &mut [u8], start: usize, end: usize) {
    for byte in &mut bytes[start..end] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn string_end(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes[i] == b'"' {
        return Some(finish_cooked(bytes, i + 1));
    }
    if prev_ident_byte(bytes, i) {
        return None;
    }
    let rest = &bytes[i..];
    for prefix in [
        b"br#".as_slice(),
        b"cr#",
        b"b#",
        b"r#",
        b"br",
        b"cr",
        b"b",
        b"c",
        b"r",
    ] {
        if rest.starts_with(prefix) {
            let after = i + prefix.len();
            if prefix.ends_with(b"#")
                || bytes.get(after) == Some(&b'#')
                || bytes.get(after) == Some(&b'"')
                || bytes.get(after) == Some(&b'\'')
            {
                return finish_prefixed(bytes, i, prefix);
            }
        }
    }
    None
}

fn finish_prefixed(bytes: &[u8], start: usize, prefix: &[u8]) -> Option<usize> {
    let mut i = start + prefix.len();
    if prefix.last() == Some(&b'#') {
        i -= 1;
    }
    if bytes.get(i) == Some(&b'\'') && (prefix == b"b" || prefix == b"c") {
        return Some(finish_char(bytes, i));
    }
    let mut hashes = 0usize;
    while bytes.get(i) == Some(&b'#') {
        hashes += 1;
        i += 1;
    }
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    if hashes == 0
        && prefix.last() != Some(&b'#')
        && !prefix.contains(&b'r')
        && !prefix.contains(&b'#')
        && (prefix == b"b" || prefix == b"c")
    {
        return Some(finish_cooked(bytes, i + 1));
    }
    if prefix.contains(&b'r') || hashes > 0 {
        i += 1;
        return Some(finish_raw(bytes, i, hashes));
    }
    Some(finish_cooked(bytes, i + 1))
}

fn finish_cooked(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' || bytes[i] == b'\n' {
            return i + 1;
        }
        i += 1;
    }
    i
}

fn finish_raw(bytes: &[u8], mut i: usize, hashes: usize) -> usize {
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let mut saw = 0usize;
            while saw < hashes && bytes.get(i + 1 + saw) == Some(&b'#') {
                saw += 1;
            }
            if saw == hashes {
                return i + 1 + hashes;
            }
        }
        i += 1;
    }
    i
}

fn finish_char(bytes: &[u8], quote: usize) -> usize {
    let mut i = quote + 1;
    if bytes.get(i) == Some(&b'\\') {
        i += 2;
    } else {
        i += 1;
    }
    while i < bytes.len() && bytes[i] != b'\'' && bytes[i] != b'\n' {
        i += 1;
    }
    if i < bytes.len() {
        i + 1
    } else {
        i
    }
}

fn prev_ident_byte(bytes: &[u8], i: usize) -> bool {
    i > 0 && is_ident_char(bytes[i - 1])
}

mod scanner_rules {
    use super::*;

    #[test]
    fn blanks_comments_and_strings_before_a_call_is_counted() {
        let source = r#"
            fn live(registry: &Registry) {
                let note = "registry.register(hidden)";
                // registry.register(comment)
                /* registry.register(block) */
                registry.register(real);
            }
        "#;
        let blank = blank_source(source);
        assert!(!blank.contains("hidden"));
        assert!(!blank.contains("comment"));
        assert!(!blank.contains("block"));
        let fns = production_fns(&blank);
        let calls = method_calls(&blank, &fns, "register", true);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "live");
    }

    #[test]
    fn skips_test_modules_test_fns_and_cfg_test_statements() {
        let source = r#"
            fn live(registry: &Registry) {
                registry.register(one);
                #[cfg(test)]
                registry.register(two);
            }
            #[test]
            fn unit(registry: &Registry) {
                registry.register(three);
            }
            #[cfg(test)]
            mod tests {
                fn inside(registry: &Registry) {
                    registry.register(four);
                }
            }
            mod tests {
                fn also(registry: &Registry) {
                    registry.register_sub_provider(five);
                }
            }
        "#;
        let blank = blank_source(source);
        let fns = production_fns(&blank);
        let calls = method_calls(&blank, &fns, "register", true);
        assert_eq!(calls.len(), 1);
        let subs = method_calls(&blank, &fns, "register_sub_provider", true);
        assert!(subs.is_empty());
    }

    #[test]
    fn cache_register_is_not_a_provider_registry_call() {
        let source = r#"
            fn live(cache: &Cache, registry: &Registry) {
                cache.register(cid);
                registry.register(provider);
                registry.register_sub_provider(name, provider);
                registry.register_sub_provider_unchecked(name, provider);
            }
        "#;
        let blank = blank_source(source);
        let fns = production_fns(&blank);
        assert_eq!(method_calls(&blank, &fns, "register", true).len(), 1);
        assert_eq!(
            method_calls(&blank, &fns, "register_sub_provider", true).len(),
            1
        );
    }

    #[test]
    fn manifest_provides_ignores_a_different_provides_field() {
        let source = r#"
            impl CapsuleManifest {
                fn validate(&self) {
                    let _ = self.provides.clone();
                }
            }
            impl ProviderRuntime {
                fn show(&self) {
                    let _ = self.provides.clone();
                }
            }
            fn admit(manifest: &CapsuleManifest, runtime: &ProviderRuntime) {
                let _ = manifest.provides.clone();
                let _ = runtime.provides.clone();
            }
        "#;
        let blank = blank_source(source);
        let fns = production_fns(&blank);
        let impls = manifest_impl_bodies(&blank, &fns);
        let reads = field_calls(&blank, &fns, "provides", |receiver, at| match receiver {
            Some("manifest") => true,
            Some("self") => impls.iter().any(|(start, end)| at >= *start && at < *end),
            _ => false,
        });
        let names: Vec<_> = reads.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["validate", "admit"]);
    }

    #[test]
    fn innermost_function_owns_the_call() {
        let source = r#"
            fn outer(registry: &Registry) {
                fn inner(registry: &Registry) {
                    registry.register(one);
                }
                registry.register(two);
            }
        "#;
        let blank = blank_source(source);
        let fns = production_fns(&blank);
        let calls = method_calls(&blank, &fns, "register", true);
        let mut names: Vec<_> = calls.iter().map(|(name, _)| name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["inner", "outer"]);
    }
}
