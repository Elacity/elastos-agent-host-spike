//! A small structural reader for the Bus WIT files: interfaces with their
//! function names and signatures, and each world's exports. It reads enough
//! to decide two evidence pins; it is not a WIT parser.

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Func {
    pub name: String,
    pub signature: String,
}

/// One file's interfaces and worlds. Files stay apart, so a Bus v2 file can
/// reuse an interface name from v1 without hiding it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WitFile {
    /// Interface name (without package or version) to its functions. Inline
    /// world exports appear as `<world>/<export>`.
    pub interfaces: BTreeMap<String, Vec<Func>>,
    /// World name to the interface names it exports.
    pub worlds: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Wit {
    pub files: Vec<WitFile>,
}

impl Wit {
    /// Every `*.wit` file directly inside `dir`, in name order.
    pub fn read_dir(dir: &Path) -> Result<Wit, String> {
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| format!("cannot list {}: {e}", dir.display()))?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<_, _>>()
            .map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        paths.retain(|path| path.extension().is_some_and(|ext| ext == "wit"));
        paths.sort();
        if paths.is_empty() {
            return Err(format!("no .wit file in {}", dir.display()));
        }
        let mut wit = Wit::default();
        for path in paths {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            wit.add(&text)
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(wit)
    }

    pub fn add(&mut self, text: &str) -> Result<(), String> {
        let code = strip_comments(text);
        let mut file = WitFile::default();
        let mut rest = code.as_str();
        while let Some((keyword, name, body, after)) = next_block(rest)? {
            match keyword {
                "interface" => {
                    file.interfaces.insert(name, functions(&body)?);
                }
                "world" => {
                    let exports = file.world_exports(&name, &body)?;
                    file.worlds.insert(name, exports);
                }
                _ => {}
            }
            rest = after;
        }
        self.files.push(file);
        Ok(())
    }

    /// Every interface with this name, in any file.
    pub fn interfaces_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [Func]> {
        self.files
            .iter()
            .filter_map(move |file| file.interfaces.get(name).map(Vec::as_slice))
    }

    /// Exported interfaces that define every one of `names`. An export is
    /// looked up in its own file first, then by name in any file.
    pub fn exports_defining(&self, names: &[&str]) -> Vec<(String, String)> {
        let defines = |funcs: &[Func]| names.iter().all(|n| funcs.iter().any(|f| f.name == *n));
        let mut found = Vec::new();
        for file in &self.files {
            for (world, exports) in &file.worlds {
                for export in exports {
                    let hit = match file.interfaces.get(export) {
                        Some(funcs) => defines(funcs),
                        None => self.interfaces_named(export).any(defines),
                    };
                    if hit {
                        found.push((world.clone(), export.clone()));
                    }
                }
            }
        }
        found
    }
}

impl WitFile {
    fn world_exports(&mut self, world: &str, body: &str) -> Result<Vec<String>, String> {
        let mut exports = Vec::new();
        let mut world_funcs = Vec::new();
        for statement in statements(body)? {
            let Some(item) = statement.strip_prefix("export ") else {
                continue;
            };
            let item = item.trim();
            match item.split_once(':') {
                Some((name, kind)) if kind.trim_start().starts_with("interface") => {
                    let open = kind.find('{').ok_or("inline export without a body")?;
                    let inner = &kind[open + 1..kind.rfind('}').ok_or("unclosed inline export")?];
                    let key = format!("{world}/{}", name.trim());
                    self.interfaces.insert(key.clone(), functions(inner)?);
                    exports.push(key);
                }
                Some((name, kind)) if kind.trim_start().starts_with("func") => {
                    world_funcs.push(Func {
                        name: name.trim().trim_start_matches('%').to_owned(),
                        signature: kind.trim().to_owned(),
                    });
                }
                _ => exports.push(local_name(item.trim_end_matches(';'))),
            }
        }
        if !world_funcs.is_empty() {
            let key = format!("{world}/<functions>");
            self.interfaces.insert(key.clone(), world_funcs);
            exports.push(key);
        }
        Ok(exports)
    }
}

/// `elastos:bus/resident@2.0.0` names the interface `resident`.
fn local_name(path: &str) -> String {
    let tail = path.rsplit('/').next().unwrap_or(path);
    tail.split('@').next().unwrap_or(tail).trim().to_owned()
}

fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The next top-level `interface` or `world` block, or any other top-level
/// statement, which is skipped.
fn next_block(text: &str) -> Result<Option<(&'static str, String, String, &str)>, String> {
    let text = text.trim_start();
    if text.is_empty() {
        return Ok(None);
    }
    for keyword in ["interface", "world"] {
        if let Some(after) = text.strip_prefix(keyword) {
            if after.starts_with(char::is_whitespace) {
                let open = after.find('{').ok_or(format!("{keyword} without a body"))?;
                let name = after[..open].trim().trim_start_matches('%').to_owned();
                let close = matching(after, open)?;
                return Ok(Some((
                    keyword,
                    name,
                    after[open + 1..close].to_owned(),
                    &after[close + 1..],
                )));
            }
        }
    }
    let end = text.find(';').ok_or("top-level statement without ';'")?;
    Ok(Some(("", String::new(), String::new(), &text[end + 1..])))
}

fn matching(text: &str, open: usize) -> Result<usize, String> {
    let mut depth = 0usize;
    for (index, ch) in text.char_indices().skip_while(|(i, _)| *i < open) {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(index);
                }
            }
            _ => {}
        }
    }
    Err("unbalanced braces".to_owned())
}

/// Depth-one statements of a block body: ended by `;`, or by the `}` that
/// closes a nested block (records, variants, inline interfaces).
fn statements(body: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    for ch in body.chars() {
        current.push(ch);
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1).ok_or("unbalanced braces")?;
                if depth == 0 {
                    out.push(current.trim().to_owned());
                    current.clear();
                }
            }
            ';' if depth == 0 => {
                out.push(current.trim().trim_end_matches(';').trim().to_owned());
                current.clear();
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err("unbalanced braces".to_owned());
    }
    if !current.trim().is_empty() {
        return Err(format!("statement without ';': {}", current.trim()));
    }
    Ok(out)
}

fn functions(body: &str) -> Result<Vec<Func>, String> {
    let mut funcs = Vec::new();
    for statement in statements(body)? {
        let Some((name, kind)) = statement.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let kind = kind.trim();
        if kind.starts_with("func") && !name.contains(char::is_whitespace) {
            funcs.push(Func {
                name: name.trim_start_matches('%').to_owned(),
                signature: kind.to_owned(),
            });
        }
    }
    Ok(funcs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &str = include_str!("../../../elastos/wit/elastos-bus-v1.wit");

    fn read(text: &str) -> Wit {
        let mut wit = Wit::default();
        wit.add(text).unwrap();
        wit
    }

    #[test]
    fn bus_v1_reads_as_one_run_once_world() {
        let wit = read(V1);
        let file = &wit.files[0];
        assert_eq!(
            file.worlds["product-capsule-v1"],
            ["lifecycle"],
            "imports are not exports"
        );
        let names = |i: &str| -> Vec<String> {
            file.interfaces[i].iter().map(|f| f.name.clone()).collect()
        };
        assert_eq!(names("lifecycle"), ["run"]);
        assert_eq!(names("capabilities"), ["request"]);
        assert_eq!(names("providers"), ["invoke"]);
        assert!(
            file.interfaces["types"].is_empty(),
            "records are not functions"
        );
        assert!(wit.exports_defining(&["start", "stop"]).is_empty());
    }

    #[test]
    fn two_files_keep_their_own_interfaces() {
        let mut wit = read(V1);
        wit.add("interface capabilities { submit: func(); }\ninterface resident { start: func(); stop: func(); }\nworld v2 { export resident; }\n")
            .unwrap();
        let capabilities: Vec<&[Func]> = wit.interfaces_named("capabilities").collect();
        assert_eq!(capabilities.len(), 2, "v1's interface is not hidden");
        assert_eq!(capabilities[0][0].name, "request");
        assert_eq!(capabilities[1][0].name, "submit");
        assert_eq!(wit.exports_defining(&["start", "stop"]).len(), 1);
        let mut cross = read(V1);
        cross
            .add("interface resident { start: func(); stop: func(); }\n")
            .unwrap();
        cross
            .add("world w { export elastos:bus/resident@2.0.0; }\n")
            .unwrap();
        assert_eq!(
            cross.exports_defining(&["start", "stop"]),
            [("w".to_owned(), "resident".to_owned())],
            "an export names an interface from another file"
        );
    }

    #[test]
    fn a_resident_export_is_found_in_every_form() {
        let named = "package elastos:bus@2.0.0;\ninterface resident {\n  use types.{bus-error};\n  start: func() -> result<_, bus-error>;\n  stop: func(reason: string);\n}\nworld resident-capsule {\n  import capabilities;\n  export resident;\n}\n";
        assert_eq!(
            read(named).exports_defining(&["start", "stop"]),
            [("resident-capsule".to_owned(), "resident".to_owned())]
        );
        let qualified = named.replace("export resident;", "export elastos:bus/resident@2.0.0;");
        assert_eq!(
            read(&qualified).exports_defining(&["start", "stop"]).len(),
            1
        );
        let inline = "world w {\n  export life: interface {\n    start: func();\n    stop: func(reason: string);\n  }\n}\n";
        assert_eq!(read(inline).exports_defining(&["start", "stop"]).len(), 1);
        let direct =
            "world w {\n  export start: func();\n  export stop: func(reason: string);\n}\n";
        assert_eq!(read(direct).exports_defining(&["start", "stop"]).len(), 1);
    }

    #[test]
    fn imports_comments_and_half_lifecycles_are_not_resident() {
        let imported =
            "interface resident { start: func(); stop: func(); }\nworld w { import resident; }\n";
        assert!(read(imported)
            .exports_defining(&["start", "stop"])
            .is_empty());
        let comment = "interface lifecycle {\n  /// start: func(); stop: func();\n  run: func();\n}\nworld w { export lifecycle; }\n";
        assert!(read(comment)
            .exports_defining(&["start", "stop"])
            .is_empty());
        let half = "interface lifecycle { start: func(); }\nworld w { export lifecycle; }\n";
        assert!(read(half).exports_defining(&["start", "stop"]).is_empty());
    }

    #[test]
    fn malformed_wit_is_refused() {
        let mut wit = Wit::default();
        assert!(wit.add("interface a { run: func();").is_err());
        assert!(wit.add("world w { export a }").is_err());
        assert!(wit.add("package a:b").is_err());
    }
}
