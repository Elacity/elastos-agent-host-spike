//! The seatbelt profiles in `capsules/*/confine.sb` are the oracle. This
//! parser reads those lines. It does not widen a rule.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allow {
    ExecProvider,
    /// `data_only` is the model profile's `file-read-data`. The did and wallet
    /// profiles use `file-read*`. Linux grants neither: a Landlock rule on `/`
    /// would cover the whole tree.
    RootRead {
        data_only: bool,
    },
    SysctlRead,
    ReadParent,
    StorageRoot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub version: String,
    pub deny_default: bool,
    pub deny_network: bool,
    pub allows: Vec<Allow>,
    pub allow_lines: Vec<String>,
}

pub fn parse_profile(text: &str) -> Result<Profile, String> {
    let mut version = None;
    let mut deny_default = false;
    let mut deny_network = false;
    let mut allows = Vec::new();
    let mut allow_lines = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let rule =
            take_form(line).ok_or_else(|| format!("line {}: not a profile form", index + 1))?;
        if rule.starts_with("(version ") {
            version = Some(
                rule.trim_start_matches("(version ")
                    .trim_end_matches(')')
                    .trim()
                    .to_string(),
            );
        } else if rule == "(deny default)" {
            deny_default = true;
        } else if rule == "(deny network*)" {
            deny_network = true;
        } else if rule == "(allow default)" {
            return Err("the profile grants allow default".to_string());
        } else if rule.starts_with("(allow ") {
            allows.push(classify(&rule)?);
            allow_lines.push(rule);
        } else if rule.starts_with("(deny ") {
            return Err(format!("unknown denial: {rule}"));
        } else {
            return Err(format!("unknown profile form: {rule}"));
        }
    }
    let version = version.ok_or("the profile has no version")?;
    if version != "1" {
        return Err(format!("the profile version is {version}"));
    }
    if !deny_default {
        return Err("the profile has no deny default".to_string());
    }
    if !deny_network {
        return Err("the profile has no network denial".to_string());
    }
    require_one(
        &allows,
        |a| matches!(a, Allow::ExecProvider),
        "process-exec",
    )?;
    require_one(
        &allows,
        |a| matches!(a, Allow::RootRead { .. }),
        "root read",
    )?;
    require_one(&allows, |a| matches!(a, Allow::SysctlRead), "sysctl-read")?;
    require_one(
        &allows,
        |a| matches!(a, Allow::ReadParent),
        "STORAGE_PARENT",
    )?;
    require_one(&allows, |a| matches!(a, Allow::StorageRoot), "STORAGE_ROOT")?;
    Ok(Profile {
        version,
        deny_default,
        deny_network,
        allows,
        allow_lines,
    })
}

fn require_one(allows: &[Allow], pred: impl Fn(&Allow) -> bool, name: &str) -> Result<(), String> {
    let count = allows.iter().filter(|a| pred(a)).count();
    if count != 1 {
        return Err(format!("the profile must name {name} once, found {count}"));
    }
    Ok(())
}

fn classify(rule: &str) -> Result<Allow, String> {
    if rule.contains("process-exec") && rule.contains("PROVIDER_EXECUTABLE") {
        return Ok(Allow::ExecProvider);
    }
    if rule.contains("sysctl-read") {
        if rule != "(allow sysctl-read)" {
            return Err(format!("sysctl-read is wider than the baseline: {rule}"));
        }
        return Ok(Allow::SysctlRead);
    }
    if rule.contains("STORAGE_PARENT") {
        if rule != "(allow file-read* (literal (param \"STORAGE_PARENT\")))" {
            return Err(format!(
                "STORAGE_PARENT is wider than a literal read: {rule}"
            ));
        }
        return Ok(Allow::ReadParent);
    }
    if rule.contains("STORAGE_ROOT") {
        if rule != "(allow file-read* file-write* (subpath (param \"STORAGE_ROOT\")))" {
            return Err(format!(
                "STORAGE_ROOT is not the shared storage rule: {rule}"
            ));
        }
        return Ok(Allow::StorageRoot);
    }
    if rule.contains("(literal \"/\")") {
        if rule == "(allow file-read-data (literal \"/\"))" {
            return Ok(Allow::RootRead { data_only: true });
        }
        if rule == "(allow file-read* (literal \"/\"))" {
            return Ok(Allow::RootRead { data_only: false });
        }
        return Err(format!("the root read is wider than the baseline: {rule}"));
    }
    Err(format!("unknown allow: {rule}"))
}

fn strip_comment(line: &str) -> &str {
    let trimmed = line.trim_start();
    if trimmed.starts_with(";;") {
        ""
    } else {
        line
    }
}

fn take_form(line: &str) -> Option<String> {
    let start = line.find('(')?;
    let bytes = line.as_bytes();
    let mut depth = 0;
    for (offset, byte) in bytes.iter().enumerate().skip(start) {
        if *byte == b'(' {
            depth += 1;
        } else if *byte == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(line[start..=offset].to_string());
            }
        }
    }
    None
}

pub fn allow_rules(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if text[i..].starts_with("(allow ") {
            if let Some(rule) = take_form(&text[i..]) {
                i += rule.len();
                out.push(rule);
                continue;
            }
        }
        i += 1;
    }
    out
}
