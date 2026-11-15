//! Cleanup rules: what to look for and how risky it is to remove.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Commands that can execute arbitrary things; never allowed as `clean_command`.
const COMMAND_DENYLIST: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "ksh",
    "csh",
    "tcsh",
    "env",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "nodejs",
    "php",
    "lua",
    "awk",
    "gawk",
    "xargs",
    "sudo",
    "doas",
    "su",
    "rm",
    "mv",
    "dd",
    "find",
    "eval",
    "exec",
    "nohup",
    "busybox",
    "curl",
    "wget",
    "ssh",
    "scp",
    "nc",
    "ncat",
    "git",
    "make",
    "cargo-run",
];

const BUILTIN: &str = include_str!("../rules/default.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    /// Regenerated automatically; removing only costs time or bandwidth.
    Safe,
    /// May hold something the user cares about. Never selected by "all".
    Review,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub risk: Risk,
    /// Glob patterns, each starting with `~/`.
    pub paths: Vec<String>,
    #[serde(default)]
    pub description: String,
    /// What happens after removal (how the data comes back).
    #[serde(default)]
    pub regrows: String,
    /// Process names (`/proc/<pid>/comm`); if any runs, the rule is skipped.
    #[serde(default)]
    pub skip_if_running: Vec<String>,
    /// The tool's own cleanup command (argv, no shell). Used instead of
    /// deleting files when its binary is on PATH.
    #[serde(default)]
    pub clean_command: Vec<String>,
}

#[derive(Deserialize)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

fn parse(text: &str, origin: &str) -> Result<Vec<Rule>> {
    let file: RuleFile =
        toml::from_str(text).with_context(|| format!("invalid rules in {origin}"))?;
    for r in &file.rule {
        validate(r).with_context(|| format!("rule '{}' in {origin}", r.id))?;
    }
    Ok(file.rule)
}

fn validate(r: &Rule) -> Result<()> {
    if r.id.trim().is_empty() {
        bail!("empty id");
    }
    if r.paths.is_empty() {
        bail!("no paths");
    }
    for p in &r.paths {
        let Some(rest) = p.strip_prefix("~/") else {
            bail!("path '{p}' must start with ~/");
        };
        let parts: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
        if parts.contains(&"..") {
            bail!("path '{p}' must not contain '..'");
        }
        if parts.len() < 2 || parts[0].contains(['*', '?', '[']) {
            bail!("path '{p}' must be at least two levels deep with a literal first component");
        }
    }
    if let Some(bin) = r.clean_command.first() {
        if bin.is_empty() || bin.contains('/') {
            bail!("clean_command must be a bare command name, got '{bin}'");
        }
        if COMMAND_DENYLIST.contains(&bin.as_str()) {
            bail!(
                "clean_command '{bin}' is not allowed (shells, interpreters and generic tools can run anything)"
            );
        }
    }
    Ok(())
}

pub fn builtin() -> Result<Vec<Rule>> {
    parse(BUILTIN, "built-in rules")
}

/// Built-in rules plus every `*.toml` in `user_dir`. A user rule with the
/// same id replaces the built-in one. User rules are untrusted input: they are
/// always `review` (never picked by "all") and labelled `[user rule]`; a file
/// that fails validation is skipped with a warning instead of aborting.
pub fn load(user_dir: Option<&Path>) -> Result<Vec<Rule>> {
    let mut rules = builtin()?;
    let Some(dir) = user_dir.filter(|d| d.is_dir()) else {
        return Ok(rules);
    };
    let mut files: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    for f in files {
        let parsed = std::fs::read_to_string(&f)
            .map_err(anyhow::Error::from)
            .and_then(|text| parse(&text, &f.display().to_string()));
        match parsed {
            Ok(user_rules) => {
                for mut r in user_rules {
                    r.risk = Risk::Review;
                    r.name = format!("{} [user rule]", r.name);
                    rules.retain(|x| x.id != r.id);
                    rules.push(r);
                }
            }
            Err(e) => eprintln!("warning: skipping {}: {e:#}", f.display()),
        }
    }
    Ok(rules)
}

/// Default user rules directory: `~/.config/dustoff/rules.d`.
pub fn default_user_dir() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("dustoff").join("rules.d"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn builtin_rules_parse_and_ids_are_unique() {
        let rules = builtin().unwrap();
        assert!(rules.len() >= 15);
        let ids: HashSet<_> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids.len(), rules.len(), "duplicate rule id");
    }

    #[test]
    fn rejects_absolute_and_parent_paths() {
        assert!(
            parse(
                "[[rule]]\nid='x'\nname='x'\ncategory='c'\nrisk='safe'\npaths=['/etc']",
                "t"
            )
            .is_err()
        );
        assert!(
            parse(
                "[[rule]]\nid='x'\nname='x'\ncategory='c'\nrisk='safe'\npaths=['~/../etc']",
                "t"
            )
            .is_err()
        );
    }

    #[test]
    fn user_rule_overrides_builtin_by_id() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.toml"),
            "[[rule]]\nid='thumbnails'\nname='mine'\ncategory='c'\nrisk='review'\npaths=['~/.cache/x']",
        )
        .unwrap();
        let rules = load(Some(dir.path())).unwrap();
        let t: Vec<_> = rules.iter().filter(|r| r.id == "thumbnails").collect();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].name, "mine [user rule]");
        assert_eq!(t[0].risk, Risk::Review);
    }

    fn one(extra: &str, paths: &str) -> String {
        format!("[[rule]]\nid='x'\nname='x'\ncategory='c'\nrisk='safe'\npaths=[{paths}]\n{extra}")
    }

    #[test]
    fn rejects_shallow_globby_unknown_keys_and_dangerous_commands() {
        assert!(parse(&one("", "'~/.cache/x'"), "t").is_ok());
        assert!(parse(&one("", "'~/*/*'"), "t").is_err());
        assert!(parse(&one("", "'~/.cache'"), "t").is_err());
        assert!(parse(&one("skip_if_runing=['a']", "'~/.cache/x'"), "t").is_err());
        assert!(parse(&one("clean_command=['sh','-c','id']", "'~/.cache/x'"), "t").is_err());
        assert!(parse(&one("clean_command=['/bin/true']", "'~/.cache/x'"), "t").is_err());
        assert!(
            parse(
                &one("clean_command=['uv','cache','clean']", "'~/.cache/x'"),
                "t"
            )
            .is_ok()
        );
    }

    #[test]
    fn bad_user_file_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.toml"), "not toml [[").unwrap();
        let rules = load(Some(dir.path())).unwrap();
        assert_eq!(rules.len(), builtin().unwrap().len());
    }
}
