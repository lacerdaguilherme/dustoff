//! Cleanup rules: what to look for and how risky it is to remove.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::Path;

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
        if !p.starts_with("~/") {
            bail!("path '{p}' must start with ~/");
        }
        if p.split('/').any(|c| c == "..") {
            bail!("path '{p}' must not contain '..'");
        }
    }
    Ok(())
}

pub fn builtin() -> Result<Vec<Rule>> {
    parse(BUILTIN, "built-in rules")
}

/// Built-in rules plus every `*.toml` in `user_dir`; a user rule with the
/// same id replaces the built-in one.
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
        let text = std::fs::read_to_string(&f)?;
        for r in parse(&text, &f.display().to_string())? {
            rules.retain(|x| x.id != r.id);
            rules.push(r);
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
        assert_eq!(t[0].name, "mine");
    }
}
