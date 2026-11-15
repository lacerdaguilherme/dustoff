//! Turn rules into concrete findings (path + size), read-only.

use crate::rules::{Risk, Rule};
use crate::safety::{expand, is_safe_target};
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub name: String,
    pub category: String,
    pub risk: Risk,
    pub path: PathBuf,
    pub bytes: u64,
    /// Days since last modification (project artifacts only).
    pub age_days: Option<u64>,
    /// Set when the item must not be deleted right now (e.g. app is running).
    pub blocked_by: Option<String>,
    pub regrows: String,
    /// Explanation shown to the user (e.g. why something looks orphaned).
    pub note: String,
    /// Tool command that will be run instead of deleting the path.
    pub via_command: Option<Vec<String>>,
}

/// Locate `bin` on PATH.
pub fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

/// Total size of a path without following symlinks. Unreadable entries count as 0.
pub fn path_size(p: &Path) -> u64 {
    WalkDir::new(p)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

/// Names of running processes (Linux: `/proc/<pid>/comm`). Empty elsewhere.
pub fn running_processes() -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.filter_map(Result::ok) {
            if let Ok(s) = std::fs::read_to_string(e.path().join("comm")) {
                set.insert(s.trim().to_string());
            }
        }
    }
    set
}

pub fn scan_rules(rules: &[Rule], home: &Path, running: &HashSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    for rule in rules {
        let via = (!rule.clean_command.is_empty() && which(&rule.clean_command[0]).is_some())
            .then(|| rule.clean_command.clone());
        let blocker = rule
            .skip_if_running
            .iter()
            .find(|n| running.contains(*n))
            .cloned();
        for pat in &rule.paths {
            for path in expand(pat, home) {
                if !is_safe_target(&path, home) {
                    continue;
                }
                let bytes = path_size(&path);
                if bytes == 0 {
                    continue;
                }
                out.push(Finding {
                    rule_id: rule.id.clone(),
                    name: rule.name.clone(),
                    category: rule.category.clone(),
                    risk: rule.risk,
                    path,
                    bytes,
                    age_days: None,
                    blocked_by: blocker.as_ref().map(|b| format!("'{b}' is running")),
                    regrows: rule.regrows.clone(),
                    note: rule.description.clone(),
                    via_command: via.clone(),
                });
            }
        }
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.bytes));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(running_guard: &[&str]) -> Rule {
        Rule {
            id: "t".into(),
            name: "t".into(),
            category: "c".into(),
            risk: Risk::Safe,
            paths: vec!["~/.cache/t".into()],
            description: String::new(),
            regrows: String::new(),
            skip_if_running: running_guard.iter().map(|s| s.to_string()).collect(),
            clean_command: Vec::new(),
        }
    }

    #[test]
    fn finds_sizes_and_skips_empty() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::create_dir_all(home.join(".cache/t")).unwrap();
        std::fs::write(home.join(".cache/t/a"), vec![0u8; 1000]).unwrap();
        let f = scan_rules(&[rule(&[])], home, &HashSet::new());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].bytes, 1000);

        std::fs::remove_file(home.join(".cache/t/a")).unwrap();
        assert!(scan_rules(&[rule(&[])], home, &HashSet::new()).is_empty());
    }

    #[test]
    fn running_app_blocks_finding() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::create_dir_all(home.join(".cache/t")).unwrap();
        std::fs::write(home.join(".cache/t/a"), b"x").unwrap();
        let running: HashSet<String> = ["chrome".to_string()].into();
        let f = scan_rules(&[rule(&["chrome"])], home, &running);
        assert_eq!(f[0].blocked_by.as_deref(), Some("'chrome' is running"));
    }
}
