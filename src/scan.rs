//! Turn rules into concrete findings (path + size), read-only.

use crate::rules::{Risk, Rule};
use crate::safety::{expand, is_safe_target, which};
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
    #[serde(serialize_with = "ser_path")]
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
    /// Other paths of the same rule that `via_command` cleans in the same run.
    #[serde(serialize_with = "ser_paths")]
    pub also_paths: Vec<PathBuf>,
    /// Process names that must not be running when this item is removed.
    pub guards: Vec<String>,
    /// Commands that need root. dustoff never runs `sudo`; it prints these
    /// for the user to run.
    pub privileged: Vec<Vec<String>>,
}

fn ser_path<S: serde::Serializer>(p: &Path, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&p.to_string_lossy())
}

fn ser_paths<S: serde::Serializer>(ps: &[PathBuf], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(ps.iter().map(|p| p.to_string_lossy()))
}

/// Disk usage of a path in bytes (allocated blocks on Unix, hard links counted
/// once), without following symlinks. Unreadable entries count as 0.
pub fn path_size(p: &Path) -> u64 {
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut total = 0;
    for e in WalkDir::new(p)
        .follow_links(false)
        .follow_root_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        let Ok(m) = e.metadata() else { continue };
        if !m.is_file() {
            continue;
        }
        total += allocated(&m, &mut seen);
    }
    total
}

#[cfg(unix)]
fn allocated(m: &std::fs::Metadata, seen: &mut HashSet<(u64, u64)>) -> u64 {
    use std::os::unix::fs::MetadataExt;
    if m.nlink() > 1 && !seen.insert((m.dev(), m.ino())) {
        return 0;
    }
    m.blocks() * 512
}

#[cfg(not(unix))]
fn allocated(m: &std::fs::Metadata, _: &mut HashSet<(u64, u64)>) -> u64 {
    m.len()
}

/// Apply `--no-commands`: items cleaned by a tool command fall back to direct
/// deletion, except package-manager items (`~/.local/share/flatpak` holds
/// installed apps, never to be deleted as a path), which are dropped instead.
pub fn apply_no_commands(items: Vec<Finding>) -> Vec<Finding> {
    items
        .into_iter()
        .filter(|f| !(f.category == "package-manager" && f.via_command.is_some()))
        .map(|mut f| {
            f.via_command = None;
            f
        })
        .collect()
}

/// Drop findings nested inside (or equal to) another finding's path, so sizes
/// are not counted twice and nothing is deleted twice. The outer one wins.
pub fn dedupe_overlaps(mut items: Vec<Finding>) -> Vec<Finding> {
    items.sort_by_key(|f| f.path.components().count());
    let mut kept: Vec<Finding> = Vec::new();
    for f in items {
        let covered = kept.iter().any(|k| {
            std::iter::once(&k.path)
                .chain(k.also_paths.iter())
                .any(|kp| f.path.starts_with(kp))
        });
        if !covered {
            kept.push(f);
        }
    }
    kept.sort_by_key(|a| std::cmp::Reverse(a.bytes));
    kept
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

/// `/proc/<pid>/comm` is truncated to 15 bytes; compare the same way.
pub fn comm_name(n: &str) -> String {
    n.chars().take(15).collect()
}

pub fn scan_rules(rules: &[Rule], home: &Path, running: &HashSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    for rule in rules {
        let via = (!rule.clean_command.is_empty() && which(&rule.clean_command[0]).is_some())
            .then(|| rule.clean_command.clone());
        let blocker = rule
            .skip_if_running
            .iter()
            .find(|n| running.contains(&comm_name(n)))
            .cloned();
        let mut hits: Vec<(PathBuf, u64)> = Vec::new();
        for pat in &rule.paths {
            for path in expand(pat, home) {
                if !is_safe_target(&path, home) {
                    continue;
                }
                let bytes = path_size(&path);
                if bytes > 0 {
                    hits.push((path, bytes));
                }
            }
        }
        // A tool command cleans everything the tool owns in one run, so it
        // is shown (and selected) as a single item covering all its paths.
        let groups: Vec<Vec<(PathBuf, u64)>> = if via.is_some() && !hits.is_empty() {
            vec![hits]
        } else {
            hits.into_iter().map(|h| vec![h]).collect()
        };
        for group in groups {
            let bytes = group.iter().map(|(_, b)| b).sum();
            let mut paths = group.into_iter().map(|(p, _)| p);
            let path = paths.next().expect("group is never empty");
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
                also_paths: paths.collect(),
                guards: rule.skip_if_running.clone(),
                privileged: Vec::new(),
            });
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
        assert!(f[0].bytes >= 1000);

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

    fn finding_at(path: PathBuf, bytes: u64) -> Finding {
        Finding {
            rule_id: "r".into(),
            name: "n".into(),
            category: "c".into(),
            risk: Risk::Safe,
            path,
            bytes,
            age_days: None,
            blocked_by: None,
            regrows: String::new(),
            note: String::new(),
            via_command: None,
            also_paths: Vec::new(),
            guards: Vec::new(),
            privileged: Vec::new(),
        }
    }

    #[test]
    fn overlapping_findings_are_counted_once_outer_wins() {
        let items = vec![
            finding_at("/h/.cargo/registry/src/x/target".into(), 5),
            finding_at("/h/.cargo/registry/src".into(), 10),
            finding_at("/h/.cache/a".into(), 7),
            finding_at("/h/.cache/a".into(), 7),
        ];
        let kept = dedupe_overlaps(items);
        let paths: Vec<_> = kept.iter().map(|f| f.path.to_str().unwrap()).collect();
        assert_eq!(paths, vec!["/h/.cargo/registry/src", "/h/.cache/a"]);
    }

    #[test]
    fn command_rules_become_one_item_covering_all_paths() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        for p in [".cache/t", ".cache/u"] {
            std::fs::create_dir_all(home.join(p)).unwrap();
            std::fs::write(home.join(p).join("f"), b"x").unwrap();
        }
        let mut r = rule(&[]);
        r.paths = vec!["~/.cache/t".into(), "~/.cache/u".into()];
        r.clean_command = vec!["true".into()];
        let f = scan_rules(&[r], home, &HashSet::new());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].also_paths.len(), 1);
        assert!(f[0].via_command.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_rule_path_is_not_sized_through_the_link() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("big"), vec![0u8; 100_000]).unwrap();
        std::fs::create_dir_all(dir.path().join(".cache")).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join(".cache/t")).unwrap();
        assert_eq!(path_size(&dir.path().join(".cache/t")), 0);
        assert!(scan_rules(&[rule(&[])], dir.path(), &HashSet::new()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn hard_links_are_counted_once() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), vec![0u8; 50_000]).unwrap();
        std::fs::hard_link(dir.path().join("a"), dir.path().join("b")).unwrap();
        let one = path_size(&dir.path().join("a"));
        assert_eq!(path_size(dir.path()), one);
    }

    #[test]
    fn no_commands_drops_package_manager_items_and_keeps_rule_items_as_deletes() {
        let mut flatpak = finding_at("/h/.local/share/flatpak".into(), 9);
        flatpak.category = "package-manager".into();
        flatpak.via_command = Some(vec!["flatpak".into()]);
        let mut cache = finding_at("/h/.cache/uv".into(), 5);
        cache.via_command = Some(vec!["uv".into()]);
        let kept = apply_no_commands(vec![flatpak, cache]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].path.to_str().unwrap(), "/h/.cache/uv");
        assert!(kept[0].via_command.is_none());
    }
}
