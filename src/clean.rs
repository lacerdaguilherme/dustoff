//! Selection parsing and the (only) code path that removes anything.

use crate::rules::Risk;
use crate::safety::{clean_text, is_safe_target_depth, trusted_path_dirs, which};
use crate::scan::{Finding, comm_name, path_size};
use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

/// Parse a user selection against the shown table.
/// `a`/`all` = every *safe*, non-blocked item; `1,3-5` = explicit 1-based items
/// (the only way to pick `review` items); `q`/empty = nothing.
pub fn parse_selection(input: &str, items: &[Finding]) -> Result<Vec<usize>, String> {
    let s = input.trim().to_lowercase();
    if s.is_empty() || s == "q" || s == "quit" {
        return Ok(Vec::new());
    }
    if s == "a" || s == "all" {
        return Ok((0..items.len())
            .filter(|&i| items[i].risk == Risk::Safe && items[i].blocked_by.is_none())
            .collect());
    }
    let mut picked = Vec::new();
    for tok in s
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
    {
        let (lo, hi) = match tok.split_once('-') {
            Some((a, b)) => (a.parse::<usize>(), b.parse::<usize>()),
            None => (tok.parse::<usize>(), tok.parse::<usize>()),
        };
        let (Ok(lo), Ok(hi)) = (lo, hi) else {
            return Err(format!("can't read '{tok}'"));
        };
        if lo == 0 || hi < lo || hi > items.len() {
            return Err(format!("'{tok}' is outside 1-{}", items.len()));
        }
        for n in lo..=hi {
            if let Some(b) = &items[n - 1].blocked_by {
                return Err(format!("#{n} is blocked: {b}"));
            }
            if !picked.contains(&(n - 1)) {
                picked.push(n - 1);
            }
        }
    }
    Ok(picked)
}

#[cfg(unix)]
fn make_writable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for e in walkdir::WalkDir::new(p)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        if e.file_type().is_dir()
            && let Ok(m) = e.metadata()
        {
            let mut perm = m.permissions();
            perm.set_mode(perm.mode() | 0o700);
            let _ = std::fs::set_permissions(e.path(), perm);
        }
    }
}
#[cfg(not(unix))]
fn make_writable(_: &Path) {}

/// Remove a file, symlink (never its target) or directory tree. Directories
/// that tools make read-only (e.g. Go's module cache) are made writable and retried.
pub fn delete_path(p: &Path) -> io::Result<()> {
    let meta = p.symlink_metadata()?;
    if !meta.is_dir() {
        return std::fs::remove_file(p);
    }
    match std::fs::remove_dir_all(p) {
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            make_writable(p);
            std::fs::remove_dir_all(p)
        }
        other => other,
    }
}

/// Environment a tool command may see. Everything else (GOMODCACHE,
/// UV_CACHE_DIR, npm_config_*, ...) is dropped so the command cleans the
/// default location shown to the user, not somewhere redirected.
const COMMAND_ENV: &[&str] = &[
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
];

fn run_command(cmd: &[String], home: &Path) -> Result<()> {
    let bin =
        which(&cmd[0]).with_context(|| format!("'{}' not found on a trusted PATH", cmd[0]))?;
    let mut c = Command::new(bin);
    c.args(&cmd[1..])
        .current_dir(home)
        .env_clear()
        .stdin(Stdio::null());
    for k in COMMAND_ENV {
        if let Some(v) = std::env::var_os(k) {
            c.env(k, v);
        }
    }
    if let Ok(p) = std::env::join_paths(trusted_path_dirs()) {
        c.env("PATH", p);
    }
    let out = c.output()?;
    if out.status.success() {
        return Ok(());
    }
    let err = clean_text(&String::from_utf8_lossy(&out.stderr));
    let tail = err.lines().rev().take(3).collect::<Vec<_>>();
    let tail = tail.into_iter().rev().collect::<Vec<_>>().join(" | ");
    bail!("`{}` exited with {}: {tail}", cmd.join(" "), out.status)
}

#[derive(Debug)]
pub struct Outcome {
    pub path: std::path::PathBuf,
    pub freed: u64,
    pub error: Option<String>,
    pub warning: Option<String>,
}

fn all_paths(f: &Finding) -> impl Iterator<Item = &std::path::PathBuf> {
    std::iter::once(&f.path).chain(f.also_paths.iter())
}

fn total_size(f: &Finding) -> u64 {
    all_paths(f)
        .filter(|p| p.symlink_metadata().is_ok())
        .map(|p| path_size(p))
        .sum()
}

/// Execute the selected findings. A finding with a `via_command` runs the
/// tool's own command (cwd = home, minimal environment); the rest are deleted.
/// Everything is re-checked right before it is touched: path safety, and that
/// no guarded application started after the scan.
pub fn execute(selected: &[&Finding], home: &Path, running: &HashSet<String>) -> Vec<Outcome> {
    let mut out = Vec::new();
    for f in selected {
        let mut outcome = Outcome {
            path: f.path.clone(),
            freed: 0,
            error: None,
            warning: None,
        };
        if !f.privileged.is_empty() {
            // never run sudo: the caller prints the commands for the user
            outcome.warning = Some("needs root: run the commands printed below yourself".into());
            out.push(outcome);
            continue;
        }
        let depth = if f.category == "orphan-config" { 1 } else { 2 };
        if f.blocked_by.is_some() || !all_paths(f).all(|p| is_safe_target_depth(p, home, depth)) {
            outcome.error = Some("refused: blocked or outside the safe area".into());
            out.push(outcome);
            continue;
        }
        if let Some(g) = f.guards.iter().find(|g| running.contains(&comm_name(g))) {
            outcome.error = Some(format!("refused: '{g}' started since the scan"));
            out.push(outcome);
            continue;
        }
        let before = total_size(f);
        let result = match &f.via_command {
            Some(cmd) => run_command(cmd, home).map_err(|e| e.to_string()),
            None => all_paths(f)
                .map(|p| match delete_path(p) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                    other => other.map_err(|e| format!("{}: {}", e.kind(), e)),
                })
                .collect::<Result<Vec<()>, String>>()
                .map(|_| ()),
        };
        match result {
            Ok(()) => {
                outcome.freed = before.saturating_sub(total_size(f));
                if f.via_command.is_some() && outcome.freed == 0 {
                    outcome.warning = Some(
                        "the command succeeded but nothing was freed at the listed path (the tool may use another location)".into(),
                    );
                }
            }
            Err(e) => outcome.error = Some(e),
        }
        out.push(outcome);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(risk: Risk, blocked: bool) -> Finding {
        Finding {
            rule_id: "r".into(),
            name: "n".into(),
            category: "c".into(),
            risk,
            path: "/home/u/.cache/x".into(),
            bytes: 1,
            age_days: None,
            blocked_by: blocked.then(|| "busy".to_string()),
            regrows: String::new(),
            note: String::new(),
            via_command: None,
            also_paths: Vec::new(),
            guards: Vec::new(),
            privileged: Vec::new(),
        }
    }

    #[test]
    fn selection_all_skips_review_and_blocked() {
        let items = vec![
            item(Risk::Safe, false),
            item(Risk::Review, false),
            item(Risk::Safe, true),
        ];
        assert_eq!(parse_selection("a", &items).unwrap(), vec![0]);
    }

    #[test]
    fn selection_ranges_and_errors() {
        let items = vec![
            item(Risk::Safe, false),
            item(Risk::Review, false),
            item(Risk::Safe, false),
        ];
        assert_eq!(parse_selection("1,3", &items).unwrap(), vec![0, 2]);
        assert_eq!(parse_selection("2-3", &items).unwrap(), vec![1, 2]);
        assert_eq!(parse_selection("2", &items).unwrap(), vec![1]); // review items only by number
        assert!(parse_selection("4", &items).is_err());
        assert!(parse_selection("0", &items).is_err());
        assert!(parse_selection("x", &items).is_err());
        assert!(parse_selection("q", &items).unwrap().is_empty());
        assert!(parse_selection("", &items).unwrap().is_empty());
    }

    #[test]
    fn blocked_item_cannot_be_picked() {
        let items = vec![item(Risk::Safe, true)];
        assert!(parse_selection("1", &items).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn deletes_read_only_tree_and_never_follows_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("keep");
        std::fs::create_dir(&keep).unwrap();
        std::fs::write(keep.join("precious"), b"x").unwrap();

        let tree = dir.path().join("mod");
        std::fs::create_dir_all(tree.join("a/b")).unwrap();
        std::fs::write(tree.join("a/b/f"), b"x").unwrap();
        symlink(&keep, tree.join("link")).unwrap();
        std::fs::set_permissions(tree.join("a/b"), std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(tree.join("a"), std::fs::Permissions::from_mode(0o555)).unwrap();

        delete_path(&tree).unwrap();
        assert!(!tree.exists());
        assert!(
            keep.join("precious").exists(),
            "symlink target must survive"
        );
    }

    #[test]
    fn execute_refuses_paths_outside_home() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("a/b")).unwrap();
        let mut f = item(Risk::Safe, false);
        f.path = outside.path().join("a/b");
        let out = execute(&[&f], home.path(), &HashSet::new());
        assert!(out[0].error.is_some());
        assert!(f.path.exists(), "must not be deleted");
    }

    #[test]
    fn execute_refuses_when_guarded_app_started_after_scan() {
        let home = tempfile::tempdir().unwrap();
        let p = home.path().join(".cache/x");
        std::fs::create_dir_all(&p).unwrap();
        let mut f = item(Risk::Safe, false);
        f.path = p.clone();
        f.guards = vec!["chrome".into()];
        let running: HashSet<String> = ["chrome".to_string()].into();
        let out = execute(&[&f], home.path(), &running);
        assert!(
            out[0]
                .error
                .as_deref()
                .unwrap()
                .contains("started since the scan")
        );
        assert!(p.exists());
    }

    #[test]
    fn execute_deletes_and_reports_freed_and_treats_missing_as_gone() {
        let home = tempfile::tempdir().unwrap();
        let p = home.path().join(".cache/x");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("f"), vec![1u8; 10_000]).unwrap();
        let mut f = item(Risk::Safe, false);
        f.path = p.clone();
        let out = execute(&[&f], home.path(), &HashSet::new());
        assert!(out[0].error.is_none());
        assert!(out[0].freed >= 10_000);
        assert!(!p.exists());
        // second time: already gone, not a failure
        assert!(
            execute(&[&f], home.path(), &HashSet::new())[0]
                .error
                .is_none()
        );
    }

    #[test]
    fn command_that_frees_nothing_warns_and_failing_command_errors() {
        let home = tempfile::tempdir().unwrap();
        let p = home.path().join(".cache/x");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("f"), b"x").unwrap();
        let mut f = item(Risk::Safe, false);
        f.path = p.clone();
        f.via_command = Some(vec!["true".into()]);
        let out = execute(&[&f], home.path(), &HashSet::new());
        assert!(out[0].error.is_none() && out[0].warning.is_some());
        f.via_command = Some(vec!["false".into()]);
        assert!(
            execute(&[&f], home.path(), &HashSet::new())[0]
                .error
                .is_some()
        );
        f.via_command = Some(vec!["definitely-not-a-binary".into()]);
        assert!(
            execute(&[&f], home.path(), &HashSet::new())[0]
                .error
                .is_some()
        );
        assert!(p.exists());
    }

    #[test]
    fn privileged_items_are_never_executed_only_reported() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("keep"), b"x").unwrap();
        let mut f = item(Risk::Safe, false);
        f.path = outside.path().to_path_buf();
        f.privileged = vec![vec!["sudo".into(), "rm".into(), "-rf".into(), "/".into()]];
        let out = execute(&[&f], home.path(), &HashSet::new());
        assert!(out[0].error.is_none());
        assert!(out[0].warning.as_deref().unwrap().contains("needs root"));
        assert!(outside.path().join("keep").exists());
    }
}
