//! Selection parsing and the (only) code path that removes anything.

use crate::rules::Risk;
use crate::safety::is_safe_target;
use crate::scan::{Finding, path_size};
use anyhow::{Result, bail};
use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::process::Command;

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

fn run_command(cmd: &[String]) -> Result<()> {
    let out = Command::new(&cmd[0]).args(&cmd[1..]).output()?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    let tail: String = err
        .lines()
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" | ");
    bail!("`{}` exited with {}: {tail}", cmd.join(" "), out.status)
}

#[derive(Debug)]
pub struct Outcome {
    pub path: std::path::PathBuf,
    pub freed: u64,
    pub error: Option<String>,
}

/// Execute the selected findings. Findings with a `via_command` run that
/// command once (shared by every finding of the same rule); the rest are
/// deleted. Re-checks safety right before touching anything.
pub fn execute(selected: &[&Finding], home: &Path) -> Vec<Outcome> {
    let mut ran: HashSet<Vec<String>> = HashSet::new();
    let mut cmd_err: std::collections::HashMap<Vec<String>, String> = Default::default();
    let mut out = Vec::new();
    for f in selected {
        let mut outcome = Outcome {
            path: f.path.clone(),
            freed: 0,
            error: None,
        };
        if f.blocked_by.is_some() || !is_safe_target(&f.path, home) {
            outcome.error = Some("refused: blocked or outside the safe area".into());
            out.push(outcome);
            continue;
        }
        let before = path_size(&f.path);
        let result = match &f.via_command {
            Some(cmd) => {
                if ran.insert(cmd.clone())
                    && let Err(e) = run_command(cmd)
                {
                    cmd_err.insert(cmd.clone(), e.to_string());
                }
                match cmd_err.get(cmd) {
                    Some(e) => Err(e.clone()),
                    None => Ok(()),
                }
            }
            None => delete_path(&f.path).map_err(|e| e.to_string()),
        };
        match result {
            Ok(()) => {
                outcome.freed = before.saturating_sub(if f.path.exists() {
                    path_size(&f.path)
                } else {
                    0
                })
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
    fn execute_refuses_unsafe_paths() {
        let mut f = item(Risk::Safe, false);
        f.path = "/etc".into();
        let out = execute(&[&f], Path::new("/home/u"));
        assert!(out[0].error.is_some());
        assert!(Path::new("/etc").exists());
    }
}
