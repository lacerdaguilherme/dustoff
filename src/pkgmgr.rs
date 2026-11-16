//! Flatpak and Snap leftovers: unused runtimes/extensions and old revisions.
//!
//! These live outside `$HOME` and need root, so dustoff computes what could go
//! and how much it weighs, then prints the exact commands for the user to run.
//! It never calls `sudo` itself. The user-level Flatpak installation needs no
//! root and is cleaned through Flatpak's own command like any other tool.

use crate::rules::Risk;
use crate::safety::clean_text;
use crate::scan::{Finding, path_size};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const FLATPAK: &str = "/usr/bin/flatpak";
const SCRIPT: &str = "/usr/bin/script";
const SNAP: &str = "/usr/bin/snap";
const SNAP_DIR: &str = "/var/lib/snapd/snaps";
const PREVIEW_TIMEOUT: Duration = Duration::from_secs(30);

fn run(bin: &str, args: &[&str]) -> Option<String> {
    if !Path::new(bin).is_file() {
        return None;
    }
    let out = Command::new(bin)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Remove ANSI escapes and carriage returns from pty output.
fn strip_tty(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for n in chars.by_ref() {
                        if n.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            }
            '\r' => {}
            _ => out.push(c),
        }
    }
    out
}

/// Refs `flatpak uninstall --unused` would remove, read from its confirmation
/// table (`  1.  org.freedesktop.Platform   25.08   r`).
pub fn parse_unused_refs(output: &str) -> Vec<(String, String)> {
    strip_tty(output)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let numbered = f.first().is_some_and(|n| {
                n.strip_suffix('.')
                    .is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
            });
            (numbered && f.len() == 4).then(|| (f[1].to_string(), f[2].to_string()))
        })
        .collect()
}

/// Flatpak sizes are decimal ("118.1 MB"); under `LC_ALL=C` the space between
/// number and unit comes out as `?`, so split on the first non-numeric char.
pub fn parse_size(s: &str) -> u64 {
    let s = s.trim();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == ','))
        .unwrap_or(s.len());
    let n: f64 = s[..split].replace(',', ".").parse().unwrap_or(0.0);
    let unit = s[split..].trim_matches(|c: char| !c.is_ascii_alphabetic());
    let mult = match unit {
        "bytes" | "B" => 1.0,
        "kB" | "KB" => 1e3,
        "MB" => 1e6,
        "GB" => 1e9,
        "TB" => 1e12,
        _ => 0.0,
    };
    (n * mult) as u64
}

/// `flatpak uninstall --unused` has no dry-run, and `--noninteractive` would
/// really remove. So it runs on a pty (`script`) fed only "n" answers: the
/// confirmation table is printed, every question is answered no, nothing changes.
fn preview_unused(installation: &str) -> Option<String> {
    if !Path::new(FLATPAK).is_file() || !Path::new(SCRIPT).is_file() {
        return None;
    }
    let mut child = Command::new(SCRIPT)
        .args([
            "-qefc",
            &format!("{FLATPAK} uninstall --unused --{installation}"),
            "/dev/null",
        ])
        .env_clear()
        .env("LC_ALL", "C")
        .env("TERM", "dumb")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let pid = child.id();
    let mut stdin = child.stdin.take()?;
    // watchdog: never hang the scan
    std::thread::spawn(move || {
        std::thread::sleep(PREVIEW_TIMEOUT);
        let _ = Command::new("/bin/kill")
            .args(["-9", &pid.to_string()])
            .status();
    });
    let answers = "n\n".repeat(200);
    let _ = stdin.write_all(answers.as_bytes());
    drop(stdin);
    let out = child.wait_with_output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `(id, branch)` -> installed bytes for one installation.
fn flatpak_sizes(installation: &str) -> HashMap<(String, String), u64> {
    let inst = format!("--{installation}");
    let Some(out) = run(
        FLATPAK,
        &["list", "--all", &inst, "--columns=application,branch,size"],
    ) else {
        return HashMap::new();
    };
    out.lines()
        .filter_map(|l| {
            let mut p = l.splitn(3, '\t');
            Some((
                (p.next()?.trim().to_string(), p.next()?.trim().to_string()),
                parse_size(p.next()?),
            ))
        })
        .collect()
}

fn base(rule_id: &str, name: String, path: PathBuf, bytes: u64, note: String) -> Finding {
    Finding {
        rule_id: rule_id.into(),
        name,
        category: "package-manager".into(),
        risk: Risk::Safe,
        path,
        bytes,
        age_days: None,
        blocked_by: None,
        regrows: "reinstalled automatically if something needs it again".into(),
        note,
        via_command: None,
        also_paths: Vec::new(),
        guards: Vec::new(),
        privileged: Vec::new(),
    }
}

pub fn scan_flatpak(home: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for installation in ["system", "user"] {
        let Some(preview) = preview_unused(installation) else {
            continue;
        };
        let refs = parse_unused_refs(&preview);
        if refs.is_empty() {
            continue;
        }
        let sizes = flatpak_sizes(installation);
        let bytes: u64 = refs
            .iter()
            .map(|r| sizes.get(r).copied().unwrap_or(0))
            .sum();
        let list = refs
            .iter()
            .map(|(id, br)| format!("{id}//{br}"))
            .collect::<Vec<_>>()
            .join(", ");
        let note = clean_text(&format!("{} unused ref(s): {list}", refs.len()));
        if installation == "system" {
            let mut f = base(
                "flatpak:unused-system",
                "Unused Flatpak runtimes (system)".into(),
                PathBuf::from("/var/lib/flatpak"),
                bytes,
                note,
            );
            f.privileged = vec![vec![
                "sudo".into(),
                "flatpak".into(),
                "uninstall".into(),
                "--unused".into(),
            ]];
            out.push(f);
        } else {
            let mut f = base(
                "flatpak:unused-user",
                "Unused Flatpak runtimes (user)".into(),
                home.join(".local/share/flatpak"),
                bytes,
                note,
            );
            f.via_command = Some(
                ["flatpak", "uninstall", "--unused", "--user", "-y"]
                    .map(String::from)
                    .to_vec(),
            );
            out.push(f);
        }
    }
    out
}

/// `(name, revision)` of every disabled (old) snap revision.
pub fn parse_snap_disabled(list_all: &str) -> Vec<(String, String)> {
    list_all
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 6 && f.last().is_some_and(|n| n.contains("disabled")))
                .then(|| (f[0].to_string(), f[2].to_string()))
        })
        .collect()
}

pub fn scan_snap() -> Vec<Finding> {
    let Some(list) = run(SNAP, &["list", "--all"]) else {
        return Vec::new();
    };
    let old = parse_snap_disabled(&list);
    if old.is_empty() {
        return Vec::new();
    }
    let bytes = old
        .iter()
        .map(|(n, r)| path_size(&Path::new(SNAP_DIR).join(format!("{n}_{r}.snap"))))
        .sum();
    let names = old
        .iter()
        .map(|(n, r)| format!("{n} r{r}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut f = base(
        "snap:old-revisions",
        format!("Old snap revisions ({})", old.len()),
        PathBuf::from(SNAP_DIR),
        bytes,
        clean_text(&format!(
            "disabled revisions kept for rollback: {names}. Tip: `sudo snap set system refresh.retain=2` keeps fewer from now on"
        )),
    );
    f.privileged = old
        .iter()
        .map(|(n, r)| {
            ["sudo", "snap", "remove", n, &format!("--revision={r}")]
                .map(String::from)
                .to_vec()
        })
        .collect();
    vec![f]
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREVIEW: &str = "n\r\nInfo: applications using the extension org.freedesktop.Platform.GL.nvidia-595-84 branch 1.4:\r\n   com.github.PintaProject.Pinta\r\nReally remove? [y/n]: \r\n\r\n        ID                                           Branch            Op\r\n 1.     org.freedesktop.Platform                     25.08             r\r\n 2.     org.freedesktop.Platform.Locale              25.08             r\r\n 3.     org.kde.Platform                             6.10              r\r\n\r\nProceed with these changes to the system installation? [Y/n]: ";

    #[test]
    fn parses_unused_ref_table_and_ignores_prompts() {
        let refs = parse_unused_refs(PREVIEW);
        assert_eq!(
            refs,
            vec![
                ("org.freedesktop.Platform".to_string(), "25.08".to_string()),
                (
                    "org.freedesktop.Platform.Locale".to_string(),
                    "25.08".to_string()
                ),
                ("org.kde.Platform".to_string(), "6.10".to_string()),
            ]
        );
        assert!(parse_unused_refs("Nothing unused to uninstall\n").is_empty());
    }

    #[test]
    fn strips_ansi_escapes() {
        assert_eq!(strip_tty("a\u{1b}[1mb\u{1b}[0m\r\n"), "ab\n");
    }

    #[test]
    fn parses_flatpak_sizes() {
        assert_eq!(parse_size("118.1 MB"), 118_100_000);
        assert_eq!(parse_size("1,5 GB"), 1_500_000_000);
        assert_eq!(parse_size("900 bytes"), 900);
        assert_eq!(parse_size("118.1?MB"), 118_100_000);
        assert_eq!(parse_size("1.0\u{202f}GB"), 1_000_000_000);
        assert_eq!(parse_size(""), 0);
    }

    #[test]
    fn finds_only_disabled_snap_revisions() {
        let list = "Name  Version  Rev  Tracking  Publisher  Notes\nchromium  157  3583  latest/stable  canonical**  -\nchromium  156  3580  latest/stable  canonical**  disabled\ncore22  2026  2437  latest/stable  canonical**  base,disabled\nsnapd  2.78  28332  latest/stable  canonical**  snapd\n";
        assert_eq!(
            parse_snap_disabled(list),
            vec![
                ("chromium".to_string(), "3580".to_string()),
                ("core22".to_string(), "2437".to_string())
            ]
        );
    }
}
