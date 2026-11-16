//! Find config/data/cache directories of applications that are no longer installed.
//!
//! Two sources of truth:
//! * `rules/apps.toml` – known apps -> HIGH confidence when no install evidence exists.
//! * heuristic over `~/.config`, `~/.local/share`, `~/.cache`, `~/.var/app`, `~/snap`
//!   -> LOW confidence ("unknown owner"), because a directory name is only a hint.
//!
//! Orphan findings are always `review` risk: they hold settings and data.

use crate::rules::Risk;
use crate::safety::{expand, is_safe_target, is_safe_target_depth, trusted_path_dirs};
use crate::scan::{Finding, path_size};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

const APPS: &str = include_str!("../rules/apps.toml");

#[derive(Debug, Deserialize)]
pub struct App {
    pub id: String,
    pub name: String,
    pub dirs: Vec<String>,
    pub names: Vec<String>,
}

#[derive(Deserialize)]
struct AppFile {
    #[serde(default)]
    app: Vec<App>,
}

pub fn known_apps() -> Result<Vec<App>> {
    let f: AppFile = toml::from_str(APPS).context("invalid rules/apps.toml")?;
    Ok(f.app)
}

/// Lowercase, alphanumerics only.
fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Everything that proves something is installed on this machine.
#[derive(Debug, Default)]
pub struct Installed {
    /// (normalized, original, where it came from)
    entries: Vec<(String, String, &'static str)>,
}

impl Installed {
    pub fn add(&mut self, name: &str, source: &'static str) {
        let n = norm(name);
        if n.len() >= 2 {
            self.entries.push((n, name.to_string(), source));
        }
    }

    /// Does evidence exist for `key` (already normalized)? Exact match, or a
    /// prefix match when both sides are long enough to be meaningful.
    pub fn find(&self, key: &str) -> Option<String> {
        self.entries
            .iter()
            .find(|(n, _, _)| {
                n == key
                    || (key.len() >= 5 && n.starts_with(key))
                    || (n.len() >= 5 && key.starts_with(n.as_str()))
            })
            .map(|(_, orig, src)| format!("{orig} ({src})"))
    }

    /// True when at least one package manager (deb, flatpak, snap) answered.
    /// Without it, "not installed" verdicts are unreliable.
    pub fn has_package_data(&self) -> bool {
        self.entries
            .iter()
            .any(|(_, _, s)| matches!(*s, "deb package" | "flatpak" | "snap"))
    }

    pub fn detect(home: &Path) -> Installed {
        let mut inst = Installed::default();
        for line in cmd_lines("/usr/bin/dpkg-query", &["-W", "-f", "${Package}\n"]) {
            inst.add(&line, "deb package");
        }
        for line in cmd_lines(
            "/usr/bin/flatpak",
            &["list", "--app", "--columns=application"],
        ) {
            inst.add(&line, "flatpak");
            if let Some(last) = line.rsplit('.').next() {
                inst.add(last, "flatpak");
            }
        }
        for line in cmd_lines("/usr/bin/snap", &["list"]).into_iter().skip(1) {
            if let Some(name) = line.split_whitespace().next() {
                inst.add(name, "snap");
            }
        }
        for dir in trusted_path_dirs() {
            for name in list_names(&dir) {
                inst.add(&name, "binary in PATH");
            }
        }
        for name in list_names(Path::new("/opt")) {
            inst.add(&name, "/opt");
        }
        for dir in [
            home.join("Applications"),
            home.join("Aplicativos"),
            home.join(".local/bin"),
        ] {
            for name in list_names(&dir) {
                let stem = name.split(['-', '_']).next().unwrap_or(&name).to_string();
                inst.add(&stem, "AppImage/local bin");
                inst.add(&name, "AppImage/local bin");
            }
        }
        let desktop_dirs = [
            PathBuf::from("/usr/share/applications"),
            PathBuf::from("/var/lib/flatpak/exports/share/applications"),
            home.join(".local/share/applications"),
            home.join(".local/share/flatpak/exports/share/applications"),
        ];
        for dir in desktop_dirs {
            for name in list_names(&dir) {
                if let Some(stem) = name.strip_suffix(".desktop") {
                    inst.add(stem, ".desktop file");
                }
            }
        }
        inst
    }
}

/// Run a fixed absolute-path command with a clean environment; empty when absent.
fn cmd_lines(bin: &str, args: &[&str]) -> Vec<String> {
    if !Path::new(bin).is_file() {
        return Vec::new();
    }
    Command::new(bin)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn list_names(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Names that belong to the desktop/OS, not to a removable app. Never reported.
const PROTECTED: &[&str] = &[
    "dconf",
    "pulse",
    "pipewire",
    "wireplumber",
    "systemd",
    "autostart",
    "gtk-2.0",
    "gtk-3.0",
    "gtk-4.0",
    "fontconfig",
    "ibus",
    "menus",
    "enchant",
    "goa-1.0",
    "gvfs",
    "gvfs-metadata",
    "nautilus",
    "applications",
    "icons",
    "fonts",
    "themes",
    "trash",
    "keyrings",
    "flatpak",
    "gnome-shell",
    "mime",
    "desktop-directories",
    "color",
    "backgrounds",
    "sounds",
    "xdg-desktop-portal",
    "evolution",
    "tracker3",
    "tracker",
    "common",
    "mesa_shader_cache",
    "mesa_shader_cache_db",
    "gstreamer-1.0",
    "babl",
    "gegl-0.4",
    "pki",
    "cups",
    "procps",
    "environment.d",
    "user-tmpfiles.d",
    "xdg-terminals",
    "update-notifier",
    "ubuntu-report",
    "session-migration",
    "gnome-session",
    "gnome-control-center",
    "evince",
    "libreoffice",
    "xorg",
    "wallpapers",
    "shell",
    "recently-used",
    "dustoff",
    "snapd",
    "modem-manager",
    "tmp",
    "libvirt",
    "mpv",
    "kdeconnect",
    "baloo",
];

fn is_protected(name: &str) -> bool {
    let n = name.to_lowercase();
    PROTECTED.contains(&n.as_str())
}

/// Candidate normalized keys for a directory name.
fn keys_for(name: &str) -> Vec<String> {
    let base = name.trim_start_matches('.');
    let mut keys = vec![norm(base)];
    if base.contains('.')
        && let Some(last) = base.rsplit('.').next()
    {
        keys.push(norm(last));
    }
    for suf in ["-desktop", "-app", "-nodejs", "-browser", "-client"] {
        if let Some(s) = base.to_lowercase().strip_suffix(suf) {
            keys.push(norm(s));
        }
    }
    keys.retain(|k| k.len() >= 2);
    keys.sort();
    keys.dedup();
    keys
}

fn age_days(p: &Path) -> Option<u64> {
    let mut newest = p.metadata().ok()?.modified().ok()?;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.filter_map(Result::ok) {
            if let Ok(m) = e.metadata().and_then(|m| m.modified()) {
                newest = newest.max(m);
            }
        }
    }
    SystemTime::now()
        .duration_since(newest)
        .ok()
        .map(|d| d.as_secs() / 86_400)
}

fn finding(app: &str, confidence: &str, path: PathBuf, note: String) -> Finding {
    let bytes = path_size(&path);
    Finding {
        rule_id: format!("orphan:{confidence}"),
        name: format!("{app} data"),
        category: "orphan-config".into(),
        risk: Risk::Review,
        age_days: age_days(&path),
        path,
        bytes,
        blocked_by: None,
        regrows: "settings and data of an app that is not installed".into(),
        note,
        via_command: None,
        also_paths: Vec::new(),
        guards: Vec::new(),
        privileged: Vec::new(),
    }
}

/// `covered`: paths already reported by cleanup rules (heuristic hits that
/// overlap them are dropped). `min_age_days`: low-confidence hits touched more
/// recently than this are assumed to be in use and dropped.
pub fn scan_orphans(
    apps: &[App],
    installed: &Installed,
    home: &Path,
    covered: &[PathBuf],
    min_age_days: u64,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut claimed: HashSet<PathBuf> = HashSet::new();

    // 1) known apps: HIGH confidence
    for app in apps {
        let dirs: Vec<PathBuf> = app.dirs.iter().flat_map(|p| expand(p, home)).collect();
        for d in &dirs {
            claimed.insert(d.clone());
        }
        let evidence = app.names.iter().find_map(|n| installed.find(&norm(n)));
        if evidence.is_some() {
            continue;
        }
        for d in dirs
            .into_iter()
            .filter(|d| is_safe_target_depth(d, home, 1))
        {
            out.push(finding(
                &app.name,
                "high",
                d,
                format!("{} is not installed (checked deb, flatpak, snap, PATH, /opt, AppImages, .desktop)", app.name),
            ));
        }
    }

    // 2) heuristic: LOW confidence, only inside the standard app-data roots
    let roots = [
        home.join(".config"),
        home.join(".local/share"),
        home.join(".cache"),
        home.join(".var/app"),
        home.join("snap"),
    ];
    for root in roots {
        let Ok(rd) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in rd.filter_map(Result::ok) {
            let path = e.path();
            let Ok(meta) = path.symlink_metadata() else {
                continue;
            };
            if !meta.is_dir() || claimed.contains(&path) || !is_safe_target(&path, home) {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            if is_protected(&name)
                || out.iter().any(|f| f.path == path)
                || covered
                    .iter()
                    .any(|c| c.starts_with(&path) || path.starts_with(c))
            {
                continue;
            }
            if age_days(&path).is_some_and(|a| a < min_age_days) {
                continue;
            }
            let keys = keys_for(&name);
            if keys.iter().any(|k| installed.find(k).is_some()) {
                continue;
            }
            out.push(finding(
                &name,
                "low",
                path,
                format!("unknown owner: no package, binary, flatpak, snap, /opt dir, AppImage or .desktop matches '{name}'"),
            ));
        }
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.bytes));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(id: &str, dirs: &[&str], names: &[&str]) -> App {
        App {
            id: id.into(),
            name: id.into(),
            dirs: dirs.iter().map(|s| s.to_string()).collect(),
            names: names.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn mk(home: &Path, rel: &str) {
        std::fs::create_dir_all(home.join(rel)).unwrap();
        std::fs::write(home.join(rel).join("f"), vec![0u8; 100]).unwrap();
    }

    #[test]
    fn builtin_apps_parse() {
        let apps = known_apps().unwrap();
        assert!(apps.len() >= 20);
        assert!(
            apps.iter()
                .all(|a| a.dirs.iter().all(|d| d.starts_with("~/")))
        );
    }

    #[test]
    fn known_app_uninstalled_is_high_confidence_and_installed_is_not_reported() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        mk(home, ".config/Cursor");
        mk(home, ".config/Slack");
        let apps = vec![
            app("cursor", &["~/.config/Cursor"], &["cursor"]),
            app("slack", &["~/.config/Slack"], &["slack"]),
        ];
        let mut inst = Installed::default();
        inst.add("slack", "deb package");
        let found = scan_orphans(&apps, &inst, home, &[], 0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "orphan:high");
        assert!(found[0].path.ends_with(".config/Cursor"));
        assert_eq!(found[0].risk, Risk::Review);
    }

    #[test]
    fn heuristic_flags_unknown_and_spares_installed_and_protected() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        mk(home, ".config/ghost-app");
        mk(home, ".config/google-chrome-beta");
        mk(home, ".config/dconf");
        mk(home, ".var/app/org.foo.Bar");
        let mut inst = Installed::default();
        inst.add("google-chrome-beta", "deb package");
        let found = scan_orphans(&[], &inst, home, &[], 0);
        let paths: Vec<_> = found
            .iter()
            .map(|f| f.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(paths.contains(&"ghost-app".to_string()), "{paths:?}");
        assert!(paths.contains(&"org.foo.Bar".to_string()), "{paths:?}");
        assert!(!paths.contains(&"dconf".to_string()));
        assert!(!paths.contains(&"google-chrome-beta".to_string()));
        assert!(found.iter().all(|f| f.rule_id == "orphan:low"));
    }

    #[test]
    fn matching_is_punctuation_insensitive_with_prefix_for_long_names() {
        let mut inst = Installed::default();
        inst.add("google-chrome-stable", "deb package");
        inst.add("go", "binary in PATH");
        assert!(inst.find(&norm("Google_Chrome")).is_some());
        assert!(inst.find("googlechromestable").is_some());
        assert!(
            inst.find("goland").is_none(),
            "short evidence must not prefix-match"
        );
        assert!(inst.find("gog").is_none());
    }

    #[test]
    fn heuristic_skips_rule_covered_and_recently_used_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        mk(home, ".cache/huggingface");
        mk(home, ".cache/mozilla/firefox");
        mk(home, ".cache/fresh-thing");
        let inst = Installed::default();
        let covered = vec![
            home.join(".cache/huggingface"),
            home.join(".cache/mozilla/firefox"),
        ];
        let found = scan_orphans(&[], &inst, home, &covered, 0);
        let names: Vec<_> = found
            .iter()
            .map(|f| f.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["fresh-thing"], "{names:?}");
        // just created => counts as "in use" with a 30 day threshold
        assert!(scan_orphans(&[], &inst, home, &covered, 30).is_empty());
    }
}
