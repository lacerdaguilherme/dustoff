//! Guards that run before anything is deleted. Everything dustoff removes
//! must pass `is_safe_target`.

use std::path::{Component, Path, PathBuf};

/// Credentials and key material: never a target, whatever a rule says.
const PROTECTED_PREFIXES: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".azure",
    ".docker",
    ".pki",
    ".password-store",
    ".mozilla",
    ".thunderbird",
    ".config/gcloud",
    ".config/gh",
    ".config/glab",
    ".config/rclone",
    ".local/share/keyrings",
    ".local/share/gnome-keyring",
    ".local/share/password-store",
];

/// A target is deletable only when, after resolving symlinks in its parent
/// directories, it lives strictly inside `home`, at least two levels deep
/// (so `~`, `~/Documents`, `~/.config` themselves are never targets), is not
/// credential material, and the path has no `..` components. The final
/// component may itself be a symlink: it is removed, never followed.
///
/// ponytail: a parent swapped for a symlink between this check and the delete
/// is narrowed (execute() re-checks) but not eliminated; fd-based deletion is
/// tracked in the issue tracker.
pub fn is_safe_target(path: &Path, home: &Path) -> bool {
    is_safe_target_depth(path, home, 2)
}

/// Same as [`is_safe_target`] with a custom minimum depth below home. Depth 1
/// is only for dot-directories owned by a known application (`~/.wine`).
pub fn is_safe_target_depth(path: &Path, home: &Path, min_depth: usize) -> bool {
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return false;
    }
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return false;
    };
    let (Ok(canon_parent), Ok(canon_home)) = (parent.canonicalize(), home.canonicalize()) else {
        return false;
    };
    let canon = canon_parent.join(name);
    match canon.strip_prefix(&canon_home) {
        Ok(rel) => {
            rel.components().count() >= min_depth.max(1)
                && !PROTECTED_PREFIXES.iter().any(|p| rel.starts_with(p))
        }
        Err(_) => false,
    }
}

/// Replace control and bidi-override characters so a hostile file name cannot
/// forge what the terminal shows.
pub fn clean_text(s: &str) -> String {
    s.chars()
        .map(|c| {
            let bidi = matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}');
            if c.is_control() || bidi { '?' } else { c }
        })
        .collect()
}

pub fn show_path(p: &Path) -> String {
    clean_text(&p.to_string_lossy())
}

/// PATH entries that are absolute; empty or relative entries (which mean "the
/// current directory") are dropped.
pub fn trusted_path_dirs() -> Vec<PathBuf> {
    std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .filter(|d| d.is_absolute())
                .collect()
        })
        .unwrap_or_default()
}

/// Locate a bare command name on the trusted PATH.
pub fn which(bin: &str) -> Option<PathBuf> {
    if bin.is_empty() || bin.contains('/') {
        return None;
    }
    trusted_path_dirs()
        .into_iter()
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

/// The home directory, refusing situations where deleting "inside home" is
/// not safe: running as root, `HOME=/`, relative HOME, or a home owned by
/// someone else.
#[cfg(unix)]
pub fn validated_home() -> anyhow::Result<PathBuf> {
    use anyhow::{Context, bail};
    use std::os::unix::fs::MetadataExt;
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let me = rustix::process::geteuid().as_raw();
    if me == 0 {
        bail!("refusing to run as root: dustoff only cleans your own home directory");
    }
    if !home.is_absolute() || home == Path::new("/") {
        bail!("unsafe home directory: {}", home.display());
    }
    let owner = std::fs::metadata(&home)?.uid();
    if me != owner {
        bail!(
            "home directory {} is not owned by the current user",
            home.display()
        );
    }
    Ok(home)
}

#[cfg(not(unix))]
pub fn validated_home() -> anyhow::Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))
}

/// Expand a `~/...` glob pattern into existing paths.
pub fn expand(pattern: &str, home: &Path) -> Vec<PathBuf> {
    let Some(rest) = pattern.strip_prefix("~/") else {
        return Vec::new();
    };
    let Some(home_str) = home.to_str() else {
        return Vec::new();
    };
    // escape glob metacharacters that may appear in the home path itself
    let full = format!("{}/{rest}", glob::Pattern::escape(home_str));
    glob::glob(&full)
        .map(|it| {
            it.filter_map(Result::ok)
                .filter(|p| p.symlink_metadata().is_ok())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkdirs(home: &Path, rel: &str) -> PathBuf {
        let p = home.join(rel);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn safe_target_rules() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        assert!(is_safe_target(&mkdirs(home, ".cache/uv"), home));
        assert!(!is_safe_target(home, home));
        assert!(!is_safe_target(&mkdirs(home, "Documents"), home));
        assert!(!is_safe_target(Path::new("/etc/passwd"), home));
        assert!(!is_safe_target(&home.join(".cache/../../x"), home));
        assert!(!is_safe_target(Path::new(".cache/uv"), home));
        let other = tempfile::tempdir().unwrap();
        assert!(!is_safe_target(&mkdirs(other.path(), ".cache/uv"), home));
    }

    #[test]
    fn credentials_are_never_targets() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        for rel in [
            ".ssh/keys",
            ".gnupg/x",
            ".aws/sso",
            ".config/gcloud/creds",
            ".local/share/keyrings/a",
        ] {
            assert!(!is_safe_target(&mkdirs(home, rel), home), "{rel}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_parent_pointing_outside_home_is_refused() {
        use std::os::unix::fs::symlink;
        let home_dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let home = home_dir.path();
        std::fs::create_dir_all(outside.path().join("Cache")).unwrap();
        mkdirs(home, ".config");
        symlink(outside.path(), home.join(".config/Code")).unwrap();
        // ~/.config/Code/Cache resolves to <outside>/Cache
        assert!(!is_safe_target(&home.join(".config/Code/Cache"), home));
        // a symlink *inside* home pointing inside home is fine
        let inner = mkdirs(home, "real/sub");
        symlink(home.join("real"), home.join("alias")).unwrap();
        assert!(is_safe_target(&home.join("alias/sub"), home));
        assert!(inner.exists());
        // the symlink itself, as last component, is a valid target (removed, not followed)
        symlink(outside.path(), home.join(".config/link")).unwrap();
        assert!(is_safe_target(&home.join(".config/link"), home));
    }

    #[test]
    fn clean_text_strips_control_and_bidi() {
        assert_eq!(clean_text("a\x1b[2Jb\r\nc\u{202E}d"), "a?[2Jb??c?d");
        assert_eq!(clean_text("plain ~/.cache"), "plain ~/.cache");
    }

    #[test]
    fn which_ignores_relative_and_slashed_names() {
        assert!(which("../x").is_none());
        assert!(which("/bin/sh").is_none());
        assert!(which("").is_none());
        assert!(which("sh").is_some());
    }

    #[test]
    fn expand_matches_globs_and_skips_missing() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::create_dir_all(home.join(".config/chrome/Default/Cache")).unwrap();
        std::fs::create_dir_all(home.join(".config/chrome/Profile 1/Cache")).unwrap();
        let got = expand("~/.config/chrome/*/Cache", home);
        assert_eq!(got.len(), 2);
        assert!(expand("~/nope/*", home).is_empty());
        assert!(expand("/abs/path", home).is_empty());
    }
}
