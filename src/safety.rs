//! Guards that run before anything is deleted. Everything dustoff removes
//! must pass `is_safe_target`.

use std::path::{Component, Path, PathBuf};

/// A target is deletable only when it lives strictly inside `home`, at least
/// two levels deep (so `~`, `~/Documents`, `~/.config` themselves are never
/// targets), with no `..` components.
pub fn is_safe_target(path: &Path, home: &Path) -> bool {
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return false;
    }
    match path.strip_prefix(home) {
        Ok(rel) => rel.components().count() >= 2,
        Err(_) => false,
    }
}

/// Expand a `~/...` glob pattern into existing paths.
pub fn expand(pattern: &str, home: &Path) -> Vec<PathBuf> {
    let Some(rest) = pattern.strip_prefix("~/") else {
        return Vec::new();
    };
    let full = home.join(rest);
    let Some(s) = full.to_str() else {
        return Vec::new();
    };
    glob::glob(s)
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

    #[test]
    fn safe_target_rules() {
        let home = Path::new("/home/u");
        assert!(is_safe_target(Path::new("/home/u/.cache/uv"), home));
        assert!(!is_safe_target(Path::new("/home/u"), home));
        assert!(!is_safe_target(Path::new("/home/u/Documents"), home));
        assert!(!is_safe_target(Path::new("/etc/passwd"), home));
        assert!(!is_safe_target(Path::new("/home/u/.cache/../../x"), home));
        assert!(!is_safe_target(Path::new("/home/user2/.cache/uv"), home));
        assert!(!is_safe_target(Path::new(".cache/uv"), home));
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
