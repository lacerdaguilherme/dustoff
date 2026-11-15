//! Find rebuildable build artifacts next to project files
//! (`node_modules` beside `package.json`, `target` beside `Cargo.toml`, ...).

use crate::rules::Risk;
use crate::safety::is_safe_target;
use crate::scan::{Finding, path_size};
use std::path::Path;
use std::time::SystemTime;
use walkdir::WalkDir;

enum Marker {
    File(&'static str),
    Ext(&'static str),
    Any,
}

struct Kind {
    dir: &'static str,
    name: &'static str,
    markers: &'static [Marker],
    risk: Risk,
    regrows: &'static str,
}

const KINDS: &[Kind] = &[
    Kind {
        dir: "node_modules",
        name: "node_modules",
        markers: &[Marker::File("package.json")],
        risk: Risk::Safe,
        regrows: "`npm/pnpm/yarn install`",
    },
    Kind {
        dir: "target",
        name: "Rust target",
        markers: &[Marker::File("Cargo.toml")],
        risk: Risk::Safe,
        regrows: "`cargo build`",
    },
    Kind {
        dir: ".terraform",
        name: "Terraform providers",
        markers: &[Marker::Ext("tf")],
        risk: Risk::Safe,
        regrows: "`terraform init`",
    },
    Kind {
        dir: ".venv",
        name: "Python virtualenv",
        markers: &[
            Marker::File("pyproject.toml"),
            Marker::File("requirements.txt"),
        ],
        risk: Risk::Review,
        regrows: "recreate the venv and reinstall",
    },
    Kind {
        dir: "__pycache__",
        name: "Python bytecode",
        markers: &[Marker::Any],
        risk: Risk::Safe,
        regrows: "regenerated on import",
    },
    Kind {
        dir: ".next",
        name: "Next.js build",
        markers: &[Marker::File("package.json")],
        risk: Risk::Safe,
        regrows: "`next build`",
    },
    Kind {
        dir: "build",
        name: "Gradle build",
        markers: &[
            Marker::File("build.gradle"),
            Marker::File("build.gradle.kts"),
        ],
        risk: Risk::Safe,
        regrows: "`gradle build`",
    },
];

fn marker_present(parent: &Path, m: &Marker) -> bool {
    match m {
        Marker::Any => true,
        Marker::File(f) => parent.join(f).is_file(),
        Marker::Ext(ext) => std::fs::read_dir(parent)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .any(|e| e.path().extension().is_some_and(|x| x == *ext))
            })
            .unwrap_or(false),
    }
}

/// Days since the project was last touched: newest mtime among the project
/// directory and its direct entries other than the artifact itself (an
/// incremental build does not change the artifact directory's own mtime).
fn project_age_days(project: &Path, artifact: &Path) -> Option<u64> {
    let mut newest = project.metadata().ok()?.modified().ok()?;
    for e in std::fs::read_dir(project).ok()?.filter_map(Result::ok) {
        if e.path() == artifact {
            continue;
        }
        if let Ok(m) = e.metadata().and_then(|m| m.modified()) {
            newest = newest.max(m);
        }
    }
    SystemTime::now()
        .duration_since(newest)
        .ok()
        .map(|d| d.as_secs() / 86_400)
}

/// Scan `root` for artifacts; descends into nothing it already matched and
/// never enters `.git`.
pub fn scan_projects(root: &Path, home: &Path, older_than_days: Option<u64>) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut it = WalkDir::new(root).follow_links(false).into_iter();
    while let Some(entry) = it.next() {
        let Ok(e) = entry else { continue };
        if !e.file_type().is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy();
        if name == ".git" {
            it.skip_current_dir();
            continue;
        }
        let Some(parent) = e.path().parent() else {
            continue;
        };
        let Some(kind) = KINDS
            .iter()
            .find(|k| k.dir == name && k.markers.iter().any(|m| marker_present(parent, m)))
        else {
            continue;
        };
        it.skip_current_dir();
        if !is_safe_target(e.path(), home) {
            continue;
        }
        let age = project_age_days(parent, e.path());
        // unknown age never passes an explicit --older-than filter
        if older_than_days.is_some_and(|min| age.is_none_or(|a| a < min)) {
            continue;
        }
        let bytes = path_size(e.path());
        if bytes == 0 {
            continue;
        }
        out.push(Finding {
            rule_id: format!("project:{}", kind.dir),
            name: format!(
                "{} ({})",
                kind.name,
                parent
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ),
            category: "project".into(),
            risk: kind.risk,
            path: e.path().to_path_buf(),
            bytes,
            age_days: age,
            blocked_by: None,
            regrows: kind.regrows.into(),
            note: String::new(),
            via_command: None,
            also_paths: Vec::new(),
            guards: Vec::new(),
        });
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.bytes));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(p: &Path, bytes: usize) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, vec![1u8; bytes]).unwrap();
    }

    #[test]
    fn detects_artifacts_only_next_to_their_marker() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        // real project
        touch(&home.join("w/app/package.json"), 2);
        touch(&home.join("w/app/node_modules/x/index.js"), 500);
        touch(&home.join("w/infra/main.tf"), 2);
        touch(&home.join("w/infra/.terraform/p/bin"), 800);
        // lookalikes without marker: must be ignored
        touch(&home.join("w/notes/node_modules/y"), 999);
        touch(&home.join("w/notes/target/z"), 999);

        let found = scan_projects(&home.join("w"), home, None);
        let ids: Vec<_> = found.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(found.len(), 2, "{ids:?}");
        assert!(ids.contains(&"project:node_modules"));
        assert!(ids.contains(&"project:.terraform"));
        assert!(found[0].bytes >= 800);
    }

    #[test]
    fn older_than_filters_fresh_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        touch(&home.join("w/app/Cargo.toml"), 2);
        touch(&home.join("w/app/target/debug/a"), 100);
        assert_eq!(scan_projects(&home.join("w"), home, Some(0)).len(), 1);
        assert!(scan_projects(&home.join("w"), home, Some(30)).is_empty());
    }

    #[test]
    fn does_not_descend_into_git_or_matched_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        touch(&home.join("w/app/package.json"), 2);
        touch(&home.join("w/app/node_modules/dep/package.json"), 2);
        touch(
            &home.join("w/app/node_modules/dep/node_modules/inner/f"),
            300,
        );
        touch(&home.join("w/app/.git/hooks/node_modules/f"), 300);
        let found = scan_projects(&home.join("w"), home, None);
        assert_eq!(found.len(), 1);
    }
}
