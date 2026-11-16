//! Human-readable output.

use crate::rules::Risk;
use crate::safety::{clean_text, show_path};
use crate::scan::Finding;

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    // 1023.95 so that one-decimal rounding never prints "1024.0 KiB"
    while v >= 1023.95 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// What dustoff will do for this finding if it is selected.
pub fn action(f: &Finding) -> String {
    if !f.privileged.is_empty() {
        return "needs root: prints the commands for you to run".to_string();
    }
    match &f.via_command {
        Some(cmd) => clean_text(&format!("run `{}`", cmd.join(" "))),
        None => "delete".to_string(),
    }
}

pub fn print_table(findings: &[Finding]) {
    println!(
        "{:>3}  {:>10}  {:<6}  {:<44}  ACTION / PATH",
        "#", "SIZE", "RISK", "WHAT"
    );
    for (i, f) in findings.iter().enumerate() {
        let risk = match f.risk {
            Risk::Safe => "safe",
            Risk::Review => "review",
        };
        let mut what = clean_text(&f.name);
        if what.chars().count() > 44 {
            what = what.chars().take(43).collect::<String>() + "…";
        }
        println!(
            "{:>3}  {:>10}  {:<6}  {:<44}  {}  {}",
            i + 1,
            human_size(f.bytes),
            risk,
            what,
            action(f),
            show_path(&f.path)
        );
        if let Some(b) = &f.blocked_by {
            println!(
                "{:>3}  {:>10}  {:<6}  {:<44}  SKIPPED: {}",
                "",
                "",
                "",
                "",
                clean_text(b)
            );
        }
        if let Some(a) = f.age_days {
            println!(
                "{:>3}  {:>10}  {:<6}  {:<44}  last modified {a} days ago",
                "", "", "", ""
            );
        }
        if !f.note.is_empty() {
            println!(
                "{:>3}  {:>10}  {:<6}  {:<44}  note: {}",
                "",
                "",
                "",
                "",
                clean_text(&f.note)
            );
        }
    }
}

/// Quote one argument for copy-paste into a POSIX shell.
pub fn shell_quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c));
    if plain {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

pub fn command_line(argv: &[String]) -> String {
    clean_text(
        &argv
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_shell_arguments() {
        assert_eq!(shell_quote("--revision=3580"), "--revision=3580");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn sizes() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }
}
