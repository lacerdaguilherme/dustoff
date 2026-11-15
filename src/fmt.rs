//! Human-readable output.

use crate::rules::Risk;
use crate::scan::Finding;

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
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
    match &f.via_command {
        Some(cmd) => format!("run `{}`", cmd.join(" ")),
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
        let mut what = f.name.clone();
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
            f.path.display()
        );
        if let Some(b) = &f.blocked_by {
            println!("{:>3}  {:>10}  {:<6}  {:<44}  SKIPPED: {b}", "", "", "", "");
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
                "", "", "", "", f.note
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }
}
