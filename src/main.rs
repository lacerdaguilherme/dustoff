use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use dustoff::clean::{execute, parse_selection};
use dustoff::fmt::{action, human_size, print_table};
use dustoff::safety::{self, clean_text, show_path};
use dustoff::scan::{Finding, dedupe_overlaps, running_processes, scan_rules};
use dustoff::{orphans, projects, rules};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Find and safely remove caches, build artifacts and orphaned app data.\nNothing is deleted without showing it first and asking you to confirm."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Select {
    /// Also look for build artifacts (node_modules, target, .terraform, ...) under PATH. Repeatable.
    #[arg(long = "projects", value_name = "PATH")]
    projects: Vec<PathBuf>,
    /// With --projects: only artifacts untouched for at least DAYS days.
    #[arg(long, value_name = "DAYS")]
    older_than: Option<u64>,
    /// Look for config/data directories of apps that are not installed.
    #[arg(long)]
    orphans: bool,
    /// With --orphans: skip unknown-owner dirs modified within the last DAYS days (assumed in use).
    #[arg(long, default_value_t = 30, value_name = "DAYS")]
    orphan_min_age: u64,
    /// Hide anything smaller than this many MiB.
    #[arg(long, default_value_t = 1, value_name = "MIB")]
    min_size: u64,
    /// Extra rules directory (default: ~/.config/dustoff/rules.d).
    #[arg(long, value_name = "DIR")]
    rules_dir: Option<PathBuf>,
    /// Never run an app's own cleanup command; delete files directly instead.
    #[arg(long)]
    no_commands: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show what could be cleaned. Read-only.
    Scan {
        #[command(flatten)]
        sel: Select,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Show what could be cleaned, then ask what to remove.
    Clean {
        #[command(flatten)]
        sel: Select,
        /// Show the plan and stop. Nothing is touched.
        #[arg(long)]
        dry_run: bool,
    },
    /// List the active rules.
    Rules {
        #[arg(long, value_name = "DIR")]
        rules_dir: Option<PathBuf>,
    },
}

fn home() -> Result<PathBuf> {
    safety::validated_home()
}

fn gather(sel: &Select) -> Result<Vec<Finding>> {
    let home = home()?;
    let user_dir = sel.rules_dir.clone().or_else(rules::default_user_dir);
    let rules = rules::load(user_dir.as_deref())?;
    if sel.older_than.is_some() && sel.projects.is_empty() {
        bail!("--older-than only applies together with --projects");
    }
    eprintln!("scanning...");
    let mut all = scan_rules(&rules, &home, &running_processes());
    for root in &sel.projects {
        let root = root
            .canonicalize()
            .with_context(|| format!("--projects {}: not a readable directory", root.display()))?;
        all.extend(projects::scan_projects(&root, &home, sel.older_than));
    }
    if sel.orphans {
        let apps = orphans::known_apps()?;
        let installed = orphans::Installed::detect(&home);
        if !installed.has_package_data() {
            eprintln!(
                "warning: no package manager answered (dpkg, flatpak, snap): 'not installed' verdicts are unreliable on this system"
            );
        }
        let covered: Vec<PathBuf> = all.iter().map(|f| f.path.clone()).collect();
        let orphan_hits =
            orphans::scan_orphans(&apps, &installed, &home, &covered, sel.orphan_min_age);
        // a known uninstalled app explains its dirs better than a generic cache rule does
        let high: Vec<PathBuf> = orphan_hits
            .iter()
            .filter(|f| f.rule_id == "orphan:high")
            .map(|f| f.path.clone())
            .collect();
        all.retain(|f| !high.iter().any(|h| f.path.starts_with(h)));
        all.extend(orphan_hits);
    }
    if sel.no_commands {
        all.iter_mut().for_each(|f| f.via_command = None);
    }
    let mut all = dedupe_overlaps(all);
    let min = sel.min_size.saturating_mul(1024 * 1024);
    all.retain(|f| f.bytes >= min);
    Ok(all)
}

fn totals(items: &[Finding]) -> (u64, u64, usize) {
    let all: u64 = items
        .iter()
        .filter(|f| f.blocked_by.is_none())
        .map(|f| f.bytes)
        .sum();
    let safe: u64 = items
        .iter()
        .filter(|f| f.blocked_by.is_none() && f.risk == rules::Risk::Safe)
        .map(|f| f.bytes)
        .sum();
    (
        all,
        safe,
        items.iter().filter(|f| f.blocked_by.is_some()).count(),
    )
}

fn prompt(msg: &str) -> Result<String> {
    print!("{msg}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line)
}

fn cmd_clean(sel: Select, dry_run: bool) -> Result<()> {
    let items = gather(&sel)?;
    if items.is_empty() {
        println!("Nothing to clean.");
        return Ok(());
    }
    print_table(&items);
    let (all, safe, blocked) = totals(&items);
    println!(
        "\nTotal {} ({} safe, rest needs review). {} item(s) skipped because the app is running.",
        human_size(all),
        human_size(safe),
        blocked
    );
    if dry_run {
        println!("\n[dry-run] Nothing was deleted.");
        return Ok(());
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!(
            "not an interactive terminal (stdin and stdout must be a TTY so you can see what you confirm): refusing to delete. Use --dry-run or `scan`."
        );
    }

    let picked = loop {
        let line = prompt(
            "\nWhat to remove? [a]ll safe items, numbers like 1,3-5 (review items only by number), [q]uit: ",
        )?;
        match parse_selection(&line, &items) {
            Ok(p) => break p,
            Err(e) => println!("  {e}"),
        }
    };
    if picked.is_empty() {
        println!("Nothing selected. Bye.");
        return Ok(());
    }

    println!("\nYou are about to:");
    let mut total = 0;
    for &i in &picked {
        let f = &items[i];
        println!(
            "  {:>10}  {}  {}",
            human_size(f.bytes),
            clean_text(&action(f)),
            show_path(&f.path)
        );
        total += f.bytes;
    }
    println!(
        "  {:>10}  TOTAL, {} item(s)",
        human_size(total),
        picked.len()
    );
    if prompt("\nType 'yes' to proceed: ")?.trim() != "yes" {
        println!("Aborted. Nothing was deleted.");
        return Ok(());
    }

    let selected: Vec<&Finding> = picked.iter().map(|&i| &items[i]).collect();
    let mut freed = 0;
    let mut failed = 0;
    let used_command = selected.iter().any(|f| f.via_command.is_some());
    for o in execute(&selected, &home()?, &running_processes()) {
        match o.error {
            None => {
                freed += o.freed;
                println!(
                    "  ok    {:>10}  {}",
                    human_size(o.freed),
                    show_path(&o.path)
                );
                if let Some(w) = o.warning {
                    println!("        warning: {w}");
                }
            }
            Some(e) => {
                failed += 1;
                println!("  FAIL  {}  {}", show_path(&o.path), clean_text(&e));
            }
        }
    }
    println!("\nFreed {}. {failed} failure(s).", human_size(freed));
    if failed > 0 && used_command {
        println!(
            "Tip: re-run with --no-commands to delete files directly instead of using the app's own command."
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Scan { sel, json } => {
            let items = gather(&sel)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else if items.is_empty() {
                println!("Nothing found.");
            } else {
                print_table(&items);
                let (all, safe, blocked) = totals(&items);
                println!(
                    "\nTotal {} ({} safe). {blocked} skipped (app running). Read-only: nothing was deleted.",
                    human_size(all),
                    human_size(safe)
                );
            }
        }
        Cmd::Clean { sel, dry_run } => cmd_clean(sel, dry_run)?,
        Cmd::Rules { rules_dir } => {
            let user_dir = rules_dir.or_else(rules::default_user_dir);
            for r in rules::load(user_dir.as_deref())? {
                let via = if r.clean_command.is_empty() {
                    String::new()
                } else {
                    format!("  via `{}`", r.clean_command.join(" "))
                };
                println!(
                    "{:<24} {:<8} {:<8} {}{}",
                    r.id,
                    r.category,
                    format!("{:?}", r.risk).to_lowercase(),
                    r.paths.join(", "),
                    via
                );
            }
        }
    }
    Ok(())
}
