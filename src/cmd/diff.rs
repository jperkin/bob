/*
 * Copyright (c) 2026 Jonathan Perkin <jonathan@perkin.org.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

use std::collections::HashMap;

use anyhow::{Result, bail};

use bob::db::{BuildDiff, Database, DiffEntry};
use bob::try_println;

use super::{Col, Formatter, OutputFormat};

const DIFF_COLUMNS: &[(&str, &str)] = &[
    ("pkgname", "Package name (current, or previous if absent)"),
    ("pkgpath", "Package path in pkgsrc"),
    ("breaks", "Number of packages broken by this failure"),
    ("stage", "Build stage that failed (current)"),
    ("stage_prev", "Build stage that failed (previous)"),
    ("outcome", "Outcome (current)"),
    ("outcome_prev", "Outcome (previous)"),
    ("pkgname_prev", "Package name (previous)"),
];

const DEFAULT_COLUMNS: &[&str] = &["pkgname", "pkgpath", "breaks", "stage"];

#[derive(Debug, clap::Args)]
#[command(after_long_help = diff_after_help())]
pub struct DiffArgs {
    /// First build ID (baseline). Default: second most recent
    pub build1: Option<String>,
    /// Second build ID. Default: most recent
    pub build2: Option<String>,
    /// List available build IDs
    #[arg(short, long)]
    pub list: bool,
    /// Show all changes, not just failures and fixes
    #[arg(short, long)]
    pub all: bool,
    /// Columns to display (comma-separated, see --help for full list)
    #[arg(short = 'o', value_delimiter = ',')]
    pub columns: Option<Vec<String>>,
}

fn diff_after_help() -> String {
    let width = DIFF_COLUMNS.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
    let mut help = String::from("Columns:\n");
    for (name, desc) in DIFF_COLUMNS {
        help.push_str(&format!("  {:<width$}  {}\n", name, desc));
    }
    help.push_str(&format!("\nDefault columns: {}", DEFAULT_COLUMNS.join(",")));
    help
}

pub fn run(db: &Database, args: DiffArgs) -> Result<()> {
    if args.list {
        return list_builds(db);
    }

    let col_names: Vec<&str> = match &args.columns {
        Some(cols) => {
            for c in cols {
                if !DIFF_COLUMNS.iter().any(|(n, _)| *n == c.as_str()) {
                    let valid: Vec<&str> = DIFF_COLUMNS.iter().map(|(n, _)| *n).collect();
                    bail!(
                        "Unknown column '{}'. Valid columns: {}",
                        c,
                        valid.join(", ")
                    );
                }
            }
            cols.iter().map(|s| s.as_str()).collect()
        }
        None => DEFAULT_COLUMNS.to_vec(),
    };

    let (build1_id, build2_id) = match (args.build1, args.build2) {
        (Some(b1), Some(b2)) => (b1, b2),
        (Some(b1), None) => {
            let builds = db.list_history_builds()?;
            if builds.is_empty() {
                bail!("No builds in history");
            }
            (b1, builds[0].build_id.clone())
        }
        (None, Some(_)) => {
            bail!("Specify both build IDs, or none for the two most recent");
        }
        (None, None) => {
            let builds = db.list_history_builds()?;
            if builds.len() < 2 {
                bail!("Need at least two builds to compare. Use --list to see available builds.");
            }
            (builds[1].build_id.clone(), builds[0].build_id.clone())
        }
    };

    let diff = db.compute_build_diff(&build1_id, &build2_id)?;

    let breaks: HashMap<String, usize> = match bob::Scheduler::new(db) {
        Ok(sched) => sched
            .iter()
            .map(|sp| (sp.pkg.to_string(), sp.dep_count))
            .collect(),
        Err(_) => HashMap::new(),
    };

    print_diff(&diff, &breaks, args.all, &col_names);
    Ok(())
}

fn list_builds(db: &Database) -> Result<()> {
    let builds = db.list_history_builds()?;
    if builds.is_empty() {
        println!("No builds in history.");
        return Ok(());
    }

    let mut fmt = Formatter::new(vec![
        Col::new("build_id", bob::Align::Left),
        Col::new("packages", bob::Align::Right),
        Col::new("succeeded", bob::Align::Right),
        Col::new("failed", bob::Align::Right),
    ]);
    for b in &builds {
        fmt.push(vec![
            b.build_id.clone(),
            b.package_count.to_string(),
            b.succeeded.to_string(),
            b.failed.to_string(),
        ]);
    }
    fmt.print(OutputFormat::Table, false);
    Ok(())
}

fn format_col(e: &DiffEntry, col: &str, breaks: &HashMap<String, usize>) -> String {
    match col {
        "pkgname" => e
            .build2_pkgname
            .as_deref()
            .or(e.build1_pkgname.as_deref())
            .unwrap_or("-")
            .to_string(),
        "pkgpath" => e.pkgpath.clone(),
        "breaks" => get_breaks(e, breaks).to_string(),
        "stage" => match e.build2_outcome {
            Some(bob::PackageStateKind::Success) | Some(bob::PackageStateKind::UpToDate) => {
                String::new()
            }
            _ => e
                .build2_stage
                .map(|s| s.into_str().to_string())
                .unwrap_or_default(),
        },
        "stage_prev" => e
            .build1_stage
            .map(|s| s.into_str().to_string())
            .unwrap_or_default(),
        "outcome" => e
            .build2_outcome
            .map(|o| <&str>::from(o).to_string())
            .unwrap_or_default(),
        "outcome_prev" => e
            .build1_outcome
            .map(|o| <&str>::from(o).to_string())
            .unwrap_or_default(),
        "pkgname_prev" => e.build1_pkgname.as_deref().unwrap_or("").to_string(),
        _ => String::new(),
    }
}

fn get_breaks(e: &DiffEntry, breaks: &HashMap<String, usize>) -> usize {
    e.build2_pkgname
        .as_deref()
        .or(e.build1_pkgname.as_deref())
        .and_then(|n| breaks.get(n).copied())
        .unwrap_or(0)
}

fn print_diff(
    diff: &BuildDiff,
    breaks: &HashMap<String, usize>,
    show_all: bool,
    col_names: &[&str],
) {
    if !try_println(&format!("--- {}", diff.build1_id)) {
        return;
    }
    if !try_println(&format!("+++ {}", diff.build2_id)) {
        return;
    }

    let nf = diff.new_failures.len();
    let fx = diff.fixes.len();
    let vc = diff.version_changes.len();
    let oc = diff.other_changes.len();

    let mut parts = Vec::new();
    if nf > 0 {
        parts.push(format!("+{} failure{}", nf, if nf == 1 { "" } else { "s" }));
    }
    if fx > 0 {
        parts.push(format!("-{} fix{}", fx, if fx == 1 { "" } else { "es" }));
    }
    if vc > 0 {
        parts.push(format!("~{} change{}", vc, if vc == 1 { "" } else { "s" }));
    }
    if show_all && oc > 0 {
        parts.push(format!(
            "{} other change{}",
            oc,
            if oc == 1 { "" } else { "s" }
        ));
    }
    if parts.is_empty() {
        try_println("@@ no changes @@");
        return;
    }
    if !try_println(&format!("@@ {} @@", parts.join(", "))) {
        return;
    }

    let widths: Vec<usize> = col_names
        .iter()
        .map(|name| {
            let all_entries = diff
                .new_failures
                .iter()
                .chain(diff.version_changes.iter())
                .chain(diff.fixes.iter())
                .chain(if show_all {
                    diff.other_changes.iter()
                } else {
                    [].iter()
                });
            let max_val = all_entries
                .map(|e| format_col(e, name, breaks).len())
                .max()
                .unwrap_or(0);
            max_val.max(name.len())
        })
        .collect();

    let header: String = col_names
        .iter()
        .zip(&widths)
        .map(|(name, w)| format!("{:<w$}", name.to_uppercase(), w = w))
        .collect::<Vec<_>>()
        .join("  ");
    if !try_println(&format!(" {}", header)) {
        return;
    }

    let print_entries = |prefix: char, entries: &mut [&DiffEntry]| -> bool {
        entries.sort_by_key(|e| std::cmp::Reverse(get_breaks(e, breaks)));
        for e in entries.iter() {
            let row: String = col_names
                .iter()
                .zip(&widths)
                .map(|(name, w)| format!("{:<w$}", format_col(e, name, breaks), w = w))
                .collect::<Vec<_>>()
                .join("  ");
            if !try_println(&format!("{}{}", prefix, row)) {
                return false;
            }
        }
        true
    };

    let mut failures: Vec<_> = diff.new_failures.iter().collect();
    if !print_entries('+', &mut failures) {
        return;
    }

    let mut version_changes: Vec<_> = diff.version_changes.iter().collect();
    if !print_entries('~', &mut version_changes) {
        return;
    }

    let mut fixes: Vec<_> = diff.fixes.iter().collect();
    if !print_entries('-', &mut fixes) {
        return;
    }

    if show_all {
        let mut other: Vec<_> = diff.other_changes.iter().collect();
        print_entries(' ', &mut other);
    }
}
