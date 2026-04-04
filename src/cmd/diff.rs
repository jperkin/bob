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

use anyhow::{Result, bail};

use bob::db::{BuildDiff, Database, DiffEntry};
use bob::{PackageStateKind, try_println};

use super::{Col, Formatter, OutputFormat};

#[derive(Debug, clap::Args)]
pub struct DiffArgs {
    /// Build ID for the left side of the diff (default: second most recent)
    #[arg(long)]
    pub left: Option<String>,
    /// Build ID for the right side of the diff (default: most recent)
    #[arg(long)]
    pub right: Option<String>,
    /// List available build IDs
    #[arg(short, long)]
    pub list: bool,
}

pub fn run(db: &Database, args: DiffArgs) -> Result<()> {
    if args.list {
        return list_builds(db);
    }
    let builds = db.list_history_builds()?;
    let (left_id, right_id) = match (args.left, args.right) {
        (Some(l), Some(r)) => (l, r),
        (Some(l), None) => {
            if builds.is_empty() {
                bail!("No builds in history");
            }
            (l, builds[0].build_id.clone())
        }
        (None, Some(r)) => {
            if builds.len() < 2 {
                bail!("Need at least two builds to infer the left side");
            }
            (builds[1].build_id.clone(), r)
        }
        (None, None) => {
            if builds.len() < 2 {
                bail!("Need at least two builds to compare. Use --list to see available builds.");
            }
            (builds[1].build_id.clone(), builds[0].build_id.clone())
        }
    };

    let diff = db.compute_build_diff(&left_id, &right_id)?;
    print_diff(&diff);
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
        Col::new("started", bob::Align::Left),
    ]);
    for b in &builds {
        let date = format_build_timestamp(b.started);
        fmt.push(vec![b.build_id.clone(), b.package_count.to_string(), date]);
    }
    fmt.print(OutputFormat::Table, false);
    Ok(())
}

fn format_build_timestamp(epoch: i64) -> String {
    let mut buf = [0u8; 20];
    let time_t = epoch as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&time_t, &mut tm) };
    let len = unsafe {
        libc::strftime(
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            c"%Y-%m-%d %H:%M:%S".as_ptr(),
            &tm,
        )
    };
    String::from_utf8_lossy(&buf[..len]).to_string()
}

fn outcome_str(o: Option<PackageStateKind>) -> &'static str {
    match o {
        Some(k) => k.into(),
        None => "-",
    }
}

fn print_diff(diff: &BuildDiff) {
    try_println(&format!(
        "Comparing {} (left) \u{2194} {} (right)\n",
        diff.left_build_id, diff.right_build_id
    ));

    print_section("New Failures", &diff.new_failures, false);
    print_section("Fixes", &diff.fixes, false);
    print_section("New Packages", &diff.new_packages, false);
    print_section("Removed Packages", &diff.removed_packages, false);
    print_section("Version Changes", &diff.version_changes, true);
    print_section("Other Changes", &diff.other_changes, true);

    try_println("");
    try_println("Summary:");
    try_println(&format!(
        "  New failures:    {:>4}",
        diff.new_failures.len()
    ));
    try_println(&format!("  Fixes:           {:>4}", diff.fixes.len()));
    try_println(&format!(
        "  New packages:    {:>4}",
        diff.new_packages.len()
    ));
    try_println(&format!(
        "  Removed:         {:>4}",
        diff.removed_packages.len()
    ));
    try_println(&format!(
        "  Version changes: {:>4}",
        diff.version_changes.len()
    ));
    try_println(&format!(
        "  Other changes:   {:>4}",
        diff.other_changes.len()
    ));
}

fn print_section(title: &str, entries: &[DiffEntry], show_outcomes: bool) {
    if entries.is_empty() {
        return;
    }
    try_println(&format!("{} ({}):", title, entries.len()));

    let max_path = entries.iter().map(|e| e.pkgpath.len()).max().unwrap_or(0);
    for e in entries {
        let pkgname = e
            .right_pkgname
            .as_deref()
            .or(e.left_pkgname.as_deref())
            .unwrap_or("-");
        if show_outcomes {
            try_println(&format!(
                "  {:<width$}  {:<30}  {} -> {}",
                e.pkgpath,
                pkgname,
                outcome_str(e.left_outcome),
                outcome_str(e.right_outcome),
                width = max_path
            ));
        } else {
            try_println(&format!(
                "  {:<width$}  {}",
                e.pkgpath,
                pkgname,
                width = max_path
            ));
        }
    }
    try_println("");
}
