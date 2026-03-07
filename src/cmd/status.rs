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
use clap::Args;
use regex::Regex;
use serde_json;

use bob::db::{Database, PackageStatusRow};
use bob::{PackageState, PackageStateKind};

use super::{ColumnDef, OutputFormat, render_output, resolve_columns};

fn parse_status(s: &str) -> Result<PackageStateKind, String> {
    s.parse().map_err(|_| format!("unknown status '{}'", s))
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Show all packages including success and up-to-date
    #[arg(short, long)]
    all: bool,
    /// Hide column headers
    #[arg(short = 'H')]
    no_header: bool,
    /// Show all columns
    #[arg(short = 'l', long)]
    long: bool,
    /// Output format
    #[arg(short = 'f', long, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,
    /// Columns to display (comma-separated; use -l to see all)
    #[arg(short = 'o', value_delimiter = ',')]
    columns: Option<Vec<String>>,
    /// Filter by status (repeatable or comma-separated)
    #[arg(
        short = 's',
        long = "status",
        value_parser = parse_status,
        value_delimiter = ',',
    )]
    statuses: Vec<PackageStateKind>,
    /// Package filters (regex on name or path)
    packages: Vec<String>,
}

pub fn run(
    db: &Database,
    args: StatusArgs,
    max_jobs: Option<usize>,
    build_threads: usize,
) -> Result<()> {
    if db.count_packages()? == 0 {
        bail!("No packages in database. Run 'bob scan' first.");
    }
    print_build_status(
        db,
        &args.statuses,
        args.columns.as_deref(),
        args.no_header,
        args.long,
        args.format,
        &args.packages,
        args.all,
        max_jobs,
        build_threads,
    )
}

/**
 * Print package status with selectable columns in build order.
 *
 * Shows packages ordered by effective weight so that packages with the
 * most transitive dependents appear first. Supports filtering by status
 * and package name/path regex.
 */
#[allow(clippy::too_many_arguments)]
fn print_build_status(
    db: &Database,
    statuses: &[PackageStateKind],
    columns: Option<&[String]>,
    no_header: bool,
    long: bool,
    format: OutputFormat,
    pkg_filters: &[String],
    show_all: bool,
    max_jobs: Option<usize>,
    build_threads: usize,
) -> Result<()> {
    let all_cols: &[&str] = &[
        "pkgname",
        "pkgpath",
        "status",
        "reason",
        "multi_version",
        "deps",
        "weight",
        "cpu",
        "jobs",
    ];
    let default_cols: &[&str] = &["pkgname", "status", "reason"];
    let cols = resolve_columns(columns, long, all_cols, default_cols)?;

    fn status_col_def<'a>(name: &'a str) -> ColumnDef<'a> {
        let mut def = ColumnDef::new(name);
        def.max_width = match name {
            "pkgname" => Some(40),
            "pkgpath" => Some(35),
            "deps" => Some(6),
            "weight" => Some(8),
            "cpu" => Some(8),
            "jobs" => Some(4),
            _ => None,
        };
        def.right_align = matches!(name, "deps" | "weight" | "cpu" | "jobs");
        def
    }

    let pkg_patterns: Vec<Regex> = pkg_filters
        .iter()
        .map(|p| Regex::new(p).map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", p, e)))
        .collect::<Result<Vec<_>>>()?;

    let need_multi = cols.contains(&"multi_version");
    let mut all_pkgs = db.get_all_package_status(need_multi)?;

    let graph = db.get_scheduling_graph()?;
    let (tw_vec, dc_vec) = bob::scheduling_weights_indexed(&graph.weights, &graph.rdeps);

    let mut total_weights: HashMap<String, usize> = HashMap::with_capacity(graph.names.len());
    let mut dep_counts: HashMap<String, usize> = HashMap::with_capacity(graph.names.len());
    for (i, name) in graph.names.iter().enumerate() {
        total_weights.insert(name.clone(), tw_vec[i]);
        dep_counts.insert(name.clone(), dc_vec[i]);
    }

    let cpu_times = db.cpu_time_by_pkg_all();

    bob::sort_by_build_priority(
        &mut all_pkgs,
        |p| total_weights.get(&p.pkgname).copied().unwrap_or(0),
        |p| dep_counts.get(&p.pkgname).copied().unwrap_or(0),
        |p| {
            let base = pkgsrc::PkgName::new(&p.pkgname).pkgbase().to_string();
            cpu_times.get(&base).copied().unwrap_or(0)
        },
        |p| &p.pkgname,
    );

    let precomputed_jobs = if cols.contains(&"jobs") {
        if let Some(mj) = max_jobs {
            let hist_durations = db.duration_by_pkg_all();
            let durations: HashMap<String, usize> = hist_durations
                .iter()
                .map(|(k, &v)| (k.clone(), v as usize))
                .collect();
            let dc_i64: HashMap<String, i64> = dep_counts
                .iter()
                .map(|(k, &v)| {
                    let base = pkgsrc::PkgName::new(k).pkgbase().to_string();
                    (base, v as i64)
                })
                .collect();
            bob::compute_budget(&dc_i64, &durations, mj, build_threads)
        } else {
            HashMap::new()
        }
    } else {
        HashMap::new()
    };

    let get_status = |pkg: &PackageStatusRow| -> (&'static str, String) {
        if let Some(state) = pkg
            .build_outcome
            .and_then(|id| PackageState::from_db(id, pkg.outcome_detail.clone()))
        {
            let reason = state.detail().map(String::from).unwrap_or_default();
            (state.status(), reason)
        } else if let Some(reason) = &pkg.build_reason {
            (PackageStateKind::Pending.into(), reason.clone())
        } else if let Some(reason) = &pkg.fail_reason {
            (
                PackageStateKind::PreFailed.into(),
                format!("PKG_FAIL_REASON: {}", reason),
            )
        } else if let Some(reason) = &pkg.skip_reason {
            (
                PackageStateKind::PreSkipped.into(),
                format!("PKG_SKIP_REASON: {}", reason),
            )
        } else {
            (PackageStateKind::Pending.into(), String::new())
        }
    };

    let matches_status = |status: &str| -> bool {
        if !statuses.is_empty() {
            return statuses.iter().any(|f| <&str>::from(f) == status);
        }
        if show_all {
            return true;
        }
        let success: &str = PackageStateKind::Success.into();
        let up_to_date: &str = PackageStateKind::UpToDate.into();
        status != success && status != up_to_date
    };

    let mut rows: Vec<Vec<String>> = Vec::new();
    for pkg in &all_pkgs {
        if !pkg_patterns.is_empty()
            && !pkg_patterns
                .iter()
                .any(|re| re.is_match(&pkg.pkgname) || re.is_match(&pkg.pkgpath))
        {
            continue;
        }

        let (status, reason) = get_status(pkg);

        if !matches_status(status) {
            continue;
        }

        let multi_version = pkg
            .multi_version
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .map(|v| v.join(" "))
            .unwrap_or_default();

        let dash = || "-".to_string();
        let pkgbase = pkgsrc::PkgName::new(&pkg.pkgname).pkgbase().to_string();

        let row: Vec<String> = cols
            .iter()
            .map(|&col| match col {
                "pkgname" => pkg.pkgname.clone(),
                "pkgpath" => pkg.pkgpath.clone(),
                "status" => status.to_string(),
                "reason" => reason.clone(),
                "multi_version" => multi_version.clone(),
                "deps" => dep_counts.get(&pkg.pkgname).unwrap_or(&0).to_string(),
                "weight" => total_weights.get(&pkg.pkgname).unwrap_or(&0).to_string(),
                "cpu" => cpu_times
                    .get(&pkgbase)
                    .map(|ms| bob::format_duration(*ms))
                    .unwrap_or_else(dash),
                "jobs" => {
                    if max_jobs.is_none() {
                        dash()
                    } else {
                        let base = pkgsrc::PkgName::new(&pkg.pkgname).pkgbase().to_string();
                        precomputed_jobs
                            .get(&base)
                            .map(|j| j.to_string())
                            .unwrap_or_else(dash)
                    }
                }
                _ => String::new(),
            })
            .collect();
        rows.push(row);
    }

    if rows.is_empty() {
        if !statuses.is_empty() || !pkg_filters.is_empty() {
            bail!("No packages match the criteria");
        }
        return Ok(());
    }

    let col_defs: Vec<ColumnDef> = cols.iter().map(|&c| status_col_def(c)).collect();
    render_output(format, &col_defs, &rows, no_header)
}
