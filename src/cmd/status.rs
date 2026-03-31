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
use strum::{EnumProperty, VariantArray};

use bob::db::{Database, PackageStatusRow};
use bob::{ColumnAlign, Config, PackageState, PackageStateKind, Scheduler};

use super::{Col, Formatter, OutputFormat};

#[derive(Clone, Copy, strum::EnumProperty, strum::IntoStaticStr, strum::VariantArray)]
#[strum(serialize_all = "snake_case")]
enum StatusCol {
    #[strum(props(default = "true", max = "40"))]
    Pkgname,
    #[strum(props(max = "35"))]
    Pkgpath,
    #[strum(props(default = "true"))]
    Status,
    #[strum(props(default = "true"))]
    Reason,
    MultiVersion,
    #[strum(props(max = "6", align = "right"))]
    Deps,
    #[strum(props(max = "8", align = "right"))]
    Priority,
    #[strum(props(max = "8", align = "right"))]
    Cpu,
    #[strum(props(max = "9", align = "right"))]
    MakeJobs,
    #[strum(props(max = "9"))]
    Wrkobjdir,
}

/**
 * Alignment from per-variant `align` props.
 */
impl bob::ColumnAlign for StatusCol {}

impl StatusCol {
    fn max_width(self) -> usize {
        self.get_str("max")
            .and_then(|s| s.parse().ok())
            .unwrap_or(usize::MAX)
    }

    fn is_default(self) -> bool {
        self.get_str("default").is_some()
    }

    fn find(name: &str) -> Option<Self> {
        Self::VARIANTS
            .iter()
            .find(|v| <&str>::from(*v) == name)
            .copied()
    }
}

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

pub fn run(db: &Database, config: &Config, args: StatusArgs) -> Result<()> {
    if db.count_packages()? == 0 {
        bail!("No packages in database. Run 'bob scan' first.");
    }
    print_build_status(
        db,
        config,
        &args.statuses,
        args.columns.as_deref(),
        args.no_header,
        args.long,
        args.format,
        &args.packages,
        args.all,
    )
}

/**
 * Print package status with selectable columns in build order.
 *
 * Uses the scheduler's iterator to get packages in priority order,
 * then joins with status data from the database for display.
 */
#[allow(clippy::too_many_arguments)]
fn print_build_status(
    db: &Database,
    config: &Config,
    statuses: &[PackageStateKind],
    columns: Option<&[String]>,
    no_header: bool,
    long: bool,
    format: OutputFormat,
    pkg_filters: &[String],
    show_all: bool,
) -> Result<()> {
    let all_names: Vec<&str> = StatusCol::VARIANTS.iter().map(|v| v.into()).collect();
    let cols: Vec<&str> = if columns.is_some() {
        columns
            .map(|c| c.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    } else if long {
        all_names.clone()
    } else {
        StatusCol::VARIANTS
            .iter()
            .filter(|v| v.is_default())
            .map(|v| v.into())
            .collect()
    };

    for col in &cols {
        if !all_names.contains(col) {
            bail!(
                "Unknown column '{}'. Valid columns: {}",
                col,
                all_names.join(", ")
            );
        }
    }

    let pkg_patterns: Vec<Regex> = pkg_filters
        .iter()
        .map(|p| {
            Regex::new(&format!("(?i){}", p))
                .map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", p, e))
        })
        .collect::<Result<Vec<_>>>()?;

    let need_multi = cols.contains(&"multi_version");
    let status_rows = db.get_all_package_status(need_multi)?;
    let status_map: HashMap<&str, &PackageStatusRow> = status_rows
        .iter()
        .map(|r| (r.pkgname.as_str(), r))
        .collect();

    let mut sched = Scheduler::new(db)?;
    if let Some(jobs) = config.jobs() {
        sched.set_allocator(bob::makejobs::Allocator::new(config.build_threads(), jobs));
        sched.allocate_all();
    }

    let wrkobjdir_map: HashMap<&str, String> = if cols.contains(&"wrkobjdir") {
        if let Some(w) = config.wrkobjdir() {
            let success = Some(PackageStateKind::Success);
            let history = db.build_history_by_pkg_all();
            status_rows
                .iter()
                .filter_map(|r| {
                    let du = history
                        .get(pkgsrc::PkgName::new(&r.pkgname).pkgbase())
                        .and_then(|h| {
                            if w.use_failed_history || h.outcome == success {
                                h.disk_usage
                            } else {
                                None
                            }
                        });
                    w.route(du)
                        .map(|kind| (r.pkgname.as_str(), kind.to_string()))
                })
                .collect()
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
        if show_all || !pkg_patterns.is_empty() {
            return true;
        }
        let success: &str = PackageStateKind::Success.into();
        let up_to_date: &str = PackageStateKind::UpToDate.into();
        status != success && status != up_to_date
    };

    let mut rows: Vec<Vec<String>> = Vec::new();
    for sp in sched.iter() {
        let Some(pkg) = status_map.get(sp.pkg.pkgname()) else {
            continue;
        };

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

        let row: Vec<String> = cols
            .iter()
            .map(|&col| match col {
                "pkgname" => pkg.pkgname.clone(),
                "pkgpath" => pkg.pkgpath.clone(),
                "status" => status.to_string(),
                "reason" => reason.clone(),
                "multi_version" => multi_version.clone(),
                "deps" => sp.dep_count.to_string(),
                "priority" => sp.total_pbulk_weight.to_string(),
                "cpu" => {
                    if sp.cpu_time > 0 {
                        bob::format_duration(sp.cpu_time)
                    } else {
                        dash()
                    }
                }
                "wrkobjdir" => wrkobjdir_map
                    .get(pkg.pkgname.as_str())
                    .cloned()
                    .unwrap_or_else(dash),
                "make_jobs" => match sp.make_jobs.allocated() {
                    Some(n) => n.to_string(),
                    None => dash(),
                },
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

    let fmt_cols: Vec<Col> = cols
        .iter()
        .map(|&name| {
            let sc = StatusCol::find(name).expect("column already validated");
            Col::new(name, sc.align()).max(sc.max_width())
        })
        .collect();
    let mut fmt = Formatter::new(fmt_cols);
    for row in rows {
        fmt.push(row);
    }
    fmt.print(format, no_header);

    Ok(())
}
