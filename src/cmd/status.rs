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

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::IsTerminal;

use anyhow::{Result, bail};
use clap::Args;
use clap::builder::styling::Style;
use regex::Regex;
use strum::{EnumCount, EnumProperty, IntoEnumIterator, VariantArray};

use bob::db::{Database, PackageStatusRow};
use bob::{
    ColumnAlign, Config, PackageState, PackageStateAlias, PackageStateKind, Scheduler,
    parse_status_filter,
};

use super::util::pkg_pattern;
use super::{Col, Formatter, OutputFormat};

#[derive(Clone, Copy, strum::EnumProperty, strum::IntoStaticStr, strum::VariantArray)]
#[strum(serialize_all = "snake_case")]
enum StatusCol {
    #[strum(props(default = "true", max = "40", desc = "Package name"))]
    Pkgname,
    #[strum(props(max = "35", desc = "Package path (category/name)"))]
    Pkgpath,
    #[strum(props(default = "true", desc = "Current build status"))]
    Status,
    #[strum(props(default = "true", desc = "Status detail or reason"))]
    Reason,
    #[strum(props(desc = "MULTI_VERSION package build variables"))]
    MultiVersion,
    #[strum(props(max = "6", align = "right", desc = "Number of dependent packages"))]
    Deps,
    #[strum(props(max = "8", align = "right", desc = "Scheduler priority order"))]
    Priority,
    #[strum(props(max = "8", align = "right", desc = "Previous build CPU time"))]
    Cpu,
    #[strum(props(max = "9", align = "right", desc = "MAKE_JOBS allocation"))]
    MakeJobs,
    #[strum(props(max = "9", desc = "WRKOBJDIR routing (tmpfs or disk)"))]
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

    fn desc(self) -> &'static str {
        self.get_str("desc").expect("desc prop")
    }

    fn find(name: &str) -> Option<Self> {
        Self::VARIANTS
            .iter()
            .find(|v| <&str>::from(*v) == name)
            .copied()
    }
}

/**
 * Order in which `Status values:` are listed in `--help`, by outcome
 * relevance.  Sized by [`PackageStateKind::COUNT`] so adding a variant
 * without extending this array fails to compile.
 */
const STATUS_DISPLAY_ORDER: [PackageStateKind; PackageStateKind::COUNT] = {
    use PackageStateKind::*;
    [
        Pending,
        UpToDate,
        Success,
        Failed,
        PreSkipped,
        PreFailed,
        Unresolved,
        IndirectFailed,
        IndirectPreSkipped,
        IndirectPreFailed,
        IndirectUnresolved,
    ]
};

/**
 * Length of the longest item in an iterator of names, used by
 * [`write_item`] so each section pads to its own longest value (matching
 * clap's per-block alignment for `Possible values:`).
 */
fn longest<'a, I: IntoIterator<Item = &'a str>>(names: I) -> usize {
    names.into_iter().map(str::len).fold(0, usize::max)
}

/**
 * Whether to emit ANSI styling.  clap passes long_help/after_long_help
 * through verbatim with no terminal detection, so we do it ourselves to
 * keep piped output free of escape codes.
 */
fn styled() -> bool {
    std::io::stdout().is_terminal()
}

/// clap's "header" style (bold + underline), or plain when not a tty.
fn header_style() -> Style {
    if styled() {
        Style::new().bold().underline()
    } else {
        Style::new()
    }
}

/// clap's "literal" style (bold), or plain when not a tty.
fn literal_style() -> Style {
    if styled() {
        Style::new().bold()
    } else {
        Style::new()
    }
}

/**
 * Append a single `- name: description` line in clap's possible-values
 * style.  `name_pad` is the longest name across the section so colons
 * align and descriptions start at a uniform column.
 */
fn write_item(out: &mut String, name: &str, desc: &str, name_pad: usize, literal: Style) {
    let padding = " ".repeat(name_pad.saturating_sub(name.len()) + 1);
    let _ = writeln!(out, "- {literal}{name}{literal:#}:{padding}{desc}");
}

/**
 * Render the `Possible values:` block listing every [`StatusCol`] variant.
 *
 * Heading wording and styling match clap's auto-generated possible-values
 * block (see `-f, --format` in this command), so all flags read the same.
 */
fn columns_section() -> String {
    let literal = literal_style();
    let width = longest(StatusCol::VARIANTS.iter().map(<&str>::from));
    let mut out = String::from("Possible values:\n");
    for c in StatusCol::VARIANTS {
        write_item(&mut out, <&str>::from(c), c.desc(), width, literal);
    }
    out
}

/**
 * Render the `Possible values:` block for `-s`, combining canonical
 * [`PackageStateKind`] values with [`PackageStateAlias`] entries marked
 * `(alias)` inline.  Single combined block matches clap's possible-values
 * format.
 */
fn status_section() -> String {
    let literal = literal_style();
    let width = longest(
        PackageStateKind::iter()
            .map(<&str>::from)
            .chain(PackageStateAlias::iter().map(<&str>::from)),
    );
    let mut out = String::from("Possible values:\n");
    for &k in &STATUS_DISPLAY_ORDER {
        write_item(&mut out, <&str>::from(k), k.desc(), width, literal);
    }
    for a in PackageStateAlias::iter() {
        let alias_desc = a.desc();
        let desc = format!("{alias_desc} (alias)");
        write_item(&mut out, <&str>::from(a), &desc, width, literal);
    }
    out
}

/**
 * Render the `Examples:` section.
 */
fn examples_section() -> String {
    let header = header_style();
    let pending: &str = PackageStateKind::Pending.into();
    let failed: &str = PackageStateKind::Failed.into();
    let skipped: &str = PackageStateAlias::Skipped.into();
    let pre_skipped: &str = PackageStateKind::PreSkipped.into();
    let pre_failed: &str = PackageStateKind::PreFailed.into();

    let examples = [
        (
            "bob status".into(),
            format!("Show {pending}/{failed} packages"),
        ),
        ("bob status -a".into(), "Show all packages".into()),
        (
            format!("bob status -s {skipped}"),
            format!("Show {pre_skipped} and {pre_failed}"),
        ),
        (
            "bob status ^mutt- meta-pkgs/bulk".into(),
            "Show multiple package or pkgpath matches".into(),
        ),
        (
            format!("bob status -Ho pkgpath -s {pending}"),
            format!("Show all {pending} pkgpath builds"),
        ),
    ];
    let ex_width = examples
        .iter()
        .map(|(cmd, _)| cmd.len())
        .fold(0, usize::max);
    let mut out = format!("{header}Examples:{header:#}\n");
    for (cmd, desc) in &examples {
        let _ = writeln!(out, "  {cmd:w$}  {desc}", w = ex_width);
    }
    out
}

/**
 * Long help for `-o`: short summary followed by the inline
 * `Possible values:` block of column names.
 *
 * Trailing newline trimmed; clap adds its own paragraph break.
 */
fn columns_long_help() -> String {
    format!(
        "Columns to display (comma-separated; use -l to see all)\n\n{}",
        columns_section().trim_end()
    )
}

/**
 * Long help for `-s`: short summary followed by the inline
 * `Possible values:` block of status kinds and aliases.
 *
 * Trailing newline trimmed; clap adds its own paragraph break.
 */
fn status_long_help() -> String {
    format!(
        "Filter by status (repeatable or comma-separated)\n\n{}",
        status_section().trim_end()
    )
}

/**
 * `after_long_help` for `bob status`.  Only the Examples section lives
 * here; per-flag value lists are inline on their flags via `long_help`.
 */
pub fn after_help() -> String {
    examples_section()
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
    #[arg(short = 'o', long_help = columns_long_help(), value_delimiter = ',')]
    columns: Option<Vec<String>>,
    /// Filter by status (repeatable or comma-separated)
    #[arg(
        short = 's',
        long = "status",
        long_help = status_long_help(),
        value_parser = parse_status_filter,
        value_delimiter = ',',
    )]
    statuses: Vec<Vec<PackageStateKind>>,
    /// Package filters (regex on name or path)
    packages: Vec<String>,
}

pub fn run(db: &Database, config: &Config, args: StatusArgs) -> Result<()> {
    if db.count_packages()? == 0 {
        bail!("No packages in database. Run 'bob scan' first.");
    }
    let statuses: HashSet<PackageStateKind> = args.statuses.iter().flatten().copied().collect();
    print_build_status(
        db,
        config,
        &statuses,
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
    statuses: &HashSet<PackageStateKind>,
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
        .map(String::as_str)
        .map(pkg_pattern)
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
                            if h.outcome == success {
                                h.disk_usage
                            } else {
                                match (h.disk_usage, w.failed_threshold) {
                                    (Some(size), Some(ft)) if size <= ft => Some(size),
                                    _ => None,
                                }
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

    let get_status = |pkg: &PackageStatusRow| -> (PackageStateKind, String) {
        if let Some(state) = pkg
            .build_outcome
            .and_then(|id| PackageState::from_db(id, pkg.outcome_detail.clone()))
        {
            let reason = state.detail().map(String::from).unwrap_or_default();
            (state.kind(), reason)
        } else if let Some(reason) = &pkg.build_reason {
            (PackageStateKind::Pending, reason.clone())
        } else if let Some(reason) = &pkg.fail_reason {
            (
                PackageStateKind::PreFailed,
                format!("PKG_FAIL_REASON: {}", reason),
            )
        } else if let Some(reason) = &pkg.skip_reason {
            (
                PackageStateKind::PreSkipped,
                format!("PKG_SKIP_REASON: {}", reason),
            )
        } else {
            (PackageStateKind::Pending, String::new())
        }
    };

    let matches_status = |kind: PackageStateKind| -> bool {
        if !statuses.is_empty() {
            return statuses.contains(&kind);
        }
        if show_all || !pkg_patterns.is_empty() {
            return true;
        }
        !matches!(kind, PackageStateKind::Success | PackageStateKind::UpToDate)
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

        let (kind, reason) = get_status(pkg);

        if !matches_status(kind) {
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
                "status" => <&str>::from(kind).to_string(),
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
