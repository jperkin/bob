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
use std::path::Path;

use anyhow::{Result, bail};
use clap::Args;
use clap::builder::styling::Style;
use pkgsrc::PkgName;
use regex::Regex;
use strum::{EnumProperty, VariantArray};

use bob::build::Stage;
use bob::db::{Database, PackageStatusRow};
use bob::{ColumnAlign, Config, PackageState, WrkObjKind};

use super::util::pkg_pattern;
use super::{
    Cell, Col, Formatter, OutputFormat, OutputOptions, SortKey, parse_sort_specs,
    parse_status_filter, sort_indexed_rows, status_filter_aliases,
};

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
    #[strum(props(
        max = "9",
        align = "right",
        desc = "MAKE_JOBS used by current build, otherwise predicted allocation"
    ))]
    MakeJobs,
    #[strum(props(
        max = "9",
        desc = "WRKOBJDIR used by current build, otherwise predicted routing"
    ))]
    Wrkobjdir,
    #[strum(props(
        max = "10",
        align = "right",
        desc = "WRKDIR size at end of current build"
    ))]
    DiskUsage,
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
 * relevance.  Sized by [`PackageState::VARIANTS`] so adding a variant
 * without extending this array fails to compile.
 */
const STATUS_DISPLAY_ORDER: [PackageState; PackageState::VARIANTS.len()] = {
    use PackageState::*;
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
 * [`PackageState`] values with `(alias)` entries inline.  Single
 * combined block matches clap's possible-values format.
 */
fn status_section() -> String {
    let literal = literal_style();
    let width = longest(
        PackageState::VARIANTS
            .iter()
            .map(|k| k.as_str())
            .chain(status_filter_aliases().map(|(name, _)| name)),
    );
    let mut out = String::from("Possible values:\n");
    for &k in &STATUS_DISPLAY_ORDER {
        write_item(&mut out, k.as_str(), k.desc(), width, literal);
    }
    for (name, desc) in status_filter_aliases() {
        let line = format!("{desc} (alias)");
        write_item(&mut out, name, &line, width, literal);
    }
    out
}

/**
 * Render the `Examples:` section.
 */
fn examples_section() -> String {
    let header = header_style();
    let pending = PackageState::Pending.as_str();
    let failed = PackageState::Failed.as_str();
    let skipped = "skipped";
    let pre_skipped = PackageState::PreSkipped.as_str();
    let pre_failed = PackageState::PreFailed.as_str();

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
    /// Output raw numeric values (ms for durations, bytes for sizes)
    #[arg(short = 'r', long)]
    raw: bool,
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
        value_delimiter = ',',
        value_parser = parse_status_filter,
    )]
    statuses: Vec<Vec<PackageState>>,
    /// Sort by column(s); prefix '-' to reverse default order (numeric defaults descending, text ascending)
    #[arg(short = 'S', long, value_delimiter = ',', allow_hyphen_values = true)]
    sort: Option<Vec<String>>,
    /// Package filters (regex on name or path)
    packages: Vec<String>,
}

pub fn run(db: &Database, config: &Config, args: StatusArgs) -> Result<()> {
    if db.count_packages()? == 0 {
        bail!("No packages in database. Run 'bob scan' first.");
    }
    let statuses: HashSet<PackageState> = args.statuses.iter().flatten().copied().collect();
    print_build_status(
        db,
        config,
        &statuses,
        args.columns.as_deref(),
        args.no_header,
        args.long,
        args.raw,
        args.format,
        &args.packages,
        args.all,
        args.sort.as_deref(),
    )
}

/**
 * Reason text for a failed build, naming the stage it failed in.  A
 * missing stage means the build never started, with the error, if any,
 * in the package's `setup.log`.
 */
fn failed_reason(stage: Option<i32>, logdir: &Path, pkgname: &str) -> String {
    match stage.and_then(Stage::from_repr) {
        Some(stage) => format!("Build failed during {} stage", stage.into_str()),
        None if logdir.join(pkgname).join("setup.log").exists() => {
            "Could not start build (see setup.log)".to_string()
        }
        None => "Could not start build".to_string(),
    }
}

/**
 * Build-stage CPU time in milliseconds for a package, or `None` when no
 * positive time is recorded.
 */
fn pkg_cpu_ms(cpu_times: &HashMap<(String, String), u64>, pkg: &PackageStatusRow) -> Option<u64> {
    let pkgbase = PkgName::new(&pkg.pkgname).pkgbase().to_string();
    cpu_times
        .get(&(pkg.pkg_location.clone(), pkgbase))
        .copied()
        .filter(|&ms| ms > 0)
}

/**
 * Print package status with selectable columns.
 *
 * Orders packages by weight, dependent count, CPU time, and name, joining
 * status, history, and predicted-allocation data for display.
 */
#[allow(clippy::too_many_arguments)]
fn print_build_status(
    db: &Database,
    config: &Config,
    statuses: &HashSet<PackageState>,
    columns: Option<&[String]>,
    no_header: bool,
    long: bool,
    raw: bool,
    format: OutputFormat,
    pkg_filters: &[String],
    show_all: bool,
    sort: Option<&[String]>,
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

    let sort_specs: Vec<(StatusCol, bool)> = match sort {
        Some(values) => parse_sort_specs(values, StatusCol::find, &all_names)?,
        None => Vec::new(),
    };

    let pkg_patterns: Vec<Regex> = pkg_filters
        .iter()
        .map(String::as_str)
        .map(pkg_pattern)
        .collect::<Result<Vec<_>>>()?;

    let status_rows = db.get_all_package_status()?;

    /*
     * Build-stage CPU times for the cpu column and the order tiebreak
     * after weight and dependent count.
     */
    let cpu_times = db.build_stage_cpu_times();

    /*
     * Allocator for predicting MAKE_JOBS of packages with no current-build
     * entry, calibrated on the safe packages' build-stage CPU times.
     * Built only when the make_jobs column is shown or sorted on and a
     * jobs budget is configured.
     */
    let need_make_jobs = cols.contains(&"make_jobs")
        || sort_specs
            .iter()
            .any(|(c, _)| matches!(c, StatusCol::MakeJobs));
    let make_jobs_alloc = match (need_make_jobs, config.jobs()) {
        (true, Some(jobs)) => {
            let mut alloc = bob::makejobs::Allocator::new(config.build_threads(), jobs);
            let mut cpu: Vec<usize> = status_rows
                .iter()
                .filter(|p| p.make_jobs_safe.unwrap_or(true))
                .filter_map(|p| pkg_cpu_ms(&cpu_times, p).map(|c| c as usize))
                .collect();
            cpu.sort_unstable();
            alloc.calibrate(&cpu);
            Some(alloc)
        }
        _ => None,
    };

    let need_history = cols
        .iter()
        .any(|c| matches!(*c, "wrkobjdir" | "make_jobs" | "disk_usage"));
    /*
     * Scoped to the current build only -- rows from previous build
     * sessions (different build_id) are deliberately excluded so the
     * status view reflects this run, not historical state.
     */
    let history = if need_history {
        match db.build_id() {
            Ok(id) => db.build_history_by_pkg_all(Some(&id)),
            Err(_) => HashMap::new(),
        }
    } else {
        HashMap::new()
    };

    /*
     * Predicted routing for packages without an actual entry in the
     * current build's history.  The prediction uses only the current
     * config (no historical disk_usage input), defaulting to the
     * routing's safe path when threshold-based routing is configured.
     */
    let predicted_wrkobjdir: Option<WrkObjKind> = config.wrkobjdir().and_then(|w| w.route(None));
    let predicted_wrkobjdir_for = |pkgpath: &str| -> Option<WrkObjKind> {
        let w = config.wrkobjdir()?;
        if w.always_disk.iter().any(|p| p == pkgpath) {
            return w.disk.clone().map(WrkObjKind::Disk);
        }
        predicted_wrkobjdir.clone()
    };

    let blockers = db.blockers()?;
    let logdir = config.logdir();
    let blocked_by = |pkgname: &str| -> String {
        match blockers.get(pkgname) {
            Some(blockers) => format!("Blocked by {}", blockers.join(", ")),
            None => String::new(),
        }
    };

    let get_status = |pkg: &PackageStatusRow| -> (PackageState, String) {
        use PackageState::*;
        if let Some(kind) = pkg
            .build_outcome
            .and_then(|o| PackageState::try_from(o).ok())
        {
            let reason = match kind {
                Failed => failed_reason(pkg.build_stage, logdir, &pkg.pkgname),
                IndirectFailed => blocked_by(&pkg.pkgname),
                _ => String::new(),
            };
            (kind, reason)
        } else if let Some(reason) = &pkg.pkg_fail_reason {
            (PreFailed, format!("PKG_FAIL_REASON: {reason}"))
        } else if let Some(reason) = &pkg.pkg_skip_reason {
            (PreSkipped, format!("PKG_SKIP_REASON: {reason}"))
        } else if let Some(kind) = pkg
            .scan_outcome
            .and_then(|o| PackageState::try_from(o).ok())
        {
            let reason = match kind {
                Unresolved => match &pkg.scan_outcome_detail {
                    Some(detail) => detail.replace('\n', "; "),
                    None => String::new(),
                },
                _ => blocked_by(&pkg.pkgname),
            };
            (kind, reason)
        } else if let Some(reason) = &pkg.build_reason {
            (Pending, reason.clone())
        } else {
            (Pending, String::new())
        }
    };

    let matches_status = |kind: PackageState| -> bool {
        if !statuses.is_empty() {
            return statuses.contains(&kind);
        }
        if show_all || !pkg_patterns.is_empty() {
            return true;
        }
        !kind.is_success()
    };

    let mut indexed_rows: Vec<(Vec<SortKey>, Vec<String>)> = Vec::new();
    for pkg in &status_rows {
        if !pkg_patterns.is_empty()
            && !pkg_patterns
                .iter()
                .any(|re| re.is_match(&pkg.pkgname) || re.is_match(&pkg.pkg_location))
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
        let cpu = pkg_cpu_ms(&cpu_times, pkg);

        let hist_key = (
            pkg.pkg_location.clone(),
            PkgName::new(&pkg.pkgname).pkgbase().to_string(),
        );
        let hist = history.get(&hist_key);
        let actual_wrkobjdir = hist.and_then(|h| h.wrkobjdir.clone());
        let actual_make_jobs = hist.and_then(|h| h.make_jobs);
        let actual_disk_usage = hist.and_then(|h| h.disk_usage);

        let need_wrkobjdir = cols.contains(&"wrkobjdir")
            || sort_specs
                .iter()
                .any(|(c, _)| matches!(c, StatusCol::Wrkobjdir));
        let resolved_wrkobjdir: Option<String> = if need_wrkobjdir {
            actual_wrkobjdir
                .clone()
                .or_else(|| predicted_wrkobjdir_for(&pkg.pkg_location).map(|k| k.to_string()))
        } else {
            None
        };
        let resolved_make_jobs: Option<u32> = actual_make_jobs.or_else(|| {
            let alloc = make_jobs_alloc.as_ref()?;
            if !pkg.make_jobs_safe.unwrap_or(true) {
                return None;
            }
            Some(alloc.assign(cpu.map(|c| c as usize)) as u32)
        });

        let row: Vec<String> = cols
            .iter()
            .map(|&col| match col {
                "pkgname" => pkg.pkgname.clone(),
                "pkgpath" => pkg.pkg_location.clone(),
                "status" => kind.as_str().to_string(),
                "reason" => reason.clone(),
                "multi_version" => multi_version.clone(),
                "deps" => pkg.dep_count.to_string(),
                "priority" => pkg.total_pbulk_weight.to_string(),
                "cpu" => cpu
                    .map(|c| {
                        if raw {
                            c.to_string()
                        } else {
                            bob::fmt::duration_ms(c)
                        }
                    })
                    .unwrap_or_else(dash),
                "wrkobjdir" => resolved_wrkobjdir.clone().unwrap_or_else(dash),
                "make_jobs" => resolved_make_jobs
                    .map(|n| n.to_string())
                    .unwrap_or_else(dash),
                "disk_usage" => actual_disk_usage
                    .map(|s| {
                        if raw {
                            s.to_string()
                        } else {
                            bob::fmt::size_bytes(s)
                        }
                    })
                    .unwrap_or_else(dash),
                _ => String::new(),
            })
            .collect();

        let mut sort_keys: Vec<SortKey> = sort_specs
            .iter()
            .map(|(c, _)| match c {
                StatusCol::Pkgname => SortKey::Str(pkg.pkgname.clone()),
                StatusCol::Pkgpath => SortKey::Str(pkg.pkg_location.clone()),
                StatusCol::Status => SortKey::Idx(kind as usize),
                StatusCol::Reason => SortKey::Str(reason.clone()),
                StatusCol::MultiVersion => SortKey::Str(multi_version.clone()),
                StatusCol::Deps => SortKey::Num(Some(pkg.dep_count as u64)),
                StatusCol::Priority => SortKey::Num(Some(pkg.total_pbulk_weight as u64)),
                StatusCol::Cpu => SortKey::Num(cpu),
                StatusCol::MakeJobs => SortKey::Num(resolved_make_jobs.map(u64::from)),
                StatusCol::Wrkobjdir => SortKey::OptStr(resolved_wrkobjdir.clone()),
                StatusCol::DiskUsage => SortKey::Num(actual_disk_usage),
            })
            .collect();

        /*
         * Default order, also the tiebreak under any user sort: weight
         * DESC, dependent count DESC, CPU DESC, name ASC.
         */
        sort_keys.push(SortKey::Num(Some(pkg.total_pbulk_weight as u64)));
        sort_keys.push(SortKey::Num(Some(pkg.dep_count as u64)));
        sort_keys.push(SortKey::Num(cpu));
        sort_keys.push(SortKey::Str(pkg.pkgname.clone()));

        indexed_rows.push((sort_keys, row));
    }

    if indexed_rows.is_empty() {
        if !statuses.is_empty() || !pkg_filters.is_empty() {
            bail!("No packages match the criteria");
        }
        return Ok(());
    }

    /*
     * Keep each appended key's natural direction: Num sorts descending
     * (weight, dependent count, CPU) and Str ascending (name).
     */
    let mut descs: Vec<bool> = sort_specs.iter().map(|(_, d)| *d).collect();
    descs.extend_from_slice(&[false, false, false, false]);
    sort_indexed_rows(&mut indexed_rows, &descs);

    let rows: Vec<Vec<String>> = indexed_rows.into_iter().map(|(_, r)| r).collect();

    let fmt_cols: Vec<Col> = cols
        .iter()
        .map(|&name| {
            let sc = StatusCol::find(name).expect("column already validated");
            Col::new(<&'static str>::from(sc), sc.align()).max(sc.max_width())
        })
        .collect();
    let mut fmt = Formatter::new(
        std::io::stdout().lock(),
        fmt_cols,
        OutputOptions {
            format,
            no_header,
            raw,
        },
    );
    for row in rows {
        fmt.row(row.into_iter().map(Cell::Text));
    }
    fmt.finish()?;

    Ok(())
}
