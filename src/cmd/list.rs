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
use std::io::IsTerminal;

use anyhow::{Result, bail};
use clap::Subcommand;
use crossterm::terminal;
use regex::Regex;
use serde_json;

use bob::db::{Database, PackageStatusRow};
use bob::try_println;
use bob::{PackageState, PackageStateKind};

fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn parse_status(s: &str) -> Result<PackageStateKind, String> {
    s.parse().map_err(|_| format!("unknown status '{}'", s))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum TreeOutput {
    /// Unicode box drawing characters
    #[default]
    Utf8,
    /// ASCII characters
    Ascii,
    /// Plain indent (no tree characters)
    None,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum HistoryFormat {
    /// Padded columns
    #[default]
    Table,
    /// Comma-separated values
    Csv,
    /// JSON array of objects
    Json,
}

#[derive(Debug, Subcommand)]
pub enum ListCmd {
    /// Show comprehensive package build status
    #[command(after_long_help = "\
Status values:
  pending              Ready to build
  success              Built successfully
  up-to-date           Binary already exists
  failed               Build attempted and failed
  preskipped           PKG_SKIP_REASON set
  prefailed            PKG_FAIL_REASON set
  unresolved           Has unresolved dependencies
  indirect-failed      Blocked by package that failed to build
  indirect-preskipped  Blocked by preskipped package
  indirect-prefailed   Blocked by prefailed package
  indirect-unresolved  Blocked by package with unresolved dependencies

Examples:
  bob list status                           Show pending/failed packages
  bob list status -a                        Show all packages
  bob list status -s preskipped,prefailed   Show all pre-* packages
  bob list status py-                       Show packages matching 'py-'
  bob list status flim glib2 mutt           Show multiple package matches
  bob list status -s failed -o pkgpath      Show failed with pkgpath column
  bob list status -Ho pkgpath -s pending    Show all pending pkgpath builds
  bob list status -o pkgpath,multi_version  Show MULTI_VERSION flags
")]
    Status {
        /// Show all packages including success and up-to-date
        #[arg(short, long)]
        all: bool,
        /// Hide column headers
        #[arg(short = 'H')]
        no_header: bool,
        /// Columns to display (comma-separated: pkgname,pkgpath,status,reason,multi_version)
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
    },
    /// Show dependency tree of packages to build
    Tree {
        /// Include up-to-date packages
        #[arg(short, long)]
        all: bool,
        /// Output format (default: utf8 on terminal, none otherwise)
        #[arg(short = 'f', long, value_enum)]
        format: Option<TreeOutput>,
        /// Output pkgpath instead of pkgname
        #[arg(short, long)]
        path: bool,
        /// Package to show tree for (regex pattern)
        package: Option<String>,
    },
    /// Show what is blocking a package from building
    Blockers {
        /// Package name or pkgpath
        package: String,
        /// Output pkgpath instead of pkgname
        #[arg(short, long)]
        path: bool,
    },
    /// Show packages blocked by a failed package
    BlockedBy {
        /// Package name or pkgpath
        package: String,
        /// Output pkgpath instead of pkgname
        #[arg(short, long)]
        path: bool,
    },
    /// View build history
    #[command(after_long_help = bob::HistoryKind::after_help())]
    History {
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
        #[arg(short = 'f', long, value_enum, default_value_t = HistoryFormat::Table)]
        format: HistoryFormat,
        /// Columns to display (comma-separated, see --help for full list)
        #[arg(short = 'o', value_delimiter = ',')]
        columns: Option<Vec<String>>,
        /// Filter by pkgpath or pkgname (regex)
        package: Option<String>,
    },
}

pub fn run(db: &Database, cmd: ListCmd) -> Result<()> {
    if !matches!(cmd, ListCmd::History { .. }) && db.count_packages()? == 0 {
        bail!("No packages in database. Run 'bob scan' first.");
    }

    match cmd {
        ListCmd::Status {
            all,
            statuses,
            columns,
            no_header,
            packages,
        } => {
            print_build_status(db, &statuses, columns.as_deref(), no_header, &packages, all)?;
        }
        ListCmd::Tree {
            all,
            format,
            path,
            package,
        } => {
            let format = format.unwrap_or(if std::io::stdout().is_terminal() {
                TreeOutput::Utf8
            } else {
                TreeOutput::None
            });
            print_build_tree(db, path, all, format, package.as_deref())?;
        }
        ListCmd::Blockers { package, path } => {
            for (pkgname, pkgpath, reason) in db.get_blockers(&package)? {
                let s = if path {
                    format!("{} ({})", pkgpath, reason)
                } else {
                    format!("{} ({})", pkgname, reason)
                };
                if !try_println(&s) {
                    break;
                }
            }
        }
        ListCmd::BlockedBy { package, path } => {
            for (pkgname, pkgpath) in db.get_blocked_by(&package)? {
                let s = if path { pkgpath } else { pkgname };
                if !try_println(&s) {
                    break;
                }
            }
        }
        ListCmd::History {
            no_header,
            long,
            raw,
            format,
            columns,
            package,
        } => {
            print_history(
                db,
                columns.as_deref(),
                no_header,
                long,
                raw,
                format,
                package.as_deref(),
            )?;
        }
    }

    Ok(())
}

/**
 * Collect transitive dependencies for a package.
 */
fn collect_transitive_deps<'a>(
    pkg: &'a str,
    deps: &'a HashMap<String, Vec<String>>,
    result: &mut HashSet<&'a str>,
) {
    if let Some(pkg_deps) = deps.get(pkg) {
        for dep in pkg_deps {
            if result.insert(dep.as_str()) {
                collect_transitive_deps(dep.as_str(), deps, result);
            }
        }
    }
}

/**
 * Print the build tree showing packages in build order (dependencies first).
 *
 * When a package pattern is provided, shows a proper dependency tree for
 * matching packages. Otherwise, uses topological levels to show build order.
 */
fn print_build_tree(
    db: &Database,
    use_path: bool,
    include_all: bool,
    format: TreeOutput,
    package: Option<&str>,
) -> Result<()> {
    // Get all buildable packages
    let buildable_pkgs = db.get_buildable_packages()?;

    // Build map for pkgname -> pkgpath lookup
    let pkgname_to_pkgpath: HashMap<String, String> = buildable_pkgs
        .iter()
        .map(|pkg| (pkg.pkgname.clone(), pkg.pkgpath.clone()))
        .collect();

    // Get resolved dependencies from database
    let pkgname_to_deps = db.get_all_resolved_deps()?;

    // Build set of packages in the resolved dependency graph
    let mut resolved: HashSet<String> = HashSet::new();
    for (pkg, deps) in &pkgname_to_deps {
        resolved.insert(pkg.clone());
        resolved.extend(deps.iter().cloned());
    }

    // Get build results for filtering
    let results = db.get_all_build_results()?;
    let excluded: HashSet<String> = results
        .iter()
        .filter(|r| matches!(r.state, PackageState::UpToDate) || r.state.is_skip())
        .map(|r| r.pkgname.pkgname().to_string())
        .collect();
    let up_to_date: HashSet<String> = results
        .iter()
        .filter(|r| matches!(r.state, PackageState::UpToDate))
        .map(|r| r.pkgname.pkgname().to_string())
        .collect();

    // Determine package set
    let packages: HashSet<String> = if let Some(pattern) = package {
        let re = Regex::new(pattern)
            .map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", pattern, e))?;

        let matches: Vec<&str> = pkgname_to_pkgpath
            .iter()
            .filter(|(name, path)| {
                resolved.contains(*name) && (re.is_match(name) || re.is_match(path))
            })
            .map(|(name, _)| name.as_str())
            .collect();

        if matches.is_empty() {
            bail!("No packages match '{}'", pattern);
        }

        let mut required: HashSet<&str> = HashSet::new();
        for pkg in &matches {
            required.insert(pkg);
            collect_transitive_deps(pkg, &pkgname_to_deps, &mut required);
        }

        let required: HashSet<String> = required.iter().map(|s| s.to_string()).collect();
        if include_all {
            required
        } else {
            required
                .into_iter()
                .filter(|p| !excluded.contains(p))
                .collect()
        }
    } else {
        let all_buildable: HashSet<String> = buildable_pkgs
            .iter()
            .filter(|pkg| resolved.contains(&pkg.pkgname))
            .map(|pkg| pkg.pkgname.clone())
            .collect();

        if include_all {
            all_buildable
        } else {
            all_buildable
                .into_iter()
                .filter(|p| !excluded.contains(p))
                .collect()
        }
    };

    if packages.is_empty() {
        println!("All packages are up-to-date");
        return Ok(());
    }

    let mut filtered_deps: HashMap<String, Vec<String>> = pkgname_to_deps
        .iter()
        .filter(|(pkg, _)| packages.contains(*pkg))
        .map(|(pkg, deps)| {
            (
                pkg.clone(),
                deps.iter()
                    .filter(|d| packages.contains(*d))
                    .cloned()
                    .collect(),
            )
        })
        .collect();
    for pkg in &packages {
        filtered_deps.entry(pkg.clone()).or_default();
    }

    let mut levels: HashMap<String, usize> = HashMap::new();
    loop {
        let before = levels.len();
        for (pkg, deps) in &filtered_deps {
            if !levels.contains_key(pkg) && deps.iter().all(|d| levels.contains_key(d)) {
                let level = deps
                    .iter()
                    .filter_map(|d| levels.get(d))
                    .max()
                    .map_or(0, |m| m + 1);
                levels.insert(pkg.clone(), level);
            }
        }
        if levels.len() == before {
            break;
        }
    }
    let max_level = levels.values().max().copied().unwrap_or(0);
    let mut by_level: Vec<Vec<String>> = vec![Vec::new(); max_level + 1];
    for (pkg, &level) in &levels {
        by_level[level].push(pkg.clone());
    }
    for level_pkgs in &mut by_level {
        level_pkgs.sort();
    }

    let display_name = |pkg: &str| -> String {
        if use_path {
            pkgname_to_pkgpath
                .get(pkg)
                .cloned()
                .unwrap_or_else(|| pkg.to_string())
        } else {
            pkg.to_string()
        }
    };

    let term_width = terminal::size().map(|(w, _)| w as usize).unwrap_or(80);
    let suffix_len = if include_all { 13 } else { 0 };

    let mut indent_width = 1;
    for try_indent in [3, 2, 1] {
        let fits = by_level.iter().enumerate().all(|(level, pkgs)| {
            level == 0
                || pkgs.iter().all(|pkg| {
                    level * try_indent + display_name(pkg).len() + suffix_len <= term_width
                })
        });
        if fits {
            indent_width = try_indent;
            break;
        }
    }

    #[cfg(target_os = "netbsd")]
    let (mid_conn, last_conn, span_mid, span_last) = match (format, indent_width) {
        (TreeOutput::Utf8, 3) => ("├─ ", "└─ ", "└──── ", "└──── "),
        (TreeOutput::Utf8, 2) => ("├ ", "└ ", "└── ", "└── "),
        (TreeOutput::Utf8, _) => ("├ ", "└ ", "└─ ", "└─ "),
        (TreeOutput::Ascii, 3) => ("|- ", "`- ", "`--+- ", "`---- "),
        (TreeOutput::Ascii, 2) => ("| ", "` ", "`-+ ", "`-- "),
        (TreeOutput::Ascii, _) => ("| ", "` ", "`+ ", "`- "),
        (TreeOutput::None, _) => ("", "", "", ""),
    };
    #[cfg(not(target_os = "netbsd"))]
    let (mid_conn, last_conn, span_mid, span_last) = match (format, indent_width) {
        (TreeOutput::Utf8, 3) => ("├─ ", "╰─ ", "╰──┬─ ", "╰──── "),
        (TreeOutput::Utf8, 2) => ("├ ", "╰ ", "╰─┬ ", "╰── "),
        (TreeOutput::Utf8, _) => ("├ ", "╰ ", "╰┬ ", "╰─ "),
        (TreeOutput::Ascii, 3) => ("|- ", "`- ", "`--+- ", "`---- "),
        (TreeOutput::Ascii, 2) => ("| ", "` ", "`-+ ", "`-- "),
        (TreeOutput::Ascii, _) => ("| ", "` ", "`+ ", "`- "),
        (TreeOutput::None, _) => ("", "", "", ""),
    };

    let max_level = by_level.len().saturating_sub(1);

    let (dim, reset) = if use_color() && format != TreeOutput::None {
        ("\x1b[2m", "\x1b[0m")
    } else {
        ("", "")
    };

    'outer: for (level, pkgs) in by_level.iter().enumerate() {
        let pkg_count = pkgs.len();
        let has_next_level = level < max_level;

        for (i, pkg) in pkgs.iter().enumerate() {
            let name = display_name(pkg);
            let suffix = if include_all && up_to_date.contains(pkg) {
                " (up-to-date)"
            } else {
                ""
            };

            let is_first = i == 0;
            let is_last = i == pkg_count - 1;

            let line = if level == 0 {
                format!("{}{}", name, suffix)
            } else if format == TreeOutput::None {
                format!("{}{}{}", " ".repeat(indent_width * level), name, suffix)
            } else if is_first && level > 1 {
                // First item at level 2+ - use spanning connector from previous level
                let prefix = " ".repeat(indent_width * (level - 2));
                let span = if pkg_count == 1 && !has_next_level {
                    span_last
                } else {
                    span_mid
                };
                format!("{}{}{}{}{}{}", dim, prefix, span, reset, name, suffix)
            } else {
                // Level 1 items, or subsequent items at any level
                let indent = " ".repeat(indent_width * (level - 1));
                let conn = if is_last && !has_next_level {
                    last_conn
                } else {
                    mid_conn
                };
                format!("{}{}{}{}{}{}", dim, indent, conn, reset, name, suffix)
            };
            if !try_println(&line) {
                break 'outer;
            }
        }
    }

    Ok(())
}

/**
 * Print package status with selectable columns in build order.
 *
 * Shows packages ordered by effective weight so that packages with the
 * most transitive dependents appear first. Supports filtering by status
 * and package name/path regex.
 */
fn print_build_status(
    db: &Database,
    statuses: &[PackageStateKind],
    columns: Option<&[String]>,
    no_header: bool,
    pkg_filters: &[String],
    show_all: bool,
) -> Result<()> {
    let all_cols = ["pkgname", "pkgpath", "status", "reason", "multi_version"];
    let default_cols = ["pkgname", "status", "reason"];
    let cols: Vec<&str> = columns
        .map(|c| c.iter().map(|s| s.as_str()).collect())
        .unwrap_or_else(|| default_cols.to_vec());

    for col in &cols {
        if !all_cols.contains(col) {
            bail!(
                "Unknown column '{}'. Valid columns: {}",
                col,
                all_cols.join(", ")
            );
        }
    }

    let max_width = |col: &str| -> usize {
        match col {
            "pkgname" => 40,
            "pkgpath" => 35,
            _ => usize::MAX,
        }
    };

    let pkg_patterns: Vec<Regex> = pkg_filters
        .iter()
        .map(|p| Regex::new(p).map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", p, e)))
        .collect::<Result<Vec<_>>>()?;

    let need_multi = cols.contains(&"multi_version");
    let all_pkgs = db.get_all_package_status(need_multi)?;
    let id_to_pkg: HashMap<i64, &PackageStatusRow> = all_pkgs.iter().map(|p| (p.id, p)).collect();

    let dep_ids = db.get_resolved_dep_ids()?;
    let mut id_deps: HashMap<i64, Vec<i64>> = HashMap::new();
    for &(pkg_id, dep_id) in &dep_ids {
        id_deps.entry(pkg_id).or_default().push(dep_id);
        id_deps.entry(dep_id).or_default();
    }

    let (sorted_ids, _) = bob::build_order(&id_deps, |_| 1);

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

    let mut rows: Vec<[String; 5]> = Vec::new();
    for id in &sorted_ids {
        let pkg = match id_to_pkg.get(id) {
            Some(p) => p,
            None => continue,
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

        rows.push([
            pkg.pkgname.clone(),
            pkg.pkgpath.clone(),
            status.to_string(),
            reason,
            multi_version,
        ]);
    }

    if rows.is_empty() {
        if !statuses.is_empty() || !pkg_filters.is_empty() {
            bail!("No packages match the criteria");
        }
        return Ok(());
    }

    let col_idx = |name: &str| -> usize {
        match name {
            "pkgname" => 0,
            "pkgpath" => 1,
            "status" => 2,
            "reason" => 3,
            "multi_version" => 4,
            _ => 0,
        }
    };

    let widths: Vec<usize> = cols
        .iter()
        .map(|&col| {
            let idx = col_idx(col);
            let header_len = col.len();
            let max_data = rows.iter().map(|r| r[idx].len()).max().unwrap_or(0);
            header_len.max(max_data).min(max_width(col))
        })
        .collect();

    if !no_header {
        let header: Vec<String> = cols
            .iter()
            .zip(&widths)
            .map(|(&col, &w)| format!("{:<width$}", col.to_uppercase(), width = w))
            .collect();
        if !try_println(header.join("  ").trim_end()) {
            return Ok(());
        }
    }

    for row in &rows {
        let values: Vec<String> = cols
            .iter()
            .zip(&widths)
            .map(|(&col, &w)| format!("{:<width$}", row[col_idx(col)], width = w))
            .collect();
        if !try_println(values.join("  ").trim_end()) {
            break;
        }
    }

    Ok(())
}

fn print_history(
    db: &Database,
    columns: Option<&[String]>,
    no_header: bool,
    long: bool,
    raw: bool,
    format: HistoryFormat,
    package: Option<&str>,
) -> Result<()> {
    let all_cols = bob::HistoryKind::all_names();
    let default_cols = bob::HistoryKind::default_names();
    let cols: Vec<&str> = if columns.is_some() {
        columns
            .map(|c| c.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    } else if long {
        all_cols.iter().map(|s| s.as_str()).collect()
    } else {
        default_cols
    };

    for col in &cols {
        if !all_cols.iter().any(|c| c == col) {
            bail!(
                "Unknown column '{}'. Valid columns: {}",
                col,
                all_cols.join(", ")
            );
        }
    }

    let pattern = package
        .map(|p| Regex::new(p).map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", p, e)))
        .transpose()?;

    let records = db.query_history(pattern.as_ref())?;

    if records.is_empty() {
        if package.is_some() {
            bail!("No history matches the pattern");
        } else {
            println!("No build history recorded");
        }
        return Ok(());
    }

    let format_val = |rec: &bob::History, col: &str| -> String {
        if raw {
            rec.format_col_raw(col)
        } else {
            rec.format_col(col)
        }
    };

    match format {
        HistoryFormat::Table => {
            let rows: Vec<Vec<String>> = records
                .iter()
                .map(|rec| cols.iter().map(|&col| format_val(rec, col)).collect())
                .collect();

            let widths: Vec<usize> = cols
                .iter()
                .enumerate()
                .map(|(i, col)| {
                    let header_len = col.len();
                    let max_data = rows.iter().map(|r| r[i].len()).max().unwrap_or(0);
                    header_len.max(max_data)
                })
                .collect();

            if !no_header {
                let header: Vec<String> = cols
                    .iter()
                    .zip(&widths)
                    .map(|(&col, &w)| format!("{:<width$}", col.to_uppercase(), width = w))
                    .collect();
                if !try_println(header.join("  ").trim_end()) {
                    return Ok(());
                }
            }

            for row in &rows {
                let values: Vec<String> = row
                    .iter()
                    .zip(&widths)
                    .map(|(val, &w)| format!("{:<width$}", val, width = w))
                    .collect();
                if !try_println(values.join("  ").trim_end()) {
                    break;
                }
            }
        }
        HistoryFormat::Csv => {
            if !no_header && !try_println(&cols.join(",")) {
                return Ok(());
            }
            for rec in &records {
                let values: Vec<String> = cols
                    .iter()
                    .map(|&col| {
                        let v = format_val(rec, col);
                        if v.contains(',') || v.contains('"') {
                            format!("\"{}\"", v.replace('"', "\"\""))
                        } else {
                            v
                        }
                    })
                    .collect();
                if !try_println(&values.join(",")) {
                    break;
                }
            }
        }
        HistoryFormat::Json => {
            let array: Vec<serde_json::Map<String, serde_json::Value>> = records
                .iter()
                .map(|rec| {
                    cols.iter()
                        .map(|&col| {
                            (
                                col.to_string(),
                                serde_json::Value::String(format_val(rec, col)),
                            )
                        })
                        .collect()
                })
                .collect();
            try_println(&serde_json::to_string_pretty(&array)?);
        }
    }

    Ok(())
}
