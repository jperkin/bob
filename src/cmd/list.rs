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

use anyhow::{Result, bail};
use clap::Subcommand;
use crossterm::terminal;
use regex::Regex;

use bob::build::BuildOutcome;
use bob::db::Database;
use bob::scan::SkipReason;
use bob::try_println;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SkipCategory {
    Prefailed,
    IndirectPrefailed,
    IndirectFailed,
    Unresolved,
}

impl From<&SkipReason> for SkipCategory {
    fn from(reason: &SkipReason) -> Self {
        match reason {
            SkipReason::PkgSkip(_) => SkipCategory::Prefailed,
            SkipReason::PkgFail(_) => SkipCategory::Prefailed,
            SkipReason::IndirectSkip(_) => SkipCategory::IndirectPrefailed,
            SkipReason::IndirectFail(_) => SkipCategory::IndirectFailed,
            SkipReason::UnresolvedDep(_) => SkipCategory::Unresolved,
        }
    }
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

#[derive(Debug, Subcommand)]
pub enum ListCmd {
    /// List all scanned packages
    All,
    /// List packages ready to build (no skip/fail reason)
    Buildable,
    /// List successfully built packages
    Success,
    /// List packages with existing binaries (up-to-date)
    UpToDate,
    /// List packages that failed to build
    Failed,
    /// List packages that depend on a package that failed to build
    IndirectFailed,
    /// List packages with PKG_SKIP_REASON or PKG_FAIL_REASON set
    Prefailed,
    /// List packages that depend on a prefailed package
    IndirectPrefailed,
    /// List packages with unresolved dependencies
    Unresolved,
    /// Show what's blocking a package from building
    Blockers {
        /// Package name or pkgpath
        package: String,
    },
    /// Show packages blocked by a failed package
    BlockedBy {
        /// Package name or pkgpath
        package: String,
    },
    /// Show dependency tree of packages to build
    Tree {
        /// Include up-to-date packages
        #[arg(short, long)]
        all: bool,
        /// Output format
        #[arg(short = 'f', long, value_enum, default_value_t = TreeOutput::Utf8)]
        format: TreeOutput,
        /// Package to show tree for (regex pattern)
        package: Option<String>,
    },
    /// Show package status with columns
    Status {
        /// Hide column headers
        #[arg(short = 'H', long = "no-header")]
        no_header: bool,
        /// Columns to display (comma-separated: pkgname,pkgpath,status,reason)
        #[arg(short = 'o', long, value_delimiter = ',')]
        columns: Option<Vec<String>>,
        /// Filter to specific package (name or path)
        package: Option<String>,
    },
}

pub fn run(db: &Database, cmd: ListCmd, path: bool) -> Result<()> {
    if db.count_packages()? == 0 {
        bail!("No packages in database. Run 'bob scan' first.");
    }

    match cmd {
        ListCmd::All => {
            for pkg in db.get_all_packages()? {
                let s = if path { &pkg.pkgpath } else { &pkg.pkgname };
                if !try_println(s) {
                    break;
                }
            }
        }
        ListCmd::Buildable => {
            for pkg in db.get_buildable_packages()? {
                let s = if path { &pkg.pkgpath } else { &pkg.pkgname };
                if !try_println(s) {
                    break;
                }
            }
        }
        ListCmd::Success => {
            for result in db.get_all_build_results()? {
                if matches!(
                    result.outcome,
                    BuildOutcome::Success | BuildOutcome::UpToDate
                ) {
                    let s = if path {
                        result.pkgpath.as_ref().map(|p| p.to_string())
                    } else {
                        Some(result.pkgname.pkgname().to_string())
                    };
                    if let Some(s) = s {
                        if !try_println(&s) {
                            break;
                        }
                    }
                }
            }
        }
        ListCmd::Failed => {
            for result in db.get_all_build_results()? {
                if matches!(result.outcome, BuildOutcome::Failed(_)) {
                    let s = if path {
                        result.pkgpath.as_ref().map(|p| p.to_string())
                    } else {
                        Some(result.pkgname.pkgname().to_string())
                    };
                    if let Some(s) = s {
                        if !try_println(&s) {
                            break;
                        }
                    }
                }
            }
        }
        ListCmd::Prefailed
        | ListCmd::IndirectPrefailed
        | ListCmd::IndirectFailed
        | ListCmd::Unresolved => {
            let filter = match cmd {
                ListCmd::Prefailed => SkipCategory::Prefailed,
                ListCmd::IndirectPrefailed => SkipCategory::IndirectPrefailed,
                ListCmd::IndirectFailed => SkipCategory::IndirectFailed,
                ListCmd::Unresolved => SkipCategory::Unresolved,
                _ => unreachable!(),
            };

            for result in db.get_all_build_results()? {
                if let BuildOutcome::Skipped(ref skip) = result.outcome {
                    if SkipCategory::from(skip) == filter {
                        let s = if path {
                            result.pkgpath.as_ref().map(|p| p.to_string())
                        } else {
                            Some(result.pkgname.pkgname().to_string())
                        };
                        if let Some(s) = s {
                            if !try_println(&s) {
                                break;
                            }
                        }
                    }
                }
            }
        }
        ListCmd::UpToDate => {
            for result in db.get_all_build_results()? {
                if matches!(result.outcome, BuildOutcome::UpToDate) {
                    let s = if path {
                        result.pkgpath.as_ref().map(|p| p.to_string())
                    } else {
                        Some(result.pkgname.pkgname().to_string())
                    };
                    if let Some(s) = s {
                        if !try_println(&s) {
                            break;
                        }
                    }
                }
            }
        }
        ListCmd::Blockers { package } => {
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
        ListCmd::BlockedBy { package } => {
            for (pkgname, pkgpath) in db.get_blocked_by(&package)? {
                let s = if path { pkgpath } else { pkgname };
                if !try_println(&s) {
                    break;
                }
            }
        }
        ListCmd::Tree {
            all,
            format,
            package,
        } => {
            print_build_tree(db, path, all, format, package.as_deref())?;
        }
        ListCmd::Status {
            no_header,
            columns,
            package,
        } => {
            print_build_status(db, no_header, columns.as_deref(), package.as_deref())?;
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
        .filter(|r| matches!(r.outcome, BuildOutcome::UpToDate | BuildOutcome::Skipped(_)))
        .map(|r| r.pkgname.pkgname().to_string())
        .collect();
    let up_to_date: HashSet<String> = results
        .iter()
        .filter(|r| matches!(r.outcome, BuildOutcome::UpToDate))
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
            println!("No packages match '{}'", pattern);
            return Ok(());
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

    let filtered_deps: HashMap<String, Vec<String>> = pkgname_to_deps
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

    let levels = calculate_levels(&packages, &filtered_deps);
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
    for try_indent in [4, 3, 2, 1] {
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

    let (mid_conn, last_conn) = match (format, indent_width) {
        (TreeOutput::Utf8, 4) => ("├── ", "└── "),
        (TreeOutput::Utf8, 3) => ("├─ ", "└─ "),
        (TreeOutput::Utf8, _) => ("├ ", "└ "),
        (TreeOutput::Ascii, 4) => ("|-- ", "`-- "),
        (TreeOutput::Ascii, 3) => ("|- ", "`- "),
        (TreeOutput::Ascii, _) => ("| ", "` "),
        (TreeOutput::None, _) => ("", ""),
    };

    'outer: for (level, pkgs) in by_level.iter().enumerate() {
        let last_idx = pkgs.len().saturating_sub(1);
        for (i, pkg) in pkgs.iter().enumerate() {
            let name = display_name(pkg);
            let suffix = if include_all && up_to_date.contains(pkg) {
                " (up-to-date)"
            } else {
                ""
            };

            let line = if level == 0 {
                format!("{}{}", name, suffix)
            } else if format == TreeOutput::None {
                format!("{}{}{}", " ".repeat(indent_width * level), name, suffix)
            } else {
                let indent = " ".repeat(indent_width * (level - 1));
                let conn = if i == last_idx { last_conn } else { mid_conn };
                format!("{}{}{}{}", indent, conn, name, suffix)
            };
            if !try_println(&line) {
                break 'outer;
            }
        }
    }

    Ok(())
}

/**
 * Calculate topological level for each package.
 * Level 0 = no dependencies in build set
 * Level N = max(level of dependencies) + 1
 */
fn calculate_levels(
    packages: &HashSet<String>,
    deps: &HashMap<String, Vec<String>>,
) -> HashMap<String, usize> {
    let mut levels: HashMap<String, usize> = HashMap::new();

    // Initialize: packages with no deps are level 0
    for pkg in packages {
        let pkg_deps = deps.get(pkg);
        if pkg_deps.is_none_or(|d| d.is_empty()) {
            levels.insert(pkg.clone(), 0);
        }
    }

    // Iterate until all levels are assigned
    loop {
        let mut changed = false;
        for pkg in packages {
            if levels.contains_key(pkg) {
                continue;
            }
            let pkg_deps = match deps.get(pkg) {
                Some(d) => d,
                None => continue,
            };
            // Check if all dependencies have levels assigned
            let all_deps_have_levels = pkg_deps.iter().all(|d| levels.contains_key(d));
            if all_deps_have_levels {
                let max_dep_level = pkg_deps
                    .iter()
                    .map(|d| levels.get(d).unwrap_or(&0))
                    .max()
                    .unwrap_or(&0);
                levels.insert(pkg.clone(), max_dep_level + 1);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    levels
}

/**
 * Print package status with selectable columns in dependency order.
 *
 * Shows packages in topological order so dependencies appear before packages
 * that depend on them. Only includes packages in the resolved dependency graph
 * (the actual build set), so a prefailed package appears before packages it
 * blocks.
 */
fn print_build_status(
    db: &Database,
    no_header: bool,
    columns: Option<&[String]>,
    filter: Option<&str>,
) -> Result<()> {
    // Default columns if none specified
    let all_cols = ["pkgname", "pkgpath", "status", "reason"];
    let default_cols = ["pkgname", "status", "reason"];
    let cols: Vec<&str> = columns
        .map(|c| c.iter().map(|s| s.as_str()).collect())
        .unwrap_or_else(|| default_cols.to_vec());

    // Validate column names
    for col in &cols {
        if !all_cols.contains(col) {
            bail!(
                "Unknown column '{}'. Valid columns: {}",
                col,
                all_cols.join(", ")
            );
        }
    }

    // Column width limits (for padding only - full values still displayed)
    let max_width = |col: &str| -> usize {
        match col {
            "pkgname" => 40,
            "pkgpath" => 35,
            _ => usize::MAX,
        }
    };

    // Compile filter as regex
    let filter_re = filter
        .map(Regex::new)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", filter.unwrap_or(""), e))?;

    // Get all packages for metadata lookup
    let all_pkgs = db.get_all_packages()?;
    let pkgname_to_pkg: HashMap<String, &_> =
        all_pkgs.iter().map(|p| (p.pkgname.clone(), p)).collect();

    // Get resolved dependencies - this defines the actual build set
    let pkgname_to_deps = db.get_all_resolved_deps()?;

    // Build set of packages in the resolved dependency graph
    let mut in_build: HashSet<String> = HashSet::new();
    for (pkg, deps) in &pkgname_to_deps {
        in_build.insert(pkg.clone());
        for dep in deps {
            in_build.insert(dep.clone());
        }
    }

    // Filter deps to only packages in the build set
    let filtered_deps: HashMap<String, Vec<String>> = pkgname_to_deps
        .into_iter()
        .filter(|(pkg, _)| in_build.contains(pkg))
        .map(|(pkg, deps)| {
            let filtered: Vec<String> = deps.into_iter().filter(|d| in_build.contains(d)).collect();
            (pkg, filtered)
        })
        .collect();

    // Get build results and reasons
    let build_results: HashMap<String, BuildOutcome> = db
        .get_all_build_results()?
        .into_iter()
        .map(|r| (r.pkgname.pkgname().to_string(), r.outcome))
        .collect();
    let build_reasons = db.get_all_build_reasons()?;

    // Calculate topological levels for packages in the build
    let levels = calculate_levels(&in_build, &filtered_deps);
    let max_level = levels.values().max().copied().unwrap_or(0);
    let mut by_level: Vec<Vec<String>> = vec![Vec::new(); max_level + 1];
    for (pkg, &level) in &levels {
        by_level[level].push(pkg.clone());
    }
    for level_pkgs in &mut by_level {
        level_pkgs.sort();
    }

    // Build rows in dependency order
    let mut rows: Vec<[String; 4]> = Vec::new();
    for pkgs in &by_level {
        for pkgname in pkgs {
            let pkg = match pkgname_to_pkg.get(pkgname) {
                Some(p) => p,
                None => continue,
            };

            // Apply regex filter if provided
            if let Some(ref re) = filter_re {
                if !re.is_match(pkgname) {
                    continue;
                }
            }

            let (status, reason) = if let Some(outcome) = build_results.get(pkgname) {
                match outcome {
                    BuildOutcome::Success => ("success", String::new()),
                    BuildOutcome::UpToDate => ("up-to-date", String::new()),
                    BuildOutcome::Failed(msg) => ("failed", msg.clone()),
                    BuildOutcome::Skipped(skip) => (skip.status(), skip.to_string()),
                }
            } else if let Some(reason) = build_reasons.get(pkgname) {
                ("pending", reason.clone())
            } else if let Some(reason) = &pkg.fail_reason {
                let skip = SkipReason::PkgFail(reason.clone());
                (skip.status(), skip.to_string())
            } else if let Some(reason) = &pkg.skip_reason {
                let skip = SkipReason::PkgSkip(reason.clone());
                (skip.status(), skip.to_string())
            } else {
                ("pending", String::new())
            };

            rows.push([
                pkgname.clone(),
                pkg.pkgpath.clone(),
                status.to_string(),
                reason,
            ]);
        }
    }

    if rows.is_empty() {
        println!("No packages to display");
        return Ok(());
    }

    // Map column names to indices
    let col_idx = |name: &str| -> usize {
        match name {
            "pkgname" => 0,
            "pkgpath" => 1,
            "status" => 2,
            "reason" => 3,
            _ => 0,
        }
    };

    // Calculate column widths (capped by max_width)
    let widths: Vec<usize> = cols
        .iter()
        .map(|&col| {
            let idx = col_idx(col);
            let header_len = col.len();
            let max_data = rows.iter().map(|r| r[idx].len()).max().unwrap_or(0);
            header_len.max(max_data).min(max_width(col))
        })
        .collect();

    // Print header
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

    // Print rows
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
