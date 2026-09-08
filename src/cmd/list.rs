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
use pkgsrc::PkgName;

use bob::db::Database;
use bob::try_println;
use bob::{PackageState, PkgMatch};

use super::{
    Cell, Column, ColumnSource, OutputFormat, OutputOptions, Writer, cols_help, package_status,
    parse_status_filter, select_columns,
};

fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
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

#[derive(Debug, Default, clap::Args)]
pub struct BuildsArgs {
    /// Hide column headers
    #[arg(short = 'H')]
    pub no_header: bool,
    /// Output raw numeric values (ms for durations)
    #[arg(short = 'r', long)]
    pub raw: bool,
    /// Output format
    #[arg(short = 'f', long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,
    /// Columns to display (comma-separated, see --help for full list)
    #[arg(short = 'o', long_help = builds_columns_help(), value_delimiter = ',')]
    pub columns: Option<Vec<String>>,
}

#[derive(Debug, Subcommand)]
pub enum ListCmd {
    /// List builds recorded in history (default)
    Builds(BuildsArgs),
    /// Show dependency tree of packages to build
    Tree {
        /// Show reverse dependencies (packages that depend on the selected package)
        #[arg(short = 'r', long)]
        reverse: bool,
        /// Filter packages by status (repeatable or comma-separated)
        #[arg(
            short = 's',
            long = "status",
            long_help = super::status::status_long_help(),
            value_delimiter = ',',
            value_parser = parse_status_filter
        )]
        statuses: Vec<Vec<PackageState>>,
        /// Output format (default: utf8 on terminal, none otherwise)
        #[arg(short = 'f', long, value_enum)]
        format: Option<TreeOutput>,
        /// Output pkgpath instead of pkgname
        #[arg(short, long)]
        path: bool,
        /// Package to show tree for
        #[arg(value_name = "PATTERN")]
        package: Option<String>,
    },
    /// Show what is blocking a package from building
    Blockers {
        /// Package name or pkgpath pattern
        #[arg(value_name = "PATTERN")]
        package: String,
        /// Output pkgpath instead of pkgname
        #[arg(short, long)]
        path: bool,
    },
    /// Show packages blocked by a failed package
    #[command(alias = "broken-by")]
    BlockedBy {
        /// Package name or pkgpath pattern
        #[arg(value_name = "PATTERN")]
        package: String,
        /// Output pkgpath instead of pkgname
        #[arg(short, long)]
        path: bool,
    },
}

pub fn run(db: &Database, cmd: ListCmd) -> Result<()> {
    if !matches!(cmd, ListCmd::Builds { .. }) && db.count_packages()? == 0 {
        bail!("No packages in database. Run 'bob scan' first.");
    }

    match cmd {
        ListCmd::Builds(args) => list_builds(db, args)?,
        ListCmd::Tree {
            reverse,
            statuses,
            format,
            path,
            package,
        } => {
            let format = format.unwrap_or(if std::io::stdout().is_terminal() {
                TreeOutput::Utf8
            } else {
                TreeOutput::None
            });
            print_build_tree(db, path, reverse, &statuses, format, package.as_deref())?;
        }
        ListCmd::Blockers { package, path } => {
            let matches = match_packages(db, &package)?;
            let multi = matches.len() > 1;
            for pkg in matches {
                if multi && !try_println(&format!("{} ({}):", pkg.pkgname, pkg.pkg_location)) {
                    return Ok(());
                }
                for (pkgname, pkgpath, reason) in db.get_blockers(pkg.id)? {
                    let s = if path {
                        format!("{}{} ({})", if multi { "  " } else { "" }, pkgpath, reason)
                    } else {
                        format!("{}{} ({})", if multi { "  " } else { "" }, pkgname, reason)
                    };
                    if !try_println(&s) {
                        return Ok(());
                    }
                }
            }
        }
        ListCmd::BlockedBy { package, path } => {
            let matches = match_packages(db, &package)?;
            let multi = matches.len() > 1;
            for pkg in matches {
                if multi && !try_println(&format!("{} ({}):", pkg.pkgname, pkg.pkg_location)) {
                    return Ok(());
                }
                for (pkgname, pkgpath) in db.get_blocked_by(pkg.id)? {
                    let s = if path {
                        format!("{}{}", if multi { "  " } else { "" }, pkgpath)
                    } else {
                        format!("{}{}", if multi { "  " } else { "" }, pkgname)
                    };
                    if !try_println(&s) {
                        return Ok(());
                    }
                }
            }
        }
    }

    Ok(())
}

const COLS: &[Column] = &[
    Column::BuildId,
    Column::Completed,
    Column::Packages,
    Column::Succeeded,
    Column::Uptodate,
    Column::Failed,
    Column::Masked,
    Column::Duration,
];

fn builds_columns_help() -> String {
    cols_help(COLS, COLS)
}

impl ColumnSource for bob::db::BuildListEntry {
    type Ctx = ();
    fn cell(&self, col: Column, _: &Self::Ctx) -> Cell {
        match col {
            Column::BuildId => self.build_id.as_str().into(),
            Column::Completed => Cell::Bool(self.completed),
            Column::Packages => self.package_count.into(),
            Column::Succeeded => self.succeeded.into(),
            Column::Uptodate => self.up_to_date.into(),
            Column::Failed => self.failed.into(),
            Column::Masked => self.masked.into(),
            Column::Duration => Cell::DurationMs(self.duration_ms),
            _ => unreachable!("column {:?} not supported by bob list builds", col),
        }
    }
}

fn list_builds(db: &Database, args: BuildsArgs) -> Result<()> {
    let chosen = select_columns(args.columns.as_deref(), false, COLS, COLS)?;

    let builds = db.list_history_builds()?;
    if builds.is_empty() {
        println!("No builds in history.");
        return Ok(());
    }
    let mut out = Writer::stdout(
        chosen,
        OutputOptions {
            format: args.format,
            no_header: args.no_header,
            raw: args.raw,
        },
    );
    for b in &builds {
        out.write(None, b, &());
    }
    out.finish()?;
    Ok(())
}

/**
 * Resolve a user-supplied package pattern to the matching set of
 * packages from the scan database.  Errors if no packages match.
 */
fn match_packages(db: &Database, pattern: &str) -> Result<Vec<bob::db::PackageRow>> {
    let re = PkgMatch::new(pattern)?;
    let matches: Vec<bob::db::PackageRow> = db
        .get_all_packages()?
        .into_iter()
        .filter(|p| re.is_match(&p.pkgname) || re.is_match(&p.pkg_location))
        .collect();
    if matches.is_empty() {
        bail!("No packages match '{}'", pattern);
    }
    Ok(matches)
}

/**
 * Collect transitive dependencies for a package.
 */
fn collect_transitive_deps<'a>(
    pkg: &'a PkgName,
    deps: &'a HashMap<PkgName, Vec<PkgName>>,
    result: &mut HashSet<&'a PkgName>,
) {
    if let Some(pkg_deps) = deps.get(pkg) {
        for dep in pkg_deps {
            if result.insert(dep) {
                collect_transitive_deps(dep, deps, result);
            }
        }
    }
}

/**
 * Print the dependency tree for packages to build.
 *
 * When a package pattern is provided, shows a proper dependency tree for
 * matching packages. Otherwise, uses topological levels to show build order.
 * Reverse mode shows the selected package followed by its reverse
 * dependencies.
 */
fn print_build_tree(
    db: &Database,
    use_path: bool,
    reverse: bool,
    status_filters: &[Vec<PackageState>],
    format: TreeOutput,
    package: Option<&str>,
) -> Result<()> {
    // pkgname -> pkgpath for every scanned package
    let pkgname_to_pkgpath: HashMap<PkgName, String> = db
        .get_all_packages()?
        .into_iter()
        .map(|p| (PkgName::new(&p.pkgname), p.pkg_location))
        .collect();

    // Get resolved dependencies from database
    let mut pkgname_to_deps = db.get_all_resolved_deps()?;

    if reverse {
        let mut reverse_deps: HashMap<PkgName, Vec<PkgName>> = HashMap::new();
        for (pkg, deps) in pkgname_to_deps {
            for dep in deps {
                reverse_deps.entry(dep).or_default().push(pkg.clone());
            }
        }
        pkgname_to_deps = reverse_deps;
    }

    // Get build results for filtering
    let statuses: HashSet<PackageState> = status_filters.iter().flatten().copied().collect();
    let package_status: HashMap<PkgName, PackageState> = db
        .get_all_package_status()?
        .into_iter()
        .map(|p| (PkgName::new(&p.pkgname), package_status(&p)))
        .collect();
    // Determine package set
    let mut roots = Vec::new();
    let candidates: HashSet<PkgName> = if let Some(pattern) = package {
        let re = PkgMatch::new(pattern)?;

        let matches: Vec<&PkgName> = pkgname_to_pkgpath
            .iter()
            .filter(|(name, path)| re.is_match(name.as_ref()) || re.is_match(path.as_str()))
            .map(|(name, _)| name)
            .collect();

        if matches.is_empty() {
            bail!("No packages match '{}'", pattern);
        }

        let mut required: HashSet<&PkgName> = HashSet::new();
        for &pkg in &matches {
            roots.push(pkg);
            required.insert(pkg);
            collect_transitive_deps(pkg, &pkgname_to_deps, &mut required);
        }

        required.into_iter().cloned().collect()
    } else {
        pkgname_to_pkgpath.keys().cloned().collect()
    };

    let packages: HashSet<PkgName> = if statuses.is_empty() {
        candidates
    } else {
        candidates
            .into_iter()
            .filter(|pkg| {
                package_status
                    .get(pkg)
                    .is_some_and(|state| statuses.contains(state))
            })
            .collect()
    };

    if packages.is_empty() {
        println!("No packages to display");
        return Ok(());
    }

    let mut filtered_deps: HashMap<PkgName, Vec<PkgName>> = pkgname_to_deps
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
    roots.retain(|root| packages.contains(*root));
    if reverse && roots.is_empty() {
        roots.extend(
            filtered_deps
                .iter()
                .filter(|(_, deps)| deps.is_empty())
                .map(|(pkg, _)| pkg),
        );
    }

    let mut levels: HashMap<&PkgName, usize> = if reverse {
        roots.into_iter().map(|pkg| (pkg, 0)).collect()
    } else {
        HashMap::new()
    };
    loop {
        let before = levels.len();
        if !reverse {
            for (pkg, deps) in &filtered_deps {
                if !levels.contains_key(pkg) && deps.iter().all(|d| levels.contains_key(d)) {
                    let level = deps
                        .iter()
                        .filter_map(|d| levels.get(d))
                        .max()
                        .map_or(0, |m| m + 1);
                    levels.insert(pkg, level);
                }
            }
        }
        if reverse {
            for (pkg, deps) in &filtered_deps {
                if let Some(&level) = levels.get(pkg) {
                    for dep in deps {
                        levels.entry(dep).or_insert(level + 1);
                    }
                }
            }
        }
        if levels.len() == before {
            break;
        }
    }
    for pkg in filtered_deps.keys() {
        if !levels.contains_key(pkg) {
            levels.insert(pkg, 0);
        }
    }
    let max_level = levels.values().max().copied().unwrap_or(0);
    let mut by_level: Vec<Vec<&PkgName>> = vec![Vec::new(); max_level + 1];
    for (pkg, &level) in &levels {
        by_level[level].push(pkg);
    }
    for level_pkgs in &mut by_level {
        level_pkgs.sort();
    }

    let display_name = |pkg: &PkgName| -> String {
        if use_path {
            pkgname_to_pkgpath
                .get(pkg)
                .map(|p| p.to_string())
                .unwrap_or_else(|| pkg.to_string())
        } else {
            pkg.to_string()
        }
    };

    let term_width = terminal::size().map(|(w, _)| w as usize).unwrap_or(80);

    let mut indent_width = 1;
    for try_indent in [3, 2, 1] {
        let fits = by_level.iter().enumerate().all(|(level, pkgs)| {
            level == 0
                || pkgs
                    .iter()
                    .all(|pkg| level * try_indent + display_name(pkg).len() <= term_width)
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
            let is_first = i == 0;
            let is_last = i == pkg_count - 1;

            let line = if level == 0 {
                name
            } else if format == TreeOutput::None {
                format!("{}{}", " ".repeat(indent_width * level), name)
            } else if is_first && level > 1 {
                // First item at level 2+ - use spanning connector from previous level
                let prefix = " ".repeat(indent_width * (level - 2));
                let span = if pkg_count == 1 && !has_next_level {
                    span_last
                } else {
                    span_mid
                };
                format!("{}{}{}{}{}", dim, prefix, span, reset, name)
            } else {
                // Level 1 items, or subsequent items at any level
                let indent = " ".repeat(indent_width * (level - 1));
                let conn = if is_last && !has_next_level {
                    last_conn
                } else {
                    mid_conn
                };
                format!("{}{}{}{}{}", dim, indent, conn, reset, name)
            };
            if !try_println(&line) {
                break 'outer;
            }
        }
    }

    Ok(())
}
