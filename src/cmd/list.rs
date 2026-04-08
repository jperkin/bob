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

use bob::PackageState;
use bob::db::Database;
use bob::try_println;

use super::util::pkg_pattern;

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

#[derive(Debug, Subcommand)]
pub enum ListCmd {
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
        /// Package name or pkgpath pattern (regex)
        package: String,
        /// Output pkgpath instead of pkgname
        #[arg(short, long)]
        path: bool,
    },
    /// Show packages blocked by a failed package
    BlockedBy {
        /// Package name or pkgpath pattern (regex)
        package: String,
        /// Output pkgpath instead of pkgname
        #[arg(short, long)]
        path: bool,
    },
}

pub fn run(db: &Database, cmd: ListCmd) -> Result<()> {
    if db.count_packages()? == 0 {
        bail!("No packages in database. Run 'bob scan' first.");
    }

    match cmd {
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
            let matches = match_packages(db, &package)?;
            let multi = matches.len() > 1;
            for pkg in matches {
                if multi && !try_println(&format!("{} ({}):", pkg.pkgname, pkg.pkgpath)) {
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
                if multi && !try_println(&format!("{} ({}):", pkg.pkgname, pkg.pkgpath)) {
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

/**
 * Resolve a user-supplied package pattern (regex) to the matching set
 * of packages from the scan database.  Errors if no packages match.
 */
fn match_packages(db: &Database, pattern: &str) -> Result<Vec<bob::db::PackageRow>> {
    let re = pkg_pattern(pattern)?;
    let matches: Vec<bob::db::PackageRow> = db
        .get_all_packages()?
        .into_iter()
        .filter(|p| re.is_match(&p.pkgname) || re.is_match(&p.pkgpath))
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
        let re = pkg_pattern(pattern)?;

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
