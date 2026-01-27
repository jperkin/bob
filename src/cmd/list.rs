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

use std::io::{self, Write};

use anyhow::{Result, bail};
use clap::Subcommand;

use bob::build::BuildOutcome;
use bob::db::Database;
use bob::scan::SkipReason;

/// Write a line to stdout, returning false on broken pipe (stop iteration).
fn out(s: &str) -> bool {
    let result = writeln!(io::stdout(), "{}", s);
    !matches!(result, Err(e) if e.kind() == io::ErrorKind::BrokenPipe)
}

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
}

pub fn run(db: &Database, cmd: ListCmd, path: bool) -> Result<()> {
    if db.count_packages()? == 0 {
        bail!("No packages in database. Run 'bob scan' first.");
    }

    match cmd {
        ListCmd::All => {
            for pkg in db.get_all_packages()? {
                let s = if path { &pkg.pkgpath } else { &pkg.pkgname };
                if !out(s) {
                    break;
                }
            }
        }
        ListCmd::Buildable => {
            for pkg in db.get_buildable_packages()? {
                let s = if path { &pkg.pkgpath } else { &pkg.pkgname };
                if !out(s) {
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
                        if !out(&s) {
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
                        if !out(&s) {
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
                            if !out(&s) {
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
                        if !out(&s) {
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
                if !out(&s) {
                    break;
                }
            }
        }
        ListCmd::BlockedBy { package } => {
            for (pkgname, pkgpath) in db.get_blocked_by(&package)? {
                let s = if path { pkgpath } else { pkgname };
                if !out(&s) {
                    break;
                }
            }
        }
    }

    Ok(())
}
