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

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::Command;

use anyhow::{Result, bail};
use clap::Args;
use regex::Regex;

use bob::db::Database;
use bob::{BuildResult, PackageState, Stage};

#[derive(Debug, Args)]
pub struct LogArgs {
    /// List log files sorted by modification time
    #[arg(short, long)]
    list: bool,
    /// Show log for a specific stage instead of the failed stage
    #[arg(short, long, value_enum)]
    stage: Option<Stage>,
    /// Package name or path pattern (regex)
    package: String,
}

pub fn run(db: &Database, args: LogArgs) -> Result<()> {
    let pattern = Regex::new(&format!("(?i){}", args.package))
        .map_err(|e| anyhow::anyhow!("Invalid pattern '{}': {}", args.package, e))?;

    let results = db.get_all_build_results()?;

    let matches: Vec<&BuildResult> = results
        .iter()
        .filter(|r| matches!(r.state, PackageState::Failed(_)))
        .filter(|r| {
            pattern.is_match(r.pkgname.pkgname())
                || r.pkgpath
                    .as_ref()
                    .is_some_and(|p| pattern.is_match(p.as_str()))
        })
        .collect();

    match matches.len() {
        0 => bail!("No failed packages match '{}'", args.package),
        1 => {
            let result = matches[0];
            if args.list {
                list_logs(result)
            } else {
                let log_file = stage_log(result, args.stage)?;
                page_file(&log_file)
            }
        }
        _ => {
            let mut msg = format!("Multiple failed packages match '{}':\n", args.package);
            for r in &matches {
                let pkgpath = r
                    .pkgpath
                    .as_ref()
                    .map_or(String::new(), |p| format!(" ({})", p));
                msg.push_str(&format!("  {}{}\n", r.pkgname.pkgname(), pkgpath));
            }
            bail!("{}", msg.trim_end());
        }
    }
}

/**
 * List log files in a package's log directory, sorted by modification time.
 */
fn list_logs(result: &BuildResult) -> Result<()> {
    let pkgname = result.pkgname.pkgname();
    let log_dir = result
        .log_dir
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No log directory for {}", pkgname))?;

    let mut entries: Vec<(std::time::SystemTime, std::path::PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(log_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "log") {
            let mtime = entry.metadata()?.modified()?;
            entries.push((mtime, path));
        }
    }
    entries.sort_by_key(|(mtime, _)| *mtime);

    for (_, path) in &entries {
        println!("{}", path.display());
    }
    Ok(())
}

/**
 * Return the path to a stage log file.
 *
 * If a stage is explicitly requested, use that.  Otherwise use the
 * stage that failed.
 */
fn stage_log(result: &BuildResult, stage: Option<Stage>) -> Result<std::path::PathBuf> {
    let pkgname = result.pkgname.pkgname();
    let log_dir = result
        .log_dir
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No log directory for {}", pkgname))?;
    let stage = stage
        .or(result.build_stats.stage)
        .ok_or_else(|| anyhow::anyhow!("No failed stage recorded for {}", pkgname))?;
    let log_file = log_dir.join(format!("{}.log", stage.into_str()));
    if !log_file.exists() {
        bail!("Log file not found: {}", log_file.display());
    }
    Ok(log_file)
}

/**
 * Display a file through the user's preferred pager.
 *
 * Uses $PAGER if set, otherwise falls back to "less".  If stdout is not
 * a terminal the file is written directly to stdout.
 */
fn page_file(path: &Path) -> Result<()> {
    if !std::io::stdout().is_terminal() {
        let content = std::fs::read(path)?;
        std::io::stdout().write_all(&content)?;
        return Ok(());
    }

    let pager = std::env::var("PAGER").unwrap_or_else(|_| "less".to_string());
    let file = std::fs::File::open(path)?;
    Command::new("sh")
        .args(["-c", &pager])
        .stdin(file)
        .status()?;

    Ok(())
}
