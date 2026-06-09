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

#![cfg_attr(not(doctest), doc = include_str!("../README.md"))]

pub mod action;
pub mod build;
pub mod config;
pub mod cpu;
pub mod db;
pub mod fmt;
pub mod logging;
pub mod makejobs;
pub mod pkgstate;
pub mod sandbox;
pub mod scan;
pub mod scheduler;
pub mod state;
pub mod summary;
pub mod vcs;

mod history;
mod init;
mod tui;

use std::io::{self, Write};

/**
 * Column alignment for tabular output.
 */
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Align {
    #[default]
    Left,
    Right,
}

/**
 * Column alignment, driven by the strum `align` prop.
 *
 * Default to left alignment.
 */
pub trait ColumnAlign: strum::EnumProperty {
    fn align(&self) -> Align {
        match self.get_str("align") {
            Some("right") => Align::Right,
            _ => Align::Left,
        }
    }
}

/**
 * Write a line to stdout, returning false on broken pipe.
 *
 * Use this in loops to gracefully handle SIGPIPE (e.g., when piped to `head`).
 */
pub fn try_println(s: &str) -> bool {
    let result = writeln!(io::stdout(), "{}", s);
    !matches!(result, Err(e) if e.kind() == io::ErrorKind::BrokenPipe)
}

/**
 * Return the current time as seconds since the Unix epoch.
 */
pub fn epoch_secs() -> Result<i64, std::time::SystemTimeError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
}

/**
 * `strftime` format for a build_id.  Build_ids are timestamp strings
 * minted at `Database::open` and stored as the primary key in
 * `build_metadata` and the `build_id` column of `build_history`.
 */
pub const BUILD_ID_FORMAT: &str = "%Y%m%dT%H%M%SZ";

/**
 * Parse a build_id string into the timestamp it encodes, or `None`
 * if `s` is not in the expected [`BUILD_ID_FORMAT`].
 */
pub fn parse_build_id(s: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(s, BUILD_ID_FORMAT).ok()
}

/**
 * Parse a human-style duration like `30d`, `6w`, `12m`, `1y` into a
 * count of seconds.  Units: `d` days, `w` weeks, `m` months (30 days),
 * `y` years (365 days).
 */
pub fn parse_duration_secs(s: &str) -> Result<i64, String> {
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num_part, unit) = s.split_at(split);
    let n: i64 = num_part
        .parse()
        .map_err(|_| format!("invalid duration '{}': expected NUMBER+UNIT", s))?;
    let secs_per = match unit {
        "d" => 86_400,
        "w" => 86_400 * 7,
        "m" => 86_400 * 30,
        "y" => 86_400 * 365,
        _ => {
            return Err(format!(
                "invalid duration unit '{}': use d, w, m, or y",
                unit
            ));
        }
    };
    Ok(n * secs_per)
}

/// Error indicating the operation was interrupted (e.g., by Ctrl+C).
#[derive(Debug)]
pub struct Interrupted;

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Interrupted")
    }
}

impl std::error::Error for Interrupted {}

// Re-export main types for convenience.
//
// The typical workflow is:
//   Config::load() → Scan::new() → scan.start() → scan.resolve()
//   → Build::new() → build.start()

pub use action::{Action, ActionType, FSType};
pub use build::{
    Build, BuildCounts, BuildReason, BuildResult, BuildSummary, PkgBuildStats, Stage,
    pkg_up_to_date,
};
pub use config::{
    Config, DynamicConfig, Options, Pkgsrc, PkgsrcEnv, Sandboxes, Summary, WrkObjDir, WrkObjKind,
};
pub use cpu::{CpuSample, CpuSamplerHandle, start_cpu_sampler};
pub use db::Database;
pub use history::{History, HistoryKind};
pub use init::Init;
pub use makejobs::PkgMakeJobs;
pub use pkgstate::{PackageCounts, PackageState};
pub use sandbox::Sandbox;
pub use scan::{ResolvedPackage, Scan, ScanResult, ScanSummary};
pub use scheduler::{
    PackageId, PackageInfo, PackageNode, PackageTable, ScheduledPackage, Scheduler,
};
pub use state::RunState;
pub use summary::generate_pkg_summary;
pub use tui::{print_elapsed, print_failed, print_status};
