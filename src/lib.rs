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
pub mod logging;
pub mod report;
pub mod sandbox;
pub mod scan;
pub mod scheduler;
pub mod state;
pub mod summary;

mod history;
mod init;
mod pkgstate;
mod tui;

use std::io::{self, Write};

/**
 * Write a line to stdout, returning false on broken pipe.
 *
 * Use this in loops to gracefully handle SIGPIPE (e.g., when piped to `head`).
 */
pub fn try_println(s: &str) -> bool {
    let result = writeln!(io::stdout(), "{}", s);
    !matches!(result, Err(e) if e.kind() == io::ErrorKind::BrokenPipe)
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
//   → Build::new() → build.start() → write_html_report()

pub use action::{Action, ActionType, FSType};
pub use build::{
    Build, BuildCounts, BuildReason, BuildResult, BuildSummary, MakeJobs, PkgBuildStats, Stage,
    pkg_up_to_date,
};
pub use config::{Config, DynamicConfig, Options, Pkgsrc, PkgsrcEnv, Sandboxes, WrkObjDir};
pub use cpu::{CpuSample, CpuSamplerHandle, start_cpu_sampler};
pub use db::Database;
pub use history::{History, HistoryKind, format_duration};
pub use init::Init;
pub use pkgstate::{PackageCounts, PackageState, PackageStateKind};
pub use report::write_html_report;
pub use sandbox::Sandbox;
pub use scan::{ResolvedPackage, Scan, ScanResult, ScanSummary};
pub use scheduler::{
    PackageNode, Scheduler, compute_budget, scheduling_weights, sort_by_build_priority,
};
pub use state::RunState;
pub use summary::generate_pkg_summary;
