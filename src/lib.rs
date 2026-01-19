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
pub mod db;
pub mod report;
pub mod sandbox;
pub mod scan;
pub mod summary;

// Internal modules - exposed for binary use but not primary API
mod init;
pub mod logging;
mod tui;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Shared context for a build or scan run.
pub struct RunContext {
    /// Flag to signal graceful shutdown.
    pub shutdown: Arc<AtomicBool>,
}

impl RunContext {
    pub fn new(shutdown: Arc<AtomicBool>) -> Self {
        Self { shutdown }
    }
}

// Re-export main types for convenience
pub use action::{Action, ActionType, FSType};
pub use build::{
    Build, BuildCounts, BuildOptions, BuildOutcome, BuildResult, BuildSummary,
};
pub use config::{Config, Options, Pkgsrc, PkgsrcEnv, Sandboxes};
pub use db::Database;
pub use report::write_html_report;
pub use sandbox::Sandbox;
pub use scan::{
    ResolvedPackage, Scan, ScanResult, ScanSummary, SkipReason, SkippedCounts,
};
pub use summary::generate_pkg_summary;

// Re-export init for CLI use
pub use init::Init;
