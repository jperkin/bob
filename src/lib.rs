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

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/**
 * Return all packages in build priority order.
 *
 * Packages that unblock the most downstream work appear first.
 * `deps` maps each package to its dependencies; all packages must
 * be keys. `weight` provides per-package base weight.
 */
pub fn build_order<K>(deps: &HashMap<K, Vec<K>>, weight: impl Fn(&K) -> usize) -> Vec<K>
where
    K: Eq + Hash + Clone + Ord,
{
    let mut rev: HashMap<&K, Vec<&K>> = HashMap::new();
    for pkg in deps.keys() {
        rev.entry(pkg).or_default();
    }
    for (pkg, d) in deps {
        for dep in d {
            rev.entry(dep).or_default().push(pkg);
        }
    }
    let mut pending: HashMap<&K, usize> = deps.keys().map(|p| (p, rev[p].len())).collect();
    let mut queue: VecDeque<&K> = pending
        .iter()
        .filter(|(_, c)| **c == 0)
        .map(|(&p, _)| p)
        .collect();
    let mut weights: HashMap<&K, usize> = HashMap::new();
    while let Some(pkg) = queue.pop_front() {
        let w = rev[pkg]
            .iter()
            .fold(weight(pkg), |a, d| a + weights.get(d).copied().unwrap_or(0));
        weights.insert(pkg, w);
        for dep in deps[pkg].iter() {
            if let Some(c) = pending.get_mut(dep) {
                *c -= 1;
                if *c == 0 {
                    queue.push_back(dep);
                }
            }
        }
    }
    let mut result: Vec<K> = deps.keys().cloned().collect();
    result.sort_by(|a, b| weights.get(b).cmp(&weights.get(a)).then_with(|| a.cmp(b)));
    result
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

/// Error indicating the operation was interrupted (e.g., by Ctrl+C).
#[derive(Debug)]
pub struct Interrupted;

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Interrupted")
    }
}

impl std::error::Error for Interrupted {}

/// Shared context for a build or scan run.
#[derive(Clone, Debug)]
pub struct RunContext {
    /// Flag to signal graceful shutdown.
    pub shutdown: Arc<AtomicBool>,
}

impl RunContext {
    /**
     * Create a new run context with the given shutdown flag.
     *
     * The shutdown flag is shared across all threads. Set it to `true`
     * to trigger graceful shutdown of any running scan or build.
     */
    pub fn new(shutdown: Arc<AtomicBool>) -> Self {
        Self { shutdown }
    }
}

// Re-export main types for convenience.
//
// The typical workflow is:
//   Config::load() → Scan::new() → scan.start() → scan.resolve()
//   → Build::new() → build.start() → write_html_report()

pub use action::{Action, ActionType, FSType};
pub use build::{
    Build, BuildCounts, BuildOutcome, BuildReason, BuildResult, BuildSummary, pkg_up_to_date,
};
pub use config::{Config, Options, Pkgsrc, PkgsrcEnv, Sandboxes};
pub use db::Database;
pub use init::Init;
pub use report::write_html_report;
pub use sandbox::Sandbox;
pub use scan::{ResolvedPackage, Scan, ScanResult, ScanSummary, SkipReason, SkippedCounts};
pub use summary::generate_pkg_summary;
