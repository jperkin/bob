/*
 * Copyright (c) 2025 Jonathan Perkin <jonathan@perkin.org.uk>
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

//! Package dependency scanning and resolution.
//!
//! This module provides the [`Scan`] struct for discovering package dependencies
//! and building a directed acyclic graph (DAG) for build ordering.
//!
//! # Scan Process
//!
//! 1. Create a scan sandbox
//! 2. Run `make pbulk-index` on each package to discover dependencies
//! 3. Recursively discover all transitive dependencies
//! 4. Resolve dependency patterns to specific package versions
//! 5. Verify no circular dependencies exist
//! 6. Return buildable and skipped package lists
//!
//! # Skip Reasons
//!
//! Packages may be skipped for several reasons:
//!
//! - `PKG_SKIP_REASON` - Package explicitly marked to skip on this platform
//! - `PKG_FAIL_REASON` - Package expected to fail on this platform
//! - Unresolved dependencies - Required dependency not found
//! - Circular dependencies - Package has a dependency cycle

use crate::config::PkgsrcEnv;
use crate::sandbox::SingleSandboxScope;
use crate::tui::{MultiProgress, format_duration};
use crate::{Config, RunContext, Sandbox};
use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use petgraph::graphmap::DiGraphMap;
use pkgsrc::{Depend, PkgName, PkgPath, ScanIndex};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::io::BufReader;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, error, info, trace};

/// Reason why a package was skipped (not built).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SkipReason {
    /// Package has `PKG_SKIP_REASON` set.
    PkgSkip(String),
    /// Package has `PKG_FAIL_REASON` set.
    PkgFail(String),
    /// Package skipped because a dependency was skipped.
    IndirectSkip(String),
    /// Package failed because a dependency failed.
    IndirectFail(String),
    /// Dependency could not be resolved.
    UnresolvedDep(String),
}

impl SkipReason {
    /// Returns the status label for this skip reason.
    pub fn status(&self) -> &'static str {
        match self {
            SkipReason::PkgSkip(_) => "pre-skipped",
            SkipReason::PkgFail(_) => "pre-failed",
            SkipReason::IndirectSkip(_) => "indirect-skipped",
            SkipReason::IndirectFail(_) => "indirect-failed",
            SkipReason::UnresolvedDep(_) => "unresolved",
        }
    }

    /// Returns true if this is a direct skip (not inherited from a dependency).
    pub fn is_direct(&self) -> bool {
        matches!(
            self,
            SkipReason::PkgSkip(_)
                | SkipReason::PkgFail(_)
                | SkipReason::UnresolvedDep(_)
        )
    }

    /// Returns true if this is an indirect skip (inherited from a dependency).
    pub fn is_indirect(&self) -> bool {
        matches!(
            self,
            SkipReason::IndirectSkip(_) | SkipReason::IndirectFail(_)
        )
    }
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::PkgSkip(r)
            | SkipReason::PkgFail(r)
            | SkipReason::IndirectSkip(r)
            | SkipReason::IndirectFail(r) => write!(f, "{}", r),
            SkipReason::UnresolvedDep(p) => {
                write!(f, "Could not resolve: {}", p)
            }
        }
    }
}

/// Counts of skipped packages by SkipReason category.
#[derive(Clone, Debug, Default)]
pub struct SkippedCounts {
    /// Packages with `PKG_SKIP_REASON` set.
    pub pkg_skip: usize,
    /// Packages with `PKG_FAIL_REASON` set.
    pub pkg_fail: usize,
    /// Packages with unresolved dependencies.
    pub unresolved: usize,
    /// Packages skipped due to a dependency being skipped.
    pub indirect_skip: usize,
    /// Packages skipped due to a dependency failure.
    pub indirect_fail: usize,
}

/// A successfully resolved package that is ready to build.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ResolvedPackage {
    /// The scan index data (always present for resolved packages).
    pub index: ScanIndex,
    /// Package path.
    pub pkgpath: PkgPath,
    /// Resolved dependencies.
    pub resolved_depends: Vec<PkgName>,
}

impl ResolvedPackage {
    /// Returns the package name.
    pub fn pkgname(&self) -> &PkgName {
        &self.index.pkgname
    }

    /// Returns resolved dependencies.
    pub fn depends(&self) -> &[PkgName] {
        &self.resolved_depends
    }

    /// Returns bootstrap_pkg if set.
    pub fn bootstrap_pkg(&self) -> Option<&str> {
        self.index.bootstrap_pkg.as_deref()
    }

    /// Returns usergroup_phase if set.
    pub fn usergroup_phase(&self) -> Option<&str> {
        self.index.usergroup_phase.as_deref()
    }

    /// Returns multi_version if set.
    pub fn multi_version(&self) -> Option<&[String]> {
        self.index.multi_version.as_deref()
    }

    /// Returns pbulk_weight if set.
    pub fn pbulk_weight(&self) -> Option<&str> {
        self.index.pbulk_weight.as_deref()
    }
}

impl std::fmt::Display for ResolvedPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.index)?;
        if !self.resolved_depends.is_empty() {
            write!(f, "DEPENDS=")?;
            for (i, d) in self.resolved_depends.iter().enumerate() {
                if i > 0 {
                    write!(f, " ")?;
                }
                write!(f, "{d}")?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

/// Result of scanning/resolving a single package.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ScanResult {
    /// Package is buildable.
    Buildable(ResolvedPackage),
    /// Package was skipped for a reason.
    Skipped {
        /// Package path.
        pkgpath: PkgPath,
        /// Reason for skipping.
        reason: SkipReason,
        /// Scan index if available (present for most skipped packages).
        index: Option<ScanIndex>,
        /// Resolved dependencies (may be partial for unresolved deps).
        resolved_depends: Vec<PkgName>,
    },
    /// Package failed to scan (bmake pbulk-index failed).
    ScanFail {
        /// Package path.
        pkgpath: PkgPath,
        /// Error message.
        error: String,
    },
}

impl ScanResult {
    /// Returns the package path.
    pub fn pkgpath(&self) -> &PkgPath {
        match self {
            ScanResult::Buildable(pkg) => &pkg.pkgpath,
            ScanResult::Skipped { pkgpath, .. } => pkgpath,
            ScanResult::ScanFail { pkgpath, .. } => pkgpath,
        }
    }

    /// Returns the package name if available.
    pub fn pkgname(&self) -> Option<&PkgName> {
        match self {
            ScanResult::Buildable(pkg) => Some(pkg.pkgname()),
            ScanResult::Skipped { index, .. } => {
                index.as_ref().map(|i| &i.pkgname)
            }
            ScanResult::ScanFail { .. } => None,
        }
    }

    /// Returns true if this package is buildable.
    pub fn is_buildable(&self) -> bool {
        matches!(self, ScanResult::Buildable(_))
    }

    /// Returns the resolved package if buildable.
    pub fn as_buildable(&self) -> Option<&ResolvedPackage> {
        match self {
            ScanResult::Buildable(pkg) => Some(pkg),
            _ => None,
        }
    }

    /// Returns the underlying ScanIndex if available.
    pub fn index(&self) -> Option<&ScanIndex> {
        match self {
            ScanResult::Buildable(pkg) => Some(&pkg.index),
            ScanResult::Skipped { index, .. } => index.as_ref(),
            ScanResult::ScanFail { .. } => None,
        }
    }

    /// Returns resolved dependencies.
    pub fn depends(&self) -> &[PkgName] {
        match self {
            ScanResult::Buildable(pkg) => &pkg.resolved_depends,
            ScanResult::Skipped { resolved_depends, .. } => resolved_depends,
            ScanResult::ScanFail { .. } => &[],
        }
    }
}

impl std::fmt::Display for ScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanResult::Buildable(pkg) => write!(f, "{}", pkg),
            ScanResult::Skipped {
                index,
                pkgpath,
                reason,
                resolved_depends,
            } => {
                if let Some(idx) = index {
                    write!(f, "{}", idx)?;
                    // Don't emit DEPENDS for unresolved deps (pbulk compat)
                    if !matches!(reason, SkipReason::UnresolvedDep(_))
                        && !resolved_depends.is_empty()
                    {
                        write!(f, "DEPENDS=")?;
                        for (i, d) in resolved_depends.iter().enumerate() {
                            if i > 0 {
                                write!(f, " ")?;
                            }
                            write!(f, "{d}")?;
                        }
                        writeln!(f)?;
                    }
                } else {
                    writeln!(f, "PKGPATH={}", pkgpath)?;
                }
                Ok(())
            }
            ScanResult::ScanFail { pkgpath, .. } => {
                writeln!(f, "PKGPATH={}", pkgpath)
            }
        }
    }
}

/// Result of scanning and resolving packages.
///
/// Returned by [`Scan::resolve`], contains all scanned packages with their outcomes.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanSummary {
    /// Number of unique package paths scanned.
    pub pkgpaths: usize,
    /// All packages in scan order with their outcomes.
    pub packages: Vec<ScanResult>,
}

/// Counts of packages by outcome category.
#[derive(Clone, Debug, Default)]
pub struct ScanCounts {
    /// Packages that are buildable.
    pub buildable: usize,
    /// Packages that were skipped.
    pub skipped: SkippedCounts,
    /// Packages that failed to scan.
    pub scanfail: usize,
}

impl ScanSummary {
    /// Compute all outcome counts in a single pass.
    pub fn counts(&self) -> ScanCounts {
        let mut c = ScanCounts::default();
        for p in &self.packages {
            match p {
                ScanResult::Buildable(_) => c.buildable += 1,
                ScanResult::Skipped {
                    reason: SkipReason::PkgSkip(_), ..
                } => c.skipped.pkg_skip += 1,
                ScanResult::Skipped {
                    reason: SkipReason::PkgFail(_), ..
                } => c.skipped.pkg_fail += 1,
                ScanResult::Skipped {
                    reason: SkipReason::IndirectSkip(_),
                    ..
                } => c.skipped.indirect_skip += 1,
                ScanResult::Skipped {
                    reason: SkipReason::IndirectFail(_),
                    ..
                } => c.skipped.indirect_fail += 1,
                ScanResult::Skipped {
                    reason: SkipReason::UnresolvedDep(_),
                    ..
                } => c.skipped.unresolved += 1,
                ScanResult::ScanFail { .. } => c.scanfail += 1,
            }
        }
        c
    }

    /// Iterator over buildable packages.
    pub fn buildable(&self) -> impl Iterator<Item = &ResolvedPackage> {
        self.packages.iter().filter_map(|p| p.as_buildable())
    }

    /// Iterator over non-buildable packages.
    pub fn failed(&self) -> impl Iterator<Item = &ScanResult> {
        self.packages.iter().filter(|p| !p.is_buildable())
    }

    /// Count of buildable packages.
    pub fn count_buildable(&self) -> usize {
        self.packages.iter().filter(|p| p.is_buildable()).count()
    }

    /// Count of packages with PKG_SKIP_REASON.
    pub fn count_preskip(&self) -> usize {
        self.packages
            .iter()
            .filter(|p| {
                matches!(
                    p,
                    ScanResult::Skipped { reason: SkipReason::PkgSkip(_), .. }
                )
            })
            .count()
    }

    /// Count of packages with PKG_FAIL_REASON.
    pub fn count_prefail(&self) -> usize {
        self.packages
            .iter()
            .filter(|p| {
                matches!(
                    p,
                    ScanResult::Skipped { reason: SkipReason::PkgFail(_), .. }
                )
            })
            .count()
    }

    /// Count of packages with unresolved dependencies.
    pub fn count_unresolved(&self) -> usize {
        self.packages
            .iter()
            .filter(|p| {
                matches!(
                    p,
                    ScanResult::Skipped {
                        reason: SkipReason::UnresolvedDep(_),
                        ..
                    }
                )
            })
            .count()
    }

    /// Count of packages that failed to scan.
    pub fn count_scanfail(&self) -> usize {
        self.packages
            .iter()
            .filter(|p| matches!(p, ScanResult::ScanFail { .. }))
            .count()
    }

    /// Count of packages skipped due to dependency being skipped.
    pub fn count_indirect_skip(&self) -> usize {
        self.packages
            .iter()
            .filter(|p| {
                matches!(
                    p,
                    ScanResult::Skipped {
                        reason: SkipReason::IndirectSkip(_),
                        ..
                    }
                )
            })
            .count()
    }

    /// Count of packages failed due to dependency failure.
    pub fn count_indirect_fail(&self) -> usize {
        self.packages
            .iter()
            .filter(|p| {
                matches!(
                    p,
                    ScanResult::Skipped {
                        reason: SkipReason::IndirectFail(_),
                        ..
                    }
                )
            })
            .count()
    }

    /// Errors derived from scan failures and unresolved dependencies.
    pub fn errors(&self) -> impl Iterator<Item = &str> {
        self.packages.iter().filter_map(|p| match p {
            ScanResult::ScanFail { error, .. } => Some(error.as_str()),
            ScanResult::Skipped {
                reason: SkipReason::UnresolvedDep(e),
                ..
            } => Some(e.as_str()),
            _ => None,
        })
    }

    /// Get a buildable package by name.
    pub fn get(&self, pkgname: &PkgName) -> Option<&ResolvedPackage> {
        self.packages.iter().find_map(|p| match p {
            ScanResult::Buildable(pkg) if pkg.pkgname() == pkgname => Some(pkg),
            _ => None,
        })
    }
}

impl std::fmt::Display for ScanSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c = self.counts();
        let s = &c.skipped;
        write!(
            f,
            "Resolved {} total packages from {} package paths\n{} buildable, {} pre-skipped, {} pre-failed, {} unresolved",
            self.packages.len(),
            self.pkgpaths,
            c.buildable,
            s.pkg_skip + s.indirect_skip,
            s.pkg_fail + s.indirect_fail,
            s.unresolved
        )
    }
}

/// Package dependency scanner.
#[derive(Debug, Default)]
pub struct Scan {
    config: Config,
    sandbox: Sandbox,
    incoming: HashSet<PkgPath>,
    /// Pkgpaths we've completed scanning (in this session).
    done: HashSet<PkgPath>,
    /// Pkgpaths already in database (loaded once at start for in-memory cache lookup).
    /// This eliminates per-dependency database queries during dependency discovery.
    cached_pkgpaths: HashSet<String>,
    /// Number of pkgpaths loaded from cache at start of scan.
    initial_cached: usize,
    /// Number of pkgpaths discovered as cached during dependency discovery.
    discovered_cached: usize,
    /// Packages loaded from scan, indexed by pkgname.
    packages: IndexMap<PkgName, ScanIndex>,
    /// Full tree scan - discover all packages, skip recursive dependency discovery.
    /// Defaults to true; set to false when packages are explicitly added.
    full_tree: bool,
    /// A previous full tree scan completed successfully.
    full_scan_complete: bool,
    /// Packages that failed to scan (pkgpath, error message).
    scan_failures: Vec<(PkgPath, String)>,
    /// Pkgsrc environment variables (populated after pre-build).
    pkgsrc_env: Option<PkgsrcEnv>,
}

impl Scan {
    pub fn new(config: &Config) -> Scan {
        let sandbox = Sandbox::new(config);
        debug!(pkgsrc = %config.pkgsrc().display(),
            make = %config.make().display(),
            scan_threads = config.scan_threads(),
            "Created new Scan instance"
        );
        Scan {
            config: config.clone(),
            sandbox,
            incoming: HashSet::new(),
            done: HashSet::new(),
            cached_pkgpaths: HashSet::new(),
            initial_cached: 0,
            discovered_cached: 0,
            packages: IndexMap::new(),
            full_tree: true,
            full_scan_complete: false,
            scan_failures: Vec::new(),
            pkgsrc_env: None,
        }
    }

    pub fn add(&mut self, pkgpath: &PkgPath) {
        info!(pkgpath = %pkgpath.as_path().display(), "Adding package to scan queue");
        self.full_tree = false;
        self.incoming.insert(pkgpath.clone());
    }

    /// Returns true if this is a full tree scan.
    pub fn is_full_tree(&self) -> bool {
        self.full_tree
    }

    /// Mark that a previous full tree scan completed successfully.
    pub fn set_full_scan_complete(&mut self) {
        self.full_scan_complete = true;
    }

    /// Initialize scan from database, checking what's already scanned.
    /// Returns (cached_count, pending_deps_count) where pending_deps_count is the
    /// number of dependencies discovered but not yet scanned (from interrupted scans).
    pub fn init_from_db(
        &mut self,
        db: &crate::db::Database,
    ) -> Result<(usize, usize)> {
        let scanned = db.get_scanned_pkgpaths()?;
        let cached_count = scanned.len();
        let mut pending_count = 0;

        if cached_count > 0 {
            info!(
                cached_count = cached_count,
                "Found cached scan results in database"
            );

            // Store scanned pkgpaths in memory for fast lookup during dependency discovery.
            // This eliminates per-dependency database queries (major performance win).
            self.cached_pkgpaths = scanned.clone();

            // For full tree scans with full_scan_complete, we'll skip scanning
            // For limited scans, remove already-scanned from incoming
            if !self.full_tree {
                self.incoming.retain(|p| !scanned.contains(&p.to_string()));
            }

            // Add scanned pkgpaths to done set
            for pkgpath_str in &scanned {
                if let Ok(pkgpath) = PkgPath::new(pkgpath_str) {
                    self.done.insert(pkgpath);
                }
            }

            // Check for dependencies that were discovered but not yet scanned.
            // This handles the case where a scan was interrupted partway through.
            let unscanned = db.get_unscanned_dependencies()?;
            if !unscanned.is_empty() {
                info!(
                    unscanned_count = unscanned.len(),
                    "Found unscanned dependencies from interrupted scan"
                );
                for pkgpath_str in unscanned {
                    if let Ok(pkgpath) = PkgPath::new(&pkgpath_str) {
                        if !self.done.contains(&pkgpath) {
                            self.incoming.insert(pkgpath);
                            pending_count += 1;
                        }
                    }
                }
            }
        }

        Ok((cached_count, pending_count))
    }

    /// Discover all packages in pkgsrc tree.
    fn discover_packages(&mut self) -> anyhow::Result<()> {
        println!("Discovering packages...");
        let pkgsrc = self.config.pkgsrc().display();
        let make = self.config.make().display();

        // Get top-level SUBDIR (categories + USER_ADDITIONAL_PKGS)
        let script = format!(
            "cd {} && {} show-subdir-var VARNAME=SUBDIR\n",
            pkgsrc, make
        );
        let child = self.sandbox.execute_script(0, &script, vec![])?;
        let output = child
            .wait_with_output()
            .context("Failed to run show-subdir-var")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to get categories: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let entries: Vec<&str> = stdout.split_whitespace().collect();

        for entry in entries {
            if entry.contains('/') {
                // USER_ADDITIONAL_PKGS - add directly as pkgpath
                if let Ok(pkgpath) = PkgPath::new(entry) {
                    self.incoming.insert(pkgpath);
                }
            } else {
                // Category - get packages within it
                let script = format!(
                    "cd {}/{} && {} show-subdir-var VARNAME=SUBDIR\n",
                    pkgsrc, entry, make
                );
                let child = self.sandbox.execute_script(0, &script, vec![])?;
                let cat_output = child.wait_with_output();

                match cat_output {
                    Ok(o) if o.status.success() => {
                        let pkgs = String::from_utf8_lossy(&o.stdout);
                        for pkg in pkgs.split_whitespace() {
                            let path = format!("{}/{}", entry, pkg);
                            if let Ok(pkgpath) = PkgPath::new(&path) {
                                self.incoming.insert(pkgpath);
                            }
                        }
                    }
                    Ok(o) => {
                        let stderr = String::from_utf8_lossy(&o.stderr);
                        debug!(category = entry, stderr = %stderr,
                            "Failed to get packages for category");
                    }
                    Err(e) => {
                        debug!(category = entry, error = %e,
                            "Failed to run make in category");
                    }
                }
            }
        }

        info!(discovered = self.incoming.len(), "Package discovery complete");
        println!("Discovered {} package paths", self.incoming.len());

        Ok(())
    }

    pub fn start(
        &mut self,
        ctx: &RunContext,
        db: &crate::db::Database,
    ) -> anyhow::Result<bool> {
        info!(
            incoming_count = self.incoming.len(),
            sandbox_enabled = self.sandbox.enabled(),
            "Starting package scan"
        );

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.config.scan_threads())
            .build()
            .context("Failed to build scan thread pool")?;

        let shutdown_flag = Arc::clone(&ctx.shutdown);

        // For full tree scans where a previous scan completed, all packages
        // are already cached - nothing to do.
        if self.full_tree && self.full_scan_complete && !self.done.is_empty() {
            println!("All {} package paths already scanned", self.done.len());
            return Ok(false);
        }

        // For non-full-tree scans, prune already-cached packages from incoming
        // before sandbox creation to avoid unnecessary setup/teardown.
        if !self.full_tree {
            self.incoming.retain(|p| !self.done.contains(p));
            if self.incoming.is_empty() {
                if !self.done.is_empty() {
                    println!(
                        "All {} package paths already scanned",
                        self.done.len()
                    );
                }
                return Ok(false);
            }
        }

        /*
         * Only a single sandbox is required, 'make pbulk-index' can safely be
         * run in parallel inside one sandbox.
         *
         * Create scope which handles sandbox lifecycle - creates on construction,
         * destroys on drop. This ensures cleanup even on error paths.
         */
        let _scope = SingleSandboxScope::new(
            self.sandbox.clone(),
            self.config.verbose(),
        )?;

        if self.sandbox.enabled() {
            // Run pre-build script if defined
            if !self.sandbox.run_pre_build(
                0,
                &self.config,
                self.config.script_env(None),
            )? {
                error!("pre-build script failed");
            }
            self.pkgsrc_env =
                Some(PkgsrcEnv::fetch(&self.config, &self.sandbox)?);
        }

        // For full tree scans, always discover all packages
        if self.full_tree {
            self.discover_packages()?;
            self.incoming.retain(|p| !self.done.contains(p));
        }

        // Nothing to scan - all packages are cached
        if self.incoming.is_empty() {
            if !self.done.is_empty() {
                println!(
                    "All {} package paths already scanned",
                    self.done.len()
                );
            }

            if self.sandbox.enabled() {
                self.run_post_build()?;
            }
            // Guard dropped here, destroys sandbox
            return Ok(false);
        }

        // Clear resolved dependencies since we're scanning new packages
        db.clear_resolved_depends()?;

        println!("Scanning packages...");

        // Track initial cached count for final summary
        self.initial_cached = self.done.len();

        // Set up multi-line progress display using ratatui inline viewport
        // Note: finished_title is unused since we print our own summary
        let total_count = self.initial_cached + self.incoming.len();
        let progress = Arc::new(Mutex::new(
            MultiProgress::new(
                "Scanning",
                "",
                total_count,
                self.config.scan_threads(),
            )
            .expect("Failed to initialize progress display"),
        ));

        // Mark cached packages in progress display
        if self.initial_cached > 0 {
            if let Ok(mut p) = progress.lock() {
                p.state_mut().cached = self.initial_cached;
            }
        }

        // Flag to stop the refresh thread
        let stop_refresh = Arc::new(AtomicBool::new(false));

        // Spawn a thread to periodically refresh the display (for timer updates)
        let progress_refresh = Arc::clone(&progress);
        let stop_flag = Arc::clone(&stop_refresh);
        let shutdown_for_refresh = Arc::clone(&shutdown_flag);
        let refresh_thread = std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed)
                && !shutdown_for_refresh.load(Ordering::SeqCst)
            {
                if let Ok(mut p) = progress_refresh.lock() {
                    // Check for keyboard events (Ctrl+C raises SIGINT)
                    let _ = p.poll_events();
                    let _ = p.render();
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });

        // Start transaction for all writes
        db.begin_transaction()?;

        let mut interrupted = false;

        // Borrow config and sandbox separately for use in scanner thread,
        // allowing main thread to mutate self.done, self.incoming, etc.
        let config = &self.config;
        let sandbox = &self.sandbox;

        /*
         * Continuously iterate over incoming queue, moving to done once
         * processed, and adding any dependencies to incoming to be processed
         * next.
         */
        loop {
            // Check for shutdown signal
            if shutdown_flag.load(Ordering::Relaxed) {
                stop_refresh.store(true, Ordering::Relaxed);
                if let Ok(mut p) = progress.lock() {
                    let _ = p.finish_interrupted();
                }
                interrupted = true;
                break;
            }

            /*
             * Convert the incoming HashSet into a Vec for parallel processing.
             */
            let pkgpaths: Vec<PkgPath> = self.incoming.drain().collect();
            if pkgpaths.is_empty() {
                break;
            }

            // Create bounded channel for streaming results
            const CHANNEL_BUFFER_SIZE: usize = 128;
            let (tx, rx) = std::sync::mpsc::sync_channel::<(
                PkgPath,
                Result<Vec<ScanIndex>>,
            )>(CHANNEL_BUFFER_SIZE);

            let mut new_incoming: HashSet<PkgPath> = HashSet::new();

            // === BENCHMARK INSTRUMENTATION ===
            // Track timing to identify performance bottlenecks
            let bench_start = std::time::Instant::now();
            let mut bench_db_write_total = std::time::Duration::ZERO;
            let mut bench_dep_discovery_total = std::time::Duration::ZERO;
            let mut bench_results_processed = 0usize;
            let mut bench_last_report = std::time::Instant::now();
            let mut bench_last_count = 0usize;
            let mut bench_last_db_write = std::time::Duration::ZERO;
            const BENCH_REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
            // === END BENCHMARK SETUP ===

            // Track channel send wait time (backpressure indicator)
            let bench_send_wait = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let bench_scan_time = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

            std::thread::scope(|s| {
                // Spawn scanning thread
                let progress_clone = Arc::clone(&progress);
                let shutdown_clone = Arc::clone(&shutdown_flag);
                let pool_ref = &pool;
                let bench_send_wait_clone = Arc::clone(&bench_send_wait);
                let bench_scan_time_clone = Arc::clone(&bench_scan_time);

                s.spawn(move || {
                    pool_ref.install(|| {
                        pkgpaths.par_iter().for_each(|pkgpath| {
                            // Check for shutdown before starting
                            if shutdown_clone.load(Ordering::Relaxed) {
                                return;
                            }

                            let pathname =
                                pkgpath.as_path().to_string_lossy().to_string();
                            let thread_id =
                                rayon::current_thread_index().unwrap_or(0);

                            // Update progress - show current package
                            if let Ok(mut p) = progress_clone.lock() {
                                p.state_mut()
                                    .set_worker_active(thread_id, &pathname);
                            }

                            let scan_start = std::time::Instant::now();
                            let result = Self::scan_pkgpath_with(
                                config, sandbox, pkgpath,
                            );
                            let scan_elapsed = scan_start.elapsed();
                            bench_scan_time_clone.fetch_add(
                                scan_elapsed.as_micros() as u64,
                                std::sync::atomic::Ordering::Relaxed
                            );

                            // Update progress counter
                            if let Ok(mut p) = progress_clone.lock() {
                                p.state_mut().set_worker_idle(thread_id);
                                if result.is_ok() {
                                    p.state_mut().increment_completed();
                                } else {
                                    p.state_mut().increment_failed();
                                }
                            }

                            // Send result (blocks if buffer full = backpressure)
                            let send_start = std::time::Instant::now();
                            let _ = tx.send((pkgpath.clone(), result));
                            let send_elapsed = send_start.elapsed();
                            bench_send_wait_clone.fetch_add(
                                send_elapsed.as_micros() as u64,
                                std::sync::atomic::Ordering::Relaxed
                            );
                        });
                    });
                    drop(tx);
                });

                // Check if we were interrupted during parallel processing
                let was_interrupted = shutdown_flag.load(Ordering::Relaxed);

                /*
                 * Process results - write to DB and extract dependencies.
                 */
                for (pkgpath, result) in rx {
                    let pkgpath_str = pkgpath.to_string();
                    let scanpkgs = match result {
                        Ok(pkgs) => pkgs,
                        Err(e) => {
                            self.scan_failures
                                .push((pkgpath.clone(), e.to_string()));
                            self.done.insert(pkgpath);
                            continue;
                        }
                    };
                    self.done.insert(pkgpath.clone());
                    // Also add to cached_pkgpaths for in-memory lookup in future iterations
                    self.cached_pkgpaths.insert(pkgpath_str.clone());

                    // Save to database (TIMED)
                    if !scanpkgs.is_empty() {
                        let db_start = std::time::Instant::now();
                        if let Err(e) = db
                            .store_scan_pkgpath(&pkgpath_str, &scanpkgs)
                        {
                            error!(error = %e, "Failed to store scan results");
                        }
                        bench_db_write_total += db_start.elapsed();
                    }

                    // Skip dependency discovery for full tree scans (all
                    // packages already discovered) or if interrupted
                    if self.full_tree || was_interrupted {
                        bench_results_processed += 1;
                    } else {
                        // Discover dependencies not yet seen (TIMED)
                        let dep_start = std::time::Instant::now();
                        for pkg in &scanpkgs {
                            if let Some(ref all_deps) = pkg.all_depends {
                                for dep in all_deps {
                                    let dep_path = dep.pkgpath();
                                    if self.done.contains(dep_path)
                                        || new_incoming.contains(dep_path)
                                    {
                                        continue;
                                    }
                                    // In-memory check for cached dependency (no database query).
                                    // This is a major performance win - eliminates ~100k queries
                                    // during a full scan with dependency discovery.
                                    let dep_path_str = dep_path.to_string();
                                    if self.cached_pkgpaths.contains(&dep_path_str) {
                                        self.done.insert(dep_path.clone());
                                        self.discovered_cached += 1;
                                        if let Ok(mut p) = progress.lock() {
                                            p.state_mut().total += 1;
                                            p.state_mut().cached += 1;
                                        }
                                    } else {
                                        new_incoming.insert(dep_path.clone());
                                        if let Ok(mut p) = progress.lock() {
                                            p.state_mut().total += 1;
                                        }
                                    }
                                }
                            }
                        }
                        bench_dep_discovery_total += dep_start.elapsed();
                        bench_results_processed += 1;
                    }

                    // === BENCHMARK PERIODIC REPORT ===
                    if bench_last_report.elapsed() >= BENCH_REPORT_INTERVAL {
                        let elapsed = bench_start.elapsed();
                        let count_delta = bench_results_processed - bench_last_count;
                        let interval_secs = bench_last_report.elapsed().as_secs_f64();
                        let rate = count_delta as f64 / interval_secs;

                        // Interval-specific metrics (to see degradation over time)
                        let interval_db_write = bench_db_write_total - bench_last_db_write;
                        let interval_db_ms = if count_delta > 0 {
                            interval_db_write.as_millis() as f64 / count_delta as f64
                        } else { 0.0 };

                        // Cumulative metrics
                        let db_pct = (bench_db_write_total.as_secs_f64() / elapsed.as_secs_f64()) * 100.0;
                        let _dep_pct = (bench_dep_discovery_total.as_secs_f64() / elapsed.as_secs_f64()) * 100.0;
                        let cumulative_db_ms = if bench_results_processed > 0 {
                            bench_db_write_total.as_millis() as f64 / bench_results_processed as f64
                        } else { 0.0 };

                        info!(
                            elapsed_secs = format!("{:.1}", elapsed.as_secs_f64()),
                            done = bench_results_processed,
                            interval_rate = format!("{:.1}/s", rate),
                            interval_db_ms = format!("{:.2}", interval_db_ms),
                            cumulative_db_ms = format!("{:.2}", cumulative_db_ms),
                            db_pct = format!("{:.1}", db_pct),
                            "Scan benchmark progress"
                        );

                        bench_last_report = std::time::Instant::now();
                        bench_last_count = bench_results_processed;
                        bench_last_db_write = bench_db_write_total;
                    }
                }
            });

            // === BENCHMARK BATCH SUMMARY ===
            {
                let batch_elapsed = bench_start.elapsed();
                let send_wait_us = bench_send_wait.load(std::sync::atomic::Ordering::Relaxed);
                let scan_time_us = bench_scan_time.load(std::sync::atomic::Ordering::Relaxed);
                let send_wait_secs = send_wait_us as f64 / 1_000_000.0;
                let scan_time_secs = scan_time_us as f64 / 1_000_000.0;

                // Calculate what percentage of time is accounted for
                let batch_secs = batch_elapsed.as_secs_f64();
                let db_secs = bench_db_write_total.as_secs_f64();
                let dep_secs = bench_dep_discovery_total.as_secs_f64();

                // Worker efficiency: total scan time / (batch time * num threads)
                // If workers were 100% efficient, scan_time would equal batch_time * threads
                let num_threads = self.config.scan_threads();
                let theoretical_max = batch_secs * num_threads as f64;
                let worker_efficiency = if theoretical_max > 0.0 {
                    (scan_time_secs / theoretical_max) * 100.0
                } else { 0.0 };

                let backpressure_pct = if scan_time_secs > 0.0 {
                    (send_wait_secs / scan_time_secs) * 100.0
                } else { 0.0 };

                info!(
                    batch_secs = format!("{:.1}", batch_secs),
                    pkgs = bench_results_processed,
                    rate = format!("{:.1}/s", bench_results_processed as f64 / batch_secs),
                    "Scan batch complete"
                );
                info!(
                    db_write_secs = format!("{:.1}", db_secs),
                    db_write_pct = format!("{:.1}%", (db_secs / batch_secs) * 100.0),
                    dep_disc_secs = format!("{:.1}", dep_secs),
                    dep_disc_pct = format!("{:.1}%", (dep_secs / batch_secs) * 100.0),
                    "Main thread timing"
                );
                info!(
                    scan_time_secs = format!("{:.1}", scan_time_secs),
                    send_wait_secs = format!("{:.1}", send_wait_secs),
                    backpressure_pct = format!("{:.1}%", backpressure_pct),
                    "Worker timing"
                );
                info!(
                    worker_efficiency_pct = format!("{:.1}%", worker_efficiency),
                    num_threads = num_threads,
                    "Worker efficiency (scan_time / batch_time * threads)"
                );
            }

            // Check for interruption after batch
            if shutdown_flag.load(Ordering::Relaxed) {
                stop_refresh.store(true, Ordering::Relaxed);
                if let Ok(mut p) = progress.lock() {
                    let _ = p.finish_interrupted();
                }
                interrupted = true;
                break;
            }

            /*
             * We're finished with the current incoming, replace it with the
             * new incoming list.  If it is empty then we've already processed
             * all known PKGPATHs and are done.
             *
             * Filter out any pkgpaths that were already scanned this wave.
             * This handles a race where dependency discovery finds a pkgpath
             * before its parallel scan completes and adds it to done.
             */
            new_incoming.retain(|p| !self.done.contains(p));
            self.incoming = new_incoming;
        }

        // Commit transaction (partial on interrupt, full on success)
        db.commit()?;

        // Stop the refresh thread and print final summary
        stop_refresh.store(true, Ordering::Relaxed);
        let _ = refresh_thread.join();

        // Only print summary for normal completion; finish_interrupted()
        // was already called immediately when interrupt was detected
        if !interrupted {
            // Get elapsed time and clean up TUI without printing generic summary
            let elapsed = if let Ok(mut p) = progress.lock() {
                p.finish_silent().ok()
            } else {
                None
            };

            // Print scan-specific summary from source of truth
            // total = initial_cached + discovered_cached + actually_scanned
            // where actually_scanned = succeeded + failed
            let total = self.done.len();
            let cached = self.initial_cached + self.discovered_cached;
            let failed = self.scan_failures.len();
            let succeeded = total.saturating_sub(cached).saturating_sub(failed);

            let elapsed_str =
                elapsed.map(format_duration).unwrap_or_else(|| "?".to_string());

            if cached > 0 {
                println!(
                    "Scanned {} package paths in {} ({} scanned, {} cached, {} failed)",
                    total, elapsed_str, succeeded, cached, failed
                );
            } else {
                println!(
                    "Scanned {} package paths in {} ({} succeeded, {} failed)",
                    total, elapsed_str, succeeded, failed
                );
            }
        }

        if self.sandbox.enabled() {
            self.run_post_build()?;
        }

        // Guard dropped here, destroys sandbox
        if interrupted {
            return Ok(true);
        }

        Ok(false)
    }

    /// Run post-build script if configured.
    fn run_post_build(&self) -> anyhow::Result<()> {
        if !self.sandbox.run_post_build(
            0,
            &self.config,
            self.config.script_env(self.pkgsrc_env.as_ref()),
        )? {
            error!("post-build script failed");
        }
        Ok(())
    }

    /// Returns scan failures as formatted error strings.
    pub fn scan_errors(&self) -> impl Iterator<Item = &str> {
        self.scan_failures.iter().map(|(_, e)| e.as_str())
    }

    /// Returns scan failures with pkgpath information.
    pub fn scan_failures(&self) -> &[(PkgPath, String)] {
        &self.scan_failures
    }

    /**
     * Scan a single PKGPATH, returning a [`Vec`] of [`ScanIndex`] results,
     * as multi-version packages may return multiple results.
     */
    pub fn scan_pkgpath(
        &self,
        pkgpath: &PkgPath,
    ) -> anyhow::Result<Vec<ScanIndex>> {
        Self::scan_pkgpath_with(&self.config, &self.sandbox, pkgpath)
    }

    /// Scan a single PKGPATH using provided config and sandbox references.
    /// This allows scanning without borrowing all of `self`.
    fn scan_pkgpath_with(
        config: &Config,
        sandbox: &Sandbox,
        pkgpath: &PkgPath,
    ) -> anyhow::Result<Vec<ScanIndex>> {
        let pkgpath_str = pkgpath.as_path().display().to_string();
        debug!(pkgpath = %pkgpath_str, "Scanning package");

        let pkgsrcdir = config.pkgsrc().display().to_string();
        let workdir = format!("{}/{}", pkgsrcdir, pkgpath_str);

        let scan_env = config.scan_env();
        trace!(pkgpath = %pkgpath_str,
            workdir = %workdir,
            scan_env = ?scan_env,
            "Executing pkg-scan"
        );
        let child = sandbox.execute_command(
            0,
            config.make(),
            ["-C", &workdir, "pbulk-index"],
            scan_env,
        )?;
        let output = child.wait_with_output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(pkgpath = %pkgpath_str,
                exit_code = ?output.status.code(),
                stderr = %stderr,
                "pkg-scan script failed"
            );
            let stderr = stderr.trim();
            let msg = if stderr.is_empty() {
                format!("Scan failed for {}", pkgpath_str)
            } else {
                format!("Scan failed for {}: {}", pkgpath_str, stderr)
            };
            bail!(msg);
        }

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        trace!(pkgpath = %pkgpath_str,
            stdout_len = stdout_str.len(),
            stdout = %stdout_str,
            "pkg-scan script output"
        );

        let reader = BufReader::new(&output.stdout[..]);
        let all_results: Vec<ScanIndex> =
            ScanIndex::from_reader(reader).collect::<Result<_, _>>()?;

        /*
         * Filter to keep only the first occurrence of each PKGNAME.
         * For multi-version packages, pbulk-index returns the *_DEFAULT
         * version first, which is the one we want.
         */
        let mut seen_pkgnames = HashSet::new();
        let mut index: Vec<ScanIndex> = Vec::new();
        for pkg in all_results {
            if seen_pkgnames.insert(pkg.pkgname.clone()) {
                index.push(pkg);
            }
        }

        info!(pkgpath = %pkgpath_str,
            packages_found = index.len(),
            "Scan complete for pkgpath"
        );

        /*
         * Set PKGPATH (PKG_LOCATION) as for some reason pbulk-index doesn't.
         */
        for pkg in &mut index {
            pkg.pkg_location = Some(pkgpath.clone());
            debug!(pkgpath = %pkgpath_str,
                pkgname = %pkg.pkgname.pkgname(),
                skip_reason = ?pkg.pkg_skip_reason,
                fail_reason = ?pkg.pkg_fail_reason,
                depends_count = pkg.all_depends.as_ref().map_or(0, |v| v.len()),
                "Found package in scan"
            );
        }

        Ok(index)
    }

    /// Resolve the list of scanned packages, matching dependency patterns to
    /// specific packages and verifying no circular dependencies exist.
    ///
    /// Returns a [`ScanSummary`] containing all packages with their outcomes.
    /// Also stores resolved dependencies in the database for fast reverse lookups.
    pub fn resolve(&mut self, db: &crate::db::Database) -> Result<ScanSummary> {
        info!(
            done_pkgpaths = self.done.len(),
            "Starting dependency resolution"
        );

        // Load all scan data in one query
        let all_scan_data = db.get_all_scan_indexes()?;

        // Track package_id for storing resolved dependencies
        let mut pkgname_to_id: HashMap<PkgName, i64> = HashMap::new();

        // Track skip reasons (packages not in this map are buildable)
        let mut skip_reasons: HashMap<PkgName, SkipReason> = HashMap::new();
        let mut depends: HashMap<PkgName, Vec<PkgName>> = HashMap::new();

        // Process all scan data
        for (pkg_id, pkg) in all_scan_data {
            // Skip duplicate PKGNAMEs - keep only the first (preferred) variant
            if self.packages.contains_key(&pkg.pkgname) {
                debug!(pkgname = %pkg.pkgname.pkgname(), "Skipping duplicate PKGNAME");
                continue;
            }

            // Track skip/fail reasons
            if let Some(reason) = &pkg.pkg_skip_reason {
                if !reason.is_empty() {
                    info!(pkgname = %pkg.pkgname.pkgname(), reason = %reason, "PKG_SKIP_REASON");
                    skip_reasons.insert(
                        pkg.pkgname.clone(),
                        SkipReason::PkgSkip(reason.clone()),
                    );
                }
            }
            if let Some(reason) = &pkg.pkg_fail_reason {
                if !reason.is_empty()
                    && !skip_reasons.contains_key(&pkg.pkgname)
                {
                    info!(pkgname = %pkg.pkgname.pkgname(), reason = %reason, "PKG_FAIL_REASON");
                    skip_reasons.insert(
                        pkg.pkgname.clone(),
                        SkipReason::PkgFail(reason.clone()),
                    );
                }
            }

            pkgname_to_id.insert(pkg.pkgname.clone(), pkg_id);
            depends.insert(pkg.pkgname.clone(), Vec::new());
            self.packages.insert(pkg.pkgname.clone(), pkg);
        }

        info!(packages = self.packages.len(), "Loaded packages");

        // Collect pkgnames for lookups (owned to avoid borrow issues)
        let pkgnames: Vec<PkgName> = self.packages.keys().cloned().collect();

        // Build pkgbase -> Vec<&PkgName> for efficient lookups
        let pkgbase_map: HashMap<&str, Vec<&PkgName>> = {
            let mut map: HashMap<&str, Vec<&PkgName>> = HashMap::new();
            for pkgname in &pkgnames {
                map.entry(pkgname.pkgbase()).or_default().push(pkgname);
            }
            map
        };

        // Cache of best Depend => PkgName matches
        let mut match_cache: HashMap<Depend, PkgName> = HashMap::new();

        // Helper to check if a dependency pattern is already satisfied
        let is_satisfied = |deps: &[PkgName], pattern: &pkgsrc::Pattern| {
            deps.iter().any(|existing| pattern.matches(existing.pkgname()))
        };

        // Resolve dependencies for each package
        for pkg in self.packages.values_mut() {
            let all_deps = match pkg.all_depends.take() {
                Some(deps) => deps,
                None => continue,
            };
            let pkg_depends = depends.get_mut(&pkg.pkgname).unwrap();

            for depend in all_deps.iter() {
                // Check cache first
                if let Some(pkgname) = match_cache.get(depend) {
                    if !is_satisfied(pkg_depends, depend.pattern())
                        && !pkg_depends.contains(pkgname)
                    {
                        pkg_depends.push(pkgname.clone());
                    }
                    continue;
                }

                // Find candidates matching the pattern
                let candidates: Vec<&PkgName> = if let Some(base) =
                    depend.pattern().pkgbase()
                {
                    pkgbase_map.get(base).map_or(Vec::new(), |v| {
                        v.iter()
                            .filter(|c| depend.pattern().matches(c.pkgname()))
                            .copied()
                            .collect()
                    })
                } else {
                    pkgnames
                        .iter()
                        .filter(|c| depend.pattern().matches(c.pkgname()))
                        .collect()
                };

                // Find best match using pbulk algorithm
                let mut best: Option<&PkgName> = None;
                let mut match_error: Option<pkgsrc::PatternError> = None;
                for candidate in candidates {
                    best = match best {
                        None => Some(candidate),
                        Some(current) => {
                            match depend.pattern().best_match_pbulk(
                                current.pkgname(),
                                candidate.pkgname(),
                            ) {
                                Ok(Some(m)) if m == candidate.pkgname() => {
                                    Some(candidate)
                                }
                                Ok(_) => Some(current),
                                Err(e) => {
                                    match_error = Some(e);
                                    break;
                                }
                            }
                        }
                    };
                }

                if let Some(e) = match_error {
                    let reason = format!(
                        "{}: pattern error for {}: {}",
                        pkg.pkgname.pkgname(),
                        depend.pattern().pattern(),
                        e
                    );
                    if !skip_reasons.contains_key(&pkg.pkgname) {
                        skip_reasons.insert(
                            pkg.pkgname.clone(),
                            SkipReason::PkgFail(reason),
                        );
                    }
                    continue;
                }

                if let Some(pkgname) = best {
                    if !is_satisfied(pkg_depends, depend.pattern())
                        && !pkg_depends.contains(pkgname)
                    {
                        pkg_depends.push(pkgname.clone());
                    }
                    match_cache.insert(depend.clone(), pkgname.clone());
                } else {
                    // Unresolved dependency - set pkg_fail_reason for output
                    // and store in outcomes for error reporting
                    let pattern = depend.pattern().pattern();
                    // pbulk format includes outer quotes: "could not resolve dependency "pattern""
                    let fail_reason = format!(
                        "\"could not resolve dependency \"{}\"\"",
                        pattern
                    );
                    pkg.pkg_fail_reason = Some(fail_reason);
                    let msg = format!(
                        "No match found for dependency {} of package {}",
                        pattern,
                        pkg.pkgname.pkgname()
                    );
                    match skip_reasons.get_mut(&pkg.pkgname) {
                        Some(SkipReason::UnresolvedDep(existing)) => {
                            existing.push('\n');
                            existing.push_str(&msg);
                        }
                        None => {
                            skip_reasons.insert(
                                pkg.pkgname.clone(),
                                SkipReason::UnresolvedDep(msg),
                            );
                        }
                        _ => {}
                    }
                }
            }
            pkg.all_depends = Some(all_deps);
        }

        // Propagate failures using O(V+E) worklist algorithm instead of O(depth × V × E) iterative.
        // If A depends on B and B is failed/skipped, A is indirect-failed/skipped.
        //
        // Algorithm:
        // 1. Build reverse dependency map (who depends on each package)
        // 2. Initialize worklist with directly failed packages
        // 3. For each failed package, propagate to all dependents
        // 4. Continue until worklist is empty
        {
            // Build reverse dependency map: pkgname -> packages that depend on it
            let mut reverse_deps: HashMap<&PkgName, Vec<&PkgName>> = HashMap::new();
            for (pkgname, pkg_depends) in &depends {
                for dep in pkg_depends {
                    reverse_deps.entry(dep).or_default().push(pkgname);
                }
            }

            // Initialize worklist with directly failed packages
            let mut worklist: std::collections::VecDeque<PkgName> = skip_reasons
                .keys()
                .cloned()
                .collect();

            // Process worklist - propagate failures to dependents
            while let Some(failed_pkg) = worklist.pop_front() {
                let Some(dependents) = reverse_deps.get(&failed_pkg) else {
                    continue;
                };

                // Get the reason for this failure (to determine skip vs fail)
                let is_skip = skip_reasons
                    .get(&failed_pkg)
                    .map(|r| matches!(r, SkipReason::PkgSkip(_) | SkipReason::IndirectSkip(_)))
                    .unwrap_or(false);

                for dependent in dependents {
                    // Skip if already marked
                    if skip_reasons.contains_key(*dependent) {
                        continue;
                    }

                    // Mark dependent as indirect-failed/skipped
                    let reason = if is_skip {
                        SkipReason::IndirectSkip(format!(
                            "dependency {} skipped",
                            failed_pkg.pkgname()
                        ))
                    } else {
                        SkipReason::IndirectFail(format!(
                            "dependency {} failed",
                            failed_pkg.pkgname()
                        ))
                    };

                    skip_reasons.insert((*dependent).clone(), reason);
                    // Add to worklist to propagate further
                    worklist.push_back((*dependent).clone());
                }
            }
        }

        // Build final packages list
        let mut packages: Vec<ScanResult> = Vec::new();
        let mut count_buildable = 0;

        for (pkgname, index) in std::mem::take(&mut self.packages) {
            let Some(pkgpath) = index.pkg_location.clone() else {
                error!(pkgname = %pkgname, "Package missing PKG_LOCATION, skipping");
                continue;
            };
            let resolved_depends = depends.remove(&pkgname).unwrap_or_default();
            let result = match skip_reasons.remove(&pkgname) {
                Some(reason) => ScanResult::Skipped {
                    pkgpath,
                    reason,
                    index: Some(index),
                    resolved_depends,
                },
                None => {
                    count_buildable += 1;
                    ScanResult::Buildable(ResolvedPackage {
                        index,
                        pkgpath,
                        resolved_depends,
                    })
                }
            };
            packages.push(result);
        }

        // Add scan failures (these don't have a ScanIndex, just pkgpath)
        for (pkgpath, error) in &self.scan_failures {
            packages.push(ScanResult::ScanFail {
                pkgpath: pkgpath.clone(),
                error: error.clone(),
            });
        }

        // Verify no circular dependencies (only for buildable packages)
        debug!(count_buildable, "Checking for circular dependencies");
        let mut graph = DiGraphMap::new();
        for pkg in &packages {
            if let ScanResult::Buildable(resolved) = pkg {
                for dep in &resolved.resolved_depends {
                    graph.add_edge(
                        dep.pkgname(),
                        resolved.pkgname().pkgname(),
                        (),
                    );
                }
            }
        }
        if let Some(cycle) = find_cycle(&graph) {
            let mut err = "Circular dependencies detected:\n".to_string();
            for n in cycle.iter().rev() {
                err.push_str(&format!("\t{}\n", n));
            }
            err.push_str(&format!("\t{}", cycle.last().unwrap()));
            error!(cycle = ?cycle, "Circular dependency detected");
            bail!(err);
        }

        info!(
            count_buildable,
            count_preskip = packages
                .iter()
                .filter(|p| matches!(
                    p,
                    ScanResult::Skipped { reason: SkipReason::PkgSkip(_), .. }
                ))
                .count(),
            count_prefail = packages
                .iter()
                .filter(|p| matches!(
                    p,
                    ScanResult::Skipped { reason: SkipReason::PkgFail(_), .. }
                ))
                .count(),
            count_unresolved = packages
                .iter()
                .filter(|p| matches!(
                    p,
                    ScanResult::Skipped {
                        reason: SkipReason::UnresolvedDep(_),
                        ..
                    }
                ))
                .count(),
            "Resolution complete"
        );

        // Store resolved dependencies in database
        let mut resolved_deps: Vec<(i64, i64)> = Vec::new();
        for pkg in &packages {
            if let ScanResult::Buildable(resolved) = pkg {
                if let Some(&pkg_id) = pkgname_to_id.get(resolved.pkgname()) {
                    for dep in &resolved.resolved_depends {
                        if let Some(&dep_id) = pkgname_to_id.get(dep) {
                            resolved_deps.push((pkg_id, dep_id));
                        }
                    }
                }
            }
        }
        if !resolved_deps.is_empty() {
            db.store_resolved_dependencies_batch(&resolved_deps)?;
            debug!(count = resolved_deps.len(), "Stored resolved dependencies");
        }

        Ok(ScanSummary { pkgpaths: self.done.len(), packages })
    }
}

pub fn find_cycle<'a>(
    graph: &'a DiGraphMap<&'a str, ()>,
) -> Option<Vec<&'a str>> {
    let mut visited = HashSet::new();
    let mut in_stack = HashSet::new();
    let mut stack = Vec::new();

    for node in graph.nodes() {
        if visited.contains(&node) {
            continue;
        }
        if let Some(cycle) =
            dfs(graph, node, &mut visited, &mut stack, &mut in_stack)
        {
            return Some(cycle);
        }
    }
    None
}

fn dfs<'a>(
    graph: &'a DiGraphMap<&'a str, ()>,
    node: &'a str,
    visited: &mut HashSet<&'a str>,
    stack: &mut Vec<&'a str>,
    in_stack: &mut HashSet<&'a str>,
) -> Option<Vec<&'a str>> {
    visited.insert(node);
    stack.push(node);
    in_stack.insert(node);
    for neighbor in graph.neighbors(node) {
        if in_stack.contains(neighbor) {
            if let Some(pos) = stack.iter().position(|&n| n == neighbor) {
                return Some(stack[pos..].to_vec());
            }
        } else if !visited.contains(neighbor) {
            let cycle = dfs(graph, neighbor, visited, stack, in_stack);
            if cycle.is_some() {
                return cycle;
            }
        }
    }
    stack.pop();
    in_stack.remove(node);
    None
}
