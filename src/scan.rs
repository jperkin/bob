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

/*!
 * Package dependency scanning and resolution.
 *
 * This module provides the [`Scan`] struct for discovering package dependencies
 * and building a directed acyclic graph (DAG) for build ordering.
 *
 * # Scan Process
 *
 * 1. Create a scan sandbox
 * 2. Run `make pbulk-index` on each package to discover dependencies
 * 3. Recursively discover all transitive dependencies
 * 4. Resolve dependency patterns to specific package versions
 * 5. Verify no circular dependencies exist
 * 6. Return buildable and skipped package lists
 *
 * # Skip Reasons
 *
 * Packages may be skipped for several reasons:
 *
 * - `PKG_SKIP_REASON` - Package explicitly marked to skip on this platform
 * - `PKG_FAIL_REASON` - Package expected to fail on this platform
 * - Unresolved dependencies - Required dependency not found
 * - Circular dependencies - Package has a dependency cycle
 */

use crate::config::{Pkgsrc, PkgsrcEnv};
use crate::sandbox::{SandboxScope, wait_output_with_shutdown, wait_parse_with_shutdown};
use crate::tui::{Progress, format_duration};
use crate::{Config, Interrupted, RunState, Sandbox};
use crate::{PackageCounts, PackageState};
use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use petgraph::algo::tarjan_scc;
use petgraph::graph::DiGraph;
use pkgsrc::{Pattern, PatternCache, PkgName, PkgPath, ScanIndex};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{debug, error, info, info_span, trace, warn};

/// A successfully resolved package that is ready to build.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ResolvedPackage {
    /// The scan index data including resolved dependencies.
    pub index: ScanIndex,
    /// Package path.
    pub pkgpath: PkgPath,
}

impl ResolvedPackage {
    /// Returns the package name.
    pub fn pkgname(&self) -> &PkgName {
        &self.index.pkgname
    }

    /// Returns resolved dependencies.
    pub fn depends(&self) -> &[PkgName] {
        self.index.depends()
    }

    /// Whether this package is part of the pkgsrc bootstrap.
    pub fn bootstrap_pkg(&self) -> bool {
        self.index
            .bootstrap_pkg
            .as_ref()
            .is_some_and(|b| b.is_bootstrap())
    }

    /// Returns usergroup_phase if set.
    pub fn usergroup_phase(&self) -> Option<&str> {
        self.index.usergroup_phase.as_deref()
    }

    /// Returns multi_version if set.
    pub fn multi_version(&self) -> Option<&[String]> {
        self.index.multi_version.as_deref()
    }

    /// Returns PBULK_WEIGHT, defaulting to 100 if missing.
    pub fn pbulk_weight(&self) -> usize {
        self.index.pbulk_weight.map_or(100, |w| w as usize)
    }
}

impl std::fmt::Display for ResolvedPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.index.presolve())
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
        /// Package state.
        state: PackageState,
        /// Human-readable reason.  Populated for [`PackageState::Unresolved`]
        /// (the multi-line list of unresolvable dependency patterns); `None`
        /// otherwise.  Other skip kinds source their reason from the
        /// `scan_index` table (`pkg_skip_reason` / `pkg_fail_reason`).
        reason: Option<String>,
        /// Scan index if available (present for most skipped packages).
        /// `index.resolved_depends` holds the resolved deps for the package,
        /// including partial resolutions when `state` is `Unresolved`.
        index: Option<ScanIndex>,
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
            ScanResult::Skipped { index, .. } => index.as_ref().map(|i| &i.pkgname),
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

    /// Returns resolved dependencies.
    pub fn depends(&self) -> &[PkgName] {
        match self {
            ScanResult::Buildable(pkg) => pkg.depends(),
            ScanResult::Skipped {
                index: Some(idx), ..
            } => idx.depends(),
            _ => &[],
        }
    }
}

impl std::fmt::Display for ScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanResult::Buildable(pkg) => write!(f, "{}", pkg),
            ScanResult::Skipped { index, pkgpath, .. } => {
                if let Some(idx) = index {
                    write!(f, "{}", idx.presolve())?;
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

/// Counts of packages by state, plus buildable and scanfail totals.
#[derive(Clone, Debug, Default)]
pub struct ScanCounts {
    /// Packages that are buildable.
    pub buildable: usize,
    /// Counts by [`PackageState`] variant.
    pub states: PackageCounts,
    /// Packages that failed to scan.
    pub scanfail: usize,
}

impl ScanSummary {
    /// Compute all counts in a single pass.
    pub fn counts(&self) -> ScanCounts {
        let mut c = ScanCounts::default();
        for p in &self.packages {
            match p {
                ScanResult::Buildable(_) => c.buildable += 1,
                ScanResult::Skipped { state, .. } => c.states.add(*state),
                ScanResult::ScanFail { .. } => c.scanfail += 1,
            }
        }
        c
    }

    /// Iterator over buildable packages.
    pub fn buildable(&self) -> impl Iterator<Item = &ResolvedPackage> {
        self.packages.iter().filter_map(|p| p.as_buildable())
    }

    /// Scan failures and unresolved dependency errors.
    pub fn errors(&self) -> impl Iterator<Item = &str> {
        self.packages.iter().filter_map(|p| match p {
            ScanResult::ScanFail { error, .. } => Some(error.as_str()),
            ScanResult::Skipped {
                state: PackageState::Unresolved,
                reason: Some(reason),
                ..
            } => Some(reason.as_str()),
            _ => None,
        })
    }

    /// Print the "Resolved N total packages..." line.
    pub fn print_resolved(&self) {
        println!(
            "Resolved {} total packages from {} package paths",
            self.packages.len(),
            self.pkgpaths
        );
    }

    /**
     * Print package counts.
     *
     * If `up_to_date` is provided (i.e. the up-to-date check has run),
     * the pending count is split into `pending` and `up-to-date`.
     * Otherwise every buildable package is still in `Pending` by the
     * state machine, so only `pending` is shown.
     */
    pub fn print_counts(&self, up_to_date: Option<usize>) {
        use crate::PackageState;
        use std::fmt::Write as _;
        let c = self.counts();
        let s = &c.states;
        let pending_count = match up_to_date {
            Some(n) => c.buildable.saturating_sub(n),
            None => c.buildable,
        };
        let mut line = String::new();
        let mut append = |n: usize, label: &str| {
            if !line.is_empty() {
                line.push_str(", ");
            }
            let _ = write!(line, "{n} {label}");
        };
        append(pending_count, PackageState::Pending.as_str());
        if let Some(n) = up_to_date {
            append(n, PackageState::UpToDate.as_str());
        }
        append(s.count(PackageState::is_skipped), "skipped");
        append(s.count(PackageState::is_blocked), "blocked");
        append(
            s[PackageState::Unresolved],
            PackageState::Unresolved.as_str(),
        );
        println!("{line}");
    }
}

/**
 * Package dependency scanner.
 *
 * Discovers packages and their dependencies by running `make pbulk-index`
 * in each package directory, then resolves dependency patterns to specific
 * package versions.
 *
 * Supports two modes:
 * - **Full tree**: scans all packages in the pkgsrc tree (default).
 * - **Limited**: scans only explicitly added packages and their transitive
 *   dependencies, matching pbulk's `presolve` behaviour.
 *
 * Results are cached in the [`Database`](crate::Database) for resumable
 * operation after interruption.
 */
#[derive(Debug, Default)]
pub struct Scan {
    config: Config,
    sandbox: Sandbox,
    incoming: HashSet<PkgPath>,
    /// Pkgpaths we've completed scanning (in this session).
    done: HashSet<PkgPath>,
    /// Number of pkgpaths loaded from cache at start of scan.
    initial_cached: usize,
    /// Number of pkgpaths discovered as cached during dependency discovery.
    discovered_cached: usize,
    /// Full tree scan - discover all packages, skip recursive dependency discovery.
    /// Defaults to true; set to false when packages are explicitly added.
    full_tree: bool,
    /// A previous full tree scan completed successfully.
    full_scan_complete: bool,
    /// Packages that failed to scan (pkgpath, error message).
    scan_failures: Vec<(PkgPath, String)>,
    /// Initial pkgpaths from limited_list (for deferred dependency discovery).
    /// Only set for non-full-tree scans.
    initial_pkgpaths: HashSet<PkgPath>,
    /// Verbosity level for resolution warnings (0=quiet, 1=location, 2=multi).
    verbosity: u8,
    /// Sandbox ID allocated by the scope, set by `start()`.
    sandbox_id: Option<usize>,
}

impl Scan {
    pub fn new(config: &Config, pkgsrc: Option<&Pkgsrc>) -> Scan {
        let sandbox = Sandbox::new(config, pkgsrc);
        debug!(
            scan_threads = config.scan_threads(),
            "Created new Scan instance"
        );
        Scan {
            config: config.clone(),
            sandbox,
            incoming: HashSet::new(),
            done: HashSet::new(),
            initial_cached: 0,
            discovered_cached: 0,
            full_tree: true,
            full_scan_complete: false,
            scan_failures: Vec::new(),
            initial_pkgpaths: HashSet::new(),
            verbosity: 0,
            sandbox_id: None,
        }
    }

    pub fn set_verbosity(&mut self, v: u8) {
        self.verbosity = v;
    }

    pub fn add(&mut self, pkgpath: &PkgPath) {
        debug!(pkgpath = %pkgpath.as_path().display(), "Adding package to scan queue");
        self.full_tree = false;
        self.incoming.insert(pkgpath.clone());
        self.initial_pkgpaths.insert(pkgpath.clone());
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
    pub fn init_from_db(&mut self, db: &crate::db::Database) -> Result<(usize, usize)> {
        let scanned = db.get_scanned_pkgpaths()?;
        let cached_count = scanned.len();
        let mut pending_count = 0;

        if cached_count > 0 {
            info!(cached_count, "Found cached scan results in database");

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

            /*
             * For full tree scans, check for dependencies that were
             * discovered but not yet scanned.  This handles resume
             * after interrupt.
             *
             * For limited scans, the early-return check in start()
             * calls find_missing_pkgpaths() instead, ensuring we only
             * scan dependencies of active packages.
             */
            if self.full_tree {
                let unscanned = db.get_unscanned_dependencies()?;
                if !unscanned.is_empty() {
                    info!(
                        unscanned_count = unscanned.len(),
                        "Found unscanned dependencies from interrupted scan"
                    );
                    for pkgpath_str in unscanned {
                        if let Ok(pkgpath) = PkgPath::new(&pkgpath_str)
                            && !self.done.contains(&pkgpath)
                        {
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
    fn discover_packages(
        &mut self,
        pool: &rayon::ThreadPool,
        shutdown: &RunState,
        pkgsrc: &Pkgsrc,
    ) -> anyhow::Result<()> {
        println!("Discovering packages...");
        let basedir = pkgsrc.basedir.display().to_string();

        // Get top-level SUBDIR (categories + USER_ADDITIONAL_PKGS)
        let child = self.sandbox.execute_command(
            self.sandbox_id,
            &pkgsrc.make,
            ["-C", &basedir, "show-subdir-var", "VARNAME=SUBDIR"],
            vec![],
        )?;
        let output =
            wait_output_with_shutdown(child, shutdown).context("Failed to run show-subdir-var")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to get categories: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let entries: Vec<&str> = stdout.split_whitespace().collect();

        // Separate USER_ADDITIONAL_PKGS (contain '/') from categories
        let mut categories: Vec<&str> = Vec::new();
        for entry in entries {
            if entry.contains('/') {
                if let Ok(pkgpath) = PkgPath::new(entry) {
                    self.incoming.insert(pkgpath);
                }
            } else {
                categories.push(entry);
            }
        }

        // Process categories in parallel
        let make = &pkgsrc.make;
        let sandbox = &self.sandbox;
        let sandbox_id = self.sandbox_id;
        let discovered: Vec<PkgPath> = pool.install(|| {
            categories
                .par_iter()
                .flat_map(|category| {
                    let workdir = format!("{}/{}", basedir, category);
                    let result = sandbox
                        .execute_command(
                            sandbox_id,
                            make,
                            [
                                "-C",
                                &workdir,
                                "show-subdir-var",
                                "VARNAME=SUBDIR",
                            ],
                            vec![],
                        )
                        .and_then(|c| wait_output_with_shutdown(c, shutdown));

                    match result {
                        Ok(o) if o.status.success() => {
                            let pkgs = String::from_utf8_lossy(&o.stdout);
                            pkgs.split_whitespace()
                                .filter_map(|pkg| {
                                    let path = format!("{}/{}", category, pkg);
                                    PkgPath::new(&path).ok()
                                })
                                .collect::<Vec<_>>()
                        }
                        Ok(o) => {
                            let stderr = String::from_utf8_lossy(&o.stderr);
                            debug!(category = *category, %stderr, "Failed to get packages for category");
                            vec![]
                        }
                        Err(e) => {
                            debug!(category = *category, error = format!("{e:#}"), "Failed to run make in category");
                            vec![]
                        }
                    }
                })
                .collect()
        });

        self.incoming.extend(discovered);

        info!(
            discovered = self.incoming.len(),
            "Package discovery complete"
        );
        println!("Discovered {} package paths", self.incoming.len());

        Ok(())
    }

    pub fn start(
        &mut self,
        db: &crate::db::Database,
        scope: &mut SandboxScope,
        pkgsrc: &Pkgsrc,
    ) -> anyhow::Result<()> {
        /*
         * Adopt the scope's sandbox so the pkgsrc cell is shared.  After
         * this, set_pkgsrc_env() on either sandbox is visible from both,
         * which lets the scope's Drop run a correct post_build cleanup
         * if scan exits via an error path.
         */
        self.sandbox = scope.sandbox().clone();

        info!(
            incoming_count = self.incoming.len(),
            sandbox_enabled = self.sandbox.enabled(),
            "Starting package scan"
        );

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.config.scan_threads())
            .thread_name(|i| format!("scan-{i}"))
            .build()
            .context("Failed to build scan thread pool")?;

        let shutdown_flag = scope.state().clone();

        // For full tree scans where a previous scan completed, all packages
        // are already cached - nothing to do.
        if self.full_tree && self.full_scan_complete && !self.done.is_empty() {
            println!("All {} package paths already scanned", self.done.len());
            return Ok(());
        }

        /*
         * For non-full-tree scans, prune already-cached packages from
         * incoming before sandbox creation to avoid unnecessary sandbox
         * create/destroy work.  If all initial packages are cached, check
         * for unscanned dependencies (resume after interrupt) before
         * deciding there's nothing to do.
         */
        if !self.full_tree {
            self.incoming.retain(|p| !self.done.contains(p));
            if self.incoming.is_empty() {
                if let Ok(deps) = self.unscanned_deps(db) {
                    self.incoming = deps;
                }
                if self.incoming.is_empty() {
                    if !self.done.is_empty() {
                        println!("All {} package paths already scanned", self.done.len());
                    }
                    return Ok(());
                }
            }
        }

        /*
         * Only a single sandbox is required, 'make pbulk-index' can safely be
         * run in parallel inside one sandbox.
         *
         * Ensure a sandbox exists. The caller manages overall lifecycle.
         */
        if scope.enabled() {
            crate::print_status("Creating sandbox");
            let start = Instant::now();
            let result = scope.ensure(1).and_then(|ids| {
                self.sandbox_id = ids.first().copied();
                self.sandbox
                    .run_pre_build(self.sandbox_id)
                    .context("pre-build failed")?;
                Ok(())
            });
            match result {
                Ok(()) => crate::print_elapsed("Creating sandbox", start.elapsed()),
                Err(e) => {
                    crate::print_failed("Creating sandbox", start.elapsed());
                    return Err(e);
                }
            }
        }

        let env = match db.load_pkgsrc_env() {
            Ok(env) => env,
            Err(_) => {
                let env = PkgsrcEnv::fetch(pkgsrc, &self.sandbox, self.sandbox_id)?;
                db.store_pkgsrc_env(&env)?;
                let mut vcs_info = crate::vcs::VcsInfo::from_path(&pkgsrc.basedir);
                if let Some(branch) = self.config.report_branch() {
                    vcs_info.remote_branch = Some(branch.to_string());
                }
                db.store_vcs_info(&vcs_info)?;
                env
            }
        };
        self.sandbox.set_pkgsrc_env(env);

        // For full tree scans, always discover all packages
        if self.full_tree {
            self.discover_packages(&pool, &shutdown_flag, pkgsrc)?;
            self.incoming.retain(|p| !self.done.contains(p));
        }

        // Nothing to scan - all packages are cached
        if self.incoming.is_empty() {
            if !self.done.is_empty() {
                println!("All {} package paths already scanned", self.done.len());
            }

            if scope.enabled() {
                self.run_post_build()?;
            }
            return Ok(());
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
            Progress::new(
                "Scanning",
                "",
                total_count,
                self.config.scan_threads(),
                self.config.tui(),
            )
            .context("Failed to initialize progress display")?,
        ));

        // Mark cached packages in progress display
        if self.initial_cached > 0
            && let Ok(mut p) = progress.lock()
        {
            p.state_mut().cached = self.initial_cached;
        }

        // Flag to stop the refresh thread
        let stop_refresh = Arc::new(AtomicBool::new(false));

        // Spawn a thread to periodically refresh the display (for timer updates)
        let progress_refresh = Arc::clone(&progress);
        let stop_flag = Arc::clone(&stop_refresh);
        let shutdown_for_refresh = shutdown_flag.clone();
        let refresh_thread = crate::spawn_named("scan-refresh", move || {
            crate::tui::refresh_loop(progress_refresh, &stop_flag, &shutdown_for_refresh)
        });

        let mut db_error: Option<anyhow::Error> = None;

        // Borrow config and sandbox separately for use in scanner thread,
        // allowing main thread to mutate self.done, self.incoming, etc.
        let sandbox = &self.sandbox;
        let sandbox_id = self.sandbox_id;
        let scan_env = self.scan_env();

        /*
         * For limited scans, prime incoming with any missing dependencies.
         * This handles resume after interrupt where initial packages are
         * already scanned but their dependencies are not.
         */
        if !self.full_tree
            && self.incoming.is_empty()
            && let Ok(deps) = self.unscanned_deps(db)
        {
            for pkgpath in deps {
                self.incoming.insert(pkgpath);
                if let Ok(mut p) = progress.lock() {
                    p.state_mut().total += 1;
                }
            }
        }

        /*
         * Continuously iterate over incoming queue, moving to done once
         * processed, and adding any dependencies to incoming to be processed
         * next.
         */
        let mut scanned_count: usize = 0;

        loop {
            // Check for interrupt (stop or shutdown).
            if shutdown_flag.interrupted() {
                if shutdown_flag.is_stopping()
                    && let Ok(mut p) = progress.lock()
                {
                    p.announce_interrupt();
                }
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
            let (tx, rx) = std::sync::mpsc::sync_channel::<(PkgPath, Result<Vec<ScanIndex>>)>(
                CHANNEL_BUFFER_SIZE,
            );

            let mut new_incoming: HashSet<PkgPath> = HashSet::new();

            std::thread::scope(|s| {
                // Spawn scanning thread
                let progress_clone = Arc::clone(&progress);
                let shutdown_clone = shutdown_flag.clone();
                let pool_ref = &pool;
                let scan_env_ref = &scan_env;

                std::thread::Builder::new()
                    .name("scan-dispatch".to_string())
                    .spawn_scoped(s, move || {
                        pool_ref.install(|| {
                            pkgpaths.par_iter().for_each(|pkgpath| {
                                // Check for interrupt before starting
                                if shutdown_clone.interrupted() {
                                    return;
                                }

                                let pathname = pkgpath.as_path().to_string_lossy().to_string();
                                let thread_id = rayon::current_thread_index().unwrap_or(0);

                                // Update progress - show current package
                                if let Ok(mut p) = progress_clone.lock() {
                                    p.state_mut().set_worker_active(thread_id, &pathname);
                                    p.state_mut().increment_dispatched();
                                }

                                let result = Self::scan_pkgpath_with(
                                    pkgsrc,
                                    sandbox,
                                    sandbox_id,
                                    pkgpath,
                                    scan_env_ref,
                                    &shutdown_clone,
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
                                let _ = tx.send((pkgpath.clone(), result));
                            });
                        });
                        drop(tx);
                    })
                    .expect("failed to spawn thread");

                /*
                 * Process results and write to DB.
                 */
                for (pkgpath, result) in rx {
                    scanned_count += 1;
                    if let Ok(mut p) = progress.lock() {
                        let total = p.state_mut().total.saturating_sub(p.state_mut().cached);
                        let _ = p.print_progress_dot(scanned_count, total);
                    }

                    let scanpkgs = match result {
                        Ok(pkgs) => pkgs,
                        Err(e) => {
                            self.scan_failures.push((pkgpath.clone(), e.to_string()));
                            self.done.insert(pkgpath);
                            continue;
                        }
                    };
                    self.done.insert(pkgpath.clone());

                    // Save to database
                    if !scanpkgs.is_empty()
                        && let Err(e) = db.store_scan_pkgpath(&pkgpath.to_string(), &scanpkgs)
                    {
                        error!(error = format!("{e:#}"), "Failed to store scan results");
                        if db_error.is_none() {
                            db_error = Some(e);
                        }
                    }
                }
            });

            if let Ok(mut p) = progress.lock() {
                let total = p.state_mut().total.saturating_sub(p.state_mut().cached);
                let _ = p.flush_progress_dots(scanned_count, total);
            }

            // Check for interrupt after batch completes.
            if shutdown_flag.interrupted() {
                if shutdown_flag.is_stopping()
                    && let Ok(mut p) = progress.lock()
                {
                    p.announce_interrupt();
                }
                break;
            }

            // Don't start new waves if database writes are failing
            if db_error.is_some() {
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

            /*
             * For limited scans, check for missing dependency pkgpaths by
             * doing a resolution pass. This matches pbulk's iterative
             * approach where dependencies are only scanned if needed.
             */
            if !self.full_tree && new_incoming.is_empty() {
                match self.unscanned_deps(db) {
                    Ok(deps) if !deps.is_empty() => {
                        let count = deps.len();
                        for pkgpath in deps {
                            new_incoming.insert(pkgpath);
                            if let Ok(mut p) = progress.lock() {
                                p.state_mut().total += 1;
                            }
                        }
                        debug!(
                            missing_count = count,
                            "Discovered missing dependency pkgpaths"
                        );
                    }
                    Err(e) => {
                        warn!(error = format!("{e:#}"), "Failed to find missing pkgpaths");
                    }
                    _ => {}
                }
            }

            self.incoming = new_incoming;
        }

        // Stop the refresh thread and print final summary
        stop_refresh.store(true, Ordering::Relaxed);
        let _ = refresh_thread.join();

        if shutdown_flag.interrupted() {
            let was_first = if let Ok(mut p) = progress.lock() {
                p.finish_interrupted().unwrap_or(false)
            } else {
                false
            };
            if was_first && shutdown_flag.is_shutdown() {
                eprintln!("Interrupted, shutting down...");
            }
        }

        if !shutdown_flag.interrupted() {
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

            let elapsed_str = elapsed
                .map(format_duration)
                .unwrap_or_else(|| "?".to_string());

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

        if scope.enabled() {
            self.run_post_build()?;
        }

        if shutdown_flag.interrupted() {
            return Err(Interrupted.into());
        }

        if let Some(e) = db_error {
            return Err(e.context("Failed to persist scan results to database"));
        }

        Ok(())
    }

    /// Run post-build operations (hook destroy actions + prefix cleanup).
    fn run_post_build(&self) -> anyhow::Result<()> {
        if let Err(e) = self.sandbox.run_post_build(self.sandbox_id) {
            warn!(error = format!("{e:#}"), "post-build error");
        }
        Ok(())
    }

    /// Returns scan failures as formatted error strings.
    pub fn scan_errors(&self) -> impl Iterator<Item = &str> {
        self.scan_failures.iter().map(|(_, e)| e.as_str())
    }

    fn scan_env(&self) -> Vec<(String, String)> {
        self.sandbox
            .pkgsrc_env()
            .map(|e| {
                e.cachevars
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn unscanned_deps(&self, db: &crate::db::Database) -> Result<HashSet<PkgPath>> {
        let missing = self.find_missing_pkgpaths(db)?;
        Ok(missing
            .into_iter()
            .filter(|p| !self.done.contains(p))
            .collect())
    }

    /*
     * Scan a single PKGPATH using provided config and sandbox references.
     * This allows scanning without borrowing all of `self`.
     */
    fn scan_pkgpath_with(
        pkgsrc: &Pkgsrc,
        sandbox: &Sandbox,
        sandbox_id: Option<usize>,
        pkgpath: &PkgPath,
        scan_env: &[(String, String)],
        shutdown: &RunState,
    ) -> anyhow::Result<Vec<ScanIndex>> {
        let pkgpath_str = pkgpath.as_path().display().to_string();
        let span = info_span!("scan", pkgpath = %pkgpath_str);
        let _guard = span.enter();
        debug!("Scanning package");

        let pkgsrcdir = pkgsrc.basedir.display().to_string();
        let workdir = format!("{}/{}", pkgsrcdir, pkgpath_str);

        trace!(%workdir, ?scan_env, "Executing pkg-scan");
        let child = sandbox.execute_command(
            sandbox_id,
            &pkgsrc.make,
            ["-C", &workdir, "pbulk-index"],
            scan_env.to_vec(),
        )?;

        /*
         * Parse output as the child produces it, keeping only the first
         * occurrence of each PKGNAME.  For multi-version packages,
         * pbulk-index returns the *_DEFAULT version first, which is the
         * one we want.  Set PKGPATH (PKG_LOCATION) as for some reason
         * pbulk-index doesn't.
         */
        let parse_pkgpath = pkgpath.clone();
        let parse_span = tracing::Span::current();
        let (status, index, stderr) = wait_parse_with_shutdown(child, shutdown, move |stdout| {
            let _guard = parse_span.enter();
            let mut seen_pkgnames = HashSet::new();
            let mut index: Vec<ScanIndex> = Vec::new();
            for pkg in ScanIndex::from_reader(stdout) {
                let mut pkg = pkg?;
                if !seen_pkgnames.insert(pkg.pkgname.clone()) {
                    continue;
                }
                pkg.pkg_location = Some(parse_pkgpath.clone());
                debug!(
                    pkgname = %pkg.pkgname.pkgname(),
                    skip_reason = ?pkg.pkg_skip_reason,
                    fail_reason = ?pkg.pkg_fail_reason,
                    depends_count = pkg.all_depends.as_ref().map_or(0, |v| v.iter().count()),
                    "Found package in scan"
                );
                index.push(pkg);
            }
            anyhow::Ok(index)
        })?;

        if !status.success() {
            error!(exit_code = ?status.code(), %stderr, "pkg-scan script failed");
            let stderr = stderr.trim();
            let msg = if stderr.is_empty() {
                format!("Scan failed for {}", pkgpath_str)
            } else {
                format!("Scan failed for {}: {}", pkgpath_str, stderr)
            };
            bail!(msg);
        }

        let index = index?;
        debug!(packages_found = index.len(), "Scan complete");

        Ok(index)
    }

    /**
     * Find dependency pkgpaths that need to be scanned to resolve all
     * dependencies.
     *
     * This is used in deferred dependency discovery mode. It does a
     * lightweight pass through scanned packages to find dependencies that
     * have no match yet. Returns the set of pkgpaths to scan next.
     *
     * Only packages from initial_pkgpaths (and their transitive dependencies
     * that have already been scanned) are considered.
     */
    fn find_missing_pkgpaths(&self, db: &crate::db::Database) -> Result<HashSet<PkgPath>> {
        /*
         * Build set of available pkgnames (first occurrence only, like
         * resolve), then iteratively expand an "active" set starting from
         * initial_pkgpaths. For each active package, try to match its
         * dependencies. If no match exists, add the dependency's pkgpath
         * to the missing set. If a match exists, add it to the active set.
         * Continue until no new packages are activated.
         */
        let mut packages: IndexMap<PkgName, ScanIndex> = IndexMap::new();
        db.with_scan_data(crate::db::ScanIndexFields::Resolve, |pull| {
            while let Some(pkg) = pull()? {
                if !packages.contains_key(&pkg.pkgname) {
                    packages.insert(pkg.pkgname.clone(), pkg);
                }
            }
            Ok(())
        })?;

        let names: Vec<PkgName> = packages.keys().cloned().collect();
        let pkgbase_map = Self::build_pkgbase_map(&names);

        let mut active_pkgnames: HashSet<PkgName> = HashSet::new();
        for pkg in packages.values() {
            if let Some(ref loc) = pkg.pkg_location
                && self.initial_pkgpaths.contains(loc)
            {
                active_pkgnames.insert(pkg.pkgname.clone());
            }
        }

        let mut missing_pkgpaths: HashSet<PkgPath> = HashSet::new();
        let mut changed = true;

        while changed {
            changed = false;
            let current_active: Vec<PkgName> = active_pkgnames.iter().cloned().collect();

            for active_pkgname in current_active {
                let Some(pkg) = packages.get(&active_pkgname) else {
                    continue;
                };
                let Some(ref all_deps) = pkg.all_depends else {
                    continue;
                };

                for depend in all_deps.depends() {
                    let depend = match depend {
                        Ok(d) => d,
                        Err(e) => {
                            warn!(
                                pkg = %pkg.pkgname.pkgname(),
                                error = format!("{e:#}"),
                                "Malformed dependency"
                            );
                            continue;
                        }
                    };
                    let candidates = Self::find_candidates(depend.pattern(), &pkgbase_map, &names);

                    if candidates.is_empty() {
                        let dep_path = depend.pkgpath();
                        if !self.done.contains(dep_path) {
                            missing_pkgpaths.insert(dep_path.clone());
                        }
                    } else {
                        for &candidate in &candidates {
                            if !active_pkgnames.contains(&names[candidate]) {
                                active_pkgnames.insert(names[candidate].clone());
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        debug!(
            missing_count = missing_pkgpaths.len(),
            active_count = active_pkgnames.len(),
            "Found missing dependency pkgpaths"
        );

        Ok(missing_pkgpaths)
    }

    /**
     * Build a map from pkgbase to matching PkgNames for efficient lookups.
     */
    fn build_pkgbase_map(names: &[PkgName]) -> HashMap<&str, Vec<usize>> {
        let mut map: HashMap<&str, Vec<usize>> = HashMap::new();
        for (id, pkgname) in names.iter().enumerate() {
            map.entry(pkgname.pkgbase()).or_default().push(id);
        }
        map
    }

    /**
     * Find all packages matching a dependency pattern, as indices into
     * `names`.
     *
     * Uses pkgbase for efficient O(1) lookup when available, falling back to
     * iteration over all packages for patterns without a pkgbase (e.g., `p5-*`).
     */
    fn find_candidates(
        pattern: &Pattern,
        pkgbase_map: &HashMap<&str, Vec<usize>>,
        names: &[PkgName],
    ) -> Vec<usize> {
        if let Some(bases) = pattern.pkgbases() {
            let mut out = Vec::new();
            for base in bases {
                if let Some(v) = pkgbase_map.get(base) {
                    out.extend(
                        v.iter()
                            .filter(|&&id| pattern.matches(names[id].pkgname()))
                            .copied(),
                    );
                }
            }
            out
        } else {
            (0..names.len())
                .filter(|&id| pattern.matches(names[id].pkgname()))
                .collect()
        }
    }

    /**
     * Find the best matching package for a dependency pattern.
     *
     * Uses pkgbase for efficient lookup when available, falling back
     * to all packages for patterns without a known base.  Matching
     * and version comparison are handled by a pbulk
     * [`BestMatch`](pkgsrc::pattern::BestMatch) accumulator.
     *
     * Returns:
     * - `Ok(Some(id))` - index into `names` of the best matching package
     * - `Ok(None)` - no candidates match the pattern
     * - `Err(e)` - version comparison error (malformed version)
     */
    fn find_best_match(
        pattern: &Pattern,
        pkgbase_map: &HashMap<&str, Vec<usize>>,
        names: &[PkgName],
    ) -> Result<Option<usize>, pkgsrc::PatternError> {
        let mut matcher = pattern.best_matcher_pbulk();
        let mut best_id: Option<usize> = None;
        if let Some(bases) = pattern.pkgbases() {
            for base in bases {
                if let Some(candidates) = pkgbase_map.get(base) {
                    for &id in candidates {
                        if matcher.consider(names[id].pkgname())? {
                            best_id = Some(id);
                        }
                    }
                }
            }
        } else {
            for (id, candidate) in names.iter().enumerate() {
                if matcher.consider(candidate.pkgname())? {
                    best_id = Some(id);
                }
            }
        }
        Ok(best_id)
    }

    /**
     * Propagate failures through the dependency graph.
     *
     * If package A depends on B, and B has a skip reason, then A gets an
     * indirect skip reason matching the dependency's category:
     * - preskipped dep → indirect-preskipped
     * - prefailed dep → indirect-prefailed
     * - unresolved dep → indirect-unresolved
     *
     * Priority: prefailed > unresolved > preskipped (we want to report the
     * most severe blocker). Iterates until no new entries are added.
     */
    fn propagate_failures(depends: &[Vec<usize>], skip_reasons: &mut [Option<PackageState>]) {
        loop {
            let mut new_skip_reasons: Vec<(usize, PackageState)> = Vec::new();
            for (id, pkg_depends) in depends.iter().enumerate() {
                if skip_reasons[id].is_some() {
                    continue;
                }
                let mut blocking_reason: Option<PackageState> = None;
                for &dep in pkg_depends {
                    if let Some(dep_reason) = skip_reasons[dep] {
                        let indirect = dep_reason.indirect();
                        use PackageState::*;
                        let dominated = match blocking_reason {
                            None => true,
                            Some(IndirectPreSkipped) => true,
                            Some(IndirectUnresolved) if indirect == IndirectPreFailed => true,
                            _ => false,
                        };
                        if dominated {
                            blocking_reason = Some(indirect);
                        }
                        if blocking_reason == Some(IndirectPreFailed) {
                            break;
                        }
                    }
                }
                if let Some(reason) = blocking_reason {
                    new_skip_reasons.push((id, reason));
                }
            }
            if new_skip_reasons.is_empty() {
                break;
            }
            for (id, reason) in new_skip_reasons {
                skip_reasons[id] = Some(reason);
            }
        }
    }

    /**
     * Check for circular dependencies in buildable packages.
     *
     * Edges are `(dep, dependent)` pairs of indices into `names`.  Any
     * strongly connected group of packages, or a package depending on
     * itself, is an error listing every package in each group.
     */
    fn check_circular_deps(names: &[PkgName], edges: &[(u32, u32)]) -> Result<()> {
        let graph = DiGraph::<(), ()>::from_edges(edges.iter().copied());
        let mut groups: Vec<Vec<&PkgName>> = Vec::new();
        for scc in tarjan_scc(&graph) {
            if scc.len() > 1 || graph.find_edge(scc[0], scc[0]).is_some() {
                let mut group: Vec<&PkgName> = scc.iter().map(|n| &names[n.index()]).collect();
                group.sort_by(|a, b| a.pkgname().cmp(b.pkgname()));
                groups.push(group);
            }
        }
        if groups.is_empty() {
            return Ok(());
        }
        error!(?groups, "Circular dependencies detected");
        let blocks: Vec<String> = groups
            .iter()
            .map(|g| {
                g.iter()
                    .map(|n| format!("\t{}", n))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .collect();
        bail!("Circular dependencies detected:\n{}", blocks.join("\n\n"));
    }

    /**
     * Resolve dependency patterns to available package names.
     *
     * Takes scanned package data (from `make pbulk-index`) and resolves
     * dependency patterns like "perl>=5.0" to specific packages like
     * "perl-5.38.0". Returns a [`ScanSummary`] classifying each package as
     * Buildable, Skipped, or ScanFail.
     *
     * # Algorithm
     *
     * **Phase 1 - Load and classify**: Load all scan indexes from the
     * database. For each package, record any PKG_SKIP_REASON or
     * PKG_FAIL_REASON as a skip reason. For limited scans (non-full-tree),
     * seed the "active" set with packages from initial_pkgpaths.
     *
     * **Phase 2 - Setup lookups**: Build a pkgbase map for O(1) candidate
     * lookup by package base name (e.g., "perl" -> [perl-5.38.0, perl-5.36.0]).
     * Initialize a match cache to memoize resolved patterns.
     *
     * **Phase 3 - Resolution loop**: For each package (active packages only
     * for limited scans), resolve each dependency pattern:
     *   - Check the cache for a previous match
     *   - Find candidates via pkgbase map (fast) or full scan (for wildcards)
     *   - Select the best match using pbulk's version comparison rules
     *   - Record unresolved dependencies as skip reasons
     *   - For limited scans, activate matched dependencies and iterate until
     *     no new packages become active
     *
     * **Phase 4 - Propagate failures**: Walk the dependency graph to mark
     * packages with failed/skipped dependencies as IndirectFail/IndirectSkip.
     *
     * **Phase 5 - Check cycles**: Error if any buildable packages form a
     * circular dependency group.
     *
     * **Phase 6 - Build results**: Transform the packages into a
     * `Vec<ScanResult>`, filtering inactive packages for limited scans,
     * and return the summary.
     *
     * # Limited vs Full Tree Scans
     *
     * Full tree scans resolve all packages in pkgsrc. Limited scans (when
     * packages are explicitly added via `add()`) only resolve packages from
     * initial_pkgpaths and their transitive dependencies, matching pbulk's
     * presolve behavior. This avoids scanning/resolving thousands of unneeded
     * packages when building a small subset.
     */
    pub fn resolve<I>(&mut self, scan_data: I) -> Result<ScanSummary>
    where
        I: IntoIterator<Item = Result<ScanIndex>>,
    {
        info!(
            done_pkgpaths = self.done.len(),
            "Starting dependency resolution"
        );

        /*
         * Packages are stored in arrival order and every resolver
         * structure is keyed by position.  `names` mirrors each
         * package's pkgname for matching while `indexes` is mutated.
         */
        let mut names: Vec<PkgName> = Vec::new();
        let mut indexes: Vec<ScanIndex> = Vec::new();
        let mut name_index: HashMap<PkgName, usize> = HashMap::new();
        let mut skip_reasons: Vec<Option<PackageState>> = Vec::new();
        let mut unresolved_reasons: HashMap<usize, Vec<String>> = HashMap::new();
        let mut depends: Vec<Vec<usize>> = Vec::new();
        let mut active: Vec<bool> = Vec::new();
        let use_active_filter = !self.full_tree && !self.initial_pkgpaths.is_empty();

        for pkg in scan_data {
            let pkg = pkg?;
            if name_index.contains_key(&pkg.pkgname) {
                debug!(pkgname = %pkg.pkgname.pkgname(), "Skipping duplicate PKGNAME");
                continue;
            }

            let mut skip = None;
            if let Some(reason) = &pkg.pkg_skip_reason
                && !reason.is_empty()
            {
                info!(pkgname = %pkg.pkgname.pkgname(), %reason, "PKG_SKIP_REASON");
                skip = Some(PackageState::PreSkipped);
            }

            if let Some(reason) = &pkg.pkg_fail_reason
                && !reason.is_empty()
                && skip.is_none()
            {
                info!(pkgname = %pkg.pkgname.pkgname(), %reason, "PKG_FAIL_REASON");
                skip = Some(PackageState::PreFailed);
            }

            active.push(
                use_active_filter
                    && pkg
                        .pkg_location
                        .as_ref()
                        .is_some_and(|loc| self.initial_pkgpaths.contains(loc)),
            );
            skip_reasons.push(skip);
            name_index.insert(pkg.pkgname.clone(), names.len());
            names.push(pkg.pkgname.clone());
            depends.push(Vec::new());
            indexes.push(pkg);
        }

        info!(packages = indexes.len(), "Loaded packages");

        let pkgbase_map = Self::build_pkgbase_map(&names);
        let verbosity = self.verbosity;
        let pkg_locations: Vec<Option<PkgPath>> = if verbosity >= 1 {
            indexes.iter().map(|idx| idx.pkg_location.clone()).collect()
        } else {
            Vec::new()
        };
        let mut match_cache: HashMap<String, usize> = HashMap::new();
        let mut patterns = PatternCache::with_capacity(names.len());
        let names_ref = &names;
        let is_satisfied = |deps: &[usize], pattern: &Pattern| {
            deps.iter()
                .any(|&existing| pattern.matches(names_ref[existing].pkgname()))
        };

        let mut resolved = vec![false; indexes.len()];
        loop {
            let mut new_active = false;
            for (id, pkg) in indexes.iter_mut().enumerate() {
                if use_active_filter && !active[id] {
                    continue;
                }
                if resolved[id] {
                    continue;
                }
                resolved[id] = true;

                let all_deps = match pkg.all_depends.take() {
                    Some(deps) => deps,
                    None => continue,
                };
                let pkg_depends = &mut depends[id];

                for dep in all_deps.iter() {
                    let dep = match dep {
                        Ok(d) => d,
                        Err(e) => {
                            warn!(
                                pkg = %pkg.pkgname.pkgname(),
                                error = format!("{e:#}"),
                                "Malformed dependency"
                            );
                            continue;
                        }
                    };

                    let pattern = match patterns.compile(dep.pattern()) {
                        Ok(p) => p,
                        Err(e) => {
                            let reason = format!(
                                "{}: pattern error for {}: {}",
                                pkg.pkgname.pkgname(),
                                dep.pattern(),
                                e
                            );
                            if skip_reasons[id].is_none() {
                                if pkg.pkg_fail_reason.is_none() {
                                    pkg.pkg_fail_reason = Some(reason);
                                }
                                skip_reasons[id] = Some(PackageState::PreFailed);
                            }
                            continue;
                        }
                    };

                    if let Some(&dep_id) = match_cache.get(dep.pattern()) {
                        if !is_satisfied(pkg_depends, pattern) && !pkg_depends.contains(&dep_id) {
                            pkg_depends.push(dep_id);
                        }
                        continue;
                    }

                    if verbosity >= 2 {
                        let candidates = Self::find_candidates(pattern, &pkgbase_map, names_ref);
                        if candidates.len() > 1 {
                            for &c in &candidates {
                                eprintln!(
                                    "Multiple matches for dependency {} of package {}: {}",
                                    dep.pattern(),
                                    pkg.pkgname.pkgname(),
                                    names_ref[c].pkgname()
                                );
                            }
                        }
                    }

                    match Self::find_best_match(pattern, &pkgbase_map, names_ref) {
                        Err(e) => {
                            let reason = format!(
                                "{}: version comparison error for {}: {}",
                                pkg.pkgname.pkgname(),
                                dep.pattern(),
                                e
                            );
                            if skip_reasons[id].is_none() {
                                if pkg.pkg_fail_reason.is_none() {
                                    pkg.pkg_fail_reason = Some(reason);
                                }
                                skip_reasons[id] = Some(PackageState::PreFailed);
                            }
                        }
                        Ok(Some(best)) => {
                            if verbosity >= 1
                                && let Some(loc) = pkg_locations.get(best).and_then(|l| l.as_ref())
                                && let Ok(dep_path) = PkgPath::new(dep.pkgpath())
                                && *loc != dep_path
                            {
                                eprintln!(
                                    "Best matching {} differs from location {} for dependency {} of package {}",
                                    names_ref[best].pkgname(),
                                    dep_path,
                                    dep.pattern(),
                                    pkg.pkgname.pkgname()
                                );
                            }
                            if !is_satisfied(pkg_depends, pattern) && !pkg_depends.contains(&best) {
                                pkg_depends.push(best);
                            }
                            match_cache.insert(dep.pattern().to_string(), best);
                            if use_active_filter && !active[best] {
                                active[best] = true;
                                new_active = true;
                            }
                        }
                        Ok(None) => {
                            let fail_reason =
                                format!("\"could not resolve dependency \"{}\"\"", dep.pattern());
                            pkg.pkg_fail_reason = Some(fail_reason);
                            let msg = format!(
                                "No match found for dependency {} of package {}",
                                dep.pattern(),
                                pkg.pkgname.pkgname()
                            );
                            if !matches!(
                                skip_reasons[id],
                                Some(PackageState::PreSkipped | PackageState::PreFailed)
                            ) {
                                skip_reasons[id] = Some(PackageState::Unresolved);
                                unresolved_reasons.entry(id).or_default().push(msg);
                            }
                        }
                    }
                }
                pkg.all_depends = Some(all_deps);
            }
            if !use_active_filter || !new_active {
                break;
            }
        }

        /*
         * Release resolver-only caches before constructing the result
         * Vec, which otherwise doubles peak memory for large scans.
         */
        drop(match_cache);
        drop(patterns);
        drop(pkg_locations);
        drop(pkgbase_map);
        drop(name_index);
        drop(resolved);

        Self::propagate_failures(&depends, &mut skip_reasons);

        debug!("Checking for circular dependencies");
        let mut edges: Vec<(u32, u32)> = Vec::new();
        for (id, deps) in depends.iter().enumerate() {
            if (use_active_filter && !active[id])
                || skip_reasons[id].is_some()
                || indexes[id].pkg_location.is_none()
            {
                continue;
            }
            for &dep in deps {
                edges.push((dep as u32, id as u32));
            }
        }
        Self::check_circular_deps(&names, &edges)?;
        drop(edges);

        let mut packages: Vec<ScanResult> = Vec::new();
        let mut count_filtered = 0;

        for (id, mut index) in indexes.into_iter().enumerate() {
            if use_active_filter && !active[id] {
                count_filtered += 1;
                continue;
            }

            let Some(pkgpath) = index.pkg_location.clone() else {
                error!(pkgname = %names[id], "Package missing PKG_LOCATION, skipping");
                continue;
            };
            let resolved_depends: Vec<PkgName> = std::mem::take(&mut depends[id])
                .into_iter()
                .map(|dep| names[dep].clone())
                .collect();
            let skip = skip_reasons[id].take();
            /*
             * pbulk compat: a directly-unresolvable package omits the
             * DEPENDS line entirely, so leave resolved_depends as None.
             */
            let complete = skip != Some(PackageState::Unresolved);
            if complete && !resolved_depends.is_empty() {
                index.resolved_depends = Some(resolved_depends);
            }
            let result = match skip {
                Some(state) => {
                    let reason = unresolved_reasons.remove(&id).map(|v| v.join("\n"));
                    ScanResult::Skipped {
                        pkgpath,
                        state,
                        reason,
                        index: Some(index),
                    }
                }
                None => ScanResult::Buildable(ResolvedPackage { index, pkgpath }),
            };
            packages.push(result);
        }

        if count_filtered > 0 {
            debug!(
                count_filtered,
                "Filtered inactive packages (not needed for resolution)"
            );
        }

        for (pkgpath, error) in &self.scan_failures {
            packages.push(ScanResult::ScanFail {
                pkgpath: pkgpath.clone(),
                error: error.clone(),
            });
        }

        let pkgpaths = packages
            .iter()
            .map(|p| p.pkgpath())
            .collect::<HashSet<_>>()
            .len();
        let summary = ScanSummary { pkgpaths, packages };

        let c = summary.counts();
        info!(
            buildable = c.buildable,
            preskip = c.states[PackageState::PreSkipped],
            prefail = c.states[PackageState::PreFailed],
            unresolved = c.states[PackageState::Unresolved],
            "Resolution complete"
        );

        Ok(summary)
    }

    /**
     * Resolve dependencies and report results.
     *
     * Loads scan data from database, resolves dependencies, stores resolved
     * dependencies back to database, and reports any unresolved dependency
     * errors. Optionally bails if `strict` is true.
     */
    pub fn resolve_with_report(
        &mut self,
        db: &crate::db::Database,
        strict: bool,
    ) -> Result<ScanSummary> {
        crate::print_status("Resolving dependencies");
        let start = std::time::Instant::now();
        let mut result = db.with_scan_data(crate::db::ScanIndexFields::Resolve, |pull| {
            self.resolve(std::iter::from_fn(|| pull().transpose()))
        })?;
        /*
         * Release ALL_DEPENDS now that resolution is done; the DB
         * writers below only need the resolved names, and keeping
         * the pattern strings alive through the write phase
         * measurably raises peak memory on large trees.
         */
        for pkg in &mut result.packages {
            match pkg {
                ScanResult::Buildable(resolved) => {
                    resolved.index.all_depends = None;
                }
                ScanResult::Skipped { index, .. } => {
                    if let Some(idx) = index {
                        idx.all_depends = None;
                    }
                }
                ScanResult::ScanFail { .. } => {}
            }
        }
        db.store_resolution(&result)?;
        db.store_pbulk_weights()?;
        crate::print_elapsed("Resolving dependencies", start.elapsed());

        let errors: Vec<_> = result.errors().collect();
        if !errors.is_empty() {
            eprintln!("Scan/resolve errors:");
            for e in &errors {
                for line in e.lines() {
                    eprintln!("  {line}");
                }
            }
            if strict {
                bail!("Aborting due to scan/resolve errors (strict_scan enabled)");
            }
        }

        Ok(result)
    }
}
