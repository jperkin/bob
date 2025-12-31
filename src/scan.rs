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
//!
//! # Example
//!
//! ```no_run
//! use bob::{Config, RunContext, Scan};
//! use pkgsrc::PkgPath;
//! use std::sync::Arc;
//! use std::sync::atomic::AtomicBool;
//!
//! let config = Config::load(None, false)?;
//! let mut scan = Scan::new(&config);
//!
//! scan.add(&PkgPath::new("mail/mutt")?);
//! scan.add(&PkgPath::new("www/curl")?);
//!
//! let ctx = RunContext::new(Arc::new(AtomicBool::new(false)));
//! scan.start(&ctx)?;  // Discover dependencies
//! let result = scan.resolve()?;
//!
//! println!("Buildable: {}", result.buildable.len());
//! println!("Skipped: {}", result.skipped.len());
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::tui::MultiProgress;
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
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace};

/// Reason why a package was excluded from the build.
///
/// Packages with skip or fail reasons set in pkgsrc are not built.
#[derive(Clone, Debug)]
pub enum SkipReason {
    /// Package has `PKG_SKIP_REASON` set.
    ///
    /// This typically indicates the package cannot be built on the current
    /// platform (e.g., architecture-specific code, missing dependencies).
    PkgSkipReason(String),
    /// Package has `PKG_FAIL_REASON` set.
    ///
    /// This indicates the package is known to fail on the current platform
    /// and should not be attempted.
    PkgFailReason(String),
}

/// Information about a package that was skipped during scanning.
#[derive(Clone, Debug)]
pub struct SkippedPackage {
    /// Package name with version.
    pub pkgname: PkgName,
    /// Package path in pkgsrc.
    pub pkgpath: Option<PkgPath>,
    /// Reason the package was skipped.
    pub reason: SkipReason,
}

/// Information about a package that failed to scan.
#[derive(Clone, Debug)]
pub struct ScanFailure {
    /// Package path in pkgsrc (e.g., `games/plib`).
    pub pkgpath: PkgPath,
    /// Error message from the scan failure.
    pub error: String,
}

/// A resolved package index entry with dependency information.
///
/// This extends [`ScanIndex`] with resolved dependencies (`depends`).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ResolvedIndex {
    /// The underlying scan index data.
    pub index: ScanIndex,
    /// Resolved dependencies as package names.
    pub depends: Vec<PkgName>,
}

impl ResolvedIndex {
    /// Create from a ScanIndex with empty depends.
    pub fn from_scan_index(index: ScanIndex) -> Self {
        Self { index, depends: Vec::new() }
    }
}

impl std::ops::Deref for ResolvedIndex {
    type Target = ScanIndex;
    fn deref(&self) -> &Self::Target {
        &self.index
    }
}

impl std::ops::DerefMut for ResolvedIndex {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.index
    }
}

impl std::fmt::Display for ResolvedIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.index)?;
        write!(f, "DEPENDS=")?;
        for (i, d) in self.depends.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{d}")?;
        }
        writeln!(f)
    }
}

/// Result of scanning and resolving packages.
///
/// Returned by [`Scan::resolve`], contains the packages that can be built
/// and those that were skipped.
#[derive(Clone, Debug, Default)]
pub struct ScanResult {
    /// Packages that can be built, indexed by package name.
    ///
    /// These packages have all dependencies resolved and no skip/fail reasons.
    pub buildable: HashMap<PkgName, ResolvedIndex>,
    /// Packages that were skipped due to skip/fail reasons.
    pub skipped: Vec<SkippedPackage>,
    /// Packages that failed to scan (bmake pbulk-index failed).
    pub scan_failed: Vec<ScanFailure>,
}

impl ScanResult {
    /// Write resolved packages to a log file in pbulk presolve format.
    pub fn write_resolve_log(
        &self,
        path: &std::path::Path,
    ) -> anyhow::Result<()> {
        let mut out = String::new();

        // Sort by package name for deterministic output
        let mut pkgnames: Vec<_> = self.buildable.keys().collect();
        pkgnames.sort_by(|a, b| a.pkgname().cmp(b.pkgname()));

        for pkgname in pkgnames {
            let idx = &self.buildable[pkgname];
            out.push_str(&idx.to_string());
            out.push('\n');
        }

        // Output skipped packages
        for pkg in &self.skipped {
            out.push_str(&format!("PKGNAME={}\n", pkg.pkgname));
            if let Some(ref loc) = pkg.pkgpath {
                out.push_str(&format!(
                    "PKG_LOCATION={}\n",
                    loc.as_path().display()
                ));
            }
            match &pkg.reason {
                SkipReason::PkgSkipReason(r) => {
                    out.push_str(&format!("PKG_SKIP_REASON={}\n", r));
                }
                SkipReason::PkgFailReason(r) => {
                    out.push_str(&format!("PKG_FAIL_REASON={}\n", r));
                }
            }
            out.push('\n');
        }

        std::fs::write(path, &out)?;
        Ok(())
    }

    /// Write the resolved DAG as a sorted edge list for comparison.
    pub fn write_resolve_dag(
        &self,
        path: &std::path::Path,
    ) -> anyhow::Result<()> {
        let mut edges: Vec<String> = Vec::new();

        for (pkgname, idx) in &self.buildable {
            for dep in &idx.depends {
                edges.push(format!("{} -> {}", dep, pkgname));
            }
        }

        // Sort edges for deterministic output
        edges.sort();

        let out = edges.join("\n") + "\n";
        std::fs::write(path, &out)?;
        Ok(())
    }
}

/// Package dependency scanner.
///
/// Discovers all dependencies for a set of packages and resolves them into
/// a buildable set with proper ordering.
///
/// # Usage
///
/// 1. Create a `Scan` with [`Scan::new`]
/// 2. Add packages to scan with [`Scan::add`]
/// 3. Run the scan with [`Scan::start`]
/// 4. Resolve dependencies with [`Scan::resolve`]
///
/// # Example
///
/// ```no_run
/// # use bob::{Config, RunContext, Scan};
/// # use pkgsrc::PkgPath;
/// # use std::sync::Arc;
/// # use std::sync::atomic::AtomicBool;
/// # fn example() -> anyhow::Result<()> {
/// let config = Config::load(None, false)?;
/// let mut scan = Scan::new(&config);
///
/// scan.add(&PkgPath::new("mail/mutt")?);
/// let ctx = RunContext::new(Arc::new(AtomicBool::new(false)));
/// scan.start(&ctx)?;
///
/// let result = scan.resolve()?;
/// println!("Found {} buildable packages", result.buildable.len());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct Scan {
    config: Config,
    sandbox: Sandbox,
    incoming: HashSet<PkgPath>,
    done: IndexMap<PkgPath, Vec<ScanIndex>>,
    /// Full cache from database for on-demand loading of dependencies.
    cache: IndexMap<PkgPath, Vec<ScanIndex>>,
    resolved: HashMap<PkgName, ResolvedIndex>,
    /// Full tree scan - discover all packages, skip recursive dependency discovery.
    /// Defaults to true; set to false when packages are explicitly added.
    full_tree: bool,
    /// Packages that failed to scan (pkgpath, error message).
    scan_failures: Vec<(PkgPath, String)>,
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
            full_tree: true,
            ..Default::default()
        }
    }

    pub fn add(&mut self, pkgpath: &PkgPath) {
        info!(pkgpath = %pkgpath.as_path().display(), "Adding package to scan queue");
        self.full_tree = false;
        self.incoming.insert(pkgpath.clone());
    }

    /// Load previously cached scan results.
    ///
    /// For limited scans, only loads cached packages reachable from the
    /// configured pkgpaths initially, but keeps the full cache available
    /// for on-demand loading when new dependencies are discovered.
    ///
    /// Returns the number of cached packages initially loaded.
    pub fn load_cached(
        &mut self,
        cached: IndexMap<PkgPath, Vec<ScanIndex>>,
    ) -> usize {
        info!(cached_count = cached.len(), "Loading cached scan results");

        // Keep full cache for on-demand loading during scan
        self.cache = cached.clone();

        if self.full_tree {
            // For full tree scans, load everything
            self.done = cached;
        } else {
            // For limited scans, only load cached data reachable from incoming
            let mut relevant: HashSet<PkgPath> = self.incoming.clone();
            let mut to_process: Vec<PkgPath> =
                self.incoming.iter().cloned().collect();

            // Walk dependency tree to find all relevant pkgpaths
            while let Some(pkgpath) = to_process.pop() {
                if let Some(indexes) = cached.get(&pkgpath) {
                    for pkg in indexes {
                        if let Some(ref all_deps) = pkg.all_depends {
                            for dep in all_deps {
                                if relevant.insert(dep.pkgpath().clone()) {
                                    to_process.push(dep.pkgpath().clone());
                                }
                            }
                        }
                    }
                }
            }

            // Only load relevant cached data
            for (pkgpath, indexes) in cached {
                if relevant.contains(&pkgpath) {
                    self.done.insert(pkgpath, indexes);
                }
            }
        }

        // Rediscover dependencies that aren't cached
        for indexes in self.done.values() {
            for pkg in indexes {
                if let Some(ref all_deps) = pkg.all_depends {
                    for dep in all_deps {
                        if !self.done.contains_key(dep.pkgpath()) {
                            self.incoming.insert(dep.pkgpath().clone());
                        }
                    }
                }
            }
        }

        self.incoming.retain(|p| !self.done.contains_key(p));
        self.done.len()
    }

    /// Access completed scan results.
    pub fn completed(&self) -> &IndexMap<PkgPath, Vec<ScanIndex>> {
        &self.done
    }

    /// Recursively load a pkgpath and all its cached dependencies.
    /// Returns the count of packages loaded.
    fn load_cached_recursive(&mut self, pkgpath: PkgPath) -> usize {
        let mut count = 0;
        let mut to_load = vec![pkgpath];

        while let Some(path) = to_load.pop() {
            if self.done.contains_key(&path) {
                continue;
            }
            if let Some(indexes) = self.cache.get(&path).cloned() {
                // Discover dependencies before inserting
                for pkg in &indexes {
                    if let Some(ref all_deps) = pkg.all_depends {
                        for dep in all_deps {
                            if !self.done.contains_key(dep.pkgpath()) {
                                to_load.push(dep.pkgpath().clone());
                            }
                        }
                    }
                }
                self.done.insert(path, indexes);
                count += 1;
            }
        }

        count
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

    pub fn start(&mut self, ctx: &RunContext) -> anyhow::Result<bool> {
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
        let stats = ctx.stats.clone();

        /*
         * Only a single sandbox is required, 'make pbulk-index' can safely be
         * run in parallel inside one sandbox.
         */
        let script_envs = self.config.script_env();

        if self.sandbox.enabled() {
            println!("Creating sandbox...");
            if let Err(e) = self.sandbox.create(0) {
                if let Err(destroy_err) = self.sandbox.destroy(0) {
                    eprintln!(
                        "Warning: failed to destroy sandbox: {}",
                        destroy_err
                    );
                }
                return Err(e);
            }

            // Run pre-build script if defined
            if let Some(pre_build) = self.config.script("pre-build") {
                debug!("Running pre-build script");
                let child = self.sandbox.execute(
                    0,
                    pre_build,
                    script_envs.clone(),
                    None,
                    None,
                )?;
                let output = child
                    .wait_with_output()
                    .context("Failed to wait for pre-build")?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!(exit_code = ?output.status.code(), stderr = %stderr, "pre-build script failed");
                }
            }
        }

        // For full tree scans, discover all packages
        if self.full_tree && self.incoming.is_empty() {
            self.discover_packages()?;
            self.incoming.retain(|p| !self.done.contains_key(p));
        }

        // Nothing to scan - all packages are cached
        if self.incoming.is_empty() {
            if !self.done.is_empty() {
                println!(
                    "All {} package paths already scanned",
                    self.done.len()
                );
            }
            return Ok(false);
        }

        println!("Scanning packages...");

        // Set up multi-line progress display using ratatui inline viewport
        // Include cached packages in total so progress shows full picture
        let cached_count = self.done.len();
        let total_count = cached_count + self.incoming.len();
        let progress = Arc::new(Mutex::new(
            MultiProgress::new(
                "Scanning",
                "Scanned",
                total_count,
                self.config.scan_threads(),
            )
            .expect("Failed to initialize progress display"),
        ));

        // Mark cached packages
        if cached_count > 0 {
            if let Ok(mut p) = progress.lock() {
                p.state_mut().cached = cached_count;
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

        /*
         * Continuously iterate over incoming queue, moving to done once
         * processed, and adding any dependencies to incoming to be processed
         * next.
         */
        let mut interrupted = false;
        loop {
            // Check for shutdown signal
            if shutdown_flag.load(Ordering::Relaxed) {
                // Immediately show interrupted message
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
            let mut parpaths: Vec<(PkgPath, Result<Vec<ScanIndex>>)> = vec![];
            for pkgpath in &self.incoming {
                parpaths.push((pkgpath.clone(), Ok(vec![])));
            }

            let progress_clone = Arc::clone(&progress);
            let shutdown_clone = Arc::clone(&shutdown_flag);
            let stats_clone = stats.clone();
            pool.install(|| {
                parpaths.par_iter_mut().for_each(|pkg| {
                    // Check for shutdown before starting each package
                    if shutdown_clone.load(Ordering::Relaxed) {
                        return;
                    }

                    let (pkgpath, result) = pkg;
                    let pathname =
                        pkgpath.as_path().to_string_lossy().to_string();

                    // Get rayon thread index for progress tracking
                    let thread_id = rayon::current_thread_index().unwrap_or(0);

                    // Update progress - show current package for this thread
                    if let Ok(mut p) = progress_clone.lock() {
                        p.state_mut().set_worker_active(thread_id, &pathname);
                    }

                    let scan_start = Instant::now();
                    *result = self.scan_pkgpath(pkgpath);
                    let scan_duration = scan_start.elapsed();

                    // Record stats if enabled
                    if let Some(ref s) = stats_clone {
                        s.scan(&pathname, scan_duration, result.is_ok());
                    }

                    // Update counter immediately after each package
                    if let Ok(mut p) = progress_clone.lock() {
                        p.state_mut().set_worker_idle(thread_id);
                        if result.is_ok() {
                            p.state_mut().increment_completed();
                        } else {
                            p.state_mut().increment_failed();
                        }
                    }
                });
            });

            // Check if we were interrupted during parallel processing
            if shutdown_flag.load(Ordering::Relaxed) {
                // Immediately show interrupted message
                stop_refresh.store(true, Ordering::Relaxed);
                if let Ok(mut p) = progress.lock() {
                    let _ = p.finish_interrupted();
                }
                interrupted = true;
                break;
            }

            /*
             * Look through the results we just processed for any new PKGPATH
             * entries in DEPENDS that we have not seen before (neither in
             * done nor incoming).
             */
            let mut new_incoming: HashSet<PkgPath> = HashSet::new();
            let mut loaded_from_cache = 0usize;
            for (pkgpath, scanpkgs) in parpaths.drain(..) {
                let scanpkgs = match scanpkgs {
                    Ok(pkgs) => pkgs,
                    Err(e) => {
                        self.scan_failures
                            .push((pkgpath.clone(), format!("{}", e)));
                        self.done.insert(pkgpath.clone(), vec![]);
                        continue;
                    }
                };
                self.done.insert(pkgpath.clone(), scanpkgs.clone());
                // Discover dependencies not yet seen
                for pkg in scanpkgs {
                    if let Some(ref all_deps) = pkg.all_depends {
                        for dep in all_deps {
                            let dep_path = dep.pkgpath();
                            if self.done.contains_key(dep_path)
                                || self.incoming.contains(dep_path)
                                || new_incoming.contains(dep_path)
                            {
                                continue;
                            }
                            // Check cache first - load on-demand if available
                            if self.cache.contains_key(dep_path) {
                                loaded_from_cache += self
                                    .load_cached_recursive(dep_path.clone());
                            } else {
                                new_incoming.insert(dep_path.clone());
                                if let Ok(mut p) = progress.lock() {
                                    p.state_mut().total += 1;
                                }
                            }
                        }
                    }
                }
            }
            if loaded_from_cache > 0 {
                if let Ok(mut p) = progress.lock() {
                    p.state_mut().total += loaded_from_cache;
                    p.state_mut().cached += loaded_from_cache;
                }
            }

            /*
             * We're finished with the current incoming, replace it with the
             * new incoming list.  If it is empty then we've already processed
             * all known PKGPATHs and are done.
             */
            self.incoming = new_incoming;
            if self.incoming.is_empty() {
                break;
            }
        }

        // Stop the refresh thread and print final summary
        stop_refresh.store(true, Ordering::Relaxed);
        let _ = refresh_thread.join();

        // Only call finish() for normal completion; finish_interrupted()
        // was already called immediately when interrupt was detected
        if !interrupted {
            if let Ok(mut p) = progress.lock() {
                let _ = p.finish();
            }
        }

        if self.sandbox.enabled() {
            // Run post-build script if defined
            if let Some(post_build) = self.config.script("post-build") {
                debug!("Running post-build script");
                let child = self.sandbox.execute(
                    0,
                    post_build,
                    script_envs,
                    None,
                    None,
                )?;
                let output = child
                    .wait_with_output()
                    .context("Failed to wait for post-build")?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!(exit_code = ?output.status.code(), stderr = %stderr, "post-build script failed");
                }
            }

            self.sandbox.destroy(0)?;
        }

        if interrupted {
            return Ok(true);
        }

        Ok(false)
    }

    /// Returns scan failures as formatted error strings.
    pub fn scan_errors(&self) -> Vec<String> {
        self.scan_failures.iter().map(|(_, e)| e.clone()).collect()
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
        let pkgpath_str = pkgpath.as_path().display().to_string();
        debug!(pkgpath = %pkgpath_str, "Scanning package");

        let bmake = self.config.make().display().to_string();
        let pkgsrcdir = self.config.pkgsrc().display().to_string();
        let script = format!(
            "cd {}/{} && {} pbulk-index\n",
            pkgsrcdir, pkgpath_str, bmake
        );

        let scan_env = self.config.scan_env();
        trace!(pkgpath = %pkgpath_str,
            script = %script,
            scan_env = ?scan_env,
            "Executing pkg-scan"
        );
        let child = self.sandbox.execute_script(0, &script, scan_env)?;
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
        let mut index: Vec<ScanIndex> =
            ScanIndex::from_reader(reader).collect::<Result<_, _>>()?;

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

    /// Get all scanned packages (before resolution).
    pub fn scanned(&self) -> impl Iterator<Item = &ScanIndex> {
        self.done.values().flatten()
    }

    /// Write scan output to a file in FOO=bar format.
    pub fn write_log(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let mut out = String::new();
        for idx in self.scanned() {
            out.push_str(&idx.to_string());
            out.push('\n');
        }
        std::fs::write(path, &out)?;
        Ok(())
    }

    /**
     * Resolve the list of scanned packages, by ensuring all of the [`Depend`]
     * patterns in `all_depends` match a found package, and that there are no
     * circular dependencies.  The best match for each is stored in the
     * `depends` for the package in question.
     *
     * Return a [`ScanResult`] containing buildable packages and skipped packages.
     */
    pub fn resolve(&mut self) -> Result<ScanResult> {
        info!(
            done_pkgpaths = self.done.len(),
            "Starting dependency resolution"
        );

        /*
         * Populate the resolved hash.  This becomes our new working set,
         * with a flat mapping of PKGNAME -> ScanIndex.
         *
         * self.done must no longer be used after this point, as its ScanIndex
         * entries are out of date (do not have depends set, for example).
         * Maybe at some point we'll handle lifetimes properly and just have
         * one canonical index.
         *
         * Also create a simple HashSet for looking up known PKGNAME for
         * matches.
         */
        let mut pkgnames: HashSet<PkgName> = HashSet::new();
        let mut skipped: Vec<SkippedPackage> = Vec::new();

        // Log what we have in self.done
        for (pkgpath, index) in &self.done {
            debug!(pkgpath = %pkgpath.as_path().display(),
                packages_in_index = index.len(),
                "Processing done entry"
            );
        }

        for index in self.done.values() {
            for pkg in index {
                // Check for skip/fail reasons
                if let Some(reason) = &pkg.pkg_skip_reason {
                    if !reason.is_empty() {
                        info!(pkgname = %pkg.pkgname.pkgname(),
                            reason = %reason,
                            "Skipping package due to PKG_SKIP_REASON"
                        );
                        skipped.push(SkippedPackage {
                            pkgname: pkg.pkgname.clone(),
                            pkgpath: pkg.pkg_location.clone(),
                            reason: SkipReason::PkgSkipReason(reason.clone()),
                        });
                        continue;
                    }
                }
                if let Some(reason) = &pkg.pkg_fail_reason {
                    if !reason.is_empty() {
                        info!(pkgname = %pkg.pkgname.pkgname(),
                            reason = %reason,
                            "Skipping package due to PKG_FAIL_REASON"
                        );
                        skipped.push(SkippedPackage {
                            pkgname: pkg.pkgname.clone(),
                            pkgpath: pkg.pkg_location.clone(),
                            reason: SkipReason::PkgFailReason(reason.clone()),
                        });
                        continue;
                    }
                }

                // Skip duplicate PKGNAMEs - keep only the first (preferred)
                // variant for multi-version packages.
                if pkgnames.contains(&pkg.pkgname) {
                    debug!(pkgname = %pkg.pkgname.pkgname(),
                        multi_version = ?pkg.multi_version,
                        "Skipping duplicate PKGNAME"
                    );
                    continue;
                }

                debug!(pkgname = %pkg.pkgname.pkgname(),
                    "Adding package to resolved set"
                );
                pkgnames.insert(pkg.pkgname.clone());
                self.resolved.insert(
                    pkg.pkgname.clone(),
                    ResolvedIndex::from_scan_index(pkg.clone()),
                );
            }
        }

        info!(
            resolved_count = self.resolved.len(),
            skipped_count = skipped.len(),
            "Initial resolution complete"
        );

        /*
         * Build a set of skipped package names for checking if unresolved
         * dependencies are due to skipped packages vs truly missing.
         */
        let skipped_pkgnames: HashSet<PkgName> =
            skipped.iter().map(|s| s.pkgname.clone()).collect();

        /*
         * Keep a cache of best Depend => PkgName matches we've already seen
         * as it's likely the same patterns will be used in multiple places.
         */
        let mut match_cache: HashMap<Depend, PkgName> = HashMap::new();

        /*
         * Track packages to skip due to skipped dependencies, and truly
         * unresolved dependencies (errors).
         */
        let mut skip_due_to_dep: HashMap<PkgName, String> = HashMap::new();
        let mut errors: Vec<String> = Vec::new();

        for pkg in self.resolved.values_mut() {
            let all_deps = match pkg.all_depends.clone() {
                Some(deps) => deps,
                None => continue,
            };
            for depend in &all_deps {
                /*
                 * Check for cached DEPENDS match first.  If found, use it.
                 */
                if let Some(pkgname) = match_cache.get(depend) {
                    pkg.depends.push(pkgname.clone());
                    continue;
                }
                /*
                 * Find best DEPENDS match out of all known PKGNAME.
                 */
                let mut best: Option<&PkgName> = None;
                for candidate in &pkgnames {
                    if depend.pattern().matches(candidate.pkgname()) {
                        if let Some(current) = best {
                            best = match depend.pattern().best_match(
                                current.pkgname(),
                                candidate.pkgname(),
                            ) {
                                Ok(Some(m)) if m == current.pkgname() => {
                                    Some(current)
                                }
                                Ok(Some(m)) if m == candidate.pkgname() => {
                                    Some(candidate)
                                }
                                Ok(Some(_)) => todo!(),
                                Ok(None) | Err(_) => None,
                            };
                        } else {
                            best = Some(candidate);
                        }
                    }
                }
                /*
                 * If we found a match, save it and add to the cache.
                 * Otherwise check if the dependency matches a skipped package.
                 */
                if let Some(pkgname) = best {
                    pkg.depends.push(pkgname.clone());
                    match_cache.insert(depend.clone(), pkgname.clone());
                } else {
                    // Check if the dependency matches a skipped package
                    let mut matched_skipped: Option<&PkgName> = None;
                    for candidate in &skipped_pkgnames {
                        if depend.pattern().matches(candidate.pkgname()) {
                            matched_skipped = Some(candidate);
                            break;
                        }
                    }

                    if let Some(skipped_dep) = matched_skipped {
                        // Dependency is skipped, so this package should be too
                        skip_due_to_dep.insert(
                            pkg.index.pkgname.clone(),
                            format!(
                                "Dependency {} skipped",
                                skipped_dep.pkgname()
                            ),
                        );
                    } else {
                        // Truly unresolved - no matching package exists
                        errors.push(format!(
                            "No match found for {} in {}",
                            depend.pattern().pattern(),
                            pkg.index.pkgname.pkgname()
                        ));
                    }
                }
            }
        }

        /*
         * Iteratively propagate skips: if A depends on B, and B is now
         * marked to skip, then A should also be skipped.
         */
        loop {
            let mut new_skips: HashMap<PkgName, String> = HashMap::new();

            for pkg in self.resolved.values() {
                if skip_due_to_dep.contains_key(&pkg.pkgname) {
                    continue;
                }
                for dep in &pkg.depends {
                    if skip_due_to_dep.contains_key(dep) {
                        // Our dependency is being skipped
                        new_skips.insert(
                            pkg.pkgname.clone(),
                            format!("Dependency {} skipped", dep.pkgname()),
                        );
                        break;
                    }
                }
            }

            if new_skips.is_empty() {
                break;
            }
            skip_due_to_dep.extend(new_skips);
        }

        /*
         * Move packages with skipped dependencies from resolved to skipped.
         */
        for (pkgname, reason) in &skip_due_to_dep {
            if let Some(pkg) = self.resolved.remove(pkgname) {
                skipped.push(SkippedPackage {
                    pkgname: pkg.pkgname.clone(),
                    pkgpath: pkg.pkg_location.clone(),
                    reason: SkipReason::PkgSkipReason(reason.clone()),
                });
            }
        }

        /*
         * Filter out errors for packages that are being skipped anyway.
         * If a package has both a skipped dependency and a missing dependency,
         * we only care about the skip - the missing dep error is noise.
         */
        let errors: Vec<String> = errors
            .into_iter()
            .filter(|err| {
                // Error format is "No match found for X in PKGNAME"
                // Extract PKGNAME and check if it's being skipped
                if let Some(pkgname_str) = err.split(" in ").last() {
                    !skip_due_to_dep.keys().any(|k| k.pkgname() == pkgname_str)
                } else {
                    true // Keep error if we can't parse it
                }
            })
            .collect();

        /*
         * Verify that the graph is acyclic.
         */
        debug!(
            resolved_count = self.resolved.len(),
            "Checking for circular dependencies"
        );
        let mut graph = DiGraphMap::new();
        for (pkgname, index) in &self.resolved {
            for dep in &index.depends {
                graph.add_edge(dep.pkgname(), pkgname.pkgname(), ());
            }
        }
        let cycle_error = find_cycle(&graph).map(|cycle| {
            let mut err = "Circular dependencies detected:\n".to_string();
            for n in cycle.iter().rev() {
                err.push_str(&format!("\t{}\n", n));
            }
            err.push_str(&format!("\t{}", cycle.last().unwrap()));
            error!(cycle = ?cycle, "Circular dependency detected");
            err
        });

        info!(
            buildable_count = self.resolved.len(),
            skipped_count = skipped.len(),
            "Resolution complete"
        );

        // Log all buildable packages
        for pkgname in self.resolved.keys() {
            debug!(pkgname = %pkgname.pkgname(), "Package is buildable");
        }

        // Convert scan failures to ScanFailure structs
        let scan_failed: Vec<ScanFailure> = self
            .scan_failures
            .iter()
            .map(|(pkgpath, error)| ScanFailure {
                pkgpath: pkgpath.clone(),
                error: error.clone(),
            })
            .collect();

        let result = ScanResult {
            buildable: self.resolved.clone(),
            skipped,
            scan_failed,
        };

        // Now check for errors
        if !errors.is_empty() {
            for err in &errors {
                error!(error = %err, "Unresolved dependency");
            }
            bail!("Unresolved dependencies:\n  {}", errors.join("\n  "));
        }

        if let Some(err) = cycle_error {
            bail!(err);
        }

        Ok(result)
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
        let cycle = dfs(graph, node, &mut visited, &mut stack, &mut in_stack);
        if cycle.is_some() {
            return cycle;
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
