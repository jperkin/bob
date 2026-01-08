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
//! use bob::{Config, Database, RunContext, Scan};
//! use pkgsrc::PkgPath;
//! use std::sync::Arc;
//! use std::sync::atomic::AtomicBool;
//!
//! let config = Config::load(None, false)?;
//! let db_path = config.logdir().join("bob").join("bob.db");
//! let db = Database::open(&db_path)?;
//! let mut scan = Scan::new(&config);
//!
//! scan.add(&PkgPath::new("mail/mutt")?);
//! scan.add(&PkgPath::new("www/curl")?);
//!
//! let ctx = RunContext::new(Arc::new(AtomicBool::new(false)));
//! scan.start(&ctx, &db)?;  // Discover dependencies
//! let result = scan.resolve(&db)?;
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
use std::time::Duration;
use tracing::{debug, error, info, trace};

/// Reason why a package was excluded from the build.
///
/// Packages with skip or fail reasons set in pkgsrc are not built.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    /// A dependency could not be resolved to any known package.
    ///
    /// Contains the dependency pattern that could not be matched.
    UnresolvedDependency(String),
}

/// Information about a package that was skipped during scanning.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SkippedPackage {
    /// Package name with version.
    pub pkgname: PkgName,
    /// Package path in pkgsrc.
    pub pkgpath: Option<PkgPath>,
    /// Reason the package was skipped.
    pub reason: SkipReason,
}

/// Information about a package that failed to scan.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    /// True if this package has an unresolved dependency.
    #[serde(default)]
    pub has_unresolved_dep: bool,
}

impl ResolvedIndex {
    /// Create from a ScanIndex with empty depends.
    pub fn from_scan_index(index: ScanIndex) -> Self {
        Self { index, depends: Vec::new(), has_unresolved_dep: false }
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
        // Only output DEPENDS= if there are dependencies and no unresolved deps.
        if !self.depends.is_empty() && !self.has_unresolved_dep {
            write!(f, "DEPENDS=")?;
            for (i, d) in self.depends.iter().enumerate() {
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

/// Result of scanning and resolving packages.
///
/// Returned by [`Scan::resolve`], contains the packages that can be built
/// and those that were skipped.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    /// Packages that can be built, indexed by package name.
    ///
    /// These packages have all dependencies resolved and no skip/fail reasons.
    /// Uses IndexMap to preserve insertion order from the original scan.
    pub buildable: IndexMap<PkgName, ResolvedIndex>,
    /// Packages that were skipped due to skip/fail reasons.
    pub skipped: Vec<SkippedPackage>,
    /// Packages that failed to scan (bmake pbulk-index failed).
    pub scan_failed: Vec<ScanFailure>,
    /// All packages in original order with their skip reason (if any).
    /// Used for presolve output that needs to preserve original ordering.
    pub all_ordered: Vec<(ResolvedIndex, Option<SkipReason>)>,
    /// Unresolved dependency errors.
    /// Callers can check this and config.strict_scan() to decide if fatal.
    pub errors: Vec<String>,
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
/// # use bob::{Config, Database, RunContext, Scan};
/// # use pkgsrc::PkgPath;
/// # use std::sync::Arc;
/// # use std::sync::atomic::AtomicBool;
/// # fn example() -> anyhow::Result<()> {
/// let config = Config::load(None, false)?;
/// let db_path = config.logdir().join("bob").join("bob.db");
/// let db = Database::open(&db_path)?;
/// let mut scan = Scan::new(&config);
///
/// scan.add(&PkgPath::new("mail/mutt")?);
/// let ctx = RunContext::new(Arc::new(AtomicBool::new(false)));
/// scan.start(&ctx, &db)?;
///
/// let result = scan.resolve(&db)?;
/// println!("Found {} buildable packages", result.buildable.len());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct Scan {
    config: Config,
    sandbox: Sandbox,
    incoming: HashSet<PkgPath>,
    /// Pkgpaths we've completed scanning (in this session).
    done: HashSet<PkgPath>,
    resolved: IndexMap<PkgName, ResolvedIndex>,
    /// Full tree scan - discover all packages, skip recursive dependency discovery.
    /// Defaults to true; set to false when packages are explicitly added.
    full_tree: bool,
    /// A previous full tree scan completed successfully.
    full_scan_complete: bool,
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

        /*
         * Only a single sandbox is required, 'make pbulk-index' can safely be
         * run in parallel inside one sandbox.
         */
        let script_envs = self.config.script_env();

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
                self.cleanup_sandbox(script_envs)?;
            }

            return Ok(false);
        }

        // Clear resolved dependencies since we're scanning new packages
        db.clear_resolved_depends()?;

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

            std::thread::scope(|s| {
                // Spawn scanning thread
                let progress_clone = Arc::clone(&progress);
                let shutdown_clone = Arc::clone(&shutdown_flag);
                let pool_ref = &pool;

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

                            let result = Self::scan_pkgpath_with(
                                config, sandbox, pkgpath,
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
                });

                // Check if we were interrupted during parallel processing
                let was_interrupted = shutdown_flag.load(Ordering::Relaxed);

                /*
                 * Process results - write to DB and extract dependencies.
                 */
                for (pkgpath, result) in rx {
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

                    // Save to database
                    if !scanpkgs.is_empty() {
                        if let Err(e) = db
                            .store_scan_pkgpath(&pkgpath.to_string(), &scanpkgs)
                        {
                            error!(error = %e, "Failed to store scan results");
                        }
                    }

                    // Skip dependency discovery for full tree scans (all
                    // packages already discovered) or if interrupted
                    if self.full_tree || was_interrupted {
                        continue;
                    }

                    // Discover dependencies not yet seen
                    for pkg in &scanpkgs {
                        if let Some(ref all_deps) = pkg.all_depends {
                            for dep in all_deps {
                                let dep_path = dep.pkgpath();
                                if self.done.contains(dep_path)
                                    || new_incoming.contains(dep_path)
                                {
                                    continue;
                                }
                                // Check database for cached dependency
                                match db
                                    .is_pkgpath_scanned(&dep_path.to_string())
                                {
                                    Ok(true) => {
                                        self.done.insert(dep_path.clone());
                                        if let Ok(mut p) = progress.lock() {
                                            p.state_mut().total += 1;
                                            p.state_mut().cached += 1;
                                        }
                                    }
                                    Ok(false) => {
                                        new_incoming.insert(dep_path.clone());
                                        if let Ok(mut p) = progress.lock() {
                                            p.state_mut().total += 1;
                                        }
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                    }
                }
            });

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
             */
            self.incoming = new_incoming;
        }

        // Commit transaction (partial on interrupt, full on success)
        db.commit()?;

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
            self.cleanup_sandbox(script_envs)?;
        }

        if interrupted {
            return Ok(true);
        }

        Ok(false)
    }

    /// Run post-build cleanup and destroy the scan sandbox.
    fn cleanup_sandbox(
        &self,
        envs: Vec<(String, String)>,
    ) -> anyhow::Result<()> {
        if let Some(post_build) = self.config.script("post-build") {
            debug!("Running post-build script");
            let child =
                self.sandbox.execute(0, post_build, envs, None, None)?;
            let output = child
                .wait_with_output()
                .context("Failed to wait for post-build")?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error!(exit_code = ?output.status.code(), stderr = %stderr, "post-build script failed");
            }
        }
        self.sandbox.destroy(0)
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

        let bmake = config.make().display().to_string();
        let pkgsrcdir = config.pkgsrc().display().to_string();
        let script = format!(
            "cd {}/{} && {} pbulk-index\n",
            pkgsrcdir, pkgpath_str, bmake
        );

        let scan_env = config.scan_env();
        trace!(pkgpath = %pkgpath_str,
            script = %script,
            scan_env = ?scan_env,
            "Executing pkg-scan"
        );
        let child = sandbox.execute_script(0, &script, scan_env)?;
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

    /**
     * Resolve the list of scanned packages, by ensuring all of the [`Depend`]
     * patterns in `all_depends` match a found package, and that there are no
     * circular dependencies.  The best match for each is stored in the
     * `depends` for the package in question.
     *
     * Return a [`ScanResult`] containing buildable packages and skipped packages.
     *
     * Also stores resolved dependencies in the database for fast reverse lookups.
     */
    pub fn resolve(&mut self, db: &crate::db::Database) -> Result<ScanResult> {
        info!(
            done_pkgpaths = self.done.len(),
            "Starting dependency resolution"
        );

        // Load all scan data in one query
        let all_scan_data = db.get_all_scan_indexes()?;

        /*
         * Populate the resolved hash with ALL packages first, including those
         * with skip/fail reasons. This allows us to resolve dependencies for
         * all packages before separating them.
         */
        let mut pkgnames: indexmap::IndexSet<PkgName> =
            indexmap::IndexSet::new();

        // Track which packages have skip/fail reasons
        let mut skip_reasons: HashMap<PkgName, SkipReason> = HashMap::new();

        // Track package_id for storing resolved dependencies
        let mut pkgname_to_id: HashMap<PkgName, i64> = HashMap::new();

        // Process all scan data, consuming to avoid clones
        for (pkg_id, pkg) in all_scan_data {
            debug!(pkgpath = ?pkg.pkg_location,
                pkgname = %pkg.pkgname.pkgname(),
                "Processing package"
            );

            // Skip duplicate PKGNAMEs - keep only the first (preferred)
            // variant for multi-version packages.
            if pkgnames.contains(&pkg.pkgname) {
                debug!(pkgname = %pkg.pkgname.pkgname(),
                    multi_version = ?pkg.multi_version,
                    "Skipping duplicate PKGNAME"
                );
                continue;
            }

            // Track skip/fail reasons but still add to resolved
            if let Some(reason) = &pkg.pkg_skip_reason {
                if !reason.is_empty() {
                    info!(pkgname = %pkg.pkgname.pkgname(),
                        reason = %reason,
                        "Package has PKG_SKIP_REASON"
                    );
                    skip_reasons.insert(
                        pkg.pkgname.clone(),
                        SkipReason::PkgSkipReason(reason.clone()),
                    );
                }
            }
            if let Some(reason) = &pkg.pkg_fail_reason {
                if !reason.is_empty()
                    && !skip_reasons.contains_key(&pkg.pkgname)
                {
                    info!(pkgname = %pkg.pkgname.pkgname(),
                        reason = %reason,
                        "Package has PKG_FAIL_REASON"
                    );
                    skip_reasons.insert(
                        pkg.pkgname.clone(),
                        SkipReason::PkgFailReason(reason.clone()),
                    );
                }
            }

            pkgname_to_id.insert(pkg.pkgname.clone(), pkg_id);
            debug!(pkgname = %pkg.pkgname.pkgname(),
                "Adding package to resolved set"
            );
            pkgnames.insert(pkg.pkgname.clone());
            self.resolved.insert(
                pkg.pkgname.clone(),
                ResolvedIndex::from_scan_index(pkg),
            );
        }

        info!(
            resolved_count = self.resolved.len(),
            skip_reasons_count = skip_reasons.len(),
            "Initial resolution complete"
        );

        /*
         * Build a hashmap of pkgbase -> Vec<&PkgName> for efficient lookups.
         * For Dewey patterns with a known pkgbase, we can directly look up
         * candidates instead of iterating through all packages.
         */
        let pkgbase_map: HashMap<&str, Vec<&PkgName>> = {
            let mut map: HashMap<&str, Vec<&PkgName>> = HashMap::new();
            for pkgname in &pkgnames {
                map.entry(pkgname.pkgbase()).or_default().push(pkgname);
            }
            map
        };

        /*
         * Keep a cache of best Depend => PkgName matches we've already seen
         * as it's likely the same patterns will be used in multiple places.
         */
        let mut match_cache: HashMap<Depend, PkgName> = HashMap::new();

        /*
         * Track packages to skip due to skipped dependencies, and
         * unresolved dependency errors (callers decide if these are fatal).
         */
        let mut skip_due_to_dep: HashMap<PkgName, String> = HashMap::new();
        let mut errors: Vec<String> = Vec::new();

        // Helper to check if a dependency pattern is already satisfied
        let is_satisfied = |depends: &[PkgName], pattern: &pkgsrc::Pattern| {
            depends.iter().any(|existing| pattern.matches(existing.pkgname()))
        };

        for pkg in self.resolved.values_mut() {
            let all_deps = match pkg.all_depends.take() {
                Some(deps) => deps,
                None => continue,
            };
            for depend in all_deps.iter() {
                // Check for cached DEPENDS match first. If found, use it
                // (but only add if the pattern isn't already satisfied).
                if let Some(pkgname) = match_cache.get(depend) {
                    if !is_satisfied(&pkg.depends, depend.pattern())
                        && !pkg.depends.contains(pkgname)
                    {
                        pkg.depends.push(pkgname.clone());
                    }
                    continue;
                }
                /*
                 * Find best DEPENDS match out of all known PKGNAME.
                 * Collect all candidates that match the pattern.
                 *
                 * Use pkgbase hashmap for efficient lookups when pattern
                 * has a known pkgbase, otherwise fall back to full scan.
                 */
                let candidates: Vec<&PkgName> = if let Some(base) =
                    depend.pattern().pkgbase()
                {
                    match pkgbase_map.get(base) {
                        Some(v) => v
                            .iter()
                            .filter(|c| depend.pattern().matches(c.pkgname()))
                            .copied()
                            .collect(),
                        None => Vec::new(),
                    }
                } else {
                    pkgnames
                        .iter()
                        .filter(|c| depend.pattern().matches(c.pkgname()))
                        .collect()
                };

                // Find best match among all candidates using pbulk algorithm:
                // higher version wins, larger name on tie.
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
                        "pattern error for {}: {}",
                        depend.pattern().pattern(),
                        e
                    );
                    errors.push(format!(
                        "{} in {}",
                        reason,
                        pkg.pkgname.pkgname()
                    ));
                    if !skip_reasons.contains_key(&pkg.pkgname) {
                        pkg.pkg_fail_reason = Some(format!("\"{}\"", reason));
                        skip_reasons.insert(
                            pkg.pkgname.clone(),
                            SkipReason::PkgFailReason(reason),
                        );
                    }
                    continue;
                }
                // If found, save to cache and add to depends (if not already satisfied)
                if let Some(pkgname) = best {
                    if !is_satisfied(&pkg.depends, depend.pattern())
                        && !pkg.depends.contains(pkgname)
                    {
                        pkg.depends.push(pkgname.clone());
                    }
                    match_cache.insert(depend.clone(), pkgname.clone());
                } else {
                    // No matching package exists
                    let pattern = depend.pattern().pattern().to_string();
                    pkg.has_unresolved_dep = true;
                    errors.push(format!(
                        "No match found for {} in {}",
                        pattern,
                        pkg.pkgname.pkgname()
                    ));
                    if !skip_reasons.contains_key(&pkg.pkgname) {
                        let reason = format!(
                            "could not resolve dependency \"{}\"",
                            pattern
                        );
                        pkg.pkg_fail_reason = Some(format!("\"{}\"", reason));
                        skip_reasons.insert(
                            pkg.pkgname.clone(),
                            SkipReason::UnresolvedDependency(pattern),
                        );
                    }
                }
            }
            // Restore all_depends for output formatting
            pkg.all_depends = Some(all_deps);
        }

        /*
         * Iteratively propagate skips: if A depends on B, and B is now
         * marked to skip, then A should also be skipped.
         */
        loop {
            let mut new_skips: HashMap<PkgName, String> = HashMap::new();

            for pkg in self.resolved.values() {
                if skip_due_to_dep.contains_key(&pkg.pkgname)
                    || skip_reasons.contains_key(&pkg.pkgname)
                {
                    continue;
                }
                for dep in &pkg.depends {
                    if skip_due_to_dep.contains_key(dep)
                        || skip_reasons.contains_key(dep)
                    {
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

        // Merge skip_due_to_dep into skip_reasons
        for (pkgname, reason) in skip_due_to_dep.iter() {
            if !skip_reasons.contains_key(pkgname) {
                skip_reasons.insert(
                    pkgname.clone(),
                    SkipReason::PkgSkipReason(reason.clone()),
                );
            }
        }

        // Build all_ordered first to preserve original order, then separate
        let mut all_ordered: Vec<(ResolvedIndex, Option<SkipReason>)> =
            Vec::new();
        let mut buildable: IndexMap<PkgName, ResolvedIndex> = IndexMap::new();
        let mut skipped: Vec<SkippedPackage> = Vec::new();

        for (pkgname, index) in std::mem::take(&mut self.resolved) {
            let reason = skip_reasons.remove(&pkgname);
            if let Some(r) = reason {
                // Skipped: extract metadata, then move index to all_ordered
                skipped.push(SkippedPackage {
                    pkgname: index.pkgname.clone(),
                    pkgpath: index.pkg_location.clone(),
                    reason: r.clone(),
                });
                all_ordered.push((index, Some(r)));
            } else {
                // Buildable: clone for all_ordered, move to buildable
                all_ordered.push((index.clone(), None));
                buildable.insert(pkgname, index);
            }
        }

        /*
         * Verify that the graph is acyclic (only for buildable packages).
         */
        debug!(
            buildable_count = buildable.len(),
            "Checking for circular dependencies"
        );
        let mut graph = DiGraphMap::new();
        for (pkgname, index) in &buildable {
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
            buildable_count = buildable.len(),
            skipped_count = skipped.len(),
            "Resolution complete"
        );

        // Log all buildable packages
        for pkgname in buildable.keys() {
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

        // Log errors but don't bail - let callers decide how to handle them
        for err in &errors {
            error!(error = %err, "Unresolved dependency");
        }

        let result =
            ScanResult { buildable, skipped, scan_failed, all_ordered, errors };

        if let Some(err) = cycle_error {
            bail!(err);
        }

        // Store resolved dependencies in database for fast reverse lookups
        let mut resolved_deps: Vec<(i64, i64)> = Vec::new();
        for (pkgname, index) in &result.buildable {
            if let Some(&pkg_id) = pkgname_to_id.get(pkgname) {
                for dep in &index.depends {
                    if let Some(&dep_id) = pkgname_to_id.get(dep) {
                        resolved_deps.push((pkg_id, dep_id));
                    }
                }
            }
        }
        if !resolved_deps.is_empty() {
            db.store_resolved_dependencies_batch(&resolved_deps)?;
            debug!(count = resolved_deps.len(), "Stored resolved dependencies");
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
