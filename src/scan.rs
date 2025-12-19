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

use crate::tui::MultiProgress;
use crate::{Config, Sandbox};
use anyhow::{bail, Context, Result};
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
#[derive(Clone, Debug)]
pub enum SkipReason {
    /// Package has PKG_SKIP_REASON set.
    PkgSkipReason(String),
    /// Package has PKG_FAIL_REASON set.
    PkgFailReason(String),
}

/// Information about a skipped package.
#[derive(Clone, Debug)]
pub struct SkippedPackage {
    pub pkgname: PkgName,
    pub pkgpath: Option<PkgPath>,
    pub reason: SkipReason,
}

/// Result of scanning and resolving packages.
#[derive(Clone, Debug, Default)]
pub struct ScanResult {
    /// Packages that can be built.
    pub buildable: HashMap<PkgName, ScanIndex>,
    /// Packages that were skipped.
    pub skipped: Vec<SkippedPackage>,
}

#[derive(Debug, Default)]
pub struct Scan {
    /**
     * Parsed [`Config`].
     */
    config: Config,
    /**
     * [`Sandbox`] configuration.
     */
    sandbox: Sandbox,
    /**
     * Incoming queue of PKGPATH to process.
     */
    incoming: HashSet<PkgPath>,
    /**
     * Completed PKGPATH scans.  With MULTI_VERSION there may be multiple
     * packages produced by a single PKGPATH (e.g. py*-foo), hence why there
     * is a [`Vec`] of [`ScanIndex`]s.
     */
    done: HashMap<PkgPath, Vec<ScanIndex>>,
    /**
     * Resolved packages, indexed by PKGNAME.
     */
    resolved: HashMap<PkgName, ScanIndex>,
}

impl Scan {
    pub fn new(config: &Config) -> Scan {
        let sandbox = Sandbox::new(config);
        debug!(
            pkgsrc = %config.pkgsrc().display(),
            make = %config.make().display(),
            scan_threads = config.scan_threads(),
            "Created new Scan instance"
        );
        Scan { config: config.clone(), sandbox, ..Default::default() }
    }

    pub fn add(&mut self, pkgpath: &PkgPath) {
        info!(pkgpath = %pkgpath.as_path().display(), "Adding package to scan queue");
        self.incoming.insert(pkgpath.clone());
    }

    pub fn start(&mut self) -> anyhow::Result<()> {
        info!(
            incoming_count = self.incoming.len(),
            sandbox_enabled = self.sandbox.enabled(),
            "Starting package scan"
        );

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.config.scan_threads())
            .build()
            .context("Failed to build scan thread pool")?;

        /*
         * Only a single sandbox is required, 'make pbulk-index' can safely be
         * run in parallel inside one sandbox.
         */
        let script_envs = self.config.script_env();

        if self.sandbox.enabled() {
            println!("Creating sandbox...");
            if let Err(e) = self.sandbox.create(0) {
                eprintln!("Failed to create sandbox: {}", e);
                if let Err(destroy_err) = self.sandbox.destroy(0) {
                    eprintln!("Warning: failed to destroy sandbox: {}", destroy_err);
                }
                return Err(e);
            }

            // Run pre-build script if defined
            if let Some(pre_build) = self.config.script("pre-build") {
                debug!("Running pre-build script");
                let child = self.sandbox.execute(0, pre_build, script_envs.clone(), None, None)?;
                let output = child.wait_with_output().context("Failed to wait for pre-build")?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!(exit_code = ?output.status.code(), stderr = %stderr, "pre-build script failed");
                }
            }
        }

        // Set up multi-line progress display using ratatui inline viewport
        let progress = Arc::new(Mutex::new(
            MultiProgress::new("Scanning", "Scanned", self.incoming.len(), self.config.scan_threads(), false)
                .expect("Failed to initialize progress display"),
        ));

        // Flag to stop the refresh thread
        let stop_refresh = Arc::new(AtomicBool::new(false));

        // Spawn a thread to periodically refresh the display (for timer updates)
        let progress_refresh = Arc::clone(&progress);
        let stop_flag = Arc::clone(&stop_refresh);
        let refresh_thread = std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                if let Ok(mut p) = progress_refresh.lock() {
                    let _ = p.render();
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });

        /*
         * Continuously iterate over incoming queue, moving to done once
         * processed, and adding any dependencies to incoming to be processed
         * next.
         */
        loop {
            /*
             * Convert the incoming HashSet into a Vec for parallel processing.
             */
            let mut parpaths: Vec<(PkgPath, Result<Vec<ScanIndex>>)> = vec![];
            for pkgpath in &self.incoming {
                parpaths.push((pkgpath.clone(), Ok(vec![])));
            }

            let progress_clone = Arc::clone(&progress);
            pool.install(|| {
                parpaths.par_iter_mut().for_each(|pkg| {
                    let (pkgpath, result) = pkg;
                    let pathname = pkgpath.as_path().to_string_lossy().to_string();

                    // Get rayon thread index for progress tracking
                    let thread_id = rayon::current_thread_index().unwrap_or(0);

                    // Update progress - show current package for this thread
                    if let Ok(mut p) = progress_clone.lock() {
                        p.state_mut().set_worker_active(thread_id, &pathname);
                    }

                    *result = self
                        .scan_pkgpath(pkgpath)
                        .context(format!("Scan failed for {}", pathname));

                    // Update progress - increment completed and mark thread idle
                    if let Ok(mut p) = progress_clone.lock() {
                        p.state_mut().increment_completed();
                        p.state_mut().set_worker_idle(thread_id);
                    }
                });
            });

            /*
             * Look through the results we just processed for any new PKGPATH
             * entries in DEPENDS that we have not seen before (neither in
             * done nor incoming).
             */
            let mut new_incoming: HashSet<PkgPath> = HashSet::new();
            for (pkgpath, scanpkgs) in parpaths.drain(..) {
                let scanpkgs = scanpkgs?;
                self.done.insert(pkgpath.clone(), scanpkgs.clone());
                for pkg in scanpkgs {
                    for dep in pkg.all_depends {
                        if !self.done.contains_key(dep.pkgpath())
                            && !self.incoming.contains(dep.pkgpath())
                            && new_incoming.insert(dep.pkgpath().clone())
                        {
                            // Update total count for new dependencies
                            if let Ok(mut p) = progress.lock() {
                                p.state_mut().total += 1;
                            }
                        }
                    }
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

        if self.sandbox.enabled() {
            // Run post-build script if defined
            if let Some(post_build) = self.config.script("post-build") {
                debug!("Running post-build script");
                let child = self.sandbox.execute(0, post_build, script_envs, None, None)?;
                let output = child.wait_with_output().context("Failed to wait for post-build")?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!(exit_code = ?output.status.code(), stderr = %stderr, "post-build script failed");
                }
            }

            self.sandbox.destroy(0)?;
        }

        // Stop the refresh thread and print final summary
        stop_refresh.store(true, Ordering::Relaxed);
        let _ = refresh_thread.join();

        if let Ok(mut p) = progress.lock() {
            let _ = p.finish();
        }

        Ok(())
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

        trace!(
            pkgpath = %pkgpath_str,
            script = %script,
            "Executing pkg-scan"
        );
        let child = self.sandbox.execute_script(0, &script, vec![])?;
        let output = child.wait_with_output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                pkgpath = %pkgpath_str,
                exit_code = ?output.status.code(),
                stderr = %stderr,
                "pkg-scan script failed"
            );
        }

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        trace!(
            pkgpath = %pkgpath_str,
            stdout_len = stdout_str.len(),
            stdout = %stdout_str,
            "pkg-scan script output"
        );

        let reader = BufReader::new(&output.stdout[..]);
        let mut index = ScanIndex::from_reader(reader)?;

        info!(
            pkgpath = %pkgpath_str,
            packages_found = index.len(),
            "Scan complete for pkgpath"
        );

        /*
         * Set PKGPATH (PKG_LOCATION) as for some reason pbulk-index doesn't.
         */
        for pkg in &mut index {
            pkg.pkg_location = Some(pkgpath.clone());
            debug!(
                pkgpath = %pkgpath_str,
                pkgname = %pkg.pkgname.pkgname(),
                skip_reason = ?pkg.pkg_skip_reason,
                fail_reason = ?pkg.pkg_fail_reason,
                depends_count = pkg.all_depends.len(),
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
            debug!(
                pkgpath = %pkgpath.as_path().display(),
                packages_in_index = index.len(),
                "Processing done entry"
            );
        }

        for index in self.done.values() {
            for pkg in index {
                // Check for skip/fail reasons
                if let Some(reason) = &pkg.pkg_skip_reason {
                    if !reason.is_empty() {
                        info!(
                            pkgname = %pkg.pkgname.pkgname(),
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
                        info!(
                            pkgname = %pkg.pkgname.pkgname(),
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

                debug!(
                    pkgname = %pkg.pkgname.pkgname(),
                    "Adding package to resolved set"
                );
                pkgnames.insert(pkg.pkgname.clone());
                self.resolved.insert(pkg.pkgname.clone(), pkg.clone());
            }
        }

        info!(
            resolved_count = self.resolved.len(),
            skipped_count = skipped.len(),
            "Initial resolution complete"
        );

        if !skipped.is_empty() {
            println!(
                "Skipping {} packages with PKG_SKIP_REASON or PKG_FAIL_REASON",
                skipped.len()
            );
        }

        /*
         * Keep a cache of best Depend => PkgName matches we've already seen
         * as it's likely the same patterns will be used in multiple places.
         */
        let mut match_cache: HashMap<Depend, PkgName> = HashMap::new();
        let mut errors: Vec<String> = Vec::new();

        for pkg in self.resolved.values_mut() {
            for depend in &pkg.all_depends {
                /*
                 * Check for cached DEPENDS match first.  If found, use it.
                 */
                if let Some(pkgname) = match_cache.get(depend) {
                    pkg.depends.push(pkgname.clone().clone());
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
                                Some(m) if m == current.pkgname() => {
                                    Some(current)
                                }
                                Some(m) if m == candidate.pkgname() => {
                                    Some(candidate)
                                }
                                Some(_) => todo!(),
                                None => None,
                            };
                        } else {
                            best = Some(candidate);
                        }
                    }
                }
                /*
                 * If we found a match, save it and add to the cache,
                 * otherwise collect the error (batch errors).
                 */
                if let Some(pkgname) = best {
                    pkg.depends.push(pkgname.clone());
                    match_cache.insert(depend.clone(), pkgname.clone());
                } else {
                    errors.push(format!(
                        "No match found for {} in {}",
                        depend.pattern().pattern(),
                        pkg.pkgname.pkgname()
                    ));
                }
            }
        }

        if !errors.is_empty() {
            for err in &errors {
                error!(error = %err, "Unresolved dependency");
            }
            bail!("Unresolved dependencies:\n  {}", errors.join("\n  "));
        }

        /*
         * Verify that the graph is acyclic.
         */
        debug!(resolved_count = self.resolved.len(), "Checking for circular dependencies");
        let mut graph = DiGraphMap::new();
        for (pkgname, index) in &self.resolved {
            for dep in &index.depends {
                graph.add_edge(dep.pkgname(), pkgname.pkgname(), ());
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
            buildable_count = self.resolved.len(),
            skipped_count = skipped.len(),
            "Resolution complete"
        );

        // Log all buildable packages
        for pkgname in self.resolved.keys() {
            debug!(pkgname = %pkgname.pkgname(), "Package is buildable");
        }

        Ok(ScanResult { buildable: self.resolved.clone(), skipped })
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
