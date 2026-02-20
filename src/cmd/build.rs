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
 * Implementation of the `bob build` command.
 *
 * Provides build-specific logic that sits between scan resolution and the
 * build engine: up-to-date checking with topological wave processing, and
 * wrapping build results with skipped/scan-failed packages.
 */

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use tracing::error;

use bob::Interrupted;
use bob::build::{self, Build};
use bob::config::Config;
use bob::db::Database;
use bob::sandbox::SandboxScope;
use bob::scan::{ScanResult, ScanSummary};

/**
 * Check in advance whether packages are up-to-date, or a reason why they
 * need to be built, and store results.
 *
 * Determines whether each package's binary is current with its sources by
 * checking file hashes, CVS IDs, and dependency states. Packages verified
 * as up-to-date are recorded with `BuildOutcome::UpToDate` to skip during
 * build; others have their rebuild reason stored in the database.
 *
 * Processing uses topological waves to avoid redundant checks. Packages
 * are checked only after all their dependencies have been processed. When
 * a checked package needs rebuilding, all its dependents are immediately
 * marked for rebuild via propagation.
 */
pub fn check_up_to_date(
    config: &Config,
    db: &Database,
    scan_result: &ScanSummary,
) -> Result<usize> {
    let pkgsrc_env = match db.load_pkgsrc_env() {
        Ok(env) => env,
        Err(_) => {
            tracing::warn!("PkgsrcEnv not cached, skipping up-to-date check");
            return Ok(0);
        }
    };
    let packages_dir = pkgsrc_env.packages.join("All");
    let pkgsrc_dir = config.pkgsrc();

    let buildable: Vec<_> = scan_result.buildable().collect();
    let mut up_to_date_count = 0usize;

    db.clear_build_reasons()?;

    print!("Calculating package build status...");
    std::io::Write::flush(&mut std::io::stdout())?;
    let start = std::time::Instant::now();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.scan_threads())
        .build()
        .context("Failed to build thread pool for up-to-date check")?;

    /*
     * Build dependency graph restricted to buildable set. Forward deps
     * determine wave ordering, reverse deps enable propagation.
     */
    let buildable_names: HashSet<&str> = buildable.iter().map(|p| p.pkgname().pkgname()).collect();
    let pkg_by_name: HashMap<&str, &bob::scan::ResolvedPackage> = buildable
        .iter()
        .map(|&p| (p.pkgname().pkgname(), p))
        .collect();

    let forward_deps: HashMap<&str, Vec<&str>> = buildable
        .iter()
        .map(|p| {
            let deps: Vec<&str> = p
                .depends()
                .iter()
                .map(|d| d.pkgname())
                .filter(|d| buildable_names.contains(d))
                .collect();
            (p.pkgname().pkgname(), deps)
        })
        .collect();

    let mut reverse_deps: HashMap<&str, Vec<&str>> = HashMap::new();
    for (pkg, deps) in &forward_deps {
        for dep in deps {
            reverse_deps.entry(*dep).or_default().push(*pkg);
        }
    }

    let mut remaining: HashSet<&str> = buildable_names.clone();
    let mut needs_rebuild: HashSet<&str> = HashSet::new();
    let mut propagated_from: HashMap<&str, &str> = HashMap::new();
    let mut checked_results: Vec<(
        &bob::scan::ResolvedPackage,
        anyhow::Result<Option<bob::BuildReason>>,
    )> = Vec::new();

    /*
     * Mark packages with missing binaries. Not propagated - dependents
     * will get their own reason (DependencyMissing) when checked.
     */
    for &pkgname in &buildable_names {
        let pkgfile = packages_dir.join(format!("{}.tgz", pkgname));
        if !pkgfile.exists() {
            needs_rebuild.insert(pkgname);
            db.store_build_reason(pkgname, &bob::BuildReason::PackageNotFound.to_string())?;
        }
    }

    /*
     * Process in topological waves. Each wave contains packages whose
     * dependencies have all been processed. Packages already marked are
     * skipped; when a checked package needs rebuild, all transitive
     * dependents are marked with DependencyRefresh via propagation.
     */
    while !remaining.is_empty() {
        let ready: Vec<&str> = remaining
            .iter()
            .filter(|pkg| {
                forward_deps[*pkg]
                    .iter()
                    .all(|dep| !remaining.contains(dep))
            })
            .copied()
            .collect();

        if ready.is_empty() {
            break;
        }

        let to_check: Vec<&str> = ready
            .iter()
            .filter(|pkg| !needs_rebuild.contains(*pkg))
            .copied()
            .collect();

        let wave_results: Vec<_> = pool.install(|| {
            to_check
                .par_iter()
                .map(|&pkgname| {
                    let pkg = pkg_by_name[pkgname];
                    let depends: Vec<&str> = pkg.depends().iter().map(|d| d.pkgname()).collect();
                    let result = bob::pkg_up_to_date(pkgname, &depends, &packages_dir, pkgsrc_dir);
                    (pkg, result)
                })
                .collect()
        });

        for (pkg, result) in wave_results {
            let pkgname = pkg.pkgname().pkgname();
            if matches!(&result, Ok(Some(_)) | Err(_)) {
                needs_rebuild.insert(pkgname);
                let mut worklist = vec![pkgname];
                while let Some(dep) = worklist.pop() {
                    if let Some(dependents) = reverse_deps.get(dep) {
                        for &dependent in dependents {
                            if needs_rebuild.insert(dependent) {
                                propagated_from.insert(dependent, dep);
                                worklist.push(dependent);
                            }
                        }
                    }
                }
            }
            checked_results.push((pkg, result));
        }

        for pkg in ready {
            remaining.remove(pkg);
        }
    }

    /*
     * Store results. Checked packages get their actual outcome (UpToDate
     * or their specific rebuild reason). Propagated packages (not checked)
     * get DependencyRefresh.
     */
    for (pkg, result) in checked_results {
        let pkgname = pkg.pkgname().pkgname();
        match result {
            Ok(None) => {
                let build_result = bob::BuildResult {
                    pkgname: pkg.pkgname().clone(),
                    pkgpath: Some(pkg.pkgpath.clone()),
                    outcome: bob::BuildOutcome::UpToDate,
                    log_dir: None,
                    build_stats: bob::PkgBuildStats::default(),
                };
                db.store_build_by_name(&build_result)?;
                up_to_date_count += 1;
            }
            Ok(Some(reason)) => {
                db.store_build_reason(pkgname, &reason.to_string())?;
            }
            Err(e) => {
                tracing::debug!(
                    pkgname,
                    error = %e,
                    "Error checking up-to-date status"
                );
                db.store_build_reason(pkgname, &format!("check failed: {}", e))?;
            }
        }
    }

    for (pkgname, dep) in propagated_from {
        let reason = bob::BuildReason::DependencyRefresh(dep.to_string());
        db.store_build_reason(pkgname, &reason.to_string())?;
    }

    println!(" done ({:.1}s)", start.elapsed().as_secs_f32());

    Ok(up_to_date_count)
}

/**
 * Run a build from scan results, including skipped and scan-failed packages
 * in the returned summary.
 *
 * This wraps the core build engine with the additional context from scan
 * resolution: packages that were skipped (PKG_SKIP_REASON, PKG_FAIL_REASON,
 * unresolved deps) and packages that failed to scan are included in the
 * summary for complete reporting.
 */
pub fn run_build_with(
    config: &Config,
    db: &Database,
    state: &bob::RunState,
    scan_result: ScanSummary,
    scope: SandboxScope,
) -> Result<build::BuildSummary> {
    if scan_result.count_buildable() == 0 {
        bail!("No packages to build");
    }

    let buildable: indexmap::IndexMap<_, _> = scan_result
        .buildable()
        .map(|p| (p.pkgname().clone(), p.clone()))
        .collect();

    let pkgsrc_env = db
        .load_pkgsrc_env()
        .context("PkgsrcEnv not cached - try 'bob clean' first")?;

    let mut build = Build::new(config, pkgsrc_env, scope, buildable);
    build.load_cached_from_db(db)?;

    tracing::debug!("Calling build.start()");
    let build_start_time = std::time::Instant::now();
    let mut summary = build.start(state, db)?;
    tracing::debug!(
        elapsed_ms = build_start_time.elapsed().as_millis(),
        "build.start() returned"
    );

    /*
     * Check if we were interrupted.  All builds that completed before
     * the interrupt have already been saved to the database inside
     * build.start().  When stopping, in-progress builds ran to
     * completion; during shutdown they were killed and discarded.
     */
    if state.interrupted() {
        return Err(Interrupted.into());
    }

    for pkg in scan_result.packages.iter() {
        match pkg {
            ScanResult::Skipped {
                pkgpath,
                reason,
                index,
                ..
            } => {
                let Some(pkgname) = index.as_ref().map(|i| &i.pkgname) else {
                    error!(%pkgpath, "Skipped package missing PKGNAME");
                    continue;
                };
                summary.results.push(build::BuildResult {
                    pkgname: pkgname.clone(),
                    pkgpath: Some(pkgpath.clone()),
                    outcome: build::BuildOutcome::Skipped(reason.clone()),
                    log_dir: None,
                    build_stats: build::PkgBuildStats::default(),
                });
            }
            ScanResult::ScanFail { pkgpath, error } => {
                summary.scanfail.push((pkgpath.clone(), error.clone()));
            }
            ScanResult::Buildable(_) => {}
        }
    }
    Ok(summary)
}
