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

use bob::Interrupted;
use bob::build::{self, Build};
use bob::config::{Config, Pkgsrc};
use bob::db::Database;
use bob::sandbox::SandboxScope;

/**
 * Check in advance whether packages are up-to-date, or a reason why they
 * need to be built, and store results.
 *
 * Determines whether each package's binary is current with its sources by
 * checking file hashes, CVS IDs, and dependency states. Packages verified
 * as up-to-date are recorded with `PackageState::UpToDate` to skip during
 * build; others have their rebuild reason stored in the database.
 *
 * Processing uses topological waves to avoid redundant checks. Packages
 * are checked only after all their dependencies have been processed. When
 * a checked package needs rebuilding, all its dependents are immediately
 * marked for rebuild via propagation.
 */
pub fn check_up_to_date(config: &Config, pkgsrc: &Pkgsrc, db: &Database) -> Result<usize> {
    let pkgsrc_env = match db.load_pkgsrc_env() {
        Ok(env) => env,
        Err(_) => {
            tracing::warn!("PkgsrcEnv not cached, skipping up-to-date check");
            return Ok(0);
        }
    };
    let packages_dir = pkgsrc_env.packages.join("All");

    let mut up_to_date_count = 0usize;

    db.clear_build_reasons()?;

    bob::print_status("Calculating package build status");
    let start = std::time::Instant::now();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.scan_threads())
        .thread_name(|i| format!("up-to-date-{i}"))
        .build()
        .context("Failed to build thread pool for up-to-date check")?;

    /*
     * Dependency graph over buildable package ids, loaded from the
     * resolution results stored in the database. Forward deps determine
     * wave ordering, reverse deps enable propagation.  `order` ranks
     * the most depended-upon packages first so processing, and with it
     * rebuild-reason attribution, follows that priority.
     */
    let rows = db.get_buildable_rows()?;
    let order: Vec<i64> = rows.iter().map(|&(id, ..)| id).collect();
    let packages: HashMap<i64, (String, String)> = rows
        .into_iter()
        .map(|(id, pkgname, pkg_location)| (id, (pkgname, pkg_location)))
        .collect();
    let mut forward_deps: HashMap<i64, Vec<i64>> =
        packages.keys().map(|&id| (id, Vec::new())).collect();
    let mut reverse_deps: HashMap<i64, Vec<i64>> = HashMap::new();
    for (pkg, dep) in db.get_buildable_depends()? {
        forward_deps.entry(pkg).or_default().push(dep);
        reverse_deps.entry(dep).or_default().push(pkg);
    }

    let mut remaining: HashSet<i64> = packages.keys().copied().collect();
    let mut needs_rebuild: HashSet<i64> = HashSet::new();
    let mut propagated_from: HashMap<i64, i64> = HashMap::new();
    let mut checked_results: Vec<(i64, anyhow::Result<Option<bob::BuildReason>>)> = Vec::new();

    /*
     * Mark packages with missing binaries. Not propagated - dependents
     * will get their own reason (DependencyMissing) when checked.
     */
    {
        let tx = db.transaction()?;
        for (&id, (pkgname, _)) in &packages {
            let pkgfile = packages_dir.join(format!("{}.tgz", pkgname));
            if !pkgfile.exists() {
                needs_rebuild.insert(id);
                db.store_build_reason(id, &bob::BuildReason::PackageNotFound.to_string())?;
            }
        }
        tx.commit()?;
    }

    /*
     * Process in topological waves. Each wave contains packages whose
     * dependencies have all been processed. Packages already marked are
     * skipped; when a checked package needs rebuild, all transitive
     * dependents are marked with DependencyRefresh via propagation.
     */
    while !remaining.is_empty() {
        let ready: Vec<i64> = order
            .iter()
            .filter(|id| {
                remaining.contains(id)
                    && forward_deps[*id].iter().all(|dep| !remaining.contains(dep))
            })
            .copied()
            .collect();

        if ready.is_empty() {
            break;
        }

        let to_check: Vec<i64> = ready
            .iter()
            .filter(|id| !needs_rebuild.contains(id))
            .copied()
            .collect();

        let wave_results: Vec<_> = pool.install(|| {
            to_check
                .par_iter()
                .map(|&id| {
                    let depends: Vec<&str> = forward_deps[&id]
                        .iter()
                        .map(|dep| packages[dep].0.as_str())
                        .collect();
                    let result = bob::pkg_up_to_date(
                        &packages[&id].0,
                        &depends,
                        &packages_dir,
                        &pkgsrc.basedir,
                    );
                    (id, result)
                })
                .collect()
        });

        for (id, result) in wave_results {
            if matches!(&result, Ok(Some(_)) | Err(_)) {
                needs_rebuild.insert(id);
                let mut worklist = vec![id];
                while let Some(dep) = worklist.pop() {
                    if let Some(dependents) = reverse_deps.get(&dep) {
                        for &dependent in dependents {
                            if needs_rebuild.insert(dependent) {
                                propagated_from.insert(dependent, dep);
                                worklist.push(dependent);
                            }
                        }
                    }
                }
            }
            checked_results.push((id, result));
        }

        for id in ready {
            remaining.remove(&id);
        }
    }

    /*
     * Store results. Checked packages get their actual outcome (UpToDate
     * or their specific rebuild reason). Propagated packages (not checked)
     * get DependencyRefresh.
     */
    let build_id = db.build_id()?;
    let mut history_inputs = Vec::new();
    {
        let tx = db.transaction()?;
        for (id, result) in checked_results {
            let (pkgname, pkg_location) = &packages[&id];
            match result {
                Ok(None) => {
                    if db.is_successful(id)? {
                        continue;
                    }
                    let build_result = bob::BuildResult {
                        pkgname: pkgsrc::PkgName::new(pkgname),
                        pkgpath: pkgsrc::PkgPath::new(pkg_location).ok(),
                        state: bob::PackageState::UpToDate,
                        log_dir: None,
                        build_stats: bob::PkgBuildStats::default(),
                    };
                    db.store_build_result(id, &build_result)?;
                    if let Some(mut input) = build_result.history_input() {
                        input.build_id = Some(build_id.clone());
                        history_inputs.push(input);
                    }
                    up_to_date_count += 1;
                }
                Ok(Some(reason)) => {
                    db.store_build_reason(id, &reason.to_string())?;
                }
                Err(e) => {
                    tracing::debug!(
                        pkgname,
                        error = format!("{e:#}"),
                        "Error checking up-to-date status"
                    );
                    db.store_build_reason(id, &format!("check failed: {}", e))?;
                }
            }
        }

        for (id, dep) in propagated_from {
            let reason = bob::BuildReason::DependencyRefresh(packages[&dep].0.clone());
            db.store_build_reason(id, &reason.to_string())?;
        }
        tx.commit()?;
    }

    db.record_history_batch(&history_inputs)
        .context("Failed to record up-to-date history")?;

    bob::print_elapsed("Calculating package build status", start.elapsed());

    db.record_up_to_date_count(&build_id, up_to_date_count)?;

    Ok(up_to_date_count)
}

/**
 * Run a build, including skipped and scan-failed packages in the returned
 * summary.
 *
 * This wraps the core build engine with the additional context from scan
 * resolution: packages that were skipped (PKG_SKIP_REASON, PKG_FAIL_REASON,
 * unresolved deps) and packages that failed to scan are loaded from the
 * database and included in the summary for complete reporting.
 */
pub fn run_build_with(
    config: &Config,
    pkgsrc: &Pkgsrc,
    db: &Database,
    state: &bob::RunState,
    scope: SandboxScope,
) -> Result<build::BuildSummary> {
    let buildable = db.get_buildable_packages()?;
    if buildable.is_empty() {
        bail!("No packages to build");
    }

    let pkgsrc_env = db
        .load_pkgsrc_env()
        .context("PkgsrcEnv not cached - try 'bob clean' first")?;

    let mut build = Build::new(config, pkgsrc, pkgsrc_env, scope, buildable);
    build.load_cached_from_db(db)?;

    tracing::debug!("Calling build.start()");
    let build_start_time = std::time::Instant::now();
    let mut summary = build.start(state, db)?;
    let build_elapsed = build_start_time.elapsed();
    tracing::debug!(
        elapsed_ms = build_elapsed.as_millis(),
        "build.start() returned"
    );
    db.add_build_duration(build_elapsed)?;

    /*
     * Check if we were interrupted.  All builds that completed before
     * the interrupt have already been saved to the database inside
     * build.start().  When stopping, in-progress builds ran to
     * completion; during shutdown they were killed and discarded.
     */
    if state.interrupted() {
        return Err(Interrupted.into());
    }

    /*
     * Record history for non-built packages (skipped, scanfail) so that
     * build diffs can compare all package outcomes between builds.  Both
     * sets were stored by resolution and loaded back here.
     */
    let skipped_results = db.get_scan_outcomes()?;
    let scanfail_results: Vec<(pkgsrc::PkgPath, String)> = db
        .get_scan_failures()?
        .into_iter()
        .filter_map(|(p, e)| pkgsrc::PkgPath::new(&p).ok().map(|pp| (pp, e)))
        .collect();

    let build_id = db.build_id().ok();
    if let Some(bid) = &build_id
        && let Some(rev) = db.load_vcs_info().ok().and_then(|v| v.revision_full)
        && let Err(e) = db.store_build_revision(bid, &rev)
    {
        tracing::warn!(error = format!("{e:#}"), "Failed to save build revision");
    }
    let history_inputs: Vec<_> = skipped_results
        .iter()
        .filter_map(|result| {
            result.history_input().map(|mut input| {
                input.build_id = build_id.clone();
                input
            })
        })
        .collect();
    if let Err(e) = db.record_history_batch(&history_inputs) {
        tracing::warn!(error = format!("{e:#}"), "Failed to save skipped history");
    }
    summary.results.extend(skipped_results);
    summary.scanfail.extend(scanfail_results);
    Ok(summary)
}
