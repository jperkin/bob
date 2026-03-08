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
 * Build scheduling using summed-weight ordering.
 *
 * Packages are prioritised by **total weight** -- the package's own
 * PBULK_WEIGHT plus the sum of all unique transitive dependents'
 * weights (diamond-deduplicated).  This matches the algorithm used
 * by pbulk's `compute_tree_depth_rec()`.
 *
 * Tiebreakers, in order: transitive dependent count (more dependents
 * first), historical CPU time (longer builds first), then package
 * name (alphabetical) for determinism.
 *
 * A ready set of packages whose dependencies are all satisfied is
 * maintained incrementally, giving O(1) dispatch via
 * [`Scheduler::poll`].
 */

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::hash::Hash;
use std::sync::mpsc::Sender;
use std::task::Poll;
use tracing::debug;

/**
 * Per-package data for scheduling.
 *
 * Bundles the dependency set with the package's own scheduling
 * metadata so that every package in the graph is guaranteed to
 * have all required fields.
 */
pub struct PackageNode<K> {
    pub deps: HashSet<K>,
    pub pbulk_weight: usize,
    pub cpu_time: u64,
}

/**
 * One-shot channel for returning MAKE_JOBS from the manager to a worker.
 */
pub(crate) struct MakeJobsResponder(pub Sender<usize>);

impl std::fmt::Debug for MakeJobsResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MakeJobsResponder")
    }
}

/**
 * Sort key for ready packages.
 *
 * Fields are compared in declaration order via the derived `Ord`:
 * highest total_weight first, then most transitive dependents,
 * then highest historical CPU time, then alphabetical name.
 *
 * `Reverse` wrapping gives descending order in BTreeSet.
 */
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ReadyKey<K: Ord> {
    total_weight: std::cmp::Reverse<usize>,
    dep_count: std::cmp::Reverse<usize>,
    cpu_time: std::cmp::Reverse<u64>,
    pkg: K,
}

/**
 * Dependency-aware build scheduler using summed-weight ordering.
 *
 * Tracks the live dependency graph and selects the next package to build
 * based on precomputed total weights.  The dependency invariant is
 * enforced: a package is only dispatched by [`poll`](Self::poll) when all
 * its dependencies have completed.
 */
pub struct Scheduler<K: Ord> {
    incoming: HashMap<K, HashSet<K>>,
    reverse_deps: HashMap<K, HashSet<K>>,
    ready: BTreeSet<ReadyKey<K>>,
    total_weights: HashMap<K, usize>,
    dep_counts: HashMap<K, usize>,
    cpu_times: HashMap<K, u64>,
    running: HashSet<K>,
    done: HashSet<K>,
    failed: HashSet<K>,
    weights: HashMap<K, usize>,
    budget: Option<Budget<K>>,
}

/*
 * MAKE_JOBS Budget Allocation
 * ===========================
 *
 * Pre-computes a default MAKE_JOBS value for every package based on
 * two inputs:
 *
 *   1. Build duration -- estimated serial time from history
 *      (build-phase wall time * make_jobs).  Longer builds save
 *      more absolute time from extra cores.
 *
 *   2. Dependency importance -- how many packages transitively
 *      depend on this one.  Finishing important packages faster
 *      unblocks more work.
 *
 * The combined score for each package is:
 *
 *   score = duration^DURATION_EXP
 *         * (1 + dep_count)^IMPORTANCE_EXP
 *
 * The raw score range is compressed with a log transform before
 * mapping to jobs:
 *
 *   log_score = ln(score)
 *   t = (log_score - min_log) / (max_log - min_log)   [0..1]
 *   ceiling = fair_share * PEAK_MULTIPLIER
 *   jobs = 1 + (ceiling - 1) * t
 *
 * The log transform compresses the extreme skew in raw scores
 * (3+ orders of magnitude) so that mid-range packages get
 * meaningful allocations instead of being crushed to 1.
 *
 * The ceiling is `fair_share * PEAK_MULTIPLIER` rather than
 * `max_jobs`.  This bounds peak overcommit: the worst case with
 * all build_threads workers running top-scored packages is
 * `build_threads * ceiling`.  With PEAK_MULTIPLIER=3 and 4
 * threads at 16 max_jobs: ceiling=12, worst case=48 (3x).  In
 * practice the peak is lower because not all 4 workers run top
 * packages simultaneously.
 *
 * The sole-buildable override (max_jobs when nothing else is
 * running) ensures solo builds fully utilise the machine.
 *
 * Sole buildable packages (nothing else running or ready) always
 * get max_jobs regardless of their pre-computed value.
 */

/**
 * Exponent for build duration.  Controls how much longer builds
 * are favoured.  0.5 (sqrt) compresses a 16200:1 range to 127:1.
 */
const DURATION_EXP: f64 = 0.5;

/**
 * Exponent for dependency importance (transitive dependent count).
 * Controls how much high-importance packages are favoured.
 * 0.3 gives modest influence (1800 dependents -> 9x multiplier).
 */
const IMPORTANCE_EXP: f64 = 0.3;

/**
 * Maximum multiplier of fair_share for concurrent builds.
 * The highest-scored package gets `fair_share * PEAK_MULTIPLIER`
 * jobs when running alongside other packages.  Controls peak
 * overcommit: worst case is `build_threads * PEAK_MULTIPLIER *
 * fair_share = PEAK_MULTIPLIER * max_jobs`.
 */
const PEAK_MULTIPLIER: f64 = 2.0;

struct Budget<K> {
    max_jobs: usize,
    precomputed: HashMap<K, usize>,
    locked: HashMap<K, usize>,
    excluded: HashSet<K>,
}

impl<K: Eq + Hash + Clone + Ord + fmt::Display> Scheduler<K> {
    /**
     * Create a new scheduler.
     *
     * `packages` maps each package to its [`PackageNode`] containing
     * dependencies, PBULK_WEIGHT, and historical CPU time.  Because
     * every field is part of the node, it is structurally impossible
     * to have a package without its scheduling data.
     *
     * `reverse_deps` maps each package to the set of packages that
     * depend on it.
     *
     * Packages already in `done` or `failed` should have been removed
     * from `packages` before calling this constructor.
     */
    pub fn new(
        packages: HashMap<K, PackageNode<K>>,
        reverse_deps: HashMap<K, HashSet<K>>,
        done: HashSet<K>,
        failed: HashSet<K>,
    ) -> Self {
        let mut incoming: HashMap<K, HashSet<K>> = HashMap::with_capacity(packages.len());
        let mut weights: HashMap<K, usize> = HashMap::with_capacity(packages.len());
        let mut cpu_times: HashMap<K, u64> = HashMap::with_capacity(packages.len());

        for (pkg, node) in &packages {
            incoming.insert(pkg.clone(), node.deps.clone());
            weights.insert(pkg.clone(), node.pbulk_weight);
            cpu_times.insert(pkg.clone(), node.cpu_time);
        }

        let (total_weights, dep_counts) =
            scheduling_weights_inner(&incoming, &reverse_deps, &weights);

        let mut ready = BTreeSet::new();
        for (pkg, node) in &packages {
            if node.deps.is_empty() {
                ready.insert(ReadyKey {
                    total_weight: std::cmp::Reverse(total_weights[pkg]),
                    dep_count: std::cmp::Reverse(dep_counts[pkg]),
                    cpu_time: std::cmp::Reverse(cpu_times[pkg]),
                    pkg: pkg.clone(),
                });
            }
        }

        Self {
            incoming,
            reverse_deps,
            ready,
            total_weights,
            dep_counts,
            cpu_times,
            running: HashSet::new(),
            done,
            failed,
            weights,
            budget: None,
        }
    }

    /**
     * Poll for the next package to build.
     *
     * Returns `Ready(Some(pkg))` with the highest-priority ready
     * package (automatically dispatched), `Pending` if all remaining
     * packages are waiting on running dependencies, or `Ready(None)`
     * when all packages have completed or failed.
     */
    pub fn poll(&mut self) -> Poll<Option<K>> {
        match self.ready.first().cloned() {
            Some(key) => {
                self.ready.remove(&key);
                self.incoming.remove(&key.pkg);
                self.running.insert(key.pkg.clone());
                Poll::Ready(Some(key.pkg))
            }
            None if self.incoming.is_empty() && self.running.is_empty() => Poll::Ready(None),
            None => Poll::Pending,
        }
    }

    /**
     * Mark a running package build as successful.
     *
     * Moves it from `running` to `done` and removes it from the
     * dependency sets of packages that depend on it.  Packages whose
     * dependency sets become empty are added to the ready set.
     */
    pub fn mark_success(&mut self, pkg: &K) {
        self.running.remove(pkg);
        self.done.insert(pkg.clone());
        if let Some(dependents) = self.reverse_deps.get(pkg) {
            for dependent in dependents {
                if let Some(deps) = self.incoming.get_mut(dependent) {
                    if deps.remove(pkg) && deps.is_empty() {
                        self.ready.insert(ReadyKey {
                            total_weight: std::cmp::Reverse(self.total_weights[dependent]),
                            dep_count: std::cmp::Reverse(self.dep_counts[dependent]),
                            cpu_time: std::cmp::Reverse(self.cpu_times[dependent]),
                            pkg: dependent.clone(),
                        });
                    }
                }
            }
        }
    }

    /**
     * Mark a package as failed and propagate to all transitive dependents.
     *
     * Returns the set of indirectly failed packages (not including the
     * original).
     */
    pub fn mark_failure(&mut self, pkg: &K) -> Vec<K> {
        self.running.remove(pkg);
        self.incoming.remove(pkg);
        self.failed.insert(pkg.clone());

        let mut broken: HashSet<K> = HashSet::new();
        let mut to_check: Vec<K> = Vec::new();
        if let Some(dependents) = self.reverse_deps.get(pkg) {
            for p in dependents {
                to_check.push(p.clone());
            }
        }
        while let Some(badpkg) = to_check.pop() {
            if broken.contains(&badpkg)
                || self.done.contains(&badpkg)
                || self.failed.contains(&badpkg)
                || !self.total_weights.contains_key(&badpkg)
            {
                continue;
            }
            if let Some(dependents) = self.reverse_deps.get(&badpkg) {
                for p in dependents {
                    to_check.push(p.clone());
                }
            }
            broken.insert(badpkg);
        }

        let mut indirect: Vec<K> = Vec::with_capacity(broken.len());
        for pkg in broken {
            self.incoming.remove(&pkg);
            if let (Some(&total_weight), Some(&dep_count), Some(&cpu_time)) = (
                self.total_weights.get(&pkg),
                self.dep_counts.get(&pkg),
                self.cpu_times.get(&pkg),
            ) {
                self.ready.remove(&ReadyKey {
                    total_weight: std::cmp::Reverse(total_weight),
                    dep_count: std::cmp::Reverse(dep_count),
                    cpu_time: std::cmp::Reverse(cpu_time),
                    pkg: pkg.clone(),
                });
            }
            self.failed.insert(pkg.clone());
            indirect.push(pkg);
        }
        indirect
    }

    /**
     * Compute the critical path cost: the longest weighted chain through
     * remaining (not done, not failed, not running) transitive dependents.
     *
     * This is used by the MAKE_JOBS allocator and is called once per
     * dispatched package, so the per-call DFS cost is acceptable.
     */
    pub fn remaining_depth(&self, pkg: &K) -> usize {
        let mut depths: HashMap<&K, usize> = HashMap::new();
        let mut stack: Vec<(&K, bool)> = vec![(pkg, false)];
        while let Some((p, children_done)) = stack.pop() {
            if children_done {
                let depth = self
                    .reverse_deps
                    .get(p)
                    .map(|rdeps| {
                        rdeps
                            .iter()
                            .filter(|r| {
                                !self.done.contains(*r)
                                    && !self.failed.contains(*r)
                                    && !self.running.contains(*r)
                            })
                            .filter_map(|r| depths.get(r).map(|d| self.weight(r) + d))
                            .max()
                            .unwrap_or(0)
                    })
                    .unwrap_or(0);
                depths.insert(p, depth);
            } else if !depths.contains_key(p) {
                stack.push((p, true));
                if let Some(rdeps) = self.reverse_deps.get(p) {
                    for rdep in rdeps {
                        if !self.done.contains(rdep)
                            && !self.failed.contains(rdep)
                            && !self.running.contains(rdep)
                            && !depths.contains_key(rdep)
                        {
                            stack.push((rdep, false));
                        }
                    }
                }
            }
        }
        depths.get(pkg).copied().unwrap_or(0)
    }

    fn weight(&self, pkg: &K) -> usize {
        self.weights[pkg]
    }

    /**
     * Peek at the ready set without consuming.
     *
     * Returns up to `n` packages from the ready set in priority order
     * (highest critical-path score first).  Used by the MAKE_JOBS
     * allocator to reserve cores for upcoming dispatches.
     */
    pub fn peek_ready(&self, n: usize) -> Vec<&K> {
        self.ready.iter().take(n).map(|key| &key.pkg).collect()
    }

    /** Number of packages waiting to be dispatched. */
    pub fn incoming_count(&self) -> usize {
        self.incoming.len()
    }

    /** Number of packages currently building. */
    pub fn running_count(&self) -> usize {
        self.running.len()
    }

    /** Number of successfully completed packages. */
    pub fn done_count(&self) -> usize {
        self.done.len()
    }

    /** Number of failed packages (direct and indirect). */
    pub fn failed_count(&self) -> usize {
        self.failed.len()
    }

    /**
     * Initialize the MAKE_JOBS budget.
     *
     * Pre-computes a jobs value for every package from two inputs:
     * build duration (from `self.weights`) and dependency importance
     * (computed from `self.reverse_deps`).
     */
    pub fn init_budget(&mut self, max_jobs: usize, build_threads: usize) {
        let fair_share = max_jobs / build_threads.max(1);

        let mut scores: Vec<(K, f64)> = Vec::new();
        for pkg in self.incoming.keys().chain(self.running.iter()) {
            let duration = self.weights.get(pkg).copied().unwrap_or(0) as f64;
            let deps = self.dep_counts.get(pkg).copied().unwrap_or(0) as f64;

            let score = duration.max(1.0).powf(DURATION_EXP) * (1.0 + deps).powf(IMPORTANCE_EXP);
            scores.push((pkg.clone(), score));
        }

        /*
         * Log-compress scores, then linearly map the log range to
         * [1, ceiling] where ceiling = fair_share * PEAK_MULTIPLIER.
         * Clamped to max_jobs as a safety bound (relevant when
         * PEAK_MULTIPLIER * fair_share > max_jobs, which shouldn't
         * happen in practice).
         */
        let ceiling = ((fair_share as f64 * PEAK_MULTIPLIER).round() as usize).clamp(1, max_jobs);

        let log_scores: Vec<f64> = scores.iter().map(|(_, s)| s.max(1.0).ln()).collect();
        let min_log = log_scores.iter().copied().fold(f64::INFINITY, f64::min);
        let max_log = log_scores.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let log_range = (max_log - min_log).max(f64::EPSILON);

        let mut precomputed: HashMap<K, usize> = HashMap::new();
        for (i, (pkg, _score)) in scores.iter().enumerate() {
            let t = (log_scores[i] - min_log) / log_range;
            let jobs = (1.0 + (ceiling - 1) as f64 * t).round() as usize;
            precomputed.insert(pkg.clone(), jobs.clamp(1, max_jobs));
        }

        debug!(
            max_jobs,
            build_threads,
            fair_share,
            ceiling,
            log_range = format!("{:.1}", log_range),
            packages = precomputed.len(),
            "budget initialized"
        );

        self.budget = Some(Budget {
            max_jobs,
            precomputed,
            locked: HashMap::new(),
            excluded: HashSet::new(),
        });
    }

    /**
     * Mark a running package as excluded from the MAKE_JOBS budget.
     *
     * Packages that are not MAKE_JOBS_SAFE always get -j1 and never
     * call [`request_make_jobs`](Self::request_make_jobs).  Marking
     * them as excluded prevents the budget from reserving a share
     * for a worker that will never claim it.
     */
    pub fn exclude_from_budget(&mut self, pkg: &K) {
        if let Some(ref mut budget) = self.budget {
            budget.excluded.insert(pkg.clone());
        }
    }

    /**
     * Return the pre-computed MAKE_JOBS allocation for a package.
     *
     * Returns `None` if the budget is not initialized.  Sole
     * buildable packages (nothing else running or ready) always
     * get `max_jobs`.
     */
    pub fn request_make_jobs(&mut self, pkg: &K) -> Option<usize> {
        let budget = self.budget.as_ref()?;
        let max_jobs = budget.max_jobs;

        let jobs = if self.is_sole_buildable(pkg) {
            max_jobs
        } else {
            budget.precomputed.get(pkg).copied().unwrap_or(1)
        };

        let budget = self.budget.as_mut()?;
        let total_before: usize = budget.locked.values().sum();
        budget.locked.insert(pkg.clone(), jobs);
        let total_after = total_before + jobs;
        debug!(
            %pkg, jobs, total_locked = total_after, max_jobs,
            overcommit = total_after > max_jobs, "make_jobs"
        );
        Some(jobs)
    }

    /**
     * Release a package's MAKE_JOBS allocation.
     */
    pub fn release_make_jobs(&mut self, pkg: &K) {
        if let Some(ref mut budget) = self.budget {
            budget.locked.remove(pkg);
        }
    }

    /**
     * Heaviest pending weight one completion away from dispatch.
     *
     * Exposed for diagnostic / simulation use only.
     */
    pub fn pending_weight(&self) -> usize {
        self.incoming
            .iter()
            .filter(|(p, deps)| {
                !deps.is_empty()
                    && !self.running.contains(*p)
                    && deps
                        .iter()
                        .all(|d| self.running.contains(d) || self.done.contains(d))
            })
            .map(|(p, _)| self.remaining_depth(p).max(1))
            .max()
            .unwrap_or(0)
    }

    /**
     * No-op: reserved cores are no longer tracked.  Retained for
     * call-site compatibility.
     */
    pub fn set_reserved(&mut self, _reserved: usize) {}

    /**
     * Fair share estimate: max_jobs divided by running count.
     *
     * Used for reservation estimates when a package has no history.
     */
    pub fn fair_share(&self) -> usize {
        let running = self.running.len().max(1);
        match &self.budget {
            Some(budget) => budget.max_jobs / running,
            None => 1,
        }
    }

    /** Sum of MAKE_JOBS across all currently locked packages. */
    pub fn total_locked_jobs(&self) -> usize {
        match &self.budget {
            Some(budget) => budget.locked.values().sum(),
            None => 0,
        }
    }

    /** Look up the pre-computed MAKE_JOBS for a package. */
    pub fn precomputed_jobs(&self, pkg: &K) -> Option<usize> {
        self.budget
            .as_ref()
            .and_then(|b| b.precomputed.get(pkg).copied())
    }

    fn is_sole_buildable(&self, _pkg: &K) -> bool {
        self.running.len() <= 1 && self.ready.is_empty()
    }
}

/**
 * Sort items by build priority using the same [`ReadyKey`] ordering
 * as the scheduler's ready set.
 */
pub fn sort_by_build_priority<T>(
    items: &mut [T],
    total_weight: impl Fn(&T) -> usize,
    dep_count: impl Fn(&T) -> usize,
    cpu_time: impl Fn(&T) -> u64,
    name: impl Fn(&T) -> &str,
) {
    items.sort_by_cached_key(|item| {
        (
            std::cmp::Reverse(total_weight(item)),
            std::cmp::Reverse(dep_count(item)),
            std::cmp::Reverse(cpu_time(item)),
            name(item).to_string(),
        )
    });
}

/**
 * Compute MAKE_JOBS budget from pre-computed dep counts and durations.
 *
 * This applies the same scoring formula as [`Scheduler::init_budget`]
 * but without requiring a full Scheduler instance or dependency graph.
 * Useful for displaying jobs allocations from stored scan data.
 */
pub fn compute_budget<K>(
    dep_counts: &HashMap<K, i64>,
    durations: &HashMap<K, usize>,
    max_jobs: usize,
    build_threads: usize,
) -> HashMap<K, usize>
where
    K: Eq + Hash + Clone,
{
    let fair_share = max_jobs / build_threads.max(1);

    let mut scores: Vec<(&K, f64)> = Vec::new();
    for (pkg, &dc) in dep_counts {
        let duration = durations.get(pkg).copied().unwrap_or(0) as f64;
        let deps = dc.max(0) as f64;
        let score = duration.max(1.0).powf(DURATION_EXP) * (1.0 + deps).powf(IMPORTANCE_EXP);
        scores.push((pkg, score));
    }

    let ceiling = ((fair_share as f64 * PEAK_MULTIPLIER).round() as usize).clamp(1, max_jobs);

    let log_scores: Vec<f64> = scores.iter().map(|(_, s)| s.max(1.0).ln()).collect();
    let min_log = log_scores.iter().copied().fold(f64::INFINITY, f64::min);
    let max_log = log_scores.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let log_range = (max_log - min_log).max(f64::EPSILON);

    let mut budget: HashMap<K, usize> = HashMap::new();
    for (i, &(pkg, _)) in scores.iter().enumerate() {
        let t = (log_scores[i] - min_log) / log_range;
        let jobs = (1.0 + (ceiling - 1) as f64 * t).round() as usize;
        budget.insert(pkg.clone(), jobs.clamp(1, max_jobs));
    }

    budget
}

/**
 * Compute scheduling weights and transitive dependent counts.
 *
 * For each package, computes:
 * - **total_weight**: own PBULK_WEIGHT plus the sum of all unique
 *   transitive dependents' PBULK_WEIGHTs (diamond-deduplicated).
 *   Matches pbulk's `compute_tree_depth_rec()` algorithm.
 * - **dep_count**: number of unique transitive dependents.
 *
 * Uses an indexed BFS for performance: packages are mapped to dense
 * integer IDs, the graph is stored as `Vec<Vec<usize>>`, and a
 * generation counter avoids clearing the visited set between iterations.
 */
pub fn scheduling_weights<K>(
    packages: &HashMap<K, PackageNode<K>>,
    reverse_deps: &HashMap<K, HashSet<K>>,
) -> (HashMap<K, usize>, HashMap<K, usize>)
where
    K: Eq + Hash + Clone + Ord,
{
    let incoming: HashMap<K, HashSet<K>> = packages
        .iter()
        .map(|(k, v)| (k.clone(), v.deps.clone()))
        .collect();
    let weights: HashMap<K, usize> = packages
        .iter()
        .map(|(k, v)| (k.clone(), v.pbulk_weight))
        .collect();
    scheduling_weights_inner(&incoming, reverse_deps, &weights)
}

fn scheduling_weights_inner<K>(
    incoming: &HashMap<K, HashSet<K>>,
    reverse_deps: &HashMap<K, HashSet<K>>,
    pbulk_weights: &HashMap<K, usize>,
) -> (HashMap<K, usize>, HashMap<K, usize>)
where
    K: Eq + Hash + Clone + Ord,
{
    let pkg_list: Vec<&K> = incoming.keys().collect();
    let n = pkg_list.len();
    let id_map: HashMap<&K, usize> = pkg_list.iter().enumerate().map(|(i, &p)| (p, i)).collect();

    let weights: Vec<usize> = pkg_list.iter().map(|p| pbulk_weights[*p]).collect();

    let mut rdeps_indexed: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (pkg, rdeps) in reverse_deps {
        if let Some(&pid) = id_map.get(pkg) {
            for r in rdeps {
                if let Some(&rid) = id_map.get(r) {
                    rdeps_indexed[pid].push(rid);
                }
            }
        }
    }

    let (tw_vec, dc_vec) = scheduling_weights_indexed(&weights, &rdeps_indexed);

    let mut total_weights: HashMap<K, usize> = HashMap::with_capacity(n);
    let mut dep_counts: HashMap<K, usize> = HashMap::with_capacity(n);
    for (i, &pkg) in pkg_list.iter().enumerate() {
        total_weights.insert(pkg.clone(), tw_vec[i]);
        dep_counts.insert(pkg.clone(), dc_vec[i]);
    }

    (total_weights, dep_counts)
}

/**
 * Compute scheduling weights from pre-indexed graph data.
 *
 * Returns parallel vectors of (total_weight, dep_count) for each node.
 */
pub fn scheduling_weights_indexed(
    weights: &[usize],
    rdeps_indexed: &[Vec<usize>],
) -> (Vec<usize>, Vec<usize>) {
    let n = weights.len();
    let mut total_weights = vec![0usize; n];
    let mut dep_counts = vec![0usize; n];
    let mut visit_gen = vec![0u32; n];
    let mut epoch = 0u32;
    let mut queue: VecDeque<usize> = VecDeque::new();

    for i in 0..n {
        epoch += 1;
        queue.clear();

        let mut weight_sum = weights[i];
        let mut count = 0usize;

        for &r in &rdeps_indexed[i] {
            if visit_gen[r] != epoch {
                visit_gen[r] = epoch;
                queue.push_back(r);
            }
        }
        while let Some(node) = queue.pop_front() {
            weight_sum += weights[node];
            count += 1;
            for &r in &rdeps_indexed[node] {
                if visit_gen[r] != epoch {
                    visit_gen[r] = epoch;
                    queue.push_back(r);
                }
            }
        }

        total_weights[i] = weight_sum;
        dep_counts[i] = count;
    }

    (total_weights, dep_counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(s: &str) -> String {
        s.to_string()
    }

    /**
     * Package with more total blocked weight is preferred.
     *
     * x has 3 dependents at weight 100 each -> total = 400.
     * w has 50 dependents at weight 1 each -> total = 150.
     * x should be dispatched first.
     */
    #[test]
    fn higher_total_weight_preferred() {
        let mut g = build_graph(
            &[("x-1.0", "y-1.0"), ("y-1.0", "z-1.0")],
            &["x-1.0", "y-1.0", "z-1.0"],
            100,
        );

        g.packages.insert(
            pkg("w-1.0"),
            PackageNode {
                deps: HashSet::new(),
                pbulk_weight: 100,
                cpu_time: 0,
            },
        );
        g.reverse_deps.entry(pkg("w-1.0")).or_default();
        for i in 0..50 {
            let fan = format!("f{}-1.0", i);
            g.packages.insert(
                fan.clone(),
                PackageNode {
                    deps: [pkg("w-1.0")].into_iter().collect(),
                    pbulk_weight: 1,
                    cpu_time: 0,
                },
            );
            g.reverse_deps
                .entry(pkg("w-1.0"))
                .or_default()
                .insert(fan.clone());
            g.reverse_deps.entry(fan).or_default();
        }

        let mut sched = Scheduler::new(g.packages, g.reverse_deps, HashSet::new(), HashSet::new());
        assert_eq!(sched.poll(), Poll::Ready(Some(pkg("x-1.0"))));
    }

    /**
     * Diamond graph: shared dependents are counted once, not twice.
     *
     *   a -> b, a -> c, b -> d, c -> d
     *
     * a's transitive dependents are {b, c, d} (not {b, c, d, d}).
     * With uniform weight 100: total_weight(a) = 400.
     */
    #[test]
    fn diamond_dedup() {
        let g = build_graph(
            &[("a", "b"), ("a", "c"), ("b", "d"), ("c", "d")],
            &["a", "b", "c", "d"],
            100,
        );

        let (tw, dc) = scheduling_weights(&g.packages, &g.reverse_deps);
        assert_eq!(
            tw[&pkg("a")],
            400,
            "a = self(100) + b(100) + c(100) + d(100)"
        );
        assert_eq!(dc[&pkg("a")], 3, "a has 3 transitive dependents");
        assert_eq!(tw[&pkg("b")], 200, "b = self(100) + d(100)");
        assert_eq!(dc[&pkg("b")], 1);
        assert_eq!(tw[&pkg("d")], 100, "d = self(100), leaf");
        assert_eq!(dc[&pkg("d")], 0);
    }

    /**
     * High PBULK_WEIGHT leaf sorts above low-weight leaf.
     *
     * With no dependents, total_weight == own weight.
     */
    #[test]
    fn pbulk_weight_affects_leaf_order() {
        let mut packages: HashMap<String, PackageNode<String>> = HashMap::new();
        packages.insert(
            pkg("heavy"),
            PackageNode {
                deps: HashSet::new(),
                pbulk_weight: 10000,
                cpu_time: 0,
            },
        );
        packages.insert(
            pkg("light"),
            PackageNode {
                deps: HashSet::new(),
                pbulk_weight: 1,
                cpu_time: 0,
            },
        );
        let reverse_deps = HashMap::new();

        let mut sched = Scheduler::new(packages, reverse_deps, HashSet::new(), HashSet::new());
        assert_eq!(sched.poll(), Poll::Ready(Some(pkg("heavy"))));
        assert_eq!(sched.poll(), Poll::Ready(Some(pkg("light"))));
    }

    /**
     * CPU time breaks ties when total_weight and dep_count are equal.
     */
    #[test]
    fn cpu_time_tiebreak() {
        let mut packages: HashMap<String, PackageNode<String>> = HashMap::new();
        packages.insert(
            pkg("slow"),
            PackageNode {
                deps: HashSet::new(),
                pbulk_weight: 100,
                cpu_time: 5000,
            },
        );
        packages.insert(
            pkg("fast"),
            PackageNode {
                deps: HashSet::new(),
                pbulk_weight: 100,
                cpu_time: 100,
            },
        );
        let reverse_deps = HashMap::new();

        let mut sched = Scheduler::new(packages, reverse_deps, HashSet::new(), HashSet::new());
        assert_eq!(sched.poll(), Poll::Ready(Some(pkg("slow"))));
        assert_eq!(sched.poll(), Poll::Ready(Some(pkg("fast"))));
    }

    /**
     * Alphabetical name is the final tiebreak.
     */
    #[test]
    fn alphabetical_tiebreak() {
        let g = build_graph(&[], &["ccc", "aaa", "bbb"], 100);
        let mut sched = Scheduler::new(g.packages, g.reverse_deps, HashSet::new(), HashSet::new());
        assert_eq!(sched.poll(), Poll::Ready(Some(pkg("aaa"))));
        assert_eq!(sched.poll(), Poll::Ready(Some(pkg("bbb"))));
        assert_eq!(sched.poll(), Poll::Ready(Some(pkg("ccc"))));
    }

    #[test]
    fn mark_failure_ignores_reverse_deps_outside_live_graph() {
        let mut packages: HashMap<String, PackageNode<String>> = HashMap::new();
        packages.insert(
            pkg("dep"),
            PackageNode {
                deps: HashSet::new(),
                pbulk_weight: 100,
                cpu_time: 0,
            },
        );

        let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        reverse_deps
            .entry(pkg("dep"))
            .or_default()
            .insert(pkg("cached-dependent"));
        reverse_deps.entry(pkg("cached-dependent")).or_default();

        let done = [pkg("cached-dependent")].into_iter().collect();
        let mut sched = Scheduler::new(packages, reverse_deps, done, HashSet::new());

        let indirect = sched.mark_failure(&pkg("dep"));
        assert!(indirect.is_empty(), "cached dependents should be ignored");
    }

    /**
     * Uniform weights: total_weight == W * (1 + dep_count).
     */
    #[test]
    fn uniform_weight_identity() {
        let g = build_graph(&[("a", "b"), ("b", "c")], &["a", "b", "c"], 100);
        let (tw, dc) = scheduling_weights(&g.packages, &g.reverse_deps);
        for name in ["a", "b", "c"] {
            let w = tw[&pkg(name)];
            let d = dc[&pkg(name)];
            assert_eq!(
                w,
                100 * (1 + d),
                "total_weight({}) = 100 * (1 + {})",
                name,
                d
            );
        }
    }

    struct TestGraph {
        packages: HashMap<String, PackageNode<String>>,
        reverse_deps: HashMap<String, HashSet<String>>,
    }

    fn build_graph(edges: &[(&str, &str)], names: &[&str], weight: usize) -> TestGraph {
        let mut packages: HashMap<String, PackageNode<String>> = HashMap::new();
        let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        for name in names {
            packages.insert(
                pkg(name),
                PackageNode {
                    deps: HashSet::new(),
                    pbulk_weight: weight,
                    cpu_time: 0,
                },
            );
            reverse_deps.entry(pkg(name)).or_default();
        }
        for &(dep, dependent) in edges {
            packages
                .entry(pkg(dependent))
                .or_insert_with(|| PackageNode {
                    deps: HashSet::new(),
                    pbulk_weight: weight,
                    cpu_time: 0,
                })
                .deps
                .insert(pkg(dep));
            packages.entry(pkg(dep)).or_insert_with(|| PackageNode {
                deps: HashSet::new(),
                pbulk_weight: weight,
                cpu_time: 0,
            });
            reverse_deps
                .entry(pkg(dep))
                .or_default()
                .insert(pkg(dependent));
            reverse_deps.entry(pkg(dependent)).or_default();
        }
        TestGraph {
            packages,
            reverse_deps,
        }
    }

    /**
     * Build a small graph:
     *
     *   a -> b -> d
     *   a -> c -> d
     *        c -> e
     */
    fn small_graph() -> TestGraph {
        let edges = [("a", "b"), ("a", "c"), ("b", "d"), ("c", "d"), ("c", "e")];
        build_graph(&edges, &["a", "b", "c", "d", "e"], 10)
    }

    #[test]
    fn lifecycle_success() {
        let g = small_graph();
        let mut sched = Scheduler::new(g.packages, g.reverse_deps, HashSet::new(), HashSet::new());

        assert_eq!(sched.incoming_count(), 5);
        assert_eq!(sched.running_count(), 0);
        assert_eq!(sched.done_count(), 0);
        assert_eq!(sched.failed_count(), 0);

        assert_eq!(sched.poll(), Poll::Ready(Some(pkg("a"))));
        assert_eq!(sched.running_count(), 1);

        assert_eq!(sched.poll(), Poll::Pending);

        sched.mark_success(&pkg("a"));
        assert_eq!(sched.done_count(), 1);
        assert_eq!(sched.running_count(), 0);

        let first = match sched.poll() {
            Poll::Ready(Some(p)) => p,
            other => panic!("expected b or c, got {:?}", other),
        };
        assert!(
            first == pkg("b") || first == pkg("c"),
            "expected b or c, got {}",
            first
        );
        sched.mark_success(&first);

        let second = match sched.poll() {
            Poll::Ready(Some(p)) => p,
            other => panic!("expected b or c, got {:?}", other),
        };
        assert!(
            second == pkg("b") || second == pkg("c"),
            "expected b or c, got {}",
            second
        );
        sched.mark_success(&second);

        assert_eq!(sched.done_count(), 3);

        while let Poll::Ready(Some(p)) = sched.poll() {
            sched.mark_success(&p);
        }

        assert_eq!(sched.poll(), Poll::Ready(None));
        assert_eq!(sched.done_count(), 5);
    }

    #[test]
    fn lifecycle_failure() {
        let g = small_graph();
        let mut sched = Scheduler::new(g.packages, g.reverse_deps, HashSet::new(), HashSet::new());

        let Poll::Ready(Some(a)) = sched.poll() else {
            panic!("a should be ready");
        };
        sched.mark_success(&a);

        /*
         * Fail "c" -- its transitive dependents "d" and "e" should be
         * indirectly failed.  "b" depends only on "a" which succeeded,
         * so "b" should still be buildable.
         */
        let Poll::Ready(Some(p)) = sched.poll() else {
            panic!("b or c should be ready");
        };
        if p == pkg("c") {
            let indirect = sched.mark_failure(&pkg("c"));
            let broken: HashSet<String> = indirect.into_iter().collect();
            assert!(broken.contains(&pkg("d")), "d should be broken");
            assert!(broken.contains(&pkg("e")), "e should be broken");
            assert!(!broken.contains(&pkg("b")), "b should not be broken");
        } else {
            sched.mark_success(&p);
            assert_eq!(sched.poll(), Poll::Ready(Some(pkg("c"))));
            let indirect = sched.mark_failure(&pkg("c"));
            let broken: HashSet<String> = indirect.into_iter().collect();
            assert!(broken.contains(&pkg("d")), "d should be broken");
            assert!(broken.contains(&pkg("e")), "e should be broken");
        }

        assert_eq!(sched.failed_count(), 3);

        while let Poll::Ready(Some(p)) = sched.poll() {
            sched.mark_success(&p);
        }

        assert_eq!(sched.poll(), Poll::Ready(None));
    }

    /**
     * Verify remaining_depth correctly computes the longest chain
     * through dependents that are not done, failed, or running.
     *
     *   a -> b -> c
     *
     * remaining_depth skips nodes in done/failed/running, so
     * completing b makes c unreachable from a, reducing depth to 0.
     */
    #[test]
    fn remaining_depth_tracks_live_graph() {
        let g = build_graph(&[("a", "b"), ("b", "c")], &["a", "b", "c"], 10);
        let mut sched = Scheduler::new(g.packages, g.reverse_deps, HashSet::new(), HashSet::new());

        /* a -> b -> c: depth(a) = weight(b) + weight(c) = 20 */
        assert_eq!(sched.remaining_depth(&pkg("a")), 20);
        assert_eq!(sched.remaining_depth(&pkg("b")), 10);
        assert_eq!(sched.remaining_depth(&pkg("c")), 0);

        /* poll() auto-dispatches a; b and c still pending */
        let Poll::Ready(Some(a)) = sched.poll() else {
            panic!("a should be ready");
        };
        sched.mark_success(&a);
        assert_eq!(sched.remaining_depth(&pkg("a")), 20);

        /* poll() auto-dispatches b (now running); c still pending */
        assert!(matches!(sched.poll(), Poll::Ready(Some(_))));
        assert_eq!(
            sched.remaining_depth(&pkg("a")),
            0,
            "b is running so filtered out, c unreachable"
        );

        /* Complete b; c becomes ready */
        sched.mark_success(&pkg("b"));
        assert_eq!(
            sched.remaining_depth(&pkg("a")),
            0,
            "b is done so filtered out, c unreachable"
        );

        assert!(matches!(sched.poll(), Poll::Ready(Some(_))));
        sched.mark_success(&pkg("c"));
        assert_eq!(sched.remaining_depth(&pkg("a")), 0);
    }

    /**
     * Verify remaining_depth excludes failed dependents.
     *
     *   r -> a -> c
     *   r -> b
     *
     * After failing a (which cascades to c), only b is visible.
     */
    #[test]
    fn remaining_depth_excludes_failed() {
        let g = build_graph(
            &[("r", "a"), ("r", "b"), ("a", "c")],
            &["r", "a", "b", "c"],
            10,
        );
        let mut sched = Scheduler::new(g.packages, g.reverse_deps, HashSet::new(), HashSet::new());

        /* r -> a -> c and r -> b: depth(r) = 10 + 10 = 20 (via a -> c) */
        assert_eq!(sched.remaining_depth(&pkg("r")), 20);

        assert!(matches!(sched.poll(), Poll::Ready(Some(_))));
        sched.mark_success(&pkg("r"));

        /* Dispatch and succeed both a and b, then fail a's dependent c */
        let Poll::Ready(Some(p1)) = sched.poll() else {
            panic!("a or b should be ready");
        };
        let Poll::Ready(Some(p2)) = sched.poll() else {
            panic!("a or b should be ready");
        };

        /* Succeed whichever is b, fail whichever is a */
        let a = if p1 == pkg("a") { &p1 } else { &p2 };
        let b = if p1 == pkg("b") { &p1 } else { &p2 };
        sched.mark_success(b);
        let indirect = sched.mark_failure(a);
        assert!(
            indirect.contains(&pkg("c")),
            "c should be indirectly failed"
        );

        /*
         * b is done, a and c are failed -- all filtered out.
         * remaining_depth(r) = 0.
         */
        assert_eq!(sched.remaining_depth(&pkg("r")), 0);
    }

    /**
     * Non-uniform weights: heavier dependents contribute more.
     *
     *   a -> b (weight 500)
     *   a -> c (weight 1)
     *
     * a's total_weight = 10 + 500 + 1 = 511.
     */
    #[test]
    fn weighted_scheduling_scores() {
        let mut g = build_graph(&[("a", "b"), ("a", "c")], &["a", "b", "c"], 100);
        g.packages.get_mut(&pkg("a")).expect("a").pbulk_weight = 10;
        g.packages.get_mut(&pkg("b")).expect("b").pbulk_weight = 500;
        g.packages.get_mut(&pkg("c")).expect("c").pbulk_weight = 1;

        let (tw, dc) = scheduling_weights(&g.packages, &g.reverse_deps);

        assert_eq!(tw[&pkg("a")], 511, "a = 10 + 500 + 1");
        assert_eq!(dc[&pkg("a")], 2);
        assert_eq!(tw[&pkg("b")], 500, "b = self only");
        assert_eq!(dc[&pkg("b")], 0);
        assert_eq!(tw[&pkg("c")], 1, "c = self only");
        assert_eq!(dc[&pkg("c")], 0);
    }

    /**
     * Helper: build a scheduler with `n` independent packages (no deps).
     * Optionally give each package a different weight.
     */
    fn independent_sched(names: &[&str], weight_vals: &[usize]) -> Scheduler<String> {
        let mut packages: HashMap<String, PackageNode<String>> = HashMap::new();
        for (i, &name) in names.iter().enumerate() {
            packages.insert(
                pkg(name),
                PackageNode {
                    deps: HashSet::new(),
                    pbulk_weight: weight_vals.get(i).copied().unwrap_or(100),
                    cpu_time: 0,
                },
            );
        }
        Scheduler::new(packages, HashMap::new(), HashSet::new(), HashSet::new())
    }

    /**
     * Single build, nothing else pending: gets max_jobs.
     *
     * a -> b (b blocked on a).  Only a is ready.  After dispatching
     * a, ready is empty and incoming has only the blocked b, so a is
     * the sole buildable package.
     */
    #[test]
    fn jobs_sole_buildable_gets_max() {
        let g = build_graph(&[("a", "b")], &["a", "b"], 100);
        let mut sched = Scheduler::new(g.packages, g.reverse_deps, HashSet::new(), HashSet::new());
        sched.init_budget(16, 4);

        let Poll::Ready(Some(a)) = sched.poll() else {
            panic!("a should be ready");
        };
        assert_eq!(sched.request_make_jobs(&a), Some(16));
    }

    /**
     * Longer duration -> more jobs.
     *
     * 4 independent packages with different durations but no
     * dependency relationships.  The longest-running package
     * should get strictly more jobs than the shortest.
     */
    #[test]
    fn jobs_longer_duration_gets_more() {
        let names = ["short", "medium", "long", "huge"];
        let mut sched = independent_sched(&names, &[10, 100, 1000, 10000]);
        sched.init_budget(16, 4);

        let mut allocs: HashMap<String, usize> = HashMap::new();
        for _ in 0..4 {
            let Poll::Ready(Some(p)) = sched.poll() else {
                panic!("should be ready");
            };
            let j = sched.request_make_jobs(&p).expect("budget initialized");
            allocs.insert(p, j);
        }

        assert!(
            allocs[&pkg("huge")] > allocs[&pkg("short")],
            "huge ({}) must get more jobs than short ({})",
            allocs[&pkg("huge")],
            allocs[&pkg("short")]
        );
        assert!(
            allocs[&pkg("long")] > allocs[&pkg("short")],
            "long ({}) must get more jobs than short ({})",
            allocs[&pkg("long")],
            allocs[&pkg("short")]
        );
        for (_, &j) in &allocs {
            assert!(j >= 1, "every package gets at least 1");
            assert!(j <= 16, "no package exceeds max_jobs");
        }
    }

    /**
     * Equal duration, equal importance -> equal allocation.
     *
     * 4 independent packages with the same duration and no
     * dependency relationships (equal importance).  All should
     * receive the same number of jobs.
     */
    #[test]
    fn jobs_equal_score_equal_allocation() {
        let names = ["p0", "p1", "p2", "p3"];
        let mut sched = independent_sched(&names, &[100, 100, 100, 100]);
        sched.init_budget(16, 4);

        let mut allocs = Vec::new();
        for _ in 0..4 {
            let Poll::Ready(Some(p)) = sched.poll() else {
                panic!("should be ready");
            };
            allocs.push(sched.request_make_jobs(&p).expect("budget initialized"));
        }

        let first = allocs[0];
        for (i, &j) in allocs.iter().enumerate() {
            assert_eq!(
                j, first,
                "package {} got {} (expected same as first: {})",
                i, j, first
            );
        }
    }

    /**
     * Dependency importance boosts jobs allocation.
     *
     * Graph:
     *   root (w=100) -> d1 -> d2 -> d3
     *   leaf (w=100)
     *
     * root and leaf have the same build duration, but root has 3
     * transitive dependents while leaf has 0.  root should get
     * strictly more jobs than leaf.
     */
    #[test]
    fn jobs_importance_boosts_allocation() {
        let mut g = build_graph(
            &[("root", "d1"), ("d1", "d2"), ("d2", "d3")],
            &["root", "d1", "d2", "d3", "leaf"],
            100,
        );
        g.reverse_deps.entry(pkg("leaf")).or_default();

        let mut sched = Scheduler::new(g.packages, g.reverse_deps, HashSet::new(), HashSet::new());
        sched.init_budget(16, 4);

        let mut dispatched = Vec::new();
        while dispatched.len() < 2 {
            if let Poll::Ready(Some(p)) = sched.poll() {
                dispatched.push(p);
            } else {
                break;
            }
        }
        assert!(dispatched.contains(&pkg("root")));
        assert!(dispatched.contains(&pkg("leaf")));

        let root_jobs = sched.request_make_jobs(&pkg("root")).expect("budget");
        let leaf_jobs = sched.request_make_jobs(&pkg("leaf")).expect("budget");
        assert!(
            root_jobs > leaf_jobs,
            "root (3 deps, {} jobs) should get more than leaf (0 deps, {} jobs)",
            root_jobs,
            leaf_jobs
        );
    }

    /**
     * Heavy package gets more jobs, even after being unblocked.
     *
     * gate (w=50) -> critical (w=400) -> c1 -> c2 -> c3
     * leaf1 (w=50), leaf2 (w=50), leaf3 (w=50)
     *
     * critical has both high duration and high dependency importance.
     * After gate completes and critical becomes dispatchable, it
     * should receive more jobs than the leaves.
     */
    #[test]
    fn jobs_heavy_package_after_unblock() {
        let edges = [
            ("gate", "critical"),
            ("critical", "c1"),
            ("c1", "c2"),
            ("c2", "c3"),
        ];
        let mut g = build_graph(
            &edges,
            &[
                "gate", "critical", "c1", "c2", "c3", "leaf1", "leaf2", "leaf3",
            ],
            100,
        );
        g.packages.get_mut(&pkg("gate")).expect("gate").pbulk_weight = 50;
        g.packages
            .get_mut(&pkg("critical"))
            .expect("critical")
            .pbulk_weight = 400;
        for name in ["leaf1", "leaf2", "leaf3"] {
            g.packages.get_mut(&pkg(name)).expect(name).pbulk_weight = 50;
            g.reverse_deps.entry(pkg(name)).or_default();
        }

        let mut sched = Scheduler::new(g.packages, g.reverse_deps, HashSet::new(), HashSet::new());
        sched.init_budget(16, 4);

        let mut dispatched = Vec::new();
        for _ in 0..4 {
            let Poll::Ready(Some(p)) = sched.poll() else {
                panic!("should be ready");
            };
            dispatched.push(p);
        }
        assert!(dispatched.contains(&pkg("gate")));

        let leaves: Vec<String> = dispatched
            .iter()
            .filter(|p| p.starts_with("leaf"))
            .cloned()
            .collect();
        assert_eq!(leaves.len(), 3);

        let leaf_jobs = sched
            .request_make_jobs(&leaves[0])
            .expect("budget initialized");

        sched.mark_success(&pkg("gate"));

        let Poll::Ready(Some(crit)) = sched.poll() else {
            panic!("critical should be ready after gate succeeds");
        };
        assert_eq!(crit, pkg("critical"));

        let crit_jobs = sched.request_make_jobs(&crit).expect("budget initialized");
        assert!(
            crit_jobs > leaf_jobs,
            "critical ({}) must get more than leaf ({})",
            crit_jobs,
            leaf_jobs
        );
    }

    /** All allocations are within [1, max_jobs]. */
    #[test]
    fn jobs_always_within_bounds() {
        let names = ["tiny", "small", "big", "huge"];
        let mut sched = independent_sched(&names, &[1, 10, 5000, 50000]);
        sched.init_budget(16, 4);

        for _ in 0..4 {
            let Poll::Ready(Some(p)) = sched.poll() else {
                panic!("should be ready");
            };
            let j = sched.request_make_jobs(&p).expect("budget initialized");
            assert!(j >= 1, "{} got 0 jobs", p);
            assert!(j <= 16, "{} got {} jobs (max 16)", p, j);
        }
    }
}
