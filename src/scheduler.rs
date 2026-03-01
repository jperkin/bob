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
 * Build scheduling using critical-path ordering.
 *
 * Each package is scored by the longest chain of dependents below it
 * (the critical path), not the total number of dependents.  This
 * distinction matters because fan-out is parallelisable but chain
 * depth is not.
 *
 * For example, given two independent roots with equal build weights:
 *
 * ```text
 *     A          X
 *     |         /|\
 *     B        C D E
 *     |
 *     F
 * ```
 *
 * A naive sum-of-dependents score picks X first (4 total packages in
 * its subtree vs 3 in A's).  But with two or more workers, C/D/E all
 * build in parallel -- X's subtree only takes two serial steps.  A's
 * subtree is three steps deep (A, B, F) and cannot be parallelised,
 * so starting A first produces a shorter overall build.
 *
 * Critical-path scores are precomputed once at construction using a
 * reverse-topological traversal.  A ready set of packages whose
 * dependencies are all satisfied is maintained incrementally, giving
 * O(1) dispatch via [`Scheduler::poll`].
 */

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::hash::Hash;
use std::sync::mpsc::Sender;
use std::task::Poll;
use tracing::debug;

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
 * Sort key for ready packages: highest critical-path score first,
 * then lexicographically by name for determinism.
 *
 * `Reverse` wrapping on score gives descending order in BTreeSet.
 */
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ReadyKey<K: Ord> {
    score: std::cmp::Reverse<usize>,
    pkg: K,
}

/**
 * Dependency-aware build scheduler using critical-path ordering.
 *
 * Tracks the live dependency graph and selects the next package to build
 * based on precomputed critical-path scores.  The dependency invariant is
 * enforced: a package is only dispatched by [`poll`](Self::poll) when all
 * its dependencies have completed.
 */
pub struct Scheduler<K: Ord> {
    incoming: HashMap<K, HashSet<K>>,
    reverse_deps: HashMap<K, HashSet<K>>,
    ready: BTreeSet<ReadyKey<K>>,
    scores: HashMap<K, usize>,
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
 * three inputs (in priority order):
 *
 *   1. Dependency importance -- how many packages transitively depend
 *      on this one.  cwrappers (depended on by everything) gets the
 *      highest importance; leaf packages get 0.  Finishing important
 *      packages faster unblocks more work.
 *
 *   2. Build duration -- historical wall-clock time in seconds.
 *      Longer builds save more absolute time from extra cores.
 *      A 3-hour build at -j8 vs -j4 saves far more than a 30-second
 *      build at the same ratio.
 *
 *   3. Parallelism efficiency -- how effectively a package uses
 *      multiple cores, measured as cpu_time / (wall_time * jobs).
 *      Lower priority: dampens allocation for packages that cannot
 *      use extra cores, so they go to packages that can.
 *
 * The combined score for each package is:
 *
 *   score = duration^DURATION_EXP
 *         * (1 + dep_count)^IMPORTANCE_EXP
 *         * efficiency^EFFICIENCY_EXP
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
 * Exponent for parallelism efficiency.  Controls how much
 * inefficient packages are penalised.  0.2 is a gentle dampener
 * (efficiency 0.1 -> 0.63x, efficiency 0.5 -> 0.87x).
 */
const EFFICIENCY_EXP: f64 = 0.2;

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
     * `incoming` maps each package to its set of unsatisfied dependencies.
     * `reverse_deps` maps each package to the set of packages that depend
     * on it.  `weights` provides per-package build weight (e.g. from
     * PBULK_WEIGHT); packages not in the map default to 100.
     *
     * Packages already in `done` or `failed` should have been removed from
     * `incoming` before calling this constructor.
     */
    pub fn new(
        incoming: HashMap<K, HashSet<K>>,
        reverse_deps: HashMap<K, HashSet<K>>,
        weights: HashMap<K, usize>,
        done: HashSet<K>,
        failed: HashSet<K>,
    ) -> Self {
        let scores = critical_path_scores(&incoming, &reverse_deps, |pkg| {
            weights.get(pkg).copied().unwrap_or(100)
        });

        let mut ready = BTreeSet::new();
        for (pkg, deps) in &incoming {
            if deps.is_empty() {
                let score = scores.get(pkg).copied().unwrap_or(0);
                ready.insert(ReadyKey {
                    score: std::cmp::Reverse(score),
                    pkg: pkg.clone(),
                });
            }
        }

        Self {
            incoming,
            reverse_deps,
            ready,
            scores,
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
                        let score = self.scores.get(dependent).copied().unwrap_or(0);
                        self.ready.insert(ReadyKey {
                            score: std::cmp::Reverse(score),
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
            if broken.contains(&badpkg) {
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
            let score = self.scores.get(&pkg).copied().unwrap_or(0);
            self.ready.remove(&ReadyKey {
                score: std::cmp::Reverse(score),
                pkg: pkg.clone(),
            });
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
        self.weights.get(pkg).copied().unwrap_or(100)
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
     * Pre-computes a jobs value for every package from three inputs:
     * build duration (from `self.weights`), dependency importance
     * (computed from `self.reverse_deps`), and parallelism efficiency
     * (from the `efficiency` map, where values are in 0.0..=1.0;
     * packages not in the map default to 1.0).
     */
    pub fn init_budget(
        &mut self,
        max_jobs: usize,
        build_threads: usize,
        efficiency: &HashMap<K, f64>,
    ) {
        let fair_share = max_jobs / build_threads.max(1);
        let dep_counts = self.transitive_dependent_counts();

        let mut scores: Vec<(K, f64)> = Vec::new();
        for pkg in self.incoming.keys().chain(self.running.iter()) {
            let duration = self.weights.get(pkg).copied().unwrap_or(0) as f64;
            let deps = dep_counts.get(pkg).copied().unwrap_or(0) as f64;
            let eff = efficiency.get(pkg).copied().unwrap_or(1.0);

            let score = duration.max(1.0).powf(DURATION_EXP)
                * (1.0 + deps).powf(IMPORTANCE_EXP)
                * eff.max(0.01).powf(EFFICIENCY_EXP);
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
     * Compute the number of transitive dependents for each package.
     *
     * For each package in `incoming`, counts how many other packages
     * transitively depend on it (i.e. the size of its reachable set
     * through `reverse_deps`).
     */
    fn transitive_dependent_counts(&self) -> HashMap<K, usize> {
        let mut counts: HashMap<&K, usize> = HashMap::new();
        for pkg in self.incoming.keys() {
            let mut visited: HashSet<&K> = HashSet::new();
            let mut queue: VecDeque<&K> = VecDeque::new();
            if let Some(rdeps) = self.reverse_deps.get(pkg) {
                for r in rdeps {
                    if self.incoming.contains_key(r) && visited.insert(r) {
                        queue.push_back(r);
                    }
                }
            }
            while let Some(p) = queue.pop_front() {
                if let Some(rdeps) = self.reverse_deps.get(p) {
                    for r in rdeps {
                        if self.incoming.contains_key(r) && visited.insert(r) {
                            queue.push_back(r);
                        }
                    }
                }
            }
            counts.insert(pkg, visited.len());
        }
        counts.into_iter().map(|(k, v)| (k.clone(), v)).collect()
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
 * Compute critical-path scores for all packages.
 *
 * The critical path score for a package is the longest weighted chain
 * through its transitive dependents (using `max` at each node, not `sum`).
 * Uses a reverse-topological traversal: leaves (packages with no
 * dependents) are processed first, then packages whose dependents have
 * all been scored.
 */
fn critical_path_scores<K>(
    incoming: &HashMap<K, HashSet<K>>,
    reverse_deps: &HashMap<K, HashSet<K>>,
    weight: impl Fn(&K) -> usize,
) -> HashMap<K, usize>
where
    K: Eq + Hash + Clone + Ord,
{
    /*
     * Count how many reverse deps (dependents) each package has.
     * Packages with zero dependents are the leaves of the reverse graph.
     */
    let mut pending: HashMap<&K, usize> = HashMap::new();
    for pkg in incoming.keys() {
        let count = reverse_deps
            .get(pkg)
            .map(|s| s.iter().filter(|r| incoming.contains_key(*r)).count())
            .unwrap_or(0);
        pending.insert(pkg, count);
    }

    let mut queue: VecDeque<&K> = pending
        .iter()
        .filter(|(_, c)| **c == 0)
        .map(|(&p, _)| p)
        .collect();

    let mut scores: HashMap<&K, usize> = HashMap::new();

    while let Some(pkg) = queue.pop_front() {
        /*
         * Score = max(weight(dependent) + score(dependent)) over all
         * dependents that are in our incoming set.  This gives the
         * longest chain, not the sum.
         */
        let score = reverse_deps
            .get(pkg)
            .map(|rdeps| {
                rdeps
                    .iter()
                    .filter(|r| incoming.contains_key(*r))
                    .filter_map(|r| scores.get(r).map(|&s| weight(r) + s))
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        scores.insert(pkg, score);

        if let Some(deps) = incoming.get(pkg) {
            for dep in deps {
                if let Some(c) = pending.get_mut(dep) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        queue.push_back(dep);
                    }
                }
            }
        }
    }

    scores.into_iter().map(|(k, v)| (k.clone(), v)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(s: &str) -> String {
        s.to_string()
    }

    /**
     * Verify that the critical path heuristic prefers a deep chain over a
     * wide fan-out when both roots are ready.
     */
    #[test]
    fn deep_chain_preferred_over_wide_fan() {
        let chain_edges: Vec<(&str, &str)> = vec![("x-1.0", "y-1.0"), ("y-1.0", "z-1.0")];
        let mut incoming: HashMap<String, HashSet<String>> = HashMap::new();
        let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        let mut weight_map: HashMap<String, usize> = HashMap::new();

        for &(dep, dependent) in &chain_edges {
            incoming.entry(pkg(dependent)).or_default().insert(pkg(dep));
            incoming.entry(pkg(dep)).or_default();
            reverse_deps
                .entry(pkg(dep))
                .or_default()
                .insert(pkg(dependent));
            reverse_deps.entry(pkg(dependent)).or_default();
        }
        for name in ["x-1.0", "y-1.0", "z-1.0"] {
            weight_map.insert(pkg(name), 100);
        }

        incoming.entry(pkg("w-1.0")).or_default();
        reverse_deps.entry(pkg("w-1.0")).or_default();
        weight_map.insert(pkg("w-1.0"), 100);
        for i in 0..50 {
            let fan = format!("f{}-1.0", i);
            incoming
                .entry(fan.clone())
                .or_default()
                .insert(pkg("w-1.0"));
            reverse_deps
                .entry(pkg("w-1.0"))
                .or_default()
                .insert(fan.clone());
            reverse_deps.entry(fan.clone()).or_default();
            weight_map.insert(fan, 1);
        }

        let mut sched = Scheduler::new(
            incoming,
            reverse_deps,
            weight_map,
            HashSet::new(),
            HashSet::new(),
        );
        assert_eq!(sched.poll(), Poll::Ready(Some(pkg("x-1.0"))));
    }

    /**
     * Verify that the critical path score correctly distinguishes
     * max-chain from sum: two packages with equal subtree sums but
     * different critical paths should be ordered by critical path.
     */
    #[test]
    fn critical_path_beats_subtree_sum() {
        let mut incoming: HashMap<String, HashSet<String>> = HashMap::new();
        let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        let mut weight_map: HashMap<String, usize> = HashMap::new();

        for &(dep, dependent) in &[("a-1.0", "b-1.0"), ("b-1.0", "c-1.0")] {
            incoming.entry(pkg(dependent)).or_default().insert(pkg(dep));
            incoming.entry(pkg(dep)).or_default();
            reverse_deps
                .entry(pkg(dep))
                .or_default()
                .insert(pkg(dependent));
            reverse_deps.entry(pkg(dependent)).or_default();
        }
        for name in ["a-1.0", "b-1.0", "c-1.0"] {
            weight_map.insert(pkg(name), 100);
        }

        incoming.entry(pkg("x-1.0")).or_default();
        reverse_deps.entry(pkg("x-1.0")).or_default();
        weight_map.insert(pkg("x-1.0"), 100);
        for i in 0..200 {
            let fan = format!("y{}-1.0", i);
            incoming
                .entry(fan.clone())
                .or_default()
                .insert(pkg("x-1.0"));
            reverse_deps
                .entry(pkg("x-1.0"))
                .or_default()
                .insert(fan.clone());
            reverse_deps.entry(fan.clone()).or_default();
            weight_map.insert(fan, 1);
        }

        let mut sched = Scheduler::new(
            incoming,
            reverse_deps,
            weight_map,
            HashSet::new(),
            HashSet::new(),
        );
        assert_eq!(sched.poll(), Poll::Ready(Some(pkg("a-1.0"))));
    }

    struct TestGraph {
        incoming: HashMap<String, HashSet<String>>,
        reverse_deps: HashMap<String, HashSet<String>>,
        weights: HashMap<String, usize>,
    }

    /**
     * Build a small graph:
     *
     *   a -> b -> d
     *   a -> c -> d
     *        c -> e
     */
    fn small_graph() -> TestGraph {
        let edges: Vec<(&str, &str)> =
            vec![("a", "b"), ("a", "c"), ("b", "d"), ("c", "d"), ("c", "e")];
        let mut incoming: HashMap<String, HashSet<String>> = HashMap::new();
        let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        for &(dep, dependent) in &edges {
            incoming.entry(pkg(dependent)).or_default().insert(pkg(dep));
            incoming.entry(pkg(dep)).or_default();
            reverse_deps
                .entry(pkg(dep))
                .or_default()
                .insert(pkg(dependent));
            reverse_deps.entry(pkg(dependent)).or_default();
        }
        let mut weights: HashMap<String, usize> = HashMap::new();
        for name in ["a", "b", "c", "d", "e"] {
            weights.insert(pkg(name), 10);
        }
        TestGraph {
            incoming,
            reverse_deps,
            weights,
        }
    }

    #[test]
    fn lifecycle_success() {
        let g = small_graph();
        let mut sched = Scheduler::new(
            g.incoming,
            g.reverse_deps,
            g.weights,
            HashSet::new(),
            HashSet::new(),
        );

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
        let mut sched = Scheduler::new(
            g.incoming,
            g.reverse_deps,
            g.weights,
            HashSet::new(),
            HashSet::new(),
        );

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
        let edges: Vec<(&str, &str)> = vec![("a", "b"), ("b", "c")];
        let mut incoming: HashMap<String, HashSet<String>> = HashMap::new();
        let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        let mut weights: HashMap<String, usize> = HashMap::new();
        for &(dep, dependent) in &edges {
            incoming.entry(pkg(dependent)).or_default().insert(pkg(dep));
            incoming.entry(pkg(dep)).or_default();
            reverse_deps
                .entry(pkg(dep))
                .or_default()
                .insert(pkg(dependent));
            reverse_deps.entry(pkg(dependent)).or_default();
        }
        for name in ["a", "b", "c"] {
            weights.insert(pkg(name), 10);
        }
        let mut sched = Scheduler::new(
            incoming,
            reverse_deps,
            weights,
            HashSet::new(),
            HashSet::new(),
        );

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
        let edges: Vec<(&str, &str)> = vec![("r", "a"), ("r", "b"), ("a", "c")];
        let mut incoming: HashMap<String, HashSet<String>> = HashMap::new();
        let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        let mut weights: HashMap<String, usize> = HashMap::new();
        for &(dep, dependent) in &edges {
            incoming.entry(pkg(dependent)).or_default().insert(pkg(dep));
            incoming.entry(pkg(dep)).or_default();
            reverse_deps
                .entry(pkg(dep))
                .or_default()
                .insert(pkg(dependent));
            reverse_deps.entry(pkg(dependent)).or_default();
        }
        for name in ["r", "a", "b", "c"] {
            weights.insert(pkg(name), 10);
        }
        let mut sched = Scheduler::new(
            incoming,
            reverse_deps,
            weights,
            HashSet::new(),
            HashSet::new(),
        );

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

    #[test]
    fn weighted_critical_path_scores() {
        let mut incoming: HashMap<String, HashSet<String>> = HashMap::new();
        let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        let mut weights: HashMap<String, usize> = HashMap::new();

        /*
         *   a -> b (weight 500)
         *   a -> c (weight 1)
         *
         * a's critical path should go through b (the heavier dependent).
         */
        for &(dep, dependent) in &[("a", "b"), ("a", "c")] {
            incoming.entry(pkg(dependent)).or_default().insert(pkg(dep));
            incoming.entry(pkg(dep)).or_default();
            reverse_deps
                .entry(pkg(dep))
                .or_default()
                .insert(pkg(dependent));
            reverse_deps.entry(pkg(dependent)).or_default();
        }
        weights.insert(pkg("a"), 10);
        weights.insert(pkg("b"), 500);
        weights.insert(pkg("c"), 1);

        let scores = critical_path_scores(&incoming, &reverse_deps, |p| {
            weights.get(p).copied().unwrap_or(100)
        });

        assert_eq!(
            scores.get(&pkg("a")).copied().unwrap_or(0),
            500,
            "a's score should be weight(b) = 500"
        );
        assert_eq!(
            scores.get(&pkg("b")).copied().unwrap_or(0),
            0,
            "b is a leaf, score 0"
        );
    }

    /**
     * Helper: build a scheduler with `n` independent packages (no deps).
     * Optionally give each package a different weight.
     */
    fn independent_sched(names: &[&str], weight_vals: &[usize]) -> Scheduler<String> {
        let mut incoming: HashMap<String, HashSet<String>> = HashMap::new();
        let reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        let mut weights: HashMap<String, usize> = HashMap::new();
        for (i, &name) in names.iter().enumerate() {
            incoming.insert(pkg(name), HashSet::new());
            let w = weight_vals.get(i).copied().unwrap_or(100);
            weights.insert(pkg(name), w);
        }
        Scheduler::new(
            incoming,
            reverse_deps,
            weights,
            HashSet::new(),
            HashSet::new(),
        )
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
        let edges = vec![("a", "b")];
        let mut incoming: HashMap<String, HashSet<String>> = HashMap::new();
        let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        let mut weights: HashMap<String, usize> = HashMap::new();
        for &(dep, dependent) in &edges {
            incoming.entry(pkg(dependent)).or_default().insert(pkg(dep));
            incoming.entry(pkg(dep)).or_default();
            reverse_deps
                .entry(pkg(dep))
                .or_default()
                .insert(pkg(dependent));
            reverse_deps.entry(pkg(dependent)).or_default();
        }
        weights.insert(pkg("a"), 100);
        weights.insert(pkg("b"), 100);

        let mut sched = Scheduler::new(
            incoming,
            reverse_deps,
            weights,
            HashSet::new(),
            HashSet::new(),
        );
        sched.init_budget(16, 4, &HashMap::new());

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
        sched.init_budget(16, 4, &HashMap::new());

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
        sched.init_budget(16, 4, &HashMap::new());

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
        let chain: Vec<(&str, &str)> = vec![("root", "d1"), ("d1", "d2"), ("d2", "d3")];
        let mut incoming: HashMap<String, HashSet<String>> = HashMap::new();
        let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        let mut weights: HashMap<String, usize> = HashMap::new();

        for &(dep, dependent) in &chain {
            incoming.entry(pkg(dependent)).or_default().insert(pkg(dep));
            incoming.entry(pkg(dep)).or_default();
            reverse_deps
                .entry(pkg(dep))
                .or_default()
                .insert(pkg(dependent));
            reverse_deps.entry(pkg(dependent)).or_default();
        }
        for name in ["root", "d1", "d2", "d3"] {
            weights.insert(pkg(name), 100);
        }
        incoming.insert(pkg("leaf"), HashSet::new());
        weights.insert(pkg("leaf"), 100);

        let mut sched = Scheduler::new(
            incoming,
            reverse_deps,
            weights,
            HashSet::new(),
            HashSet::new(),
        );
        sched.init_budget(16, 4, &HashMap::new());

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
        let edges: Vec<(&str, &str)> = vec![
            ("gate", "critical"),
            ("critical", "c1"),
            ("c1", "c2"),
            ("c2", "c3"),
        ];
        let mut incoming: HashMap<String, HashSet<String>> = HashMap::new();
        let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        let mut weights: HashMap<String, usize> = HashMap::new();

        for &(dep, dependent) in &edges {
            incoming.entry(pkg(dependent)).or_default().insert(pkg(dep));
            incoming.entry(pkg(dep)).or_default();
            reverse_deps
                .entry(pkg(dep))
                .or_default()
                .insert(pkg(dependent));
            reverse_deps.entry(pkg(dependent)).or_default();
        }
        weights.insert(pkg("gate"), 50);
        weights.insert(pkg("critical"), 400);
        for name in ["c1", "c2", "c3"] {
            weights.insert(pkg(name), 100);
        }

        for name in ["leaf1", "leaf2", "leaf3"] {
            incoming.insert(pkg(name), HashSet::new());
            weights.insert(pkg(name), 50);
        }

        let mut sched = Scheduler::new(
            incoming,
            reverse_deps,
            weights,
            HashSet::new(),
            HashSet::new(),
        );
        sched.init_budget(16, 4, &HashMap::new());

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

    /**
     * Low efficiency reduces job allocation.
     *
     * Two packages with identical duration and no dependents.
     * One has perfect efficiency (1.0), the other has poor
     * efficiency (0.1).  The efficient package should get more.
     */
    #[test]
    fn jobs_efficiency_dampens_allocation() {
        let names = ["efficient", "inefficient"];
        let mut sched = independent_sched(&names, &[1000, 1000]);
        let mut eff: HashMap<String, f64> = HashMap::new();
        eff.insert(pkg("efficient"), 1.0);
        eff.insert(pkg("inefficient"), 0.1);
        sched.init_budget(16, 2, &eff);

        let mut allocs: HashMap<String, usize> = HashMap::new();
        for _ in 0..2 {
            let Poll::Ready(Some(p)) = sched.poll() else {
                panic!("should be ready");
            };
            let j = sched.request_make_jobs(&p).expect("budget initialized");
            allocs.insert(p, j);
        }

        assert!(
            allocs[&pkg("efficient")] > allocs[&pkg("inefficient")],
            "efficient ({}) should get more than inefficient ({})",
            allocs[&pkg("efficient")],
            allocs[&pkg("inefficient")]
        );
    }

    /** All allocations are within [1, max_jobs]. */
    #[test]
    fn jobs_always_within_bounds() {
        let names = ["tiny", "small", "big", "huge"];
        let mut sched = independent_sched(&names, &[1, 10, 5000, 50000]);
        sched.init_budget(16, 4, &HashMap::new());

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
