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

/**
 * MAKE_JOBS budget tracking for the scheduler.
 *
 * Distributes a fixed CPU budget across concurrent builds using
 * weight-proportional allocation with per-package history caps.
 */
struct Budget<K> {
    max_jobs: usize,
    build_threads: usize,
    caps: HashMap<K, usize>,
    budget_weights: HashMap<K, usize>,
    locked: HashMap<K, usize>,
    excluded: HashSet<K>,
    reserved: usize,
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
     * `caps` maps packages to their historical parallelism cap
     * (ceil(cpu_time / wall_time)).  Packages not in `caps` are
     * uncapped (effective cap = max_jobs).
     */
    pub fn init_budget(&mut self, max_jobs: usize, build_threads: usize, caps: HashMap<K, usize>) {
        self.budget = Some(Budget {
            max_jobs,
            build_threads,
            caps,
            budget_weights: HashMap::new(),
            locked: HashMap::new(),
            excluded: HashSet::new(),
            reserved: 0,
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

    /*
     * MAKE_JOBS Budget Allocation -- Design Notes
     * ============================================
     *
     * Problem: N build threads share a pool of max_jobs CPU cores.
     * Each thread runs one package at a time through serial phases
     * (overhead, configure) and parallel phases (build).  When a
     * package enters a parallel phase it calls request_make_jobs()
     * to learn how many cores to use; when it leaves the phase it
     * calls release_make_jobs() to return them.  Packages that are
     * not MAKE_JOBS_SAFE are excluded and always run -j1.
     *
     * The algorithm maintains these hard invariants (verified by
     * unit tests):
     *
     *   1. Sum of all allocations <= max_jobs
     *   2. No allocation exceeds the package's scaling cap
     *   3. Equal-weight packages get equal shares
     *   4. Higher-weight packages get strictly more cores
     *
     * These invariants make the algorithm predictable: a user
     * watching the build can understand why each package got the
     * jobs count it did.
     *
     * The core formula is weight-proportional allocation with
     * cap clamping and waste redistribution (locked_waste/absorb).
     * Imputation scales known weights to estimate competition from
     * packages not yet in the budget.
     *
     *
     * Overcommit strategy
     * -------------------
     *
     * Rather than complicating the allocation formula to squeeze
     * more throughput from a fixed core budget, the recommended
     * approach is overcommit: set max_jobs higher than physical
     * cores (e.g., 1.5x-2x).  This works because:
     *
     * - Build threads spend significant time in serial phases
     *   (overhead, configure) where they use exactly 1 core.
     *   Overcommit lets the parallel phases of other packages
     *   use those notionally-reserved cores.
     *
     * - Scaling caps derived from history (cpu/wall ratio) limit
     *   poorly-scaling packages.  With a larger virtual pool,
     *   well-scaling packages can claim more cores without the
     *   cap being the binding constraint, while the cap still
     *   prevents waste on packages that cannot use the cores.
     *
     * - The invariants hold with any max_jobs value, so the
     *   algorithm remains simple and predictable.
     *
     * Simulation results (71-package mutt build, 4 threads,
     * 16 physical cores, actual build 70m23s, critical-path
     * minimum 52m44s):
     *
     *   max_jobs=16:  60m25s  (no overcommit)
     *   max_jobs=20:  59m19s  (1.25x)
     *   max_jobs=24:  58m30s  (1.5x)
     *   max_jobs=32:  57m14s  (2x)
     *
     *
     * Experiments tried and rejected
     * ------------------------------
     *
     * The following algorithm changes were tested against the mutt
     * simulation.  All of them either broke the hard invariants or
     * produced worse results.  Overcommit at max_jobs=32 achieved
     * the same throughput (57m14s) while preserving all invariants.
     *
     * - Passive/dead-end worker classification: Discounting
     *   workers in serial phases or those whose completion would
     *   not unblock new work.  Helped modestly (59m46s at 16
     *   cores) but added complexity and interacted poorly with
     *   other changes.
     *
     * - Real ready-queue weights (instead of imputation): Using
     *   actual weights of ready packages rather than scaling known
     *   weights.  Improved results (58m23s) because imputation
     *   inflated estimated_total when ready packages were much
     *   lighter than active builders.  However, this complicated
     *   the estimated_total calculation and was subsumed by the
     *   surplus bonus (which it was a prerequisite for).
     *
     * - Two-tier surplus bonus: After computing the capped target,
     *   distributing leftover cores proportional to weight.  Best
     *   single-algorithm result (57m28s at 16 cores) but violated
     *   invariants 1 and 2 -- allocations could exceed both the
     *   cap and max_jobs.  Simple overcommit to 32 cores achieved
     *   57m14s while keeping all invariants intact.
     *
     * - Subtracting passive cores from available: Shrunk the pool,
     *   starving budget participants.  Result: 60m55s.
     *
     * - Using in_budget as concurrent (ignoring ready queue):
     *   First builders over-allocated.  Result: 61m20s.
     *
     * - Giving ALL surplus to requester: First builder locked
     *   everything.  Result: 62m33s.
     *
     * - Halving effective_pending: Current builders over-allocated,
     *   starving the heavy arrival.  Result: 60m28s.
     *
     * - Removing caps entirely: Poorly-scaling packages grabbed
     *   cores better used by well-scaling ones.  Result: 58m01s
     *   at 16 cores.  (Notably, no-caps + overcommit does very
     *   well in simulation -- 55m59s at 24 cores -- but caps
     *   serve a purpose under real contention with many threads.)
     */

    /**
     * Compute MAKE_JOBS allocation for a package entering a build phase.
     *
     * Returns `None` if the budget is not initialized.  The allocation
     * uses weight-proportional distribution with imputation for workers
     * not yet in the budget.
     */
    pub fn request_make_jobs(&mut self, pkg: &K) -> Option<usize> {
        let budget = self.budget.as_ref()?;
        let sole = self.is_sole_buildable(pkg);
        let excluded_running = self
            .running
            .iter()
            .filter(|p| budget.excluded.contains(*p))
            .count();
        let potential = self.running.len().saturating_sub(excluded_running);
        let in_budget = budget.locked.len() + 1;
        let running_plus_ready = potential.max(in_budget) + self.ready.len();

        /*
         * Look ahead at packages one completion away from dispatch:
         * all deps are running or done.  The heaviest pending weight
         * inflates the denominator to prevent current workers from
         * over-allocating when a high-priority package is about to
         * arrive.
         *
         * Only the maximum weight is used, not the sum of all pending.
         * Pending packages arrive one at a time and the proportional
         * formula adjusts as each enters; summing them all would
         * over-dampen current allocations as if they competed
         * simultaneously.
         *
         * The pending count feeds into the pipeline estimate for
         * active_threads, so the budget accounts for upcoming
         * dispatches even when the ready queue is empty.
         */
        let mut pending_count: usize = 0;
        let mut pending_weight: usize = 0;
        for (p, deps) in &self.incoming {
            if !deps.is_empty()
                && !self.running.contains(p)
                && !deps.contains(pkg)
                && deps
                    .iter()
                    .all(|d| self.running.contains(d) || self.done.contains(d))
            {
                pending_count += 1;
                let w = self.weights.get(p).copied().unwrap_or(100);
                if w > pending_weight {
                    pending_weight = w;
                }
            }
        }

        let budget = self.budget.as_mut()?;
        let concurrent = running_plus_ready.min(budget.build_threads).max(1);

        if sole {
            let jobs = budget.max_jobs;
            debug!(
                %pkg, jobs,
                max_jobs = budget.max_jobs,
                "make_jobs: sole buildable"
            );
            budget.budget_weights.insert(pkg.clone(), 1);
            budget.locked.insert(pkg.clone(), jobs);
            return Some(jobs);
        }

        /*
         * Use the package's own build weight (duration in seconds)
         * for proportional budget allocation.  A package expected to
         * build for 400s benefits proportionally more from extra
         * cores than one that builds for 30s, because those cores
         * are utilized for longer.
         */
        let my_weight = self.weights.get(pkg).copied().unwrap_or(100);
        budget.budget_weights.insert(pkg.clone(), my_weight);

        let total_known: usize = budget.budget_weights.values().sum();
        let known_count = budget.budget_weights.len();

        let estimated_total = if known_count > 0 {
            total_known * concurrent / known_count
        } else {
            concurrent
        };
        let effective_pending = pending_weight.saturating_sub(my_weight);
        let estimated_total = (estimated_total + effective_pending).max(1);

        let excluded = budget.excluded.len();
        let available = budget.max_jobs.saturating_sub(excluded);
        let share = (available * my_weight).div_ceil(estimated_total);

        let cap = budget
            .caps
            .get(pkg)
            .copied()
            .unwrap_or(budget.max_jobs)
            .max(1);
        let fair_share = available / concurrent.max(1);
        let floor = if effective_pending > fair_share {
            fair_share.div_ceil(2)
        } else {
            fair_share
        };
        let target = share.max(floor).min(cap);

        let pipeline = self.ready.len() + pending_count;
        let active_threads =
            (concurrent + pipeline).min(budget.build_threads.saturating_sub(excluded));
        let extra = available.saturating_sub(active_threads);
        let locked_extra: usize = budget.locked.values().map(|j| j.saturating_sub(1)).sum();
        let extra_avail = extra
            .saturating_sub(locked_extra)
            .saturating_sub(budget.reserved);

        let locked_waste: usize = budget
            .locked
            .keys()
            .map(|k| {
                let k_cap = budget
                    .caps
                    .get(k)
                    .copied()
                    .unwrap_or(budget.max_jobs)
                    .max(1);
                let k_weight = budget.budget_weights.get(k).copied().unwrap_or(1);
                let k_share = (available * k_weight).div_ceil(estimated_total);
                k_share.saturating_sub(k_cap)
            })
            .sum();
        let headroom = cap.saturating_sub(target);
        let absorb = locked_waste.min(headroom);
        let jobs = 1 + extra_avail.min(target.saturating_sub(1) + absorb);

        let locked_summary: Vec<String> = budget
            .locked
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        debug!(
            %pkg, jobs, my_weight, concurrent, pipeline,
            pending_weight, effective_pending, active_threads,
            estimated_total, share, cap, target,
            available, extra, locked_extra, extra_avail,
            locked_waste, absorb,
            locked = %locked_summary.join(" "),
            "make_jobs: allocated"
        );

        budget.locked.insert(pkg.clone(), jobs);
        Some(jobs)
    }

    /**
     * Release a package's MAKE_JOBS allocation.
     */
    pub fn release_make_jobs(&mut self, pkg: &K) {
        if let Some(ref mut budget) = self.budget {
            budget.locked.remove(pkg);
            budget.budget_weights.remove(pkg);
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
     * Set the number of cores reserved for upcoming dispatches.
     */
    pub fn set_reserved(&mut self, reserved: usize) {
        if let Some(ref mut budget) = self.budget {
            budget.reserved = reserved;
        }
    }

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
        sched.init_budget(16, 4, HashMap::new());

        let Poll::Ready(Some(a)) = sched.poll() else {
            panic!("a should be ready");
        };
        assert_eq!(sched.request_make_jobs(&a), Some(16));
    }

    /**
     * Single build starts but others are pending in the ready set.
     *
     * Workers arrive one at a time (poll, request, poll, request).
     * The first must not grab the whole budget -- it should get
     * approximately max_jobs / build_threads even though it is the
     * only one with a locked allocation at that point.
     */
    #[test]
    fn jobs_staggered_arrival() {
        let names = ["p0", "p1", "p2", "p3"];
        let mut sched = independent_sched(&names, &[100, 100, 100, 100]);
        sched.init_budget(16, 4, HashMap::new());

        let mut allocs = Vec::new();
        for _ in 0..4 {
            let Poll::Ready(Some(p)) = sched.poll() else {
                panic!("should be ready");
            };
            let j = sched.request_make_jobs(&p).expect("budget initialized");
            allocs.push((p, j));
        }

        let fair = 16 / 4;
        assert_eq!(allocs[0].1, fair, "first arrival should get fair share");

        let total: usize = allocs.iter().map(|(_, j)| j).sum();
        assert!(total <= 16, "sum {} exceeds max_jobs 16", total);

        for (p, j) in &allocs {
            assert!(*j >= 1, "allocation {} starves {}", j, p);
        }
    }

    /**
     * No history, equal weights: every package gets the same
     * allocation and the total equals max_jobs exactly.
     */
    #[test]
    fn jobs_equal_weight_equal_share() {
        let names = ["p0", "p1", "p2", "p3"];
        let mut sched = independent_sched(&names, &[100, 100, 100, 100]);
        sched.init_budget(16, 4, HashMap::new());

        let mut pkgs = Vec::new();
        for _ in 0..4 {
            let Poll::Ready(Some(p)) = sched.poll() else {
                panic!("should be ready");
            };
            pkgs.push(p);
        }

        let mut allocs = Vec::new();
        for p in &pkgs {
            allocs.push(sched.request_make_jobs(p).expect("budget initialized"));
        }

        let expected = 16 / 4;
        for (i, &j) in allocs.iter().enumerate() {
            assert_eq!(
                j, expected,
                "package {} got {} (expected {})",
                i, j, expected
            );
        }
        assert_eq!(allocs.iter().sum::<usize>(), 16);
    }

    /**
     * Higher-weight packages get more cores.
     *
     * Graph:
     *   root (w=400) -> d1 -> d2 -> d3
     *   leaf1 (w=50), leaf2 (w=50), leaf3 (w=50)
     *
     * All four are dispatched concurrently.  root should get the
     * majority of the budget because its higher weight means it
     * will build for longer and therefore benefit more from extra
     * cores.
     */
    #[test]
    fn jobs_weighted_allocation() {
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
        weights.insert(pkg("root"), 400);
        for name in ["d1", "d2", "d3"] {
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
        sched.init_budget(16, 4, HashMap::new());

        let mut dispatched = Vec::new();
        for _ in 0..4 {
            let Poll::Ready(Some(p)) = sched.poll() else {
                panic!("should be ready");
            };
            dispatched.push(p);
        }
        assert!(dispatched.contains(&pkg("root")));

        let mut allocs: HashMap<String, usize> = HashMap::new();
        for p in &dispatched {
            let j = sched.request_make_jobs(p).expect("budget initialized");
            allocs.insert(p.clone(), j);
        }

        let root_jobs = allocs[&pkg("root")];
        for name in ["leaf1", "leaf2", "leaf3"] {
            if let Some(&leaf_jobs) = allocs.get(&pkg(name)) {
                assert!(
                    root_jobs > leaf_jobs,
                    "root ({}) must be strictly > {} ({})",
                    root_jobs,
                    name,
                    leaf_jobs
                );
            }
        }
        assert!(allocs.values().sum::<usize>() <= 16);
    }

    /**
     * History caps: a package with cap=2 gets exactly 2 and its
     * surplus is redistributed to the uncapped package.
     *
     * 2 packages, equal weight, max_jobs=16, build_threads=2.
     * Without history both get 8.  With cap=2 on one: it gets 2,
     * the other absorbs the surplus and gets 14.  Total = 16.
     */
    #[test]
    fn jobs_history_redistributes_surplus() {
        let names = ["capped", "uncapped"];
        let mut sched = independent_sched(&names, &[100, 100]);
        let mut caps = HashMap::new();
        caps.insert(pkg("capped"), 2);
        sched.init_budget(16, 2, caps);

        let mut pkgs = Vec::new();
        for _ in 0..2 {
            let Poll::Ready(Some(p)) = sched.poll() else {
                panic!("should be ready");
            };
            pkgs.push(p);
        }

        let mut allocs: HashMap<String, usize> = HashMap::new();
        for p in &pkgs {
            let j = sched.request_make_jobs(p).expect("budget initialized");
            allocs.insert(p.clone(), j);
        }

        assert_eq!(allocs[&pkg("capped")], 2, "capped must not exceed cap");
        assert_eq!(
            allocs[&pkg("uncapped")],
            14,
            "uncapped should absorb surplus"
        );
        assert_eq!(allocs.values().sum::<usize>(), 16);
    }

    /**
     * A high-weight pending package must not be starved by leaves.
     *
     * gate is MAKE_JOBS_SAFE=no so it never participates in the
     * budget (no request/release).  3 leaves are independent and
     * do request jobs.  critical is blocked on gate and has a deep
     * chain of dependents (c1 -> c2 -> c3).
     *
     *   gate (w=50) -> critical (w=400) -> c1 -> c2 -> c3
     *   leaf1 (w=50), leaf2 (w=50), leaf3 (w=50)
     *
     * With build_threads=4 and max_jobs=16, the look-ahead sees
     * that critical (w=400) is one completion away from being
     * dispatched.  Its high weight inflates the denominator, giving
     * each leaf a reduced floor (half of fair_share) instead of a
     * full fair_share.  When gate finishes and critical takes its
     * slot, it gets the majority of the remaining budget -- more
     * than all leaves combined.
     */
    #[test]
    fn jobs_reservation_for_critical_package() {
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
        sched.init_budget(16, 4, HashMap::new());

        /*
         * Dispatch gate + 3 leaves (all ready).
         * critical is blocked waiting on gate.
         */
        let mut dispatched = Vec::new();
        for _ in 0..4 {
            let Poll::Ready(Some(p)) = sched.poll() else {
                panic!("should be ready");
            };
            dispatched.push(p);
        }
        assert!(dispatched.contains(&pkg("gate")));

        /*
         * gate is MAKE_JOBS_SAFE=no: it never calls request_make_jobs.
         * The 3 leaves request.  The look-ahead sees critical
         * (w=400) blocked only on gate (running), so
         * pending_weight=400 inflates the denominator.  Each leaf
         * gets a reduced floor (half of fair_share) instead of a
         * full fair_share, reserving most of the budget for critical.
         */
        let leaves: Vec<String> = dispatched
            .iter()
            .filter(|p| p.starts_with("leaf"))
            .cloned()
            .collect();
        assert_eq!(leaves.len(), 3);

        let mut leaf_allocs: Vec<usize> = Vec::new();
        for p in &leaves {
            let j = sched.request_make_jobs(p).expect("budget initialized");
            leaf_allocs.push(j);
        }
        let leaf_total: usize = leaf_allocs.iter().sum();

        /*
         * gate completes, critical becomes ready and is dispatched.
         * The 3 leaves are still building with their locked
         * allocations -- they do NOT release.
         */
        sched.mark_success(&pkg("gate"));

        let Poll::Ready(Some(crit)) = sched.poll() else {
            panic!("critical should be ready after gate succeeds");
        };
        assert_eq!(crit, pkg("critical"));

        /*
         * critical requests.  Its pending dependents (c1..c3) all
         * depend on critical itself, so they are excluded from the
         * look-ahead.  pending_weight=0.  With weight 400 vs leaves
         * at 50 each, critical gets the majority of the remaining
         * budget -- more than all leaves combined.
         */
        let crit_jobs = sched.request_make_jobs(&crit).expect("budget initialized");
        assert!(
            crit_jobs > leaf_total,
            "critical ({}) must get more than all leaves combined ({})",
            crit_jobs,
            leaf_total
        );
        assert_eq!(
            leaf_total + crit_jobs,
            16,
            "leaves ({}) + critical ({}) should fill the budget exactly",
            leaf_total,
            crit_jobs
        );
    }

    /**
     * Excluded (unsafe) worker does not waste budget.
     *
     * 4 independent packages: 1 unsafe (MAKE_JOBS_SAFE=no) + 3 leaves.
     * No other packages in the graph.  The unsafe worker gets -j1
     * outside the budget.  The 3 leaves should split the remaining
     * 15 cores equally (5 each) rather than getting only 4 each
     * because the budget reserved a share for the unsafe worker.
     */
    #[test]
    fn jobs_excluded_worker_frees_budget() {
        let names = ["unsafe", "leaf1", "leaf2", "leaf3"];
        let mut sched = independent_sched(&names, &[100, 100, 100, 100]);
        sched.init_budget(16, 4, HashMap::new());

        let mut dispatched = Vec::new();
        for _ in 0..4 {
            let Poll::Ready(Some(p)) = sched.poll() else {
                panic!("should be ready");
            };
            dispatched.push(p);
        }

        sched.exclude_from_budget(&pkg("unsafe"));

        let leaves: Vec<String> = dispatched
            .iter()
            .filter(|p| p.starts_with("leaf"))
            .cloned()
            .collect();
        assert_eq!(leaves.len(), 3);

        let mut allocs: Vec<usize> = Vec::new();
        for p in &leaves {
            let j = sched.request_make_jobs(p).expect("budget initialized");
            allocs.push(j);
        }

        for (i, &j) in allocs.iter().enumerate() {
            assert_eq!(
                j, 5,
                "leaf {} got {} (expected 5 = 15 available / 3 workers)",
                i, j
            );
        }
        assert_eq!(allocs.iter().sum::<usize>(), 15);
    }
}
