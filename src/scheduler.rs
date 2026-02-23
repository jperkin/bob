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
use std::task::Poll;

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
}
