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
 * Dependency-aware build scheduler using summed PBULK_WEIGHT ordering.
 *
 * Packages are prioritised by **total PBULK_WEIGHT** -- the package's own
 * `PBULK_WEIGHT`, plus the sum of all unique transitive dependents'
 * PBULK_WEIGHTs.  This matches the algorithm used by pbulk's
 * `compute_tree_depth_rec()`.
 *
 * Tiebreakers, in order:
 *
 * * Transitive dependent count (more dependents first)
 * * Historical CPU time (longer builds first)
 * * Package name (alphabetical)
 *
 * The scheduler provides two interfaces:
 *
 * * [`Scheduler::poll`] dispatches packages one at a time for building,
 *   tracking dependencies.
 *
 * * [`Scheduler::iter`] returns all packages in priority order for
 *   read-only display (e.g., `bob status`).
 */

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::hash::Hash;
use std::task::Poll;

use anyhow::Result;
use pkgsrc::PkgName;
use tracing::warn;

use crate::db::Database;
use crate::makejobs;

/**
 * Input data for [`Scheduler::from_graph`].
 *
 * Each package provides its forward dependencies, PBULK_WEIGHT, and
 * historical CPU time.
 */
pub struct PackageNode<K> {
    pub deps: HashSet<K>,
    pub pbulk_weight: usize,
    pub cpu_time: u64,
}

/**
 * A package returned by [`Scheduler::poll`] or [`Scheduler::iter`].
 *
 * Carries the package key together with all computed scheduling metadata
 * so that callers never need to reach back into the scheduler.
 */
#[derive(Debug)]
pub struct ScheduledPackage<K> {
    pub pkg: K,
    pub total_pbulk_weight: usize,
    pub dep_count: usize,
    pub pbulk_weight: usize,
    pub cpu_time: u64,
    pub make_jobs: makejobs::PkgMakeJobs,
}

/**
 * Dependency-aware build scheduler.
 *
 * Each package is assigned a numeric priority rank at construction
 * time (0 = highest priority).  The ready set is a `BTreeSet` keyed
 * by `(rank, K)`, so `first()` always returns the highest-priority
 * ready package.
 */
pub struct Scheduler<K: Ord> {
    incoming: HashMap<K, HashSet<K>>,
    reverse_deps: HashMap<K, HashSet<K>>,
    priority: HashMap<K, usize>,
    ranked: Vec<K>,
    ready: BTreeSet<(usize, K)>,
    total_pbulk_weights: HashMap<K, usize>,
    dep_counts: HashMap<K, usize>,
    running: HashSet<K>,
    done: HashSet<K>,
    failed: HashSet<K>,
    pbulk_weights: HashMap<K, usize>,
    cpu_times: HashMap<K, u64>,
    pkg_make_jobs: HashMap<K, makejobs::PkgMakeJobs>,
    pkg_cpu_history: HashMap<K, usize>,
    allocator: Option<makejobs::Allocator>,
}

impl Scheduler<PkgName> {
    /**
     * Create a scheduler from the database.
     *
     * Queries the packages table, resolved dependencies, and historical
     * CPU times.  All selected packages are included; use
     * [`mark_success`](Self::mark_success) or
     * [`mark_failure`](Self::mark_failure) to pre-mark cached results.
     */
    pub fn new(db: &Database) -> Result<Self> {
        let mut packages: HashMap<PkgName, PackageNode<PkgName>> = HashMap::new();
        let mut id_to_name: HashMap<i64, PkgName> = HashMap::new();
        let mut pkg_paths: HashMap<PkgName, String> = HashMap::new();
        let mut pkg_make_jobs: HashMap<PkgName, makejobs::PkgMakeJobs> = HashMap::new();

        for row in crate::db::query_selected_packages(db.conn())? {
            id_to_name.insert(row.id, row.pkgname.clone());
            pkg_paths.insert(row.pkgname.clone(), row.pkgpath);
            pkg_make_jobs.insert(
                row.pkgname.clone(),
                makejobs::PkgMakeJobs::new(row.make_jobs_safe),
            );
            packages.insert(
                row.pkgname,
                PackageNode {
                    deps: HashSet::new(),
                    pbulk_weight: row.pbulk_weight,
                    cpu_time: 0,
                },
            );
        }

        for (pkg_id, dep_id) in crate::db::query_resolved_deps(db.conn())? {
            if let (Some(pkg), Some(dep)) = (id_to_name.get(&pkg_id), id_to_name.get(&dep_id)) {
                if let Some(node) = packages.get_mut(pkg) {
                    node.deps.insert(dep.clone());
                }
            }
        }

        let stage_timings = match db.history_conn() {
            Ok(conn) => crate::db::query_build_stage_timings(conn),
            Err(e) => {
                warn!(error = %e, "Scheduler::new: failed to open history db");
                HashMap::new()
            }
        };
        for (pkgname, node) in &mut packages {
            if let Some(pkgpath) = pkg_paths.get(pkgname) {
                let pkgbase = pkgname.pkgbase().to_string();
                if let Some(t) = stage_timings.get(&(pkgpath.clone(), pkgbase)) {
                    node.cpu_time = t.cpu_ms;
                }
            }
        }

        let mut sched = Self::from_graph(packages);
        sched.pkg_make_jobs = pkg_make_jobs;

        let safe_paths: HashMap<PkgName, String> = pkg_paths
            .into_iter()
            .filter(|(k, _)| {
                sched
                    .pkg_make_jobs
                    .get(k)
                    .map(|mj| mj.safe())
                    .unwrap_or(false)
            })
            .collect();
        sched.pkg_cpu_history = makejobs::pkg_cpu_history(&stage_timings, &safe_paths);

        Ok(sched)
    }
}

impl<K: Eq + Hash + Clone + Ord + fmt::Display> Scheduler<K> {
    /**
     * Create a scheduler from an explicit package graph.
     *
     * Used by the simulator and tests.  Reverse dependencies are
     * derived from the forward dependency sets in each
     * [`PackageNode`].
     *
     * No MAKE_JOBS values are computed; `poll()` returns
     * `make_jobs: None`.  Use [`Scheduler::new`] with a database
     * for MAKE_JOBS-aware scheduling.
     */
    pub fn from_graph(packages: HashMap<K, PackageNode<K>>) -> Self {
        let pkg_cpu_history = HashMap::new();
        let pkg_make_jobs: HashMap<K, makejobs::PkgMakeJobs> = packages
            .keys()
            .map(|k| (k.clone(), makejobs::PkgMakeJobs::new(true)))
            .collect();
        let mut incoming: HashMap<K, HashSet<K>> = HashMap::with_capacity(packages.len());
        let mut pbulk_weights: HashMap<K, usize> = HashMap::with_capacity(packages.len());
        let mut cpu_times: HashMap<K, u64> = HashMap::with_capacity(packages.len());
        let mut reverse_deps: HashMap<K, HashSet<K>> = HashMap::with_capacity(packages.len());

        for (pkg, node) in &packages {
            incoming.insert(pkg.clone(), node.deps.clone());
            pbulk_weights.insert(pkg.clone(), node.pbulk_weight);
            cpu_times.insert(pkg.clone(), node.cpu_time);
            reverse_deps.entry(pkg.clone()).or_default();
            for dep in &node.deps {
                reverse_deps
                    .entry(dep.clone())
                    .or_default()
                    .insert(pkg.clone());
            }
        }

        let (total_pbulk_weights, dep_counts) =
            compute_total_pbulk_weights(&incoming, &reverse_deps, &pbulk_weights);

        /*
         * Assign a priority rank to each package.  Rank 0 is highest
         * priority.  Sort by (total_pbulk_weight DESC, dep_count DESC,
         * cpu_time DESC, name ASC).
         */
        let mut ranked: Vec<&K> = packages.keys().collect();
        ranked.sort_by(|a, b| {
            total_pbulk_weights[*b]
                .cmp(&total_pbulk_weights[*a])
                .then(dep_counts[*b].cmp(&dep_counts[*a]))
                .then(packages[*b].cpu_time.cmp(&packages[*a].cpu_time))
                .then((*a).cmp(*b))
        });
        let priority: HashMap<K, usize> = ranked
            .iter()
            .enumerate()
            .map(|(rank, &pkg)| (pkg.clone(), rank))
            .collect();
        let ranked: Vec<K> = ranked.into_iter().cloned().collect();

        let mut ready = BTreeSet::new();
        for (pkg, node) in &packages {
            if node.deps.is_empty() {
                ready.insert((priority[pkg], pkg.clone()));
            }
        }
        incoming.retain(|_, deps| !deps.is_empty());

        Self {
            incoming,
            reverse_deps,
            priority,
            ranked,
            ready,
            total_pbulk_weights,
            dep_counts,
            running: HashSet::new(),
            done: HashSet::new(),
            failed: HashSet::new(),
            pbulk_weights,
            cpu_times,
            pkg_make_jobs,
            pkg_cpu_history,
            allocator: None,
        }
    }

    /**
     * Poll for the next package to build.
     *
     * Returns `Ready(Some(pkg))` with the highest-priority ready
     * package, `Pending` if all remaining packages are waiting on
     * running dependencies, or `Ready(None)` when all packages have
     * completed or failed.
     *
     * The returned [`ScheduledPackage`] includes the recommended
     * `make_jobs` from the precomputed recommendations.  The builder may
     * override this based on live conditions.
     */
    pub fn poll(&mut self) -> Poll<Option<ScheduledPackage<K>>> {
        match self.ready.pop_first() {
            Some((rank, pkg)) => {
                tracing::debug!(
                    %pkg, rank,
                    weight = self.total_pbulk_weights[&pkg],
                    deps = self.dep_counts[&pkg],
                    cpu = self.cpu_times[&pkg],
                    ready = self.ready.len(),
                    "poll"
                );
                self.incoming.remove(&pkg);
                self.running.insert(pkg.clone());

                let cpu_time = self.pkg_cpu_history.get(&pkg).copied();
                let safe = self.pkg_make_jobs.get(&pkg).is_some_and(|mj| mj.safe());
                if safe {
                    if let Some(ref alloc) = self.allocator {
                        let jobs = self.tail_assign(alloc, &pkg, cpu_time);
                        self.pkg_make_jobs.get_mut(&pkg).unwrap().allocate(jobs);
                    }
                }
                let make_jobs = self.pkg_make_jobs.get(&pkg).copied().unwrap_or_default();

                Poll::Ready(Some(ScheduledPackage {
                    total_pbulk_weight: self.total_pbulk_weights[&pkg],
                    dep_count: self.dep_counts[&pkg],
                    pbulk_weight: self.pbulk_weights[&pkg],
                    cpu_time: self.cpu_times[&pkg],
                    make_jobs,
                    pkg,
                }))
            }
            None if self.incoming.is_empty() && self.running.is_empty() => Poll::Ready(None),
            None => Poll::Pending,
        }
    }

    /**
     * Mark a package as successfully built.
     *
     * Unlocks dependents whose dependency sets become empty.  Can
     * also be called for pre-cached results before the build loop
     * starts.
     */
    pub fn mark_success(&mut self, pkg: &K) {
        self.deschedule(pkg);
        self.running.remove(pkg);
        self.done.insert(pkg.clone());

        if let Some(dependents) = self.reverse_deps.get(pkg).cloned() {
            for dependent in dependents {
                if let Some(deps) = self.incoming.get_mut(&dependent) {
                    deps.remove(pkg);
                }
                if self.incoming.get(&dependent).is_some_and(HashSet::is_empty) {
                    self.incoming.remove(&dependent);
                    let rank = self.priority[&dependent];
                    self.ready.insert((rank, dependent));
                }
            }
        }
    }

    /**
     * Mark a package as failed and propagate to all transitive
     * dependents.
     *
     * Returns the set of indirectly failed packages (not including
     * the original).
     */
    pub fn mark_failure(&mut self, pkg: &K) -> Vec<K> {
        self.deschedule(pkg);
        self.running.remove(pkg);
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
                || !self.total_pbulk_weights.contains_key(&badpkg)
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
            self.deschedule(&pkg);
            self.failed.insert(pkg.clone());
            indirect.push(pkg);
        }
        indirect
    }

    fn deschedule(&mut self, pkg: &K) {
        self.incoming.remove(pkg);
        if let Some(&rank) = self.priority.get(pkg) {
            self.ready.remove(&(rank, pkg.clone()));
        }
    }

    /**
     * Iterate all packages in priority order.
     *
     * Returns precomputed scheduling data for each package.  Does
     * not modify scheduler state.  Use this for display purposes
     * (e.g., `bob status`).
     */
    /**
     * Get the static dep_count for a package.
     */
    pub fn dep_count(&self, pkg: &K) -> usize {
        self.dep_counts.get(pkg).copied().unwrap_or(0)
    }

    pub fn iter(&self) -> impl Iterator<Item = ScheduledPackage<K>> + '_ {
        self.ranked.iter().map(move |pkg| ScheduledPackage {
            pkg: pkg.clone(),
            total_pbulk_weight: self.total_pbulk_weights[pkg],
            dep_count: self.dep_counts[pkg],
            pbulk_weight: self.pbulk_weights[pkg],
            cpu_time: self.cpu_times[pkg],
            make_jobs: self.pkg_make_jobs.get(pkg).copied().unwrap_or_default(),
        })
    }

    /** Number of packages not yet dispatched (ready + blocked). */
    pub fn queued_count(&self) -> usize {
        self.ready.len() + self.incoming.len()
    }

    /** Set the historical CPU time for a package. */
    pub fn set_pkg_cpu_history(&mut self, pkg: &K, cpu_time: usize) {
        self.pkg_cpu_history.insert(pkg.clone(), cpu_time);
    }

    /** Mark a package as not supporting parallel make. */
    pub fn set_make_jobs_unsafe(&mut self, pkg: &K) {
        self.pkg_make_jobs
            .insert(pkg.clone(), makejobs::PkgMakeJobs::new(false));
    }

    /**
     * Compute MAKE_JOBS for a package, boosting in the build tail.
     *
     * Normal mode: use the allocator's log-scaled assignment.
     * Sole builder (mid-build, nothing else runnable): full budget.
     * Tail (no deps left to unblock): split available cores among
     * remaining packages proportionally to their base allocations
     * so that heavier packages get a larger share.
     */
    fn tail_assign(&self, alloc: &makejobs::Allocator, pkg: &K, cpu_time: Option<usize>) -> usize {
        let base = alloc.assign(cpu_time);

        if self.running.len() == 1 && self.ready.is_empty() {
            return alloc.budget();
        }
        if !self.incoming.is_empty() {
            return base;
        }

        /*
         * Tail: no packages waiting on dependencies.  Compute the
         * budget not yet committed to other running packages, then
         * split it proportionally among this package and the remaining
         * ready packages using base allocations as weights.
         */
        let committed: usize = self
            .running
            .iter()
            .filter(|p| *p != pkg)
            .filter_map(|p| self.pkg_make_jobs.get(p))
            .filter_map(|mj| mj.jobs().or(mj.allocated()))
            .sum();
        let available = alloc.budget().saturating_sub(committed);

        let ready_weight: usize = self
            .ready
            .iter()
            .map(|(_, p)| {
                let ct = self.pkg_cpu_history.get(p).copied();
                alloc.assign(ct)
            })
            .sum();
        let total_weight = base + ready_weight;

        if total_weight == 0 {
            return available;
        }

        let scaled = (available as f64 * base as f64 / total_weight as f64).round() as usize;
        scaled.max(base)
    }

    /** Set the allocator for MAKE_JOBS allocation. */
    pub fn set_allocator(&mut self, mut allocator: makejobs::Allocator) {
        let mut cpu_times: Vec<usize> = self.pkg_cpu_history.values().copied().collect();
        cpu_times.sort();
        allocator.calibrate(&cpu_times);
        self.allocator = Some(allocator);
    }

    /**
     * Pre-allocate jobs for all safe packages.
     *
     * Uses non-sole-builder mode to show the steady-state allocation
     * each package would receive when running alongside others.
     * Call after [`set_allocator`](Self::set_allocator).
     */
    pub fn allocate_all(&mut self) {
        if let Some(ref alloc) = self.allocator {
            for (pkg, mj) in &mut self.pkg_make_jobs {
                if mj.safe() {
                    let cpu_time = self.pkg_cpu_history.get(pkg).copied();
                    mj.allocate(alloc.assign(cpu_time));
                }
            }
        }
    }
}

/**
 * Compute total PBULK_WEIGHTs and transitive dependent counts via BFS.
 *
 * For each package, walks the reverse dependency graph to find all
 * unique transitive dependents, summing their PBULK_WEIGHTs.
 * Diamond dependencies are counted once (deduplicated).
 */
fn compute_total_pbulk_weights<K>(
    incoming: &HashMap<K, HashSet<K>>,
    reverse_deps: &HashMap<K, HashSet<K>>,
    pbulk_weights: &HashMap<K, usize>,
) -> (HashMap<K, usize>, HashMap<K, usize>)
where
    K: Eq + Hash + Clone,
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

    let mut tw_map: HashMap<K, usize> = HashMap::with_capacity(n);
    let mut dc_map: HashMap<K, usize> = HashMap::with_capacity(n);
    for (i, &pkg) in pkg_list.iter().enumerate() {
        tw_map.insert(pkg.clone(), total_weights[i]);
        dc_map.insert(pkg.clone(), dep_counts[i]);
    }

    (tw_map, dc_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(s: &str) -> String {
        s.to_string()
    }

    fn build_graph(
        edges: &[(&str, &str)],
        names: &[&str],
        weight: usize,
    ) -> HashMap<String, PackageNode<String>> {
        let mut packages: HashMap<String, PackageNode<String>> = HashMap::new();
        for name in names {
            packages.insert(
                pkg(name),
                PackageNode {
                    deps: HashSet::new(),
                    pbulk_weight: weight,
                    cpu_time: 0,
                },
            );
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
        }
        packages
    }

    fn sched(packages: HashMap<String, PackageNode<String>>) -> Scheduler<String> {
        Scheduler::from_graph(packages)
    }

    /**
     * Package with more total blocked pbulk_weight is preferred.
     *
     * x has 3 dependents at pbulk_weight 100 each -> total = 400.
     * w has 50 dependents at pbulk_weight 1 each -> total = 150.
     * x should be dispatched first.
     */
    #[test]
    fn higher_total_pbulk_weight_preferred() {
        let mut packages = build_graph(
            &[("x-1.0", "y-1.0"), ("y-1.0", "z-1.0")],
            &["x-1.0", "y-1.0", "z-1.0"],
            100,
        );

        packages.insert(
            pkg("w-1.0"),
            PackageNode {
                deps: HashSet::new(),
                pbulk_weight: 100,
                cpu_time: 0,
            },
        );
        for i in 0..50 {
            let fan = format!("f{}-1.0", i);
            packages.insert(
                fan.clone(),
                PackageNode {
                    deps: [pkg("w-1.0")].into_iter().collect(),
                    pbulk_weight: 1,
                    cpu_time: 0,
                },
            );
        }

        let mut s = sched(packages);
        let p = match s.poll() {
            Poll::Ready(Some(sp)) => sp.pkg,
            other => panic!("expected Ready, got {:?}", other),
        };
        assert_eq!(p, pkg("x-1.0"));
    }

    /**
     * Diamond graph: shared dependents are counted once, not twice.
     *
     *   a -> b, a -> c, b -> d, c -> d
     *
     * a's transitive dependents are {b, c, d} (not {b, c, d, d}).
     * With uniform pbulk_weight 100: total_pbulk_weight(a) = 400.
     */
    #[test]
    fn diamond_dedup() {
        let packages = build_graph(
            &[("a", "b"), ("a", "c"), ("b", "d"), ("c", "d")],
            &["a", "b", "c", "d"],
            100,
        );
        let s = sched(packages);

        let find = |name: &str| {
            s.iter()
                .find(|p| p.pkg == name)
                .unwrap_or_else(|| panic!("{} not found", name))
        };
        let a = find("a");
        assert_eq!(a.total_pbulk_weight, 400, "a = self(100) + b + c + d");
        assert_eq!(a.dep_count, 3);
        let b = find("b");
        assert_eq!(b.total_pbulk_weight, 200, "b = self(100) + d(100)");
        assert_eq!(b.dep_count, 1);
        let d = find("d");
        assert_eq!(d.total_pbulk_weight, 100, "d = self(100), leaf");
        assert_eq!(d.dep_count, 0);
    }

    /**
     * High PBULK_WEIGHT leaf sorts above low-weight leaf.
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

        let mut s = sched(packages);
        let first = match s.poll() {
            Poll::Ready(Some(sp)) => sp.pkg,
            _ => panic!("expected Ready"),
        };
        let second = match s.poll() {
            Poll::Ready(Some(sp)) => sp.pkg,
            _ => panic!("expected Ready"),
        };
        assert_eq!(first, pkg("heavy"));
        assert_eq!(second, pkg("light"));
    }

    /**
     * CPU time breaks ties when total_pbulk_weight and dep_count are equal.
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

        let mut s = sched(packages);
        let first = match s.poll() {
            Poll::Ready(Some(sp)) => sp.pkg,
            _ => panic!("expected Ready"),
        };
        let second = match s.poll() {
            Poll::Ready(Some(sp)) => sp.pkg,
            _ => panic!("expected Ready"),
        };
        assert_eq!(first, pkg("slow"));
        assert_eq!(second, pkg("fast"));
    }

    /**
     * Alphabetical name is the final tiebreak.
     */
    #[test]
    fn alphabetical_tiebreak() {
        let packages = build_graph(&[], &["ccc", "aaa", "bbb"], 100);
        let mut s = sched(packages);
        let first = match s.poll() {
            Poll::Ready(Some(sp)) => sp.pkg,
            _ => panic!("expected Ready"),
        };
        assert_eq!(first, pkg("aaa"));
    }

    /**
     * mark_failure skips packages not in the live graph.
     */
    #[test]
    fn mark_failure_ignores_outside_graph() {
        let packages = build_graph(&[], &["dep"], 100);
        let mut s = sched(packages);

        /*
         * Manually mark "dep" as having a reverse dep outside
         * the graph.  This simulates a cached dependent.
         */
        s.reverse_deps
            .entry(pkg("dep"))
            .or_default()
            .insert(pkg("cached-dependent"));

        let sp = match s.poll() {
            Poll::Ready(Some(sp)) => sp,
            _ => panic!("expected Ready"),
        };
        let indirect = s.mark_failure(&sp.pkg);
        assert!(indirect.is_empty(), "cached dependents should be ignored");
    }

    /**
     * Uniform pbulk_weights: total_pbulk_weight == W * (1 + dep_count).
     */
    #[test]
    fn uniform_pbulk_weight_identity() {
        let packages = build_graph(&[("a", "b"), ("b", "c")], &["a", "b", "c"], 100);
        let s = sched(packages);
        for sp in s.iter() {
            assert_eq!(
                sp.total_pbulk_weight,
                100 * (1 + sp.dep_count),
                "total_pbulk_weight({}) = 100 * (1 + {})",
                sp.pkg,
                sp.dep_count
            );
        }
    }

    /**
     * Build a small graph:
     *
     *   a -> b -> d
     *   a -> c -> d
     *        c -> e
     */
    fn small_graph() -> HashMap<String, PackageNode<String>> {
        build_graph(
            &[("a", "b"), ("a", "c"), ("b", "d"), ("c", "d"), ("c", "e")],
            &["a", "b", "c", "d", "e"],
            10,
        )
    }

    #[test]
    fn lifecycle_success() {
        let mut s = sched(small_graph());

        let a = match s.poll() {
            Poll::Ready(Some(sp)) => sp.pkg,
            _ => panic!("expected a"),
        };
        assert_eq!(a, pkg("a"));
        assert!(matches!(s.poll(), Poll::Pending));

        s.mark_success(&a);

        let first = match s.poll() {
            Poll::Ready(Some(sp)) => sp.pkg,
            other => panic!("expected b or c, got {:?}", other),
        };
        assert!(
            first == pkg("b") || first == pkg("c"),
            "expected b or c, got {}",
            first
        );
        s.mark_success(&first);

        let second = match s.poll() {
            Poll::Ready(Some(sp)) => sp.pkg,
            other => panic!("expected b or c, got {:?}", other),
        };
        assert!(
            second == pkg("b") || second == pkg("c"),
            "expected b or c, got {}",
            second
        );
        s.mark_success(&second);

        while let Poll::Ready(Some(sp)) = s.poll() {
            s.mark_success(&sp.pkg);
        }

        assert!(matches!(s.poll(), Poll::Ready(None)));
    }

    #[test]
    fn lifecycle_failure() {
        let mut s = sched(small_graph());

        let Poll::Ready(Some(sp)) = s.poll() else {
            panic!("a should be ready");
        };
        s.mark_success(&sp.pkg);

        /*
         * Fail "c" -- its transitive dependents "d" and "e" should
         * be indirectly failed.  "b" depends only on "a" which
         * succeeded, so "b" should still be buildable.
         */
        let Poll::Ready(Some(sp)) = s.poll() else {
            panic!("b or c should be ready");
        };
        if sp.pkg == pkg("c") {
            let indirect = s.mark_failure(&sp.pkg);
            let broken: HashSet<String> = indirect.into_iter().collect();
            assert!(broken.contains(&pkg("d")), "d should be broken");
            assert!(broken.contains(&pkg("e")), "e should be broken");
            assert!(!broken.contains(&pkg("b")), "b should not be broken");
        } else {
            s.mark_success(&sp.pkg);
            let Poll::Ready(Some(sp)) = s.poll() else {
                panic!("c should be ready");
            };
            assert_eq!(sp.pkg, pkg("c"));
            let indirect = s.mark_failure(&sp.pkg);
            let broken: HashSet<String> = indirect.into_iter().collect();
            assert!(broken.contains(&pkg("d")), "d should be broken");
            assert!(broken.contains(&pkg("e")), "e should be broken");
        }

        while let Poll::Ready(Some(sp)) = s.poll() {
            s.mark_success(&sp.pkg);
        }

        assert!(matches!(s.poll(), Poll::Ready(None)));
    }

    /**
     * Non-uniform pbulk_weights: heavier dependents contribute more.
     *
     *   a -> b (pbulk_weight 500)
     *   a -> c (pbulk_weight 1)
     *
     * a's total_pbulk_weight = 10 + 500 + 1 = 511.
     */
    #[test]
    fn weighted_scheduling_scores() {
        let mut packages = build_graph(&[("a", "b"), ("a", "c")], &["a", "b", "c"], 100);
        packages.get_mut(&pkg("a")).expect("a").pbulk_weight = 10;
        packages.get_mut(&pkg("b")).expect("b").pbulk_weight = 500;
        packages.get_mut(&pkg("c")).expect("c").pbulk_weight = 1;

        let s = sched(packages);
        let find = |name: &str| {
            s.iter()
                .find(|p| p.pkg == name)
                .unwrap_or_else(|| panic!("{} not found", name))
        };

        let a = find("a");
        assert_eq!(a.total_pbulk_weight, 511, "a = 10 + 500 + 1");
        assert_eq!(a.dep_count, 2);
        assert_eq!(find("b").total_pbulk_weight, 500, "b = self only");
        assert_eq!(find("c").total_pbulk_weight, 1, "c = self only");
    }

    /**
     * mark_success before poll (cached result) works correctly.
     */
    #[test]
    fn mark_success_before_poll() {
        let packages = build_graph(&[("a", "b"), ("b", "c")], &["a", "b", "c"], 100);
        let mut s = sched(packages);

        s.mark_success(&pkg("a"));
        s.mark_success(&pkg("b"));

        let Poll::Ready(Some(sp)) = s.poll() else {
            panic!("c should be ready");
        };
        assert_eq!(sp.pkg, pkg("c"));
    }

    /**
     * mark_failure before poll (cached result) cascades correctly.
     */
    #[test]
    fn mark_failure_before_poll() {
        let packages = build_graph(&[("a", "b"), ("b", "c")], &["a", "b", "c"], 100);
        let mut s = sched(packages);

        let indirect = s.mark_failure(&pkg("a"));
        let broken: HashSet<String> = indirect.into_iter().collect();
        assert!(broken.contains(&pkg("b")));
        assert!(broken.contains(&pkg("c")));
        assert!(matches!(s.poll(), Poll::Ready(None)));
    }

    /**
     * iter() returns all packages in priority order.
     */
    #[test]
    fn iter_returns_priority_order() {
        let packages = build_graph(&[("a", "b"), ("b", "c")], &["a", "b", "c"], 100);
        let s = sched(packages);
        let names: Vec<String> = s.iter().map(|sp| sp.pkg).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }
}
