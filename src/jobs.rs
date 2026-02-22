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
 * Pluggable MAKE_JOBS allocation algorithms.
 *
 * When `dynamic_jobs` is enabled, the build manager distributes a total
 * CPU budget across concurrent package builds.  The [`JobAllocator`]
 * trait defines the interface, and [`make_allocator`] selects the
 * concrete implementation based on configuration.
 *
 * # Background
 *
 * Package builds run in parallel across `build_threads` sandboxed
 * workers.  Each package goes through multiple phases, but only
 * `configure` and `build` are CPU-intensive and parallelisable via
 * `MAKE_JOBS`.  The other phases (depends, install, package, clean)
 * are single-threaded and do not hold any CPU budget.
 *
 * The build manager locks a MAKE_JOBS allocation when a worker enters
 * its configure or build phase, and releases it when that phase ends.
 * Between configure and build the lock is released and re-acquired,
 * allowing the allocator to adjust based on current state.  However,
 * there is no mid-phase rebalancing: once a worker locks N cores for
 * a build phase, it holds them until the phase completes.
 *
 * # Weights
 *
 * Each package's weight is its `remaining_depth`: the longest chain
 * of not-yet-built packages that depend on it (by hop count).
 * A package with high remaining depth is on or near the critical
 * path — building it faster directly reduces wall-clock time.
 * A package with low remaining depth is a leaf or near-leaf whose
 * build time has slack.
 *
 * # Sole builder
 *
 * When exactly one worker is running and no packages are ready to
 * dispatch, the worker gets the full `max` budget.  This is safe
 * because no other worker can enter a build phase and compete for
 * cores.  This is the common case during the serial tail at the
 * end of a build, where a deep dependency chain forces sequential
 * building.
 *
 * # Look-ahead
 *
 * The allocator receives `upcoming_weights`: the weights of ready
 * packages that idle workers will pick up soon.  These participate
 * in the weight distribution as virtual entries, absorbing
 * proportional budget that nobody locks.  This holds back cores
 * from shallow current work so that high-depth upcoming packages
 * get a larger allocation when they enter their build phase.
 *
 * The upcoming weights are amplified by [`UPCOMING_WEIGHT_FACTOR`]
 * to strengthen this effect.  The virtual entries do not increase
 * the active worker count (which determines total distributable
 * budget), only the weight pool (which determines how the budget
 * is split).
 *
 * # Choosing an algorithm
 *
 * ## `weighted_fair_share` (default)
 *
 * Best for builds with deep dependency chains where the serial tail
 * dominates wall-clock time (e.g. cmake → re2c → ninja → meson →
 * gnutls → gnupg2).  Gives more cores to high-depth packages at the
 * expense of shallow leaves, reducing critical path duration.  The
 * look-ahead mechanism deliberately under-utilises CPU when it knows
 * deep work is about to start, so that work gets a larger share.
 *
 * ## `equal_share`
 *
 * Divides cores equally: each worker gets `max / active`.  Ignores
 * weights and upcoming work entirely.  Useful as a baseline for
 * comparison, or when the package set has no dominant serial chain
 * and uniform throughput matters more than critical path latency.
 */

use crate::config::{DynamicJobs, JobAlgorithm};
use std::collections::HashMap;

/*
 * Multiplier applied to upcoming package weights before they enter the
 * weight distribution pool.  Higher values cause the allocator to hold
 * back more budget from current workers, reserving it for high-depth
 * packages that are about to start.
 *
 * At 1, upcoming weights compete equally with real workers — the
 * effect is subtle and mostly noticeable when weight ratios are large.
 * At 2, a ready package with weight 800 competes as 1600, absorbing
 * roughly twice as much of the extra budget and pushing current
 * workers noticeably below the flat split.  At 3+, the effect
 * becomes aggressive and may starve current workers below useful
 * parallelism (e.g. -j2 on a package that benefits from -j4).
 *
 * The optimal value depends on the ratio of max_jobs to
 * build_threads and the depth variance of the package set.  Start
 * with 2 and adjust based on debug logs (`MAKE_JOBS allocate`
 * messages show the actual allocations and upcoming weights).
 */
const UPCOMING_WEIGHT_FACTOR: usize = 2;

/**
 * Context passed to the allocator for each MAKE_JOBS decision.
 */
pub struct AllocContext<'a> {
    /// This worker's sandbox ID.
    pub sandbox_id: usize,
    /// This worker's critical path depth.
    pub my_weight: usize,
    /// (sandbox_id, weight) for every currently dispatched worker.
    pub all_dispatched: &'a [(usize, usize)],
    /// True only when this is the sole dispatched worker AND nothing
    /// else is ready to dispatch.
    pub sole_builder: bool,
    /// Weights of ready packages that will start soon.  These
    /// participate in weight distribution (absorbing proportional
    /// budget) but do not increase the active worker count.  This
    /// holds back budget from low-depth current workers so that
    /// high-depth upcoming work gets a larger allocation when it
    /// enters its build phase.
    pub upcoming_weights: &'a [usize],
}

/**
 * Strategy for distributing MAKE_JOBS across concurrent builds.
 */
pub trait JobAllocator {
    /// Return MAKE_JOBS for the worker described by `ctx`.
    fn allocate(&self, ctx: &AllocContext) -> usize;

    /// Record that `sandbox_id` has locked `jobs` cores.
    fn lock(&mut self, sandbox_id: usize, jobs: usize);

    /// Release the lock for `sandbox_id`.
    fn release(&mut self, sandbox_id: usize);

    /// Name for logging/debugging.
    fn name(&self) -> &str;

    /// Return a summary of internal state for debug logging.
    fn debug_state(&self) -> String;
}

/**
 * Distribute extra budget proportional to critical path depth.
 *
 * The total CPU budget (`max`) is divided into two parts:
 *
 *   1. **Minimum reservation**: `min` cores for each dispatched worker.
 *      This guarantees every worker can make progress regardless of
 *      weight.  With 16 cores, 4 workers, and min=2, this reserves 8.
 *
 *   2. **Extra pool**: the remaining cores (`max - active * min`),
 *      distributed proportionally by weight using the largest-remainder
 *      method.  Workers with higher remaining depth get a larger share,
 *      accelerating the critical path.
 *
 * The extra pool is further reduced by what already-locked workers
 * have consumed above their minimum.  This prevents over-allocation:
 * if one worker locked 6 cores (4 above min), only 4 of the original
 * 8 extra remain for the next workers.
 *
 * ## Look-ahead
 *
 * Ready packages that idle workers will pick up are added to the
 * weight pool as virtual entries (amplified by [`UPCOMING_WEIGHT_FACTOR`]).
 * They absorb proportional extra budget that nobody locks, effectively
 * reserving it.  When the high-depth package actually enters its build
 * phase, the locked totals are lower (because earlier workers got
 * less), so more extra is available.
 */
struct WeightedFairShare {
    max_jobs: usize,
    min_per_worker: usize,
    locked: HashMap<usize, usize>,
}

impl JobAllocator for WeightedFairShare {
    fn allocate(&self, ctx: &AllocContext) -> usize {
        if ctx.sole_builder {
            return self.max_jobs;
        }

        let active = ctx.all_dispatched.len().max(1);
        let extra = self.max_jobs.saturating_sub(active * self.min_per_worker);
        let locked_extra: usize = self
            .locked
            .values()
            .map(|j| j.saturating_sub(self.min_per_worker))
            .sum();
        let remaining_extra = extra.saturating_sub(locked_extra);

        if remaining_extra == 0 {
            return self.min_per_worker;
        }

        let mut unlocked: Vec<(usize, usize)> = ctx
            .all_dispatched
            .iter()
            .filter(|(sid, _)| !self.locked.contains_key(sid))
            .copied()
            .collect();
        for (i, &w) in ctx.upcoming_weights.iter().enumerate() {
            unlocked.push((usize::MAX - i, w * UPCOMING_WEIGHT_FACTOR));
        }

        let total_weight: usize = unlocked.iter().map(|(_, w)| *w).sum();
        if total_weight == 0 {
            return self.min_per_worker;
        }

        /*
         * Largest-remainder method: take the floor of each proportional
         * share, then hand out the leftover one at a time to whichever
         * entries have the biggest fractional parts.  This distributes
         * integer cores fairly without rounding bias.
         */
        let mut entries: Vec<(usize, usize, f64)> = unlocked
            .iter()
            .map(|&(sid, weight)| {
                let exact = remaining_extra as f64 * weight as f64 / total_weight as f64;
                let floor = exact as usize;
                let remainder = exact - floor as f64;
                (sid, floor, remainder)
            })
            .collect();

        let floor_sum: usize = entries.iter().map(|(_, f, _)| f).sum();
        let mut leftover = remaining_extra.saturating_sub(floor_sum);

        entries.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        for entry in &mut entries {
            if leftover == 0 {
                break;
            }
            entry.1 += 1;
            leftover -= 1;
        }

        let my_extra = entries
            .iter()
            .find(|(sid, _, _)| *sid == ctx.sandbox_id)
            .map(|(_, e, _)| *e)
            .unwrap_or(0);

        self.min_per_worker + my_extra
    }

    fn lock(&mut self, sandbox_id: usize, jobs: usize) {
        self.locked.insert(sandbox_id, jobs);
    }

    fn release(&mut self, sandbox_id: usize) {
        self.locked.remove(&sandbox_id);
    }

    fn name(&self) -> &str {
        "weighted_fair_share"
    }

    fn debug_state(&self) -> String {
        let mut pairs: Vec<_> = self.locked.iter().collect();
        pairs.sort_by_key(|(sid, _)| *sid);
        let locked_str: Vec<String> = pairs.iter().map(|(s, j)| format!("{}:{}", s, j)).collect();
        let used: usize = self.locked.values().sum();
        format!(
            "locked:{{{}}} used:{}/{}",
            locked_str.join(","),
            used,
            self.max_jobs
        )
    }
}

/**
 * Simple equal division: each worker gets `max / active`.
 *
 * Every worker entering a build phase gets the same allocation:
 * the total budget divided by the number of dispatched workers.
 * Weights, remaining depth, and upcoming packages are all ignored.
 *
 * The actual allocation is capped by the available (unlocked) budget
 * and floored at `min` to guarantee minimum progress.
 */
struct EqualShare {
    max_jobs: usize,
    min_per_worker: usize,
    locked: HashMap<usize, usize>,
}

impl JobAllocator for EqualShare {
    fn allocate(&self, ctx: &AllocContext) -> usize {
        if ctx.sole_builder {
            return self.max_jobs;
        }

        let active = ctx.all_dispatched.len().max(1);
        let ideal = self.max_jobs / active;

        let locked_total: usize = self.locked.values().sum();
        let available = self.max_jobs.saturating_sub(locked_total);

        ideal.min(available).max(self.min_per_worker)
    }

    fn lock(&mut self, sandbox_id: usize, jobs: usize) {
        self.locked.insert(sandbox_id, jobs);
    }

    fn release(&mut self, sandbox_id: usize) {
        self.locked.remove(&sandbox_id);
    }

    fn name(&self) -> &str {
        "equal_share"
    }

    fn debug_state(&self) -> String {
        let mut pairs: Vec<_> = self.locked.iter().collect();
        pairs.sort_by_key(|(sid, _)| *sid);
        let locked_str: Vec<String> = pairs.iter().map(|(s, j)| format!("{}:{}", s, j)).collect();
        let used: usize = self.locked.values().sum();
        format!(
            "locked:{{{}}} used:{}/{}",
            locked_str.join(","),
            used,
            self.max_jobs
        )
    }
}

/**
 * Create a [`JobAllocator`] from dynamic jobs configuration.
 */
pub fn make_allocator(dj: &DynamicJobs) -> Box<dyn JobAllocator> {
    match dj.algorithm {
        JobAlgorithm::WeightedFairShare => Box::new(WeightedFairShare {
            max_jobs: dj.max,
            min_per_worker: dj.min,
            locked: HashMap::new(),
        }),
        JobAlgorithm::EqualShare => Box::new(EqualShare {
            max_jobs: dj.max,
            min_per_worker: dj.min,
            locked: HashMap::new(),
        }),
    }
}
