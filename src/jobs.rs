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
 * When dynamic_jobs is enabled, the build manager distributes a total
 * CPU budget across concurrent package builds.  The [`JobAllocator`]
 * trait defines the interface, and [`make_allocator`] selects the
 * concrete implementation based on configuration.
 */

use crate::config::{DynamicJobs, JobAlgorithm};
use std::collections::HashMap;

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
 * The budget reserves `min_per_worker` for each dispatched
 * worker.  The remaining "extra" is distributed proportionally by
 * weight using the largest-remainder method across unlocked workers,
 * after subtracting what locked workers have already consumed.
 * This prevents a worker from over-allocating when earlier workers
 * already hold budget above the minimum.
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
            unlocked.push((usize::MAX - i, w));
        }

        let total_weight: usize = unlocked.iter().map(|(_, w)| *w).sum();
        if total_weight == 0 {
            return self.min_per_worker;
        }

        /*
         * Largest-remainder method: take the floor of each proportional
         * share, then hand out the leftover one at a time to whichever
         * entries have the biggest fractional parts.
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
 * Simple equal division: each build-phase worker gets max / active.
 *
 * Ignores weights entirely. Useful as a baseline for comparison
 * and for users who don't want weight-based skew.
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
