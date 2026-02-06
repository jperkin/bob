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
}

/**
 * Distribute extra budget proportional to critical path depth.
 *
 * Each worker's ideal allocation is proportional to its critical
 * path depth among ALL dispatched workers, not just those currently
 * in the build phase.  Locked allocations (workers mid-build)
 * cannot be reclaimed, so a new worker gets
 * `min(ideal_share, available_budget)`.
 */
struct WeightedFairShare {
    max_jobs: usize,
    min_per_worker: usize,
    build_threads: usize,
    locked: HashMap<usize, usize>,
}

impl JobAllocator for WeightedFairShare {
    fn allocate(&self, ctx: &AllocContext) -> usize {
        if ctx.sole_builder {
            return self.max_jobs;
        }

        let total_weight: usize = ctx.all_dispatched.iter().map(|(_, w)| *w).sum();
        let extra = self
            .max_jobs
            .saturating_sub(self.build_threads * self.min_per_worker);

        let ideal = if total_weight > 0 && extra > 0 {
            let share = extra as f64 * ctx.my_weight as f64 / total_weight as f64;
            self.min_per_worker + share.round() as usize
        } else {
            self.min_per_worker
        };

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
        "weighted_fair_share"
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
}

/**
 * Create a [`JobAllocator`] from dynamic jobs configuration.
 */
pub fn make_allocator(dj: &DynamicJobs, build_threads: usize) -> Box<dyn JobAllocator> {
    match dj.algorithm {
        JobAlgorithm::WeightedFairShare => Box::new(WeightedFairShare {
            max_jobs: dj.max,
            min_per_worker: dj.min,
            build_threads,
            locked: HashMap::new(),
        }),
        JobAlgorithm::EqualShare => Box::new(EqualShare {
            max_jobs: dj.max,
            min_per_worker: dj.min,
            locked: HashMap::new(),
        }),
    }
}
