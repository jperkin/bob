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

//! MAKE_JOBS allocation and speed modelling.
//!
//! This module provides types for managing parallel make job allocation
//! across concurrent package builds, using Amdahl's law speed models
//! fitted from historical build data.

use std::collections::HashMap;
use std::sync::mpsc::Sender;

/**
 * MAKE_JOBS configuration for a package build.
 */
#[derive(Clone, Copy, Debug, Default)]
pub enum MakeJobs {
    /**
     * Package has MAKE_JOBS_SAFE=no; parallel make not supported.
     */
    #[default]
    NotSafe,
    /**
     * Parallel make with this many jobs.
     */
    Jobs(usize),
}

impl MakeJobs {
    pub(crate) fn is_safe(&self) -> bool {
        matches!(self, Self::Jobs(_))
    }

    /**
     * Integer representation for storage (0 = not safe).
     */
    pub fn count(&self) -> usize {
        match self {
            Self::NotSafe => 0,
            Self::Jobs(n) => *n,
        }
    }
}

impl serde::Serialize for MakeJobs {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.count() as u64)
    }
}

impl<'de> serde::Deserialize<'de> for MakeJobs {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let n = u64::deserialize(d)? as usize;
        Ok(if n == 0 { Self::NotSafe } else { Self::Jobs(n) })
    }
}

const DEFAULT_SERIAL_FRACTION: f64 = 0.5;

/**
 * Amdahl's law speed model for a package: T(j) = p + q/j.
 *
 * `p` is the serial component and `q` is the parallel component.
 * Fitted from historical (make_jobs, duration_ms) observations via
 * linear regression on y = T, x = 1/j.
 */
#[derive(Clone, Debug)]
pub struct SpeedModel {
    pub(crate) t1_ms: f64,
    #[allow(dead_code)]
    serial_fraction: f64,
}

impl SpeedModel {
    pub(crate) fn from_samples(data: &[(usize, f64)]) -> Self {
        if data.is_empty() {
            return Self::default();
        }
        if data.len() == 1 {
            let (_, ms) = data[0];
            return Self {
                t1_ms: ms.max(1.0),
                serial_fraction: DEFAULT_SERIAL_FRACTION,
            };
        }
        /*
         * Linear regression: y = T, x = 1/j  =>  T = p + q * (1/j)
         * where p = serial component, q = parallel component.
         */
        let n = data.len() as f64;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_xx = 0.0;
        for &(jobs, ms) in data {
            let x = 1.0 / jobs as f64;
            sum_x += x;
            sum_y += ms;
            sum_xy += x * ms;
            sum_xx += x * x;
        }
        let denom = n * sum_xx - sum_x * sum_x;
        let (p, q) = if denom.abs() < 1e-12 {
            let avg = sum_y / n;
            (
                avg * DEFAULT_SERIAL_FRACTION,
                avg * (1.0 - DEFAULT_SERIAL_FRACTION),
            )
        } else {
            let q_raw = (n * sum_xy - sum_x * sum_y) / denom;
            let p_raw = (sum_y - q_raw * sum_x) / n;
            (p_raw.max(0.0), q_raw.max(0.0))
        };
        let t1 = p + q;
        let sf = if t1 > 0.0 {
            (p / t1).clamp(0.0, 1.0)
        } else {
            DEFAULT_SERIAL_FRACTION
        };
        Self {
            t1_ms: t1.max(1.0),
            serial_fraction: sf,
        }
    }
}

impl Default for SpeedModel {
    fn default() -> Self {
        Self {
            t1_ms: 100.0,
            serial_fraction: DEFAULT_SERIAL_FRACTION,
        }
    }
}

/**
 * One-shot channel for returning MAKE_JOBS from the manager to a worker.
 */
pub(crate) struct MakeJobsResponder(pub(crate) Sender<usize>);

impl std::fmt::Debug for MakeJobsResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MakeJobsResponder")
    }
}

/**
 * Tracks MAKE_JOBS budget allocation across concurrent builds.
 *
 * The total CPU budget (`max_jobs`) is divided into a base allocation
 * (1 per dispatched worker) and an extra pool distributed
 * proportionally by weight using Hamilton's method.
 *
 * Weight reflects a package's impact on overall build time: the
 * maximum of its critical-path depth (longest chain of remaining
 * dependents) and its total dependent work divided by the number of
 * workers. This captures both depth (serial bottlenecks) and
 * breadth (fan-out gating many packages).
 *
 * Ready packages that idle workers will pick up soon participate as
 * virtual entries, reserving budget so that high-impact upcoming
 * packages get adequate allocation when they start.
 *
 * When exactly one worker is running and nothing else is ready to
 * dispatch, the worker gets the full budget.
 */
pub(crate) struct JobAllocator {
    max_jobs: usize,
    locked: HashMap<usize, usize>,
}

impl JobAllocator {
    pub(crate) fn new(max_jobs: usize) -> Self {
        Self {
            max_jobs,
            locked: HashMap::new(),
        }
    }

    /**
     * Allocate MAKE_JOBS for a worker entering a CPU phase.
     *
     * `sole_builder` should be true only when this is the sole running
     * worker AND no packages are ready to dispatch.
     *
     * `all_dispatched` lists `(sandbox_id, weight)` for every worker
     * that currently has a package assigned.
     *
     * `upcoming` are weights for ready-to-dispatch packages that idle
     * workers will pick up soon, truncated to idle worker slots.
     */
    pub(crate) fn allocate(
        &self,
        sandbox_id: usize,
        all_dispatched: &[(usize, usize)],
        sole_builder: bool,
        upcoming: &[usize],
    ) -> usize {
        if sole_builder {
            return self.max_jobs;
        }

        let active = all_dispatched.len().max(1);
        let extra_pool = self.max_jobs.saturating_sub(active);
        let locked_extra: usize = self.locked.values().map(|j| j.saturating_sub(1)).sum();
        let remaining_extra = extra_pool.saturating_sub(locked_extra);

        if remaining_extra == 0 {
            return 1;
        }

        /*
         * Compute ideal allocation across ALL dispatched workers
         * (locked and unlocked) plus upcoming virtual entries,
         * distributed proportionally over the full extra pool.
         *
         * This prevents a small package from grabbing all available
         * cores just because it happens to be the last to enter a
         * build phase. Each worker gets its proportional share of
         * the total budget regardless of entry order.
         *
         * The result is capped by remaining_extra so that locked
         * over-allocations from earlier rounds don't cause budget
         * overflow.
         */
        let mut entries: Vec<(usize, usize)> = all_dispatched.to_vec();
        for (i, &weight) in upcoming.iter().enumerate() {
            entries.push((usize::MAX - i, weight));
        }

        if entries.is_empty() {
            return 1;
        }

        let total_weight: usize = entries.iter().map(|(_, w)| *w).sum();

        let my_ideal = if total_weight == 0 {
            let per = extra_pool / entries.len();
            let leftover = extra_pool % entries.len();
            let idx = entries.iter().position(|(sid, _)| *sid == sandbox_id);
            per + if idx.is_some_and(|i| i < leftover) {
                1
            } else {
                0
            }
        } else {
            let mut allocs: Vec<(usize, usize, f64)> = entries
                .iter()
                .map(|&(sid, w)| {
                    let exact = w as f64 / total_weight as f64 * extra_pool as f64;
                    (sid, exact as usize, exact.fract())
                })
                .collect();
            let floor_total: usize = allocs.iter().map(|(_, f, _)| *f).sum();
            let leftover = extra_pool - floor_total;
            let mut idx: Vec<usize> = (0..allocs.len()).collect();
            idx.sort_unstable_by(|&a, &b| {
                allocs[b]
                    .2
                    .partial_cmp(&allocs[a].2)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            for &i in idx.iter().take(leftover) {
                allocs[i].1 += 1;
            }
            allocs
                .iter()
                .find(|(sid, _, _)| *sid == sandbox_id)
                .map(|(_, e, _)| *e)
                .unwrap_or(0)
        };

        1 + my_ideal.min(remaining_extra)
    }

    /**
     * Record that a worker has locked an allocation.
     */
    pub(crate) fn lock(&mut self, sandbox_id: usize, jobs: usize) {
        self.locked.insert(sandbox_id, jobs);
    }

    /**
     * Release a worker's CPU lock.
     */
    pub(crate) fn release(&mut self, sandbox_id: usize) {
        self.locked.remove(&sandbox_id);
    }

    /**
     * Return a summary of internal state for debug logging.
     */
    pub(crate) fn debug_state(&self) -> String {
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
