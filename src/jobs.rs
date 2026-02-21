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
    pub(crate) serial_fraction: f64,
}

impl SpeedModel {
    pub(crate) fn from_samples(data: &[(usize, f64)]) -> Self {
        if data.is_empty() {
            return Self::default();
        }
        if data.len() == 1 {
            return Self {
                t1_ms: data[0].1,
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
 * Amdahl's law parameters and critical-path depth for a worker,
 * used by the allocator to estimate build cost at different job
 * counts: `T(j) = t1_ms * (sf + (1-sf)/j) + remaining_depth`.
 */
#[derive(Clone, Copy, Debug)]
pub(crate) struct WorkerModel {
    pub(crate) t1_ms: f64,
    pub(crate) serial_fraction: f64,
    pub(crate) remaining_depth: f64,
}

impl WorkerModel {
    /**
     * Estimated wall-clock cost at `jobs` cores: Amdahl's T(j)
     * plus the critical-path cost of packages that depend on this
     * one. Minimizing the max of this across workers minimizes
     * overall makespan.
     */
    fn cost(&self, jobs: usize) -> f64 {
        let j = jobs.max(1) as f64;
        self.t1_ms * (self.serial_fraction + (1.0 - self.serial_fraction) / j)
            + self.remaining_depth
    }
}

/**
 * Tracks MAKE_JOBS budget allocation across concurrent builds.
 *
 * The total CPU budget (`max_jobs`) is divided into a minimum
 * reservation (1 per dispatched worker) and an extra pool distributed
 * via minimax allocation using Amdahl's law speed models.
 *
 * Each extra core goes to whichever worker currently has the highest
 * estimated cost `T(j) + remaining_depth`, equalizing finish times
 * across the critical path. This minimizes makespan: packages that
 * either take a long time themselves or sit on the critical path
 * get more cores.
 *
 * Ready packages that idle workers will pick up soon participate as
 * virtual entries, reserving budget so that high-cost upcoming
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
     * `all_dispatched` lists `(sandbox_id, model)` for every worker
     * that currently has a package assigned.
     *
     * `upcoming` are models for ready-to-dispatch packages that idle
     * workers will pick up soon, truncated to idle worker slots.
     */
    pub(crate) fn allocate(
        &self,
        sandbox_id: usize,
        all_dispatched: &[(usize, WorkerModel)],
        sole_builder: bool,
        upcoming: &[WorkerModel],
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
         * Collect unlocked dispatched workers and upcoming virtual
         * entries. Each starts at 1 job (the base allocation).
         * Distribute remaining_extra via minimax: each core goes to
         * whichever entry has the highest T(j) + remaining_depth,
         * equalizing estimated finish times.
         */
        let mut extras: Vec<(usize, WorkerModel, usize)> = all_dispatched
            .iter()
            .filter(|(sid, _)| !self.locked.contains_key(sid))
            .map(|&(sid, model)| (sid, model, 0))
            .collect();
        for (i, &model) in upcoming.iter().enumerate() {
            extras.push((usize::MAX - i, model, 0));
        }

        if extras.is_empty() {
            return 1;
        }

        for _ in 0..remaining_extra {
            if let Some(best) = (0..extras.len()).max_by(|&a, &b| {
                let ca = extras[a].1.cost(1 + extras[a].2);
                let cb = extras[b].1.cost(1 + extras[b].2);
                ca.partial_cmp(&cb)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| {
                        extras[a]
                            .1
                            .remaining_depth
                            .partial_cmp(&extras[b].1.remaining_depth)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
            }) {
                extras[best].2 += 1;
            }
        }

        let my_extra = extras
            .iter()
            .find(|(sid, _, _)| *sid == sandbox_id)
            .map(|(_, _, e)| *e)
            .unwrap_or(0);

        1 + my_extra
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
