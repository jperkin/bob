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
use tracing::trace;

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
    serial_fraction: f64,
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

    fn estimated_ms(&self, jobs: usize) -> f64 {
        let j = jobs.max(1) as f64;
        let p = self.t1_ms * self.serial_fraction;
        let q = self.t1_ms * (1.0 - self.serial_fraction);
        p + q / j
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
 * Pending worker awaiting job allocation.
 */
struct PendingWorker {
    pkgpath: String,
    jobs: usize,
}

/**
 * Tracks MAKE_JOBS budget allocation across concurrent builds.
 *
 * Uses minimax allocation based on Amdahl's law speed models. Each
 * extra job goes to whichever pending worker has the longest estimated
 * build time, equalizing finish times to minimize makespan.
 */
pub(crate) struct JobAllocator {
    max_jobs: usize,
    estimates: HashMap<String, SpeedModel>,
    pending: HashMap<usize, PendingWorker>,
    locked: HashMap<usize, usize>,
}

impl JobAllocator {
    pub(crate) fn new(max_jobs: usize, estimates: HashMap<String, SpeedModel>) -> Self {
        Self {
            max_jobs,
            estimates,
            pending: HashMap::new(),
            locked: HashMap::new(),
        }
    }

    /**
     * Register a newly dispatched worker and recompute pending allocations.
     */
    pub(crate) fn dispatch(&mut self, sandbox_id: usize, pkgpath: &str) {
        self.pending.insert(
            sandbox_id,
            PendingWorker {
                pkgpath: pkgpath.to_string(),
                jobs: 1,
            },
        );
        self.recompute();
    }

    /**
     * Lock a worker's allocation as it enters the build phase.
     */
    pub(crate) fn lock(&mut self, sandbox_id: usize) -> usize {
        let (jobs, pkgpath) = if let Some(w) = self.pending.remove(&sandbox_id) {
            (w.jobs, w.pkgpath)
        } else {
            (1, String::new())
        };
        let model = self.estimates.get(&pkgpath).cloned().unwrap_or_default();
        self.locked.insert(sandbox_id, jobs);
        trace!(
            sandbox_id,
            jobs,
            estimated_ms = model.estimated_ms(jobs),
            pkgpath = %pkgpath,
            "JobAllocator locked"
        );
        self.recompute();
        jobs
    }

    /**
     * Release a worker's allocation and recompute pending.
     */
    pub(crate) fn release(&mut self, sandbox_id: usize) {
        self.locked.remove(&sandbox_id);
        self.pending.remove(&sandbox_id);
        self.recompute();
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

    /**
     * Minimax distribution of MAKE_JOBS.
     *
     * Each pending worker starts at 1 job. Remaining budget is handed
     * out one at a time to whichever worker has the longest estimated
     * build time, equalizing finish times to minimize makespan.
     */
    fn recompute(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let locked_sum: usize = self.locked.values().sum();
        let available = self.max_jobs.saturating_sub(locked_sum);
        let n = self.pending.len();
        if available <= n {
            for w in self.pending.values_mut() {
                w.jobs = 1;
            }
            return;
        }
        for w in self.pending.values_mut() {
            w.jobs = 1;
        }

        let pending_sids: Vec<usize> = self.pending.keys().copied().collect();
        let mut remaining = available - n;

        while remaining > 0 {
            let mut best_sid = None;
            let mut best_est = -1.0_f64;

            for &sid in &pending_sids {
                if let Some(w) = self.pending.get(&sid) {
                    let model = self.estimates.get(&w.pkgpath).cloned().unwrap_or_default();
                    let est = model.estimated_ms(w.jobs);
                    if est > best_est {
                        best_est = est;
                        best_sid = Some(sid);
                    }
                }
            }

            let Some(winner) = best_sid else { break };
            if let Some(w) = self.pending.get_mut(&winner) {
                w.jobs += 1;
            }
            remaining -= 1;
        }
    }
}
