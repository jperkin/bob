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
 * MAKE_JOBS allocation.
 *
 * Packages that do not set MAKE_JOBS_SAFE=no can use parallel make.  The
 * [`Allocator`] decides how many jobs each package gets, based on
 * historical build CPU time from previous runs if available.
 *
 * The allocator maps each package's CPU time onto a log scale covering
 * the full range of observed values, then linearly interpolates
 * between min_jobs and max_jobs.  Packages with no history get a
 * fair share (jobs / workers).  When only one package can run
 * (sole builder), it gets the entire budget.
 *
 * [`PkgMakeJobs`] tracks the full lifecycle for a single package:
 *
 *  1. Created with `new(safe)` from the scan's MAKE_JOBS_SAFE flag.
 *  2. The scheduler calls `allocate(jobs)` with the allocator's
 *     output.  This sets the MAKE_JOBS value passed to bmake.
 *  3. After bmake runs, `set_jobs(n)` records the actual _MAKE_JOBS_N
 *     value bmake resolved to (which may differ from the allocation
 *     if the package caps it lower).
 */

use std::collections::HashMap;

use pkgsrc::PkgName;
use tracing::debug;

use crate::db::BuildStageTiming;

/**
 * Maps historical CPU time to a job count for each package.
 *
 * Created once per build with the total MAKE_JOBS budget and
 * number of concurrent workers.  Call [`calibrate`](Self::calibrate)
 * with the sorted CPU times from all safe packages, then call
 * [`assign`](Self::assign) per package at dispatch time.
 */
pub struct Allocator {
    /// Total MAKE_JOBS budget across all workers (`dynamic.jobs` config).
    jobs: usize,
    /// Equal share per worker: jobs / workers (rounded up).  Used as
    /// the default for packages with no build history.
    fair: usize,
    /// Fewest jobs any package gets, clamped to total jobs.
    min_jobs: usize,
    /// Most jobs a non-sole package gets, clamped to total jobs.
    max_jobs: usize,
    /// Natural log of the smallest CPU time in the calibration set.
    log_min: f64,
    /// Span of the log scale: ln(max) - ln(min).
    /// Zero means all packages have the same CPU time (or no data).
    log_range: f64,
}

impl Allocator {
    /**
     * Create an allocator for the given build configuration.
     *
     * `workers` is the number of concurrent build slots.  `jobs`
     * is the total MAKE_JOBS budget (from the `dynamic.jobs` config
     * option).
     *
     * `fair` is the equal share each worker gets (jobs / workers,
     * rounded up), used as the default for packages with no history.
     * `min_jobs` is 2 (so even the lightest package gets some
     * parallelism), and `max_jobs` is derived from the fair share.
     * Both are clamped to the total so they never exceed what is
     * available.
     */
    pub fn new(workers: usize, jobs: usize) -> Self {
        let fair = jobs.div_ceil(workers.max(1));
        let min_jobs = 2.min(jobs);
        let max_jobs = (fair + 2).max(jobs / 3).min(jobs);
        Self {
            jobs,
            fair,
            min_jobs,
            max_jobs,
            log_min: 0.0,
            log_range: 0.0,
        }
    }

    /**
     * Set the log scale endpoints from the full set of historical
     * CPU times.
     *
     * `cpu_times` must be sorted ascending.  Call this once before
     * any calls to [`assign`](Self::assign).  Without calibration,
     * all packages get a fair share.
     */
    pub fn calibrate(&mut self, cpu_times: &[usize]) {
        if cpu_times.is_empty() {
            return;
        }
        let min_t = cpu_times[0].max(1) as f64;
        let max_t = cpu_times[cpu_times.len() - 1].max(1) as f64;
        self.log_min = min_t.ln();
        self.log_range = (max_t.ln() - self.log_min).max(1.0);
    }

    /**
     * Compute the job count for a package.
     *
     * Maps `cpu_time` onto the calibrated log scale and interpolates
     * between min_jobs and max_jobs.  Packages with no history
     * (`None`) get a fair share (jobs / workers).  A sole builder
     * (nothing else running or ready) gets the entire budget.
     */
    pub fn assign(&self, cpu_time: Option<usize>, sole_builder: bool) -> usize {
        if sole_builder {
            return self.jobs;
        }
        if self.log_range == 0.0 {
            return self.fair;
        }
        match cpu_time {
            Some(v) if v > 0 => {
                let t = ((v as f64).ln() - self.log_min) / self.log_range;
                let t = t.clamp(0.0, 1.0);
                let j = self.min_jobs as f64 + t * (self.max_jobs - self.min_jobs) as f64;
                (j.round() as usize).clamp(self.min_jobs, self.max_jobs)
            }
            _ => self.fair,
        }
    }
}

/**
 * MAKE_JOBS state for a single package.
 *
 * Tracks whether the package supports parallel make, the job count
 * allocated by the scheduler, and the actual MAKE_JOBS value used
 * by bmake for the build.
 */
#[derive(Clone, Copy, Debug)]
pub struct PkgMakeJobs {
    safe: bool,
    allocated: Option<usize>,
    jobs: Option<usize>,
}

impl PkgMakeJobs {
    pub fn new(safe: bool) -> Self {
        Self {
            safe,
            allocated: None,
            jobs: None,
        }
    }

    /// Whether the package supports parallel make.
    pub fn safe(&self) -> bool {
        self.safe
    }

    /// Job count allocated by the scheduler.
    pub fn allocated(&self) -> Option<usize> {
        self.allocated
    }

    /// Actual MAKE_JOBS value used by bmake.
    pub fn jobs(&self) -> Option<usize> {
        self.jobs
    }

    /// Record the scheduler's job allocation.
    pub fn allocate(&mut self, jobs: usize) {
        debug_assert!(self.safe, "allocate called on unsafe package");
        self.allocated = Some(jobs);
    }

    /// Record the actual MAKE_JOBS value from bmake.
    pub fn set_jobs(&mut self, n: usize) {
        self.jobs = Some(n);
    }
}

impl Default for PkgMakeJobs {
    fn default() -> Self {
        Self::new(false)
    }
}

impl serde::Serialize for PkgMakeJobs {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.jobs.serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for PkgMakeJobs {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let jobs = Option::<usize>::deserialize(d)?;
        let mut mj = PkgMakeJobs::new(jobs.is_some());
        if let Some(n) = jobs {
            mj.set_jobs(n);
        }
        Ok(mj)
    }
}

pub(crate) fn pkg_cpu_history(
    stage_timings: &HashMap<(String, String), BuildStageTiming>,
    pkg_paths: &HashMap<PkgName, String>,
) -> HashMap<PkgName, usize> {
    let mut result: HashMap<PkgName, usize> = HashMap::new();
    let mut with_history = 0usize;
    for (pkgname, pkgpath) in pkg_paths {
        let pkgbase = pkgname.pkgbase().to_string();
        if let Some(t) = stage_timings.get(&(pkgpath.clone(), pkgbase)) {
            if t.cpu_ms > 0 {
                result.insert(pkgname.clone(), t.cpu_ms as usize);
                with_history += 1;
            }
        }
    }
    debug!(
        with_history,
        total = pkg_paths.len(),
        "pkg_cpu_history computed"
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calibrated(workers: usize, jobs: usize, cpu_times: &[usize]) -> Allocator {
        let mut alloc = Allocator::new(workers, jobs);
        alloc.calibrate(cpu_times);
        alloc
    }

    #[test]
    fn sole_builder_gets_all_jobs() {
        for &(w, c) in &[(4, 16), (7, 10), (24, 32)] {
            let alloc = Allocator::new(w, c);
            assert_eq!(
                alloc.assign(Some(1000), true),
                c,
                "w={w} c={c} with history"
            );
            assert_eq!(alloc.assign(None, true), c, "w={w} c={c} no history");
        }
    }

    #[test]
    fn no_history_gets_fair_share() {
        for &(w, c, fair) in &[(4, 16, 4), (7, 10, 2), (24, 32, 2)] {
            let alloc = Allocator::new(w, c);
            for i in 0..w {
                assert_eq!(alloc.assign(None, false), fair, "w={w} c={c} worker {i}");
            }
        }
    }

    #[test]
    fn history_spreads_across_range() {
        /* w=4 c=16: min=2, max=6 */
        let times = [100, 1_000, 10_000, 100_000];
        let alloc = calibrated(4, 16, &times);
        let assigned: Vec<usize> = times
            .iter()
            .map(|&v| alloc.assign(Some(v), false))
            .collect();
        assert_eq!(assigned, [2, 3, 5, 6], "w=4 c=16");

        /* w=7 c=10: min=2, max=3 (narrow range) */
        let times = [100, 300, 1_000, 3_000, 10_000, 30_000, 100_000];
        let alloc = calibrated(7, 10, &times);
        let assigned: Vec<usize> = times
            .iter()
            .map(|&v| alloc.assign(Some(v), false))
            .collect();
        assert_eq!(assigned, [2, 2, 3, 3, 3, 4, 4], "w=7 c=10");

        /* w=24 c=32: min=2, max=10 (wide range, doubling times) */
        let times: Vec<usize> = (0..24).map(|i| 100 * (1 << i)).collect();
        let alloc = calibrated(24, 32, &times);
        let assigned: Vec<usize> = times
            .iter()
            .map(|&v| alloc.assign(Some(v), false))
            .collect();
        assert_eq!(
            assigned,
            [
                2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 7, 7, 7, 8, 8, 8, 9, 9, 9, 10, 10
            ],
            "w=24 c=32"
        );
    }

    #[test]
    fn unsafe_package_gets_one_job() {
        let mut mj = PkgMakeJobs::new(false);
        assert!(!mj.safe());
        assert_eq!(mj.allocated(), None);
        mj.set_jobs(1);
        assert_eq!(mj.jobs(), Some(1));
    }

    #[test]
    fn empty_calibration_returns_fair() {
        let alloc = calibrated(4, 16, &[]);
        assert_eq!(alloc.assign(Some(5000), false), 4);
    }

    #[test]
    fn no_history_after_calibration_returns_fair() {
        let alloc = calibrated(4, 16, &[100, 10_000]);
        assert_eq!(alloc.assign(None, false), 4);
    }

    #[test]
    fn safe_package_allocate_and_jobs() {
        let mut mj = PkgMakeJobs::new(true);
        assert!(mj.safe());
        mj.allocate(8);
        assert_eq!(mj.allocated(), Some(8));
        mj.set_jobs(6);
        assert_eq!(mj.jobs(), Some(6));
    }

    #[test]
    fn serde_roundtrip() {
        let mut mj = PkgMakeJobs::new(true);
        mj.set_jobs(4);
        let json = serde_json::to_string(&mj).expect("serialize");
        assert_eq!(json, "4");

        let de: PkgMakeJobs = serde_json::from_str(&json).expect("deserialize");
        assert!(de.safe());
        assert_eq!(de.jobs(), Some(4));

        let mj = PkgMakeJobs::new(false);
        let json = serde_json::to_string(&mj).expect("serialize null");
        assert_eq!(json, "null");

        let de: PkgMakeJobs = serde_json::from_str(&json).expect("deserialize null");
        assert!(!de.safe());
        assert_eq!(de.jobs(), None);
    }

    #[test]
    fn jobs_less_than_workers() {
        let alloc = Allocator::new(4, 1);
        assert_eq!(alloc.assign(None, false), 1, "fair clamped to 1");
        assert_eq!(alloc.assign(Some(1000), true), 1, "sole builder gets all");
    }

    #[test]
    fn max_jobs_clamped_to_total() {
        let alloc = calibrated(1, 3, &[100, 100_000]);
        assert_eq!(
            alloc.assign(Some(100_000), false),
            3,
            "max clamped to total"
        );
    }
}
