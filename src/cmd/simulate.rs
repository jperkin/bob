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

use std::collections::{HashMap, HashSet};
use std::io::BufRead;
use std::path::Path;
use std::task::Poll;

use anyhow::{Context, Result, bail};

use bob::try_println;
use bob::{HistoryKind, PackageNode, Scheduler, Stage};

/**
 * Per-package timing profile loaded from a history CSV.
 *
 * Phases:
 *   overhead_pre  = pre-clean + depends + checksum (serial)
 *   configure     = configure stage (serial)
 *   build         = build stage (parallel, scales with jobs)
 *   overhead_post = install + package + deinstall + clean (serial)
 */
struct PkgProfile {
    overhead_pre_ms: u64,
    configure_wall_ms: u64,
    build_cpu_ms: u64,
    build_wall_ms: u64,
    overhead_post_ms: u64,
    hist_jobs: u64,
    make_jobs_safe: bool,
}

impl PkgProfile {
    /**
     * Phase durations in seconds: [overhead_pre, configure, build, overhead_post].
     *
     * Only the build phase scales with jobs.
     * All other phases are serial.
     */
    fn phase_durations(&self, jobs: usize) -> [usize; 4] {
        let build_ms = Self::estimate_build_time(
            self.build_cpu_ms,
            self.build_wall_ms,
            self.hist_jobs,
            jobs.max(1) as u64,
        );
        [
            (self.overhead_pre_ms / 1000).max(1) as usize,
            (self.configure_wall_ms / 1000).max(1) as usize,
            (build_ms / 1000).max(1) as usize,
            (self.overhead_post_ms / 1000).max(1) as usize,
        ]
    }

    fn estimate_build_time(cpu_ms: u64, wall_ms: u64, hist_jobs: u64, target_jobs: u64) -> u64 {
        if wall_ms == 0 || cpu_ms == 0 {
            return wall_ms;
        }
        let ratio = cpu_ms as f64 / wall_ms as f64;
        if ratio <= 1.0 {
            return wall_ms;
        }
        let parallel_at_hist = cpu_ms / hist_jobs.max(1);
        let serial = wall_ms.saturating_sub(parallel_at_hist);
        serial + cpu_ms / target_jobs
    }
}

fn col(cols: &HashMap<String, usize>, name: &str) -> Result<usize> {
    cols.get(name)
        .copied()
        .with_context(|| format!("Missing column '{name}' in history CSV"))
}

/**
 * Load detailed per-package profiles from a history CSV.
 *
 * Accepts plain CSV or zstd-compressed CSV (detected by .zst extension).
 */
fn load_history(path: &Path) -> Result<HashMap<String, PkgProfile>> {
    let file =
        std::fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let buf = std::io::BufReader::new(file);
    let reader: Box<dyn BufRead> = if path.extension().map(|e| e == "zst").unwrap_or(false) {
        let decoder = zstd::Decoder::new(buf)
            .with_context(|| format!("Failed to decompress {}", path.display()))?;
        Box::new(std::io::BufReader::new(decoder))
    } else {
        Box::new(buf)
    };
    let mut lines = reader.lines();

    let header = lines
        .next()
        .context("Empty history file")?
        .context("Failed to read header")?;
    let cols: HashMap<String, usize> = header
        .split(',')
        .enumerate()
        .map(|(i, name)| (name.to_string(), i))
        .collect();

    let pkgname = col(&cols, HistoryKind::Pkgname.into())?;
    let outcome = col(&cols, HistoryKind::Outcome.into())?;
    let make_jobs = col(&cols, HistoryKind::MakeJobs.into())?;
    let pre_clean = col(&cols, Stage::PreClean.into_str())?;
    let depends = col(&cols, Stage::Depends.into_str())?;
    let checksum = col(&cols, Stage::Checksum.into_str())?;
    let configure = col(&cols, Stage::Configure.into_str())?;
    let build = col(&cols, Stage::Build.into_str())?;
    let install = col(&cols, Stage::Install.into_str())?;
    let package = col(&cols, Stage::Package.into_str())?;
    let deinstall = col(&cols, Stage::Deinstall.into_str())?;
    let clean = col(&cols, Stage::Clean.into_str())?;
    let cpu_build = col(&cols, &format!("cpu:{}", Stage::Build.into_str()))?;

    let ncols = cols.len();
    let mut result = HashMap::new();
    let parse = |s: &str| -> u64 { s.parse::<u64>().unwrap_or(0) };
    for line in lines {
        let line = line.context("Failed to read history line")?;
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() != ncols {
            continue;
        }
        if fields[outcome] != "success" {
            continue;
        }
        let pkg = fields[pkgname].to_string();
        let make_jobs_safe = fields[make_jobs] != "-";
        let hist_jobs = if make_jobs_safe {
            fields[make_jobs].parse::<u64>().unwrap_or(1)
        } else {
            1
        };
        let overhead_pre_ms =
            parse(fields[pre_clean]) + parse(fields[depends]) + parse(fields[checksum]);
        let overhead_post_ms = parse(fields[install])
            + parse(fields[package])
            + parse(fields[deinstall])
            + parse(fields[clean]);
        result.insert(
            pkg,
            PkgProfile {
                overhead_pre_ms,
                configure_wall_ms: parse(fields[configure]),
                build_cpu_ms: parse(fields[cpu_build]),
                build_wall_ms: parse(fields[build]),
                overhead_post_ms,
                hist_jobs,
                make_jobs_safe,
            },
        );
    }
    Ok(result)
}

const PHASE_BUILD: usize = 2;
const PHASE_COUNT: usize = 4;

/**
 * Simulate a parallel build and report scheduling efficiency.
 *
 * Reads a dependency graph in edge format (`dep -> dependent`, one per
 * line) and runs an event-driven simulation with `workers` workers.
 *
 * Without `--history` each package takes one time unit.  With
 * `--history`, build durations are estimated from historical CPU and
 * wall times, and jobs are allocated using the same algorithm as
 * `bob build`.
 *
 * Use `--uniform` to force equal allocation for baseline comparison.
 *
 * Generate a history file with: `bob history -l --raw --format csv`
 */
pub fn run(
    file: &Path,
    workers: usize,
    jobs: Option<usize>,
    history_path: Option<&Path>,
    uniform: bool,
) -> Result<()> {
    if workers == 0 {
        bail!("workers must be at least 1");
    }

    let reader: Box<dyn BufRead> = if file == Path::new("-") {
        Box::new(std::io::BufReader::new(std::io::stdin()))
    } else {
        let f = std::fs::File::open(file)
            .with_context(|| format!("Failed to open {}", file.display()))?;
        let buf = std::io::BufReader::new(f);
        if file.extension().map(|e| e == "zst").unwrap_or(false) {
            let decoder = zstd::Decoder::new(buf)
                .with_context(|| format!("Failed to decompress {}", file.display()))?;
            Box::new(std::io::BufReader::new(decoder))
        } else {
            Box::new(buf)
        }
    };

    let mut packages: HashMap<String, PackageNode<String>> = HashMap::new();
    for line in reader.lines() {
        let line = line.context("Failed to read line")?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((dep, dependent)) = line.split_once(" -> ") else {
            bail!("malformed edge: {}", line);
        };
        packages
            .entry(dependent.to_string())
            .or_insert_with(|| PackageNode {
                deps: HashSet::new(),
                pbulk_weight: 100,
                cpu_time: 0,
            })
            .deps
            .insert(dep.to_string());
        packages
            .entry(dep.to_string())
            .or_insert_with(|| PackageNode {
                deps: HashSet::new(),
                pbulk_weight: 100,
                cpu_time: 0,
            });
    }

    let history = match history_path {
        Some(path) => load_history(path)?,
        None => HashMap::new(),
    };

    let pkg_count = packages.len();
    let mut sched = Scheduler::from_graph(packages);
    for (pkg, profile) in &history {
        if !profile.make_jobs_safe {
            sched.set_make_jobs_unsafe(pkg);
        }
        if !uniform && profile.build_cpu_ms > 0 {
            sched.set_pkg_cpu_history(pkg, profile.build_cpu_ms as usize);
        }
    }
    if let Some(mj) = jobs {
        sched.set_allocator(bob::makejobs::Allocator::new(workers, mj));
    }

    struct Slot {
        pkg: String,
        phase: usize,
        phase_end: usize,
        phases: [usize; PHASE_COUNT],
        jobs: usize,
    }

    impl Slot {
        fn active_jobs(&self) -> usize {
            if self.phase == PHASE_BUILD {
                self.jobs
            } else {
                1
            }
        }
    }

    let mut slots: Vec<Option<Slot>> = (0..workers).map(|_| None).collect();
    let mut time = 0usize;
    let mut total_busy = 0usize;
    let mut total_job_seconds = 0usize;
    let mut peak_jobs = 0usize;
    let mut overalloc_seconds = 0usize;
    let mut printing = true;

    loop {
        let mut state_changed = false;

        /*
         * Advance completed phases.  If a slot finishes its current
         * phase, move to the next.  If all phases are done, the
         * package is complete.
         */
        for slot in slots.iter_mut() {
            let done = if let Some(ref s) = *slot {
                s.phase_end == time && s.phase + 1 >= PHASE_COUNT
            } else {
                false
            };
            if done {
                let s = slot.take().expect("slot");
                sched.mark_success(&s.pkg);
                state_changed = true;
                continue;
            }
            if let Some(ref mut s) = *slot {
                while s.phase_end == time && s.phase + 1 < PHASE_COUNT {
                    s.phase += 1;
                    s.phase_end = time + s.phases[s.phase];
                }
            }
        }

        /*
         * Dispatch new packages to idle worker slots.
         */
        loop {
            let idle = slots.iter().position(|s| s.is_none());
            let Some(idx) = idle else { break };
            let Poll::Ready(Some(sp)) = sched.poll() else {
                break;
            };

            let jobs = sp.make_jobs.allocated().unwrap_or(1);

            let phases = if let Some(p) = history.get(&sp.pkg) {
                p.phase_durations(jobs)
            } else {
                [0, 0, 1, 0]
            };

            let total_d: usize = phases.iter().sum();
            total_busy += total_d;

            let first_phase_dur = phases[0];
            slots[idx] = Some(Slot {
                pkg: sp.pkg,
                phase: 0,
                phase_end: time + first_phase_dur,
                phases,
                jobs,
            });
            state_changed = true;
        }

        if state_changed && printing {
            let mut active: Vec<(&str, usize)> = slots
                .iter()
                .filter_map(|s| s.as_ref().map(|s| (s.pkg.as_str(), s.jobs)))
                .collect();
            active.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            let total_jobs: usize = active.iter().map(|(_, c)| c).sum();
            let pkgs: String = active
                .iter()
                .map(|(name, jobs)| format!("{}({})", name, jobs))
                .collect::<Vec<_>>()
                .join(" ");
            printing = try_println(&format!(
                "{:>14}  {:>2}/{}  ({:>2}): {}",
                format_hms(time),
                active.len(),
                workers,
                total_jobs,
                pkgs,
            ));
        }

        /*
         * Track core-seconds for actual core demand.
         */
        let next_time = slots
            .iter()
            .filter_map(|s| s.as_ref().map(|s| s.phase_end))
            .min();
        let Some(next_time) = next_time else {
            break;
        };
        let dt = next_time - time;
        let current_jobs: usize = slots
            .iter()
            .filter_map(|s| s.as_ref())
            .map(|s| s.active_jobs())
            .sum();
        total_job_seconds += dt * current_jobs;
        peak_jobs = peak_jobs.max(current_jobs);
        if let Some(mj) = jobs {
            if current_jobs > mj {
                overalloc_seconds += dt;
            }
        }
        time = next_time;
    }

    let total_worker_time = time * workers;
    let utilisation = if total_worker_time > 0 {
        100.0 * total_busy as f64 / total_worker_time as f64
    } else {
        0.0
    };
    let job_utilisation = if time > 0 {
        let mj = jobs.unwrap_or(workers);
        100.0 * total_job_seconds as f64 / (time * mj) as f64
    } else {
        0.0
    };
    let overalloc_pct = if time > 0 {
        100.0 * overalloc_seconds as f64 / time as f64
    } else {
        0.0
    };
    eprintln!();
    eprintln!(
        "{} packages, {} workers, wall {}, work {}, \
         {:.1}% worker util, {:.1}% job util, peak {} jobs, {:.1}% time over-allocated",
        pkg_count,
        workers,
        format_hms(time),
        format_hms(total_busy),
        utilisation,
        job_utilisation,
        peak_jobs,
        overalloc_pct,
    );

    Ok(())
}

fn format_hms(seconds: usize) -> String {
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    let s = seconds % 60;
    format!("{}h {:02}m {:02}s", h, m, s)
}
