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
use bob::{PackageNode, Scheduler};

/**
 * Load per-package timings from a file.
 *
 * Each line is `pkgname duration` where duration is a positive integer.
 * Blank lines are skipped.
 */
fn load_timings(path: &Path) -> Result<HashMap<String, usize>> {
    let file =
        std::fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let reader = std::io::BufReader::new(file);
    let mut timings = HashMap::new();
    for line in reader.lines() {
        let line = line.context("Failed to read timings line")?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, dur)) = line.split_once(' ') else {
            bail!("malformed timings line: {}", line);
        };
        let dur: usize = dur
            .trim()
            .parse()
            .with_context(|| format!("invalid duration in: {}", line))?;
        timings.insert(name.to_string(), dur);
    }
    Ok(timings)
}

/**
 * Simulate a parallel build and report scheduling efficiency.
 *
 * Reads a dependency graph in edge format (`dep -> dependent`, one per
 * line) and runs an event-driven simulation with `workers` workers.
 *
 * Without timings, each package takes one time unit (lockstep).  With
 * a timings file, packages take the specified duration and the
 * simulation advances to each completion event.
 *
 * Per-event output shows the time, idle worker count, and the packages
 * dispatched at that time.  A summary line is printed to stderr.
 */
pub fn run(file: &Path, workers: usize, timings_path: Option<&Path>) -> Result<()> {
    if workers == 0 {
        bail!("workers must be at least 1");
    }

    let reader: Box<dyn BufRead> = if file == Path::new("-") {
        Box::new(std::io::BufReader::new(std::io::stdin()))
    } else {
        Box::new(std::io::BufReader::new(
            std::fs::File::open(file)
                .with_context(|| format!("Failed to open {}", file.display()))?,
        ))
    };

    let mut packages: HashMap<String, PackageNode<String>> = HashMap::new();
    let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
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
        reverse_deps
            .entry(dep.to_string())
            .or_default()
            .insert(dependent.to_string());
        reverse_deps.entry(dependent.to_string()).or_default();
    }

    let timings = match timings_path {
        Some(path) => load_timings(path)?,
        None => HashMap::new(),
    };
    let duration = |pkg: &str| -> usize { timings.get(pkg).copied().unwrap_or(1) };

    let pkg_count = packages.len();
    let mut sched = Scheduler::new(packages, reverse_deps, HashSet::new(), HashSet::new());

    /*
     * Event-driven simulation with explicit worker slots.  Each slot
     * holds the package name and completion time, or None if idle.
     * At each event we complete all workers finishing at that time,
     * dispatch new work to idle slots, and print the full worker state.
     */
    let mut slots: Vec<Option<(String, usize)>> = vec![None; workers];
    let mut time = 0usize;
    let mut total_busy = 0usize;
    let mut printing = true;

    loop {
        /*
         * Complete all workers finishing at the current time.
         */
        let mut changed = false;
        for slot in slots.iter_mut() {
            if let Some((ref pkg, t)) = *slot {
                if t == time {
                    sched.mark_success(pkg);
                    *slot = None;
                    changed = true;
                }
            }
        }

        /*
         * Dispatch new packages to idle worker slots.
         */
        for slot in slots.iter_mut() {
            if slot.is_none() {
                if let Poll::Ready(Some(pkg)) = sched.poll() {
                    let d = duration(&pkg);
                    total_busy += d;
                    *slot = Some((pkg, time + d));
                    changed = true;
                }
            }
        }

        if printing && changed {
            let active: Vec<&str> = slots
                .iter()
                .filter_map(|s| s.as_ref().map(|(name, _)| name.as_str()))
                .collect();
            printing = try_println(&format!(
                "{:>14}  {:>2}/{}  {}",
                format_hms(time),
                active.len(),
                workers,
                active.join(", ")
            ));
        }

        let next_time = slots
            .iter()
            .filter_map(|s| s.as_ref().map(|(_, t)| *t))
            .min();
        let Some(next_time) = next_time else {
            break;
        };
        time = next_time;
    }

    let total_worker_time = time * workers;
    let utilisation = if total_worker_time > 0 {
        100.0 * total_busy as f64 / total_worker_time as f64
    } else {
        0.0
    };
    eprintln!();
    eprintln!(
        "{} packages, {} workers, wall {}, work {}, {:.1}% utilisation",
        pkg_count,
        workers,
        format_hms(time),
        format_hms(total_busy),
        utilisation
    );

    Ok(())
}

fn format_hms(seconds: usize) -> String {
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    let s = seconds % 60;
    format!("{}h {:02}m {:02}s", h, m, s)
}
