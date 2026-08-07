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
 * MAKE_JOBS allocation tests.
 */

use bob::PackageNode;
use bob::scheduler::Scheduler;
use std::collections::{HashMap, HashSet};
use std::task::Poll;

/**
 * Tail allocation after mark_success with different CPU histories.
 *
 * Three packages (A, B, C) depend on D.  D is cached.  A is heavy,
 * B is medium, C is light.  The budget should be split proportionally
 * with no idle cores.
 */
#[test]
fn tail_after_mark_success_weighted() {
    use bob::makejobs::Allocator;

    let mut packages = HashMap::new();
    packages.insert(
        "D".to_string(),
        PackageNode {
            deps: HashSet::new(),
            pbulk_weight: 1,
            cpu_time: 0,
        },
    );
    for name in ["A", "B", "C"] {
        packages.insert(
            name.to_string(),
            PackageNode {
                deps: HashSet::from(["D".to_string()]),
                pbulk_weight: 1,
                cpu_time: 0,
            },
        );
    }

    let mut sched = Scheduler::from_graph(packages);
    sched.set_pkg_cpu_history(&"A".to_string(), 100_000);
    sched.set_pkg_cpu_history(&"B".to_string(), 1_000);
    sched.set_pkg_cpu_history(&"C".to_string(), 100);
    sched.set_allocator(Allocator::new(8, 32));

    sched.mark_success(&"D".to_string());

    let mut allocations = Vec::new();
    for _ in 0..3 {
        if let Poll::Ready(Some(sp)) = sched.poll() {
            allocations.push((sp.pkg.clone(), sp.make_jobs.allocated().unwrap_or(0)));
        }
    }

    let total: usize = allocations.iter().map(|(_, j)| j).sum();
    assert_eq!(total, 32, "all cores allocated: {allocations:?}");

    let a = allocations.iter().find(|(p, _)| p == "A").unwrap().1;
    let b = allocations.iter().find(|(p, _)| p == "B").unwrap().1;
    let c = allocations.iter().find(|(p, _)| p == "C").unwrap().1;
    assert_eq!((a, b, c), (18, 9, 5), "A={a} B={b} C={c}");
}

/**
 * One package in a [`Runnable`] set.
 */
struct Pkg<'a> {
    /// Number of packages blocked waiting on this one.
    dependents: usize,
    /// Build CPU time from history, in milliseconds.  Zero for a
    /// package with no history, which is allocated the fair share.
    cpu: usize,
    /// Optional list of dependencies on this package, for testing with
    /// specific values set for them, otherwise assume zero.
    blocked: &'a [Pkg<'a>],
    /// Whether the build supports parallel make.
    parallel: bool,
}

/**
 * A package blocking `deps` others, with `cpu` ms of build history.
 *
 * The blocked packages are anonymous unless spelled out in the third
 * argument, which describes the first `blocked.len()` of the `deps`.
 * A trailing `serial` marks a build that does not support parallel
 * make (MAKE_JOBS_SAFE=no).
 */
macro_rules! p {
    ($deps:expr, $cpu:expr, serial) => {
        p!($deps, $cpu, &[], false)
    };
    ($deps:expr, $cpu:expr, $blocked:expr, serial) => {
        p!($deps, $cpu, $blocked, false)
    };
    ($deps:expr, $cpu:expr) => {
        p!($deps, $cpu, &[], true)
    };
    ($deps:expr, $cpu:expr, $blocked:expr) => {
        p!($deps, $cpu, $blocked, true)
    };
    ($deps:expr, $cpu:expr, $blocked:expr, $parallel:expr) => {
        Pkg {
            dependents: $deps,
            cpu: $cpu,
            blocked: $blocked,
            parallel: $parallel,
        }
    };
}

/**
 * The only packages a build can run, everything else blocked.
 */
struct Runnable<'a> {
    /// Concurrent build slots.
    workers: usize,
    /// Total MAKE_JOBS budget (`dynamic.jobs`).
    jobs: usize,
    /// Runnable packages.  Everything else is blocked on one of them.
    packages: &'a [Pkg<'a>],
    /// Base allocation and final jobs per package, in dispatch order.
    expect: &'a [(usize, usize)],
}

/**
 * Add `pkg` as `name`, then everything blocked waiting on it.
 *
 * `history` collects the packages that have a recorded build time, to
 * be handed to the scheduler once the graph is complete.
 */
fn add_pkg(
    packages: &mut HashMap<String, PackageNode<String>>,
    history: &mut Vec<(String, usize)>,
    serial_pkgs: &mut Vec<String>,
    name: String,
    pkg: &Pkg,
    deps: HashSet<String>,
) {
    packages.insert(
        name.clone(),
        PackageNode {
            deps,
            pbulk_weight: 1,
            cpu_time: pkg.cpu as u64,
        },
    );
    /*
     * A build reads history only for the packages that support
     * parallel make, so a serial one never reaches the allocator.
     */
    if !pkg.parallel {
        serial_pkgs.push(name.clone());
    } else if pkg.cpu > 0 {
        history.push((name.clone(), pkg.cpu));
    }
    for d in 0..pkg.dependents.saturating_sub(pkg.blocked.len()) {
        let blocked_on = HashSet::from([name.clone()]);
        add_pkg(
            packages,
            history,
            serial_pkgs,
            format!("{name}d{d}"),
            &p!(0, 0),
            blocked_on,
        );
    }
    for (b, blocked) in pkg.blocked.iter().enumerate() {
        let blocked_on = HashSet::from([name.clone()]);
        add_pkg(
            packages,
            history,
            serial_pkgs,
            format!("{name}b{b}"),
            blocked,
            blocked_on,
        );
    }
}

/**
 * Dispatch every runnable package and return what each was allocated.
 *
 * Results are `(base, jobs)` in dispatch order, which is most blocked
 * dependents first, then longest build.  A build that does not support
 * parallel make is never allocated, so no MAKE_JOBS is set for it and
 * bmake runs it with the single job it reads as `(1, 1)`.
 */
fn running_jobs(case: &Runnable) -> Vec<(usize, usize)> {
    let mut packages = HashMap::new();
    let mut history = Vec::new();
    let mut serial_pkgs = Vec::new();
    for (i, pkg) in case.packages.iter().enumerate() {
        add_pkg(
            &mut packages,
            &mut history,
            &mut serial_pkgs,
            format!("p{i}"),
            pkg,
            HashSet::new(),
        );
    }

    let mut sched = Scheduler::from_graph(packages);
    for name in &serial_pkgs {
        sched.set_make_jobs_unsafe(name);
    }
    for (name, cpu) in &history {
        sched.set_pkg_cpu_history(name, *cpu);
    }
    sched.set_allocator(bob::makejobs::Allocator::new(case.workers, case.jobs));

    (0..case.packages.len())
        .filter_map(|_| match sched.poll() {
            Poll::Ready(Some(sp)) => Some(match sp.make_jobs.allocated() {
                Some(jobs) => {
                    let cpu = (sp.cpu_time > 0).then_some(sp.cpu_time as usize);
                    (sched.allocator()?.assign(cpu, sp.dep_count), jobs)
                }
                None => (1, 1),
            }),
            _ => None,
        })
        .collect()
}

/**
 * Run every case and compare the allocations against its expectation.
 */
fn check(cases: &[Runnable]) {
    for case in cases {
        let dependents: Vec<usize> = case.packages.iter().map(|p| p.dependents).collect();
        assert_eq!(
            running_jobs(case),
            case.expect,
            "workers={} jobs={} dependents={dependents:?}",
            case.workers,
            case.jobs
        );
    }
}

/**
 * Early GCC builds: one of them is the primary compiler, which all
 * other builds are blocked by, while the others are simply leaves
 * that are runnable.  Ensure the primary GCC gets the full budget.
 */
#[test]
fn make_jobs_early_gcc_builds() {
    check(&[
        Runnable {
            workers: 4,
            jobs: 16,
            packages: &[p!(20000, 0), p!(0, 0), p!(0, 0)],
            expect: &[(4, 8), (4, 4), (4, 4)],
        },
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[p!(20000, 0), p!(0, 0), p!(0, 0)],
            expect: &[(2, 28), (2, 2), (2, 2)],
        },
        /*
         * The same but with cpu values added to test spread.  These obviously
         * are not representative.  The scheduler still heavily weighs towards
         * dependency count.
         */
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[p!(20000, 100_000_000), p!(0, 10_000_000), p!(0, 1_000_000)],
            expect: &[(14, 27), (3, 3), (2, 2)],
        },
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[p!(20000, 1_000_000), p!(0, 100_000_000), p!(0, 100_000_000)],
            expect: &[(2, 24), (4, 4), (4, 4)],
        },
    ]);
}

/**
 * Increase the number of deps that the other GCCs have to ensure that
 * the primary is not over-allocated.  Just the number of deps here, no
 * cpu history involved.
 */
#[test]
fn make_jobs_early_gcc_builds_with_deps() {
    check(&[
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[p!(20000, 0), p!(1, 0), p!(1, 0)],
            expect: &[(2, 24), (2, 2), (2, 2)],
        },
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[p!(20000, 0), p!(2, 0), p!(2, 0)],
            expect: &[(2, 20), (2, 2), (2, 2)],
        },
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[p!(20000, 0), p!(4, 0), p!(4, 0)],
            expect: &[(2, 12), (2, 2), (2, 2)],
        },
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[p!(20000, 0), p!(8, 0), p!(8, 0)],
            expect: &[(2, 2), (2, 2), (2, 2)],
        },
    ]);
}

/**
 * Now add in dependency cpu information, ensuring we are not over-allocating
 * prior to a massive dependency being unlocked.  Add an unrealistic gigantic
 * leaf package behind the leafy GCCs.
 */
#[test]
fn make_jobs_early_gcc_builds_with_deps_and_cpu() {
    check(&[
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[
                p!(20000, 1_000_000),
                p!(1, 1_000_000, &[p!(0, 100_000_000)]),
                p!(0, 1_000_000),
            ],
            expect: &[(2, 24), (2, 2), (2, 2)],
        },
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[
                p!(20000, 1_000_000),
                p!(1, 1_000_000, &[p!(0, 1_000_000_000)]),
                p!(1, 1_000_000, &[p!(0, 100_000_000)]),
            ],
            expect: &[(2, 21), (2, 2), (2, 2)],
        },
    ]);
}

/**
 * A build that does not support parallel make takes a single CPU, so
 * only that much is set aside for it.
 */
#[test]
fn make_jobs_serial_packages() {
    check(&[
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[p!(20000, 0), p!(0, 0, serial), p!(0, 0)],
            expect: &[(2, 29), (1, 1), (2, 2)],
        },
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[p!(20000, 0), p!(0, 0, serial), p!(0, 0, serial)],
            expect: &[(2, 30), (1, 1), (1, 1)],
        },
        /* Fewer workers, so more would have been set aside for each. */
        Runnable {
            workers: 4,
            jobs: 16,
            packages: &[p!(20000, 0), p!(0, 0, serial), p!(0, 0, serial)],
            expect: &[(4, 14), (1, 1), (1, 1)],
        },
        /*
         * A serial build holding up as much as a parallel one.  The
         * spare goes to the builds that can use it, so the first takes
         * the share the serial one would have diluted.
         */
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[p!(1, 0), p!(1, 0, serial), p!(0, 0)],
            expect: &[(2, 19), (1, 1), (2, 8)],
        },
    ]);
}

/**
 * A single runnable package gets all available CPU, regardless of how
 * many dependents it has (libnbcompat at the start of a build,
 * whatever is left at the end).
 */
#[test]
fn make_jobs_single_runnable() {
    check(&[
        Runnable {
            workers: 4,
            jobs: 16,
            packages: &[p!(20000, 0)],
            expect: &[(4, 16)],
        },
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[p!(20000, 0)],
            expect: &[(2, 32)],
        },
        Runnable {
            workers: 18,
            jobs: 32,
            packages: &[p!(0, 0)],
            expect: &[(2, 32)],
        },
    ]);
}

/**
 * With nothing blocked the whole budget is split by weight, and with
 * few workers the fair share is already most of the budget.
 */
#[test]
fn nothing_blocked_splits_by_weight() {
    check(&[
        Runnable {
            workers: 4,
            jobs: 32,
            packages: &[p!(20, 0), p!(0, 0), p!(0, 0)],
            expect: &[(8, 16), (8, 8), (8, 8)],
        },
        Runnable {
            workers: 8,
            jobs: 32,
            packages: &[p!(0, 100_000), p!(0, 1_000), p!(0, 100)],
            expect: &[(6, 18), (3, 9), (2, 5)],
        },
    ]);
}

/**
 * Tail allocation with an overcommitted budget must never allocate 0
 * jobs.  Three independent packages with a budget of 4 and 2 workers:
 * the first two each get base=2, exhausting the budget.  The third
 * must still get at least base=2 (not 0).
 */
#[test]
fn tail_overcommitted_budget() {
    use bob::makejobs::Allocator;

    let mut packages = HashMap::new();
    for name in ["A", "B", "C"] {
        packages.insert(
            name.to_string(),
            PackageNode {
                deps: HashSet::new(),
                pbulk_weight: 1,
                cpu_time: 0,
            },
        );
    }

    let mut sched = Scheduler::from_graph(packages);
    sched.set_allocator(Allocator::new(2, 4));

    for _ in 0..3 {
        if let Poll::Ready(Some(sp)) = sched.poll() {
            assert!(
                sp.make_jobs.allocated().unwrap_or(0) >= 2,
                "{} got {} jobs",
                sp.pkg,
                sp.make_jobs.allocated().unwrap_or(0),
            );
        }
    }
}

/**
 * Jobs set aside for a blocked package are still there when it starts.
 *
 * A primary GCC is boosted while two other packages run, one of which
 * has a package waiting behind it.  When that one is built, the
 * package it releases must find the jobs that were held for it, with
 * the GCC still holding its boost.
 */
#[test]
fn make_jobs_released_package_gets_its_share() {
    let mut packages = HashMap::new();
    let mut history = Vec::new();
    let mut serial_pkgs = Vec::new();
    for (i, pkg) in [p!(20000, 0), p!(1, 0), p!(0, 0)].iter().enumerate() {
        add_pkg(
            &mut packages,
            &mut history,
            &mut serial_pkgs,
            format!("p{i}"),
            pkg,
            HashSet::new(),
        );
    }

    let mut sched = Scheduler::from_graph(packages);
    sched.set_allocator(bob::makejobs::Allocator::new(18, 32));

    let mut jobs = Vec::new();
    for _ in 0..3 {
        if let Poll::Ready(Some(sp)) = sched.poll() {
            jobs.push((sp.pkg.clone(), sp.make_jobs.allocated().unwrap_or(1)));
        }
    }
    assert_eq!(
        jobs,
        [
            ("p0".to_string(), 26),
            ("p1".to_string(), 2),
            ("p2".to_string(), 2)
        ],
    );

    /* p1 is built, so the package waiting on it can start. */
    sched.mark_success(&"p1".to_string());
    let Poll::Ready(Some(sp)) = sched.poll() else {
        panic!("expected the released package");
    };
    assert_eq!(sp.pkg, "p1d0");
    assert_eq!(sp.make_jobs.allocated(), Some(2));

    /* p1 has finished, so only p0, p2 and the released package hold jobs. */
    let live = jobs[0].1 + jobs[2].1 + sp.make_jobs.allocated().unwrap_or(1);
    assert!(live <= 32, "{live} jobs against a budget of 32");
}

/**
 * Jobs are set aside for the packages that can start while this one
 * builds, and equals share what is left.
 *
 * A and B are both runnable and D waits on both of them, so D can
 * start once both have built.  A and B hold up the same one package,
 * so they take the same share.
 */
#[test]
fn make_jobs_shared_dependency_cannot_start() {
    let mut packages = HashMap::new();
    for name in ["A", "B"] {
        packages.insert(
            name.to_string(),
            PackageNode {
                deps: HashSet::new(),
                pbulk_weight: 1,
                cpu_time: 0,
            },
        );
    }
    packages.insert(
        "D".to_string(),
        PackageNode {
            deps: HashSet::from(["A".to_string(), "B".to_string()]),
            pbulk_weight: 1,
            cpu_time: 0,
        },
    );

    let mut sched = Scheduler::from_graph(packages);
    sched.set_allocator(bob::makejobs::Allocator::new(18, 32));

    let mut jobs = Vec::new();
    for _ in 0..2 {
        if let Poll::Ready(Some(sp)) = sched.poll() {
            jobs.push((sp.pkg.clone(), sp.make_jobs.allocated().unwrap_or(1)));
        }
    }
    assert_eq!(jobs, [("A".to_string(), 16), ("B".to_string(), 16)]);
}
