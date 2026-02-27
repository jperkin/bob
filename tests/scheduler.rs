/*!
 * Integration tests for build scheduling using real-world dependency data.
 *
 * The `tests/data/depgraph.zst` file is a zstd-compressed version of the
 * output from `bob util print-dep-graph`, containing one `dep -> dependent`
 * edge per line.
 *
 * Each test spawns real threads that dispatch, "build" (with deterministic
 * hash-based sleep), and complete packages.  Every worker verifies that all
 * dependencies are in the shared `built` set before proceeding, catching
 * ordering violations and race conditions.
 *
 * Sleep durations are scaled by worker count: more workers means longer
 * per-package sleeps, increasing the window for race conditions without
 * increasing total runtime (since the work is more parallelised).
 */

use bob::scheduler::Scheduler;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::BufRead;
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::task::Poll;
use std::time::Duration;

const DEPGRAPH_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/depgraph.zst");

struct DepGraph {
    incoming: HashMap<String, HashSet<String>>,
    reverse_deps: HashMap<String, HashSet<String>>,
    pkg_count: usize,
    edge_count: usize,
}

static DEPGRAPH: OnceLock<DepGraph> = OnceLock::new();

fn load_depgraph() -> &'static DepGraph {
    DEPGRAPH.get_or_init(|| {
        let file = std::fs::File::open(DEPGRAPH_PATH).expect("failed to open depgraph.zst");
        let reader = std::io::BufReader::new(file);
        let decoder = zstd::Decoder::new(reader).expect("failed to create zstd decoder");
        let lines = std::io::BufReader::new(decoder);

        let mut incoming: HashMap<String, HashSet<String>> = HashMap::new();
        let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
        let mut edge_count = 0;
        for line in lines.lines() {
            let line = line.expect("failed to read line");
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(2, " -> ").collect();
            assert_eq!(parts.len(), 2, "malformed edge: {}", line);
            let dep = parts[0].to_string();
            let dependent = parts[1].to_string();
            incoming
                .entry(dependent.clone())
                .or_default()
                .insert(dep.clone());
            incoming.entry(dep.clone()).or_default();
            reverse_deps
                .entry(dep)
                .or_default()
                .insert(dependent.clone());
            reverse_deps.entry(dependent).or_default();
            edge_count += 1;
        }
        let pkg_count = incoming.len();
        DepGraph {
            incoming,
            reverse_deps,
            pkg_count,
            edge_count,
        }
    })
}

fn load_depgraph_zst(path: &str) -> DepGraph {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {}", path, e));
    let reader = std::io::BufReader::new(file);
    let decoder = zstd::Decoder::new(reader).unwrap_or_else(|e| panic!("zstd {}: {}", path, e));
    let lines = std::io::BufReader::new(decoder);
    let mut incoming: HashMap<String, HashSet<String>> = HashMap::new();
    let mut reverse_deps: HashMap<String, HashSet<String>> = HashMap::new();
    let mut edge_count = 0;
    for line in lines.lines() {
        let line = line.expect("failed to read line");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, " -> ").collect();
        assert_eq!(parts.len(), 2, "malformed edge: {}", line);
        let dep = parts[0].to_string();
        let dependent = parts[1].to_string();
        incoming
            .entry(dependent.clone())
            .or_default()
            .insert(dep.clone());
        incoming.entry(dep.clone()).or_default();
        reverse_deps
            .entry(dep)
            .or_default()
            .insert(dependent.clone());
        reverse_deps.entry(dependent).or_default();
        edge_count += 1;
    }
    let pkg_count = incoming.len();
    DepGraph {
        incoming,
        reverse_deps,
        pkg_count,
        edge_count,
    }
}

fn new_scheduler(g: &DepGraph) -> Scheduler<String> {
    Scheduler::new(
        g.incoming.clone(),
        g.reverse_deps.clone(),
        HashMap::new(),
        HashSet::new(),
        HashSet::new(),
    )
}

/**
 * Deterministic per-package sleep duration.
 *
 * Hashes the package name to produce a duration in the range
 * `[0, 100 * workers)` microseconds.  More workers means longer
 * per-package sleeps, increasing the window for race conditions
 * without increasing total test runtime.
 */
fn pkg_sleep(pkg: &str, workers: usize) -> Duration {
    let mut hasher = std::hash::DefaultHasher::new();
    pkg.hash(&mut hasher);
    let h = hasher.finish();
    Duration::from_micros((h % 100) * workers as u64)
}

/**
 * Compute the full set of transitive dependents of the given root
 * packages, including the roots themselves.
 */
fn transitive_dependents(g: &DepGraph, roots: &HashSet<String>) -> HashSet<String> {
    let mut result = roots.clone();
    let mut queue: VecDeque<String> = roots.iter().cloned().collect();
    while let Some(pkg) = queue.pop_front() {
        if let Some(rdeps) = g.reverse_deps.get(&pkg) {
            for rdep in rdeps {
                if result.insert(rdep.clone()) {
                    queue.push_back(rdep.clone());
                }
            }
        }
    }
    result
}

/**
 * Select the `count` packages with the most direct reverse dependencies.
 * These are the packages whose failure will cascade most widely.
 * Ties are broken lexicographically for determinism.
 */
fn most_depended_on(g: &DepGraph, count: usize) -> Vec<String> {
    let mut pkgs: Vec<_> = g
        .reverse_deps
        .iter()
        .map(|(pkg, rdeps)| (pkg.clone(), rdeps.len()))
        .collect();
    pkgs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    pkgs.into_iter().take(count).map(|(pkg, _)| pkg).collect()
}

/**
 * Run a threaded build simulation with `workers` threads.
 *
 * Packages in `fail_set` are treated as build failures; their transitive
 * dependents are verified to be correctly propagated via `mark_failure`.
 *
 * Each worker dispatches a package, verifies all its dependencies are
 * in the shared `built` set, sleeps for a deterministic hash-based
 * duration (skipped for single-worker tests), then signals completion.
 *
 * Asserts:
 * - Every dispatched package had all deps already completed.
 * - No indirectly-failed package was ever dispatched.
 * - The set of failed packages exactly matches the expected transitive
 *   closure of `fail_set`.
 * - All non-failed packages complete (no deadlock).
 */
fn run_build(workers: usize, fail_set: &HashSet<String>) {
    let g = load_depgraph();

    let expected_failed = transitive_dependents(g, fail_set);
    let expected_success = g.pkg_count - expected_failed.len();

    let sched = Arc::new(Mutex::new(new_scheduler(g)));
    let built_set: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let incoming = g.incoming.clone();

    let (done_tx, done_rx) = mpsc::channel::<(String, bool)>();
    let mut handles = Vec::new();

    for _ in 0..workers {
        let sched = Arc::clone(&sched);
        let built_set = Arc::clone(&built_set);
        let incoming = incoming.clone();
        let done_tx = done_tx.clone();
        let fail_set = fail_set.clone();

        handles.push(std::thread::spawn(move || {
            loop {
                let pkg = {
                    let mut s = sched.lock().expect("lock poisoned");
                    match s.poll() {
                        Poll::Ready(Some(p)) => p,
                        Poll::Ready(None) => return,
                        Poll::Pending => {
                            drop(s);
                            std::thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                    }
                };

                if let Some(deps) = incoming.get(&pkg) {
                    let built = built_set.lock().expect("lock poisoned");
                    for dep in deps {
                        assert!(
                            built.contains(dep),
                            "building {} but dependency {} not yet completed",
                            pkg,
                            dep
                        );
                    }
                }

                if fail_set.contains(&pkg) {
                    done_tx.send((pkg, false)).expect("channel closed");
                } else {
                    if workers > 1 {
                        std::thread::sleep(pkg_sleep(&pkg, workers));
                    }

                    built_set.lock().expect("lock poisoned").insert(pkg.clone());
                    done_tx.send((pkg, true)).expect("channel closed");
                }
            }
        }));
    }
    drop(done_tx);

    let mut succeeded = 0usize;
    let mut all_failed: HashSet<String> = HashSet::new();

    for (pkg, success) in done_rx {
        let mut s = sched.lock().expect("lock poisoned");
        if success {
            s.mark_success(&pkg);
            succeeded += 1;
        } else {
            let indirect = s.mark_failure(&pkg);
            all_failed.insert(pkg);
            for p in indirect {
                all_failed.insert(p);
            }
        }
    }

    for h in handles {
        h.join().expect("worker thread panicked");
    }

    assert_eq!(
        succeeded, expected_success,
        "expected {} successes, got {}",
        expected_success, succeeded
    );

    assert_eq!(
        all_failed, expected_failed,
        "failed set does not match expected transitive closure"
    );

    let built = built_set.lock().expect("lock poisoned");
    for pkg in &all_failed {
        assert!(
            !built.contains(pkg),
            "failed package {} appears in built set",
            pkg
        );
    }
}

#[test]
fn depgraph_loads() {
    let g = load_depgraph();
    assert!(
        g.pkg_count > 25000,
        "expected >25k packages, got {}",
        g.pkg_count
    );
    assert!(
        g.edge_count > 100000,
        "expected >100k edges, got {}",
        g.edge_count
    );
}

#[test]
fn depgraph_1_worker() {
    run_build(1, &HashSet::new());
}

#[test]
fn depgraph_2_workers() {
    run_build(2, &HashSet::new());
}

#[test]
fn depgraph_4_workers() {
    run_build(4, &HashSet::new());
}

#[test]
fn depgraph_32_workers() {
    run_build(32, &HashSet::new());
}

#[test]
fn depgraph_128_workers() {
    run_build(128, &HashSet::new());
}

/**
 * Deterministic per-package phase duration.
 *
 * Hashes pkg name + phase to produce a tick count in `[1, max]`.
 * Build phases are typically longer than configure.
 */
fn phase_ticks(pkg: &str, phase: usize) -> u32 {
    let mut hasher = std::hash::DefaultHasher::new();
    pkg.hash(&mut hasher);
    phase.hash(&mut hasher);
    let h = hasher.finish();
    let max = if phase == 0 { 3 } else { 10 };
    (h % max) as u32 + 1
}

/**
 * Simulate a full build with MAKE_JOBS budget allocation and measure
 * utilization.
 *
 * This is a single-threaded deterministic simulation.  Each package
 * goes through 2 phases (configure + build) with hash-based durations
 * to create realistic variation.  At each phase entry, request_make_jobs
 * allocates cores; at phase exit, release_make_jobs returns them.
 *
 * The simulation tracks total allocated cores at every tick and computes
 * utilization statistics and a histogram, so formula changes can be
 * evaluated against real-world dependency data.
 */
/**
 * Per-package timing from real build history.
 *
 * All times are in milliseconds, matching the CSV output of
 * `bob list history -lr -f csv`.  Four phases model the full
 * build lifecycle:
 *
 *   overhead_pre  = pre-clean + depends + checksum  (always -j1)
 *   configure     = configure phase                 (uses MAKE_JOBS)
 *   build         = build phase                     (uses MAKE_JOBS)
 *   overhead_post = install + package + deinstall + clean  (always -j1)
 *
 * Packages with `make_jobs == "-"` in the history are unsafe
 * (MAKE_JOBS_SAFE=no) and always build single-threaded.
 */
struct PkgTiming {
    overhead_pre_ms: u32,
    configure_ms: u32,
    build_ms: u32,
    overhead_post_ms: u32,
    cpu_configure_ms: u32,
    cpu_build_ms: u32,
    duration_ms: u32,
    history_jobs: u32,
}

struct HistoryData {
    timings: HashMap<String, PkgTiming>,
    unsafe_pkgs: HashSet<String>,
}

/**
 * Load per-package build timings from a zstd-compressed CSV history file.
 *
 * CSV columns (indices):
 *   0:timestamp, 1:pkgpath, 2:pkgname, 3:outcome, 4:stage,
 *   5:make_jobs, 6:duration, 7:disk_usage, 8:pre-clean, 9:depends,
 *   10:checksum, 11:configure, 12:build, 13:install, 14:package,
 *   15:deinstall, 16:clean, 17:cpu:pre-clean, 18:cpu:depends,
 *   19:cpu:checksum, 20:cpu:configure, 21:cpu:build, 22:cpu:install,
 *   23:cpu:package, 24:cpu:deinstall, 25:cpu:clean
 *
 * Packages with make_jobs="-" are detected as MAKE_JOBS_SAFE=no.
 */
fn load_history(path: &str) -> HistoryData {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {}", path, e));
    let reader = std::io::BufReader::new(file);
    let decoder = zstd::Decoder::new(reader).unwrap_or_else(|e| panic!("zstd {}: {}", path, e));
    let mut timings = HashMap::new();
    let mut unsafe_pkgs = HashSet::new();
    let parse = |s: &str| -> u32 { s.parse::<u32>().unwrap_or(0) };
    for line in std::io::BufReader::new(decoder).lines() {
        let line = line.expect("read line");
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 22 || fields[0] == "timestamp" {
            continue;
        }
        let pkgname = fields[2].to_string();
        let is_unsafe = fields[5] == "-";
        if is_unsafe {
            unsafe_pkgs.insert(pkgname.clone());
        }
        let overhead_pre_ms = parse(fields[8]) + parse(fields[9]) + parse(fields[10]);
        let configure_ms = parse(fields[11]);
        let build_ms = parse(fields[12]);
        let overhead_post_ms =
            parse(fields[13]) + parse(fields[14]) + parse(fields[15]) + parse(fields[16]);
        let cpu_configure_ms = parse(fields[20]);
        let cpu_build_ms = parse(fields[21]);
        let duration_ms = parse(fields[6]);
        let history_jobs = if is_unsafe {
            1
        } else {
            fields[5].parse::<u32>().unwrap_or(1)
        };
        timings.insert(
            pkgname,
            PkgTiming {
                overhead_pre_ms,
                configure_ms,
                build_ms,
                overhead_post_ms,
                cpu_configure_ms,
                cpu_build_ms,
                duration_ms,
                history_jobs,
            },
        );
    }
    HistoryData {
        timings,
        unsafe_pkgs,
    }
}

/**
 * Simulation phases.
 *
 * Each package progresses through four phases:
 *   0: overhead_pre  (pre-clean + depends + checksum) -- always -j1
 *   1: configure     -- MAKE_JOBS allocated (or -j1 if unsafe)
 *   2: build         -- MAKE_JOBS allocated (or -j1 if unsafe)
 *   3: overhead_post (install + package + deinstall + clean) -- always -j1
 *
 * During overhead phases, the package occupies a build thread but
 * only uses 1 core and does not participate in the MAKE_JOBS budget.
 * This models the real-world cost of serial setup/teardown phases.
 *
 * Without real timings, the hash-based model uses 2 phases
 * (configure + build) for backwards compatibility.
 */
const PHASE_OVERHEAD_PRE: usize = 0;
const PHASE_CONFIGURE: usize = 1;
const PHASE_BUILD: usize = 2;
const PHASE_OVERHEAD_POST: usize = 3;
const PHASE_COUNT_TIMED: usize = 4;
const PHASE_COUNT_HASH: usize = 2;

struct SimConfig<'a> {
    build_threads: usize,
    max_jobs: usize,
    graph: Option<&'a DepGraph>,
    unsafe_pkgs: &'a HashSet<String>,
    timings: Option<&'a HashMap<String, PkgTiming>>,
    weights: HashMap<String, usize>,
    caps: HashMap<String, usize>,
    verbose: bool,
    min_utilization: f64,
    /// When set, every parallel phase gets exactly this many jobs
    /// regardless of the budget system.  Models the real-world
    /// "fixed MAKE_JOBS=N" behaviour.
    fixed_jobs: Option<usize>,
}

struct SimResult {
    ticks: u64,
    utilization: f64,
    completed: usize,
}

fn run_make_jobs_sim(
    build_threads: usize,
    max_jobs: usize,
    graph: Option<&DepGraph>,
    unsafe_pkgs: &HashSet<String>,
    timings: Option<&HashMap<String, PkgTiming>>,
) -> SimResult {
    run_sim(&SimConfig {
        build_threads,
        max_jobs,
        graph,
        unsafe_pkgs,
        timings,
        weights: HashMap::new(),
        caps: HashMap::new(),
        verbose: graph.is_some(),
        min_utilization: 40.0,
        fixed_jobs: None,
    })
}

fn run_sim(cfg: &SimConfig<'_>) -> SimResult {
    let loaded;
    let g = match cfg.graph {
        Some(g) => g,
        None => {
            loaded = load_depgraph();
            loaded
        }
    };
    let mut sched = Scheduler::new(
        g.incoming.clone(),
        g.reverse_deps.clone(),
        cfg.weights.clone(),
        HashSet::new(),
        HashSet::new(),
    );
    if cfg.fixed_jobs.is_none() {
        sched.init_budget(cfg.max_jobs, cfg.build_threads, cfg.caps.clone());
    }
    let timings = cfg.timings;
    let unsafe_pkgs = cfg.unsafe_pkgs;
    let max_jobs = cfg.max_jobs;
    let build_threads = cfg.build_threads;
    let verbose = cfg.verbose;
    let fixed_jobs = cfg.fixed_jobs;

    let phase_count = if timings.is_some() {
        PHASE_COUNT_TIMED
    } else {
        PHASE_COUNT_HASH
    };

    struct Active {
        phase: usize,
        ticks_left: u32,
        jobs: usize,
        in_budget: bool,
    }

    let mut active: HashMap<String, Active> = HashMap::new();
    let mut total_job_ticks: u64 = 0;
    let mut total_ticks: u64 = 0;
    let mut histogram: Vec<u64> = vec![0; max_jobs + 1];
    let mut completed = 0usize;
    let mut max_active = 0usize;

    /*
     * Compute ticks for a phase given the allocated job count.
     *
     * With real timings, 1 tick = 1 second.  For parallel phases
     * (configure, build), Amdahl's law scales the wall time when the
     * allocated job count differs from the history's MAKE_JOBS:
     *
     *   serial_ms = (wall_ms - cpu_ms / history_jobs) / (1 - 1/history_jobs)
     *   parallel_ms = cpu_ms - serial_ms
     *   predicted_wall = serial_ms + parallel_ms / allocated_jobs
     *
     * Packages where cpu <= wall (I/O-bound) use the original wall
     * time unchanged since more cores do not help.
     *
     * Without real timings, the 2-phase hash model uses fixed ticks.
     */
    let get_ticks = |pkg: &str, phase: usize, allocated_jobs: usize| -> u32 {
        if let Some(t) = timings {
            if let Some(pt) = t.get(pkg) {
                let (wall_ms, cpu_ms) = match phase {
                    PHASE_CONFIGURE => (pt.configure_ms, pt.cpu_configure_ms),
                    PHASE_BUILD => (pt.build_ms, pt.cpu_build_ms),
                    PHASE_OVERHEAD_PRE => (pt.overhead_pre_ms, 0),
                    PHASE_OVERHEAD_POST => (pt.overhead_post_ms, 0),
                    _ => (0, 0),
                };
                let j = allocated_jobs as f64;
                let hj = pt.history_jobs as f64;
                if cpu_ms > wall_ms && hj > 1.0 && j != hj {
                    let wall = wall_ms as f64;
                    let cpu = cpu_ms as f64;
                    let serial = (wall - cpu / hj) / (1.0 - 1.0 / hj);
                    let serial = serial.max(0.0);
                    let parallel = (cpu - serial).max(0.0);
                    let predicted = serial + parallel / j;
                    (predicted / 1000.0).ceil().max(1.0) as u32
                } else {
                    wall_ms.div_ceil(1000).max(1)
                }
            } else {
                phase_ticks(pkg, phase)
            }
        } else {
            phase_ticks(pkg, phase)
        }
    };

    /*
     * Whether a phase uses MAKE_JOBS or runs single-threaded.
     * Configure and build both receive MAKE_JOBS; most packages
     * are serial during configure but some (e.g. cmake) do use
     * parallel jobs.  Without real timings, both hash-based
     * phases (0=configure, 1=build) use MAKE_JOBS.
     */
    let is_parallel_phase = |phase: usize| -> bool {
        if timings.is_some() {
            phase == PHASE_CONFIGURE || phase == PHASE_BUILD
        } else {
            true
        }
    };

    /*
     * Enter or leave the MAKE_JOBS budget for a package at a phase
     * boundary.  Returns the core allocation for the new phase.
     */
    let enter_phase = |sched: &mut Scheduler<String>,
                       pkg: &str,
                       phase: usize,
                       was_in_budget: bool|
     -> (usize, bool) {
        let dominated = unsafe_pkgs.contains(pkg);
        if is_parallel_phase(phase) && !dominated {
            if let Some(fj) = fixed_jobs {
                (fj, false)
            } else {
                let jobs = sched.request_make_jobs(&String::from(pkg)).unwrap_or(1);
                (jobs, true)
            }
        } else {
            if dominated && !was_in_budget && fixed_jobs.is_none() {
                sched.exclude_from_budget(&String::from(pkg));
            }
            (1, false)
        }
    };

    loop {
        while active.len() < build_threads {
            match sched.poll() {
                std::task::Poll::Ready(Some(pkg)) => {
                    let first_phase = if timings.is_some() {
                        PHASE_OVERHEAD_PRE
                    } else {
                        0
                    };
                    let (jobs, in_budget) = enter_phase(&mut sched, &pkg, first_phase, false);
                    let ticks = get_ticks(&pkg, first_phase, jobs);
                    active.insert(
                        pkg,
                        Active {
                            phase: first_phase,
                            ticks_left: ticks,
                            jobs,
                            in_budget,
                        },
                    );
                }
                _ => break,
            }
        }

        if active.is_empty() {
            break;
        }

        if verbose {
            let used: usize = active.values().map(|a| a.jobs).sum();
            if used < max_jobs {
                let phase_char = |p: usize| -> &'static str {
                    match p {
                        PHASE_OVERHEAD_PRE => "pre",
                        PHASE_CONFIGURE => "conf",
                        PHASE_BUILD => "bld",
                        PHASE_OVERHEAD_POST => "post",
                        _ => "?",
                    }
                };
                let mut allocs: Vec<String> = active
                    .iter()
                    .map(|(p, a)| {
                        let w = sched.remaining_depth(p);
                        let short = p
                            .find(|c: char| c.is_ascii_digit())
                            .map(|i| &p[..i.max(1)])
                            .unwrap_or(p)
                            .trim_end_matches('-');
                        if timings.is_some() {
                            format!("{}={}:{}(w{})", short, a.jobs, phase_char(a.phase), w)
                        } else {
                            format!("{}={}(w{})", short, a.jobs, w)
                        }
                    })
                    .collect();
                allocs.sort();
                let pw = sched.pending_weight();
                let marker = if active.len() < build_threads {
                    "  (draining)"
                } else {
                    ""
                };
                eprintln!(
                    "  tick {:>4}: {} = {}/{} pw={}{}",
                    total_ticks,
                    allocs.join(" + "),
                    used,
                    max_jobs,
                    pw,
                    marker
                );
            }
        }
        max_active = max_active.max(active.len());

        let used: usize = active.values().map(|a| a.jobs).sum();
        histogram[used.min(max_jobs)] += 1;
        total_job_ticks += used as u64;
        total_ticks += 1;

        let mut finished_phase: Vec<String> = Vec::new();
        for (pkg, a) in active.iter_mut() {
            a.ticks_left -= 1;
            if a.ticks_left == 0 {
                finished_phase.push(pkg.clone());
            }
        }

        let mut done_pkgs: Vec<String> = Vec::new();
        for pkg in finished_phase {
            let a = active.get_mut(&pkg).expect("active");
            let next_phase = a.phase + 1;
            if a.in_budget {
                sched.release_make_jobs(&String::from(pkg.as_str()));
            }
            if next_phase < phase_count {
                let (jobs, in_budget) = enter_phase(&mut sched, &pkg, next_phase, a.in_budget);
                let ticks = get_ticks(&pkg, next_phase, jobs);
                a.phase = next_phase;
                a.ticks_left = ticks;
                a.jobs = jobs;
                a.in_budget = in_budget;
            } else {
                done_pkgs.push(pkg);
            }
        }

        for pkg in done_pkgs {
            active.remove(&pkg);
            sched.mark_success(&pkg);
            completed += 1;
        }
    }

    let utilization = if total_ticks > 0 {
        total_job_ticks as f64 / (total_ticks as f64 * max_jobs as f64) * 100.0
    } else {
        0.0
    };

    if verbose {
        eprintln!(
            "\n=== MAKE_JOBS simulation: {} threads, {} max_jobs, {} packages ===",
            build_threads, max_jobs, completed
        );
        if timings.is_some() {
            let mins = total_ticks / 60;
            let secs = total_ticks % 60;
            eprintln!("Simulated wall time: {}m{}s", mins, secs);
        }
        eprintln!(
            "Utilization: {:.1}% ({} job-ticks / {} tick-slots)",
            utilization,
            total_job_ticks,
            total_ticks * max_jobs as u64
        );
        eprintln!("Ticks: {}, max concurrent: {}", total_ticks, max_active);

        eprintln!("Core usage histogram:");
        let max_count = *histogram.iter().max().unwrap_or(&1);
        for (cores, &count) in histogram.iter().enumerate() {
            if count > 0 {
                let bar_len = (count * 50 / max_count) as usize;
                let bar: String = "#".repeat(bar_len);
                eprintln!("  {:>3} cores: {:>6} ticks  {}", cores, count, bar);
            }
        }
    }

    assert!(
        utilization > cfg.min_utilization,
        "Utilization too low: {:.1}% (minimum {:.1}%)",
        utilization,
        cfg.min_utilization
    );

    SimResult {
        ticks: total_ticks,
        utilization,
        completed,
    }
}

#[test]
fn depgraph_make_jobs_full() {
    run_make_jobs_sim(4, 16, None, &HashSet::new(), None);
}

const MUTT_DEPGRAPH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/depgraph-mutt.zst");
const MUTT_HISTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/history-mutt.zst");

#[test]
fn depgraph_make_jobs_mutt() {
    let g = load_depgraph_zst(MUTT_DEPGRAPH);
    eprintln!(
        "\nmutt build: {} packages, {} edges",
        g.pkg_count, g.edge_count
    );
    let unsafe_pkgs: HashSet<String> = [
        "cyrus-sasl-2.1.28nb2",
        "gnupg2-2.4.9nb1",
        "libusb1-1.0.29",
        "lynx-2.9.2nb6",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    run_make_jobs_sim(4, 16, Some(&g), &unsafe_pkgs, None);
}

#[test]
fn depgraph_make_jobs_mutt_timed() {
    let g = load_depgraph_zst(MUTT_DEPGRAPH);
    let history = load_history(MUTT_HISTORY);
    let unsafe_list: Vec<&str> = history.unsafe_pkgs.iter().map(|s| s.as_str()).collect();
    eprintln!(
        "\nmutt build (timed): {} packages, {} edges, {} timings, {} unsafe {:?}",
        g.pkg_count,
        g.edge_count,
        history.timings.len(),
        history.unsafe_pkgs.len(),
        unsafe_list
    );
    run_make_jobs_sim(
        4,
        16,
        Some(&g),
        &history.unsafe_pkgs,
        Some(&history.timings),
    );
}

/**
 * Derive scheduling weights from history: total duration in seconds.
 * Packages without history get the default (100).
 */
fn weights_from_history(timings: &HashMap<String, PkgTiming>) -> HashMap<String, usize> {
    timings
        .iter()
        .map(|(k, v)| (k.clone(), (v.duration_ms / 1000).max(1) as usize))
        .collect()
}

/**
 * Derive per-package parallelism caps from CPU/wall ratio during
 * the build phase.  A package whose build uses 2x CPU vs wall
 * time is capped at 2 -- giving it more cores would be waste.
 * Minimum cap is 1.
 */
fn caps_from_history(timings: &HashMap<String, PkgTiming>) -> HashMap<String, usize> {
    timings
        .iter()
        .filter_map(|(k, v)| {
            if v.build_ms > 0 {
                let ratio = v.cpu_build_ms.div_ceil(v.build_ms).max(1) as usize;
                Some((k.clone(), ratio))
            } else {
                None
            }
        })
        .collect()
}

fn fmt_time(ticks: u64) -> String {
    format!("{}m{:02}s", ticks / 60, ticks % 60)
}

#[test]
fn depgraph_make_jobs_mutt_verbose() {
    let g = load_depgraph_zst(MUTT_DEPGRAPH);
    let history = load_history(MUTT_HISTORY);
    let weights = weights_from_history(&history.timings);
    run_sim(&SimConfig {
        build_threads: 4,
        max_jobs: 16,
        graph: Some(&g),
        unsafe_pkgs: &history.unsafe_pkgs,
        timings: Some(&history.timings),
        weights,
        caps: HashMap::new(),
        verbose: true,
        min_utilization: 0.0,
        fixed_jobs: None,
    });
}

/**
 * Experiment: try multiple scheduler configurations against the real
 * mutt build data and compare wall times.
 */
#[test]
fn depgraph_make_jobs_mutt_experiments() {
    let g = load_depgraph_zst(MUTT_DEPGRAPH);
    let history = load_history(MUTT_HISTORY);
    let weights = weights_from_history(&history.timings);
    let caps = caps_from_history(&history.timings);

    eprintln!(
        "\n=== mutt build experiments ({} packages) ===",
        g.pkg_count
    );
    eprintln!("Actual build time: 70m23s (4 workers x MAKE_JOBS=4)\n");
    eprintln!(
        "{:<55} {:>8} {:>8} {:>6}",
        "Configuration", "Wall", "vs base", "Util%"
    );
    eprintln!("{}", "-".repeat(81));

    struct Experiment {
        label: &'static str,
        threads: usize,
        use_weights: bool,
        use_caps: bool,
        fixed_jobs: Option<usize>,
    }

    let experiments = [
        Experiment {
            label: "ACTUAL: fixed 4 workers x MAKE_JOBS=4",
            threads: 4,
            use_weights: false,
            use_caps: false,
            fixed_jobs: Some(4),
        },
        Experiment {
            label: "fixed 4 workers x MAKE_JOBS=8",
            threads: 4,
            use_weights: false,
            use_caps: false,
            fixed_jobs: Some(8),
        },
        Experiment {
            label: "fixed 4 workers x MAKE_JOBS=16",
            threads: 4,
            use_weights: false,
            use_caps: false,
            fixed_jobs: Some(16),
        },
        Experiment {
            label: "dynamic 4 threads",
            threads: 4,
            use_weights: false,
            use_caps: false,
            fixed_jobs: None,
        },
        Experiment {
            label: "dynamic 4 threads + weights",
            threads: 4,
            use_weights: true,
            use_caps: false,
            fixed_jobs: None,
        },
    ];

    /*
     * Compute theoretical minimum: critical path wall time.
     * Sum the wall times (at max parallelism) along the longest
     * dependency chain, where "longest" means maximum total seconds.
     */
    {
        let mut path_time: HashMap<String, u64> = HashMap::new();
        let mut topo_order: Vec<String> = Vec::new();
        let mut remaining: HashMap<String, usize> = g
            .incoming
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect();
        let mut queue: VecDeque<String> = remaining
            .iter()
            .filter(|(_, v)| **v == 0)
            .map(|(k, _)| k.clone())
            .collect();
        while let Some(pkg) = queue.pop_front() {
            topo_order.push(pkg.clone());
            if let Some(rdeps) = g.reverse_deps.get(&pkg) {
                for rdep in rdeps {
                    if let Some(c) = remaining.get_mut(rdep) {
                        *c -= 1;
                        if *c == 0 {
                            queue.push_back(rdep.clone());
                        }
                    }
                }
            }
        }
        for pkg in &topo_order {
            let pt = history.timings.get(pkg);
            let pkg_secs = if let Some(pt) = pt {
                let pre = pt.overhead_pre_ms.div_ceil(1000) as u64;
                let post = pt.overhead_post_ms.div_ceil(1000) as u64;
                let conf_wall = if pt.cpu_configure_ms > pt.configure_ms && pt.history_jobs > 1 {
                    let hj = pt.history_jobs as f64;
                    let serial = ((pt.configure_ms as f64 - pt.cpu_configure_ms as f64 / hj)
                        / (1.0 - 1.0 / hj))
                        .max(0.0);
                    let parallel = (pt.cpu_configure_ms as f64 - serial).max(0.0);
                    ((serial + parallel / 16.0) / 1000.0).ceil().max(1.0) as u64
                } else {
                    pt.configure_ms.div_ceil(1000) as u64
                };
                let build_wall = if pt.cpu_build_ms > pt.build_ms && pt.history_jobs > 1 {
                    let hj = pt.history_jobs as f64;
                    let serial = ((pt.build_ms as f64 - pt.cpu_build_ms as f64 / hj)
                        / (1.0 - 1.0 / hj))
                        .max(0.0);
                    let parallel = (pt.cpu_build_ms as f64 - serial).max(0.0);
                    ((serial + parallel / 16.0) / 1000.0).ceil().max(1.0) as u64
                } else {
                    pt.build_ms.div_ceil(1000) as u64
                };
                pre + conf_wall + build_wall + post
            } else {
                5
            };
            let dep_max = g
                .incoming
                .get(pkg)
                .map(|deps| {
                    deps.iter()
                        .filter_map(|d| path_time.get(d))
                        .max()
                        .copied()
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            path_time.insert(pkg.clone(), dep_max + pkg_secs);
        }
        let critical = path_time.values().max().copied().unwrap_or(0);
        eprintln!(
            "Theoretical minimum (critical path @16 jobs): {}\n",
            fmt_time(critical)
        );
    }

    let mut baseline_ticks = 0u64;
    for exp in &experiments {
        let result = run_sim(&SimConfig {
            build_threads: exp.threads,
            max_jobs: 16,
            graph: Some(&g),
            unsafe_pkgs: &history.unsafe_pkgs,
            timings: Some(&history.timings),
            weights: if exp.use_weights {
                weights.clone()
            } else {
                HashMap::new()
            },
            caps: if exp.use_caps {
                caps.clone()
            } else {
                HashMap::new()
            },
            verbose: false,
            min_utilization: 0.0,
            fixed_jobs: exp.fixed_jobs,
        });
        if baseline_ticks == 0 {
            baseline_ticks = result.ticks;
        }
        let diff = result.ticks as i64 - baseline_ticks as i64;
        let diff_str = if diff == 0 {
            "--".to_string()
        } else if diff > 0 {
            format!("+{}s", diff)
        } else {
            format!("{}s", diff)
        };
        eprintln!(
            "{:<55} {:>8} {:>8} {:>5.1}%",
            exp.label,
            fmt_time(result.ticks),
            diff_str,
            result.utilization
        );
    }
    eprintln!();
}

#[test]
fn depgraph_single_failure() {
    let g = load_depgraph();
    let fail_pkgs: HashSet<String> = most_depended_on(g, 1).into_iter().collect();
    run_build(4, &fail_pkgs);
}

#[test]
fn depgraph_multi_failure() {
    let g = load_depgraph();
    let fail_pkgs: HashSet<String> = most_depended_on(g, 3).into_iter().collect();
    run_build(32, &fail_pkgs);
}
