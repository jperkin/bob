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

fn load_depgraph_file(path: &str) -> DepGraph {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {}", path, e));
    let lines = std::io::BufReader::new(file);
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
fn load_timings(path: &str) -> HashMap<String, u32> {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {}", path, e));
    let mut timings = HashMap::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.expect("read line");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((pkg, secs)) = line.rsplit_once(' ') {
            if let Ok(s) = secs.parse::<u32>() {
                timings.insert(pkg.to_string(), s);
            }
        }
    }
    timings
}

/**
 * Look up a timing for a package, falling back to fuzzy match on the
 * base name (everything before the version number) if the exact
 * version is not in the timing data.
 */
fn lookup_timing(timings: &HashMap<String, u32>, pkg: &str) -> Option<u32> {
    if let Some(&t) = timings.get(pkg) {
        return Some(t);
    }
    /*
     * Extract base name: everything up to the last '-' followed by a
     * digit, e.g. "cmake-4.2.1nb1" -> "cmake".
     */
    let base = pkg
        .rmatch_indices('-')
        .find(|(i, _)| {
            pkg.as_bytes()
                .get(i + 1)
                .is_some_and(|c| c.is_ascii_digit())
        })
        .map(|(i, _)| &pkg[..i]);
    let base = base?;
    let mut best: Option<(u32, &str)> = None;
    for (k, &v) in timings {
        if k.starts_with(base) && k.as_bytes().get(base.len()) == Some(&b'-') {
            match best {
                None => best = Some((v, k)),
                Some((_, prev)) if k.as_str() > prev => best = Some((v, k)),
                _ => {}
            }
        }
    }
    best.map(|(v, _)| v)
}

fn run_make_jobs_sim(
    build_threads: usize,
    max_jobs: usize,
    graph: Option<&DepGraph>,
    unsafe_pkgs: &HashSet<String>,
    timings: Option<&HashMap<String, u32>>,
) {
    let verbose = graph.is_some();
    let loaded;
    let g = match graph {
        Some(g) => g,
        None => {
            loaded = load_depgraph();
            loaded
        }
    };
    let mut sched = Scheduler::new(
        g.incoming.clone(),
        g.reverse_deps.clone(),
        HashMap::new(),
        HashSet::new(),
        HashSet::new(),
    );
    sched.init_budget(max_jobs, build_threads, HashMap::new());

    struct Active {
        phase: usize,
        ticks_left: u32,
        jobs: usize,
    }

    let mut active: HashMap<String, Active> = HashMap::new();
    let mut total_job_ticks: u64 = 0;
    let mut total_ticks: u64 = 0;
    let mut histogram: Vec<u64> = vec![0; max_jobs + 1];
    let mut completed = 0usize;
    let mut max_active = 0usize;

    let get_ticks = |pkg: &str, phase: usize| -> u32 {
        if let Some(t) = timings {
            let total = lookup_timing(t, pkg).unwrap_or(10);
            let conf = (total / 5).max(1);
            if phase == 0 {
                conf
            } else {
                total.saturating_sub(conf).max(1)
            }
        } else {
            phase_ticks(pkg, phase)
        }
    };

    loop {
        // Dispatch packages to fill available worker slots
        while active.len() < build_threads {
            match sched.poll() {
                std::task::Poll::Ready(Some(pkg)) => {
                    let ticks = get_ticks(&pkg, 0);
                    let jobs = if unsafe_pkgs.contains(&pkg) {
                        sched.exclude_from_budget(&pkg);
                        1
                    } else {
                        sched.request_make_jobs(&pkg).unwrap_or(1)
                    };
                    active.insert(
                        pkg,
                        Active {
                            phase: 0,
                            ticks_left: ticks,
                            jobs,
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
                let mut allocs: Vec<String> = active
                    .iter()
                    .map(|(p, a)| {
                        let w = sched.remaining_depth(p);
                        let short = p
                            .find(|c: char| c.is_ascii_digit())
                            .map(|i| &p[..i.max(1)])
                            .unwrap_or(p)
                            .trim_end_matches('-');
                        format!("{}={}(w{})", short, a.jobs, w)
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
                    "  tick {:>3}: {} = {}/{} pw={}{}",
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

        // Record utilization for this tick
        let used: usize = active.values().map(|a| a.jobs).sum();
        histogram[used.min(max_jobs)] += 1;
        total_job_ticks += used as u64;
        total_ticks += 1;

        // Advance: decrement all ticks
        let mut finished_phase: Vec<String> = Vec::new();
        for (pkg, a) in active.iter_mut() {
            a.ticks_left -= 1;
            if a.ticks_left == 0 {
                finished_phase.push(pkg.clone());
            }
        }

        // Process phase completions
        let mut done_pkgs: Vec<String> = Vec::new();
        for pkg in finished_phase {
            let a = active.get_mut(&pkg).expect("active");
            if !unsafe_pkgs.contains(&pkg) {
                sched.release_make_jobs(&pkg);
            }
            if a.phase == 0 {
                let ticks = get_ticks(&pkg, 1);
                let jobs = if unsafe_pkgs.contains(&pkg) {
                    1
                } else {
                    sched.request_make_jobs(&pkg).unwrap_or(1)
                };
                a.phase = 1;
                a.ticks_left = ticks;
                a.jobs = jobs;
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

    eprintln!(
        "\n=== MAKE_JOBS simulation: {} threads, {} max_jobs, {} packages ===",
        build_threads, max_jobs, completed
    );
    eprintln!(
        "Utilization: {:.1}% ({} job-ticks / {} tick-slots)",
        utilization,
        total_job_ticks,
        total_ticks * max_jobs as u64
    );
    eprintln!("Ticks: {}, max concurrent: {}", total_ticks, max_active);

    // Print histogram
    eprintln!("Core usage histogram:");
    let max_count = *histogram.iter().max().unwrap_or(&1);
    for (cores, &count) in histogram.iter().enumerate() {
        if count > 0 {
            let bar_len = (count * 50 / max_count) as usize;
            let bar: String = "#".repeat(bar_len);
            eprintln!("  {:>3} cores: {:>6} ticks  {}", cores, count, bar);
        }
    }

    assert!(
        utilization > 40.0,
        "Utilization too low: {:.1}%",
        utilization
    );
}

#[test]
fn depgraph_make_jobs_full() {
    run_make_jobs_sim(4, 16, None, &HashSet::new(), None);
}

const MUTT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/mutt.txt");

#[test]
fn depgraph_make_jobs_mutt() {
    let g = load_depgraph_file(MUTT_PATH);
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

const TIMINGS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/timings2.txt");

#[test]
fn depgraph_make_jobs_mutt_timed() {
    let g = load_depgraph_file(MUTT_PATH);
    let timings = load_timings(TIMINGS_PATH);
    eprintln!(
        "\nmutt build (timed): {} packages, {} edges, {} timings",
        g.pkg_count,
        g.edge_count,
        timings.len()
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
    run_make_jobs_sim(4, 16, Some(&g), &unsafe_pkgs, Some(&timings));
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
