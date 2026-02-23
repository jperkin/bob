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
