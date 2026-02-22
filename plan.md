# Dynamic MAKE_JOBS Allocation Algorithm — Design Plan

## Executive Summary

Design a clean, battle-tested algorithm for distributing MAKE_JOBS across
concurrent package builds. The algorithm must be simple to reason about,
handle all edge cases naturally, and produce good results for 99% of
real-world pkgsrc builds without complex tuning.

---

## Part 1: Analysis of Existing Work

### What the system does

Bob builds pkgsrc packages in parallel across `build_threads` sandboxed
workers. Each package goes through phases: pre-clean → depends → checksum →
configure → build → install → package → deinstall → clean. Only `configure`
and `build` are CPU-intensive and parallelisable via `MAKE_JOBS`. The other
phases are serial I/O work.

When `dynamic_jobs` is enabled, instead of every package getting a fixed
`MAKE_JOBS`, the manager distributes a total CPU budget across workers.
Workers request a MAKE_JOBS allocation when entering configure/build phases
and release it when exiting.

### The `jobs-better` branch (good — Opus 4.5)

**Key design decisions that work well:**

1. **Trait-based allocator (`JobAllocator`)** — Clean separation of
   allocation logic from the build manager. The manager just calls
   `allocate()`, `lock()`, `release()`. Testable in isolation.

2. **Two algorithms behind the trait:** `WeightedFairShare` (default) and
   `EqualShare` (baseline). Selectable via config.

3. **Sole builder optimisation** — When exactly one worker is running AND
   nothing else is ready to dispatch, give it the full budget. This handles
   the serial tail perfectly.

4. **Look-ahead with upcoming weights** — Ready-to-dispatch packages
   participate in weight distribution as virtual entries (amplified by
   `UPCOMING_WEIGHT_FACTOR=2`). This holds back budget from shallow current
   work so that deep upcoming packages get more when they start.

5. **Dynamic scheduling in `get_next_build()`** — Removed precomputed
   `build_order` vector. Instead, picks the ready package with highest
   `remaining_depth()` at dispatch time. This adapts to the evolving state
   of the build as packages complete or fail.

6. **`AllocContext` struct** — All allocation inputs bundled into a clean
   struct: `sandbox_id`, `my_weight`, `all_dispatched`, `sole_builder`,
   `upcoming_weights`. No hidden state.

7. **Extensive debug logging** — `MAKE_JOBS init/dispatch/allocate/complete/
   phase-exit/snapshot` messages with budget state, weights, worker status.
   Periodic 30-second snapshots.

8. **Config:** `dynamic_jobs = { max = N, min = M, algorithm = "..." }`

**What works well:**
- Simple mental model: min guaranteed per worker, extra distributed by weight
- Sole builder handles single-package and serial-tail cases
- Look-ahead prevents the "first mover gets all" problem
- Weight = `remaining_depth` = critical path cost (CPM)
- No history dependency — works from first build using PBULK_WEIGHT

### The `jobs` branch (bad — Opus 4.6 previous session)

**Key problems:**

1. **Over-engineered SpeedModel / Amdahl's law** — Fits `T(j) = p + q/j`
   from historical `(make_jobs, total_duration_ms)` pairs using linear
   regression. This is theoretically interesting but practically broken:
   - Needs multiple builds at different job counts to fit properly
   - First build has no history, so falls back to PBULK_WEIGHT anyway
   - The model is only used for `t1_ms` (estimated single-job time), not
     for optimising job counts — so the regression is wasted complexity
   - `total_duration_ms` includes ALL phases (depends, install, clean etc.),
     not just the parallelisable build phase, corrupting the model

2. **Removed `min_per_worker`** — The config was simplified to just
   `dynamic_jobs = N` (a single integer). This means there's no minimum
   guarantee. The base allocation is just 1 per dispatched worker. With
   16 cores and 4 workers, extra_pool = 12 with base of 1 each. A
   low-weight worker could get stuck at 1 job — worse than no dynamic_jobs.

3. **Complex `weight()` function** — `t1 + rd.max(tdw / num_workers)` mixes
   the package's own estimated time with the max of critical path depth and
   total-dependent-work/workers. This tries to capture both depth and
   breadth but the units don't make sense together (ms + ms, but with
   different scales and meanings). It's hard to reason about.

4. **`dependent_stats()` / `total_dependent_work()`** — Full transitive
   closure computation on every allocation. O(V+E) per call, called for
   every dispatched worker on every build phase entry. With thousands of
   packages, this is expensive and adds complexity without clear benefit.

5. **Kept `build_order` vector** — Still precomputes static build order,
   missing the improvement from jobs-better that dynamically picks the
   highest-depth ready package.

6. **`db.build_time_profiles()`** — New DB query to load all historical
   build times. Added complexity to db.rs for the SpeedModel that doesn't
   pay off.

---

## Part 2: The Algorithm Design

### Core Principles

1. **Simple inputs, predictable outputs** — The algorithm takes: total CPU
   budget, minimum per worker, set of active workers with weights, and
   upcoming ready packages. It returns: how many jobs this worker gets.

2. **Weight = remaining critical path depth** — One metric, well-understood.
   Packages on the critical path (deep chains of dependents) get more cores.
   Leaves get fewer. This directly optimises wall-clock time.

3. **No history needed for correctness** — PBULK_WEIGHT (from pkgsrc
   metadata, available from first build) is a good-enough proxy. History
   can refine it later but is not required.

4. **Handle edge cases naturally, not as special cases** — The sole builder
   case, single package case, and many-small-packages case should all fall
   out of the same logic without if/else branches.

### The Algorithm: Weighted Fair Share with Look-ahead

```
INPUTS:
  max_jobs      — total CPU budget (e.g. 16)
  min_per_worker — guaranteed minimum per worker (e.g. 2)
  active_workers — [(sandbox_id, weight)] for all dispatched workers
  locked        — {sandbox_id: jobs} for workers already in build phase
  my_sandbox_id — which worker is asking
  upcoming      — [weight] for ready-to-dispatch packages (capped to idle slots)
  sole_builder  — true if only one worker running and nothing ready

OUTPUT:
  jobs — how many MAKE_JOBS this worker gets

ALGORITHM:
  1. If sole_builder: return max_jobs
     (Nothing else can compete. Give everything.)

  2. active = len(active_workers)
     extra_pool = max_jobs - (active * min_per_worker)
     (Reserve min for each active worker. Rest is distributable.)

  3. locked_above_min = sum(locked[sid] - min_per_worker for sid in locked)
     remaining_extra = extra_pool - locked_above_min
     (Subtract what locked workers already consumed above minimum.)

  4. If remaining_extra <= 0: return min_per_worker
     (Budget exhausted. Everyone gets minimum.)

  5. Build weight pool from unlocked workers + upcoming (amplified):
     pool = [(sid, weight) for (sid, weight) in active_workers if sid not in locked]
     pool += [(virtual_id, weight * UPCOMING_FACTOR) for weight in upcoming]

  6. Distribute remaining_extra across pool using largest-remainder:
     For each entry: exact_share = remaining_extra * weight / total_weight
     Take floor, distribute leftover to highest remainders.

  7. my_share = pool entry for my_sandbox_id
     return min_per_worker + my_share
```

### Key design points explained

**Why `min_per_worker` matters:** Without a guaranteed minimum, low-weight
packages can be starved to -j1, which is slower than not enabling
dynamic_jobs at all. A minimum of 2 ensures every build makes reasonable
progress. The user controls this via config.

**Why `remaining_depth` as the sole weight:** It's the Critical Path Method
(CPM) — the longest chain of remaining work that depends on this package.
A package with depth 5000 gates a chain of heavy builds; giving it more
cores directly reduces wall-clock time. A leaf with depth 0 has slack; it
can afford fewer cores. This is optimal scheduling theory applied simply.

**Why look-ahead with amplification:** Without look-ahead, a shallow package
that enters its build phase first grabs all the extra budget. When a deep
package enters later, nothing is left. The upcoming virtual entries absorb
proportional budget that stays unallocated, so when the deep package arrives,
more extra is available. Factor=2 means upcoming packages compete at 2x
their weight — strong enough to matter, not so strong as to starve current
work below useful levels.

**Why sole_builder is the only special case:** When there's truly nothing
else to compete, handing over all cores is provably optimal. Every other
scenario is handled by the proportional distribution — even single-package
builds where other workers are idle but could potentially pick up work.

**Why no Amdahl's law / SpeedModel:** The theoretical benefit of knowing
a package's serial fraction is that you can compute diminishing returns
(giving -j16 to a 90% serial package wastes 14 cores). But in practice:
(a) we don't have reliable serial fraction data from first builds,
(b) PBULK_WEIGHT already encodes rough build time,
(c) the weighted fair share already allocates proportional to importance
rather than trying to predict speedup curves. Adding Amdahl's law is
complexity that doesn't pay for itself.

### Scheduling: Dynamic, not precomputed

The `get_next_build()` function should NOT use a precomputed `build_order`
vector. Instead, at dispatch time, it iterates over ready packages (deps
satisfied) and picks the one with the highest `remaining_depth`. This
adapts as builds complete or fail, always prioritising the current critical
path.

This is a small change from the original code but important: the precomputed
order becomes stale as packages complete, especially when failures cascade
and change the dependency graph.

### Configuration

```lua
options = {
    build_threads = 4,
    dynamic_jobs = {
        max = 16,       -- total CPU budget
        min = 2,        -- minimum per worker
        algorithm = "weighted_fair_share",  -- or "equal_share"
    },
}
```

Keep the `algorithm` field from `jobs-better` to allow easy A/B comparison
with `equal_share`.

### History data: Use it simply or not at all

**For the initial implementation:** Use `PBULK_WEIGHT` as the weight for
`remaining_depth`. This is available from the first build, requires no
history, and works well enough.

**Future enhancement (optional, not in this PR):** Replace PBULK_WEIGHT
with average historical build duration from `history.db` when available.
This is a simple substitution in the `pkg_weight()` function — no Amdahl's
law, no regression, just `AVG(build_duration_ms)` for successful builds of
the same pkgpath. The existing `db.avg_build_duration()` function already
does this. When no history exists, fall back to PBULK_WEIGHT.

---

## Part 3: Feedback and Analysis

### Debug logging (keep from jobs-better)

The `jobs-better` branch has excellent debug logging. Keep all of it:

- **`MAKE_JOBS init`** — Log algorithm name, max, min, build_threads, total
  packages at start.
- **`MAKE_JOBS dispatch`** — Log when a package is dispatched to a worker,
  with weight and queue state.
- **`MAKE_JOBS allocate`** — Log every allocation decision: worker, package,
  weight, allocated jobs, sole_builder flag, all_weights, upcoming_weights,
  budget state, queue counts.
- **`MAKE_JOBS complete`** — Log when a build finishes: actual duration,
  budget state, queue counts.
- **`MAKE_JOBS phase-exit`** — Log when a worker exits build phase.
- **`MAKE_JOBS snapshot`** — Every 30 seconds, log full state: all workers,
  what they're building, queue counts.

All at `debug` level so they don't appear normally but are available with
`log_level = "debug"` or `RUST_LOG=bob::build=debug`.

### Post-build analysis

After a build completes, the history database already stores per-package:
- `make_jobs` allocated
- `build_duration` (compilation phase only)
- `total_duration` (all phases)
- Per-stage durations

A separate `bob list history` command already exists to query this data.
Potential future analysis:

1. **Efficiency metric:** For each package, compare actual `build_duration`
   at `make_jobs=N` against what it would have been at `make_jobs=1` (from
   history). This gives observed parallel speedup and identifies packages
   where extra cores are wasted.

2. **Critical path analysis:** Post-build, compute what the critical path
   actually was (using observed durations) vs. what the algorithm predicted
   (using PBULK_WEIGHT). Identify where predictions were wrong.

3. **Utilisation metric:** Track total CPU-seconds used vs. total
   CPU-seconds available (`max_jobs * wall_clock_time`). Low utilisation
   indicates the algorithm is holding back too many cores.

These are all analysis tools, not changes to the core algorithm.

---

## Part 4: Implementation Plan

### Files to modify

1. **`src/jobs.rs`** — New file (from jobs-better), containing:
   - `AllocContext` struct
   - `JobAllocator` trait
   - `WeightedFairShare` struct implementing `JobAllocator`
   - `EqualShare` struct implementing `JobAllocator`
   - `make_allocator()` factory function
   - Unit tests for the allocators

2. **`src/build.rs`** — Modify the build manager:
   - Remove inline `MakeJobsBudget` struct (replaced by jobs.rs)
   - Remove precomputed `build_order` from `BuildJobs`
   - Change `get_next_build()` to pick highest `remaining_depth` dynamically
   - Use `AllocContext` and `JobAllocator` trait in manager loop
   - Track `build_phase_workers` and `worker_stages` for context
   - Add all debug logging from jobs-better
   - Add periodic 30-second snapshot logging

3. **`src/config.rs`** — Add `JobAlgorithm` enum, add `algorithm` field to
   `DynamicJobs`, parse from Lua config. Keep `max` and `min` fields.

4. **`src/lib.rs`** — Add `pub mod jobs;` and re-export types.

5. **`src/logging.rs`** — Minor: any needed log format adjustments.

6. **`src/main.rs`** — Wire up dbdir changes if needed.

7. **`config/*.lua`** — Remove `logdir` from pkgsrc section (moved to
   dbdir-based default per jobs-better).

8. **`tests/scan_build.rs`** — Update tests for new config structure.

### What NOT to include

- No `SpeedModel` / Amdahl's law fitting
- No `build_time_profiles()` DB query
- No `dependent_stats()` / `total_dependent_work()` functions
- No `t1_ms()` / `t1_ms_source()` complexity
- No complex `weight()` function mixing multiple metrics
- The `remaining_depth()` function (existing, using PBULK_WEIGHT) is
  sufficient and well-tested

### Testing strategy

1. **Unit tests for allocators** (in jobs.rs):
   - Single worker, sole builder → gets max_jobs
   - Two equal-weight workers → each gets max/2 (approximately)
   - One heavy, one light worker → heavy gets more
   - All budget locked → new worker gets min
   - Look-ahead: upcoming heavy package reduces current allocation
   - Edge: max < workers * min → everyone gets what's available

2. **Integration tests** (in tests/scan_build.rs):
   - Build with dynamic_jobs enabled, verify packages complete
   - Build with single package, verify it gets full budget
   - Build with chain dependency, verify ordering

3. **Manual validation:**
   - Run a real build with `log_level = "debug"`
   - Grep for `MAKE_JOBS allocate` messages
   - Verify allocations make intuitive sense for known package graphs
