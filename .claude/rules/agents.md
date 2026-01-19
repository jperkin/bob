# AI Agent Guide for Bob

Bob is a pkgsrc package builder that combines the safety of bulk build systems
with the simplicity of direct tools. It provides automatic sandboxing, parallel
builds via DAG scheduling, and SQLite-backed resumable operations.

## Architecture Overview

```
config.lua (Lua)
      │
      ▼
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│    Scan     │───▶│   Resolve    │───▶│    Build    │
│  (parallel) │    │    (DAG)     │    │  (parallel) │
└─────────────┘    └──────────────┘    └─────────────┘
      │                   │                   │
      └───────────────────┴───────────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │   SQLite    │  (bob.db - persistent cache)
                   └─────────────┘
```

**Flow:** Configuration → Scan packages → Resolve dependencies → Build in DAG
order → Generate reports

## Source Layout

```
src/
├── main.rs          CLI entry point, BuildRunner, command dispatch
├── lib.rs           Public API exports, RunContext (shutdown flag)
├── config.rs        Lua config parsing, Options, Pkgsrc, Sandboxes
├── scan.rs          Dependency scanning, resolution, ScanResult/SkipReason
├── build.rs         Parallel build orchestration, BuildOutcome/BuildResult
├── db.rs            SQLite caching, PackageRow, schema management
├── sandbox.rs       Platform abstraction, SandboxScope (RAII cleanup)
├── action.rs        Sandbox actions: Mount, Copy, Symlink, Cmd
├── report.rs        HTML report generation
├── summary.rs       pkg_summary.gz generation
├── tui.rs           Ratatui progress display
├── logging.rs       JSON tracing setup
├── init.rs          `bob init` command
└── sandbox/
    ├── sandbox_linux.rs   Mount namespaces + chroot
    ├── sandbox_macos.rs   bindfs/devfs + chroot
    ├── sandbox_netbsd.rs  Native mounts + chroot
    └── sandbox_sunos.rs   illumos mounts + chroot
```

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `RunContext` | lib.rs | Shared shutdown flag (`Arc<AtomicBool>`) |
| `Config` | config.rs | Validated configuration from Lua |
| `Scan` | scan.rs | Scanner state and orchestration |
| `ScanResult` | scan.rs | Buildable / Skipped / ScanFail |
| `SkipReason` | scan.rs | PkgSkip / PkgFail / IndirectSkip / IndirectFail / UnresolvedDep |
| `Build` | build.rs | Build orchestrator |
| `BuildOutcome` | build.rs | Success / Failed / UpToDate / Skipped |
| `BuildResult` | build.rs | Complete build result with duration, log path |
| `Database` | db.rs | SQLite connection wrapper |
| `Sandbox` | sandbox.rs | Platform-abstracted sandbox |
| `SandboxScope` | sandbox.rs | RAII guard for sandbox lifecycle |
| `Action` | action.rs | Single sandbox setup/teardown action |

## CLI Commands

| Command | Purpose |
|---------|---------|
| `bob init <dir>` | Create new config directory from templates |
| `bob scan` | Scan packages and resolve dependencies |
| `bob build [PKGPATH...]` | Full scan + build cycle |
| `bob rebuild [-f] <PKG...>` | Rebuild packages and their dependents |
| `bob clean` | Remove database and logs |
| `bob db <SQL>` | Execute raw SQL |
| `bob util sandbox {create\|destroy\|list}` | Manage sandboxes |
| `bob util generate-report` | Generate HTML from existing data |
| `bob util print-dep-graph` | Output resolved dependency graph |
| `bob util print-presolve` | Output pbulk-compatible format |

## Common Tasks

### Adding a New CLI Command
1. Add variant to `Cmd` enum in main.rs
2. Add match arm in `main()` function
3. Implement logic (often via `BuildRunner` methods)

### Adding a Sandbox Action Type
1. Add variant to `ActionType` enum in action.rs
2. Update parsing in `Action::from_lua_table()`
3. Implement in each `sandbox_*.rs` platform file

### Modifying Scan/Build Logic
1. Understand the data flow: Scan → ScanSummary → Build → BuildSummary
2. Check database caching implications
3. Ensure shutdown flag is respected in loops
4. Update tests in `tests/resolve.rs` if resolution changes

### Adding Configuration Options
1. Add field to appropriate struct in config.rs (Options, Pkgsrc, Sandboxes)
2. Update Lua parsing in `from_lua_value()` method
3. Update validation in `Config::validate()`
4. Document in example configs under `config/`

## Pitfalls to Avoid

1. **Forgetting shutdown checks** - Long-running loops must check
   `ctx.shutdown.load(Ordering::SeqCst)`

2. **Manual sandbox cleanup** - Always use `SandboxScope` RAII, never manually
   destroy sandboxes

3. **Blocking on pipes** - Use `wait_output_with_shutdown()` helpers to avoid
   deadlocks when child processes fill pipe buffers

4. **Schema changes without version bump** - Always increment `SCHEMA_VERSION`
   when modifying database tables

5. **Unwrap usage** - The project forbids `unwrap()` even in tests; use `?` with
   Result-returning test functions

6. **Over-engineering** - Keep changes minimal and focused. Don't add features,
   refactor surrounding code, or add unnecessary abstractions beyond what's
   requested.

## Dependencies

Key crates:
- `clap` - CLI parsing (derive feature)
- `anyhow` - Error handling
- `rusqlite` - SQLite (bundled)
- `mlua` - Lua scripting (lua54)
- `rayon` - Parallel scanning
- `petgraph` - DAG for build scheduling
- `ratatui` - Terminal UI
- `pkgsrc` - pkgsrc types (PkgPath, PkgName, ScanIndex)
- `tracing` - Structured logging
