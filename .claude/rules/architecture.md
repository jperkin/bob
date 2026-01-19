# Architecture

## Data Flow

```
config.lua → Config → Scan → ScanSummary → Build → BuildSummary → Report
                        ↓         ↓           ↓
                      Database (bob.db) - persistent cache
```

## Core Abstractions

### RunContext
Shared across all operations, carries the shutdown flag:
```rust
pub struct RunContext {
    pub shutdown: Arc<AtomicBool>,
}
```

### Config (config.rs)
Parsed from Lua, validated before use:
- `Options` - build_threads, scan_threads, strict_scan, verbose
- `Pkgsrc` - paths, package lists
- `Sandboxes` - setup/teardown actions

### Scan (scan.rs)
Discovers packages and dependencies:
- Runs `make pbulk-index` per package
- Recursively discovers transitive dependencies
- Caches results to database
- Resolves wildcard patterns

### Build (build.rs)
Orchestrates parallel builds:
- Uses petgraph DAG for scheduling
- Respects dependency order
- Manages worker threads
- Streams output to TUI

### Database (db.rs)
SQLite with optimized pragmas:
- WAL mode, 64MB cache
- Schema versioning (increment `SCHEMA_VERSION` on changes)
- Tables: packages, depends, resolved_depends, builds, metadata

### Sandbox (sandbox.rs)
Platform-abstracted isolation:
- `SandboxScope` - RAII lifecycle management
- Platform implementations in `sandbox/sandbox_*.rs`
- Actions: Mount, Copy, Symlink, Cmd

## Build Phases

Each package goes through stages:
1. pre-clean
2. depends
3. checksum
4. configure
5. build
6. install
7. package
8. deinstall
9. clean

## Database Schema

```sql
packages     -- pkgname, pkgpath, status, cached scan JSON
depends      -- raw dependency patterns
resolved_depends  -- resolved deps (for reverse lookups)
builds       -- results with indexed outcome
metadata     -- key-value flags
```

Changing schema requires:
1. Increment `SCHEMA_VERSION` in db.rs
2. User runs `bob clean` to migrate

## Platform Support

| Platform | Sandbox Method |
|----------|----------------|
| Linux | Mount namespaces + chroot |
| macOS | bindfs/devfs + chroot |
| NetBSD | Native mounts + chroot |
| illumos | Platform mounts + chroot |

## Testing

Integration tests in `tests/resolve.rs`:
- 29,022 package dataset (zstd compressed)
- Verifies dependency resolution
- Checks pbulk compatibility

Run: `cargo test`
