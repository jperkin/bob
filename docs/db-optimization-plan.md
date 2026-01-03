# Database Architecture Optimization Plan

## Executive Summary

The current database architecture loads all scan and build data into memory at startup, resulting in ~3GB RAM usage for a full pkgsrc tree (~25,000 packages). This plan redesigns the database schema and access patterns to:

1. Minimize memory usage through lazy loading and indexed queries
2. Optimize for fast reverse dependency lookups
3. Maintain full resumability after interruption
4. Handle changing pkgpath lists efficiently
5. Balance JSON storage vs. columns for performance

## Current Architecture Analysis

### Current Schema (3 tables)

```sql
-- All scan results stored as JSON blobs
CREATE TABLE scan (
    pkgpath TEXT PRIMARY KEY,  -- e.g., "mail/mutt"
    data TEXT NOT NULL         -- JSON: Vec<ScanIndex>
);

-- All build results stored as JSON blobs
CREATE TABLE build (
    pkgname TEXT PRIMARY KEY,  -- e.g., "mutt-2.2.12"
    data TEXT NOT NULL         -- JSON: BuildResult
);

-- Key-value metadata
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

### Current Memory Issues

1. **`db.get_all_scan()`** (db.rs:83-105): Loads ALL scan data into `IndexMap<PkgPath, Vec<ScanIndex>>`
2. **`db.get_all_build()`** (db.rs:157-178): Loads ALL build results into `IndexMap<PkgName, BuildResult>`
3. **`Scan::load_cached()`** (scan.rs:278-334): Clones entire cache to both `self.cache` and `self.done`
4. **JSON parsing**: Every ScanIndex with `all_depends: Vec<Depend>` must be deserialized

### Current Data Flow

```
Startup:
  db.get_all_scan() -> IndexMap (full load, ~2GB for 25K packages)
  scan.load_cached(cached) -> copies to cache + done fields
  scan.resolve() -> creates resolved IndexMap

  db.get_all_build() -> IndexMap (full load)
  build.load_cached(cached) -> filters to scanpkgs
```

---

## Proposed Architecture

### New Schema Design

```sql
-- Schema version tracking for migrations
CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY
);

-- ============================================================
-- SCAN TABLES
-- ============================================================

-- Core package identity and status (frequently queried columns)
CREATE TABLE packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pkgname TEXT UNIQUE NOT NULL,           -- e.g., "mutt-2.2.12"
    pkgpath TEXT NOT NULL,                  -- e.g., "mail/mutt"
    pkgname_base TEXT NOT NULL,             -- e.g., "mutt" (for pattern matching)
    version TEXT NOT NULL,                  -- e.g., "2.2.12"

    -- Status flags (avoid loading JSON)
    skip_reason TEXT,                       -- PKG_SKIP_REASON if set
    fail_reason TEXT,                       -- PKG_FAIL_REASON if set
    is_bootstrap BOOLEAN DEFAULT FALSE,
    pbulk_weight INTEGER DEFAULT 100,

    -- Full scan data (lazy load when needed)
    scan_data TEXT,                         -- JSON: remaining ScanIndex fields

    -- Timestamps for change detection
    scanned_at INTEGER NOT NULL,            -- Unix timestamp

    UNIQUE(pkgpath, pkgname)                -- Multi-version packages
);

-- Indexed for fast pkgpath lookups
CREATE INDEX idx_packages_pkgpath ON packages(pkgpath);
CREATE INDEX idx_packages_pkgname_base ON packages(pkgname_base);
CREATE INDEX idx_packages_status ON packages(skip_reason, fail_reason);

-- ============================================================
-- DEPENDENCY TABLES (normalized for fast lookups)
-- ============================================================

-- Raw dependency patterns from scan (ALL_DEPENDS)
CREATE TABLE raw_dependencies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    depend_pattern TEXT NOT NULL,           -- e.g., "gtk2>=2.12.0"
    depend_pkgpath TEXT NOT NULL,           -- e.g., "x11/gtk2"

    UNIQUE(package_id, depend_pattern)
);

CREATE INDEX idx_raw_deps_package ON raw_dependencies(package_id);
CREATE INDEX idx_raw_deps_pkgpath ON raw_dependencies(depend_pkgpath);

-- Resolved dependencies (after pattern matching)
CREATE TABLE resolved_dependencies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    depends_on_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,

    UNIQUE(package_id, depends_on_id)
);

CREATE INDEX idx_resolved_deps_package ON resolved_dependencies(package_id);
CREATE INDEX idx_resolved_deps_depends_on ON resolved_dependencies(depends_on_id);

-- ============================================================
-- BUILD TABLES
-- ============================================================

-- Build results with indexed status columns
CREATE TABLE builds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,

    -- Status (indexed for fast filtering)
    outcome TEXT NOT NULL,                  -- 'success', 'failed', 'up_to_date',
                                            -- 'pre_failed', 'indirect_failed',
                                            -- 'indirect_pre_failed'
    outcome_detail TEXT,                    -- Error message or failed dependency name

    -- Timing
    duration_ms INTEGER NOT NULL DEFAULT 0,
    built_at INTEGER NOT NULL,              -- Unix timestamp

    -- Log location (nullable - cleaned up on success)
    log_dir TEXT,

    UNIQUE(package_id)                      -- One build result per package
);

CREATE INDEX idx_builds_outcome ON builds(outcome);
CREATE INDEX idx_builds_package ON builds(package_id);

-- ============================================================
-- METADATA
-- ============================================================

CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Known metadata keys:
-- 'full_scan_complete' = 'true'/'false'
-- 'resolve_complete' = 'true'/'false'
-- 'resolve_buildable_count' = integer as string
-- 'scan_pkgpath_list_hash' = hash of pkgpath list for change detection
```

### Key Design Decisions

#### 1. Separate Package Identity from Full Data

The `packages` table stores frequently-needed columns directly:
- `pkgname`, `pkgpath`, `version` - identity
- `skip_reason`, `fail_reason` - quick status checks
- `is_bootstrap`, `pbulk_weight` - build scheduling

The `scan_data` column stores remaining ScanIndex fields as JSON for lazy loading.

**Trade-off**: Slight duplication vs. ability to query/filter without parsing JSON.

#### 2. Normalized Dependency Tables

Raw dependencies (`raw_dependencies`) and resolved dependencies (`resolved_dependencies`) are stored in normalized form with proper foreign keys and indexes.

**Benefits**:
- O(1) reverse dependency lookup via `idx_resolved_deps_depends_on`
- No need to load all packages to find dependents
- Incremental updates possible

#### 3. Build Results Indexed by Outcome

The `builds` table has an index on `outcome` for fast filtering:
- Get all failed packages: `SELECT * FROM builds WHERE outcome = 'failed'`
- Get all successful packages: `SELECT * FROM builds WHERE outcome = 'success'`

---

## API Changes

### Database Struct Changes

```rust
pub struct Database {
    conn: Connection,
}

impl Database {
    // ========== PACKAGE QUERIES (lazy loading) ==========

    /// Get count of scanned packages (no data load)
    pub fn count_packages(&self) -> Result<i64>;

    /// Get package IDs that are buildable (no skip/fail reason)
    pub fn get_buildable_package_ids(&self) -> Result<Vec<i64>>;

    /// Get package by pkgname (single row)
    pub fn get_package_by_name(&self, pkgname: &str) -> Result<Option<PackageRow>>;

    /// Get packages by pkgpath (for multi-version)
    pub fn get_packages_by_path(&self, pkgpath: &str) -> Result<Vec<PackageRow>>;

    /// Check if pkgpath is scanned (without loading data)
    pub fn is_pkgpath_scanned(&self, pkgpath: &str) -> Result<bool>;

    /// Get all pkgpaths that are scanned
    pub fn get_scanned_pkgpaths(&self) -> Result<HashSet<String>>;

    /// Load full ScanIndex for a package (lazy load scan_data JSON)
    pub fn get_full_scan_index(&self, package_id: i64) -> Result<ScanIndex>;

    // ========== DEPENDENCY QUERIES ==========

    /// Get direct dependencies of a package
    pub fn get_dependencies(&self, package_id: i64) -> Result<Vec<i64>>;

    /// Get reverse dependencies (packages that depend on this one)
    /// This is the key query for marking indirect failures
    pub fn get_reverse_dependencies(&self, package_id: i64) -> Result<Vec<i64>>;

    /// Get all reverse dependencies transitively (BFS in SQL)
    pub fn get_transitive_reverse_deps(&self, package_id: i64) -> Result<Vec<i64>>;

    /// Check if dependencies are resolved
    pub fn is_resolved(&self) -> Result<bool>;

    // ========== BUILD QUERIES ==========

    /// Get build status for a package (without full result)
    pub fn get_build_status(&self, package_id: i64) -> Result<Option<BuildOutcome>>;

    /// Get all completed package IDs (success or up_to_date)
    pub fn get_completed_package_ids(&self) -> Result<HashSet<i64>>;

    /// Get all failed package IDs (any failure type)
    pub fn get_failed_package_ids(&self) -> Result<HashSet<i64>>;

    /// Get packages ready to build (deps satisfied, not built)
    pub fn get_ready_to_build(&self) -> Result<Vec<i64>>;

    // ========== WRITE OPERATIONS ==========

    /// Store scan result for a pkgpath (insert/update packages + raw_dependencies)
    pub fn store_scan_result(&self, pkgpath: &str, indexes: &[ScanIndex]) -> Result<()>;

    /// Store resolved dependency (after pattern matching)
    pub fn store_resolved_dependency(
        &self,
        package_id: i64,
        depends_on_id: i64
    ) -> Result<()>;

    /// Store build result
    pub fn store_build_result(&self, package_id: i64, result: &BuildResult) -> Result<()>;

    /// Mark package and all reverse dependencies as failed
    /// Returns count of packages marked
    pub fn mark_failure_cascade(&self, package_id: i64, reason: &str) -> Result<usize>;
}
```

### New Data Structures

```rust
/// Lightweight package row (no full scan data)
pub struct PackageRow {
    pub id: i64,
    pub pkgname: String,
    pub pkgpath: String,
    pub skip_reason: Option<String>,
    pub fail_reason: Option<String>,
    pub is_bootstrap: bool,
    pub pbulk_weight: i32,
}

/// Minimal build info for scheduling
pub struct BuildInfo {
    pub package_id: i64,
    pub pkgname: String,
    pub pkgpath: String,
    pub depends_on: Vec<i64>,  // Package IDs this depends on
}
```

---

## Implementation Plan

### Phase 1: Schema Migration

1. **Add schema_version table** for tracking migrations
2. **Create new tables** alongside existing ones
3. **Migrate data** from old tables to new
4. **Verify data integrity** with checksums
5. **Drop old tables** after verification

Migration SQL:

```sql
-- Step 1: Create new schema
BEGIN TRANSACTION;

-- [Create all new tables as defined above]

-- Step 2: Migrate scan data
INSERT INTO packages (pkgname, pkgpath, pkgname_base, version,
                      skip_reason, fail_reason, is_bootstrap,
                      pbulk_weight, scan_data, scanned_at)
SELECT
    json_extract(value, '$.pkgname') as pkgname,
    key as pkgpath,
    -- Extract base name (before version)
    substr(json_extract(value, '$.pkgname'), 1,
           instr(json_extract(value, '$.pkgname') || '-', '-') - 1) as pkgname_base,
    -- Extract version (after last -)
    substr(json_extract(value, '$.pkgname'),
           length(json_extract(value, '$.pkgname')) -
           instr(reverse(json_extract(value, '$.pkgname')), '-') + 2) as version,
    json_extract(value, '$.pkg_skip_reason'),
    json_extract(value, '$.pkg_fail_reason'),
    json_extract(value, '$.bootstrap_pkg') = 'yes',
    COALESCE(CAST(json_extract(value, '$.pbulk_weight') AS INTEGER), 100),
    value,
    strftime('%s', 'now')
FROM scan, json_each(scan.data);

-- Step 3: Migrate raw dependencies
INSERT INTO raw_dependencies (package_id, depend_pattern, depend_pkgpath)
SELECT
    p.id,
    json_extract(dep.value, '$.pattern'),
    json_extract(dep.value, '$.pkgpath')
FROM packages p
JOIN scan s ON s.pkgpath = p.pkgpath
, json_each(json_extract(s.data, '$[0].all_depends')) as dep
WHERE json_extract(s.data, '$[0].pkgname') = p.pkgname;

-- Step 4: Migrate build results
INSERT INTO builds (package_id, outcome, outcome_detail, duration_ms, built_at, log_dir)
SELECT
    p.id,
    CASE json_extract(b.data, '$.outcome')
        WHEN '"Success"' THEN 'success'
        WHEN '"UpToDate"' THEN 'up_to_date'
        -- Handle Failed/PreFailed/etc variants
        ELSE lower(json_extract(b.data, '$.outcome.type'))
    END,
    json_extract(b.data, '$.outcome.reason'),
    CAST(json_extract(b.data, '$.duration.secs') * 1000 +
         json_extract(b.data, '$.duration.nanos') / 1000000 AS INTEGER),
    strftime('%s', 'now'),
    json_extract(b.data, '$.log_dir')
FROM build b
JOIN packages p ON p.pkgname = b.pkgname;

COMMIT;
```

### Phase 2: Lazy Loading API

Replace `get_all_scan()` and `get_all_build()` with targeted queries:

```rust
impl Database {
    /// Get packages that need scanning (not in DB or pkgpath changed)
    pub fn get_pkgpaths_needing_scan(
        &self,
        requested_pkgpaths: &[&str]
    ) -> Result<Vec<String>> {
        let scanned = self.get_scanned_pkgpaths()?;
        Ok(requested_pkgpaths
            .iter()
            .filter(|p| !scanned.contains(*p))
            .map(|s| s.to_string())
            .collect())
    }

    /// Load only what's needed for building
    pub fn load_build_queue(&self) -> Result<BuildQueue> {
        // 1. Get buildable package IDs (no skip/fail reason)
        let buildable_ids = self.get_buildable_package_ids()?;

        // 2. Get completed builds
        let completed_ids = self.get_completed_package_ids()?;

        // 3. Get failed builds
        let failed_ids = self.get_failed_package_ids()?;

        // 4. Load minimal info for remaining packages
        let mut queue = BuildQueue::new();
        for id in buildable_ids {
            if completed_ids.contains(&id) || failed_ids.contains(&id) {
                continue;
            }
            let info = self.get_build_info(id)?;
            queue.add(info);
        }

        Ok(queue)
    }
}
```

### Phase 3: Reverse Dependency Optimization

The key optimization for marking indirect failures:

```rust
impl Database {
    /// Mark a package and all its transitive reverse dependencies as failed.
    /// Uses recursive CTE for efficiency.
    pub fn mark_failure_cascade(
        &self,
        package_id: i64,
        reason: &str,
        duration: Duration,
    ) -> Result<usize> {
        // Use recursive CTE to find all affected packages
        let affected_ids: Vec<i64> = self.conn.prepare(
            "WITH RECURSIVE affected(id) AS (
                -- Base case: the failed package
                SELECT ?1
                UNION
                -- Recursive case: packages that depend on affected ones
                SELECT rd.package_id
                FROM resolved_dependencies rd
                JOIN affected a ON rd.depends_on_id = a.id
            )
            SELECT id FROM affected"
        )?.query_map([package_id], |row| row.get(0))?
          .collect::<Result<Vec<_>, _>>()?;

        // Batch insert/update all failures
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        self.conn.execute("BEGIN TRANSACTION", [])?;

        for (i, &id) in affected_ids.iter().enumerate() {
            let (outcome, detail, dur) = if i == 0 {
                ("failed", reason.to_string(), duration.as_millis() as i64)
            } else {
                ("indirect_failed",
                 format!("depends on failed {}", self.get_pkgname(package_id)?),
                 0)
            };

            self.conn.execute(
                "INSERT OR REPLACE INTO builds
                 (package_id, outcome, outcome_detail, duration_ms, built_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, outcome, detail, dur, now]
            )?;
        }

        self.conn.execute("COMMIT", [])?;

        Ok(affected_ids.len())
    }
}
```

### Phase 4: Change Detection for pkgpath Lists

Handle the case where pkgpath list changes between runs:

```rust
impl Database {
    /// Compare requested pkgpaths against cached ones.
    /// Returns (to_add, to_remove, unchanged)
    pub fn compare_pkgpath_lists(
        &self,
        requested: &[&str],
    ) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
        let scanned = self.get_scanned_pkgpaths()?;
        let requested_set: HashSet<_> = requested.iter().map(|s| s.to_string()).collect();

        let to_add: Vec<_> = requested_set
            .difference(&scanned)
            .cloned()
            .collect();

        let to_remove: Vec<_> = scanned
            .difference(&requested_set)
            .cloned()
            .collect();

        let unchanged: Vec<_> = scanned
            .intersection(&requested_set)
            .cloned()
            .collect();

        Ok((to_add, to_remove, unchanged))
    }

    /// Clear scan data for pkgpaths no longer in the list
    pub fn clear_removed_pkgpaths(&self, pkgpaths: &[&str]) -> Result<usize> {
        if pkgpaths.is_empty() {
            return Ok(0);
        }

        let placeholders = pkgpaths.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "DELETE FROM packages WHERE pkgpath IN ({})",
            placeholders
        );

        let count = self.conn.execute(&sql, rusqlite::params_from_iter(pkgpaths))?;
        Ok(count)
    }
}
```

### Phase 5: Scan Changes (scan.rs)

Update Scan struct to use lazy loading:

```rust
pub struct Scan {
    config: Config,
    sandbox: Sandbox,
    /// Packages to scan (not yet in DB)
    incoming: HashSet<PkgPath>,
    /// Package IDs that have been scanned
    done_ids: HashSet<i64>,
    /// Full tree scan mode
    full_tree: bool,
    full_scan_complete: bool,
    scan_failures: Vec<(PkgPath, String)>,
}

impl Scan {
    /// Initialize scan with change detection
    pub fn init_from_db(&mut self, db: &Database, pkgpaths: &[&str]) -> Result<()> {
        if self.full_tree {
            // Full tree: check full_scan_complete flag
            if db.full_scan_complete() {
                self.full_scan_complete = true;
                return Ok(());
            }
        } else {
            // Limited scan: detect changes in pkgpath list
            let (to_add, to_remove, _unchanged) = db.compare_pkgpath_lists(pkgpaths)?;

            // Clear removed pkgpaths and their dependents
            if !to_remove.is_empty() {
                db.clear_removed_pkgpaths(&to_remove.iter().map(|s| s.as_str()).collect::<Vec<_>>())?;
            }

            // Add new pkgpaths to incoming
            for path in to_add {
                self.incoming.insert(PkgPath::new(&path)?);
            }
        }

        // Load IDs of already-scanned packages
        self.done_ids = db.get_scanned_package_ids()?;

        Ok(())
    }
}
```

### Phase 6: Build Changes (build.rs)

Update Build and BuildJobs to use database:

```rust
pub struct Build {
    config: Config,
    sandbox: Sandbox,
    /// Package IDs to build
    package_ids: HashSet<i64>,
}

impl Build {
    /// Initialize from database, loading minimal data
    pub fn init_from_db(&mut self, db: &Database) -> Result<()> {
        // Get all buildable package IDs
        let buildable = db.get_buildable_package_ids()?;

        // Subtract already completed
        let completed = db.get_completed_package_ids()?;
        let failed = db.get_failed_package_ids()?;

        self.package_ids = buildable
            .into_iter()
            .filter(|id| !completed.contains(id) && !failed.contains(id))
            .collect();

        Ok(())
    }
}

struct BuildJobs {
    db: Arc<Database>,
    /// Package ID -> dependency package IDs
    incoming: HashMap<i64, HashSet<i64>>,
    running: HashSet<i64>,
    done: HashSet<i64>,
    failed: HashSet<i64>,
}

impl BuildJobs {
    /// Mark failure using database cascade
    fn mark_failure(&mut self, package_id: i64, duration: Duration) -> Result<usize> {
        // Use database recursive CTE for efficiency
        let affected = self.db.mark_failure_cascade(
            package_id,
            "Build failed",
            duration
        )?;

        // Update local state
        for id in self.db.get_transitive_reverse_deps(package_id)? {
            self.incoming.remove(&id);
            self.failed.insert(id);
        }

        Ok(affected)
    }
}
```

---

## Memory Usage Comparison

### Current (Full Load)

| Data | Packages | Est. Size Per | Total |
|------|----------|---------------|-------|
| ScanIndex (with all_depends) | 25,000 | 50-100 KB | 1.25-2.5 GB |
| Clone to cache | 25,000 | 50-100 KB | 1.25-2.5 GB |
| Clone to done | 25,000 | 50-100 KB | 1.25-2.5 GB |
| BuildResult | 25,000 | 1 KB | 25 MB |
| **Total** | | | **~3-7 GB** |

### Proposed (Lazy Load)

| Data | Packages | Est. Size Per | Total |
|------|----------|---------------|-------|
| PackageRow (minimal) | 25,000 | 200 bytes | 5 MB |
| BuildInfo (IDs only) | 10,000 (active) | 100 bytes | 1 MB |
| Dependency edges | 100,000 | 16 bytes | 1.6 MB |
| **Total** | | | **~10-20 MB** |

**Memory reduction: 99%+**

---

## Performance Optimizations

### 1. Batch Inserts with Transactions

```rust
impl Database {
    pub fn store_scan_results_batch(
        &self,
        results: &[(String, Vec<ScanIndex>)]
    ) -> Result<()> {
        let tx = self.conn.transaction()?;

        for (pkgpath, indexes) in results {
            // Insert packages
            for idx in indexes {
                tx.execute(
                    "INSERT OR REPLACE INTO packages (...) VALUES (...)",
                    params![...]
                )?;

                // Insert raw dependencies in batch
                let pkg_id = tx.last_insert_rowid();
                if let Some(deps) = &idx.all_depends {
                    for dep in deps {
                        tx.execute(
                            "INSERT OR IGNORE INTO raw_dependencies (...) VALUES (...)",
                            params![pkg_id, dep.pattern(), dep.pkgpath()]
                        )?;
                    }
                }
            }
        }

        tx.commit()?;
        Ok(())
    }
}
```

### 2. Prepared Statements Cache

```rust
pub struct Database {
    conn: Connection,
    // Cached prepared statements
    stmt_get_reverse_deps: RefCell<Option<Statement<'_>>>,
    stmt_get_package: RefCell<Option<Statement<'_>>>,
}
```

### 3. SQLite Pragmas

```rust
impl Database {
    fn configure_for_performance(&self) -> Result<()> {
        self.conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;  -- 64MB cache
            PRAGMA temp_store = MEMORY;
            PRAGMA mmap_size = 268435456;  -- 256MB mmap
        ")?;
        Ok(())
    }
}
```

### 4. Index-Only Scans

For common queries, ensure indexes cover all needed columns:

```sql
-- Covers: get_ready_to_build()
CREATE INDEX idx_build_queue ON packages(id, pkgpath, pkgname, pbulk_weight)
    WHERE skip_reason IS NULL AND fail_reason IS NULL;

-- Covers: get_buildable_package_ids()
CREATE INDEX idx_buildable ON packages(id)
    WHERE skip_reason IS NULL AND fail_reason IS NULL;
```

---

## Resumability Guarantees

### Scan Resumability

1. **Incremental saves**: Each pkgpath saved to DB immediately after scanning
2. **Change detection**: Compare requested vs. scanned pkgpaths
3. **Full tree flag**: `full_scan_complete` metadata
4. **Resolve caching**: Resolved dependencies stored in DB, not just metadata

### Build Resumability

1. **Immediate saves**: BuildResult saved to DB as soon as package completes
2. **Cascade failures**: `mark_failure_cascade()` atomic transaction
3. **Status tracking**: `outcome` column indexed for fast filtering
4. **No data loss**: WAL mode ensures durability

### Recovery Scenarios

| Scenario | Current | Proposed |
|----------|---------|----------|
| Interrupt during scan | Resume from last pkgpath | Same, but no full load |
| Interrupt during build | Resume, reload all | Resume, load only needed |
| pkgpath list changed | Manual clean required | Auto-detect, update |
| Add package to build | Full rescan | Incremental add |

---

## Testing Strategy

### Unit Tests

1. Schema migration preserves all data
2. Reverse dependency queries return correct results
3. Failure cascade marks all dependents
4. Change detection identifies added/removed pkgpaths

### Integration Tests

1. Full scan with interruption and resume
2. Build with failures and cascade
3. pkgpath list modification between runs
4. Concurrent builds don't corrupt DB

### Performance Tests

1. Startup time: < 1 second for 25K packages
2. Memory usage: < 50 MB during normal operation
3. Reverse dep query: < 10ms for 1000 dependents
4. Failure cascade: < 100ms for 5000 affected packages

---

## Migration Path

### Step 1: Add New Tables (Non-Breaking)

- Create new tables alongside existing
- New code writes to both old and new
- Old code continues reading old tables

### Step 2: Migrate Existing Data

- Run migration script to populate new tables
- Verify data integrity with checksums
- Run parallel validation

### Step 3: Switch Read Path

- Update all read operations to use new tables
- Keep write dual-path for safety
- Monitor for regressions

### Step 4: Remove Old Tables

- Remove write to old tables
- Archive old tables
- Drop old tables after verification

---

## Summary

This architecture addresses all requirements:

| Requirement | Solution |
|-------------|----------|
| Resumability | Immediate saves, WAL mode, atomic cascades |
| pkgpath list changes | Change detection, incremental updates |
| Full tree scan flag | `full_scan_complete` metadata |
| Fast reverse deps | Indexed `resolved_dependencies` table, recursive CTE |
| Avoid struct duplication | Columns for hot fields, JSON for cold data |
| Low memory | Lazy loading, IDs instead of full objects |
| Fast startup | No full data load, query only what's needed |

The estimated memory reduction is 99%+ (3GB → <50MB), with faster startup and better resumability.
