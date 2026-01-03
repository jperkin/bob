/*
 * Copyright (c) 2025 Jonathan Perkin <jonathan@perkin.org.uk>
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

//! SQLite database for caching scan and build results.
//!
//! This module provides optimized database access with:
//! - Lazy loading to minimize memory usage
//! - Indexed reverse dependency lookups for fast failure cascades
//! - Normalized dependency tables for efficient queries
//! - Hybrid storage: columns for hot fields, JSON for cold data
//!
//! # Schema
//!
//! - `packages` - Core package identity and status
//! - `depends` - Raw dependency patterns from scans
//! - `resolved_depends` - Resolved dependencies after pattern matching
//! - `builds` - Build results with indexed outcome
//! - `metadata` - Key-value store for flags and cached data

use crate::build::BuildResult;
use anyhow::{Context, Result};
use indexmap::IndexMap;
use pkgsrc::{PkgName, PkgPath, ScanIndex};
use rusqlite::{Connection, params};
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Current schema version for migrations.
const SCHEMA_VERSION: i32 = 2;

/// Lightweight package row without full scan data.
#[derive(Clone, Debug)]
pub struct PackageRow {
    pub id: i64,
    pub pkgname: String,
    pub pkgpath: String,
    pub skip_reason: Option<String>,
    pub fail_reason: Option<String>,
    pub is_bootstrap: bool,
    pub pbulk_weight: i32,
}

/// Minimal build info for scheduling.
#[derive(Clone, Debug)]
pub struct BuildInfo {
    pub package_id: i64,
    pub pkgname: String,
    pub pkgpath: String,
    pub depends_on: Vec<i64>,
}

/// Build outcome for database storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DbBuildOutcome {
    Success,
    Failed,
    UpToDate,
    PreFailed,
    IndirectFailed,
    IndirectPreFailed,
}

impl DbBuildOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            DbBuildOutcome::Success => "success",
            DbBuildOutcome::Failed => "failed",
            DbBuildOutcome::UpToDate => "up_to_date",
            DbBuildOutcome::PreFailed => "pre_failed",
            DbBuildOutcome::IndirectFailed => "indirect_failed",
            DbBuildOutcome::IndirectPreFailed => "indirect_pre_failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "success" => Some(DbBuildOutcome::Success),
            "failed" => Some(DbBuildOutcome::Failed),
            "up_to_date" => Some(DbBuildOutcome::UpToDate),
            "pre_failed" => Some(DbBuildOutcome::PreFailed),
            "indirect_failed" => Some(DbBuildOutcome::IndirectFailed),
            "indirect_pre_failed" => Some(DbBuildOutcome::IndirectPreFailed),
            _ => None,
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self, DbBuildOutcome::Success | DbBuildOutcome::UpToDate)
    }

    pub fn is_failed(&self) -> bool {
        !self.is_complete()
    }
}

/// SQLite database for scan and build caching.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open or create a database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create database directory")?;
        }
        let conn = Connection::open(path).context("Failed to open database")?;
        let db = Self { conn };
        db.configure_pragmas()?;
        db.init_or_migrate()?;
        Ok(db)
    }

    /// Configure SQLite for performance.
    fn configure_pragmas(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -64000;
             PRAGMA temp_store = MEMORY;
             PRAGMA mmap_size = 268435456;
             PRAGMA foreign_keys = ON;"
        )?;
        Ok(())
    }

    /// Initialize schema or migrate from older versions.
    fn init_or_migrate(&self) -> Result<()> {
        // Check if schema_version table exists
        let has_schema_version: bool = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'",
            [],
            |row| row.get::<_, i32>(0).map(|c| c > 0),
        )?;

        if !has_schema_version {
            // Check for old schema (v1)
            let has_old_scan: bool = self.conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='scan'",
                [],
                |row| row.get::<_, i32>(0).map(|c| c > 0),
            )?;

            if has_old_scan {
                info!("Migrating from schema v1 to v{}", SCHEMA_VERSION);
                self.migrate_v1_to_v2()?;
            } else {
                self.create_schema_v2()?;
            }
        } else {
            let version: i32 = self.conn.query_row(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
                [],
                |row| row.get(0),
            ).unwrap_or(1);

            if version < SCHEMA_VERSION {
                info!("Migrating from schema v{} to v{}", version, SCHEMA_VERSION);
                if version == 1 {
                    self.migrate_v1_to_v2()?;
                }
            }
        }

        Ok(())
    }

    /// Create the v2 schema from scratch.
    fn create_schema_v2(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );

            INSERT OR REPLACE INTO schema_version (version) VALUES (2);

            CREATE TABLE IF NOT EXISTS packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pkgname TEXT UNIQUE NOT NULL,
                pkgpath TEXT NOT NULL,
                pkgname_base TEXT NOT NULL,
                version TEXT NOT NULL,
                skip_reason TEXT,
                fail_reason TEXT,
                is_bootstrap INTEGER DEFAULT 0,
                pbulk_weight INTEGER DEFAULT 100,
                scan_data TEXT,
                scanned_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_packages_pkgpath ON packages(pkgpath);
            CREATE INDEX IF NOT EXISTS idx_packages_pkgname_base ON packages(pkgname_base);
            CREATE INDEX IF NOT EXISTS idx_packages_status ON packages(skip_reason, fail_reason);

            CREATE TABLE IF NOT EXISTS depends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
                depend_pattern TEXT NOT NULL,
                depend_pkgpath TEXT NOT NULL,
                UNIQUE(package_id, depend_pattern)
            );

            CREATE INDEX IF NOT EXISTS idx_depends_package ON depends(package_id);
            CREATE INDEX IF NOT EXISTS idx_depends_pkgpath ON depends(depend_pkgpath);

            CREATE TABLE IF NOT EXISTS resolved_depends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
                depends_on_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
                UNIQUE(package_id, depends_on_id)
            );

            CREATE INDEX IF NOT EXISTS idx_resolved_depends_package ON resolved_depends(package_id);
            CREATE INDEX IF NOT EXISTS idx_resolved_depends_depends_on ON resolved_depends(depends_on_id);

            CREATE TABLE IF NOT EXISTS builds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
                outcome TEXT NOT NULL,
                outcome_detail TEXT,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                built_at INTEGER NOT NULL,
                log_dir TEXT,
                UNIQUE(package_id)
            );

            CREATE INDEX IF NOT EXISTS idx_builds_outcome ON builds(outcome);
            CREATE INDEX IF NOT EXISTS idx_builds_package ON builds(package_id);

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );"
        )?;

        debug!("Created schema v2");
        Ok(())
    }

    /// Migrate from v1 (old scan/build tables) to v2.
    fn migrate_v1_to_v2(&self) -> Result<()> {
        // Create new schema first
        self.create_schema_v2()?;

        // Migrate scan data
        let mut stmt = self.conn.prepare(
            "SELECT pkgpath, data FROM scan ORDER BY rowid"
        )?;

        let rows: Vec<(String, String)> = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?.filter_map(|r| r.ok()).collect();

        let mut migrated_count = 0;
        for (pkgpath, json) in rows {
            let indexes: Vec<ScanIndex> = match serde_json::from_str(&json) {
                Ok(idx) => idx,
                Err(e) => {
                    warn!(pkgpath = %pkgpath, error = %e, "Failed to parse scan data during migration");
                    continue;
                }
            };

            for idx in indexes {
                if let Err(e) = self.store_package(&pkgpath, &idx) {
                    warn!(pkgpath = %pkgpath, error = %e, "Failed to migrate package");
                }
            }
            migrated_count += 1;
        }

        // Migrate build data
        let mut stmt = self.conn.prepare(
            "SELECT pkgname, data FROM build ORDER BY rowid"
        )?;

        let rows: Vec<(String, String)> = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?.filter_map(|r| r.ok()).collect();

        let mut build_count = 0;
        for (pkgname, json) in rows {
            let result: BuildResult = match serde_json::from_str(&json) {
                Ok(r) => r,
                Err(e) => {
                    warn!(pkgname = %pkgname, error = %e, "Failed to parse build data during migration");
                    continue;
                }
            };

            // Look up package_id
            if let Ok(Some(pkg)) = self.get_package_by_name(&pkgname) {
                if let Err(e) = self.store_build_result(pkg.id, &result) {
                    warn!(pkgname = %pkgname, error = %e, "Failed to migrate build result");
                }
                build_count += 1;
            }
        }

        // Migrate metadata
        let metadata_keys = ["full_scan_complete", "resolve_result", "resolve_buildable_count"];
        for key in metadata_keys {
            if let Ok(value) = self.conn.query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                [key],
                |row| row.get::<_, String>(0),
            ) {
                // Already in new metadata table or will be re-added
                let _ = self.conn.execute(
                    "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
                    params![key, value],
                );
            }
        }

        // Drop old tables
        self.conn.execute_batch(
            "DROP TABLE IF EXISTS scan;
             DROP TABLE IF EXISTS build;"
        )?;

        info!(packages = migrated_count, builds = build_count, "Migration to v2 complete");
        Ok(())
    }

    // ========================================================================
    // PACKAGE QUERIES
    // ========================================================================

    /// Store a package from scan results.
    pub fn store_package(&self, pkgpath: &str, index: &ScanIndex) -> Result<i64> {
        let pkgname = index.pkgname.pkgname();
        let (base, version) = split_pkgname(pkgname);

        let skip_reason = index.pkg_skip_reason.as_ref()
            .filter(|s| !s.is_empty());
        let fail_reason = index.pkg_fail_reason.as_ref()
            .filter(|s| !s.is_empty());
        let is_bootstrap = index.bootstrap_pkg.as_deref() == Some("yes");
        let pbulk_weight: i32 = index.pbulk_weight
            .as_ref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let scan_data = serde_json::to_string(index)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        self.conn.execute(
            "INSERT OR REPLACE INTO packages
             (pkgname, pkgpath, pkgname_base, version, skip_reason, fail_reason,
              is_bootstrap, pbulk_weight, scan_data, scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![pkgname, pkgpath, base, version, skip_reason, fail_reason,
                    is_bootstrap, pbulk_weight, scan_data, now],
        )?;

        let package_id = self.conn.last_insert_rowid();

        // Store raw dependencies
        if let Some(ref deps) = index.all_depends {
            for dep in deps {
                self.conn.execute(
                    "INSERT OR IGNORE INTO depends (package_id, depend_pattern, depend_pkgpath)
                     VALUES (?1, ?2, ?3)",
                    params![package_id, dep.pattern().pattern(), dep.pkgpath().to_string()],
                )?;
            }
        }

        debug!(pkgname = pkgname, package_id = package_id, "Stored package");
        Ok(package_id)
    }

    /// Store scan results for a pkgpath (compatibility wrapper).
    pub fn store_scan_pkgpath(&self, pkgpath: &str, indexes: &[ScanIndex]) -> Result<()> {
        for index in indexes {
            self.store_package(pkgpath, index)?;
        }
        Ok(())
    }

    /// Get package by name.
    pub fn get_package_by_name(&self, pkgname: &str) -> Result<Option<PackageRow>> {
        let result = self.conn.query_row(
            "SELECT id, pkgname, pkgpath, skip_reason, fail_reason, is_bootstrap, pbulk_weight
             FROM packages WHERE pkgname = ?1",
            [pkgname],
            |row| Ok(PackageRow {
                id: row.get(0)?,
                pkgname: row.get(1)?,
                pkgpath: row.get(2)?,
                skip_reason: row.get(3)?,
                fail_reason: row.get(4)?,
                is_bootstrap: row.get::<_, i32>(5)? != 0,
                pbulk_weight: row.get(6)?,
            }),
        );

        match result {
            Ok(pkg) => Ok(Some(pkg)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get package ID by name.
    pub fn get_package_id(&self, pkgname: &str) -> Result<Option<i64>> {
        let result = self.conn.query_row(
            "SELECT id FROM packages WHERE pkgname = ?1",
            [pkgname],
            |row| row.get(0),
        );

        match result {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get pkgname by package ID.
    pub fn get_pkgname(&self, package_id: i64) -> Result<String> {
        self.conn.query_row(
            "SELECT pkgname FROM packages WHERE id = ?1",
            [package_id],
            |row| row.get(0),
        ).context("Package not found")
    }

    /// Get packages by pkgpath.
    pub fn get_packages_by_path(&self, pkgpath: &str) -> Result<Vec<PackageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pkgname, pkgpath, skip_reason, fail_reason, is_bootstrap, pbulk_weight
             FROM packages WHERE pkgpath = ?1"
        )?;

        let rows = stmt.query_map([pkgpath], |row| Ok(PackageRow {
            id: row.get(0)?,
            pkgname: row.get(1)?,
            pkgpath: row.get(2)?,
            skip_reason: row.get(3)?,
            fail_reason: row.get(4)?,
            is_bootstrap: row.get::<_, i32>(5)? != 0,
            pbulk_weight: row.get(6)?,
        }))?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Check if pkgpath is scanned.
    pub fn is_pkgpath_scanned(&self, pkgpath: &str) -> Result<bool> {
        let count: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM packages WHERE pkgpath = ?1",
            [pkgpath],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Get all scanned pkgpaths.
    pub fn get_scanned_pkgpaths(&self) -> Result<HashSet<String>> {
        let mut stmt = self.conn.prepare("SELECT DISTINCT pkgpath FROM packages")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<HashSet<_>, _>>().map_err(Into::into)
    }

    /// Count of scanned packages.
    pub fn count_packages(&self) -> Result<i64> {
        self.conn.query_row("SELECT COUNT(*) FROM packages", [], |row| row.get(0))
            .context("Failed to count packages")
    }

    /// Count of scanned pkgpaths (for compatibility).
    pub fn count_scan(&self) -> Result<i64> {
        self.conn.query_row("SELECT COUNT(DISTINCT pkgpath) FROM packages", [], |row| row.get(0))
            .context("Failed to count scan")
    }

    /// Get all buildable package IDs (no skip/fail reason).
    pub fn get_buildable_package_ids(&self) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM packages WHERE skip_reason IS NULL AND fail_reason IS NULL"
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Get all buildable packages (lightweight).
    pub fn get_buildable_packages(&self) -> Result<Vec<PackageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pkgname, pkgpath, skip_reason, fail_reason, is_bootstrap, pbulk_weight
             FROM packages WHERE skip_reason IS NULL AND fail_reason IS NULL"
        )?;

        let rows = stmt.query_map([], |row| Ok(PackageRow {
            id: row.get(0)?,
            pkgname: row.get(1)?,
            pkgpath: row.get(2)?,
            skip_reason: row.get(3)?,
            fail_reason: row.get(4)?,
            is_bootstrap: row.get::<_, i32>(5)? != 0,
            pbulk_weight: row.get(6)?,
        }))?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Load full ScanIndex for a package.
    pub fn get_full_scan_index(&self, package_id: i64) -> Result<ScanIndex> {
        let json: String = self.conn.query_row(
            "SELECT scan_data FROM packages WHERE id = ?1",
            [package_id],
            |row| row.get(0),
        )?;
        serde_json::from_str(&json).context("Failed to deserialize scan data")
    }

    /// Load all scan data (compatibility wrapper for migration period).
    pub fn get_all_scan(&self) -> Result<IndexMap<PkgPath, Vec<ScanIndex>>> {
        let mut stmt = self.conn.prepare(
            "SELECT pkgpath, scan_data FROM packages ORDER BY id"
        )?;

        let mut result: IndexMap<PkgPath, Vec<ScanIndex>> = IndexMap::new();
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        for row in rows {
            let (pkgpath_str, json) = row?;
            let pkgpath = PkgPath::new(&pkgpath_str)
                .context("Invalid pkgpath in database")?;
            let index: ScanIndex = serde_json::from_str(&json)
                .context("Failed to deserialize scan data")?;
            result.entry(pkgpath).or_default().push(index);
        }

        Ok(result)
    }

    /// Clear all scan data.
    pub fn clear_scan(&self) -> Result<()> {
        self.conn.execute("DELETE FROM packages", [])?;
        self.clear_full_scan_complete()?;
        self.clear_resolve()?;
        Ok(())
    }

    // ========================================================================
    // DEPENDENCY QUERIES
    // ========================================================================

    /// Store a resolved dependency.
    pub fn store_resolved_dependency(&self, package_id: i64, depends_on_id: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO resolved_depends (package_id, depends_on_id) VALUES (?1, ?2)",
            params![package_id, depends_on_id],
        )?;
        Ok(())
    }

    /// Store multiple resolved dependencies.
    pub fn store_resolved_dependencies(&self, package_id: i64, depends_on_ids: &[i64]) -> Result<()> {
        for &dep_id in depends_on_ids {
            self.store_resolved_dependency(package_id, dep_id)?;
        }
        Ok(())
    }

    /// Get direct dependencies of a package.
    pub fn get_dependencies(&self, package_id: i64) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT depends_on_id FROM resolved_depends WHERE package_id = ?1"
        )?;
        let rows = stmt.query_map([package_id], |row| row.get::<_, i64>(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Get reverse dependencies (packages that depend on this one).
    pub fn get_reverse_dependencies(&self, package_id: i64) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT package_id FROM resolved_depends WHERE depends_on_id = ?1"
        )?;
        let rows = stmt.query_map([package_id], |row| row.get::<_, i64>(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Get all transitive reverse dependencies using recursive CTE.
    pub fn get_transitive_reverse_deps(&self, package_id: i64) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            "WITH RECURSIVE affected(id) AS (
                SELECT ?1
                UNION
                SELECT rd.package_id
                FROM resolved_depends rd
                JOIN affected a ON rd.depends_on_id = a.id
            )
            SELECT id FROM affected WHERE id != ?1"
        )?;
        let rows = stmt.query_map([package_id], |row| row.get::<_, i64>(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Check if dependencies are resolved.
    pub fn is_resolved(&self) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM resolved_depends",
            [],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Clear all resolved dependencies.
    pub fn clear_resolved_depends(&self) -> Result<()> {
        self.conn.execute("DELETE FROM resolved_depends", [])?;
        Ok(())
    }

    /// Get raw dependencies for pattern matching.
    pub fn get_raw_dependencies(&self, package_id: i64) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT depend_pattern, depend_pkgpath FROM depends WHERE package_id = ?1"
        )?;
        let rows = stmt.query_map([package_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // ========================================================================
    // BUILD QUERIES
    // ========================================================================

    /// Store a build result.
    pub fn store_build_result(&self, package_id: i64, result: &BuildResult) -> Result<()> {
        let (outcome, detail) = build_outcome_to_db(&result.outcome);
        let duration_ms = result.duration.as_millis() as i64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let log_dir = result.log_dir.as_ref().map(|p| p.display().to_string());

        self.conn.execute(
            "INSERT OR REPLACE INTO builds
             (package_id, outcome, outcome_detail, duration_ms, built_at, log_dir)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![package_id, outcome, detail, duration_ms, now, log_dir],
        )?;

        debug!(package_id = package_id, outcome = outcome, "Stored build result");
        Ok(())
    }

    /// Store build result by pkgname (compatibility wrapper).
    pub fn store_build_pkgname(&self, pkgname: &str, result: &BuildResult) -> Result<()> {
        if let Some(pkg) = self.get_package_by_name(pkgname)? {
            self.store_build_result(pkg.id, result)
        } else {
            // Package not in scan database - store minimally
            // This can happen during migration or if build runs before scan
            warn!(pkgname = %pkgname, "Package not found in database for build result");
            Ok(())
        }
    }

    /// Store multiple build results in a transaction.
    pub fn store_build_batch(&self, results: &[BuildResult]) -> Result<()> {
        self.conn.execute("BEGIN TRANSACTION", [])?;
        for result in results {
            if let Err(e) = self.store_build_pkgname(result.pkgname.pkgname(), result) {
                let _ = self.conn.execute("ROLLBACK", []);
                return Err(e);
            }
        }
        self.conn.execute("COMMIT", [])?;
        debug!(count = results.len(), "Stored build results batch");
        Ok(())
    }

    /// Get build status for a package.
    pub fn get_build_status(&self, package_id: i64) -> Result<Option<DbBuildOutcome>> {
        let result = self.conn.query_row(
            "SELECT outcome FROM builds WHERE package_id = ?1",
            [package_id],
            |row| row.get::<_, String>(0),
        );

        match result {
            Ok(s) => Ok(DbBuildOutcome::parse(&s)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get all completed package IDs.
    pub fn get_completed_package_ids(&self) -> Result<HashSet<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT package_id FROM builds WHERE outcome IN ('success', 'up_to_date')"
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
        rows.collect::<Result<HashSet<_>, _>>().map_err(Into::into)
    }

    /// Get all failed package IDs.
    pub fn get_failed_package_ids(&self) -> Result<HashSet<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT package_id FROM builds WHERE outcome NOT IN ('success', 'up_to_date')"
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
        rows.collect::<Result<HashSet<_>, _>>().map_err(Into::into)
    }

    /// Load all build results (compatibility wrapper).
    pub fn get_all_build(&self) -> Result<IndexMap<PkgName, BuildResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.pkgname, p.pkgpath, b.outcome, b.outcome_detail, b.duration_ms, b.log_dir
             FROM builds b
             JOIN packages p ON b.package_id = p.id
             ORDER BY b.id"
        )?;

        let mut result = IndexMap::new();
        let rows = stmt.query_map([], |row| {
            let pkgname: String = row.get(0)?;
            let pkgpath: Option<String> = row.get(1)?;
            let outcome: String = row.get(2)?;
            let detail: Option<String> = row.get(3)?;
            let duration_ms: i64 = row.get(4)?;
            let log_dir: Option<String> = row.get(5)?;
            Ok((pkgname, pkgpath, outcome, detail, duration_ms, log_dir))
        })?;

        for row in rows {
            let (pkgname, pkgpath, outcome, detail, duration_ms, log_dir) = row?;
            let build_outcome = db_outcome_to_build(&outcome, detail);
            let build_result = BuildResult {
                pkgname: PkgName::new(&pkgname),
                pkgpath: pkgpath.and_then(|p| PkgPath::new(&p).ok()),
                outcome: build_outcome,
                duration: Duration::from_millis(duration_ms as u64),
                log_dir: log_dir.map(std::path::PathBuf::from),
            };
            result.insert(PkgName::new(&pkgname), build_result);
        }

        Ok(result)
    }

    /// Count of build results.
    pub fn count_build(&self) -> Result<i64> {
        self.conn.query_row("SELECT COUNT(*) FROM builds", [], |row| row.get(0))
            .context("Failed to count builds")
    }

    /// Clear all build data.
    pub fn clear_build(&self) -> Result<()> {
        self.conn.execute("DELETE FROM builds", [])?;
        Ok(())
    }

    /// Delete build result for a pkgname.
    pub fn delete_build_pkgname(&self, pkgname: &str) -> Result<bool> {
        let rows = self.conn.execute(
            "DELETE FROM builds WHERE package_id IN (SELECT id FROM packages WHERE pkgname = ?1)",
            params![pkgname],
        )?;
        Ok(rows > 0)
    }

    /// Delete build results by pkgpath.
    pub fn delete_build_by_pkgpath(&self, pkgpath: &str) -> Result<usize> {
        let rows = self.conn.execute(
            "DELETE FROM builds WHERE package_id IN (SELECT id FROM packages WHERE pkgpath = ?1)",
            params![pkgpath],
        )?;
        Ok(rows)
    }

    /// Mark a package and all its transitive reverse dependencies as failed.
    /// Returns the count of packages marked.
    pub fn mark_failure_cascade(
        &self,
        package_id: i64,
        reason: &str,
        duration: Duration,
    ) -> Result<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let pkgname = self.get_pkgname(package_id)?;

        // Get all affected packages using recursive CTE
        let mut stmt = self.conn.prepare(
            "WITH RECURSIVE affected(id, depth) AS (
                SELECT ?1, 0
                UNION
                SELECT rd.package_id, a.depth + 1
                FROM resolved_depends rd
                JOIN affected a ON rd.depends_on_id = a.id
            )
            SELECT id, depth FROM affected ORDER BY depth"
        )?;

        let affected: Vec<(i64, i32)> = stmt.query_map([package_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i32>(1)?))
        })?.filter_map(|r| r.ok()).collect();

        // Batch insert failures
        self.conn.execute("BEGIN TRANSACTION", [])?;

        for (id, depth) in &affected {
            let (outcome, detail, dur) = if *depth == 0 {
                ("failed", reason.to_string(), duration.as_millis() as i64)
            } else {
                ("indirect_failed", format!("depends on failed {}", pkgname), 0)
            };

            self.conn.execute(
                "INSERT OR REPLACE INTO builds
                 (package_id, outcome, outcome_detail, duration_ms, built_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, outcome, detail, dur, now],
            )?;
        }

        self.conn.execute("COMMIT", [])?;

        debug!(package_id = package_id, affected_count = affected.len(), "Marked failure cascade");
        Ok(affected.len())
    }

    // ========================================================================
    // METADATA
    // ========================================================================

    /// Check if a full tree scan has been completed.
    pub fn full_scan_complete(&self) -> bool {
        self.conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'full_scan_complete'",
                [],
                |row| row.get::<_, String>(0),
            )
            .map(|v| v == "true")
            .unwrap_or(false)
    }

    /// Mark a full tree scan as complete.
    pub fn set_full_scan_complete(&self) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('full_scan_complete', 'true')",
            [],
        )?;
        Ok(())
    }

    /// Clear the full tree scan complete marker.
    pub fn clear_full_scan_complete(&self) -> Result<()> {
        self.conn.execute(
            "DELETE FROM metadata WHERE key = 'full_scan_complete'",
            [],
        )?;
        Ok(())
    }

    /// Store resolved scan result (compatibility).
    pub fn store_resolve(&self, result: &crate::scan::ScanResult) -> Result<()> {
        // Store resolved dependencies
        for (pkgname, index) in &result.buildable {
            if let Some(pkg) = self.get_package_by_name(pkgname.pkgname())? {
                for dep in &index.depends {
                    if let Some(dep_pkg) = self.get_package_by_name(dep.pkgname())? {
                        self.store_resolved_dependency(pkg.id, dep_pkg.id)?;
                    }
                }
            }
        }

        // Store counts for quick access
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('resolve_buildable_count', ?1)",
            params![result.buildable.len().to_string()],
        )?;

        // Store full result as JSON for compatibility during migration
        let json = serde_json::to_string(result)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('resolve_result', ?1)",
            params![json],
        )?;

        debug!("Stored resolve result");
        Ok(())
    }

    /// Get just the buildable count without loading full resolve.
    pub fn get_resolve_buildable_count(&self) -> Result<Option<usize>> {
        let result = self.conn.query_row(
            "SELECT value FROM metadata WHERE key = 'resolve_buildable_count'",
            [],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(s) => Ok(Some(s.parse().unwrap_or(0))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Load cached resolve result.
    pub fn get_resolve(&self) -> Result<Option<crate::scan::ScanResult>> {
        let result = self.conn.query_row(
            "SELECT value FROM metadata WHERE key = 'resolve_result'",
            [],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(json) => {
                let scan_result: crate::scan::ScanResult =
                    serde_json::from_str(&json)
                        .context("Failed to deserialize resolve data")?;
                Ok(Some(scan_result))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Clear cached resolve result.
    pub fn clear_resolve(&self) -> Result<()> {
        self.conn.execute("DELETE FROM metadata WHERE key = 'resolve_result'", [])?;
        self.conn.execute("DELETE FROM metadata WHERE key = 'resolve_buildable_count'", [])?;
        self.clear_resolved_depends()?;
        Ok(())
    }

    // ========================================================================
    // CHANGE DETECTION
    // ========================================================================

    /// Compare requested pkgpaths against cached ones.
    pub fn compare_pkgpath_lists(
        &self,
        requested: &[&str],
    ) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
        let scanned = self.get_scanned_pkgpaths()?;
        let requested_set: HashSet<_> = requested.iter().map(|s| s.to_string()).collect();

        let to_add: Vec<_> = requested_set.difference(&scanned).cloned().collect();
        let to_remove: Vec<_> = scanned.difference(&requested_set).cloned().collect();
        let unchanged: Vec<_> = scanned.intersection(&requested_set).cloned().collect();

        Ok((to_add, to_remove, unchanged))
    }

    /// Delete packages for pkgpaths no longer in the list.
    pub fn delete_pkgpaths(&self, pkgpaths: &[&str]) -> Result<usize> {
        if pkgpaths.is_empty() {
            return Ok(0);
        }

        let mut count = 0;
        for pkgpath in pkgpaths {
            count += self.conn.execute(
                "DELETE FROM packages WHERE pkgpath = ?1",
                [pkgpath],
            )?;
        }
        Ok(count)
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Split pkgname into base and version.
fn split_pkgname(pkgname: &str) -> (String, String) {
    // Find the last dash that's followed by a digit
    let bytes = pkgname.as_bytes();
    for i in (0..bytes.len()).rev() {
        if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            return (
                pkgname[..i].to_string(),
                pkgname[i + 1..].to_string(),
            );
        }
    }
    // No version found
    (pkgname.to_string(), String::new())
}

/// Convert BuildOutcome to database format.
fn build_outcome_to_db(outcome: &crate::build::BuildOutcome) -> (&'static str, Option<String>) {
    use crate::build::BuildOutcome;
    match outcome {
        BuildOutcome::Success => ("success", None),
        BuildOutcome::UpToDate => ("up_to_date", None),
        BuildOutcome::Failed(s) => ("failed", Some(s.clone())),
        BuildOutcome::PreFailed(s) => ("pre_failed", Some(s.clone())),
        BuildOutcome::IndirectFailed(s) => ("indirect_failed", Some(s.clone())),
        BuildOutcome::IndirectPreFailed(s) => ("indirect_pre_failed", Some(s.clone())),
    }
}

/// Convert database format to BuildOutcome.
fn db_outcome_to_build(outcome: &str, detail: Option<String>) -> crate::build::BuildOutcome {
    use crate::build::BuildOutcome;
    match outcome {
        "success" => BuildOutcome::Success,
        "up_to_date" => BuildOutcome::UpToDate,
        "failed" => BuildOutcome::Failed(detail.unwrap_or_default()),
        "pre_failed" => BuildOutcome::PreFailed(detail.unwrap_or_default()),
        "indirect_failed" => BuildOutcome::IndirectFailed(detail.unwrap_or_default()),
        "indirect_pre_failed" => BuildOutcome::IndirectPreFailed(detail.unwrap_or_default()),
        _ => BuildOutcome::Failed(format!("Unknown outcome: {}", outcome)),
    }
}
