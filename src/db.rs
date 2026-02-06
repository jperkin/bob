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
 * SQLite database for caching scan and build results.
 *
 * This module provides optimized database access with:
 * - Lazy loading to minimize memory usage
 * - Indexed reverse dependency lookups for fast failure cascades
 * - Normalized dependency tables for efficient queries
 * - Hybrid storage: columns for hot fields, JSON for cold data
 *
 * # Schema
 *
 * - `packages` - Core package identity and status
 * - `depends` - Raw dependency patterns from scans
 * - `resolved_depends` - Resolved dependencies after pattern matching
 * - `builds` - Build results with indexed outcome
 * - `metadata` - Key-value store for flags and cached data
 */

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use pkgsrc::{PkgName, PkgPath, ScanIndex};
use rusqlite::{Connection, params};
use tracing::{debug, warn};

use crate::build::{BuildOutcome, BuildResult};
use crate::config::PkgsrcEnv;
use crate::try_println;

/**
 * Schema version - update when schema changes.
 */
const SCHEMA_VERSION: i32 = 6;

/**
 * Lightweight package row without full scan data.
 *
 * Use [`Database::get_full_scan_index`] when the complete
 * [`ScanIndex`] is needed.
 */
#[derive(Clone, Debug)]
pub struct PackageRow {
    /// Database row ID.
    pub id: i64,
    /// Package name with version (e.g., `"curl-8.7.1"`).
    pub pkgname: String,
    /// Package path in the pkgsrc tree (e.g., `"www/curl"`).
    pub pkgpath: String,
    /// `PKG_SKIP_REASON` from scan, if set.
    pub skip_reason: Option<String>,
    /// `PKG_FAIL_REASON` from scan, if set.
    pub fail_reason: Option<String>,
    /// Whether this is a bootstrap package.
    pub is_bootstrap: bool,
    /// Build priority weight from `PBULK_WEIGHT`.
    pub pbulk_weight: i32,
    /// `MULTI_VERSION` value, if this package has multiple versions.
    pub multi_version: Option<String>,
}

impl PackageRow {
    /**
     * Construct a PackageRow from a database row.
     */
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            pkgname: row.get(1)?,
            pkgpath: row.get(2)?,
            skip_reason: row.get(3)?,
            fail_reason: row.get(4)?,
            is_bootstrap: row.get::<_, i32>(5)? != 0,
            pbulk_weight: row.get(6)?,
            multi_version: row.get(7)?,
        })
    }
}

/**
 * SQLite database for scan and build caching.
 */
pub struct Database {
    conn: Connection,
}

/**
 * RAII transaction guard that rolls back on drop unless committed.
 */
pub struct TransactionGuard<'a> {
    conn: &'a Connection,
    committed: bool,
}

impl<'a> TransactionGuard<'a> {
    fn new(conn: &'a Connection) -> Result<Self> {
        conn.execute("BEGIN TRANSACTION", [])?;
        Ok(Self {
            conn,
            committed: false,
        })
    }

    /**
     * Commit the transaction.
     */
    pub fn commit(mut self) -> Result<()> {
        self.conn.execute("COMMIT", [])?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for TransactionGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.conn.execute("ROLLBACK", []);
        }
    }
}

impl Database {
    /**
     * Open or create a database at the given path.
     */
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create database directory")?;
        }
        let conn = Connection::open(path).context("Failed to open database")?;
        let db = Self { conn };
        db.configure_pragmas()?;
        db.init()?;
        Ok(db)
    }

    /**
     * Begin a transaction, returning an RAII guard that rolls back on
     * drop unless explicitly committed.
     */
    pub fn transaction(&self) -> Result<TransactionGuard<'_>> {
        TransactionGuard::new(&self.conn)
    }

    /**
     * Configure SQLite for performance.
     */
    fn configure_pragmas(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -64000;
             PRAGMA temp_store = MEMORY;
             PRAGMA mmap_size = 268435456;
             PRAGMA foreign_keys = ON;",
        )?;
        Ok(())
    }

    /**
     * Initialize schema or fail if version mismatch.
     */
    fn init(&self) -> Result<()> {
        // Check if schema_version table exists
        let has_schema_version: bool = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'",
            [],
            |row| row.get::<_, i32>(0).map(|c| c > 0),
        )?;

        if !has_schema_version {
            // Fresh database, create schema
            self.create_schema()?;
        } else {
            // Check version matches
            let version: i32 =
                self.conn
                    .query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
                        row.get(0)
                    })?;

            if version != SCHEMA_VERSION {
                anyhow::bail!(
                    "Schema mismatch: found v{}, expected v{}. \
                     Run 'bob clean' to restart.",
                    version,
                    SCHEMA_VERSION
                );
            }
        }

        Ok(())
    }

    /**
     * Create the database schema.
     */
    fn create_schema(&self) -> Result<()> {
        self.conn.execute_batch(&format!(
            "CREATE TABLE schema_version (version INTEGER NOT NULL);
             INSERT INTO schema_version (version) VALUES ({});

             CREATE TABLE packages (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 pkgname TEXT UNIQUE NOT NULL,
                 pkgpath TEXT NOT NULL,
                 skip_reason TEXT,
                 fail_reason TEXT,
                 build_reason TEXT,
                 is_bootstrap INTEGER DEFAULT 0,
                 pbulk_weight INTEGER DEFAULT 100,
                 scan_data TEXT
             );

             CREATE INDEX idx_packages_pkgpath ON packages(pkgpath);
             CREATE INDEX idx_packages_status ON packages(skip_reason, fail_reason);

             CREATE TABLE depends (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 package_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
                 depend_pattern TEXT NOT NULL,
                 depend_pkgpath TEXT NOT NULL,
                 UNIQUE(package_id, depend_pattern)
             );

             CREATE INDEX idx_depends_package ON depends(package_id);
             CREATE INDEX idx_depends_pkgpath ON depends(depend_pkgpath);

             CREATE TABLE resolved_depends (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 package_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
                 depends_on_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
                 UNIQUE(package_id, depends_on_id)
             );

             CREATE INDEX idx_resolved_depends_package ON resolved_depends(package_id);
             CREATE INDEX idx_resolved_depends_depends_on ON resolved_depends(depends_on_id);

             CREATE TABLE builds (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 package_id INTEGER NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
                 outcome TEXT NOT NULL,
                 outcome_detail TEXT,
                 duration_ms INTEGER NOT NULL DEFAULT 0,
                 log_dir TEXT,
                 UNIQUE(package_id)
             );

             CREATE INDEX idx_builds_outcome ON builds(outcome);
             CREATE INDEX idx_builds_package ON builds(package_id);

             CREATE TABLE metadata (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );",
            SCHEMA_VERSION
        ))?;

        debug!(version = SCHEMA_VERSION, "Created schema");
        Ok(())
    }

    // ========================================================================
    // PACKAGE QUERIES
    // ========================================================================

    /**
     * Store a package from scan results.
     */
    pub fn store_package(&self, pkgpath: &str, index: &ScanIndex) -> Result<i64> {
        let pkgname = index.pkgname.pkgname();

        let skip_reason = index.pkg_skip_reason.as_ref().filter(|s| !s.is_empty());
        let fail_reason = index.pkg_fail_reason.as_ref().filter(|s| !s.is_empty());
        let is_bootstrap = index.bootstrap_pkg.as_deref() == Some("yes");
        let pbulk_weight: i32 = index
            .pbulk_weight
            .as_ref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let scan_data = serde_json::to_string(index)?;

        {
            let mut stmt = self.conn.prepare_cached(
                "INSERT OR REPLACE INTO packages
                 (pkgname, pkgpath, skip_reason, fail_reason,
                  is_bootstrap, pbulk_weight, scan_data)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            stmt.execute(params![
                pkgname,
                pkgpath,
                skip_reason,
                fail_reason,
                is_bootstrap,
                pbulk_weight,
                scan_data
            ])?;
        }

        let package_id = self.conn.last_insert_rowid();

        // Store raw dependencies
        if let Some(ref deps) = index.all_depends {
            let mut stmt = self.conn.prepare_cached(
                "INSERT OR IGNORE INTO depends (package_id, depend_pattern, depend_pkgpath)
                 VALUES (?1, ?2, ?3)",
            )?;
            for dep in deps {
                stmt.execute(params![
                    package_id,
                    dep.pattern().pattern(),
                    dep.pkgpath().to_string()
                ])?;
            }
        }

        debug!(pkgname = pkgname, package_id = package_id, "Stored package");
        Ok(package_id)
    }

    /**
     * Store scan results for a pkgpath.
     */
    pub fn store_scan_pkgpath(&self, pkgpath: &str, indexes: &[ScanIndex]) -> Result<()> {
        for index in indexes {
            self.store_package(pkgpath, index)?;
        }
        Ok(())
    }

    /**
     * Get package by name.
     */
    pub fn get_package_by_name(&self, pkgname: &str) -> Result<Option<PackageRow>> {
        let result = self.conn.query_row(
            "SELECT id, pkgname, pkgpath, skip_reason, fail_reason, is_bootstrap, pbulk_weight,
                    json_extract(scan_data, '$.MULTI_VERSION')
             FROM packages WHERE pkgname = ?1",
            [pkgname],
            PackageRow::from_row,
        );

        match result {
            Ok(pkg) => Ok(Some(pkg)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /**
     * Get package ID by name.
     */
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

    /**
     * Get pkgname by package ID.
     */
    pub fn get_pkgname(&self, package_id: i64) -> Result<String> {
        self.conn
            .query_row(
                "SELECT pkgname FROM packages WHERE id = ?1",
                [package_id],
                |row| row.get(0),
            )
            .context("Package not found")
    }

    /**
     * Get packages by pkgpath.
     */
    pub fn get_packages_by_path(&self, pkgpath: &str) -> Result<Vec<PackageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pkgname, pkgpath, skip_reason, fail_reason, is_bootstrap, pbulk_weight,
                    json_extract(scan_data, '$.MULTI_VERSION')
             FROM packages WHERE pkgpath = ?1",
        )?;

        let rows = stmt.query_map([pkgpath], PackageRow::from_row)?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /**
     * Get all scanned pkgpaths.
     */
    pub fn get_scanned_pkgpaths(&self) -> Result<HashSet<String>> {
        let mut stmt = self.conn.prepare("SELECT DISTINCT pkgpath FROM packages")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<HashSet<_>, _>>().map_err(Into::into)
    }

    /**
     * Get pkgpaths that are referenced as dependencies but haven't been scanned
     * yet. These are dependencies that were discovered during scanning but the
     * scan was interrupted before they could be processed.
     */
    pub fn get_unscanned_dependencies(&self) -> Result<HashSet<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT d.depend_pkgpath
             FROM depends d
             WHERE d.depend_pkgpath NOT IN (SELECT pkgpath FROM packages)",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<HashSet<_>, _>>().map_err(Into::into)
    }

    /**
     * Count of scanned packages.
     */
    pub fn count_packages(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM packages", [], |row| row.get(0))
            .context("Failed to count packages")
    }

    /**
     * Get all packages (lightweight).
     */
    pub fn get_all_packages(&self) -> Result<Vec<PackageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pkgname, pkgpath, skip_reason, fail_reason, is_bootstrap, pbulk_weight,
                    json_extract(scan_data, '$.MULTI_VERSION')
             FROM packages ORDER BY id",
        )?;

        let rows = stmt.query_map([], PackageRow::from_row)?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /**
     * Get all buildable packages (no skip/fail reason).
     */
    pub fn get_buildable_packages(&self) -> Result<Vec<PackageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pkgname, pkgpath, skip_reason, fail_reason, is_bootstrap, pbulk_weight,
                    json_extract(scan_data, '$.MULTI_VERSION')
             FROM packages WHERE skip_reason IS NULL AND fail_reason IS NULL",
        )?;

        let rows = stmt.query_map([], PackageRow::from_row)?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /**
     * Load full ScanIndex for a package.
     */
    pub fn get_full_scan_index(&self, package_id: i64) -> Result<ScanIndex> {
        let json: String = self.conn.query_row(
            "SELECT scan_data FROM packages WHERE id = ?1",
            [package_id],
            |row| row.get(0),
        )?;
        serde_json::from_str(&json).context("Failed to deserialize scan data")
    }

    /**
     * Load all ScanIndex data in one query.
     */
    pub fn get_all_scan_data(&self) -> Result<Vec<ScanIndex>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, scan_data FROM packages ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((id, json))
        })?;
        let mut results = Vec::new();
        for row in rows {
            let (id, json) = row?;
            let index: ScanIndex = serde_json::from_str(&json)
                .with_context(|| format!("Failed to deserialize scan data for package {}", id))?;
            results.push(index);
        }
        Ok(results)
    }

    /**
     * Clear all scan data.
     */
    pub fn clear_scan(&self) -> Result<()> {
        self.conn.execute("DELETE FROM packages", [])?;
        self.clear_full_scan_complete()?;
        Ok(())
    }

    // ========================================================================
    // BUILD REASON QUERIES
    // ========================================================================

    /**
     * Store why a package needs to be built.
     */
    pub fn store_build_reason(&self, pkgname: &str, reason: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE packages SET build_reason = ?1 WHERE pkgname = ?2",
            params![reason, pkgname],
        )?;
        Ok(())
    }

    /**
     * Clear all build reasons (called before re-checking up-to-date status).
     */
    pub fn clear_build_reasons(&self) -> Result<()> {
        self.conn
            .execute("UPDATE packages SET build_reason = NULL", [])?;
        Ok(())
    }

    /**
     * Get build reason for a package by name.
     */
    pub fn get_build_reason(&self, pkgname: &str) -> Result<Option<String>> {
        let result = self.conn.query_row(
            "SELECT build_reason FROM packages WHERE pkgname = ?1",
            [pkgname],
            |row| row.get(0),
        );
        match result {
            Ok(reason) => Ok(reason),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /**
     * Get all packages with their build reasons.
     */
    pub fn get_all_build_reasons(&self) -> Result<HashMap<String, String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT pkgname, build_reason FROM packages WHERE build_reason IS NOT NULL")?;
        let rows = stmt.query_map([], |row| {
            let pkgname: String = row.get(0)?;
            let reason: String = row.get(1)?;
            Ok((pkgname, reason))
        })?;
        let mut result = HashMap::new();
        for row in rows {
            let (pkgname, reason) = row?;
            result.insert(pkgname, reason);
        }
        Ok(result)
    }

    // ========================================================================
    // DEPENDENCY QUERIES
    // ========================================================================

    /**
     * Store resolved dependencies from a ScanSummary.
     */
    pub fn store_resolved_deps(&self, summary: &crate::scan::ScanSummary) -> Result<()> {
        use crate::scan::ScanResult;

        let mut resolved_deps: Vec<(i64, i64)> = Vec::new();
        for pkg in &summary.packages {
            match pkg {
                ScanResult::Buildable(resolved) => {
                    if let Some(pkg_id) = self.get_package_id(resolved.pkgname().pkgname())? {
                        for dep in resolved.depends() {
                            if let Some(dep_id) = self.get_package_id(dep.pkgname())? {
                                resolved_deps.push((pkg_id, dep_id));
                            }
                        }
                    }
                }
                ScanResult::Skipped {
                    index,
                    resolved_depends,
                    ..
                } => {
                    let Some(idx) = index else { continue };
                    if let Some(pkg_id) = self.get_package_id(idx.pkgname.pkgname())? {
                        for dep in resolved_depends {
                            if let Some(dep_id) = self.get_package_id(dep.pkgname())? {
                                resolved_deps.push((pkg_id, dep_id));
                            }
                        }
                    }
                }
                ScanResult::ScanFail { .. } => {}
            }
        }

        if !resolved_deps.is_empty() {
            self.store_resolved_dependencies_batch(&resolved_deps)?;
            debug!(count = resolved_deps.len(), "Stored resolved dependencies");
        }
        Ok(())
    }

    /**
     * Store skipped packages from scan resolution.
     *
     * This persists all skip reasons to the builds table so that queries
     * like `get_blockers` can find them consistently.
     */
    pub fn store_scan_skipped(&self, summary: &crate::scan::ScanSummary) -> Result<()> {
        use crate::scan::ScanResult;

        let tx = self.transaction()?;

        for pkg in &summary.packages {
            if let ScanResult::Skipped { reason, index, .. } = pkg {
                let Some(idx) = index else { continue };
                let pkgname = idx.pkgname.pkgname();

                let Some(pkg_row) = self.get_package_by_name(pkgname)? else {
                    continue;
                };

                let outcome = reason.db_key();
                let detail = reason.to_string();

                self.conn.execute(
                    "INSERT OR IGNORE INTO builds
                     (package_id, outcome, outcome_detail, duration_ms)
                     VALUES (?1, ?2, ?3, 0)",
                    params![pkg_row.id, outcome, detail],
                )?;
            }
        }

        tx.commit()
    }

    /**
     * Store resolved dependencies in batch.
     */
    fn store_resolved_dependencies_batch(&self, deps: &[(i64, i64)]) -> Result<()> {
        let tx = self.transaction()?;
        let mut stmt = self.conn.prepare(
            "INSERT OR IGNORE INTO resolved_depends (package_id, depends_on_id) VALUES (?1, ?2)",
        )?;
        for (package_id, depends_on_id) in deps {
            stmt.execute(params![package_id, depends_on_id])?;
        }
        drop(stmt);
        tx.commit()
    }

    /**
     * Get all transitive reverse dependencies using recursive CTE.
     */
    pub fn get_transitive_reverse_deps(&self, package_id: i64) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            "WITH RECURSIVE affected(id) AS (
                SELECT ?1
                UNION
                SELECT rd.package_id
                FROM resolved_depends rd
                JOIN affected a ON rd.depends_on_id = a.id
            )
            SELECT id FROM affected WHERE id != ?1",
        )?;
        let rows = stmt.query_map([package_id], |row| row.get::<_, i64>(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /**
     * Clear all resolved dependencies.
     */
    pub fn clear_resolved_depends(&self) -> Result<()> {
        self.conn.execute("DELETE FROM resolved_depends", [])?;
        Ok(())
    }

    /**
     * Get all resolved dependencies as a map from pkgname to list of dependency pkgnames.
     */
    pub fn get_all_resolved_deps(&self) -> Result<HashMap<String, Vec<String>>> {
        let mut stmt = self.conn.prepare(
            "SELECT p1.pkgname, p2.pkgname
             FROM resolved_depends rd
             JOIN packages p1 ON rd.package_id = p1.id
             JOIN packages p2 ON rd.depends_on_id = p2.id
             ORDER BY p1.pkgname, p2.pkgname",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut deps: HashMap<String, Vec<String>> = HashMap::new();
        for row in rows {
            let (pkg, dep) = row?;
            deps.entry(pkg).or_default().push(dep);
        }
        Ok(deps)
    }

    // ========================================================================
    // BUILD QUERIES
    // ========================================================================

    /**
     * Store a build result by package ID.
     */
    pub fn store_build_result(&self, package_id: i64, result: &BuildResult) -> Result<()> {
        let outcome = result.outcome.db_key();
        let detail = result.outcome.db_detail();
        let duration_ms = result.duration.as_millis() as i64;
        let log_dir = result.log_dir.as_ref().map(|p| p.display().to_string());

        self.conn.execute(
            "INSERT OR REPLACE INTO builds
             (package_id, outcome, outcome_detail, duration_ms, log_dir)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![package_id, outcome, detail, duration_ms, log_dir],
        )?;

        debug!(
            package_id = package_id,
            outcome = outcome,
            "Stored build result"
        );
        Ok(())
    }

    /**
     * Store a build result by pkgname.
     */
    pub fn store_build_by_name(&self, result: &BuildResult) -> Result<()> {
        if let Some(pkg) = self.get_package_by_name(result.pkgname.pkgname())? {
            self.store_build_result(pkg.id, result)
        } else {
            warn!(pkgname = %result.pkgname.pkgname(), "Package not found in database for build result");
            Ok(())
        }
    }

    /**
     * Get build result for a package.
     */
    pub fn get_build_result(&self, package_id: i64) -> Result<Option<BuildResult>> {
        let result = self.conn.query_row(
            "SELECT p.pkgname, p.pkgpath, b.outcome, b.outcome_detail, b.duration_ms, b.log_dir
             FROM builds b
             JOIN packages p ON b.package_id = p.id
             WHERE b.package_id = ?1",
            [package_id],
            |row| {
                let pkgname: String = row.get(0)?;
                let pkgpath: Option<String> = row.get(1)?;
                let outcome: String = row.get(2)?;
                let detail: Option<String> = row.get(3)?;
                let duration_ms: i64 = row.get(4)?;
                let log_dir: Option<String> = row.get(5)?;
                Ok((pkgname, pkgpath, outcome, detail, duration_ms, log_dir))
            },
        );

        match result {
            Ok((pkgname, pkgpath, outcome, detail, duration_ms, log_dir)) => {
                let Some(build_outcome) = BuildOutcome::from_db(&outcome, detail) else {
                    anyhow::bail!("Unknown build outcome: {}", outcome);
                };
                Ok(Some(BuildResult {
                    pkgname: PkgName::new(&pkgname),
                    pkgpath: pkgpath.and_then(|p| PkgPath::new(&p).ok()),
                    outcome: build_outcome,
                    duration: Duration::from_millis(duration_ms as u64),
                    log_dir: log_dir.map(std::path::PathBuf::from),
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /**
     * Delete build result for a pkgname.
     */
    pub fn delete_build_by_name(&self, pkgname: &str) -> Result<bool> {
        let rows = self.conn.execute(
            "DELETE FROM builds WHERE package_id IN (SELECT id FROM packages WHERE pkgname = ?1)",
            params![pkgname],
        )?;
        Ok(rows > 0)
    }

    /**
     * Delete build results by pkgpath.
     */
    pub fn delete_build_by_pkgpath(&self, pkgpath: &str) -> Result<usize> {
        let rows = self.conn.execute(
            "DELETE FROM builds WHERE package_id IN (SELECT id FROM packages WHERE pkgpath = ?1)",
            params![pkgpath],
        )?;
        Ok(rows)
    }

    /**
     * Clear all build results.
     */
    pub fn clear_builds(&self) -> Result<usize> {
        let rows = self.conn.execute("DELETE FROM builds", [])?;
        Ok(rows)
    }

    /**
     * Get all build results from the database.
     */
    pub fn get_all_build_results(&self) -> Result<Vec<BuildResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.pkgname, p.pkgpath, b.outcome, b.outcome_detail, b.duration_ms, b.log_dir
             FROM builds b
             JOIN packages p ON b.package_id = p.id
             ORDER BY p.pkgname",
        )?;

        let rows = stmt.query_map([], |row| {
            let pkgname: String = row.get(0)?;
            let pkgpath: Option<String> = row.get(1)?;
            let outcome: String = row.get(2)?;
            let detail: Option<String> = row.get(3)?;
            let duration_ms: i64 = row.get(4)?;
            let log_dir: Option<String> = row.get(5)?;
            Ok((pkgname, pkgpath, outcome, detail, duration_ms, log_dir))
        })?;

        let mut results = Vec::new();
        for row in rows {
            let (pkgname, pkgpath, outcome, detail, duration_ms, log_dir) = row?;
            let Some(build_outcome) = BuildOutcome::from_db(&outcome, detail) else {
                continue;
            };
            results.push(BuildResult {
                pkgname: PkgName::new(&pkgname),
                pkgpath: pkgpath.and_then(|p| PkgPath::new(&p).ok()),
                outcome: build_outcome,
                duration: Duration::from_millis(duration_ms as u64),
                log_dir: log_dir.map(std::path::PathBuf::from),
            });
        }

        Ok(results)
    }

    /**
     * Count how many packages are broken by each failed package.
     * Returns a map from pkgname to the count of packages that depend on it.
     */
    pub fn count_breaks_for_failed(&self) -> Result<std::collections::HashMap<String, usize>> {
        use std::collections::HashMap;

        let mut counts: HashMap<String, usize> = HashMap::new();

        // Get all failed package IDs and their names
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.pkgname FROM builds b
             JOIN packages p ON b.package_id = p.id
             WHERE b.outcome = 'failed'",
        )?;

        let failed: Vec<(i64, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();

        // For each failed package, count indirect failures that reference it
        for (_pkg_id, pkgname) in failed {
            let count: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM builds b
                 JOIN packages p ON b.package_id = p.id
                 WHERE b.outcome = 'indirect_failed'
                 AND b.outcome_detail LIKE ?1",
                params![format!("%{}", pkgname)],
                |row| row.get(0),
            )?;
            counts.insert(pkgname, count as usize);
        }

        Ok(counts)
    }

    /**
     * Get total build duration from all builds.
     */
    pub fn get_total_build_duration(&self) -> Result<Duration> {
        let total_ms: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(duration_ms), 0) FROM builds",
            [],
            |row| row.get(0),
        )?;
        Ok(Duration::from_millis(total_ms as u64))
    }

    /**
     * Get blockers for a package - what's preventing it from building.
     * Accepts either pkgname or pkgpath (auto-detected by presence of '/').
     * Returns (pkgname, pkgpath, reason) for each blocking dependency.
     */
    pub fn get_blockers(&self, package: &str) -> Result<Vec<(String, String, String)>> {
        let pkg = if package.contains('/') {
            let pkgs = self.get_packages_by_path(package)?;
            pkgs.into_iter().next()
        } else {
            self.get_package_by_name(package)?
        };

        let Some(pkg) = pkg else {
            anyhow::bail!("Package '{}' not found in database", package);
        };

        let mut stmt = self.conn.prepare(
            "WITH RECURSIVE
             blocking(id, outcome) AS (
                 -- Direct dependencies that have failed/skipped builds
                 SELECT rd.depends_on_id, b.outcome
                 FROM resolved_depends rd
                 JOIN builds b ON b.package_id = rd.depends_on_id
                 WHERE rd.package_id = ?1
                   AND b.outcome NOT IN ('success', 'up_to_date')
                 UNION
                 -- Transitive: deps of deps that are blocked
                 SELECT rd.depends_on_id, b.outcome
                 FROM resolved_depends rd
                 JOIN blocking bl ON rd.package_id = bl.id
                 JOIN builds b ON b.package_id = rd.depends_on_id
                 WHERE b.outcome NOT IN ('success', 'up_to_date')
             )
             SELECT DISTINCT p.pkgname, p.pkgpath, bl.outcome
             FROM blocking bl
             JOIN packages p ON bl.id = p.id
             -- Only show root causes (failed or prefailed/preskipped), not indirect
             WHERE bl.outcome IN ('failed', 'pkg_fail', 'pkg_skip', 'unresolved')
             ORDER BY p.pkgname",
        )?;

        let rows = stmt.query_map([pkg.id], |row| {
            let pkgname: String = row.get(0)?;
            let pkgpath: String = row.get(1)?;
            let outcome: String = row.get(2)?;
            let status = BuildOutcome::from_db(&outcome, None)
                .map(|o| o.status())
                .unwrap_or("unknown");
            Ok((pkgname, pkgpath, status.to_string()))
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /**
     * Get packages blocked by a failed package.
     * Accepts either pkgname or pkgpath (auto-detected by presence of '/').
     * Returns (pkgname, pkgpath) for each blocked package.
     */
    pub fn get_blocked_by(&self, package: &str) -> Result<Vec<(String, String)>> {
        let pkg = if package.contains('/') {
            let pkgs = self.get_packages_by_path(package)?;
            pkgs.into_iter().next()
        } else {
            self.get_package_by_name(package)?
        };

        let Some(pkg) = pkg else {
            anyhow::bail!("Package '{}' not found in database", package);
        };

        let mut stmt = self.conn.prepare(
            "WITH RECURSIVE
             affected(id) AS (
                 -- Direct reverse dependencies
                 SELECT rd.package_id
                 FROM resolved_depends rd
                 WHERE rd.depends_on_id = ?1
                 UNION
                 -- Transitive reverse dependencies
                 SELECT rd.package_id
                 FROM resolved_depends rd
                 JOIN affected a ON rd.depends_on_id = a.id
             )
             SELECT p.pkgname, p.pkgpath
             FROM affected a
             JOIN packages p ON a.id = p.id
             ORDER BY p.pkgname",
        )?;

        let rows = stmt.query_map([pkg.id], |row| Ok((row.get(0)?, row.get(1)?)))?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /**
     * Get pre-failed packages (those with skip_reason or fail_reason but no
     * build result). Returns (pkgname, pkgpath, reason).
     */
    pub fn get_prefailed_packages(&self) -> Result<Vec<(String, Option<String>, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.pkgname, p.pkgpath,
                    COALESCE(p.fail_reason, p.skip_reason) as reason
             FROM packages p
             WHERE (p.skip_reason IS NOT NULL OR p.fail_reason IS NOT NULL)
               AND NOT EXISTS (SELECT 1 FROM builds b WHERE b.package_id = p.id)
             ORDER BY p.pkgname",
        )?;

        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /**
     * Get packages without build results that depend on failed packages.
     * Returns (pkgname, pkgpath, failed_deps) where failed_deps is
     * comma-separated. Excludes packages that have skip_reason or fail_reason
     * (they're pre-failed). Only lists root failures (direct failures), not
     * indirect failures.
     */
    pub fn get_indirect_failures(&self) -> Result<Vec<(String, Option<String>, String)>> {
        // Find packages that:
        // 1. Have no build result
        // 2. Have no skip_reason or fail_reason (not pre-failed)
        // 3. Depend (transitively) on a package with a direct failure
        // Group by package and aggregate failed deps into comma-separated string
        // Only 'failed' and 'pkg_fail' are root causes, not 'indirect_*'
        let mut stmt = self.conn.prepare(
            "WITH RECURSIVE
             -- Only direct failures are root causes
             failed_pkgs(id) AS (
                 SELECT package_id FROM builds
                 WHERE outcome IN ('failed', 'pkg_fail')
             ),
             -- Packages affected by failures (transitive closure)
             affected(id, root_id) AS (
                 SELECT id, id FROM failed_pkgs
                 UNION
                 SELECT rd.package_id, a.root_id
                 FROM resolved_depends rd
                 JOIN affected a ON rd.depends_on_id = a.id
                 WHERE rd.package_id NOT IN (SELECT id FROM failed_pkgs)
             )
             SELECT p.pkgname, p.pkgpath, GROUP_CONCAT(DISTINCT fp.pkgname) as failed_deps
             FROM affected a
             JOIN packages p ON a.id = p.id
             JOIN packages fp ON a.root_id = fp.id
             WHERE a.id != a.root_id
               AND NOT EXISTS (SELECT 1 FROM builds b WHERE b.package_id = a.id)
               AND p.skip_reason IS NULL
               AND p.fail_reason IS NULL
             GROUP BY p.id, p.pkgname, p.pkgpath
             ORDER BY p.pkgname",
        )?;

        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /**
     * Mark a package and all its transitive reverse dependencies as failed.
     * Returns the count of packages marked.
     */
    pub fn mark_failure_cascade(
        &self,
        package_id: i64,
        reason: &str,
        duration: Duration,
    ) -> Result<usize> {
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
            SELECT id, depth FROM affected ORDER BY depth",
        )?;

        let affected: Vec<(i64, i32)> = stmt
            .query_map([package_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i32>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();

        // Batch insert failures
        let tx = self.transaction()?;

        for (id, depth) in &affected {
            let (outcome, detail, dur) = if *depth == 0 {
                ("failed", reason.to_string(), duration.as_millis() as i64)
            } else {
                (
                    "indirect_failed",
                    format!("depends on failed {}", pkgname),
                    0,
                )
            };

            self.conn.execute(
                "INSERT OR REPLACE INTO builds
                 (package_id, outcome, outcome_detail, duration_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![id, outcome, detail, dur],
            )?;
        }

        tx.commit()?;

        debug!(
            package_id = package_id,
            affected_count = affected.len(),
            "Marked failure cascade"
        );
        Ok(affected.len())
    }

    // ========================================================================
    // METADATA
    // ========================================================================

    /**
     * Check if a full tree scan has been completed.
     */
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

    /**
     * Mark a full tree scan as complete.
     */
    pub fn set_full_scan_complete(&self) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('full_scan_complete', 'true')",
            [],
        )?;
        Ok(())
    }

    /**
     * Clear the full tree scan complete marker.
     */
    pub fn clear_full_scan_complete(&self) -> Result<()> {
        self.conn
            .execute("DELETE FROM metadata WHERE key = 'full_scan_complete'", [])?;
        Ok(())
    }

    /**
     * Store the pkgsrc environment to the database.  Errors if already present
     * as this should only ever be done once.
     */
    pub fn store_pkgsrc_env(&self, env: &PkgsrcEnv) -> Result<()> {
        let json = serde_json::json!({
            "packages": env.packages,
            "pkgtools": env.pkgtools,
            "prefix": env.prefix,
            "pkg_dbdir": env.pkg_dbdir,
            "pkg_refcount_dbdir": env.pkg_refcount_dbdir,
            "cachevars": env.cachevars,
        });
        self.conn.execute(
            "INSERT INTO metadata (key, value) VALUES ('pkgsrc_env', ?1)",
            params![json.to_string()],
        )?;
        Ok(())
    }

    /**
     * Load the pkgsrc environment from the database.
     */
    pub fn load_pkgsrc_env(&self) -> Result<PkgsrcEnv> {
        let json_str: String = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'pkgsrc_env'",
                [],
                |row| row.get(0),
            )
            .context("pkgsrc environment not found in database")?;

        let json: serde_json::Value =
            serde_json::from_str(&json_str).context("Invalid pkgsrc_env JSON")?;

        let get_path = |key: &str| -> Result<PathBuf> {
            json.get(key)
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .ok_or_else(|| anyhow::anyhow!("Missing {} in pkgsrc_env", key))
        };

        let cachevars: HashMap<String, String> = json
            .get("cachevars")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        Ok(PkgsrcEnv {
            packages: get_path("packages")?,
            pkgtools: get_path("pkgtools")?,
            prefix: get_path("prefix")?,
            pkg_dbdir: get_path("pkg_dbdir")?,
            pkg_refcount_dbdir: get_path("pkg_refcount_dbdir")?,
            cachevars,
        })
    }

    /**
     * Get all package names with failed build outcomes.
     */
    pub fn get_failed_packages(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.pkgname FROM builds b
             JOIN packages p ON b.package_id = p.id
             WHERE b.outcome = 'failed'
             ORDER BY p.pkgname",
        )?;

        let pkgnames = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(pkgnames)
    }

    /**
     * Get all package names with successful build outcomes.
     */
    pub fn get_successful_packages(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.pkgname FROM builds b
             JOIN packages p ON b.package_id = p.id
             WHERE b.outcome IN ('success', 'up_to_date')
             ORDER BY p.pkgname",
        )?;

        let pkgnames = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(pkgnames)
    }

    /**
     * Execute arbitrary SQL and print results.
     */
    pub fn execute_raw(&self, sql: &str) -> Result<()> {
        let mut stmt = self.conn.prepare(sql)?;
        let column_count = stmt.column_count();

        if column_count == 0 {
            // Non-query statement (INSERT, UPDATE, DELETE, etc.)
            let affected = stmt.execute([])?;
            if affected > 0 {
                println!("{} row(s) affected", affected);
            }
        } else {
            // Query statement (SELECT, PRAGMA, etc.)
            let mut rows = stmt.query([])?;

            while let Some(row) = rows.next()? {
                let values: Vec<String> = (0..column_count)
                    .map(|i| {
                        row.get_ref(i)
                            .map(|v| match v {
                                rusqlite::types::ValueRef::Null => String::new(),
                                rusqlite::types::ValueRef::Integer(i) => i.to_string(),
                                rusqlite::types::ValueRef::Real(f) => f.to_string(),
                                rusqlite::types::ValueRef::Text(s) => {
                                    String::from_utf8_lossy(s).to_string()
                                }
                                rusqlite::types::ValueRef::Blob(b) => {
                                    format!("<blob:{} bytes>", b.len())
                                }
                            })
                            .unwrap_or_default()
                    })
                    .collect();
                if !try_println(&values.join("|")) {
                    break;
                }
            }
        }

        Ok(())
    }
}
