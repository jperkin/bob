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
 * - `scan_index` - `ScanIndex` data, one row per package, columns verbatim
 *   from the `pkgsrc::ScanIndex` struct
 * - `package_state` - bob's per-package state (selected, build_reason)
 * - `resolved_depends` - Resolved dependencies after pattern matching
 * - `builds` - Build results with indexed outcome
 * - `metadata` - Key-value store for flags and cached data
 */

use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use indexmap::IndexMap;
use pkgsrc::{AllDepends, BootstrapPkg, MakeJobsSafe, PkgName, PkgPath, ScanDepends, ScanIndex};
use rusqlite::{Connection, params};
use tracing::{debug, warn};

use strum::VariantArray;

use crate::build::{BuildResult, PkgBuildStats, Stage};
use crate::config::PkgsrcEnv;
use crate::scan::ScanResult;
use crate::try_println;
use crate::{HistoryKind, PackageState};

/// Row type for [`Database::get_report_data`]:
/// (pkgname, scan_index, outcome_id).
pub type ReportRow = (String, ScanIndex, Option<i32>);

/**
 * `(pkgpath, pkgbase)` -- the identity key for matching
 * `build_history` rows across builds.  Code that joins, diffs, or
 * correlates history between builds must key on this pair, never on
 * `pkgname`.  Within a single build, use [`latest_history_partition`]
 * for the canonical `ROW_NUMBER()` window.
 */
pub type PkgKey = (String, String);

/**
 * SQL fragment for the `ROW_NUMBER()` partition that selects the
 * latest `build_history` row per [`PkgKey`].
 *
 * Use as `ROW_NUMBER() OVER ({clause}) AS rn` inside a CTE, then
 * filter `WHERE rn = 1`; always select `pkgpath` and `pkgbase` from
 * the same partition so the result map can be keyed by [`PkgKey`].
 */
pub fn latest_history_partition() -> String {
    let pkgpath: &str = HistoryKind::Pkgpath.into();
    let pkgbase: &str = HistoryKind::Pkgbase.into();
    format!("PARTITION BY {pkgpath}, {pkgbase} ORDER BY id DESC")
}

fn stage_values() -> String {
    Stage::VARIANTS
        .iter()
        .map(|v| format!("({}, '{}')", *v as i32, v.into_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

/**
 * SQL VALUES list seeding the `outcome_types` lookup table.  `Pending`
 * is the implicit default and is not persisted, so it is excluded.
 */
fn outcome_values() -> String {
    PackageState::VARIANTS
        .iter()
        .filter(|k| **k != PackageState::Pending)
        .map(|k| format!("({}, '{}')", k.id(), k.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

/**
 * Generate `build_history` column definitions from [`HistoryKind`].
 *
 * SQL types and foreign key constraints live here because they are
 * properties of the database schema, not of the history types.
 */
fn history_schema() -> String {
    use strum::VariantArray;
    HistoryKind::VARIANTS
        .iter()
        .map(|v| {
            let name: &str = v.into();
            let sql = match v {
                HistoryKind::Pkgpath | HistoryKind::Pkgname | HistoryKind::Pkgbase => {
                    "TEXT NOT NULL"
                }
                HistoryKind::Outcome => "INTEGER NOT NULL REFERENCES outcome_types(id)",
                HistoryKind::Stage => "INTEGER REFERENCES stage_types(id)",
                HistoryKind::Duration | HistoryKind::Timestamp => "INTEGER NOT NULL",
                HistoryKind::MakeJobs => "INTEGER",
                HistoryKind::DiskUsage => "INTEGER",
                HistoryKind::Wrkobjdir => "TEXT",
                HistoryKind::BuildId => "TEXT",
            };
            format!("{name} {sql}")
        })
        .collect::<Vec<_>>()
        .join(",\n                 ")
}

/**
 * Schema version for bob.db - update when schema changes.
 */
const SCHEMA_VERSION: i32 = 20260604;

/**
 * Schema version for history.db - update when history schema changes.
 */
const HISTORY_SCHEMA_VERSION: i32 = 20260609;

/**
 * Summary of a package's most recent build from history.
 */
#[derive(Clone, Debug)]
pub struct PkgBuildHistory {
    /// Build outcome.
    pub outcome: PackageState,
    /// Disk usage in bytes, if recorded.
    pub disk_usage: Option<u64>,
    /// MAKE_JOBS used, if recorded.
    pub make_jobs: Option<u32>,
    /// WRKOBJDIR type used (raw "tmpfs"/"disk" string from the
    /// history column), if recorded.
    pub wrkobjdir: Option<String>,
}

/**
 * Lightweight package row without full scan data.
 *
 * Use [`Database::get_full_scan_index`] when the complete
 * [`ScanIndex`] is needed.
 */
#[derive(Clone, Debug, serde::Deserialize)]
pub struct PackageRow {
    /// Database row ID.
    pub id: i64,
    /// Package name with version (e.g., `"curl-8.7.1"`).
    pub pkgname: String,
    /// Package path in the pkgsrc tree (e.g., `"www/curl"`).
    pub pkg_location: String,
    /// `MULTI_VERSION` value, if this package has multiple versions.
    pub multi_version: Option<String>,
}

/**
 * Package data combined with build status.
 *
 * Returned by [`Database::get_all_package_status`] which fetches
 * package metadata and build results in a single query.
 */
#[derive(Clone, Debug, serde::Deserialize)]
pub struct PackageStatusRow {
    pub id: i64,
    pub pkgname: String,
    pub pkg_location: String,
    pub pkg_skip_reason: Option<String>,
    pub pkg_fail_reason: Option<String>,
    pub build_reason: Option<String>,
    pub multi_version: Option<String>,
    pub build_outcome: Option<i32>,
    pub build_stage: Option<i32>,
    pub scan_outcome: Option<i32>,
    pub scan_outcome_detail: Option<String>,
}

fn build_result_from_row(row: &rusqlite::Row) -> rusqlite::Result<Option<BuildResult>> {
    let Ok(state) = PackageState::try_from(row.get::<_, i32>("outcome")?) else {
        return Ok(None);
    };
    Ok(Some(BuildResult {
        pkgname: PkgName::new(&row.get::<_, String>("pkgname")?),
        pkgpath: row
            .get::<_, Option<String>>("pkgpath")?
            .and_then(|p| PkgPath::new(&p).ok()),
        state,
        log_dir: row.get::<_, Option<String>>("log_dir")?.map(PathBuf::from),
        build_stats: PkgBuildStats {
            stage: row
                .get::<_, Option<i32>>("stage")?
                .and_then(Stage::from_repr),
            duration: Duration::from_millis(row.get::<_, i64>("duration_ms")? as u64),
            ..PkgBuildStats::default()
        },
    }))
}

/**
 * SQLite database for scan, build, and history data.
 *
 * The history connection is opened lazily on first use, so commands
 * that don't touch history (e.g. `bob scan`) never create `history.db`.
 */
pub struct Database {
    conn: Connection,
    dbdir: PathBuf,
    history_conn: OnceCell<Connection>,
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
     * Open or create the database in the given directory.
     *
     * Opens `bob.db` (scan/build cache) immediately. The history
     * connection to `history.db` is opened lazily on first use.
     */
    pub fn open(dbdir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dbdir).context("Failed to create database directory")?;

        let conn = Connection::open(dbdir.join("bob.db")).context("Failed to open database")?;
        let db = Self {
            conn,
            dbdir: dbdir.to_path_buf(),
            history_conn: OnceCell::new(),
        };
        db.configure_pragmas()?;
        db.init()?;
        Ok(db)
    }

    pub fn dbdir(&self) -> &Path {
        &self.dbdir
    }

    /** Borrow the underlying database connection. */
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /**
     * Run a query and deserialize every row into `T` via
     * [`serde_rusqlite`].  Columns are matched to fields by name, so
     * `SELECT *` works for any struct whose fields are a subset of the
     * table's columns.
     */
    fn query_rows<T, P>(&self, sql: &str, params: P) -> Result<Vec<T>>
    where
        T: for<'de> serde::Deserialize<'de>,
        P: rusqlite::Params,
    {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query(params)?;
        Ok(serde_rusqlite::from_rows::<T>(rows).collect::<Result<_, _>>()?)
    }

    /**
     * Run a query expected to return at most one row.
     */
    fn query_one<T, P>(&self, sql: &str, params: P) -> Result<Option<T>>
    where
        T: for<'de> serde::Deserialize<'de>,
        P: rusqlite::Params,
    {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query(params)?;
        Ok(serde_rusqlite::from_rows::<T>(rows).next().transpose()?)
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
             PRAGMA temp_store = MEMORY;
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

        check_history_schema(&self.dbdir)?;

        Ok(())
    }

    /**
     * Create the database schema.
     */
    fn create_schema(&self) -> Result<()> {
        self.conn.execute_batch(&format!(
            "CREATE TABLE schema_version (version INTEGER NOT NULL) STRICT;
             INSERT INTO schema_version (version) VALUES ({});

             CREATE TABLE outcome_types (
                 id INTEGER PRIMARY KEY,
                 name TEXT UNIQUE NOT NULL
             ) STRICT;
             INSERT INTO outcome_types (id, name) VALUES {outcome_types};

             CREATE TABLE stage_types (
                 id INTEGER PRIMARY KEY,
                 name TEXT UNIQUE NOT NULL
             ) STRICT;
             INSERT INTO stage_types (id, name) VALUES {stages};

             CREATE TABLE scan_index (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 pkgname TEXT UNIQUE NOT NULL,
                 pkg_location TEXT NOT NULL,
                 all_depends TEXT,
                 pkg_skip_reason TEXT,
                 pkg_fail_reason TEXT,
                 no_bin_on_ftp TEXT,
                 restricted TEXT,
                 categories TEXT,
                 maintainer TEXT,
                 use_destdir TEXT,
                 bootstrap_pkg INTEGER,
                 usergroup_phase TEXT,
                 scan_depends TEXT,
                 make_jobs_safe INTEGER,
                 pbulk_weight INTEGER,
                 multi_version TEXT
             ) STRICT;

             CREATE INDEX idx_scan_index_pkg_location ON scan_index(pkg_location);

             CREATE TABLE package_state (
                 package_id INTEGER PRIMARY KEY
                     REFERENCES scan_index(id) ON DELETE CASCADE,
                 selected INTEGER NOT NULL DEFAULT 0,
                 build_reason TEXT
             ) STRICT;

             CREATE TABLE resolved_depends (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 package_id INTEGER NOT NULL REFERENCES scan_index(id) ON DELETE CASCADE,
                 depends_on_id INTEGER NOT NULL REFERENCES scan_index(id) ON DELETE CASCADE,
                 UNIQUE(package_id, depends_on_id)
             ) STRICT;

             CREATE INDEX idx_resolved_depends_package ON resolved_depends(package_id);
             CREATE INDEX idx_resolved_depends_depends_on ON resolved_depends(depends_on_id);

             CREATE TABLE builds (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 package_id INTEGER NOT NULL REFERENCES scan_index(id) ON DELETE CASCADE,
                 outcome INTEGER NOT NULL REFERENCES outcome_types(id),
                 stage INTEGER REFERENCES stage_types(id),
                 duration_ms INTEGER NOT NULL DEFAULT 0,
                 log_dir TEXT,
                 UNIQUE(package_id)
             ) STRICT;

             CREATE INDEX idx_builds_outcome ON builds(outcome);
             CREATE INDEX idx_builds_package ON builds(package_id);

             CREATE TABLE scan_outcomes (
                 package_id INTEGER PRIMARY KEY
                     REFERENCES scan_index(id) ON DELETE CASCADE,
                 outcome INTEGER NOT NULL REFERENCES outcome_types(id),
                 detail TEXT
             ) STRICT;

             CREATE INDEX idx_scan_outcomes_outcome ON scan_outcomes(outcome);

             CREATE VIEW buildable AS
                 SELECT p.*
                 FROM scan_index p
                 JOIN package_state s
                     ON s.package_id = p.id AND s.selected = 1
                 WHERE NOT EXISTS (
                     SELECT 1 FROM scan_outcomes o WHERE o.package_id = p.id
                 );

             CREATE TABLE scan_failures (
                 pkgpath TEXT PRIMARY KEY,
                 error TEXT NOT NULL
             ) STRICT;

             CREATE TABLE metadata (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             ) STRICT;",
            SCHEMA_VERSION,
            outcome_types = outcome_values(),
            stages = stage_values(),
        ))?;

        let build_id = chrono::Utc::now()
            .format(crate::BUILD_ID_FORMAT)
            .to_string();
        self.conn.execute(
            "INSERT INTO metadata (key, value) VALUES ('build_id', ?1)",
            params![build_id],
        )?;

        debug!(version = SCHEMA_VERSION, build_id = %build_id, "Created schema");
        Ok(())
    }

    // ========================================================================
    // PACKAGE QUERIES
    // ========================================================================

    /**
     * Store a package from scan results.
     *
     * Duplicate PKGNAMEs are dropped by the unique index (first occurrence
     * wins), which is the single point that keeps scan_index canonical for
     * every writer.
     */
    pub fn store_package(&self, pkgpath: &str, index: &ScanIndex) -> Result<()> {
        let pkgname = index.pkgname.pkgname();
        let skip_reason = index.pkg_skip_reason.as_deref().filter(|s| !s.is_empty());
        let fail_reason = index.pkg_fail_reason.as_deref().filter(|s| !s.is_empty());
        let all_depends = index.all_depends.as_ref().map(|d| d.as_str());
        let multi_version = index.multi_version.as_ref().map(|v| v.join(" "));

        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO scan_index
             (pkgname, pkg_location, all_depends,
              pkg_skip_reason, pkg_fail_reason, no_bin_on_ftp,
              restricted, categories, maintainer, use_destdir,
              bootstrap_pkg, usergroup_phase, scan_depends,
              make_jobs_safe, pbulk_weight, multi_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                     ?11, ?12, ?13, ?14, ?15, ?16)
             ON CONFLICT(pkgname) DO NOTHING",
        )?;
        let inserted = stmt.execute(params![
            pkgname,
            pkgpath,
            all_depends,
            skip_reason,
            fail_reason,
            index.no_bin_on_ftp,
            index.restricted,
            index.categories,
            index.maintainer,
            index.use_destdir,
            index.bootstrap_pkg.as_ref().map(BootstrapPkg::is_bootstrap),
            index.usergroup_phase,
            index.scan_depends.as_ref().map(|d| d.as_str()),
            index.make_jobs_safe.as_ref().map(MakeJobsSafe::is_safe),
            index.pbulk_weight,
            multi_version,
        ])?;
        drop(stmt);

        if inserted == 0 {
            debug!(pkgname = pkgname, "Skipping duplicate pkgname");
            return Ok(());
        }

        let package_id = self.conn.last_insert_rowid();
        self.conn.execute(
            "INSERT OR IGNORE INTO package_state (package_id) VALUES (?1)",
            params![package_id],
        )?;

        debug!(pkgname = pkgname, package_id = package_id, "Stored package");
        Ok(())
    }

    /**
     * Store scan results for a pkgpath in their own transaction.
     *
     * Committing per pkgpath keeps completed results durable as the scan
     * streams, instead of buffering them in one long-lived transaction.
     */
    pub fn store_scan_pkgpath(&self, pkgpath: &str, indexes: &[ScanIndex]) -> Result<()> {
        let tx = self.transaction()?;
        for index in indexes {
            self.store_package(pkgpath, index)?;
        }
        tx.commit()?;
        Ok(())
    }

    /**
     * Get package by name.
     */
    pub fn get_package_by_name(&self, pkgname: &str) -> Result<Option<PackageRow>> {
        self.query_one("SELECT * FROM scan_index WHERE pkgname = ?1", [pkgname])
    }

    /**
     * Get pkgname by package ID.
     */
    pub fn get_pkgname(&self, package_id: i64) -> Result<String> {
        self.conn
            .query_row(
                "SELECT pkgname FROM scan_index WHERE id = ?1",
                [package_id],
                |row| row.get(0),
            )
            .context("Package not found")
    }

    /**
     * Get packages by pkgpath.
     */
    pub fn get_packages_by_path(&self, pkgpath: &str) -> Result<Vec<PackageRow>> {
        self.query_rows(
            "SELECT * FROM scan_index WHERE pkg_location = ?1",
            [pkgpath],
        )
    }

    /**
     * Get all scanned pkgpaths.
     */
    pub fn get_scanned_pkgpaths(&self) -> Result<HashSet<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT pkg_location FROM scan_index")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<HashSet<_>, _>>().map_err(Into::into)
    }

    /**
     * Get pkgpaths that are referenced as dependencies but haven't been scanned
     * yet. These are dependencies that were discovered during scanning but the
     * scan was interrupted before they could be processed.
     */
    pub fn get_unscanned_dependencies(&self) -> Result<HashSet<String>> {
        let scanned = self.get_scanned_pkgpaths()?;
        let mut stmt = self
            .conn
            .prepare("SELECT all_depends FROM scan_index WHERE all_depends IS NOT NULL")?;
        let mut rows = stmt.query([])?;
        let mut unscanned = HashSet::new();
        while let Some(row) = rows.next()? {
            let raw: String = row.get(0)?;
            let deps = AllDepends::from(raw.as_str());
            for entry in deps.iter().flatten() {
                let pkgpath: String = entry.pkgpath().to_string();
                if !scanned.contains(&pkgpath) {
                    unscanned.insert(pkgpath);
                }
            }
        }
        Ok(unscanned)
    }

    /**
     * Count of scanned packages.
     */
    pub fn count_packages(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM scan_index", [], |row| row.get(0))
            .context("Failed to count packages")
    }

    /**
     * Get all packages (lightweight).
     */
    pub fn get_all_packages(&self) -> Result<Vec<PackageRow>> {
        self.query_rows("SELECT * FROM scan_index ORDER BY id", [])
    }

    /**
     * Get all package data with build results in a single query.
     *
     * Combines packages, build outcomes, and build reasons into one
     * LEFT JOIN, avoiding multiple round-trips.
     */
    pub fn get_all_package_status(&self) -> Result<Vec<PackageStatusRow>> {
        self.query_rows(
            "SELECT p.id, p.pkgname, p.pkg_location,
                    p.pkg_skip_reason, p.pkg_fail_reason, p.multi_version,
                    s.build_reason,
                    b.outcome AS build_outcome, b.stage AS build_stage,
                    o.outcome AS scan_outcome, o.detail AS scan_outcome_detail
             FROM scan_index p
             JOIN package_state s ON s.package_id = p.id
             LEFT JOIN builds b ON b.package_id = p.id
             LEFT JOIN scan_outcomes o ON o.package_id = p.id
             WHERE s.selected = 1",
            [],
        )
    }

    fn scan_index_from_row(row: &rusqlite::Row) -> rusqlite::Result<ScanIndex> {
        Ok(ScanIndex {
            pkgname: row.get::<_, String>("pkgname")?.into(),
            pkg_location: row
                .get::<_, Option<String>>("pkg_location")?
                .and_then(|s| s.parse().ok()),
            all_depends: row
                .get::<_, Option<String>>("all_depends")?
                .map(|s| AllDepends::from(s.as_str())),
            pkg_skip_reason: row.get("pkg_skip_reason")?,
            pkg_fail_reason: row.get("pkg_fail_reason")?,
            no_bin_on_ftp: row.get("no_bin_on_ftp")?,
            restricted: row.get("restricted")?,
            categories: row.get("categories")?,
            maintainer: row.get("maintainer")?,
            use_destdir: row.get("use_destdir")?,
            bootstrap_pkg: row
                .get::<_, Option<bool>>("bootstrap_pkg")?
                .map(BootstrapPkg::from),
            usergroup_phase: row.get("usergroup_phase")?,
            scan_depends: row
                .get::<_, Option<String>>("scan_depends")?
                .map(|s| ScanDepends::from(s.as_str())),
            make_jobs_safe: row
                .get::<_, Option<bool>>("make_jobs_safe")?
                .map(MakeJobsSafe::from),
            pbulk_weight: row.get("pbulk_weight")?,
            multi_version: row
                .get::<_, Option<String>>("multi_version")?
                .map(|s| s.split_ascii_whitespace().map(str::to_string).collect()),
            resolved_depends: None,
        })
    }

    /**
     * Load full ScanIndex for a package.
     */
    pub fn get_full_scan_index(&self, package_id: i64) -> Result<ScanIndex> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT * FROM scan_index WHERE id = ?1")?;
        let mut rows = stmt.query([package_id])?;
        let row = rows
            .next()?
            .ok_or_else(|| anyhow::anyhow!("Package {package_id} not found"))?;
        Self::scan_index_from_row(row).map_err(Into::into)
    }

    /**
     * Stream ScanIndex rows to a caller-supplied scope without buffering
     * the full result set.
     */
    pub fn with_scan_data<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut dyn FnMut() -> Result<Option<ScanIndex>>) -> Result<R>,
    {
        let mut stmt = self.conn.prepare("SELECT * FROM scan_index ORDER BY id")?;
        let mut rows = stmt.query([])?;
        let mut pull = || -> Result<Option<ScanIndex>> {
            let Some(row) = rows.next()? else {
                return Ok(None);
            };
            let id: i64 = row.get("id")?;
            let index = Self::scan_index_from_row(row)
                .with_context(|| format!("Failed to read package {id}"))?;
            Ok(Some(index))
        };
        f(&mut pull)
    }

    /**
     * Clear all scan data.
     */
    pub fn clear_scan(&self) -> Result<()> {
        self.conn.execute("DELETE FROM scan_index", [])?;
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
            "UPDATE package_state SET build_reason = ?1
             WHERE package_id = (SELECT id FROM scan_index WHERE pkgname = ?2)",
            params![reason, pkgname],
        )?;
        Ok(())
    }

    /**
     * Clear all build reasons (called before re-checking up-to-date status).
     */
    pub fn clear_build_reasons(&self) -> Result<()> {
        self.conn
            .execute("UPDATE package_state SET build_reason = NULL", [])?;
        Ok(())
    }

    // ========================================================================
    // DEPENDENCY QUERIES
    // ========================================================================

    /**
     * Store resolved dependencies from a ScanSummary.
     */
    pub fn store_resolved_deps(&self, summary: &crate::scan::ScanSummary) -> Result<()> {
        let id_map: HashMap<String, i64> = self
            .conn
            .prepare("SELECT pkgname, id FROM scan_index")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;

        let tx = self.transaction()?;
        let mut stmt = self.conn.prepare(
            "INSERT OR IGNORE INTO resolved_depends (package_id, depends_on_id) VALUES (?1, ?2)",
        )?;
        let mut count: usize = 0;
        for pkg in &summary.packages {
            let Some(pkgname) = pkg.pkgname() else {
                continue;
            };
            let Some(&pkg_id) = id_map.get(pkgname.pkgname()) else {
                continue;
            };
            for dep in pkg.depends() {
                if let Some(&dep_id) = id_map.get(dep.pkgname()) {
                    stmt.execute(params![pkg_id, dep_id])?;
                    count += 1;
                }
            }
        }
        drop(stmt);
        tx.commit()?;
        if count > 0 {
            debug!(count, "Stored resolved dependencies");
        }
        Ok(())
    }

    /**
     * Record the resolution outcome for every skipped package.
     */
    pub fn store_scan_skipped(&self, summary: &crate::scan::ScanSummary) -> Result<()> {
        let tx = self.transaction()?;
        let mut stmt = self.conn.prepare(
            "INSERT OR REPLACE INTO scan_outcomes (package_id, outcome, detail)
             SELECT id, ?1, ?2 FROM scan_index WHERE pkgname = ?3",
        )?;
        for pkg in &summary.packages {
            if let ScanResult::Skipped {
                state,
                index,
                reason,
                ..
            } = pkg
            {
                let Some(idx) = index else { continue };
                stmt.execute(params![state.id(), reason, idx.pkgname.pkgname()])?;
            }
        }
        drop(stmt);
        tx.commit()
    }

    /**
     * Mark which scanned packages participated in the latest resolution.
     *
     * Scan results may cache additional package rows that are not part of the
     * current resolved package set. Status/scheduling queries should ignore
     * those rows and only operate on the packages emitted by the most recent
     * resolve step.
     */
    /**
     * Store scan failures in the database.
     */
    pub fn store_scan_failures(&self, summary: &crate::scan::ScanSummary) -> Result<()> {
        self.conn.execute("DELETE FROM scan_failures", [])?;
        let mut stmt = self
            .conn
            .prepare("INSERT INTO scan_failures (pkgpath, error) VALUES (?1, ?2)")?;
        for pkg in &summary.packages {
            if let ScanResult::ScanFail { pkgpath, error } = pkg {
                stmt.execute(params![pkgpath.as_path().display().to_string(), error])?;
            }
        }
        Ok(())
    }

    /**
     * Load scan failures from the database.
     */
    pub fn get_scan_failures(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT pkgpath, error FROM scan_failures ORDER BY pkgpath")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn store_resolved_selection(&self, summary: &crate::scan::ScanSummary) -> Result<()> {
        let tx = self.transaction()?;
        self.conn
            .execute("UPDATE package_state SET selected = 0", [])?;
        let mut stmt = self.conn.prepare(
            "UPDATE package_state SET selected = 1
             WHERE package_id = (SELECT id FROM scan_index WHERE pkgname = ?1)",
        )?;
        for pkg in &summary.packages {
            let Some(pkgname) = pkg.pkgname() else {
                continue;
            };
            stmt.execute([pkgname.pkgname()])?;
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
    pub fn get_all_resolved_deps(&self) -> Result<HashMap<PkgName, Vec<PkgName>>> {
        let mut stmt = self.conn.prepare(
            "SELECT p1.pkgname, p2.pkgname
             FROM resolved_depends rd
             JOIN scan_index p1 ON rd.package_id = p1.id
             JOIN scan_index p2 ON rd.depends_on_id = p2.id
             ORDER BY p1.pkgname, p2.pkgname",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                PkgName::from(row.get::<_, String>(0)?),
                PkgName::from(row.get::<_, String>(1)?),
            ))
        })?;

        let mut deps: HashMap<PkgName, Vec<PkgName>> = HashMap::new();
        for row in rows {
            let (pkg, dep) = row?;
            deps.entry(pkg).or_default().push(dep);
        }
        Ok(deps)
    }

    /**
     * The buildable packages in build order: those that passed scanning
     * with no skip, fail, or unresolved outcome.  Dependencies are not
     * attached; the resolved dependency graph is owned by the scheduler's
     * package table.  See
     * [`get_buildable_pkgpaths`](Self::get_buildable_pkgpaths) for the same
     * set as a plain `pkgname` -> `pkgpath` map.
     */
    pub fn get_buildable_packages(
        &self,
    ) -> Result<IndexMap<PkgName, crate::scan::ResolvedPackage>> {
        let mut stmt = self.conn.prepare(
            "SELECT pkgname, pkg_location, bootstrap_pkg, usergroup_phase, multi_version
             FROM buildable
             ORDER BY id",
        )?;
        let mut out = IndexMap::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let pkgname: String = row.get("pkgname")?;
            let pkg_location: String = row.get("pkg_location")?;
            let multi_version = row
                .get::<_, Option<String>>("multi_version")?
                .map(|s| s.split_ascii_whitespace().map(str::to_string).collect());
            out.insert(
                pkgname.clone().into(),
                crate::scan::ResolvedPackage {
                    pkgpath: pkg_location.parse()?,
                    index: ScanIndex {
                        pkgname: pkgname.into(),
                        bootstrap_pkg: row
                            .get::<_, Option<bool>>("bootstrap_pkg")?
                            .map(BootstrapPkg::from),
                        usergroup_phase: row.get("usergroup_phase")?,
                        multi_version,
                        ..Default::default()
                    },
                },
            );
        }
        Ok(out)
    }

    /**
     * The buildable packages as a `pkgname` -> `pkgpath` map: the same set
     * as [`get_buildable_packages`](Self::get_buildable_packages), but
     * without resolving dependencies.
     */
    pub fn get_buildable_pkgpaths(&self) -> Result<HashMap<PkgName, PkgPath>> {
        let mut stmt = self
            .conn
            .prepare("SELECT pkgname, pkg_location FROM buildable")?;
        let mut out = HashMap::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let pkgname: String = row.get(0)?;
            let pkg_location: String = row.get(1)?;
            out.insert(pkgname.into(), pkg_location.parse()?);
        }
        Ok(out)
    }

    // ========================================================================
    // BUILD QUERIES
    // ========================================================================

    /**
     * Store a build result by package ID.
     */
    pub fn store_build_result(&self, package_id: i64, result: &BuildResult) -> Result<()> {
        let outcome = result.state.id();
        let stage = result.build_stats.stage.map(|s| s as i32);
        let duration_ms = result.build_stats.duration.as_millis() as i64;
        let log_dir = result.log_dir.as_ref().map(|p| p.display().to_string());

        self.conn.execute(
            "INSERT OR REPLACE INTO builds
             (package_id, outcome, stage, duration_ms, log_dir)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![package_id, outcome, stage, duration_ms, log_dir],
        )?;

        debug!(
            package_id = package_id,
            outcome = outcome,
            "Stored build result"
        );
        Ok(())
    }

    /**
     * Check if a package has a successful build result.
     */
    pub fn is_successful(&self, pkgname: &str) -> Result<bool> {
        let success = PackageState::Success.id();
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM builds b
             JOIN scan_index p ON b.package_id = p.id
             WHERE p.pkgname = ?1 AND b.outcome = ?2",
            params![pkgname, success],
            |row| row.get::<_, i64>(0),
        )? > 0)
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
        let mut stmt = self.conn.prepare(
            "SELECT p.pkgname, p.pkg_location AS pkgpath,
                    b.outcome,
                    b.stage, b.duration_ms, b.log_dir
             FROM builds b
             JOIN scan_index p ON b.package_id = p.id
             WHERE b.package_id = ?1",
        )?;
        let mut rows = stmt.query([package_id])?;
        match rows.next()? {
            Some(row) => Ok(build_result_from_row(row)?),
            None => Ok(None),
        }
    }

    /**
     * Delete build result for a pkgname.
     */
    pub fn delete_build_by_name(&self, pkgname: &str) -> Result<bool> {
        let rows = self.conn.execute(
            "DELETE FROM builds WHERE package_id IN (SELECT id FROM scan_index WHERE pkgname = ?1)",
            params![pkgname],
        )?;
        Ok(rows > 0)
    }

    /**
     * Delete build results by pkgpath.
     */
    pub fn delete_build_by_pkgpath(&self, pkgpath: &str) -> Result<usize> {
        let rows = self.conn.execute(
            "DELETE FROM builds WHERE package_id IN (SELECT id FROM scan_index WHERE pkg_location = ?1)",
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
            "SELECT p.pkgname, p.pkg_location AS pkgpath,
                    b.outcome,
                    b.stage, b.duration_ms, b.log_dir
             FROM builds b
             JOIN scan_index p ON b.package_id = p.id
             ORDER BY p.pkgname",
        )?;

        let mut rows = stmt.query([])?;
        let mut results = Vec::new();
        while let Some(row) = rows.next()? {
            if let Some(r) = build_result_from_row(row)? {
                results.push(r);
            }
        }
        Ok(results)
    }

    /**
     * Add to the wall clock duration of the current build.
     *
     * Accumulates across build and rebuild invocations so the
     * report shows total wall clock time, not per-invocation.
     */
    pub fn add_build_duration(&self, duration: Duration) -> Result<()> {
        let build_id = self.build_id()?;
        let conn = self.history_conn()?;
        conn.execute(
            "INSERT INTO build_metadata (build_id, duration_ms) VALUES (?1, ?2) \
             ON CONFLICT(build_id) DO UPDATE SET duration_ms = duration_ms + excluded.duration_ms",
            params![build_id, duration.as_millis() as i64],
        )?;
        Ok(())
    }

    /**
     * Get the accumulated wall clock build duration.
     */
    pub fn get_build_duration(&self) -> Result<Duration> {
        let build_id = self.build_id()?;
        let conn = self.history_conn()?;
        let ms: i64 = conn.query_row(
            "SELECT COALESCE( \
                 (SELECT duration_ms FROM build_metadata WHERE build_id = ?1), \
                 0 \
             )",
            params![build_id],
            |row| row.get(0),
        )?;
        Ok(Duration::from_millis(ms as u64))
    }

    /**
     * Get blockers for a package - what's preventing it from building.
     * Returns (pkgname, pkgpath, reason) for each blocking dependency.
     */
    pub fn get_blockers(&self, package_id: i64) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self.conn.prepare(
            "WITH RECURSIVE
             blocking(id, outcome) AS (
                 -- Direct dependencies that have failed/skipped builds
                 SELECT rd.depends_on_id, b.outcome
                 FROM resolved_depends rd
                 JOIN builds b ON b.package_id = rd.depends_on_id
                 WHERE rd.package_id = ?1
                   AND b.outcome NOT IN (?2, ?3)
                 UNION
                 -- Transitive: deps of deps that are blocked
                 SELECT rd.depends_on_id, b.outcome
                 FROM resolved_depends rd
                 JOIN blocking bl ON rd.package_id = bl.id
                 JOIN builds b ON b.package_id = rd.depends_on_id
                 WHERE b.outcome NOT IN (?2, ?3)
             )
             SELECT DISTINCT p.pkgname, p.pkg_location, bl.outcome
             FROM blocking bl
             JOIN scan_index p ON bl.id = p.id
             -- Only show root causes (failed or prefailed/preskipped), not indirect
             WHERE bl.outcome IN (?4, ?5, ?6, ?7)
             ORDER BY p.pkgname",
        )?;

        let rows = stmt.query_map(
            params![
                package_id,
                PackageState::Success.id(),
                PackageState::UpToDate.id(),
                PackageState::Failed.id(),
                PackageState::PreFailed.id(),
                PackageState::PreSkipped.id(),
                PackageState::Unresolved.id(),
            ],
            |row| {
                let pkgname: String = row.get(0)?;
                let pkgpath: String = row.get(1)?;
                let outcome_id: i32 = row.get(2)?;
                let kind = PackageState::try_from(outcome_id).map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Integer,
                        format!("unknown outcome type id: {}", outcome_id).into(),
                    )
                })?;
                let status = kind.as_str();
                Ok((pkgname, pkgpath, status.to_string()))
            },
        )?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /**
     * Get packages blocked by a failed package.
     * Returns (pkgname, pkgpath) for each blocked package.
     */
    pub fn get_blocked_by(&self, package_id: i64) -> Result<Vec<(String, String)>> {
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
             SELECT p.pkgname, p.pkg_location
             FROM affected a
             JOIN scan_index p ON a.id = p.id
             ORDER BY p.pkgname",
        )?;

        let rows = stmt.query_map([package_id], |row| Ok((row.get(0)?, row.get(1)?)))?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /**
     * Packages blocked at scan time (pre-skipped, pre-failed, unresolved,
     * or an indirect propagation of one), as [`BuildResult`]s carrying
     * only the outcome.  They never reached the build, so there is no log
     * or timing.  Counted and reported alongside the real build results.
     */
    pub fn get_scan_outcomes(&self) -> Result<Vec<BuildResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.pkgname, p.pkg_location, o.outcome
             FROM scan_outcomes o
             JOIN scan_index p ON o.package_id = p.id
             ORDER BY p.pkgname",
        )?;
        let rows = stmt.query_map([], |row| {
            let outcome: i32 = row.get("outcome")?;
            let state = PackageState::try_from(outcome).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Integer,
                    e.into(),
                )
            })?;
            Ok(BuildResult {
                pkgname: PkgName::new(&row.get::<_, String>("pkgname")?),
                pkgpath: row
                    .get::<_, Option<String>>("pkg_location")?
                    .and_then(|p| PkgPath::new(&p).ok()),
                state,
                log_dir: None,
                build_stats: PkgBuildStats::default(),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /**
     * `(pkgpath, reason)` for every unresolved package that recorded a
     * reason.  Feeds the report's scan-failures section alongside
     * [`get_scan_failures`](Self::get_scan_failures).
     */
    pub fn get_unresolved_reasons(&self) -> Result<Vec<(PkgPath, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.pkg_location, o.detail
             FROM scan_outcomes o
             JOIN scan_index p ON o.package_id = p.id
             WHERE o.outcome = ?1 AND o.detail IS NOT NULL
             ORDER BY p.pkgname",
        )?;
        let rows = stmt.query_map([PackageState::Unresolved.id()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (location, reason) = row?;
            out.push((PkgPath::new(&location)?, reason));
        }
        Ok(out)
    }

    /**
     * For every blocked package, the packages blocking it (those that
     * failed to build, or were pre-skipped, pre-failed, or unresolved at
     * scan), ordered by how many packages each blocks.
     */
    pub fn blockers(&self) -> Result<HashMap<String, Vec<String>>> {
        let mut stmt = self.conn.prepare(
            "WITH RECURSIVE
             blockers(id) AS (
                 SELECT package_id FROM builds WHERE outcome = ?1
                 UNION
                 SELECT package_id FROM scan_outcomes WHERE outcome IN (?2, ?3, ?4)
             ),
             affected(id, blocker_id) AS (
                 SELECT id, id FROM blockers
                 UNION
                 SELECT rd.package_id, a.blocker_id
                 FROM resolved_depends rd
                 JOIN affected a ON rd.depends_on_id = a.id
                 WHERE rd.package_id NOT IN (SELECT id FROM blockers)
             ),
             impact(blocker_id, n) AS (
                 SELECT blocker_id, COUNT(*) FROM affected WHERE id != blocker_id GROUP BY blocker_id
             )
             SELECT p.pkgname, bp.pkgname
             FROM affected a
             JOIN scan_index p ON a.id = p.id
             JOIN scan_index bp ON a.blocker_id = bp.id
             JOIN impact i ON i.blocker_id = a.blocker_id
             WHERE a.id != a.blocker_id
             ORDER BY i.n DESC, bp.pkgname",
        )?;
        let rows = stmt.query_map(
            params![
                PackageState::Failed.id(),
                PackageState::PreSkipped.id(),
                PackageState::PreFailed.id(),
                PackageState::Unresolved.id(),
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for row in rows {
            let (pkgname, blocker) = row?;
            map.entry(pkgname).or_default().push(blocker);
        }
        Ok(map)
    }

    // ========================================================================
    // METADATA
    // ========================================================================

    /**
     * Get the build ID for this run.
     *
     * The build ID is an ISO timestamp set when the database is first
     * created, and persists across rebuilds until `bob clean`.
     */
    pub fn build_id(&self) -> Result<String> {
        self.conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'build_id'",
                [],
                |row| row.get(0),
            )
            .context("build_id not found in database")
    }

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
            "metadata": env.metadata,
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

        let metadata: HashMap<String, String> = json
            .get("metadata")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

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
            metadata,
            cachevars,
        })
    }

    /**
     * Store version control information in the database.
     */
    pub fn store_vcs_info(&self, info: &crate::vcs::VcsInfo) -> Result<()> {
        let json = serde_json::to_string(info)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('vcs_info', ?1)",
            params![json],
        )?;
        Ok(())
    }

    /**
     * Load version control information from the database.
     */
    pub fn load_vcs_info(&self) -> Result<crate::vcs::VcsInfo> {
        let json_str: String = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'vcs_info'",
                [],
                |row| row.get(0),
            )
            .context("vcs_info not found in database")?;
        serde_json::from_str(&json_str).context("Invalid vcs_info JSON")
    }

    /**
     * Get all package names with failed build outcomes.
     */
    pub fn get_failed_packages(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.pkgname FROM builds b
             JOIN scan_index p ON b.package_id = p.id
             WHERE b.outcome = ?1
             ORDER BY p.pkgname",
        )?;

        let pkgnames = stmt
            .query_map([PackageState::Failed.id()], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(pkgnames)
    }

    /**
     * Get all package names with successful build outcomes.
     */
    pub fn get_successful_packages(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.pkgname FROM builds b
             JOIN scan_index p ON b.package_id = p.id
             WHERE b.outcome IN (?1, ?2)
             ORDER BY p.pkgname",
        )?;

        let pkgnames = stmt
            .query_map(
                params![PackageState::Success.id(), PackageState::UpToDate.id(),],
                |row| row.get::<_, String>(0),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(pkgnames)
    }

    /**
     * Get the set of restricted package names.
     *
     * Returns packages that have NO_BIN_ON_FTP set.  Packages that
     * depend on restricted packages are not themselves restricted --
     * users can build the restricted packages locally and still use
     * the published dependents.
     */
    pub fn get_restricted_packages(&self) -> Result<HashMap<String, String>> {
        let mut stmt = self.conn.prepare(
            "SELECT pkgname, no_bin_on_ftp FROM scan_index
             WHERE no_bin_on_ftp IS NOT NULL AND no_bin_on_ftp != ''",
        )?;
        let restricted = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<HashMap<_, _>, _>>()?;

        Ok(restricted)
    }

    /**
     * Get all packages with their scan data and build status for
     * reporting.  Returns `(pkgname, scan_index, outcome_id)` rows
     * ordered by pkgname.
     */
    pub fn get_report_data(&self) -> Result<Vec<ReportRow>> {
        let resolved = self.get_all_resolved_deps()?;
        let mut stmt = self.conn.prepare(
            "SELECT p.*,
                    COALESCE(b.outcome, o.outcome) AS outcome
             FROM scan_index p
             LEFT JOIN builds b ON b.package_id = p.id
             LEFT JOIN scan_outcomes o ON o.package_id = p.id
             ORDER BY p.pkgname",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let pkgname: String = row.get("pkgname")?;
            let outcome: Option<i32> = row.get("outcome")?;
            let mut index = Self::scan_index_from_row(row)?;
            if let Some(deps) = resolved.get(pkgname.as_str()) {
                index.resolved_depends = Some(deps.clone());
            }
            out.push((pkgname, index, outcome));
        }
        Ok(out)
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

    // ========================================================================
    // BUILD HISTORY
    // ========================================================================

    /**
     * Get the history database connection, opening it on first use.
     */
    pub(crate) fn history_conn(&self) -> Result<&Connection> {
        if let Some(conn) = self.history_conn.get() {
            return Ok(conn);
        }
        let conn = open_history_conn(&self.dbdir)?;
        let _ = self.history_conn.set(conn);
        self.history_conn
            .get()
            .ok_or_else(|| anyhow::anyhow!("history connection not initialized"))
    }

    /**
     * Record a build in the history database.
     */
    pub fn record_history(&self, rec: &crate::History) -> Result<()> {
        let conn = self.history_conn()?;
        record_history_to(conn, rec)
    }

    /**
     * Query build history, optionally filtering by regex on pkgpath
     * or pkgname. Results are returned most recent first.  Defaults
     * to Success and Failed outcomes only; `all = true` returns
     * every recorded outcome including UpToDate and masked rows.
     */
    pub fn query_history(
        &self,
        patterns: &[regex::Regex],
        all: bool,
    ) -> Result<Vec<crate::History>> {
        let conn = self.history_conn()?;
        let cols: String = HistoryKind::VARIANTS
            .iter()
            .map(|v| format!("bh.{}", <&str>::from(v)))
            .collect::<Vec<_>>()
            .join(", ");
        let where_clause = if all {
            String::new()
        } else {
            format!(
                "WHERE bh.outcome IN ({success}, {failed})",
                success = PackageState::Success.id(),
                failed = PackageState::Failed.id(),
            )
        };
        let sql = format!(
            "SELECT bh.id, {cols}, \
                    wt.stage, wt.duration, ct.duration \
             FROM build_history bh \
             LEFT JOIN wall_times wt ON wt.history_id = bh.id \
             LEFT JOIN cpu_times ct ON ct.history_id = bh.id \
                                   AND ct.stage = wt.stage \
             {where_clause} \
             ORDER BY bh.timestamp DESC, bh.id DESC",
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i32>(5)?,
                row.get::<_, Option<i32>>(6)?,
                row.get::<_, Option<i64>>(7)?.map(|v| v as usize),
                row.get::<_, i64>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<i32>>(12)?,
                row.get::<_, Option<i64>>(13)?,
                row.get::<_, Option<i64>>(14)?,
            ))
        })?;

        let mut results: Vec<crate::History> = Vec::new();
        let mut current_id: Option<i64> = None;
        let mut current_accepted = false;
        for row in rows {
            let (
                id,
                timestamp,
                pkgpath,
                pkgname,
                pkgbase,
                outcome_id,
                stage_id,
                make_jobs,
                duration,
                disk_usage,
                wrkobjdir,
                build_id,
                wt_stage,
                wt_duration,
                ct_duration,
            ) = row?;

            if Some(id) == current_id {
                if current_accepted
                    && let Some(last) = results.last_mut()
                    && let Some(stage_id) = wt_stage
                {
                    let stage = Stage::from_repr(stage_id)
                        .ok_or_else(|| anyhow::anyhow!("Unknown stage id: {}", stage_id))?;
                    if let Some(ms) = wt_duration {
                        last.stage_durations
                            .push((stage, Duration::from_millis(ms as u64)));
                    }
                    if let Some(ms) = ct_duration {
                        last.stage_cpu_times
                            .push((stage, Duration::from_millis(ms as u64)));
                    }
                }
                continue;
            }

            current_id = Some(id);
            current_accepted = false;

            if !patterns.is_empty()
                && !patterns
                    .iter()
                    .any(|re| re.is_match(&pkgpath) || re.is_match(&pkgname))
            {
                continue;
            }

            current_accepted = true;
            let outcome = PackageState::try_from(outcome_id)
                .map_err(|_| anyhow::anyhow!("Unknown outcome type id: {}", outcome_id))?;
            let stage = stage_id
                .map(|id| {
                    Stage::from_repr(id).ok_or_else(|| anyhow::anyhow!("Unknown stage id: {}", id))
                })
                .transpose()?;

            let mut stage_durations = Vec::new();
            let mut stage_cpu_times = Vec::new();
            if let Some(st_id) = wt_stage {
                let st = Stage::from_repr(st_id)
                    .ok_or_else(|| anyhow::anyhow!("Unknown stage id: {}", st_id))?;
                if let Some(ms) = wt_duration {
                    stage_durations.push((st, Duration::from_millis(ms as u64)));
                }
                if let Some(ms) = ct_duration {
                    stage_cpu_times.push((st, Duration::from_millis(ms as u64)));
                }
            }

            results.push(crate::History {
                timestamp,
                pkgpath,
                pkgname,
                pkgbase,
                outcome,
                stage,
                make_jobs,
                duration: Duration::from_millis(duration as u64),
                disk_usage: disk_usage.map(|s| s as u64),
                wrkobjdir: wrkobjdir.and_then(|s| s.parse().ok()),
                stage_durations,
                stage_cpu_times,
                build_id,
            });
        }

        Ok(results)
    }

    /**
     * Query build history for all packages.
     *
     * For each [`PkgKey`] returns the outcome, MAKE_JOBS, WRKOBJDIR,
     * and disk usage from the most recent matching row.  When
     * `build_id` is `Some`, only rows from that build session are
     * considered; when `None`, all history is searched.  Returns an
     * empty map on error.
     */
    pub fn build_history_by_pkg_all(
        &self,
        build_id: Option<&str>,
    ) -> HashMap<PkgKey, PkgBuildHistory> {
        let conn = match self.history_conn() {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    "build_history_by_pkg_all: failed to open history db"
                );
                return HashMap::new();
            }
        };

        let du: &str = HistoryKind::DiskUsage.into();
        let out: &str = HistoryKind::Outcome.into();
        let mj: &str = HistoryKind::MakeJobs.into();
        let wo: &str = HistoryKind::Wrkobjdir.into();
        let pkgbase_col: &str = HistoryKind::Pkgbase.into();
        let pkgpath_col: &str = HistoryKind::Pkgpath.into();
        let partition = latest_history_partition();
        let up_to_date = PackageState::UpToDate.id();

        /*
         * UpToDate rows are markers; they carry no disk_usage,
         * make_jobs, or wrkobjdir.  Exclude them so the latest row per
         * package is the most recent real build measurement.
         */
        let where_clause = if build_id.is_some() {
            format!("WHERE h.build_id = ?1 AND h.{out} != {up_to_date}")
        } else {
            format!("WHERE h.{out} != {up_to_date}")
        };

        let sql = format!(
            "WITH latest AS ( \
                 SELECT h.{pkgpath_col}, h.{pkgbase_col}, \
                        h.{du}, h.{out}, h.{mj}, h.{wo}, \
                        ROW_NUMBER() OVER ({partition}) AS rn \
                 FROM build_history h \
                 {where_clause} \
             ) \
             SELECT {pkgpath_col}, {pkgbase_col}, {out}, {du}, {mj}, {wo} \
             FROM latest WHERE rn = 1",
        );

        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    "build_history_by_pkg_all: failed to prepare query"
                );
                return HashMap::new();
            }
        };
        let map_row = |row: &rusqlite::Row<'_>| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i32>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        };
        let rows = match build_id {
            Some(id) => stmt.query_map(params![id], map_row),
            None => stmt.query_map([], map_row),
        };
        let rows = match rows {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    "build_history_by_pkg_all: query failed"
                );
                return HashMap::new();
            }
        };

        let mut result = HashMap::new();
        for row in rows.flatten() {
            let (pkgpath, pkgbase, outcome, du, mj, wo) = row;
            let outcome = match PackageState::try_from(outcome) {
                Ok(k) => k,
                Err(e) => {
                    warn!(error = e, "build_history_by_pkg_all: skipping row");
                    continue;
                }
            };
            result.insert(
                (pkgpath, pkgbase),
                PkgBuildHistory {
                    outcome,
                    disk_usage: du.map(|v| v as u64),
                    make_jobs: mj.map(|v| v as u32),
                    wrkobjdir: wo,
                },
            );
        }
        result
    }

    /**
     * Write CPU usage samples to the `cpu_usage` table in history.db.
     */
    pub fn store_cpu_usage(&self, samples: &[crate::cpu::CpuSample]) -> Result<()> {
        if samples.is_empty() {
            return Ok(());
        }
        let conn = self.history_conn()?;
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO cpu_usage (timestamp, user_pct, sys_pct) \
                 VALUES (?1, ?2, ?3)",
            )?;
            for s in samples {
                stmt.execute(params![s.timestamp, s.user_pct as i32, s.sys_pct as i32])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /**
     * List all build IDs in history, most recent first.
     *
     * Succeeded/failed/masked counts come from `build_history`;
     * `UpToDate` rows in `build_history` (present for builds run
     * after schema v20260515) are excluded from the masked bucket
     * because the canonical up-to-date count lives on
     * `build_metadata.up_to_date`, which also covers older builds
     * that never wrote per-package up-to-date rows.
     */
    pub fn list_history_builds(&self) -> Result<Vec<BuildListEntry>> {
        let conn = self.history_conn()?;
        let success = PackageState::Success.id();
        let failed = PackageState::Failed.id();
        let up_to_date = PackageState::UpToDate.id();
        let mut stmt = conn.prepare(
            "WITH attempted AS ( \
                 SELECT build_id, \
                        SUM(CASE WHEN outcome = ?1 THEN 1 ELSE 0 END) AS succeeded, \
                        SUM(CASE WHEN outcome = ?2 THEN 1 ELSE 0 END) AS failed, \
                        SUM(CASE WHEN outcome NOT IN (?1, ?2, ?3) THEN 1 ELSE 0 END) AS masked \
                 FROM build_history \
                 WHERE build_id IS NOT NULL \
                 GROUP BY build_id \
             ), \
             all_builds AS ( \
                 SELECT build_id FROM attempted \
                 UNION \
                 SELECT build_id FROM build_metadata \
             ) \
             SELECT b.build_id, \
                    COALESCE(a.succeeded, 0) + COALESCE(a.failed, 0) \
                        + COALESCE(a.masked, 0) + COALESCE(m.up_to_date, 0), \
                    COALESCE(a.succeeded, 0), \
                    COALESCE(m.up_to_date, 0), \
                    COALESCE(a.failed, 0), \
                    COALESCE(a.masked, 0), \
                    COALESCE(m.duration_ms, 0) \
             FROM all_builds b \
             LEFT JOIN attempted a ON a.build_id = b.build_id \
             LEFT JOIN build_metadata m ON m.build_id = b.build_id \
             ORDER BY b.build_id DESC",
        )?;
        let rows = stmt.query_map(params![success, failed, up_to_date], |row| {
            Ok(BuildListEntry {
                build_id: row.get(0)?,
                package_count: row.get::<_, i64>(1)? as usize,
                succeeded: row.get::<_, i64>(2)? as usize,
                up_to_date: row.get::<_, i64>(3)? as usize,
                failed: row.get::<_, i64>(4)? as usize,
                masked: row.get::<_, i64>(5)? as usize,
                duration_ms: row.get::<_, i64>(6)? as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .context("Failed to list history builds")
    }

    /**
     * Delete the listed build_ids from `build_history` and
     * `build_metadata`, then `VACUUM` to reclaim space.  Cascaded
     * deletes via FK clean up `wall_times` and `cpu_times`.  No-op if
     * `build_ids` is empty.
     */
    pub fn prune_builds(&self, build_ids: &[String]) -> Result<()> {
        if build_ids.is_empty() {
            return Ok(());
        }
        let conn = self.history_conn()?;
        let tx = conn.unchecked_transaction()?;
        {
            let mut hist = tx.prepare("DELETE FROM build_history WHERE build_id = ?1")?;
            let mut meta = tx.prepare("DELETE FROM build_metadata WHERE build_id = ?1")?;
            for id in build_ids {
                hist.execute([id])?;
                meta.execute([id])?;
            }
        }
        tx.commit()?;
        conn.execute_batch("VACUUM")?;
        Ok(())
    }

    /**
     * Store VCS revision for a build in the history database.
     */
    pub fn store_build_revision(&self, build_id: &str, revision: &str) -> Result<()> {
        let conn = self.history_conn()?;
        conn.execute(
            "INSERT INTO build_metadata (build_id, revision) VALUES (?1, ?2) \
             ON CONFLICT(build_id) DO UPDATE SET revision = excluded.revision",
            params![build_id, revision],
        )?;
        Ok(())
    }

    /**
     * Record the up-to-date package count for a build.
     */
    pub fn record_up_to_date_count(&self, build_id: &str, count: usize) -> Result<()> {
        let conn = self.history_conn()?;
        conn.execute(
            "INSERT INTO build_metadata (build_id, up_to_date) VALUES (?1, ?2) \
             ON CONFLICT(build_id) DO UPDATE SET up_to_date = excluded.up_to_date",
            params![build_id, count as i64],
        )?;
        Ok(())
    }

    /**
     * Get the VCS revision for a build from the history database.
     */
    pub fn get_build_revision(&self, build_id: &str) -> Result<Option<String>> {
        let conn = self.history_conn()?;
        match conn.query_row(
            "SELECT revision FROM build_metadata WHERE build_id = ?1",
            [build_id],
            |row| row.get(0),
        ) {
            Ok(rev) => Ok(Some(rev)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /**
     * Compute the diff between two builds.
     *
     * Returns categorised changes: new failures, fixes, added/removed
     * packages, version changes, and other outcome transitions.
     */
    pub fn compute_build_diff(&self, build1_id: &str, build2_id: &str) -> Result<BuildDiff> {
        let conn = self.history_conn()?;

        struct PkgRecord {
            pkgname: String,
            outcome: i32,
            stage: Option<i32>,
        }
        let sql = "SELECT pkgpath, pkgbase, pkgname, outcome, stage \
                   FROM build_history WHERE build_id = ?1";
        let query_build = |bid: &str| -> Result<HashMap<PkgKey, PkgRecord>> {
            let mut stmt = conn.prepare(sql)?;
            let mut map = HashMap::new();
            let rows = stmt.query_map([bid], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i32>(3)?,
                    row.get::<_, Option<i32>>(4)?,
                ))
            })?;
            for row in rows {
                let (pkgpath, pkgbase, pkgname, outcome, stage) = row?;
                map.insert(
                    (pkgpath, pkgbase),
                    PkgRecord {
                        pkgname,
                        outcome,
                        stage,
                    },
                );
            }
            Ok(map)
        };

        let b1 = query_build(build1_id)?;
        let b2 = query_build(build2_id)?;

        let mut diff = BuildDiff {
            build1_id: build1_id.to_string(),
            build2_id: build2_id.to_string(),
            new_failures: Vec::new(),
            fixes: Vec::new(),
            version_changes: Vec::new(),
            other_changes: Vec::new(),
        };

        use PackageState::*;

        for ((pkgpath, pkgbase), b2_rec) in &b2 {
            let b2_outcome = PackageState::try_from(b2_rec.outcome).ok();
            let b2_stage = b2_rec.stage.and_then(Stage::from_repr);

            let entry_from = |b1_rec: Option<&PkgRecord>| DiffEntry {
                pkgpath: pkgpath.clone(),
                build1_pkgname: b1_rec.map(|r| r.pkgname.clone()),
                build2_pkgname: Some(b2_rec.pkgname.clone()),
                build1_outcome: b1_rec.and_then(|r| PackageState::try_from(r.outcome).ok()),
                build2_outcome: b2_outcome,
                build1_stage: b1_rec.and_then(|r| r.stage.and_then(Stage::from_repr)),
                build2_stage: b2_stage,
            };

            match b1.get(&(pkgpath.clone(), pkgbase.clone())) {
                Some(b1_rec) => {
                    let b1_outcome = PackageState::try_from(b1_rec.outcome).ok();
                    let b1_stage = b1_rec.stage.and_then(Stage::from_repr);
                    let pkgname_changed = b1_rec.pkgname != b2_rec.pkgname;
                    let both_ok = matches!(
                        (b1_outcome, b2_outcome),
                        (Some(Success | UpToDate), Some(Success | UpToDate))
                    );
                    let no_change = if both_ok {
                        !pkgname_changed
                    } else {
                        b1_outcome == b2_outcome && b1_stage == b2_stage && !pkgname_changed
                    };
                    if no_change {
                        continue;
                    }
                    let entry = entry_from(Some(b1_rec));
                    match (b1_outcome, b2_outcome) {
                        (Some(b1o), Some(b2o)) => {
                            let was_failed = matches!(b1o, Failed);
                            let now_failed = matches!(b2o, Failed);
                            let now_ok = matches!(b2o, Success | UpToDate);
                            if !was_failed && now_failed {
                                diff.new_failures.push(entry);
                            } else if was_failed && now_ok {
                                diff.fixes.push(entry);
                            } else if was_failed && now_failed {
                                diff.version_changes.push(entry);
                            } else {
                                diff.other_changes.push(entry);
                            }
                        }
                        _ => diff.other_changes.push(entry),
                    }
                }
                None => {
                    let entry = entry_from(None);
                    if matches!(b2_outcome, Some(Failed)) {
                        diff.new_failures.push(entry);
                    } else {
                        diff.other_changes.push(entry);
                    }
                }
            }
        }

        for ((pkgpath, pkgbase), b1_rec) in &b1 {
            if b2.contains_key(&(pkgpath.clone(), pkgbase.clone())) {
                continue;
            }
            let b1_outcome = PackageState::try_from(b1_rec.outcome).ok();
            let entry = DiffEntry {
                pkgpath: pkgpath.clone(),
                build1_pkgname: Some(b1_rec.pkgname.clone()),
                build2_pkgname: None,
                build1_outcome: b1_outcome,
                build2_outcome: None,
                build1_stage: b1_rec.stage.and_then(Stage::from_repr),
                build2_stage: None,
            };
            if matches!(b1_outcome, Some(Failed)) {
                diff.fixes.push(entry);
            } else {
                diff.other_changes.push(entry);
            }
        }

        Ok(diff)
    }
}

/**
 * A single entry in a build diff.
 */
pub struct DiffEntry {
    pub pkgpath: String,
    pub build1_pkgname: Option<String>,
    pub build2_pkgname: Option<String>,
    pub build1_outcome: Option<PackageState>,
    pub build2_outcome: Option<PackageState>,
    pub build1_stage: Option<Stage>,
    pub build2_stage: Option<Stage>,
}

/**
 * Categorised differences between two builds.
 *
 * Categories focus on build failures:
 *  - `new_failures`: packages now failing that were not before
 *  - `fixes`: packages that were failing but now succeed
 *  - `version_changes`: packages still broken but with a change (version bump,
 *    failure mode change, etc.)
 */
pub struct BuildDiff {
    pub build1_id: String,
    pub build2_id: String,
    pub new_failures: Vec<DiffEntry>,
    pub fixes: Vec<DiffEntry>,
    pub version_changes: Vec<DiffEntry>,
    pub other_changes: Vec<DiffEntry>,
}

/**
 * Summary of a build session from history.
 */
pub struct BuildListEntry {
    pub build_id: String,
    pub package_count: usize,
    pub succeeded: usize,
    pub up_to_date: usize,
    pub failed: usize,
    pub masked: usize,
    pub duration_ms: u64,
}

/**
 * History schema migrations in `(from, to, apply)` order.
 *
 * [`check_history_schema`] applies each step whose `from` matches the
 * current version.  Bumping the schema is one new row plus its
 * function; no other code changes.
 */
type HistoryMigration = (i32, i32, fn(&Connection) -> Result<()>);

const HISTORY_MIGRATIONS: &[HistoryMigration] = &[
    (20260406, 20260513, migrate_history_20260406_to_20260513),
    (20260513, 20260515, migrate_history_20260513_to_20260515),
    (20260515, 20260609, migrate_history_20260515_to_20260609),
];

/**
 * Check the history.db schema version if the file exists.
 *
 * This runs eagerly at Database::open() time so that a version mismatch
 * is reported immediately rather than hours into a bulk build.
 */
fn check_history_schema(dbdir: &Path) -> Result<()> {
    let path = dbdir.join("history.db");
    if !path.exists() {
        return Ok(());
    }
    let conn = Connection::open(&path).context("Failed to open history database")?;
    let has_schema: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master \
         WHERE type='table' AND name='schema_version'",
        [],
        |row| row.get::<_, i32>(0).map(|c| c > 0),
    )?;
    if !has_schema {
        let table_count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
            [],
            |row| row.get(0),
        )?;
        if table_count > 0 {
            anyhow::bail!(
                "{} has tables but no schema_version. Remove the file to reset.",
                path.display(),
            );
        }
        return Ok(());
    }
    let mut version: i32 =
        conn.query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
            row.get(0)
        })?;
    for &(from, to, apply) in HISTORY_MIGRATIONS {
        if version == from {
            apply(&conn)
                .with_context(|| format!("Failed to migrate history schema v{from} to v{to}"))?;
            version = conn.query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
                row.get(0)
            })?;
        }
    }
    if version == HISTORY_SCHEMA_VERSION {
        return Ok(());
    }
    anyhow::bail!(
        "History schema mismatch: found v{version}, expected v{expected}. \
         Remove {} to reset.",
        path.display(),
        expected = HISTORY_SCHEMA_VERSION
    );
}

/**
 * Migrate history.db from v20260406 to v20260513.
 *
 * Adds the `up_to_date` and `duration_ms` columns to `build_metadata`.
 */
fn migrate_history_20260406_to_20260513(conn: &Connection) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "ALTER TABLE build_metadata ADD COLUMN up_to_date  INTEGER NOT NULL DEFAULT 0;
         ALTER TABLE build_metadata ADD COLUMN duration_ms INTEGER NOT NULL DEFAULT 0;",
    )?;
    tx.execute("UPDATE schema_version SET version = ?1", params![20260513])?;
    tx.commit()?;
    Ok(())
}

/**
 * Migrate history.db from v20260513 to v20260515.
 *
 * Adds `UNIQUE(build_id, pkgpath, pkgbase)` to `build_history`,
 * rebuilding the table to install the constraint.  Pre-existing
 * duplicate rows are collapsed to the most recent row per key
 * (`MAX(id)` per group).  Rows with a NULL `build_id` are kept
 * verbatim: SQL `GROUP BY` treats NULLs as equal but the new UNIQUE
 * constraint treats them as distinct, so grouping would discard
 * rows that the constraint allows.  Orphaned `wall_times` /
 * `cpu_times` rows for dropped history rows are removed in the
 * same transaction.
 */
fn migrate_history_20260513_to_20260515(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA foreign_keys=OFF")?;
    let tx = conn.unchecked_transaction()?;
    let history_cols = history_schema();
    tx.execute_batch(&format!(
        "CREATE TABLE build_history_new (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             {history_cols},
             UNIQUE (build_id, pkgpath, pkgbase)
         );
         INSERT INTO build_history_new
             SELECT * FROM build_history
             WHERE build_id IS NULL
                OR id IN (
                    SELECT MAX(id) FROM build_history
                    WHERE build_id IS NOT NULL
                    GROUP BY build_id, pkgpath, pkgbase
                );
         DELETE FROM wall_times
             WHERE history_id NOT IN (SELECT id FROM build_history_new);
         DELETE FROM cpu_times
             WHERE history_id NOT IN (SELECT id FROM build_history_new);
         DROP TABLE build_history;
         ALTER TABLE build_history_new RENAME TO build_history;
         CREATE INDEX idx_history_pkgpath
             ON build_history(pkgpath);
         CREATE INDEX idx_history_pkgpath_pkgbase
             ON build_history(pkgpath, pkgbase);
         CREATE INDEX idx_history_pkgpath_outcome
             ON build_history(pkgpath, outcome);
         CREATE INDEX idx_history_timestamp
             ON build_history(timestamp);
         CREATE INDEX idx_history_build_id
             ON build_history(build_id, pkgpath, id);",
    ))?;
    tx.execute("UPDATE schema_version SET version = ?1", params![20260515])?;
    tx.commit()?;
    conn.execute_batch("PRAGMA foreign_keys=ON")?;
    Ok(())
}

/**
 * Migrate history.db from v20260515 to v20260609.
 *
 * Adds `idx_history_outcome_pkg`, a covering index for the
 * latest-successful-build window query so it no longer seeks the table
 * once per row.
 */
fn migrate_history_20260515_to_20260609(conn: &Connection) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_history_outcome_pkg
             ON build_history(outcome, pkgpath, pkgbase);",
    )?;
    tx.execute("UPDATE schema_version SET version = ?1", params![20260609])?;
    tx.commit()?;
    Ok(())
}

/**
 * Open and initialize the history database connection.
 */
fn open_history_conn(dbdir: &Path) -> Result<Connection> {
    let conn =
        Connection::open(dbdir.join("history.db")).context("Failed to open history database")?;

    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA cache_size = -8000;
         PRAGMA temp_store = MEMORY;
         PRAGMA foreign_keys = ON;",
    )?;

    let has_schema: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master \
         WHERE type='table' AND name='schema_version'",
        [],
        |row| row.get::<_, i32>(0).map(|c| c > 0),
    )?;

    if !has_schema {
        create_history_schema(&conn)?;
    }

    Ok(conn)
}

/**
 * Create the history database schema.
 *
 * Applies all table and index definitions to the given connection.
 * Used by [`open_history_conn`] for new databases and by tests
 * that need an in-memory history database.
 */
pub(crate) fn create_history_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(&format!(
        "CREATE TABLE schema_version (version INTEGER NOT NULL);
         INSERT INTO schema_version (version) VALUES ({});

         CREATE TABLE outcome_types (
             id INTEGER PRIMARY KEY,
             name TEXT UNIQUE NOT NULL
         );
         INSERT INTO outcome_types (id, name) VALUES {outcome_types};

         CREATE TABLE stage_types (
             id INTEGER PRIMARY KEY,
             name TEXT UNIQUE NOT NULL
         );
         INSERT INTO stage_types (id, name) VALUES {stages};

         /*
          * build_history is keyed by (build_id, pkgpath, pkgbase) and
          * holds the latest outcome per key, not an append-only event
          * log: record_history_to upserts on conflict, replacing any
          * prior row for the same key (e.g. a transient failure
          * superseded by a successful rebuild within the same
          * build_id).  Within-build retries collapse to the final
          * state; cross-build history is preserved because each build
          * has its own build_id.
          */
         CREATE TABLE build_history (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             {history_columns},
             UNIQUE (build_id, pkgpath, pkgbase)
         );

         CREATE INDEX idx_history_pkgpath
             ON build_history(pkgpath);
         CREATE INDEX idx_history_pkgpath_pkgbase
             ON build_history(pkgpath, pkgbase);
         CREATE INDEX idx_history_pkgpath_outcome
             ON build_history(pkgpath, outcome);
         CREATE INDEX idx_history_timestamp
             ON build_history(timestamp);
         CREATE INDEX idx_history_build_id
             ON build_history(build_id, pkgpath, id);
         CREATE INDEX idx_history_outcome_pkg
             ON build_history(outcome, pkgpath, pkgbase);

         CREATE TABLE wall_times (
             history_id INTEGER NOT NULL
                 REFERENCES build_history(id) ON DELETE CASCADE,
             stage INTEGER NOT NULL REFERENCES stage_types(id),
             duration INTEGER NOT NULL,
             PRIMARY KEY (history_id, stage)
         );

         CREATE TABLE cpu_times (
             history_id INTEGER NOT NULL
                 REFERENCES build_history(id) ON DELETE CASCADE,
             stage INTEGER NOT NULL REFERENCES stage_types(id),
             duration INTEGER NOT NULL,
             PRIMARY KEY (history_id, stage)
         );

         CREATE TABLE cpu_usage (
             timestamp INTEGER NOT NULL,
             user_pct INTEGER NOT NULL,
             sys_pct INTEGER NOT NULL
         );
         CREATE INDEX idx_cpu_timestamp ON cpu_usage(timestamp);

         CREATE TABLE build_metadata (
             build_id    TEXT PRIMARY KEY,
             revision    TEXT,
             up_to_date  INTEGER NOT NULL DEFAULT 0,
             duration_ms INTEGER NOT NULL DEFAULT 0
         );",
        HISTORY_SCHEMA_VERSION,
        outcome_types = outcome_values(),
        stages = stage_values(),
        history_columns = history_schema(),
    ))?;
    Ok(())
}

/**
 * Insert a build record into the history database.
 *
 * `build_history` has `UNIQUE(build_id, pkgpath, pkgbase)`.  Real
 * outcomes (Success, Failed, etc.) replace any prior row for the
 * same key and refresh the `wall_times` / `cpu_times` side rows;
 * an `UpToDate` write is a marker only and yields to any existing
 * row, since a real outcome is always more informative than "we
 * didn't rebuild it."
 *
 * Used by [`Database::record_history`] and by tests that need to
 * populate an in-memory history database.
 */
pub(crate) fn record_history_to(conn: &Connection, rec: &crate::History) -> Result<()> {
    let cols: Vec<&str> = HistoryKind::VARIANTS.iter().map(<&str>::from).collect();
    let placeholders: String = (1..=cols.len())
        .map(|i| format!("?{}", i))
        .collect::<Vec<_>>()
        .join(", ");
    let dur_ms = |d: Duration| d.as_millis() as i64;
    let values = params![
        rec.timestamp,
        rec.pkgpath,
        rec.pkgname,
        rec.pkgbase,
        rec.outcome.id(),
        rec.stage.map(|s| s as i32),
        rec.make_jobs.map(|j| j as i64),
        dur_ms(rec.duration),
        rec.disk_usage.map(|s| s as i64),
        rec.wrkobjdir.as_ref().map(|k| k.to_string()),
        rec.build_id.as_deref(),
    ];

    if rec.outcome == crate::PackageState::UpToDate {
        let sql = format!(
            "INSERT INTO build_history ({}) VALUES ({}) \
             ON CONFLICT(build_id, pkgpath, pkgbase) DO NOTHING",
            cols.join(", "),
            placeholders,
        );
        conn.execute(&sql, values)?;
        return Ok(());
    }

    let update_assignments: String = cols
        .iter()
        .map(|c| format!("{c} = excluded.{c}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO build_history ({}) VALUES ({}) \
         ON CONFLICT(build_id, pkgpath, pkgbase) DO UPDATE SET {} \
         RETURNING id",
        cols.join(", "),
        placeholders,
        update_assignments,
    );
    let history_id: i64 = conn.query_row(&sql, values, |row| row.get(0))?;

    conn.execute(
        "DELETE FROM wall_times WHERE history_id = ?1",
        params![history_id],
    )?;
    conn.execute(
        "DELETE FROM cpu_times WHERE history_id = ?1",
        params![history_id],
    )?;
    if !rec.stage_durations.is_empty() {
        let mut stmt = conn.prepare_cached(
            "INSERT INTO wall_times \
                 (history_id, stage, duration) \
             VALUES (?1, ?2, ?3)",
        )?;
        for &(stage, duration) in &rec.stage_durations {
            stmt.execute(params![history_id, stage as i32, dur_ms(duration)])?;
        }
    }
    if !rec.stage_cpu_times.is_empty() {
        let mut stmt = conn.prepare_cached(
            "INSERT INTO cpu_times \
                 (history_id, stage, duration) \
             VALUES (?1, ?2, ?3)",
        )?;
        for &(stage, duration) in &rec.stage_cpu_times {
            stmt.execute(params![history_id, stage as i32, dur_ms(duration)])?;
        }
    }
    Ok(())
}

/*
 * Scheduler query support.
 *
 * Used by `Scheduler::from_db` to construct the dependency graph from the
 * build database, and by `jobs::make_jobs_from_db` and the scheduler
 * itself to query historical build-stage timing data from history.db.
 */

/**
 * Selected package row from the build database.
 */
pub(crate) struct SelectedPackage {
    pub id: i64,
    pub pkgname: PkgName,
    pub pkg_location: String,
    pub pbulk_weight: usize,
    pub make_jobs_safe: bool,
}

/**
 * Query all selected packages from the build database.
 */
pub(crate) fn query_selected_packages(conn: &Connection) -> Result<Vec<SelectedPackage>> {
    let mut stmt = conn.prepare(
        "SELECT p.id, p.pkgname, p.pkg_location, p.pbulk_weight, p.make_jobs_safe \
         FROM scan_index p \
         JOIN package_state s ON s.package_id = p.id \
         WHERE s.selected = 1",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(SelectedPackage {
            id: row.get(0)?,
            pkgname: PkgName::from(row.get::<_, String>(1)?),
            pkg_location: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            pbulk_weight: row.get::<_, Option<u32>>(3)?.map_or(100, |w| w as usize),
            make_jobs_safe: row.get::<_, Option<bool>>(4)?.is_none_or(|s| s),
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/**
 * Query all resolved dependency edges from the build database.
 *
 * Returns `(package_id, depends_on_id)` pairs.
 */
pub(crate) fn query_resolved_deps(conn: &Connection) -> Result<Vec<(i64, i64)>> {
    let mut stmt = conn.prepare("SELECT package_id, depends_on_id FROM resolved_depends")?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/**
 * Historical build-stage CPU timing for a single package.
 *
 * The value is in milliseconds and covers only the build stage
 * (not configure, install, package, etc.).
 */
pub(crate) struct BuildStageTiming {
    pub cpu_ms: u64,
}

/**
 * Query build-stage wall time and CPU time for all packages.
 *
 * Returns the most recent successful build's timing data for the
 * build stage, keyed by [`PkgKey`].
 */
pub(crate) fn query_build_stage_timings(conn: &Connection) -> HashMap<PkgKey, BuildStageTiming> {
    let out: &str = HistoryKind::Outcome.into();
    let pkgbase_col: &str = HistoryKind::Pkgbase.into();
    let pkgpath_col: &str = HistoryKind::Pkgpath.into();
    let success_outcome = PackageState::Success.id();
    let build_stage = Stage::Build as i32;

    /*
     * The latest successful build per package is the row with the
     * greatest id in its (pkgpath, pkgbase) group.  A grouped MAX(id)
     * streams over idx_history_outcome_pkg; a ROW_NUMBER() window would
     * number every row into a temporary b-tree for the same result.
     */
    let sql = format!(
        "WITH latest AS ( \
             SELECT {pkgpath_col}, {pkgbase_col}, MAX(id) AS id \
             FROM build_history \
             WHERE {out} = {success_outcome} \
             GROUP BY {pkgpath_col}, {pkgbase_col} \
         ) \
         SELECT l.{pkgpath_col}, l.{pkgbase_col}, ct.duration \
         FROM latest l \
         JOIN cpu_times ct ON ct.history_id = l.id \
              AND ct.stage = {build_stage}",
    );

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                error = format!("{e:#}"),
                "query_build_stage_timings: failed to prepare query"
            );
            return HashMap::new();
        }
    };
    let rows = match stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
        ))
    }) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                error = format!("{e:#}"),
                "query_build_stage_timings: query failed"
            );
            return HashMap::new();
        }
    };

    let mut result = HashMap::new();
    for row in rows.flatten() {
        let (pkgpath, pkgbase, cpu_ms) = row;
        result.insert(
            (pkgpath, pkgbase),
            BuildStageTiming {
                cpu_ms: cpu_ms as u64,
            },
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::Stage;

    fn test_history_db() -> Connection {
        let conn = Connection::open_in_memory().expect("failed to open in-memory db");
        create_history_schema(&conn).expect("failed to create schema");
        conn
    }

    fn insert_build(conn: &Connection, pkgpath: &str, pkgname: &str, wall_ms: u64, cpu_ms: u64) {
        use crate::{History, PackageState};
        use std::time::Duration;

        let rec = History {
            timestamp: 0,
            pkgpath: pkgpath.to_string(),
            pkgname: pkgname.to_string(),
            pkgbase: PkgName::new(pkgname).pkgbase().to_string(),
            outcome: PackageState::Success,
            stage: None,
            make_jobs: Some(1),
            duration: Duration::ZERO,
            disk_usage: None,
            wrkobjdir: None,
            stage_durations: vec![(Stage::Build, Duration::from_millis(wall_ms))],
            stage_cpu_times: vec![(Stage::Build, Duration::from_millis(cpu_ms))],
            build_id: None,
        };
        record_history_to(conn, &rec).expect("failed to insert build");
    }

    fn key(pkgpath: &str, pkgbase: &str) -> (String, String) {
        (pkgpath.to_string(), pkgbase.to_string())
    }

    /** Query returns timings keyed by (pkgpath, pkgbase). */
    #[test]
    fn build_stage_timings_basic() {
        let conn = test_history_db();
        insert_build(&conn, "devel/cmake", "cmake-3.28.0", 60000, 180000);
        let timings = query_build_stage_timings(&conn);
        assert_eq!(timings.len(), 1);
        let t = &timings[&key("devel/cmake", "cmake")];
        assert_eq!(t.cpu_ms, 180000);
    }

    /** Most recent build wins when multiple exist for a pkgpath. */
    #[test]
    fn build_stage_timings_latest() {
        let conn = test_history_db();
        insert_build(&conn, "devel/cmake", "cmake-3.27.0", 1000, 2000);
        insert_build(&conn, "devel/cmake", "cmake-3.28.0", 5000, 15000);
        let timings = query_build_stage_timings(&conn);
        assert_eq!(timings.len(), 1);
        let t = &timings[&key("devel/cmake", "cmake")];
        assert_eq!(t.cpu_ms, 15000);
    }

    /** Different pkgpaths with same pkgbase are separate entries. */
    #[test]
    fn build_stage_timings_pkgpath_disambiguates() {
        let conn = test_history_db();
        insert_build(
            &conn,
            "databases/mysql80-client",
            "mysql-client-8.0.1",
            3000,
            9000,
        );
        insert_build(
            &conn,
            "databases/mysql57-client",
            "mysql-client-5.7.42",
            2000,
            4000,
        );
        let timings = query_build_stage_timings(&conn);
        assert_eq!(timings.len(), 2);
        let t80 = &timings[&key("databases/mysql80-client", "mysql-client")];
        assert_eq!(t80.cpu_ms, 9000);
        let t57 = &timings[&key("databases/mysql57-client", "mysql-client")];
        assert_eq!(t57.cpu_ms, 4000);
    }

    /** Empty database returns empty map. */
    #[test]
    fn build_stage_timings_empty() {
        let conn = test_history_db();
        let timings = query_build_stage_timings(&conn);
        assert!(timings.is_empty());
    }
}
