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

//! SQLite database for persistent state storage.
//!
//! This module provides persistent storage for bob's state, enabling:
//!
//! - **Resumption**: Resume interrupted scans/builds from where they left off
//! - **Scan caching**: Reuse scan data from completed scans
//! - **Build tracking**: Track package build status
//! - **Stage management**: Track progress through stages (scan, build, report)
//!
//! # Database Location
//!
//! The database is stored at `{logdir}/bob/bob.db`.
//!
//! # Example
//!
//! ```no_run
//! use bob::db::Database;
//! use std::path::Path;
//!
//! let db = Database::open(Path::new("/path/to/logdir/bob/bob.db"))?;
//!
//! // Check for resumable state
//! if let Some(state) = db.get_latest_session()? {
//!     if state.can_resume() {
//!         // Resume from where we left off
//!     }
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```

use anyhow::{Context, Result};
use pkgsrc::{PkgName, ScanIndex};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tracing::{debug, info};

use crate::scan::ResolvedIndex;

/// Current database schema version.
const SCHEMA_VERSION: i32 = 1;

/// Status of a build session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    /// Session created but not started
    Pending,
    /// Currently scanning packages
    Scanning,
    /// Scan complete, ready to build
    Scanned,
    /// Currently building packages
    Building,
    /// All builds completed successfully
    Completed,
    /// Build was interrupted (can be resumed)
    Interrupted,
    /// Build failed with unrecoverable error
    Failed,
}

impl SessionStatus {
    fn as_str(&self) -> &'static str {
        match self {
            SessionStatus::Pending => "pending",
            SessionStatus::Scanning => "scanning",
            SessionStatus::Scanned => "scanned",
            SessionStatus::Building => "building",
            SessionStatus::Completed => "completed",
            SessionStatus::Interrupted => "interrupted",
            SessionStatus::Failed => "failed",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(SessionStatus::Pending),
            "scanning" => Some(SessionStatus::Scanning),
            "scanned" => Some(SessionStatus::Scanned),
            "building" => Some(SessionStatus::Building),
            "completed" => Some(SessionStatus::Completed),
            "interrupted" => Some(SessionStatus::Interrupted),
            "failed" => Some(SessionStatus::Failed),
            _ => None,
        }
    }
}

/// Status of a package scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanStatus {
    /// Not yet scanned
    Pending,
    /// Scan completed successfully
    Completed,
    /// Scan failed
    Failed,
    /// Package was skipped (PKG_SKIP_REASON or PKG_FAIL_REASON)
    Skipped,
}

/// Status of a package build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BuildStatus {
    /// Not yet built (waiting for dependencies or not started)
    Pending,
    /// Currently being built
    InProgress,
    /// Build completed successfully
    Success,
    /// Build failed
    Failed,
    /// Build was skipped (dependency failed or up-to-date)
    Skipped,
}

/// Information about a build session.
#[derive(Clone, Debug)]
pub struct Session {
    /// Unique session identifier.
    pub id: i64,
    /// Session status.
    pub status: SessionStatus,
    /// When the session was created.
    pub created_at: String,
    /// When the session was last updated.
    pub updated_at: String,
    /// Total packages to process.
    pub total_packages: i64,
    /// Packages scanned so far.
    pub scanned_packages: i64,
    /// Packages built so far.
    pub built_packages: i64,
    /// Packages that failed to build.
    pub failed_packages: i64,
    /// Packages that were skipped.
    pub skipped_packages: i64,
}

impl Session {
    /// Check if this session can be resumed.
    pub fn can_resume(&self) -> bool {
        matches!(
            self.status,
            SessionStatus::Scanning
                | SessionStatus::Scanned
                | SessionStatus::Building
                | SessionStatus::Interrupted
        )
    }

    /// Check if the scan phase is complete.
    pub fn scan_complete(&self) -> bool {
        matches!(
            self.status,
            SessionStatus::Scanned
                | SessionStatus::Building
                | SessionStatus::Completed
                | SessionStatus::Interrupted
        )
    }
}

/// Serializable form of ResolvedIndex for database storage.
///
/// Instead of duplicating all ScanIndex fields, we store the pbulk-index
/// text format directly. This is the same format produced by `bmake pbulk-index`
/// and parsed by `ScanIndex::from_reader()`, so it automatically stays in sync
/// with any changes to the pkgsrc crate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredResolvedIndex {
    /// ScanIndex serialized as pbulk-index text format.
    pub index_text: String,
    /// Resolved dependencies as package names.
    pub depends: Vec<String>,
}

impl StoredResolvedIndex {
    /// Convert from ResolvedIndex.
    pub fn from_resolved_index(idx: &ResolvedIndex) -> Self {
        Self {
            // ScanIndex implements Display, producing pbulk-index format
            index_text: idx.index.to_string(),
            depends: idx.depends.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// Convert back to ResolvedIndex.
    pub fn to_resolved_index(&self) -> Result<ResolvedIndex> {
        use std::io::BufReader;

        // Parse ScanIndex from pbulk-index text format
        let reader = BufReader::new(self.index_text.as_bytes());
        let mut indices: Vec<ScanIndex> = ScanIndex::from_reader(reader)
            .collect::<Result<_, _>>()
            .context("Failed to parse stored scan index")?;

        let index = indices
            .pop()
            .context("No scan index found in stored data")?;

        let depends = self.depends.iter().map(|s| PkgName::new(s)).collect();
        Ok(ResolvedIndex { index, depends })
    }
}

/// Package information stored in the database.
#[derive(Clone, Debug)]
pub struct StoredPackage {
    /// Package path (e.g., "mail/mutt").
    pub pkgpath: String,
    /// Package name with version (e.g., "mutt-2.2.12"), set after scan.
    pub pkgname: Option<String>,
    /// Scan status.
    pub scan_status: ScanStatus,
    /// Scan data as JSON (StoredResolvedIndex).
    pub scan_data: Option<String>,
    /// Error message if scan failed.
    pub scan_error: Option<String>,
    /// Build status.
    pub build_status: BuildStatus,
    /// Build outcome reason (for failed/skipped).
    pub build_reason: Option<String>,
    /// Build duration in milliseconds.
    pub build_duration_ms: Option<i64>,
}

/// SQLite database connection for bob state.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open (or create) a database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create database directory")?;
        }

        let conn = Connection::open(path)
            .context("Failed to open database")?;

        // Enable foreign keys
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Run database migrations to ensure schema is up to date.
    fn migrate(&self) -> Result<()> {
        // Check current schema version
        let version: i32 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM pragma_user_version",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if version >= SCHEMA_VERSION {
            debug!(version, "Database schema is up to date");
            return Ok(());
        }

        info!(from = version, to = SCHEMA_VERSION, "Migrating database schema");

        // Initial schema
        if version < 1 {
            self.conn.execute_batch(
                r#"
                -- Sessions table: tracks build runs
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    total_packages INTEGER NOT NULL DEFAULT 0,
                    scanned_packages INTEGER NOT NULL DEFAULT 0,
                    built_packages INTEGER NOT NULL DEFAULT 0,
                    failed_packages INTEGER NOT NULL DEFAULT 0,
                    skipped_packages INTEGER NOT NULL DEFAULT 0
                );

                -- Packages table: tracks individual package status
                CREATE TABLE IF NOT EXISTS packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    pkgpath TEXT NOT NULL,
                    pkgname TEXT,
                    scan_status TEXT NOT NULL DEFAULT 'pending',
                    scan_data TEXT,
                    scan_error TEXT,
                    build_status TEXT NOT NULL DEFAULT 'pending',
                    build_reason TEXT,
                    build_duration_ms INTEGER,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
                    UNIQUE(session_id, pkgpath)
                );

                -- Index for fast pkgname lookups
                CREATE INDEX IF NOT EXISTS idx_packages_pkgname
                    ON packages(session_id, pkgname);

                -- Index for status queries
                CREATE INDEX IF NOT EXISTS idx_packages_scan_status
                    ON packages(session_id, scan_status);
                CREATE INDEX IF NOT EXISTS idx_packages_build_status
                    ON packages(session_id, build_status);

                -- Dependencies table: resolved package dependencies
                CREATE TABLE IF NOT EXISTS dependencies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    pkgname TEXT NOT NULL,
                    depends_on TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
                    UNIQUE(session_id, pkgname, depends_on)
                );

                -- Index for dependency lookups
                CREATE INDEX IF NOT EXISTS idx_dependencies_pkgname
                    ON dependencies(session_id, pkgname);
                CREATE INDEX IF NOT EXISTS idx_dependencies_depends_on
                    ON dependencies(session_id, depends_on);

                PRAGMA user_version = 1;
                "#,
            )?;
        }

        Ok(())
    }

    /// Create a new build session.
    pub fn create_session(&self) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO sessions DEFAULT VALUES",
            [],
        )?;
        let id = self.conn.last_insert_rowid();
        info!(state_id = id, "Created new state");
        Ok(id)
    }

    /// Get the latest session.
    pub fn get_latest_session(&self) -> Result<Option<Session>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, status, created_at, updated_at, total_packages,
                    scanned_packages, built_packages, failed_packages, skipped_packages
             FROM sessions
             ORDER BY id DESC
             LIMIT 1",
        )?;

        let session = stmt
            .query_row([], |row| {
                Ok(Session {
                    id: row.get(0)?,
                    status: SessionStatus::from_str(row.get::<_, String>(1)?.as_str())
                        .unwrap_or(SessionStatus::Failed),
                    created_at: row.get(2)?,
                    updated_at: row.get(3)?,
                    total_packages: row.get(4)?,
                    scanned_packages: row.get(5)?,
                    built_packages: row.get(6)?,
                    failed_packages: row.get(7)?,
                    skipped_packages: row.get(8)?,
                })
            })
            .ok();

        Ok(session)
    }

    /// Get a session by ID.
    pub fn get_session(&self, id: i64) -> Result<Option<Session>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, status, created_at, updated_at, total_packages,
                    scanned_packages, built_packages, failed_packages, skipped_packages
             FROM sessions
             WHERE id = ?1",
        )?;

        let session = stmt
            .query_row([id], |row| {
                Ok(Session {
                    id: row.get(0)?,
                    status: SessionStatus::from_str(row.get::<_, String>(1)?.as_str())
                        .unwrap_or(SessionStatus::Failed),
                    created_at: row.get(2)?,
                    updated_at: row.get(3)?,
                    total_packages: row.get(4)?,
                    scanned_packages: row.get(5)?,
                    built_packages: row.get(6)?,
                    failed_packages: row.get(7)?,
                    skipped_packages: row.get(8)?,
                })
            })
            .ok();

        Ok(session)
    }

    /// List all sessions.
    pub fn list_sessions(&self) -> Result<Vec<Session>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, status, created_at, updated_at, total_packages,
                    scanned_packages, built_packages, failed_packages, skipped_packages
             FROM sessions
             ORDER BY id DESC",
        )?;

        let sessions = stmt
            .query_map([], |row| {
                Ok(Session {
                    id: row.get(0)?,
                    status: SessionStatus::from_str(row.get::<_, String>(1)?.as_str())
                        .unwrap_or(SessionStatus::Failed),
                    created_at: row.get(2)?,
                    updated_at: row.get(3)?,
                    total_packages: row.get(4)?,
                    scanned_packages: row.get(5)?,
                    built_packages: row.get(6)?,
                    failed_packages: row.get(7)?,
                    skipped_packages: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(sessions)
    }

    /// Update session status.
    pub fn set_session_status(&self, id: i64, status: SessionStatus) -> Result<()> {
        self.conn.execute(
            "UPDATE sessions SET status = ?1, updated_at = datetime('now') WHERE id = ?2",
            params![status.as_str(), id],
        )?;
        debug!(state_id = id, status = status.as_str(), "Updated state status");
        Ok(())
    }

    /// Add a package to scan.
    pub fn add_package(&self, state_id: i64, pkgpath: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO packages (session_id, pkgpath) VALUES (?1, ?2)",
            params![state_id, pkgpath],
        )?;
        Ok(())
    }

    /// Add multiple packages to scan.
    pub fn add_packages(&self, state_id: i64, pkgpaths: &[&str]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for pkgpath in pkgpaths {
            tx.execute(
                "INSERT OR IGNORE INTO packages (session_id, pkgpath) VALUES (?1, ?2)",
                params![state_id, pkgpath],
            )?;
        }
        tx.commit()?;

        // Update total package count
        self.conn.execute(
            "UPDATE sessions SET total_packages = (
                SELECT COUNT(*) FROM packages WHERE session_id = ?1
             ), updated_at = datetime('now')
             WHERE id = ?1",
            [state_id],
        )?;

        Ok(())
    }

    /// Get packages pending scan.
    pub fn get_packages_to_scan(&self, state_id: i64) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT pkgpath FROM packages
             WHERE session_id = ?1 AND scan_status = 'pending'
             ORDER BY pkgpath",
        )?;

        let pkgpaths = stmt
            .query_map([state_id], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;

        Ok(pkgpaths)
    }

    /// Mark a package scan as complete and store the result.
    pub fn complete_package_scan(
        &self,
        state_id: i64,
        pkgpath: &str,
        resolved: &ResolvedIndex,
    ) -> Result<()> {
        let stored = StoredResolvedIndex::from_resolved_index(resolved);
        let json = serde_json::to_string(&stored)?;

        self.conn.execute(
            "UPDATE packages
             SET pkgname = ?1, scan_status = 'completed', scan_data = ?2,
                 updated_at = datetime('now')
             WHERE session_id = ?3 AND pkgpath = ?4",
            params![resolved.pkgname.to_string(), json, state_id, pkgpath],
        )?;

        // Store dependencies
        for dep in &resolved.depends {
            self.conn.execute(
                "INSERT OR IGNORE INTO dependencies (session_id, pkgname, depends_on)
                 VALUES (?1, ?2, ?3)",
                params![state_id, resolved.pkgname.to_string(), dep.to_string()],
            )?;
        }

        // Update scanned count
        self.conn.execute(
            "UPDATE sessions SET scanned_packages = (
                SELECT COUNT(*) FROM packages
                WHERE session_id = ?1 AND scan_status = 'completed'
             ), updated_at = datetime('now')
             WHERE id = ?1",
            [state_id],
        )?;

        Ok(())
    }

    /// Mark a package scan as failed.
    pub fn fail_package_scan(
        &self,
        state_id: i64,
        pkgpath: &str,
        error: &str,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE packages
             SET scan_status = 'failed', scan_error = ?1, updated_at = datetime('now')
             WHERE session_id = ?2 AND pkgpath = ?3",
            params![error, state_id, pkgpath],
        )?;
        Ok(())
    }

    /// Mark a package as skipped during scan (PKG_SKIP_REASON, etc.).
    pub fn skip_package_scan(
        &self,
        state_id: i64,
        pkgpath: &str,
        pkgname: &str,
        reason: &str,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE packages
             SET pkgname = ?1, scan_status = 'skipped', scan_error = ?2,
                 build_status = 'skipped', build_reason = ?2,
                 updated_at = datetime('now')
             WHERE session_id = ?3 AND pkgpath = ?4",
            params![pkgname, reason, state_id, pkgpath],
        )?;
        Ok(())
    }

    /// Get all successfully scanned packages as ResolvedIndex.
    pub fn get_scanned_packages(
        &self,
        state_id: i64,
    ) -> Result<HashMap<PkgName, ResolvedIndex>> {
        let mut stmt = self.conn.prepare(
            "SELECT scan_data FROM packages
             WHERE session_id = ?1 AND scan_status = 'completed' AND scan_data IS NOT NULL",
        )?;

        let mut result = HashMap::new();
        let rows = stmt.query_map([state_id], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })?;

        for row in rows {
            let json = row?;
            let stored: StoredResolvedIndex = serde_json::from_str(&json)
                .context("Failed to deserialize scan data")?;
            let resolved = stored.to_resolved_index()?;
            result.insert(resolved.index.pkgname.clone(), resolved);
        }

        Ok(result)
    }

    /// Get packages pending build.
    pub fn get_packages_to_build(&self, state_id: i64) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT pkgname FROM packages
             WHERE session_id = ?1
               AND scan_status = 'completed'
               AND build_status = 'pending'
             ORDER BY pkgname",
        )?;

        let pkgnames = stmt
            .query_map([state_id], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;

        Ok(pkgnames)
    }

    /// Mark a package build as starting.
    pub fn start_package_build(&self, state_id: i64, pkgname: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE packages
             SET build_status = 'in_progress', updated_at = datetime('now')
             WHERE session_id = ?1 AND pkgname = ?2",
            params![state_id, pkgname],
        )?;
        Ok(())
    }

    /// Mark a package build as successful.
    pub fn complete_package_build(
        &self,
        state_id: i64,
        pkgname: &str,
        duration: Duration,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE packages
             SET build_status = 'success', build_duration_ms = ?1,
                 updated_at = datetime('now')
             WHERE session_id = ?2 AND pkgname = ?3",
            params![duration.as_millis() as i64, state_id, pkgname],
        )?;

        // Update built count
        self.conn.execute(
            "UPDATE sessions SET built_packages = (
                SELECT COUNT(*) FROM packages
                WHERE session_id = ?1 AND build_status = 'success'
             ), updated_at = datetime('now')
             WHERE id = ?1",
            [state_id],
        )?;

        Ok(())
    }

    /// Mark a package build as failed.
    pub fn fail_package_build(
        &self,
        state_id: i64,
        pkgname: &str,
        reason: &str,
        duration: Duration,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE packages
             SET build_status = 'failed', build_reason = ?1, build_duration_ms = ?2,
                 updated_at = datetime('now')
             WHERE session_id = ?3 AND pkgname = ?4",
            params![reason, duration.as_millis() as i64, state_id, pkgname],
        )?;

        // Update failed count
        self.conn.execute(
            "UPDATE sessions SET failed_packages = (
                SELECT COUNT(*) FROM packages
                WHERE session_id = ?1 AND build_status = 'failed'
             ), updated_at = datetime('now')
             WHERE id = ?1",
            [state_id],
        )?;

        Ok(())
    }

    /// Mark a package build as skipped.
    pub fn skip_package_build(
        &self,
        state_id: i64,
        pkgname: &str,
        reason: &str,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE packages
             SET build_status = 'skipped', build_reason = ?1,
                 updated_at = datetime('now')
             WHERE session_id = ?2 AND pkgname = ?3",
            params![reason, state_id, pkgname],
        )?;

        // Update skipped count
        self.conn.execute(
            "UPDATE sessions SET skipped_packages = (
                SELECT COUNT(*) FROM packages
                WHERE session_id = ?1 AND build_status = 'skipped'
             ), updated_at = datetime('now')
             WHERE id = ?1",
            [state_id],
        )?;

        Ok(())
    }

    /// Reset in-progress builds to pending (for resuming after interruption).
    pub fn reset_in_progress_builds(&self, state_id: i64) -> Result<usize> {
        let count = self.conn.execute(
            "UPDATE packages
             SET build_status = 'pending', updated_at = datetime('now')
             WHERE session_id = ?1 AND build_status = 'in_progress'",
            [state_id],
        )?;
        if count > 0 {
            info!(state_id, count, "Reset in-progress builds to pending");
        }
        Ok(count)
    }

    /// Delete a session and all its data.
    pub fn delete_session(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM sessions WHERE id = ?1", [id])?;
        info!(state_id = id, "Deleted state");
        Ok(())
    }

    /// Check if a scan is complete.
    pub fn is_scan_complete(&self, state_id: i64) -> Result<bool> {
        let pending: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM packages
             WHERE session_id = ?1 AND scan_status = 'pending'",
            [state_id],
            |row| row.get(0),
        )?;
        Ok(pending == 0)
    }

    /// Get build status counts.
    pub fn get_build_status_counts(&self, state_id: i64) -> Result<(i64, i64, i64, i64)> {
        let mut stmt = self.conn.prepare(
            "SELECT
                SUM(CASE WHEN build_status = 'pending' THEN 1 ELSE 0 END),
                SUM(CASE WHEN build_status = 'success' THEN 1 ELSE 0 END),
                SUM(CASE WHEN build_status = 'failed' THEN 1 ELSE 0 END),
                SUM(CASE WHEN build_status = 'skipped' THEN 1 ELSE 0 END)
             FROM packages
             WHERE session_id = ?1 AND scan_status = 'completed'",
        )?;

        let (pending, success, failed, skipped) = stmt.query_row([state_id], |row| {
            Ok((
                row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                row.get::<_, Option<i64>>(3)?.unwrap_or(0),
            ))
        })?;

        Ok((pending, success, failed, skipped))
    }

    /// Store all resolved packages from a ScanResult.
    pub fn store_scan_result(
        &self,
        state_id: i64,
        buildable: &HashMap<PkgName, ResolvedIndex>,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;

        for (pkgname, resolved) in buildable {
            let pkgpath = resolved
                .pkg_location
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_default();

            let stored = StoredResolvedIndex::from_resolved_index(resolved);
            let json = serde_json::to_string(&stored)?;

            // Insert or update the package
            tx.execute(
                "INSERT INTO packages (session_id, pkgpath, pkgname, scan_status, scan_data)
                 VALUES (?1, ?2, ?3, 'completed', ?4)
                 ON CONFLICT(session_id, pkgpath) DO UPDATE SET
                    pkgname = excluded.pkgname,
                    scan_status = excluded.scan_status,
                    scan_data = excluded.scan_data,
                    updated_at = datetime('now')",
                params![state_id, pkgpath, pkgname.to_string(), json],
            )?;

            // Store dependencies
            for dep in &resolved.depends {
                tx.execute(
                    "INSERT OR IGNORE INTO dependencies (session_id, pkgname, depends_on)
                     VALUES (?1, ?2, ?3)",
                    params![state_id, pkgname.to_string(), dep.to_string()],
                )?;
            }
        }

        tx.commit()?;

        // Update counts
        self.conn.execute(
            "UPDATE sessions SET
                total_packages = (SELECT COUNT(*) FROM packages WHERE session_id = ?1),
                scanned_packages = (SELECT COUNT(*) FROM packages WHERE session_id = ?1 AND scan_status = 'completed'),
                updated_at = datetime('now')
             WHERE id = ?1",
            [state_id],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_state_lifecycle() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Database::open(&db_path).unwrap();

        // Create state
        let state_id = db.create_session().unwrap();
        assert_eq!(state_id, 1);

        // Get state - starts as Pending (not resumable yet)
        let state = db.get_session(state_id).unwrap().unwrap();
        assert_eq!(state.status, SessionStatus::Pending);
        assert!(!state.can_resume()); // Pending can't be resumed

        // Update status to Scanning (now resumable)
        db.set_session_status(state_id, SessionStatus::Scanning).unwrap();
        let state = db.get_session(state_id).unwrap().unwrap();
        assert_eq!(state.status, SessionStatus::Scanning);
        assert!(state.can_resume());

        // Update to Scanned (still resumable)
        db.set_session_status(state_id, SessionStatus::Scanned).unwrap();
        let state = db.get_session(state_id).unwrap().unwrap();
        assert!(state.scan_complete());
        assert!(state.can_resume());

        // Update to Completed (no longer resumable)
        db.set_session_status(state_id, SessionStatus::Completed).unwrap();
        let state = db.get_session(state_id).unwrap().unwrap();
        assert!(!state.can_resume());

        // List states
        let states = db.list_sessions().unwrap();
        assert_eq!(states.len(), 1);

        // Delete state
        db.delete_session(state_id).unwrap();
        assert!(db.get_session(state_id).unwrap().is_none());
    }

    #[test]
    fn test_package_tracking() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = Database::open(&db_path).unwrap();

        let state_id = db.create_session().unwrap();

        // Add packages
        db.add_packages(state_id, &["mail/mutt", "www/curl"]).unwrap();

        // Check pending
        let pending = db.get_packages_to_scan(state_id).unwrap();
        assert_eq!(pending.len(), 2);

        // Check state counts
        let state = db.get_session(state_id).unwrap().unwrap();
        assert_eq!(state.total_packages, 2);
    }
}
