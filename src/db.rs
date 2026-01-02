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
//! Stores [`ScanIndex`] data per pkgpath to enable resuming interrupted scans.
//! Stores [`BuildResult`] data per pkgname to enable resuming interrupted builds.
//! Users should clear the database when pkgsrc is updated.

use crate::build::BuildResult;
use anyhow::{Context, Result};
use indexmap::IndexMap;
use pkgsrc::{PkgName, PkgPath, ScanIndex};
use rusqlite::{Connection, params};
use std::path::Path;
use tracing::{debug, warn};

/// SQLite database for scan result caching.
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
        db.init()?;
        Ok(db)
    }

    fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scan (
                pkgpath TEXT PRIMARY KEY,
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS build (
                pkgname TEXT PRIMARY KEY,
                data TEXT NOT NULL
            )",
        )?;
        Ok(())
    }

    /// Store scan results for a pkgpath.
    pub fn store_scan_pkgpath(
        &self,
        pkgpath: &str,
        indexes: &[ScanIndex],
    ) -> Result<()> {
        let json = serde_json::to_string(indexes)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO scan (pkgpath, data) VALUES (?1, ?2)",
            params![pkgpath, json],
        )?;
        debug!(pkgpath, "Stored scan result");
        Ok(())
    }

    /// Load all cached scan, preserving insertion order.
    pub fn get_all_scan(&self) -> Result<IndexMap<PkgPath, Vec<ScanIndex>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT pkgpath, data FROM scan ORDER BY rowid")?;
        let mut result = IndexMap::new();

        let rows = stmt.query_map([], |row| {
            let pkgpath: String = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((pkgpath, json))
        })?;

        for row in rows {
            let (pkgpath_str, json) = row?;
            let pkgpath = PkgPath::new(&pkgpath_str)
                .context("Invalid pkgpath in database")?;
            let indexes: Vec<ScanIndex> = serde_json::from_str(&json)
                .context("Failed to deserialize scan data")?;
            result.insert(pkgpath, indexes);
        }

        Ok(result)
    }

    /// Count of cached pkgpaths.
    pub fn count_scan(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM scan", [], |row| row.get(0))
            .context("Failed to count scan")
    }

    /// Clear all cached scan data.
    pub fn clear_scan(&self) -> Result<()> {
        self.conn.execute("DELETE FROM scan", [])?;
        Ok(())
    }

    /// Store build result for a pkgname.
    pub fn store_build_pkgname(
        &self,
        pkgname: &str,
        result: &BuildResult,
    ) -> Result<()> {
        let json = serde_json::to_string(result)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO build (pkgname, data) VALUES (?1, ?2)",
            params![pkgname, json],
        )?;
        debug!(pkgname, "Stored build result");
        Ok(())
    }

    /// Load all cached build results, preserving insertion order.
    pub fn get_all_build(&self) -> Result<IndexMap<PkgName, BuildResult>> {
        let mut stmt = self
            .conn
            .prepare("SELECT pkgname, data FROM build ORDER BY rowid")?;
        let mut result = IndexMap::new();

        let rows = stmt.query_map([], |row| {
            let pkgname: String = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((pkgname, json))
        })?;

        for row in rows {
            let (pkgname_str, json) = row?;
            let pkgname = PkgName::new(&pkgname_str);
            let build_result: BuildResult = serde_json::from_str(&json)
                .context("Failed to deserialize build data")?;
            result.insert(pkgname, build_result);
        }

        Ok(result)
    }

    /// Count of cached build results.
    pub fn count_build(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM build", [], |row| row.get(0))
            .context("Failed to count build")
    }

    /// Clear all cached build data.
    pub fn clear_build(&self) -> Result<()> {
        self.conn.execute("DELETE FROM build", [])?;
        Ok(())
    }

    /// Delete cached build result for a specific pkgname.
    pub fn delete_build_pkgname(&self, pkgname: &str) -> Result<bool> {
        let rows = self.conn.execute(
            "DELETE FROM build WHERE pkgname = ?1",
            params![pkgname],
        )?;
        Ok(rows > 0)
    }

    /// Delete cached build results matching a pkgpath.
    /// Returns the number of deleted entries.
    pub fn delete_build_by_pkgpath(&self, pkgpath: &str) -> Result<usize> {
        let normalized = PkgPath::new(pkgpath)
            .map(|pp| pp.to_string())
            .unwrap_or_else(|_| pkgpath.to_string());
        // Build results store pkgpath in the JSON data, so we need to search
        let mut stmt = self.conn.prepare("SELECT pkgname, data FROM build")?;
        let rows = stmt.query_map([], |row| {
            let pkgname: String = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((pkgname, json))
        })?;

        let mut to_delete = Vec::new();
        let mut corrupted = Vec::new();
        for row in rows {
            let (pkgname, json) = row?;
            match serde_json::from_str::<BuildResult>(&json) {
                Ok(result) => {
                    if let Some(ref pp) = result.pkgpath {
                        if pp.to_string() == normalized {
                            to_delete.push(pkgname);
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        pkgname,
                        error = ?err,
                        "Failed to parse cached build result; deleting entry"
                    );
                    corrupted.push(pkgname);
                }
            }
        }

        for pkgname in to_delete.iter().chain(corrupted.iter()) {
            self.conn.execute(
                "DELETE FROM build WHERE pkgname = ?1",
                params![pkgname],
            )?;
        }

        Ok(to_delete.len() + corrupted.len())
    }
}
