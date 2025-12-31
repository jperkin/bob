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

//! SQLite database for caching scan results.
//!
//! Stores [`ScanIndex`] data per pkgpath to enable resuming interrupted scan.
//! Users should clear the database when pkgsrc is updated.

use anyhow::{Context, Result};
use indexmap::IndexMap;
use pkgsrc::{PkgPath, ScanIndex};
use rusqlite::{Connection, params};
use std::path::Path;
use tracing::debug;

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

    /// Clear all cached data.
    pub fn clear_scan(&self) -> Result<()> {
        self.conn.execute("DELETE FROM scan", [])?;
        Ok(())
    }
}
