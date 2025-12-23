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

//! Statistics collection for performance analysis.
//!
//! Writes events to a JSONL (JSON Lines) file for later analysis.
//! Each line is a self-contained JSON object, making the file easy
//! to process with tools like `jq`.
//!
//! # Example
//!
//! ```sh
//! # Find slowest scans
//! jq -s 'map(select(.event == "scan")) | sort_by(.duration_ms) | reverse | .[0:10]' stats.jsonl
//!
//! # Average build time
//! jq -s '[.[] | select(.event == "build") | .duration_ms] | add / length' stats.jsonl
//! ```

use serde::Serialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

/// A thread-safe JSONL stats writer.
pub struct Stats {
    writer: Mutex<BufWriter<File>>,
}

/// Events that can be recorded to the stats file.
#[derive(Serialize)]
#[serde(tag = "event")]
pub enum Event<'a> {
    #[serde(rename = "scan")]
    Scan { pkgpath: &'a str, duration_ms: u64, success: bool },
    #[serde(rename = "resolve")]
    Resolve { buildable: usize, skipped: usize, duration_ms: u64 },
    #[serde(rename = "build")]
    Build {
        pkgname: &'a str,
        pkgpath: Option<&'a str>,
        duration_ms: u64,
        outcome: &'a str,
    },
}

impl Stats {
    /// Create a new stats writer that writes to the given path.
    pub fn new(path: &Path) -> anyhow::Result<Self> {
        let file = File::create(path)?;
        Ok(Self { writer: Mutex::new(BufWriter::new(file)) })
    }

    /// Record an event to the stats file.
    pub fn record(&self, event: Event) {
        if let Ok(mut writer) = self.writer.lock() {
            if let Ok(json) = serde_json::to_string(&event) {
                let _ = writeln!(writer, "{}", json);
            }
        }
    }

    /// Record a package scan event.
    pub fn scan(&self, pkgpath: &str, duration: Duration, success: bool) {
        self.record(Event::Scan {
            pkgpath,
            duration_ms: duration.as_millis() as u64,
            success,
        });
    }

    /// Record a dependency resolution event.
    pub fn resolve(
        &self,
        buildable: usize,
        skipped: usize,
        duration: Duration,
    ) {
        self.record(Event::Resolve {
            buildable,
            skipped,
            duration_ms: duration.as_millis() as u64,
        });
    }

    /// Record a package build event.
    pub fn build(
        &self,
        pkgname: &str,
        pkgpath: Option<&str>,
        duration: Duration,
        outcome: &str,
    ) {
        self.record(Event::Build {
            pkgname,
            pkgpath,
            duration_ms: duration.as_millis() as u64,
            outcome,
        });
    }

    /// Flush any buffered data to disk.
    pub fn flush(&self) {
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writer.flush();
        }
    }
}

impl Drop for Stats {
    fn drop(&mut self) {
        self.flush();
    }
}
