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
 * Build history types and display formatting.
 *
 * [`HistoryKind`] is the single source of truth for history column
 * definitions, including database schema and display formatting.
 * [`History`] holds the data for a single build history record, used
 * for both database writes and reads.
 */

use std::time::Duration;

use strum::{EnumMessage, VariantArray};

use crate::build::Stage;
use crate::{ColumnAlign, PackageState};

/// Prefix for selecting CPU time instead of wall time for a stage.
const CPU_PREFIX: &str = "cpu:";

/**
 * Columns in the `build_history` table.
 *
 * Variant names map 1:1 to [`History`] struct fields.  The snake_case
 * serialization provides both the database column name and the CLI
 * display name.  Per-stage duration columns come from [`Stage`]
 * variants via a separate table.
 */
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    strum::IntoStaticStr,
    strum::VariantArray,
    strum::EnumMessage,
    strum::EnumProperty,
)]
#[strum(serialize_all = "snake_case")]
pub enum HistoryKind {
    #[strum(message = "Build start time")]
    Timestamp,
    #[strum(message = "Package path in pkgsrc")]
    Pkgpath,
    #[strum(message = "Package name and version")]
    Pkgname,
    #[strum(message = "Package name without version")]
    Pkgbase,
    #[strum(message = "Build result")]
    Outcome,
    #[strum(message = "Last stage attempted (for failures)")]
    Stage,
    #[strum(message = "MAKE_JOBS used", props(align = "right"))]
    MakeJobs,
    #[strum(message = "Total wall-clock duration", props(align = "right"))]
    Duration,
    #[strum(message = "WRKDIR size at end of build", props(align = "right"))]
    DiskUsage,
    #[strum(message = "WRKOBJDIR type (tmpfs or disk)")]
    Wrkobjdir,
    #[strum(message = "Build session identifier")]
    BuildId,
}

/**
 * Alignment from per-variant `align` props.
 */
impl crate::ColumnAlign for HistoryKind {}

impl HistoryKind {
    /// All valid column names with alignment.
    pub fn all_columns() -> Vec<(String, crate::Align)> {
        Self::VARIANTS
            .iter()
            .map(|v| (<&str>::from(v).to_string(), v.align()))
            .chain(
                Stage::VARIANTS
                    .iter()
                    .map(|s| (s.into_str().to_string(), s.align())),
            )
            .chain(
                Stage::VARIANTS
                    .iter()
                    .map(|s| (format!("{CPU_PREFIX}{}", s.into_str()), s.align())),
            )
            .collect()
    }

    /// Column names shown by default.
    pub fn default_names() -> Vec<&'static str> {
        use HistoryKind::*;
        [
            Timestamp, Pkgname, Outcome, MakeJobs, Wrkobjdir, DiskUsage, Duration,
        ]
        .iter()
        .map(|v| v.into())
        .collect()
    }

    /// Generate the `after_long_help` text for `bob history`.
    pub fn after_help() -> String {
        let all_cols = Self::all_columns();
        let max_name = all_cols.iter().map(|(n, _)| n.len()).max().unwrap_or(0);

        let mut help = String::from("Columns:\n");
        for col in Self::VARIANTS {
            let name: &str = col.into();
            let desc = col.get_message().unwrap_or("");
            help.push_str(&format!("  {:<width$}  {}\n", name, desc, width = max_name));
        }
        for s in Stage::VARIANTS {
            let name = s.into_str();
            help.push_str(&format!(
                "  {:<width$}  Wall time for {} stage\n",
                name,
                name,
                width = max_name
            ));
        }
        for s in Stage::VARIANTS {
            let name = s.into_str();
            help.push_str(&format!(
                "  {:<width$}  CPU time for {} stage\n",
                format!("{CPU_PREFIX}{name}"),
                name,
                width = max_name
            ));
        }
        help.push_str(&format!(
            "\nDefault columns: {}\n",
            Self::default_names().join(",")
        ));

        help.push_str(
            "\n\
             Examples:\n  \
             bob history                                        Show all build history\n  \
             bob history rust                                   Show history matching 'rust'\n  \
             bob history -o pkgname,build,cpu:build,duration    Show build wall+cpu time\n  \
             bob history -Ho pkgpath                            Show pkgpaths only, no header",
        );

        help
    }
}

/**
 * A single build history record.
 *
 * Field names match [`HistoryKind`] variant names and are used
 * directly as database column names.
 */
pub struct History {
    pub timestamp: i64,
    pub pkgpath: String,
    pub pkgname: String,
    pub pkgbase: String,
    pub outcome: PackageState,
    pub stage: Option<Stage>,
    pub make_jobs: Option<usize>,
    pub duration: Duration,
    pub disk_usage: Option<u64>,
    /// WRKOBJDIR type used for this build.
    pub wrkobjdir: Option<crate::config::WrkObjKind>,
    /// Per-stage wall-clock durations.
    pub stage_durations: Vec<(Stage, Duration)>,
    /// Per-stage CPU time (user+sys from wait4).
    pub stage_cpu_times: Vec<(Stage, Duration)>,
    /// Build session identifier (from bob.db metadata).
    pub build_id: Option<String>,
}

fn format_timestamp(epoch: i64) -> String {
    let mut buf = [0u8; 20];
    let time_t = epoch as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&time_t, &mut tm) };
    let len = unsafe {
        libc::strftime(
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            c"%Y-%m-%d %H:%M:%S".as_ptr(),
            &tm,
        )
    };
    String::from_utf8_lossy(&buf[..len]).to_string()
}

pub fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        let mins = ms / 60_000;
        let secs = (ms % 60_000) / 1000;
        format!("{}m{:02}s", mins, secs)
    } else {
        let hours = ms / 3_600_000;
        let mins = (ms % 3_600_000) / 60_000;
        format!("{}h{:02}m", hours, mins)
    }
}

fn format_size(bytes: u64) -> String {
    const K: u64 = 1024;
    const M: u64 = 1024 * 1024;
    const G: u64 = 1024 * 1024 * 1024;
    if bytes >= G {
        format!("{:.1}G", bytes as f64 / G as f64)
    } else if bytes >= M {
        format!("{:.1}M", bytes as f64 / M as f64)
    } else if bytes >= K {
        format!("{:.1}K", bytes as f64 / K as f64)
    } else {
        format!("{}B", bytes)
    }
}

impl History {
    /**
     * Format a column value for display.
     *
     * Handles both [`HistoryKind`] variants (exhaustive match) and
     * [`Stage`] per-stage duration columns.
     */
    pub fn format_col(&self, name: &str) -> String {
        let fmt_dur = |d: Duration| format_duration(d.as_millis() as u64);
        let dash = || "-".to_string();

        if let Some(stage_name) = name.strip_prefix(CPU_PREFIX) {
            if let Some(stage) = Stage::VARIANTS.iter().find(|s| s.into_str() == stage_name) {
                return self
                    .stage_cpu_times
                    .iter()
                    .find(|(st, _)| st == stage)
                    .map(|(_, d)| fmt_dur(*d))
                    .unwrap_or_else(dash);
            }
        }

        if let Some(stage) = Stage::VARIANTS.iter().find(|s| s.into_str() == name) {
            return self
                .stage_durations
                .iter()
                .find(|(st, _)| st == stage)
                .map(|(_, d)| fmt_dur(*d))
                .unwrap_or_else(dash);
        }

        let col = HistoryKind::VARIANTS
            .iter()
            .find(|c| <&str>::from(*c) == name)
            .expect("column already validated");
        match col {
            HistoryKind::Timestamp => format_timestamp(self.timestamp),
            HistoryKind::Pkgpath => self.pkgpath.clone(),
            HistoryKind::Pkgname => self.pkgname.clone(),
            HistoryKind::Pkgbase => self.pkgbase.clone(),
            HistoryKind::Outcome => self.outcome.status().to_string(),
            HistoryKind::Stage => {
                if self.outcome == PackageState::Success {
                    dash()
                } else {
                    self.stage
                        .map(|s| s.into_str().to_string())
                        .unwrap_or_else(dash)
                }
            }
            HistoryKind::MakeJobs => self.make_jobs.map(|j| j.to_string()).unwrap_or_else(dash),
            HistoryKind::Duration => fmt_dur(self.duration),
            HistoryKind::DiskUsage => self.disk_usage.map(format_size).unwrap_or_else(dash),
            HistoryKind::Wrkobjdir => self
                .wrkobjdir
                .as_ref()
                .map(|k| k.to_string())
                .unwrap_or_else(dash),
            HistoryKind::BuildId => self.build_id.clone().unwrap_or_else(dash),
        }
    }

    /**
     * Format a column value as raw numeric output.
     *
     * Durations are output as milliseconds, sizes as bytes, and
     * timestamps as epoch seconds.  All other columns are identical
     * to [`format_col`](Self::format_col).
     */
    pub fn format_col_raw(&self, name: &str) -> String {
        let fmt_dur = |d: Duration| d.as_millis().to_string();
        let dash = || "-".to_string();

        if let Some(stage_name) = name.strip_prefix(CPU_PREFIX) {
            if let Some(stage) = Stage::VARIANTS.iter().find(|s| s.into_str() == stage_name) {
                return self
                    .stage_cpu_times
                    .iter()
                    .find(|(st, _)| st == stage)
                    .map(|(_, d)| fmt_dur(*d))
                    .unwrap_or_else(dash);
            }
        }

        if let Some(stage) = Stage::VARIANTS.iter().find(|s| s.into_str() == name) {
            return self
                .stage_durations
                .iter()
                .find(|(st, _)| st == stage)
                .map(|(_, d)| fmt_dur(*d))
                .unwrap_or_else(dash);
        }

        let col = HistoryKind::VARIANTS
            .iter()
            .find(|c| <&str>::from(*c) == name)
            .expect("column already validated");
        match col {
            HistoryKind::Timestamp => self.timestamp.to_string(),
            HistoryKind::Pkgpath => self.pkgpath.clone(),
            HistoryKind::Pkgname => self.pkgname.clone(),
            HistoryKind::Pkgbase => self.pkgbase.clone(),
            HistoryKind::Outcome => self.outcome.status().to_string(),
            HistoryKind::Stage => {
                if self.outcome == PackageState::Success {
                    dash()
                } else {
                    self.stage
                        .map(|s| s.into_str().to_string())
                        .unwrap_or_else(dash)
                }
            }
            HistoryKind::MakeJobs => self.make_jobs.map(|j| j.to_string()).unwrap_or_else(dash),
            HistoryKind::Duration => fmt_dur(self.duration),
            HistoryKind::DiskUsage => self.disk_usage.map(|b| b.to_string()).unwrap_or_else(dash),
            HistoryKind::Wrkobjdir => self
                .wrkobjdir
                .as_ref()
                .map(|k| k.to_string())
                .unwrap_or_else(dash),
            HistoryKind::BuildId => self.build_id.clone().unwrap_or_else(dash),
        }
    }
}
