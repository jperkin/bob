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

use anyhow::Result;
use bob::db::Database;
use bob::try_println;
use regex::Regex;

fn format_duration_ms(ms: u64) -> String {
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

pub fn run(db: &Database, package: Option<&str>) -> Result<()> {
    let pattern = package
        .map(|p| Regex::new(p).map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", p, e)))
        .transpose()?;

    let records = db.query_history(pattern.as_ref())?;

    if records.is_empty() {
        if package.is_some() {
            println!("No history matches the pattern");
        } else {
            println!("No build history recorded");
        }
        return Ok(());
    }

    let headers = [
        "TIMESTAMP",
        "PKGPATH",
        "PKGNAME",
        "OUTCOME",
        "STAGE",
        "JOBS",
        "BUILD",
        "TOTAL",
    ];

    let mut rows: Vec<[String; 8]> = Vec::new();
    for rec in &records {
        let ts = rec.timestamp.clone();
        let stage = rec
            .stage
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|| "-".to_string());
        let jobs = if rec.make_jobs == 0 {
            "-".to_string()
        } else {
            rec.make_jobs.to_string()
        };
        let build = rec
            .build_duration
            .map(|d| format_duration_ms(d.as_millis() as u64))
            .unwrap_or_else(|| "-".to_string());
        let total = format_duration_ms(rec.total_duration.as_millis() as u64);
        rows.push([
            ts,
            rec.pkgpath.clone(),
            rec.pkgname.clone(),
            rec.outcome.as_str().to_string(),
            stage,
            jobs,
            build,
            total,
        ]);
    }

    let widths: Vec<usize> = (0..8)
        .map(|i| {
            let header_len = headers[i].len();
            let max_data = rows.iter().map(|r| r[i].len()).max().unwrap_or(0);
            header_len.max(max_data)
        })
        .collect();

    let header: Vec<String> = headers
        .iter()
        .zip(&widths)
        .map(|(h, &w)| format!("{:<width$}", h, width = w))
        .collect();
    if !try_println(header.join("  ").trim_end()) {
        return Ok(());
    }

    for row in &rows {
        let values: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(v, &w)| format!("{:<width$}", v, width = w))
            .collect();
        if !try_println(values.join("  ").trim_end()) {
            break;
        }
    }

    Ok(())
}
