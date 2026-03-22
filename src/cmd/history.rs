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

use anyhow::{Result, bail};
use clap::Args;
use regex::Regex;
use serde_json;

use bob::db::Database;
use bob::try_println;

use super::OutputFormat;

#[derive(Debug, Args)]
pub struct HistoryArgs {
    /// Hide column headers
    #[arg(short = 'H')]
    no_header: bool,
    /// Show all columns
    #[arg(short = 'l', long)]
    long: bool,
    /// Output raw numeric values (ms for durations, bytes for sizes)
    #[arg(short = 'r', long)]
    raw: bool,
    /// Output format
    #[arg(short = 'f', long, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,
    /// Columns to display (comma-separated, see --help for full list)
    #[arg(short = 'o', value_delimiter = ',')]
    columns: Option<Vec<String>>,
    /// Filter by pkgpath or pkgname (regex)
    package: Option<String>,
}

pub fn run(db: &Database, args: HistoryArgs) -> Result<()> {
    print_history(
        db,
        args.columns.as_deref(),
        args.no_header,
        args.long,
        args.raw,
        args.format,
        args.package.as_deref(),
    )
}

fn print_history(
    db: &Database,
    columns: Option<&[String]>,
    no_header: bool,
    long: bool,
    raw: bool,
    format: OutputFormat,
    package: Option<&str>,
) -> Result<()> {
    let all_cols = bob::HistoryKind::all_names();
    let default_cols = bob::HistoryKind::default_names();
    let cols: Vec<&str> = if columns.is_some() {
        columns
            .map(|c| c.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    } else if long {
        all_cols.iter().map(|s| s.as_str()).collect()
    } else {
        default_cols
    };

    for col in &cols {
        if !all_cols.iter().any(|c| c == col) {
            bail!(
                "Unknown column '{}'. Valid columns: {}",
                col,
                all_cols.join(", ")
            );
        }
    }

    let pattern = package
        .map(|p| {
            Regex::new(&format!("(?i){}", p))
                .map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", p, e))
        })
        .transpose()?;

    let records = db.query_history(pattern.as_ref())?;

    if records.is_empty() {
        if package.is_some() {
            bail!("No history matches the pattern");
        } else {
            println!("No build history recorded");
        }
        return Ok(());
    }

    let format_val = |rec: &bob::History, col: &str| -> String {
        if raw {
            rec.format_col_raw(col)
        } else {
            rec.format_col(col)
        }
    };

    match format {
        OutputFormat::Table => {
            let rows: Vec<Vec<String>> = records
                .iter()
                .map(|rec| cols.iter().map(|&col| format_val(rec, col)).collect())
                .collect();

            let widths: Vec<usize> = cols
                .iter()
                .enumerate()
                .map(|(i, col)| {
                    let header_len = col.len();
                    let max_data = rows.iter().map(|r| r[i].len()).max().unwrap_or(0);
                    header_len.max(max_data)
                })
                .collect();

            if !no_header {
                let header: Vec<String> = cols
                    .iter()
                    .zip(&widths)
                    .map(|(&col, &w)| format!("{:<width$}", col.to_uppercase(), width = w))
                    .collect();
                if !try_println(header.join("  ").trim_end()) {
                    return Ok(());
                }
            }

            for row in &rows {
                let values: Vec<String> = row
                    .iter()
                    .zip(&widths)
                    .map(|(val, &w)| format!("{:<width$}", val, width = w))
                    .collect();
                if !try_println(values.join("  ").trim_end()) {
                    break;
                }
            }
        }
        OutputFormat::Csv => {
            if !no_header && !try_println(&cols.join(",")) {
                return Ok(());
            }
            for rec in &records {
                let values: Vec<String> = cols
                    .iter()
                    .map(|&col| {
                        let v = format_val(rec, col);
                        if v.contains(',') || v.contains('"') {
                            format!("\"{}\"", v.replace('"', "\"\""))
                        } else {
                            v
                        }
                    })
                    .collect();
                if !try_println(&values.join(",")) {
                    break;
                }
            }
        }
        OutputFormat::Json => {
            let array: Vec<serde_json::Map<String, serde_json::Value>> = records
                .iter()
                .map(|rec| {
                    cols.iter()
                        .map(|&col| {
                            (
                                col.to_string(),
                                serde_json::Value::String(format_val(rec, col)),
                            )
                        })
                        .collect()
                })
                .collect();
            try_println(&serde_json::to_string_pretty(&array)?);
        }
    }

    Ok(())
}
