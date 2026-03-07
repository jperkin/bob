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

use bob::db::Database;

use super::{ColumnDef, OutputFormat, render_output, resolve_columns};

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
    let all_col_refs: Vec<&str> = all_cols.iter().map(|s| s.as_str()).collect();
    let default_cols = bob::HistoryKind::default_names();
    let cols = resolve_columns(columns, long, &all_col_refs, &default_cols)?;

    let pattern = package
        .map(|p| Regex::new(p).map_err(|e| anyhow::anyhow!("Invalid regex '{}': {}", p, e)))
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

    let rows: Vec<Vec<String>> = records
        .iter()
        .map(|rec| cols.iter().map(|&col| format_val(rec, col)).collect())
        .collect();

    let col_defs: Vec<ColumnDef> = cols.iter().map(|&c| ColumnDef::new(c)).collect();
    render_output(format, &col_defs, &rows, no_header)
}
