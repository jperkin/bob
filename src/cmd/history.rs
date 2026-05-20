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

use bob::db::Database;

use super::util::pkg_pattern;
use super::{Cell, Col, Formatter, OutputFormat, OutputOptions};

#[derive(Debug, Args)]
pub struct HistoryArgs {
    /// Include rows for every recorded outcome (up-to-date, masked, etc.)
    #[arg(short = 'a', long)]
    all: bool,
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
    /// Columns to display (comma-separated; use --help for full list)
    #[arg(short = 'o', long_help = bob::HistoryKind::columns_help(), value_delimiter = ',')]
    columns: Option<Vec<String>>,
    /// Filter by pkgpath or pkgname (regex; any match)
    packages: Vec<String>,
}

pub fn run(db: &Database, args: HistoryArgs) -> Result<()> {
    print_history(
        db,
        args.columns.as_deref(),
        args.no_header,
        args.long,
        args.raw,
        args.all,
        args.format,
        &args.packages,
    )
}

#[allow(clippy::too_many_arguments)]
fn print_history(
    db: &Database,
    columns: Option<&[String]>,
    no_header: bool,
    long: bool,
    raw: bool,
    all: bool,
    format: OutputFormat,
    packages: &[String],
) -> Result<()> {
    let all_cols = bob::HistoryKind::all_columns();
    let default_cols = bob::HistoryKind::default_names();
    let cols: Vec<&str> = if columns.is_some() {
        columns
            .map(|c| c.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    } else if long {
        all_cols.iter().map(|(s, _)| s.as_str()).collect()
    } else {
        default_cols
    };

    for col in &cols {
        if !all_cols.iter().any(|(c, _)| c == col) {
            let names: Vec<&str> = all_cols.iter().map(|(n, _)| n.as_str()).collect();
            bail!(
                "Unknown column '{}'. Valid columns: {}",
                col,
                names.join(", ")
            );
        }
    }

    let patterns: Vec<regex::Regex> = packages
        .iter()
        .map(String::as_str)
        .map(pkg_pattern)
        .collect::<Result<Vec<_>>>()?;

    let records = db.query_history(&patterns, all)?;

    if records.is_empty() {
        if !patterns.is_empty() {
            bail!("No history matches the pattern");
        } else {
            println!("No build history recorded");
        }
        return Ok(());
    }

    let fmt_cols: Vec<Col> = cols
        .iter()
        .map(|&name| {
            let (_, align) = all_cols.iter().find(|(n, _)| n == name).expect("validated");
            Col::new(name.to_string(), *align)
        })
        .collect();

    let mut fmt = Formatter::new(
        std::io::stdout().lock(),
        fmt_cols,
        OutputOptions {
            format,
            no_header,
            raw,
        },
    )?;
    for rec in &records {
        let row: Vec<Cell> = cols
            .iter()
            .map(|&col| {
                let s = if raw {
                    rec.format_col_raw(col)
                } else {
                    rec.format_col(col)?
                };
                Ok::<_, anyhow::Error>(Cell::Text(s))
            })
            .collect::<Result<_>>()?;
        fmt.row(row)?;
    }
    fmt.finish()?;

    Ok(())
}
