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

use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail};

use bob::PackageState;
use bob::db::{BuildDiff, Database, DiffEntry};

use super::{
    Cell, Column, ColumnSource, OutputFormat, OutputOptions, Writer, cols_help,
    parse_status_filter, select_columns,
};

const SUPPORTED: &[Column] = &[
    Column::Pkgname,
    Column::Pkgpath,
    Column::Breaks,
    Column::Stage,
    Column::StagePrev,
    Column::Outcome,
    Column::OutcomePrev,
    Column::PkgnamePrev,
];

const DEFAULT: &[Column] = &[
    Column::Pkgname,
    Column::Pkgpath,
    Column::Breaks,
    Column::Stage,
];

#[derive(Debug, clap::Args)]
#[command(after_long_help = diff_after_help())]
pub struct DiffArgs {
    /// First build ID (baseline). Default: second most recent
    pub build1: Option<String>,
    /// Second build ID. Default: most recent
    pub build2: Option<String>,
    /// Show all changes, not just failures and fixes
    #[arg(short, long)]
    pub all: bool,
    /// Hide column headers
    #[arg(short = 'H')]
    pub no_header: bool,
    /// Show all columns
    #[arg(short = 'l', long)]
    pub long: bool,
    /// Columns to display (comma-separated, see --help for full list)
    #[arg(short = 'o', value_delimiter = ',')]
    pub columns: Option<Vec<String>>,
    /// Filter by baseline status (see `bob status -s` for valid values)
    #[arg(short = 'f', long = "from", value_delimiter = ',', value_parser = parse_status_filter)]
    pub from: Vec<Vec<PackageState>>,
    /// Filter by current status (see `bob status -s` for valid values)
    #[arg(short = 't', long = "to", value_delimiter = ',', value_parser = parse_status_filter)]
    pub to: Vec<Vec<PackageState>>,
}

fn diff_after_help() -> String {
    cols_help(SUPPORTED, DEFAULT)
}

impl ColumnSource for DiffEntry {
    type Ctx = HashMap<String, usize>;
    fn cell(&self, col: Column, breaks: &Self::Ctx) -> Cell {
        match col {
            Column::Pkgname => self
                .build2_pkgname
                .as_deref()
                .or(self.build1_pkgname.as_deref())
                .map_or(Cell::Null, Cell::from),
            Column::Pkgpath => self.pkgpath.as_str().into(),
            Column::Breaks => get_breaks(self, breaks).into(),
            Column::Stage => match self.build2_outcome {
                Some(k) if k.is_success() => Cell::Null,
                _ => self
                    .build2_stage
                    .map_or(Cell::Null, |s| <&str>::from(s).into()),
            },
            Column::StagePrev => self
                .build1_stage
                .map_or(Cell::Null, |s| <&str>::from(s).into()),
            Column::Outcome => self
                .build2_outcome
                .map_or(Cell::Null, |o| o.as_str().into()),
            Column::OutcomePrev => self
                .build1_outcome
                .map_or(Cell::Null, |o| o.as_str().into()),
            Column::PkgnamePrev => self
                .build1_pkgname
                .as_deref()
                .map_or(Cell::Null, Cell::from),
            _ => unreachable!("column {:?} not supported by bob diff", col),
        }
    }
}

pub fn run(db: &Database, args: DiffArgs) -> Result<()> {
    let chosen = select_columns(args.columns.as_deref(), args.long, DEFAULT, SUPPORTED)?;

    let (build1_id, build2_id) = match (args.build1, args.build2) {
        (Some(b1), Some(b2)) => (b1, b2),
        (Some(b1), None) => {
            let builds = db.list_history_builds()?;
            if builds.is_empty() {
                bail!("No builds in history");
            }
            (b1, builds[0].build_id.clone())
        }
        (None, Some(_)) => {
            bail!("Specify both build IDs, or none for the two most recent");
        }
        (None, None) => {
            let builds = db.list_history_builds()?;
            if builds.len() < 2 {
                bail!(
                    "Need at least two builds to compare. \
                     Use 'bob list builds' to see available builds."
                );
            }
            (builds[1].build_id.clone(), builds[0].build_id.clone())
        }
    };

    let diff = db.compute_build_diff(&build1_id, &build2_id)?;

    let breaks: HashMap<String, usize> = match bob::Scheduler::from_db(db) {
        Ok((sched, table)) => sched
            .iter()
            .map(|sp| (table.info(sp.pkg).pkgname.to_string(), sp.dep_count))
            .collect(),
        Err(_) => HashMap::new(),
    };

    let from: Option<HashSet<PackageState>> =
        (!args.from.is_empty()).then(|| args.from.iter().flatten().copied().collect());
    let to: Option<HashSet<PackageState>> =
        (!args.to.is_empty()).then(|| args.to.iter().flatten().copied().collect());

    let opts = OutputOptions {
        format: OutputFormat::Table,
        no_header: args.no_header,
        raw: false,
    };

    if from.is_some() || to.is_some() {
        print_filtered(&diff, &breaks, chosen, opts, from.as_ref(), to.as_ref())
    } else {
        print_diff(&diff, &breaks, args.all, chosen, opts)
    }
}

fn matches_filter(
    e: &DiffEntry,
    from: Option<&HashSet<PackageState>>,
    to: Option<&HashSet<PackageState>>,
) -> bool {
    let ok = |set: Option<&HashSet<PackageState>>, state: Option<PackageState>| match set {
        Some(s) => state.is_some_and(|k| s.contains(&k)),
        None => true,
    };
    ok(from, e.build1_outcome) && ok(to, e.build2_outcome)
}

fn print_filtered(
    diff: &BuildDiff,
    breaks: &HashMap<String, usize>,
    chosen: Vec<Column>,
    opts: OutputOptions,
    from: Option<&HashSet<PackageState>>,
    to: Option<&HashSet<PackageState>>,
) -> Result<()> {
    let mut entries: Vec<&DiffEntry> = diff
        .new_failures
        .iter()
        .chain(diff.version_changes.iter())
        .chain(diff.fixes.iter())
        .chain(diff.other_changes.iter())
        .filter(|e| matches_filter(e, from, to))
        .collect();

    let label = |set: Option<&HashSet<PackageState>>| -> String {
        set.map(|s| {
            let mut names: Vec<&str> = s.iter().map(|k| k.as_str()).collect();
            names.sort_unstable();
            names.join(",")
        })
        .unwrap_or_else(|| "any".into())
    };
    let summary = format!(
        "@@ {}: from {} to {} @@",
        entries.len(),
        label(from),
        label(to),
    );

    let mut out = Writer::stdout(chosen, opts)?;
    out.message(&format!("--- {}", diff.build1_id))?;
    out.message(&format!("+++ {}", diff.build2_id))?;
    out.message(&summary)?;

    entries.sort_by_key(|e| std::cmp::Reverse(get_breaks(e, breaks)));
    for e in &entries {
        out.write(Some(' '), *e, breaks)?;
    }
    out.finish()
}

fn get_breaks(e: &DiffEntry, breaks: &HashMap<String, usize>) -> usize {
    e.build2_pkgname
        .as_deref()
        .or(e.build1_pkgname.as_deref())
        .and_then(|n| breaks.get(n).copied())
        .unwrap_or(0)
}

fn print_diff(
    diff: &BuildDiff,
    breaks: &HashMap<String, usize>,
    show_all: bool,
    chosen: Vec<Column>,
    opts: OutputOptions,
) -> Result<()> {
    let nf = diff.new_failures.len();
    let fx = diff.fixes.len();
    let vc = diff.version_changes.len();
    let oc = diff.other_changes.len();

    let mut parts = Vec::new();
    if nf > 0 {
        parts.push(format!("+{} failure{}", nf, if nf == 1 { "" } else { "s" }));
    }
    if fx > 0 {
        parts.push(format!("-{} fix{}", fx, if fx == 1 { "" } else { "es" }));
    }
    if vc > 0 {
        parts.push(format!("~{} change{}", vc, if vc == 1 { "" } else { "s" }));
    }
    if show_all && oc > 0 {
        parts.push(format!(
            "{} other change{}",
            oc,
            if oc == 1 { "" } else { "s" }
        ));
    }
    let summary = if parts.is_empty() {
        "@@ no changes @@".to_string()
    } else {
        format!("@@ {} @@", parts.join(", "))
    };

    let mut out = Writer::stdout(chosen, opts)?;
    out.message(&format!("--- {}", diff.build1_id))?;
    out.message(&format!("+++ {}", diff.build2_id))?;
    out.message(&summary)?;

    let emit = |out: &mut Writer<std::io::StdoutLock<'static>>,
                prefix: char,
                entries: &mut [&DiffEntry]|
     -> Result<()> {
        entries.sort_by_key(|e| std::cmp::Reverse(get_breaks(e, breaks)));
        for e in entries.iter() {
            out.write(Some(prefix), *e, breaks)?;
        }
        Ok(())
    };

    let mut failures: Vec<_> = diff.new_failures.iter().collect();
    emit(&mut out, '+', &mut failures)?;
    let mut version_changes: Vec<_> = diff.version_changes.iter().collect();
    emit(&mut out, '~', &mut version_changes)?;
    let mut fixes: Vec<_> = diff.fixes.iter().collect();
    emit(&mut out, '-', &mut fixes)?;
    if show_all {
        let mut other: Vec<_> = diff.other_changes.iter().collect();
        emit(&mut out, ' ', &mut other)?;
    }

    out.finish()
}
