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
use bob::try_println;

#[derive(Debug, Args)]
pub struct PruneArgs {
    /// Range or single endpoint: ..X, X..Y, or X (build_id or YYYY-MM-DD)
    range: Option<String>,
    /// Keep the N most recent builds, drop the rest
    #[arg(long, conflicts_with_all = ["range", "older_than"])]
    keep_last: Option<usize>,
    /// Drop builds older than DUR (e.g. 30d, 6w, 12m, 1y)
    #[arg(long, conflicts_with_all = ["range", "keep_last"])]
    older_than: Option<String>,
    /// Don't delete; print what would be pruned
    #[arg(short = 'n', long)]
    dry_run: bool,
}

pub fn run(db: &Database, args: PruneArgs) -> Result<()> {
    let current = db.build_id().ok();
    let builds = db.list_history_builds()?;

    let to_drop = if let Some(range) = args.range.as_deref() {
        select_range(&builds, range)?
    } else if let Some(n) = args.keep_last {
        select_keep_last(&builds, n)
    } else if let Some(dur) = args.older_than.as_deref() {
        select_older_than(&builds, dur)?
    } else {
        bail!("specify a range, --keep-last, or --older-than");
    };

    if let Some(cur) = current.as_deref() {
        if to_drop.iter().any(|b| b == cur) {
            bail!("refusing to prune current build_id: {cur}");
        }
    }

    if !args.dry_run {
        db.prune_builds(&to_drop)?;
    }
    for id in &to_drop {
        if !try_println(id) {
            return Ok(());
        }
    }
    Ok(())
}

/**
 * Resolve a `..X`, `X..Y`, or single-endpoint selector to the matching
 * build_ids from `builds` (sorted most-recent first).
 *
 * Endpoints are either a literal build_id (`YYYYMMDDTHHMMSSZ`) or an
 * ISO date (`YYYY-MM-DD`).  Dates expand to inclusive day boundaries:
 * a date used as an upper bound matches anything up to and including
 * 23:59:59 that day; as a lower bound, from 00:00:00.
 */
fn select_range(builds: &[bob::db::BuildListEntry], range: &str) -> Result<Vec<String>> {
    let (lower, upper) = if let Some((lhs, rhs)) = range.split_once("..") {
        if rhs.is_empty() {
            bail!("open-ended ranges (X..) are not supported");
        }
        let lower = if lhs.is_empty() {
            None
        } else {
            Some(normalize_endpoint(lhs, Bound::Lower)?)
        };
        let upper = Some(normalize_endpoint(rhs, Bound::Upper)?);
        (lower, upper)
    } else {
        (
            Some(normalize_endpoint(range, Bound::Lower)?),
            Some(normalize_endpoint(range, Bound::Upper)?),
        )
    };

    let mut out: Vec<String> = builds
        .iter()
        .filter(|b| {
            lower.as_deref().is_none_or(|l| b.build_id.as_str() >= l)
                && upper.as_deref().is_none_or(|u| b.build_id.as_str() <= u)
        })
        .map(|b| b.build_id.clone())
        .collect();
    out.reverse();
    Ok(out)
}

fn select_keep_last(builds: &[bob::db::BuildListEntry], n: usize) -> Vec<String> {
    let mut out: Vec<String> = builds.iter().skip(n).map(|b| b.build_id.clone()).collect();
    out.reverse();
    out
}

fn select_older_than(builds: &[bob::db::BuildListEntry], dur: &str) -> Result<Vec<String>> {
    let secs = bob::parse_duration_secs(dur).map_err(|e| anyhow::anyhow!(e))?;
    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(secs);
    let cutoff_id = cutoff.format(bob::BUILD_ID_FORMAT).to_string();
    let mut out: Vec<String> = builds
        .iter()
        .filter(|b| b.build_id.as_str() < cutoff_id.as_str())
        .map(|b| b.build_id.clone())
        .collect();
    out.reverse();
    Ok(out)
}

#[derive(Clone, Copy)]
enum Bound {
    Lower,
    Upper,
}

fn normalize_endpoint(s: &str, bound: Bound) -> Result<String> {
    if bob::parse_build_id(s).is_some() {
        return Ok(s.to_string());
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let suffix = match bound {
            Bound::Lower => "T000000Z",
            Bound::Upper => "T235959Z",
        };
        return Ok(format!("{}{}", date.format("%Y%m%d"), suffix));
    }
    bail!(
        "invalid endpoint '{}': expected build_id (YYYYMMDDTHHMMSSZ) or date (YYYY-MM-DD)",
        s
    );
}
