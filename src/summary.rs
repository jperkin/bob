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
 * Generate pkg_summary.gz and pkg_summary.zst for binary packages.
 *
 * This module provides functionality to generate compressed pkg_summary
 * files containing metadata for binary packages tracked in the database.
 */

use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use flate2::Compression;
use flate2::write::GzEncoder;
use pkgsrc::archive::BinaryPackage;
use rayon::prelude::*;
use tracing::{debug, warn};
use zstd::stream::raw::CParameter;

use crate::config::PkgsrcEnv;
use crate::db::Database;

/**
 * Generate pkg_summary.gz and pkg_summary.zst for all successful packages.
 *
 * Queries the database for packages with successful build outcomes, generates
 * Summary entries using pkgsrc::archive::BinaryPackage, and writes the
 * concatenated output to `PACKAGES/All/pkg_summary.{gz,zst}`.
 *
 * The gz and zst files are written in parallel.
 */
pub fn generate_pkg_summary(db: &Database, threads: usize) -> Result<()> {
    let pkgsrc_env = db.load_pkgsrc_env()?;
    let pkgnames = db.get_successful_packages()?;

    if pkgnames.is_empty() {
        debug!("No successful packages to include in pkg_summary");
        return Ok(());
    }

    let packages_dir = pkgsrc_env.packages.join("All");

    debug!(
        count = pkgnames.len(),
        dir = %packages_dir.display(),
        "Generating pkg_summary for packages"
    );

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .context("Failed to build thread pool for pkg_summary generation")?;

    let results: Vec<String> = pool.install(|| {
        pkgnames
            .par_iter()
            .filter_map(|pkgname| {
                let pkgfile = packages_dir.join(format!("{}.tgz", pkgname));
                generate_summary_entry(&pkgfile)
            })
            .collect()
    });

    write_pkg_summary(&pkgsrc_env, &results)
}

fn generate_summary_entry(pkgfile: &Path) -> Option<String> {
    if !pkgfile.exists() {
        warn!(path = %pkgfile.display(), "Package file not found");
        return None;
    }

    match BinaryPackage::open(pkgfile) {
        Ok(pkg) => match pkg.to_summary() {
            Ok(summary) => Some(format!("{}\n", summary)),
            Err(e) => {
                warn!(
                    path = %pkgfile.display(),
                    error = %e,
                    "Failed to generate summary"
                );
                None
            }
        },
        Err(e) => {
            warn!(
                path = %pkgfile.display(),
                error = %e,
                "Failed to open package"
            );
            None
        }
    }
}

fn write_pkg_summary(pkgsrc_env: &PkgsrcEnv, entries: &[String]) -> Result<()> {
    let all_dir = pkgsrc_env.packages.join("All");

    std::thread::scope(|s| {
        let gz = s.spawn(|| write_pkg_summary_gz(&all_dir, entries));
        let zst = s.spawn(|| write_pkg_summary_zst(&all_dir, entries));

        gz.join()
            .map_err(|_| anyhow::anyhow!("gz thread panicked"))??;
        zst.join()
            .map_err(|_| anyhow::anyhow!("zst thread panicked"))??;
        Ok(())
    })
}

fn write_pkg_summary_gz(dir: &Path, entries: &[String]) -> Result<()> {
    let path = dir.join("pkg_summary.gz");
    let file =
        File::create(&path).with_context(|| format!("Failed to create {}", path.display()))?;
    let mut encoder = GzEncoder::new(file, Compression::default());
    for entry in entries {
        encoder.write_all(entry.as_bytes())?;
    }
    encoder.finish()?;
    debug!(path = %path.display(), count = entries.len(), "pkg_summary.gz written");
    Ok(())
}

fn write_pkg_summary_zst(dir: &Path, entries: &[String]) -> Result<()> {
    let path = dir.join("pkg_summary.zst");
    let file =
        File::create(&path).with_context(|| format!("Failed to create {}", path.display()))?;
    let mut encoder = zstd::Encoder::new(file, 19)?;
    encoder.set_parameter(CParameter::EnableLongDistanceMatching(true))?;
    encoder.set_parameter(CParameter::WindowLog(25))?;
    for entry in entries {
        encoder.write_all(entry.as_bytes())?;
    }
    encoder.finish()?;
    debug!(path = %path.display(), count = entries.len(), "pkg_summary.zst written");
    Ok(())
}
