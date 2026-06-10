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

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use pkgsrc::ScanIndex;
use regex::Regex;

use bob::PackageState;
use bob::config::Config;
use bob::db::{Database, ScanIndexFields};
use bob::scan::Scan;
use bob::try_println;

/**
 * Compile a case-insensitive regex from a user-supplied package
 * pattern.  Used by commands like `bob log`, `bob list`, `bob status`,
 * and `bob history` to match packages by pkgname or pkgpath.
 *
 * The pattern is wrapped with `(?i)` so matching is case-insensitive
 * regardless of how the user wrote it.  Returns an error with the
 * offending pattern in the message if the regex is malformed.
 */
pub fn pkg_pattern(pattern: &str) -> Result<Regex> {
    Regex::new(&format!("(?i){}", pattern))
        .map_err(|e| anyhow!("Invalid pattern '{}': {}", pattern, e))
}

pub fn presolve(file: &PathBuf, output: Option<&PathBuf>, strict: bool, verbose: u8) -> Result<()> {
    let reader: Box<dyn std::io::BufRead> = if file.as_os_str() == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(
            File::open(file).with_context(|| format!("Failed to open {}", file.display()))?,
        ))
    };

    let mut scan_data = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for result in ScanIndex::from_reader(reader) {
        match result {
            Ok(index) => scan_data.push(index),
            Err(e) => errors.push(e.to_string()),
        }
    }

    if !errors.is_empty() {
        for err in &errors {
            eprintln!("{}", err);
        }
        eprintln!("Warning: {} record(s) failed to parse", errors.len());
    }

    let mut scan = Scan::default();
    scan.set_verbosity(verbose);
    let result = scan.resolve(scan_data.into_iter().map(Ok))?;

    let resolve_errors: Vec<_> = result.errors().collect();
    if !resolve_errors.is_empty() {
        eprintln!(
            "Unresolved dependencies:\n  {}",
            resolve_errors.join("\n  ")
        );
        if strict {
            bail!("Aborting due to scan/resolve errors (strict mode)");
        }
    }

    let mut out = String::new();
    for pkg in &result.packages {
        out.push_str(&pkg.to_string());
    }

    if let Some(path) = output {
        std::fs::write(path, &out)?;
        let c = result.counts();
        let s = &c.states;
        let skipped =
            s[PackageState::PreSkipped] + s[PackageState::PreFailed] + s[PackageState::Unresolved];
        eprintln!(
            "Wrote {} buildable, {} skipped to {}",
            c.buildable,
            skipped,
            path.display()
        );
    } else {
        print!("{}", out);
    }

    Ok(())
}

pub fn import_scan(config: &Config, file: &PathBuf, no_resolve: bool) -> Result<()> {
    let db = Database::open(config.dbdir())?;

    println!("Importing scan data from {}", file.display());

    let f = File::open(file).with_context(|| format!("Failed to open {}", file.display()))?;
    let reader = BufReader::new(f);

    let mut error_count: usize = 0;

    let tx = db.transaction()?;
    db.clear_scan()?;
    for result in ScanIndex::from_reader(reader) {
        match result {
            Ok(index) => {
                let pkgpath = index
                    .pkg_location
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                db.store_package(&pkgpath, &index).with_context(|| {
                    format!("Failed to store package {}", index.pkgname.pkgname())
                })?;
            }
            Err(e) => {
                eprintln!("{}", e);
                error_count += 1;
            }
        }
    }

    if error_count > 0 && config.strict_scan() {
        bail!("{} record(s) failed to parse", error_count);
    }
    tx.commit()?;

    if error_count > 0 {
        eprintln!(
            "Warning: {} record(s) failed to parse, continuing anyway",
            error_count
        );
    }

    if no_resolve {
        return Ok(());
    }

    let mut scan = Scan::new(config, None);
    let result = scan.resolve_with_report(&db, config.strict_scan())?;
    result.print_resolved();
    result.print_counts(None);

    Ok(())
}

pub fn print_presolve(config: &Config, output: Option<&PathBuf>, sort: bool) -> Result<()> {
    let db = Database::open(config.dbdir())?;

    let count = db.count_packages()?;
    if count == 0 {
        bail!("No cached scan data found. Run 'bob scan' first.");
    }

    let mut scan = Scan::new(config, None);
    scan.init_from_db(&db)?;

    let mut result = db.with_scan_data(ScanIndexFields::Full, |pull| {
        scan.resolve(std::iter::from_fn(|| pull().transpose()))
    })?;

    let errors: Vec<_> = result.errors().collect();
    if !errors.is_empty() {
        eprintln!("Scan/resolve errors:");
        for e in &errors {
            for line in e.lines() {
                eprintln!("  {line}");
            }
        }
    }

    if sort {
        result
            .packages
            .sort_by(|a, b| a.pkgname().cmp(&b.pkgname()));
    }

    if let Some(path) = output {
        let mut w = BufWriter::new(File::create(path)?);
        for pkg in &result.packages {
            write!(w, "{pkg}")?;
        }
        w.flush()?;
        let c = result.counts();
        let s = &c.states;
        let skipped =
            s[PackageState::PreSkipped] + s[PackageState::PreFailed] + s[PackageState::Unresolved];
        eprintln!(
            "Wrote {} buildable, {} skipped to {}",
            c.buildable,
            skipped,
            path.display()
        );
    } else {
        for pkg in &result.packages {
            for line in pkg.to_string().lines() {
                if !try_println(line) {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}
