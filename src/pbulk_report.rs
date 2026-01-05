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

//! pbulk-compatible report generation.
//!
//! This module generates text reports and sends email reports in the exact
//! format produced by pbulk from pkgsrc. This is critical for compatibility
//! with tools like bulktracker that parse these reports.
//!
//! # Report Format
//!
//! The text report (`report.txt`) follows the pbulk format:
//!
//! ```text
//! pkgsrc bulk build report
//! ========================
//! Darwin 23.6.0/aarch64
//! Compiler: clang
//!
//! Build start: 2025-10-18 18:55
//! Build end:   2025-10-19 05:03
//!
//! Full report: https://example.com/report.html
//! Machine readable version: https://example.com/report.txt.xz
//!
//! Total number of packages:         28840
//! Successfully built:               23844
//! Failed to build:                   1750
//! Depending on failed package:       2203
//! Explicitly broken or masked:        750
//!   of which invalid dependencies:      0
//! Depending on masked package:        293
//!
//! Packages breaking the most other packages
//!
//! Package                             Breaks  Maintainer
//! -----------------------------------------------------------------------
//! devel/ruby-redmine                      13  ryoon@NetBSD.org
//! ...
//!
//! Packages with build failures
//!
//! Package                             Breaks  Maintainer
//! -----------------------------------------------------------------------
//! archivers/advancecomp                    0  pkgsrc-users@NetBSD.org
//! ...
//! ```
//!
//! # Email Format
//!
//! The email report uses the same text format as the body, with a subject line:
//! `<prefix> <os>/<arch> <timestamp>`
//!
//! # Usage
//!
//! ```no_run
//! use bob::{write_pbulk_report, send_pbulk_email, Database};
//! use std::path::Path;
//!
//! # fn example(db: &Database) -> anyhow::Result<()> {
//! let logdir = Path::new("/data/bob/logs");
//!
//! // Write report.txt file
//! write_pbulk_report(db, logdir, None)?;
//!
//! // Send email report
//! send_pbulk_email(
//!     db,
//!     logdir,
//!     "reports@example.com",
//!     "Build Bot",
//!     "me@example.com",
//!     "pkgsrc-trunk",
//!     None,
//!     None,
//! )?;
//! # Ok(())
//! # }
//! ```

use crate::build::{BuildOutcome, BuildResult};
use crate::db::Database;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Configuration for pbulk report generation.
pub struct ReportConfig {
    /// Base URL for full report (e.g., "https://reports.example.com/2025Q1")
    pub base_url: Option<String>,
    /// OS/arch string (e.g., "Darwin 23.6.0/aarch64")
    pub platform: Option<String>,
    /// Compiler string (e.g., "clang", "gcc")
    pub compiler: Option<String>,
}

/// Statistics for the build report.
struct BuildStats {
    total: usize,
    succeeded: usize,
    failed: usize,
    depending_on_failed: usize,
    broken_or_masked: usize,
    invalid_deps: usize,
    depending_on_masked: usize,
}

/// Information about a failed package for reporting.
struct FailedPackage {
    pkgpath: String,
    _pkgname: String,
    breaks_count: usize,
    maintainer: String,
}

/// Generate a pbulk-compatible text report.
///
/// This creates a `report.txt` file in the logdir that is 100% compatible
/// with the format produced by pbulk.
///
/// # Arguments
///
/// * `db` - Database containing build results
/// * `logdir` - Directory for logs and reports
/// * `config` - Optional configuration for URLs and platform info
pub fn write_pbulk_report(
    db: &Database,
    logdir: &Path,
    config: Option<&ReportConfig>,
) -> Result<()> {
    let report_path = logdir.join("report.txt");
    let mut file = fs::File::create(&report_path)
        .context("Failed to create report.txt")?;

    let report_text = generate_report_text(db, config)?;
    file.write_all(report_text.as_bytes())
        .context("Failed to write report.txt")?;

    Ok(())
}

/// Generate the text content for a pbulk report.
fn generate_report_text(
    db: &Database,
    config: Option<&ReportConfig>,
) -> Result<String> {
    let mut report = String::new();

    // Header
    report.push_str("pkgsrc bulk build report\n");
    report.push_str("========================\n");

    // Platform info
    if let Some(platform) = config.and_then(|c| c.platform.as_ref()) {
        report.push_str(platform);
        report.push('\n');
    } else {
        report.push_str(&get_platform_string());
        report.push('\n');
    }

    // Compiler info
    if let Some(compiler) = config.and_then(|c| c.compiler.as_ref()) {
        report.push_str("Compiler: ");
        report.push_str(compiler);
        report.push('\n');
    }

    report.push('\n');

    // Build timestamps
    write_timestamps(&mut report, db)?;
    report.push('\n');

    // URLs
    if let Some(base_url) = config.and_then(|c| c.base_url.as_ref()) {
        report.push_str("Full report: ");
        report.push_str(base_url);
        report.push_str("/report.html\n");
        report.push_str("Machine readable version: ");
        report.push_str(base_url);
        report.push_str("/report.txt.xz\n\n");
    }

    // Statistics
    let stats = calculate_stats(db)?;
    write_stats(&mut report, &stats);
    report.push('\n');

    // Breaking packages table
    let failed_packages = get_failed_packages(db)?;
    write_breaking_packages(&mut report, &failed_packages);
    report.push('\n');

    // All failures table
    write_all_failures(&mut report, &failed_packages);

    Ok(report)
}

/// Get platform string (OS/arch).
fn get_platform_string() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    // Try to get more detailed OS version
    #[cfg(target_os = "linux")]
    {
        if let Ok(release) = fs::read_to_string("/etc/os-release") {
            for line in release.lines() {
                if let Some(name) = line.strip_prefix("PRETTY_NAME=") {
                    let name = name.trim_matches('"');
                    return format!("{}/{}", name, arch);
                }
            }
        }
    }

    format!("{}/{}", os, arch)
}

/// Write build timestamps to the report.
fn write_timestamps(report: &mut String, db: &Database) -> Result<()> {
    use std::fmt::Write;

    // Get earliest and latest build timestamps
    let (start_time, end_time) = db.get_build_timestamps()?;

    if let Some(start) = start_time {
        let start_dt = chrono::DateTime::from_timestamp(start, 0)
            .unwrap_or_else(|| chrono::Utc::now().into());
        write!(
            report,
            "Build start: {}\n",
            start_dt.format("%Y-%m-%d %H:%M")
        )?;
    }

    if let Some(end) = end_time {
        let end_dt = chrono::DateTime::from_timestamp(end, 0)
            .unwrap_or_else(|| chrono::Utc::now().into());
        write!(
            report,
            "Build end:   {}\n",
            end_dt.format("%Y-%m-%d %H:%M")
        )?;
    }

    Ok(())
}

/// Calculate build statistics.
fn calculate_stats(db: &Database) -> Result<BuildStats> {
    let mut results = db.get_all_build_results()?;

    // Add pre-failed packages
    for (pkgname, pkgpath, reason) in db.get_prefailed_packages()? {
        results.push(BuildResult {
            pkgname: pkgsrc::PkgName::new(&pkgname),
            pkgpath: pkgpath.and_then(|p| pkgsrc::PkgPath::new(&p).ok()),
            outcome: BuildOutcome::PreFailed(reason),
            duration: std::time::Duration::ZERO,
            log_dir: None,
        });
    }

    // Add indirect failures
    for (pkgname, pkgpath, failed_dep) in db.get_indirect_failures()? {
        results.push(BuildResult {
            pkgname: pkgsrc::PkgName::new(&pkgname),
            pkgpath: pkgpath.and_then(|p| pkgsrc::PkgPath::new(&p).ok()),
            outcome: BuildOutcome::IndirectFailed(failed_dep),
            duration: std::time::Duration::ZERO,
            log_dir: None,
        });
    }

    let total = results.len();
    let succeeded = results
        .iter()
        .filter(|r| matches!(r.outcome, BuildOutcome::Success))
        .count();
    let failed = results
        .iter()
        .filter(|r| matches!(r.outcome, BuildOutcome::Failed(_)))
        .count();
    let depending_on_failed = results
        .iter()
        .filter(|r| matches!(r.outcome, BuildOutcome::IndirectFailed(_)))
        .count();
    let broken_or_masked = results
        .iter()
        .filter(|r| matches!(r.outcome, BuildOutcome::PreFailed(_)))
        .count();

    Ok(BuildStats {
        total,
        succeeded,
        failed,
        depending_on_failed,
        broken_or_masked,
        invalid_deps: 0, // Not tracked currently
        depending_on_masked: 0, // Not distinguished from depending_on_failed
    })
}

/// Write statistics section.
fn write_stats(report: &mut String, stats: &BuildStats) {
    use std::fmt::Write;

    write!(
        report,
        "Total number of packages:     {:>10}\n",
        stats.total
    )
    .unwrap();
    write!(
        report,
        "Successfully built:           {:>10}\n",
        stats.succeeded
    )
    .unwrap();
    write!(
        report,
        "Failed to build:              {:>10}\n",
        stats.failed
    )
    .unwrap();
    write!(
        report,
        "Depending on failed package:  {:>10}\n",
        stats.depending_on_failed
    )
    .unwrap();
    write!(
        report,
        "Explicitly broken or masked:  {:>10}\n",
        stats.broken_or_masked
    )
    .unwrap();
    write!(
        report,
        "  of which invalid dependencies: {:>7}\n",
        stats.invalid_deps
    )
    .unwrap();
    write!(
        report,
        "Depending on masked package:  {:>10}\n",
        stats.depending_on_masked
    )
    .unwrap();
}

/// Get failed packages with breaks counts and maintainer info.
fn get_failed_packages(db: &Database) -> Result<Vec<FailedPackage>> {
    let breaks_counts = db.count_breaks_for_failed()?;
    let mut failed = Vec::new();

    // Get all build results
    let results = db.get_all_build_results()?;

    for result in results {
        if matches!(result.outcome, BuildOutcome::Failed(_)) {
            let pkgname = result.pkgname.to_string();
            let pkgpath = result
                .pkgpath
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_default();

            // Get maintainer from scan data
            let maintainer = if let Some(package_id) = db.get_package_id(&pkgname)? {
                get_maintainer(db, package_id).unwrap_or_else(|_| {
                    "pkgsrc-users@NetBSD.org".to_string()
                })
            } else {
                "pkgsrc-users@NetBSD.org".to_string()
            };

            let breaks_count = breaks_counts.get(&pkgname).copied().unwrap_or(0);

            failed.push(FailedPackage {
                pkgpath,
                _pkgname: pkgname,
                breaks_count,
                maintainer,
            });
        }
    }

    // Sort by breaks_count descending, then by pkgpath
    failed.sort_by(|a, b| {
        b.breaks_count
            .cmp(&a.breaks_count)
            .then_with(|| a.pkgpath.cmp(&b.pkgpath))
    });

    Ok(failed)
}

/// Get maintainer for a package.
fn get_maintainer(db: &Database, package_id: i64) -> Result<String> {
    let scan_index = db.get_full_scan_index(package_id)?;
    Ok(scan_index
        .maintainer
        .unwrap_or_else(|| "pkgsrc-users@NetBSD.org".to_string()))
}

/// Write breaking packages section (top packages by breaks count).
fn write_breaking_packages(report: &mut String, failed: &[FailedPackage]) {
    report.push_str("Packages breaking the most other packages\n\n");
    report.push_str("Package                             Breaks  Maintainer\n");
    report.push_str("-----------------------------------------------------------------------\n");

    // Show top packages that break others (breaks_count > 0)
    for pkg in failed.iter().filter(|p| p.breaks_count > 0).take(20) {
        report.push_str(&format!(
            "{:<35} {:>6}  {}\n",
            pkg.pkgpath, pkg.breaks_count, pkg.maintainer
        ));
    }
}

/// Write all failures section.
fn write_all_failures(report: &mut String, failed: &[FailedPackage]) {
    report.push_str("Packages with build failures\n\n");
    report.push_str("Package                             Breaks  Maintainer\n");
    report.push_str("-----------------------------------------------------------------------\n");

    // Group by category
    let mut by_category: HashMap<String, Vec<&FailedPackage>> = HashMap::new();

    for pkg in failed {
        let category = pkg
            .pkgpath
            .split('/')
            .next()
            .unwrap_or("unknown")
            .to_string();
        by_category.entry(category).or_default().push(pkg);
    }

    // Sort categories and write
    let mut categories: Vec<_> = by_category.keys().collect();
    categories.sort();

    for category in categories {
        if let Some(packages) = by_category.get(category) {
            for pkg in packages {
                report.push_str(&format!(
                    "{:<35} {:>6}  {}\n",
                    pkg.pkgpath, pkg.breaks_count, pkg.maintainer
                ));
            }
        }
    }
}

/// Send a pbulk-compatible email report.
///
/// # Arguments
///
/// * `db` - Database containing build results
/// * `logdir` - Directory for logs
/// * `from_addr` - Sender email address
/// * `from_name` - Sender display name
/// * `to_addr` - Recipient email address
/// * `subject_prefix` - Subject line prefix (e.g., "pkgsrc-trunk")
/// * `smtp_server` - SMTP server address (e.g., "localhost:25")
/// * `config` - Optional configuration for URLs and platform info
pub fn send_pbulk_email(
    db: &Database,
    _logdir: &Path,
    from_addr: &str,
    from_name: &str,
    to_addr: &str,
    subject_prefix: &str,
    smtp_server: Option<&str>,
    config: Option<&ReportConfig>,
) -> Result<()> {
    let report_text = generate_report_text(db, config)?;

    // Generate subject line: "<prefix> <platform> <timestamp>"
    let platform = config
        .and_then(|c| c.platform.as_ref())
        .cloned()
        .unwrap_or_else(get_platform_string);

    // Get latest build timestamp for subject
    let (_, end_time) = db.get_build_timestamps()?;

    let timestamp = if let Some(end) = end_time {
        let end_dt = chrono::DateTime::from_timestamp(end, 0)
            .unwrap_or_else(|| chrono::Utc::now().into());
        end_dt.format("%Y-%m-%d %H:%M").to_string()
    } else {
        chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string()
    };

    let subject = format!("{} {} {}", subject_prefix, platform, timestamp);

    // Send email using sendmail or SMTP
    send_email(
        from_addr,
        from_name,
        to_addr,
        &subject,
        &report_text,
        smtp_server,
    )?;

    Ok(())
}

/// Send email via sendmail or SMTP.
fn send_email(
    from_addr: &str,
    from_name: &str,
    to_addr: &str,
    subject: &str,
    body: &str,
    _smtp_server: Option<&str>,
) -> Result<()> {
    use lettre::message::{header, Message};
    use lettre::transport::sendmail::SendmailTransport;
    use lettre::Transport;

    // Create email message
    let email = Message::builder()
        .from(format!("{} <{}>", from_name, from_addr).parse()?)
        .to(to_addr.parse()?)
        .subject(subject)
        .header(header::ContentType::TEXT_PLAIN)
        .body(body.to_string())?;

    // Send via sendmail (SMTP not currently supported)
    // Note: smtp_server parameter is ignored for now
    let mailer = SendmailTransport::new();
    mailer.send(&email)?;

    Ok(())
}
