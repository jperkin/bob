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

//! HTML build report generation.
//!
//! This module generates HTML reports summarizing build results. Reports include:
//!
//! - Summary statistics (succeeded, failed, skipped counts)
//! - Failed packages with links to build logs
//! - Skipped packages with reasons
//! - Successfully built packages with build times
//!
//! # Report Structure
//!
//! The generated HTML report is self-contained with embedded CSS and JavaScript.
//! Tables are sortable by clicking column headers.
//!
//! ## Failed Packages Section
//!
//! Shows packages that failed to build, sorted by the number of other packages
//! they block. Each entry includes:
//!
//! - Package name and path
//! - Number of packages blocked by this failure
//! - The build phase where failure occurred
//! - Links to individual phase logs
//!
//! ## Skipped Packages Section
//!
//! Shows packages that were not built, with the reason for skipping
//! (e.g., "Dependency X failed", "up-to-date").
//!
//! ## Successful Packages Section
//!
//! Shows all successfully built packages with their build duration.

use crate::build::{BuildOutcome, BuildResult, BuildSummary};
use crate::db::Database;
use crate::scan::SkipReason;
use anyhow::Result;
use pkgsrc::PkgPath;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Build phases in order, with their log file names.
const BUILD_PHASES: &[(&str, &str)] = &[
    ("pre-clean", "pre-clean.log"),
    ("depends", "depends.log"),
    ("checksum", "checksum.log"),
    ("configure", "configure.log"),
    ("build", "build.log"),
    ("install", "install.log"),
    ("package", "package.log"),
    ("deinstall", "deinstall.log"),
    ("clean", "clean.log"),
];

/// Information about a failed package for reporting.
struct FailedPackageInfo<'a> {
    result: &'a BuildResult,
    breaks_count: usize,
    failed_phase: Option<String>,
    failed_log: Option<String>,
}

/// Read the failed phase from the .stage file in the log directory.
fn read_failed_phase(log_dir: &Path) -> Option<String> {
    let stage_file = log_dir.join(".stage");
    fs::read_to_string(stage_file)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Generate an HTML build report from database.
///
/// Reads build results from the database, ensuring accurate duration and
/// breaks counts even for interrupted or resumed builds.
pub fn write_html_report(db: &Database, logdir: &Path, path: &Path) -> Result<()> {
    let mut results = db.get_all_build_results()?;
    let breaks_counts = db.count_breaks_for_failed()?;
    let duration = db.get_total_build_duration()?;

    // Add pre-failed packages (those with skip_reason or fail_reason)
    for (pkgname, pkgpath, reason) in db.get_prefailed_packages()? {
        results.push(BuildResult {
            pkgname: pkgsrc::PkgName::new(&pkgname),
            pkgpath: pkgpath.and_then(|p| pkgsrc::PkgPath::new(&p).ok()),
            outcome: BuildOutcome::Skipped(SkipReason::PkgFail(reason)),
            duration: std::time::Duration::ZERO,
            log_dir: None,
        });
    }

    // Add calculated indirect failures for packages without build results
    for (pkgname, pkgpath, failed_dep) in db.get_indirect_failures()? {
        results.push(BuildResult {
            pkgname: pkgsrc::PkgName::new(&pkgname),
            pkgpath: pkgpath.and_then(|p| pkgsrc::PkgPath::new(&p).ok()),
            outcome: BuildOutcome::Skipped(SkipReason::IndirectFail(failed_dep)),
            duration: std::time::Duration::ZERO,
            log_dir: None,
        });
    }

    let summary = BuildSummary {
        duration,
        results,
        scanfail: Vec::new(),
    };

    write_report_impl(&summary, &breaks_counts, logdir, path)
}

/// Internal implementation for report generation.
fn write_report_impl(
    summary: &BuildSummary,
    breaks_counts: &HashMap<String, usize>,
    logdir: &Path,
    path: &Path,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = fs::File::create(path)?;

    // Collect and sort results
    let mut succeeded: Vec<&BuildResult> = summary.succeeded();
    let mut skipped: Vec<&BuildResult> = summary
        .results
        .iter()
        .filter(|r| matches!(r.outcome, BuildOutcome::UpToDate | BuildOutcome::Skipped(_)))
        .collect();

    // Collect failed packages with additional info
    let mut failed_info: Vec<FailedPackageInfo> = summary
        .failed()
        .into_iter()
        .map(|result| {
            let breaks_count = breaks_counts
                .get(result.pkgname.pkgname())
                .copied()
                .unwrap_or(0);
            let pkg_log_dir = logdir.join(result.pkgname.pkgname());
            let failed_phase = read_failed_phase(&pkg_log_dir);
            let failed_log = failed_phase.as_ref().and_then(|phase| {
                BUILD_PHASES
                    .iter()
                    .find(|(name, _)| *name == phase)
                    .map(|(_, log)| (*log).to_string())
            });
            FailedPackageInfo {
                result,
                breaks_count,
                failed_phase,
                failed_log,
            }
        })
        .collect();

    // Sort failed by breaks_count descending, then by name
    failed_info.sort_by(|a, b| {
        b.breaks_count
            .cmp(&a.breaks_count)
            .then_with(|| a.result.pkgname.pkgname().cmp(b.result.pkgname.pkgname()))
    });

    succeeded.sort_by(|a, b| a.pkgname.pkgname().cmp(b.pkgname.pkgname()));
    skipped.sort_by(|a, b| a.pkgname.pkgname().cmp(b.pkgname.pkgname()));

    // Write HTML header
    writeln!(file, "<!DOCTYPE html>")?;
    writeln!(file, "<html lang=\"en\">")?;
    writeln!(file, "<head>")?;
    writeln!(file, "  <meta charset=\"UTF-8\">")?;
    writeln!(
        file,
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
    )?;
    writeln!(file, "  <title>pkgsrc Build Report</title>")?;
    write_styles(&mut file)?;
    write_sort_script(&mut file)?;
    writeln!(file, "</head>")?;
    writeln!(file, "<body>")?;
    writeln!(file, "<div class=\"container\">")?;

    // Header with pkgsrc logo
    writeln!(file, "<div class=\"header\">")?;
    writeln!(
        file,
        "  <img src=\"https://www.pkgsrc.org/img/pkgsrc-square.png\" alt=\"pkgsrc\" class=\"logo\">"
    )?;
    writeln!(file, "  <h1>Build Report</h1>")?;
    writeln!(file, "</div>")?;

    // Summary stats
    write_summary_stats(&mut file, summary)?;

    // Failed packages section
    write_failed_section(&mut file, &failed_info, logdir)?;

    // Scan failed section (if any)
    if !summary.scanfail.is_empty() {
        write_scanfail_section(&mut file, &summary.scanfail)?;
    }

    // Skipped packages section
    write_skipped_section(&mut file, &skipped)?;

    // Successful packages section
    write_success_section(&mut file, &succeeded, logdir)?;

    // Footer
    writeln!(
        file,
        "<p style=\"color: #666; font-size: 0.9em; text-align: center; margin-top: 40px;\">"
    )?;
    writeln!(
        file,
        "  Generated by <a href=\"https://github.com/jperkin/bob\">bob</a>"
    )?;
    writeln!(file, "</p>")?;

    writeln!(file, "</div>")?;
    writeln!(file, "</body>")?;
    writeln!(file, "</html>")?;

    Ok(())
}

fn write_styles(file: &mut fs::File) -> Result<()> {
    writeln!(file, "  <style>")?;
    writeln!(
        file,
        "    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #fff; }}"
    )?;
    writeln!(
        file,
        "    .container {{ max-width: 1400px; margin: 0 auto; }}"
    )?;
    writeln!(
        file,
        "    .header {{ display: flex; align-items: center; gap: 20px; margin-bottom: 20px; padding-bottom: 20px; border-bottom: 3px solid #f37021; }}"
    )?;
    writeln!(file, "    .logo {{ height: 48px; }}")?;
    writeln!(file, "    h1 {{ color: #f37021; margin: 0; }}")?;
    writeln!(
        file,
        "    .summary {{ display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }}"
    )?;
    writeln!(
        file,
        "    .stat {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 150px; }}"
    )?;
    writeln!(
        file,
        "    .stat h2 {{ margin: 0 0 10px 0; font-size: 14px; color: #666; text-transform: uppercase; }}"
    )?;
    writeln!(
        file,
        "    .stat .value {{ font-size: 36px; font-weight: bold; }}"
    )?;
    writeln!(file, "    .stat.success .value {{ color: #28a745; }}")?;
    writeln!(file, "    .stat.failed .value {{ color: #dc3545; }}")?;
    writeln!(file, "    .stat.skipped .value {{ color: #ffc107; }}")?;
    writeln!(file, "    .stat.scan-failed .value {{ color: #fd7e14; }}")?;
    writeln!(
        file,
        "    .stat.duration .value {{ color: #17a2b8; font-size: 24px; }}"
    )?;
    writeln!(
        file,
        "    .section {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}"
    )?;
    writeln!(
        file,
        "    .section h2 {{ margin-top: 0; border-bottom: 2px solid #eee; padding-bottom: 10px; }}"
    )?;
    writeln!(
        file,
        "    .section.success h2 {{ color: #28a745; border-color: #28a745; }}"
    )?;
    writeln!(
        file,
        "    .section.failed h2 {{ color: #dc3545; border-color: #dc3545; }}"
    )?;
    writeln!(
        file,
        "    .section.skipped h2 {{ color: #856404; border-color: #ffc107; }}"
    )?;
    writeln!(
        file,
        "    .section.scan-failed h2 {{ color: #fd7e14; border-color: #fd7e14; }}"
    )?;
    writeln!(
        file,
        "    table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}"
    )?;
    writeln!(
        file,
        "    th, td {{ text-align: left; padding: 12px 8px; border-bottom: 1px solid #eee; }}"
    )?;
    writeln!(
        file,
        "    th {{ background: #ffeee6; font-weight: 600; cursor: pointer; user-select: none; }}"
    )?;
    writeln!(file, "    th:hover {{ background: #ffddc9; }}")?;
    writeln!(
        file,
        "    th .sort-indicator {{ margin-left: 5px; color: #999; }}"
    )?;
    writeln!(
        file,
        "    th.sort-asc .sort-indicator::after {{ content: ' ▲'; }}"
    )?;
    writeln!(
        file,
        "    th.sort-desc .sort-indicator::after {{ content: ' ▼'; }}"
    )?;
    writeln!(file, "    tr:hover {{ background: #fef6f3; }}")?;
    writeln!(file, "    a {{ color: #d35400; text-decoration: none; }}")?;
    writeln!(file, "    a:hover {{ text-decoration: underline; }}")?;
    writeln!(file, "    .reason {{ color: #666; font-size: 0.9em; }}")?;
    writeln!(file, "    .duration {{ color: #666; font-size: 0.9em; }}")?;
    writeln!(file, "    .empty {{ color: #666; font-style: italic; }}")?;
    writeln!(
        file,
        "    .phase-links {{ display: flex; gap: 6px; flex-wrap: wrap; }}"
    )?;
    writeln!(
        file,
        "    .phase-link {{ padding: 2px 8px; border-radius: 4px; font-size: 0.85em; background: #ffeee6; }}"
    )?;
    writeln!(file, "    .phase-link:hover {{ background: #ffddc9; }}")?;
    writeln!(
        file,
        "    .phase-link.failed {{ background: #f8d7da; color: #721c24; font-weight: bold; }}"
    )?;
    writeln!(
        file,
        "    .breaks-count {{ font-weight: bold; color: #dc3545; }}"
    )?;
    writeln!(file, "    .breaks-zero {{ color: #666; }}")?;
    writeln!(file, "  </style>")?;
    Ok(())
}

fn write_sort_script(file: &mut fs::File) -> Result<()> {
    writeln!(file, "  <script>")?;
    writeln!(file, "    function sortTable(table, colIdx, type) {{")?;
    writeln!(file, "      const tbody = table.querySelector('tbody');")?;
    writeln!(
        file,
        "      const rows = Array.from(tbody.querySelectorAll('tr'));"
    )?;
    writeln!(
        file,
        "      const th = table.querySelectorAll('th')[colIdx];"
    )?;
    writeln!(
        file,
        "      const isAsc = th.classList.contains('sort-asc');"
    )?;
    writeln!(file, "      ")?;
    writeln!(file, "      // Remove sort classes from all headers")?;
    writeln!(
        file,
        "      table.querySelectorAll('th').forEach(h => h.classList.remove('sort-asc', 'sort-desc'));"
    )?;
    writeln!(file, "      ")?;
    writeln!(file, "      // Add appropriate class to clicked header")?;
    writeln!(
        file,
        "      th.classList.add(isAsc ? 'sort-desc' : 'sort-asc');"
    )?;
    writeln!(file, "      ")?;
    writeln!(file, "      rows.sort((a, b) => {{")?;
    writeln!(
        file,
        "        let aVal = a.cells[colIdx].getAttribute('data-sort') || a.cells[colIdx].textContent;"
    )?;
    writeln!(
        file,
        "        let bVal = b.cells[colIdx].getAttribute('data-sort') || b.cells[colIdx].textContent;"
    )?;
    writeln!(file, "        ")?;
    writeln!(file, "        if (type === 'num') {{")?;
    writeln!(file, "          aVal = parseFloat(aVal) || 0;")?;
    writeln!(file, "          bVal = parseFloat(bVal) || 0;")?;
    writeln!(file, "          return isAsc ? bVal - aVal : aVal - bVal;")?;
    writeln!(file, "        }} else {{")?;
    writeln!(
        file,
        "          return isAsc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);"
    )?;
    writeln!(file, "        }}")?;
    writeln!(file, "      }});")?;
    writeln!(file, "      ")?;
    writeln!(file, "      rows.forEach(row => tbody.appendChild(row));")?;
    writeln!(file, "    }}")?;
    writeln!(file, "  </script>")?;
    Ok(())
}

fn write_summary_stats(file: &mut fs::File, summary: &BuildSummary) -> Result<()> {
    let duration_secs = summary.duration.as_secs();
    let hours = duration_secs / 3600;
    let minutes = (duration_secs % 3600) / 60;
    let seconds = duration_secs % 60;
    let duration_str = if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    };

    let c = summary.counts();
    let s = &c.skipped;
    let skipped_count =
        c.up_to_date + s.pkg_skip + s.pkg_fail + s.unresolved + s.indirect_skip + s.indirect_fail;
    writeln!(file, "<div class=\"summary\">")?;
    writeln!(
        file,
        "  <div class=\"stat success\"><h2>Succeeded</h2><div class=\"value\">{}</div></div>",
        c.success
    )?;
    writeln!(
        file,
        "  <div class=\"stat failed\"><h2>Failed</h2><div class=\"value\">{}</div></div>",
        c.failed
    )?;
    writeln!(
        file,
        "  <div class=\"stat skipped\"><h2>Skipped</h2><div class=\"value\">{}</div></div>",
        skipped_count
    )?;
    if c.scanfail > 0 {
        writeln!(
            file,
            "  <div class=\"stat scan-failed\"><h2>Scan Failed</h2><div class=\"value\">{}</div></div>",
            c.scanfail
        )?;
    }
    writeln!(
        file,
        "  <div class=\"stat duration\"><h2>Duration</h2><div class=\"value\">{}</div></div>",
        duration_str
    )?;
    writeln!(file, "</div>")?;
    Ok(())
}

fn generate_phase_links(pkg_name: &str, log_dir: &Path, failed_phase: Option<&str>) -> String {
    if !log_dir.exists() {
        return "-".to_string();
    }

    let mut links = Vec::new();
    for (phase_name, log_file) in BUILD_PHASES {
        let log_path = log_dir.join(log_file);
        if log_path.exists() {
            let is_failed = failed_phase == Some(*phase_name);
            let class = if is_failed {
                "phase-link failed"
            } else {
                "phase-link"
            };
            links.push(format!(
                "<a href=\"{}/{}\" class=\"{}\">{}</a>",
                pkg_name, log_file, class, phase_name
            ));
        }
    }
    if links.is_empty() {
        "-".to_string()
    } else {
        format!("<div class=\"phase-links\">{}</div>", links.join(""))
    }
}

fn write_failed_section(
    file: &mut fs::File,
    failed_info: &[FailedPackageInfo],
    logdir: &Path,
) -> Result<()> {
    writeln!(file, "<div class=\"section failed\">")?;
    writeln!(file, "  <h2>Failed Packages ({})</h2>", failed_info.len())?;

    if failed_info.is_empty() {
        writeln!(file, "  <p class=\"empty\">No failed packages</p>")?;
    } else {
        writeln!(file, "  <table id=\"failed-table\">")?;
        writeln!(file, "    <thead><tr>")?;
        writeln!(
            file,
            "      <th onclick=\"sortTable(document.getElementById('failed-table'), 0, 'str')\">Package<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(
            file,
            "      <th onclick=\"sortTable(document.getElementById('failed-table'), 1, 'str')\">Path<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(
            file,
            "      <th onclick=\"sortTable(document.getElementById('failed-table'), 2, 'num')\" class=\"sort-desc\">Breaks<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(
            file,
            "      <th onclick=\"sortTable(document.getElementById('failed-table'), 3, 'num')\">Duration<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(file, "      <th>Build Logs</th>")?;
        writeln!(file, "    </tr></thead>")?;
        writeln!(file, "    <tbody>")?;

        for info in failed_info {
            let pkg_name = info.result.pkgname.pkgname();
            let pkgpath = info
                .result
                .pkgpath
                .as_ref()
                .map(|p| p.as_path().display().to_string())
                .unwrap_or_default();

            let breaks_class = if info.breaks_count > 0 {
                "breaks-count"
            } else {
                "breaks-zero"
            };

            let dur_secs = info.result.duration.as_secs();
            let duration = if dur_secs >= 60 {
                format!("{}m {}s", dur_secs / 60, dur_secs % 60)
            } else {
                format!("{}s", dur_secs)
            };

            // Package name links to the failed log if available
            let pkg_link = match &info.failed_log {
                Some(log) => {
                    format!("<a href=\"{}/{}\">{}</a>", pkg_name, log, pkg_name)
                }
                None => pkg_name.to_string(),
            };

            let log_dir = logdir.join(pkg_name);
            let phase_links =
                generate_phase_links(pkg_name, &log_dir, info.failed_phase.as_deref());

            writeln!(
                file,
                "    <tr><td>{}</td><td>{}</td><td class=\"{}\" data-sort=\"{}\">{}</td><td class=\"duration\" data-sort=\"{}\">{}</td><td>{}</td></tr>",
                pkg_link,
                pkgpath,
                breaks_class,
                info.breaks_count,
                info.breaks_count,
                dur_secs,
                duration,
                phase_links
            )?;
        }

        writeln!(file, "    </tbody>")?;
        writeln!(file, "  </table>")?;
    }
    writeln!(file, "</div>")?;
    Ok(())
}

fn write_skipped_section(file: &mut fs::File, skipped: &[&BuildResult]) -> Result<()> {
    writeln!(file, "<div class=\"section skipped\">")?;
    writeln!(file, "  <h2>Skipped Packages ({})</h2>", skipped.len())?;

    if skipped.is_empty() {
        writeln!(file, "  <p class=\"empty\">No skipped packages</p>")?;
    } else {
        writeln!(file, "  <table id=\"skipped-table\">")?;
        writeln!(file, "    <thead><tr>")?;
        writeln!(
            file,
            "      <th onclick=\"sortTable(document.getElementById('skipped-table'), 0, 'str')\">Package<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(
            file,
            "      <th onclick=\"sortTable(document.getElementById('skipped-table'), 1, 'str')\">Path<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(
            file,
            "      <th onclick=\"sortTable(document.getElementById('skipped-table'), 2, 'str')\">Status<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(
            file,
            "      <th onclick=\"sortTable(document.getElementById('skipped-table'), 3, 'str')\">Reason<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(file, "    </tr></thead>")?;
        writeln!(file, "    <tbody>")?;

        for result in skipped {
            let (status, reason) = match &result.outcome {
                BuildOutcome::UpToDate => ("up-to-date", String::new()),
                BuildOutcome::Skipped(r) => (r.status(), r.to_string()),
                BuildOutcome::Success | BuildOutcome::Failed(_) => continue,
            };
            let pkgpath = result
                .pkgpath
                .as_ref()
                .map(|p| p.as_path().display().to_string())
                .unwrap_or_default();
            writeln!(
                file,
                "    <tr><td>{}</td><td>{}</td><td>{}</td><td class=\"reason\">{}</td></tr>",
                result.pkgname.pkgname(),
                pkgpath,
                status,
                reason
            )?;
        }

        writeln!(file, "    </tbody>")?;
        writeln!(file, "  </table>")?;
    }
    writeln!(file, "</div>")?;
    Ok(())
}

fn write_success_section(
    file: &mut fs::File,
    succeeded: &[&BuildResult],
    logdir: &Path,
) -> Result<()> {
    writeln!(file, "<div class=\"section success\">")?;
    writeln!(file, "  <h2>Successful Packages ({})</h2>", succeeded.len())?;

    if succeeded.is_empty() {
        writeln!(file, "  <p class=\"empty\">No successful packages</p>")?;
    } else {
        writeln!(file, "  <table id=\"success-table\">")?;
        writeln!(file, "    <thead><tr>")?;
        writeln!(
            file,
            "      <th onclick=\"sortTable(document.getElementById('success-table'), 0, 'str')\">Package<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(
            file,
            "      <th onclick=\"sortTable(document.getElementById('success-table'), 1, 'str')\">Path<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(
            file,
            "      <th onclick=\"sortTable(document.getElementById('success-table'), 2, 'num')\">Duration<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(file, "      <th>Build Logs</th>")?;
        writeln!(file, "    </tr></thead>")?;
        writeln!(file, "    <tbody>")?;

        for result in succeeded {
            let pkg_name = result.pkgname.pkgname();
            let pkgpath = result
                .pkgpath
                .as_ref()
                .map(|p| p.as_path().display().to_string())
                .unwrap_or_default();
            let dur_secs = result.duration.as_secs();
            let duration = if dur_secs >= 60 {
                format!("{}m {}s", dur_secs / 60, dur_secs % 60)
            } else {
                format!("{}s", dur_secs)
            };

            let log_dir = logdir.join(pkg_name);
            let phase_links = generate_phase_links(pkg_name, &log_dir, None);

            writeln!(
                file,
                "    <tr><td>{}</td><td>{}</td><td class=\"duration\" data-sort=\"{}\">{}</td><td>{}</td></tr>",
                pkg_name, pkgpath, dur_secs, duration, phase_links
            )?;
        }

        writeln!(file, "    </tbody>")?;
        writeln!(file, "  </table>")?;
    }
    writeln!(file, "</div>")?;
    Ok(())
}

fn write_scanfail_section(file: &mut fs::File, scanfail: &[(PkgPath, String)]) -> Result<()> {
    writeln!(file, "<div class=\"section scan-failed\">")?;
    writeln!(file, "  <h2>Scan Failed Packages ({})</h2>", scanfail.len())?;

    writeln!(file, "  <table id=\"scan-failed-table\">")?;
    writeln!(file, "    <thead><tr>")?;
    writeln!(
        file,
        "      <th onclick=\"sortTable(document.getElementById('scan-failed-table'), 0, 'str')\">Path<span class=\"sort-indicator\"></span></th>"
    )?;
    writeln!(
        file,
        "      <th onclick=\"sortTable(document.getElementById('scan-failed-table'), 1, 'str')\">Error<span class=\"sort-indicator\"></span></th>"
    )?;
    writeln!(file, "    </tr></thead>")?;
    writeln!(file, "    <tbody>")?;

    for (pkgpath, error_msg) in scanfail {
        let path_str = pkgpath.as_path().display().to_string();
        // Escape HTML in error message
        let error = error_msg
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        writeln!(
            file,
            "    <tr><td>{}</td><td class=\"reason\">{}</td></tr>",
            path_str, error
        )?;
    }

    writeln!(file, "    </tbody>")?;
    writeln!(file, "  </table>")?;
    writeln!(file, "</div>")?;
    Ok(())
}
