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

//! HTML build report generation.
//!
//! This module generates HTML reports summarizing build results. Reports include:
//!
//! - Summary statistics (succeeded, failed, skipped counts)
//! - Failed packages with links to build logs
//! - Skipped packages with reasons
//! - Successfully built packages with build times
//!
//! # Usage
//!
//! ```no_run
//! use bob::{write_html_report, BuildSummary};
//! use std::path::Path;
//!
//! # fn example(summary: &BuildSummary) -> anyhow::Result<()> {
//! write_html_report(summary, Path::new("/data/bob/logs/report.html"))?;
//! # Ok(())
//! # }
//! ```
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
use crate::scan::ScanFailure;
use anyhow::Result;
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
    ("clean", "clean.log"),
];

/// Information about a failed package for reporting.
struct FailedPackageInfo<'a> {
    result: &'a BuildResult,
    breaks_count: usize,
    failed_phase: Option<String>,
}

/// Count how many packages each failed package breaks.
fn count_broken_packages(summary: &BuildSummary) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();

    // Initialize counts for all failed packages
    for result in &summary.results {
        if matches!(result.outcome, BuildOutcome::Failed(_)) {
            counts.insert(result.pkgname.pkgname().to_string(), 0);
        }
    }

    // Count skipped packages that reference each failed package
    for result in &summary.results {
        if let BuildOutcome::Skipped(reason) = &result.outcome {
            // Parse "Dependency <pkgname> failed" pattern
            if reason.starts_with("Dependency ") && reason.ends_with(" failed")
            {
                let dep_name = reason
                    .strip_prefix("Dependency ")
                    .and_then(|s| s.strip_suffix(" failed"))
                    .unwrap_or("");
                if let Some(count) = counts.get_mut(dep_name) {
                    *count += 1;
                }
            }
        }
    }

    counts
}

/// Read the failed phase from the .stage file in the log directory.
fn read_failed_phase(log_dir: &Path) -> Option<String> {
    let stage_file = log_dir.join(".stage");
    fs::read_to_string(stage_file).ok().map(|s| s.trim().to_string())
}

/// Generate an HTML build report.
pub fn write_html_report(summary: &BuildSummary, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = fs::File::create(path)?;

    // Calculate broken package counts
    let broken_counts = count_broken_packages(summary);

    // Collect and sort results
    let mut succeeded: Vec<&BuildResult> = summary.succeeded();
    let mut skipped: Vec<&BuildResult> = summary.skipped();

    // Collect failed packages with additional info
    let mut failed_info: Vec<FailedPackageInfo> = summary
        .failed()
        .into_iter()
        .map(|result| {
            let breaks_count = broken_counts
                .get(result.pkgname.pkgname())
                .copied()
                .unwrap_or(0);
            let failed_phase =
                result.log_dir.as_ref().and_then(|dir| read_failed_phase(dir));
            FailedPackageInfo { result, breaks_count, failed_phase }
        })
        .collect();

    // Sort failed by breaks_count descending, then by name
    failed_info.sort_by(|a, b| {
        b.breaks_count.cmp(&a.breaks_count).then_with(|| {
            a.result.pkgname.pkgname().cmp(b.result.pkgname.pkgname())
        })
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
    writeln!(file, "  <title>Bob Build Report</title>")?;
    write_styles(&mut file)?;
    write_sort_script(&mut file)?;
    writeln!(file, "</head>")?;
    writeln!(file, "<body>")?;
    writeln!(file, "<div class=\"container\">")?;

    // Header
    writeln!(file, "<h1>Bob Build Report</h1>")?;

    // Summary stats
    write_summary_stats(&mut file, summary)?;

    // Failed packages section
    write_failed_section(&mut file, &failed_info)?;

    // Scan failed section (if any)
    if !summary.scan_failed.is_empty() {
        write_scan_failed_section(&mut file, &summary.scan_failed)?;
    }

    // Skipped packages section
    write_skipped_section(&mut file, &skipped)?;

    // Successful packages section
    write_success_section(&mut file, &succeeded)?;

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
        "    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #f5f5f5; }}"
    )?;
    writeln!(file, "    .container {{ max-width: 1400px; margin: 0 auto; }}")?;
    writeln!(file, "    h1 {{ color: #333; }}")?;
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
    writeln!(file, "    table {{ width: 100%; border-collapse: collapse; }}")?;
    writeln!(
        file,
        "    th, td {{ text-align: left; padding: 12px 8px; border-bottom: 1px solid #eee; }}"
    )?;
    writeln!(
        file,
        "    th {{ background: #f8f9fa; font-weight: 600; cursor: pointer; user-select: none; }}"
    )?;
    writeln!(file, "    th:hover {{ background: #e9ecef; }}")?;
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
    writeln!(file, "    tr:hover {{ background: #f8f9fa; }}")?;
    writeln!(file, "    a {{ color: #007bff; text-decoration: none; }}")?;
    writeln!(file, "    a:hover {{ text-decoration: underline; }}")?;
    writeln!(file, "    .reason {{ color: #666; font-size: 0.9em; }}")?;
    writeln!(file, "    .duration {{ color: #666; font-size: 0.9em; }}")?;
    writeln!(file, "    .empty {{ color: #666; font-style: italic; }}")?;
    writeln!(
        file,
        "    .phase-links {{ display: flex; gap: 8px; flex-wrap: wrap; }}"
    )?;
    writeln!(
        file,
        "    .phase-link {{ padding: 2px 8px; border-radius: 4px; font-size: 0.85em; background: #e9ecef; }}"
    )?;
    writeln!(file, "    .phase-link:hover {{ background: #dee2e6; }}")?;
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
    writeln!(file, "      const th = table.querySelectorAll('th')[colIdx];")?;
    writeln!(file, "      const isAsc = th.classList.contains('sort-asc');")?;
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

fn write_summary_stats(
    file: &mut fs::File,
    summary: &BuildSummary,
) -> Result<()> {
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

    writeln!(file, "<div class=\"summary\">")?;
    writeln!(
        file,
        "  <div class=\"stat success\"><h2>Succeeded</h2><div class=\"value\">{}</div></div>",
        summary.success_count()
    )?;
    writeln!(
        file,
        "  <div class=\"stat failed\"><h2>Failed</h2><div class=\"value\">{}</div></div>",
        summary.failed_count()
    )?;
    writeln!(
        file,
        "  <div class=\"stat skipped\"><h2>Skipped</h2><div class=\"value\">{}</div></div>",
        summary.skipped_count()
    )?;
    if summary.scan_failed_count() > 0 {
        writeln!(
            file,
            "  <div class=\"stat scan-failed\"><h2>Scan Failed</h2><div class=\"value\">{}</div></div>",
            summary.scan_failed_count()
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

fn write_failed_section(
    file: &mut fs::File,
    failed_info: &[FailedPackageInfo],
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
            "      <th onclick=\"sortTable(document.getElementById('failed-table'), 3, 'str')\">Failed Phase<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(file, "      <th>Build Logs</th>")?;
        writeln!(file, "    </tr></thead>")?;
        writeln!(file, "    <tbody>")?;

        for info in failed_info {
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

            let failed_phase = info.failed_phase.as_deref().unwrap_or("-");

            // Generate phase links (relative paths)
            let phase_links = if let Some(log_dir) = &info.result.log_dir {
                // Get the package name for relative path
                let pkg_name = info.result.pkgname.pkgname();
                let mut links = Vec::new();
                for (phase_name, log_file) in BUILD_PHASES {
                    let log_path = log_dir.join(log_file);
                    if log_path.exists() {
                        let is_failed =
                            info.failed_phase.as_deref() == Some(*phase_name);
                        let class = if is_failed {
                            "phase-link failed"
                        } else {
                            "phase-link"
                        };
                        // Relative link from report.html to pkg/logfile
                        links.push(format!(
                            "<a href=\"{}/{}\" class=\"{}\">{}</a>",
                            pkg_name, log_file, class, phase_name
                        ));
                    }
                }
                // Also add work.log if it exists
                let work_log = log_dir.join("work.log");
                if work_log.exists() {
                    links.push(format!(
                        "<a href=\"{}/work.log\" class=\"phase-link\">work</a>",
                        pkg_name
                    ));
                }
                if links.is_empty() {
                    "-".to_string()
                } else {
                    format!(
                        "<div class=\"phase-links\">{}</div>",
                        links.join("")
                    )
                }
            } else {
                "-".to_string()
            };

            writeln!(
                file,
                "    <tr><td>{}</td><td>{}</td><td class=\"{}\" data-sort=\"{}\">{}</td><td>{}</td><td>{}</td></tr>",
                info.result.pkgname.pkgname(),
                pkgpath,
                breaks_class,
                info.breaks_count,
                info.breaks_count,
                failed_phase,
                phase_links
            )?;
        }

        writeln!(file, "    </tbody>")?;
        writeln!(file, "  </table>")?;
    }
    writeln!(file, "</div>")?;
    Ok(())
}

fn write_skipped_section(
    file: &mut fs::File,
    skipped: &[&BuildResult],
) -> Result<()> {
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
            "      <th onclick=\"sortTable(document.getElementById('skipped-table'), 2, 'str')\">Reason<span class=\"sort-indicator\"></span></th>"
        )?;
        writeln!(file, "    </tr></thead>")?;
        writeln!(file, "    <tbody>")?;

        for result in skipped {
            let reason = match &result.outcome {
                BuildOutcome::Skipped(r) => r.as_str(),
                _ => "",
            };
            let pkgpath = result
                .pkgpath
                .as_ref()
                .map(|p| p.as_path().display().to_string())
                .unwrap_or_default();
            writeln!(
                file,
                "    <tr><td>{}</td><td>{}</td><td class=\"reason\">{}</td></tr>",
                result.pkgname.pkgname(),
                pkgpath,
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
        writeln!(file, "    </tr></thead>")?;
        writeln!(file, "    <tbody>")?;

        for result in succeeded {
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
            writeln!(
                file,
                "    <tr><td>{}</td><td>{}</td><td class=\"duration\" data-sort=\"{}\">{}</td></tr>",
                result.pkgname.pkgname(),
                pkgpath,
                dur_secs,
                duration
            )?;
        }

        writeln!(file, "    </tbody>")?;
        writeln!(file, "  </table>")?;
    }
    writeln!(file, "</div>")?;
    Ok(())
}

fn write_scan_failed_section(
    file: &mut fs::File,
    scan_failed: &[ScanFailure],
) -> Result<()> {
    writeln!(file, "<div class=\"section scan-failed\">")?;
    writeln!(file, "  <h2>Scan Failed Packages ({})</h2>", scan_failed.len())?;

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

    for failure in scan_failed {
        let pkgpath = failure.pkgpath.as_path().display().to_string();
        // Escape HTML in error message
        let error = failure
            .error
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        writeln!(
            file,
            "    <tr><td>{}</td><td class=\"reason\">{}</td></tr>",
            pkgpath, error
        )?;
    }

    writeln!(file, "    </tbody>")?;
    writeln!(file, "  </table>")?;
    writeln!(file, "</div>")?;
    Ok(())
}
