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

mod action;
mod build;
mod config;
mod init;
mod logging;
mod report;
mod sandbox;
mod scan;
mod status;
mod tui;

use crate::build::Build;
use crate::config::Config;
use crate::init::Init;
use crate::sandbox::Sandbox;
use crate::scan::{Scan, SkipReason};
use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Use the specified configuration file instead of the default path
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Build all packages as defined by the configuration file
    Build,
    /// Generate HTML report from existing bulklog data
    GenerateReport,
    /// Create a new configuration area
    Init { dir: PathBuf },
    /// Create and destroy build sandboxes
    Sandbox {
        #[command(subcommand)]
        cmd: SandboxCmd,
    },
    /// Scan packages as defined by the configuration file
    Scan,
}

#[derive(Debug, Subcommand)]
enum SandboxCmd {
    /// Create all sandboxes
    Create,
    /// Destroy all sandboxes
    Destroy,
    /// List currently created sandboxes
    List,
}

fn print_summary(summary: &build::BuildSummary) {
    println!();
    println!("Build Summary");
    println!("=============");
    println!("  Succeeded: {}", summary.success_count());
    println!("  Failed:    {}", summary.failed_count());
    println!("  Skipped:   {}", summary.skipped_count());
    println!();
}

/// Scan the bulklog directory to reconstruct build results for report generation.
fn scan_bulklog_for_report(bulklog: &Path) -> Result<build::BuildSummary> {
    use std::fs;
    use std::time::Duration;

    let mut results = Vec::new();

    for entry in fs::read_dir(bulklog)? {
        let entry = entry?;
        let path = entry.path();

        // Skip non-directories (report.html, etc.)
        if !path.is_dir() {
            continue;
        }

        let pkg_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        // Check for .stage file to determine failure phase
        let stage_file = path.join(".stage");
        let failed_reason = if stage_file.exists() {
            fs::read_to_string(&stage_file)
                .ok()
                .map(|s| format!("Failed in {} phase", s.trim()))
                .unwrap_or_else(|| "Build failed".to_string())
        } else {
            "Build failed (no phase marker)".to_string()
        };

        // Any directory in bulklog = failed build (successful builds clean up)
        results.push(build::BuildResult {
            pkgname: pkgsrc::PkgName::new(&pkg_name),
            pkgpath: None,
            outcome: build::BuildOutcome::Failed(failed_reason),
            duration: Duration::ZERO,
            log_dir: Some(path),
        });
    }

    Ok(build::BuildSummary {
        duration: Duration::ZERO,
        results,
    })
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.cmd {
        Cmd::Build => {
            let config = Config::load(&args)?;

            // Initialize logging
            let logs_dir = config
                .config_path()
                .and_then(|p| p.parent())
                .map(|p| p.join("logs"))
                .ok_or_else(|| anyhow::anyhow!("Cannot determine logs directory"))?;
            logging::init(&logs_dir, config.verbose())?;

            tracing::info!("Build command started");

            // Validate configuration
            if let Err(errors) = config.validate() {
                eprintln!("Configuration errors:");
                for e in &errors {
                    eprintln!("  - {}", e);
                }
                bail!("{} configuration error(s) found", errors.len());
            }

            let mut scan = Scan::new(&config);
            if let Some(pkgs) = config.pkgpaths() {
                for p in pkgs {
                    scan.add(p);
                }
            }
            scan.start()?;
            println!("Resolving dependencies...");
            let scan_result = scan.resolve()?;

            tracing::info!(
                buildable = scan_result.buildable.len(),
                skipped = scan_result.skipped.len(),
                "Scan complete"
            );

            if scan_result.buildable.is_empty() {
                bail!("No packages to build");
            }

            let mut build = Build::new(&config, scan_result.buildable.clone());

            // Set up Ctrl+C handler for graceful shutdown
            let shutdown_flag = Arc::new(AtomicBool::new(false));
            let shutdown_for_handler = Arc::clone(&shutdown_flag);
            let sandbox_for_handler = Sandbox::new(&config);
            let build_threads = config.build_threads();

            ctrlc::set_handler(move || {
                shutdown_for_handler.store(true, Ordering::SeqCst);
                // Kill processes in sandboxes to stop running builds
                if sandbox_for_handler.enabled() {
                    for i in 0..build_threads {
                        sandbox_for_handler.kill_processes_by_id(i);
                    }
                }
            }).expect("Error setting Ctrl-C handler");

            let mut summary = build.start(Arc::clone(&shutdown_flag))?;

            // Check if we were interrupted
            if shutdown_flag.load(Ordering::SeqCst) {
                let sandbox = Sandbox::new(&config);
                if sandbox.enabled() {
                    let _ = sandbox.destroy_all(config.build_threads());
                }
                std::process::exit(130);
            }

            // Add pre-skipped packages from scan to summary
            for pkg in scan_result.skipped {
                let reason = match pkg.reason {
                    SkipReason::PkgSkipReason(r) => format!("PKG_SKIP_REASON: {}", r),
                    SkipReason::PkgFailReason(r) => format!("PKG_FAIL_REASON: {}", r),
                };
                summary.results.push(build::BuildResult {
                    pkgname: pkg.pkgname,
                    pkgpath: pkg.pkgpath,
                    outcome: build::BuildOutcome::Skipped(reason),
                    duration: std::time::Duration::ZERO,
                    log_dir: None,
                });
            }

            print_summary(&summary);

            // Generate HTML report in bulklog directory
            println!("Generating reports...");
            let bulklog = config.bulklog();
            let report_path = bulklog.join("report.html");
            if let Err(e) = report::write_html_report(&summary, &report_path) {
                eprintln!("Warning: Failed to write HTML report: {}", e);
            } else {
                println!("HTML report written to: {}", report_path.display());
            }
        }
        Cmd::GenerateReport => {
            let config = Config::load(&args)?;
            let bulklog = config.bulklog();

            if !bulklog.exists() {
                bail!("Bulklog directory does not exist: {}", bulklog.display());
            }

            println!("Generating reports...");
            let summary = scan_bulklog_for_report(bulklog)?;
            let report_path = bulklog.join("report.html");

            report::write_html_report(&summary, &report_path)?;
            println!("HTML report written to: {}", report_path.display());
        }
        Cmd::Init { dir: ref arg } => {
            Init::create(arg)?;
        }
        Cmd::Sandbox { cmd: SandboxCmd::Create } => {
            let config = Config::load(&args)?;
            let sandbox = Sandbox::new(&config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            if config.verbose() {
                println!("Creating sandboxes");
            }
            sandbox.create_all(config.build_threads())?;
        }
        Cmd::Sandbox { cmd: SandboxCmd::Destroy } => {
            let config = Config::load(&args)?;
            let sandbox = Sandbox::new(&config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            if config.verbose() {
                println!("Destroying sandboxes");
            }
            sandbox.destroy_all(config.build_threads())?;
        }
        Cmd::Sandbox { cmd: SandboxCmd::List } => {
            let config = Config::load(&args)?;
            let sandbox = Sandbox::new(&config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            sandbox.list_all(config.build_threads());
        }
        Cmd::Scan => {
            let config = Config::load(&args)?;
            if let Err(errors) = config.validate() {
                eprintln!("Configuration errors:");
                for e in &errors {
                    eprintln!("  - {}", e);
                }
                bail!("{} configuration error(s) found", errors.len());
            }
            let mut scan = Scan::new(&config);
            if let Some(pkgs) = config.pkgpaths() {
                for p in pkgs {
                    scan.add(p);
                }
            }
            scan.start()?;
            println!("Resolving dependencies...");
            let result = scan.resolve()?;
            println!(
                "Resolved {} buildable packages, {} skipped",
                result.buildable.len(),
                result.skipped.len()
            );
        }
    };

    Ok(())
}
