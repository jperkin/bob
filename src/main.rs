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

use anyhow::{Result, bail};
use bob::Init;
use bob::build::{self, Build};
use bob::config::Config;
use bob::db::{Database, SessionStatus};
use bob::logging;
use bob::report;
use bob::sandbox::Sandbox;
use bob::scan::{Scan, SkipReason};
use bob::{RunContext, Stats};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::str;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
    Build {
        /// Resume the most recent session if possible
        #[arg(long)]
        resume: bool,

        /// Force a new session (don't prompt about existing sessions)
        #[arg(long, conflicts_with = "resume")]
        new: bool,
    },
    /// Generate HTML report from existing logdir data
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
    /// Manage build sessions
    Session {
        #[command(subcommand)]
        cmd: SessionCmd,
    },
}

#[derive(Debug, Subcommand)]
enum SessionCmd {
    /// List all build sessions
    List,
    /// Show details of a specific session
    Show {
        /// Session ID to show
        id: i64,
    },
    /// Delete a session
    Delete {
        /// Session ID to delete
        id: i64,
    },
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

/// Determine which session to use based on CLI flags and existing sessions.
/// Returns (session_id, should_resume_scan).
fn determine_session(db: &Database, resume: bool, new: bool) -> Result<(i64, bool)> {
    // If --new is specified, always create a new session
    if new {
        let session_id = db.create_session()?;
        println!("Created new session {}", session_id);
        return Ok((session_id, false));
    }

    // Check for existing resumable session
    if let Some(session) = db.get_latest_session()? {
        if session.can_resume() {
            if resume {
                // --resume specified, use existing session
                println!(
                    "Resuming session {} (status: {:?})",
                    session.id, session.status
                );

                // If scan is complete, we can skip it
                let skip_scan = session.scan_complete();
                if skip_scan {
                    println!(
                        "  Scan already complete: {} packages scanned",
                        session.scanned_packages
                    );
                    let (pending, success, failed, skipped) =
                        db.get_build_status_counts(session.id)?;
                    println!(
                        "  Build progress: {} pending, {} success, {} failed, {} skipped",
                        pending, success, failed, skipped
                    );
                }

                return Ok((session.id, skip_scan));
            } else {
                // Prompt about existing session
                println!();
                println!("Found existing session {} that can be resumed:", session.id);
                println!("  Status: {:?}", session.status);
                println!("  Created: {}", session.created_at);
                if session.scan_complete() {
                    println!(
                        "  Scan: complete ({} packages)",
                        session.scanned_packages
                    );
                    let (pending, success, failed, skipped) =
                        db.get_build_status_counts(session.id)?;
                    println!(
                        "  Build: {} pending, {} success, {} failed, {} skipped",
                        pending, success, failed, skipped
                    );
                }
                println!();
                println!("Options:");
                println!("  bob build --resume    Resume this session");
                println!("  bob build --new       Start a fresh build");
                println!();
                bail!(
                    "Session {} can be resumed. Use --resume or --new to proceed.",
                    session.id
                );
            }
        }
    }

    // No resumable session, create new one
    let session_id = db.create_session()?;
    println!("Created new session {}", session_id);
    Ok((session_id, false))
}

fn print_summary(summary: &build::BuildSummary) {
    println!();
    println!("Build Summary");
    println!("=============");
    println!("  Succeeded:   {}", summary.success_count());
    println!("  Failed:      {}", summary.failed_count());
    println!("  Skipped:     {}", summary.skipped_count());
    if summary.scan_failed_count() > 0 {
        println!("  Scan failed: {}", summary.scan_failed_count());
    }
    println!();
}

/// Scan the logdir directory to reconstruct build results for report generation.
fn scan_logdir_for_report(logdir: &Path) -> Result<build::BuildSummary> {
    use std::fs;
    use std::time::Duration;

    let mut results = Vec::new();

    for entry in fs::read_dir(logdir)? {
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

        // Any directory in logdir = failed build (successful builds clean up)
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
        scan_failed: Vec::new(),
    })
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.cmd {
        Cmd::Build { resume, new } => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;

            // Initialize logging in logdir/bob/
            let logs_dir = config.logdir().join("bob");
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

            // Open the database
            let db_path = logs_dir.join("bob.db");
            let db = Database::open(&db_path)?;

            // Determine session: resume existing or create new
            let (session_id, resuming_scan) = determine_session(&db, resume, new)?;

            // Set up signal handler for graceful shutdown (SIGINT and SIGTERM)
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
            })
            .expect("Error setting signal handler");

            // Create stats collector
            let stats_path = logs_dir.join("stats.jsonl");
            let stats = Stats::new(&stats_path)?;
            let ctx = RunContext::new(Arc::clone(&shutdown_flag))
                .with_stats(Arc::new(stats));

            // Get scan result either from database (resume) or by scanning
            let scan_result = if resuming_scan {
                println!("Resuming from previous scan...");
                db.set_session_status(session_id, SessionStatus::Building)?;

                // Reset any in-progress builds from interrupted session
                let reset_count = db.reset_in_progress_builds(session_id)?;
                if reset_count > 0 {
                    println!("Reset {} interrupted builds", reset_count);
                }

                // Load scan data from database
                let buildable = db.get_scanned_packages(session_id)?;
                if buildable.is_empty() {
                    bail!("No packages found in session - scan may not have completed");
                }

                println!("Loaded {} packages from previous scan", buildable.len());

                bob::scan::ScanResult {
                    buildable,
                    skipped: Vec::new(),
                    scan_failed: Vec::new(),
                }
            } else {
                // Mark session as scanning
                db.set_session_status(session_id, SessionStatus::Scanning)?;

                let mut scan = Scan::new(&config);
                if let Some(pkgs) = config.pkgpaths() {
                    for p in pkgs {
                        scan.add(p);
                    }
                }
                if scan.start(&ctx)? {
                    db.set_session_status(session_id, SessionStatus::Interrupted)?;
                    if let Some(ref s) = ctx.stats {
                        s.flush();
                    }
                    std::process::exit(130);
                }
                scan.write_log(&logs_dir.join("scan.log"))?;

                // Handle scan errors
                let scan_errors = scan.scan_errors();
                if !scan_errors.is_empty() {
                    eprintln!();
                    for err in &scan_errors {
                        eprintln!("{}", err);
                    }
                    if config.strict_scan() {
                        db.set_session_status(session_id, SessionStatus::Failed)?;
                        bail!("{} package(s) failed to scan", scan_errors.len());
                    }
                    eprintln!(
                        "Warning: {} package(s) failed to scan, continuing anyway",
                        scan_errors.len()
                    );
                    eprintln!();
                }

                println!("Resolving dependencies...");
                let scan_result = scan.resolve(Some(&logs_dir))?;

                tracing::info!(
                    buildable = scan_result.buildable.len(),
                    skipped = scan_result.skipped.len(),
                    "Scan complete"
                );

                // Store scan result in database
                db.store_scan_result(session_id, &scan_result.buildable)?;
                db.set_session_status(session_id, SessionStatus::Scanned)?;

                println!("Scan complete, {} packages to build", scan_result.buildable.len());

                scan_result
            };

            if scan_result.buildable.is_empty() {
                db.set_session_status(session_id, SessionStatus::Completed)?;
                bail!("No packages to build");
            }

            // Mark session as building
            db.set_session_status(session_id, SessionStatus::Building)?;

            let mut build = Build::new(&config, scan_result.buildable.clone());
            let mut summary = build.start(&ctx)?;

            // Flush stats before checking for interruption
            if let Some(ref s) = ctx.stats {
                s.flush();
            }

            // Check if we were interrupted
            if ctx.shutdown.load(Ordering::SeqCst) {
                db.set_session_status(session_id, SessionStatus::Interrupted)?;
                let sandbox = Sandbox::new(&config);
                if sandbox.enabled() {
                    let _ = sandbox.destroy_all(config.build_threads());
                }
                eprintln!("\nBuild interrupted. Resume with: bob build --resume");
                std::process::exit(130);
            }

            // Add pre-skipped packages from scan to summary
            for pkg in scan_result.skipped {
                let reason = match pkg.reason {
                    SkipReason::PkgSkipReason(r) => {
                        format!("PKG_SKIP_REASON: {}", r)
                    }
                    SkipReason::PkgFailReason(r) => {
                        format!("PKG_FAIL_REASON: {}", r)
                    }
                };
                summary.results.push(build::BuildResult {
                    pkgname: pkg.pkgname,
                    pkgpath: pkg.pkgpath,
                    outcome: build::BuildOutcome::Skipped(reason),
                    duration: std::time::Duration::ZERO,
                    log_dir: None,
                });
            }

            // Add scan failures to summary
            summary.scan_failed = scan_result.scan_failed;

            // Update session status based on results
            if summary.failed_count() > 0 {
                db.set_session_status(session_id, SessionStatus::Completed)?;
            } else {
                db.set_session_status(session_id, SessionStatus::Completed)?;
            }

            print_summary(&summary);

            // Generate HTML report in logdir directory
            println!("Generating reports...");
            let logdir = config.logdir();
            let report_path = logdir.join("report.html");
            if let Err(e) = report::write_html_report(&summary, &report_path) {
                eprintln!("Warning: Failed to write HTML report: {}", e);
            } else {
                println!("HTML report written to: {}", report_path.display());
            }
        }
        Cmd::GenerateReport => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let logdir = config.logdir();

            if !logdir.exists() {
                bail!("logdir directory does not exist: {}", logdir.display());
            }

            println!("Generating reports...");
            let summary = scan_logdir_for_report(logdir)?;
            let report_path = logdir.join("report.html");

            report::write_html_report(&summary, &report_path)?;
            println!("HTML report written to: {}", report_path.display());
        }
        Cmd::Init { dir: ref arg } => {
            Init::create(arg)?;
        }
        Cmd::Sandbox { cmd: SandboxCmd::Create } => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
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
            let config = Config::load(args.config.as_deref(), args.verbose)?;
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
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let sandbox = Sandbox::new(&config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            sandbox.list_all(config.build_threads());
        }
        Cmd::Scan => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let logs_dir = config.logdir().join("bob");
            logging::init(&logs_dir, config.verbose())?;
            if let Err(errors) = config.validate() {
                eprintln!("Configuration errors:");
                for e in &errors {
                    eprintln!("  - {}", e);
                }
                bail!("{} configuration error(s) found", errors.len());
            }

            // Set up signal handler for graceful shutdown
            let shutdown_flag = Arc::new(AtomicBool::new(false));
            let shutdown_for_handler = Arc::clone(&shutdown_flag);
            let sandbox_for_handler = Sandbox::new(&config);

            ctrlc::set_handler(move || {
                shutdown_for_handler.store(true, Ordering::SeqCst);
                if sandbox_for_handler.enabled() {
                    sandbox_for_handler.kill_processes_by_id(0);
                }
            })
            .expect("Error setting signal handler");

            // Create stats collector
            let stats_path = logs_dir.join("stats.jsonl");
            let stats = Stats::new(&stats_path)?;
            let ctx = RunContext::new(Arc::clone(&shutdown_flag))
                .with_stats(Arc::new(stats));

            let mut scan = Scan::new(&config);
            if let Some(pkgs) = config.pkgpaths() {
                for p in pkgs {
                    scan.add(p);
                }
            }
            if scan.start(&ctx)? {
                if let Some(ref s) = ctx.stats {
                    s.flush();
                }
                std::process::exit(130);
            }
            scan.write_log(&logs_dir.join("scan.log"))?;

            // Handle scan errors
            let scan_errors = scan.scan_errors();
            if !scan_errors.is_empty() {
                eprintln!();
                for err in &scan_errors {
                    eprintln!("{}", err);
                }
                if config.strict_scan() {
                    bail!("{} package(s) failed to scan", scan_errors.len());
                }
                eprintln!(
                    "Warning: {} package(s) failed to scan, continuing anyway",
                    scan_errors.len()
                );
                eprintln!();
            }

            // Flush stats
            if let Some(ref s) = ctx.stats {
                s.flush();
            }

            println!("Resolving dependencies...");
            let result = scan.resolve(Some(&logs_dir))?;
            println!(
                "Resolved {} buildable packages, {} skipped",
                result.buildable.len(),
                result.skipped.len()
            );
        }
        Cmd::Session { cmd: SessionCmd::List } => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");

            if !db_path.exists() {
                println!("No sessions found (database does not exist)");
                return Ok(());
            }

            let db = Database::open(&db_path)?;
            let sessions = db.list_sessions()?;

            if sessions.is_empty() {
                println!("No sessions found");
                return Ok(());
            }

            println!(
                "{:>4}  {:>12}  {:>10}  {:>8}  {:>8}  {:>8}  {}",
                "ID", "STATUS", "TOTAL", "SCANNED", "BUILT", "FAILED", "CREATED"
            );
            println!("{}", "-".repeat(80));

            for session in sessions {
                println!(
                    "{:>4}  {:>12}  {:>10}  {:>8}  {:>8}  {:>8}  {}",
                    session.id,
                    format!("{:?}", session.status),
                    session.total_packages,
                    session.scanned_packages,
                    session.built_packages,
                    session.failed_packages,
                    session.created_at
                );
            }
        }
        Cmd::Session { cmd: SessionCmd::Show { id } } => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");

            let db = Database::open(&db_path)?;
            let session = db.get_session(id)?;

            match session {
                Some(s) => {
                    println!("Session {}", s.id);
                    println!("=========");
                    println!("  Status:          {:?}", s.status);
                    println!("  Created:         {}", s.created_at);
                    println!("  Updated:         {}", s.updated_at);
                    println!("  Total packages:  {}", s.total_packages);
                    println!("  Scanned:         {}", s.scanned_packages);
                    println!("  Built:           {}", s.built_packages);
                    println!("  Failed:          {}", s.failed_packages);
                    println!("  Skipped:         {}", s.skipped_packages);

                    if s.can_resume() {
                        println!();
                        println!("This session can be resumed with: bob build --resume");
                    }
                }
                None => {
                    bail!("Session {} not found", id);
                }
            }
        }
        Cmd::Session { cmd: SessionCmd::Delete { id } } => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");

            let db = Database::open(&db_path)?;

            // Check session exists
            if db.get_session(id)?.is_none() {
                bail!("Session {} not found", id);
            }

            db.delete_session(id)?;
            println!("Deleted session {}", id);
        }
    };

    Ok(())
}
