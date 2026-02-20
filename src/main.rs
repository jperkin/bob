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

use anyhow::{Context, Result, bail};
use bob::Init;
use bob::Interrupted;
use bob::RunState;
use bob::build::{self, Build};
use bob::config::Config;
use bob::db::Database;
use bob::logging;
use bob::report;
use bob::sandbox::{Sandbox, SandboxScope};
use bob::scan::Scan;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod cmd;

/// Exit code when interrupted.  We do not know what exact signal this was.
const EXIT_INTERRUPTED: u8 = 128 + libc::SIGINT as u8;

/// Common context for build operations.
struct BuildRunner {
    config: Config,
    db: Database,
    state: RunState,
}

impl BuildRunner {
    /// Set up the build environment: config, logging, validation, db, signals.
    fn new(config_path: Option<&Path>) -> Result<Self> {
        let config = Config::load(config_path)?;

        logging::init(config.dbdir(), config.log_level())?;

        if let Err(errors) = config.validate() {
            eprintln!("Configuration errors:");
            for e in &errors {
                eprintln!("  - {}", e);
            }
            bail!("{} configuration error(s) found", errors.len());
        }

        let db = Database::open(config.dbdir())?;

        let state = bob::RunState::new();
        state.register_signals()?;

        Ok(Self { config, db, state })
    }

    /**
     * Run scan phase with a provided scope (for scan+build flow).
     *
     * The scope is managed by the caller, allowing it to persist for a
     * subsequent build phase. Returns `Err(Interrupted)` if interrupted.
     */
    fn run_scan_phase(&self, scan: &mut Scan, scope: &mut SandboxScope) -> Result<()> {
        // For full tree scans with full_scan_complete, we might be able to
        // skip scanning entirely
        if scan.is_full_tree() && self.db.full_scan_complete() {
            scan.set_full_scan_complete();
        }

        // Initialize scan from database (checks what's already scanned)
        let (cached_count, pending_count) = scan.init_from_db(&self.db)?;
        if cached_count > 0 {
            println!("Found {} cached package paths", cached_count);
            if pending_count > 0 {
                println!("Resuming scan with {} pending dependencies", pending_count);
            }
        }

        scan.start(&self.db, scope)?;

        // Handle scan errors
        let scan_errors: Vec<_> = scan.scan_errors().collect();
        let has_scan_errors = !scan_errors.is_empty();
        if has_scan_errors {
            eprintln!();
            for err in &scan_errors {
                eprintln!("{}", err);
            }
            if self.config.strict_scan() {
                bail!("{} package(s) failed to scan", scan_errors.len());
            }
            eprintln!(
                "Warning: {} package(s) failed to scan, continuing anyway",
                scan_errors.len()
            );
            eprintln!();
        } else if scan.is_full_tree() {
            // Mark full tree scan as complete if no errors
            self.db.set_full_scan_complete()?;
        }

        Ok(())
    }

    /**
     * Execute a build from resolved packages and run post-build steps.
     *
     * Shared by the build and rebuild commands: loads cached results,
     * runs the build, and generates pkg_summary on success.
     */
    fn run_build(
        &self,
        buildable: indexmap::IndexMap<pkgsrc::PkgName, bob::scan::ResolvedPackage>,
        scope: SandboxScope,
    ) -> Result<build::BuildSummary> {
        let pkgsrc_env = self
            .db
            .load_pkgsrc_env()
            .context("PkgsrcEnv not cached - try 'bob clean' first")?;

        let mut build = Build::new(&self.config, pkgsrc_env, scope, buildable);
        build.load_cached_from_db(&self.db)?;

        tracing::debug!("Calling build.start()");
        let build_start_time = std::time::Instant::now();
        let summary = build.start(&self.state, &self.db)?;
        tracing::debug!(
            elapsed_ms = build_start_time.elapsed().as_millis(),
            "build.start() returned"
        );

        /*
         * Check if we were interrupted.  All builds that completed before
         * the interrupt have already been saved to the database inside
         * build.start().  When stopping, in-progress builds ran to
         * completion; during shutdown they were killed and discarded.
         */
        if self.state.interrupted() {
            return Err(Interrupted.into());
        }

        Ok(summary)
    }

    /**
     * Regenerate pkg_summary if the set of successful packages changed
     * or any packages were rebuilt (their metadata may have changed).
     *
     * `prior` is the list of successful package names captured before any
     * database mutations (build results stored, cache cleared, etc.).
     */
    fn update_pkg_summary(&self, prior: &[String], summary: &build::BuildSummary) {
        let changed = match self.db.get_successful_packages() {
            Ok(current) => prior != current || summary.counts().success > 0,
            Err(_) => true,
        };
        if !changed {
            return;
        }
        print!("Generating pkg_summary...");
        if std::io::Write::flush(&mut std::io::stdout()).is_err() {
            return;
        }
        tracing::debug!("Generating pkg_summary");
        let start = std::time::Instant::now();
        match bob::generate_pkg_summary(&self.db, self.config.build_threads()) {
            Ok(()) => {
                println!(" done ({:.1}s)", start.elapsed().as_secs_f32());
                tracing::debug!(
                    elapsed_ms = start.elapsed().as_millis(),
                    "Finished generating pkg_summary"
                );
            }
            Err(e) => {
                println!();
                eprintln!("Warning: Failed to generate pkg_summary: {}", e);
            }
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "bob",
    author,
    version,
    about,
    long_about = "\
A pkgsrc package builder

\x1b[1;4mFirst time setup:\x1b[0m

  bob init <dir>   Create new configuration directory
  cd <dir>         Bob looks for config.lua in current directory by default
  vi config.lua    Configure packages to build, customise sandboxes, etc.

\x1b[1;4mBuild all packages:\x1b[0m

  bob build

Each of the main target commands depend on the previous being up-to-date, so
'bob build' will automatically run 'bob scan' first to get build information."
)]
pub struct Args {
    /// Use the specified configuration file instead of the default path
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Initialise a new build directory and configuration file
    Init { dir: PathBuf },
    /// Perform recursive scan of packages and resolve dependencies
    Scan {
        /// Skip up-to-date checking (scan and resolve only)
        #[arg(long)]
        scan_only: bool,
    },
    /// Build all scanned packages
    Build {
        /// Package paths to build (overrides config pkgpaths)
        #[arg(value_name = "PKGPATH")]
        pkgpaths: Vec<String>,
    },
    /// Rebuild specific packages
    Rebuild {
        /// Rebuild all previously failed packages
        #[arg(short, long)]
        all: bool,
        /// Only rebuild specified packages (skip dependents)
        #[arg(long)]
        only: bool,
        /// Package paths or package names to rebuild
        #[arg(value_name = "PKGPATH|PKGNAME")]
        packages: Vec<String>,
    },
    /// Generate HTML report from current build logs
    Report,
    /// Remove current build state (database and build logs)
    Clean {
        /// Only remove package log directories, preserve database
        #[arg(short = 'l', long = "logs-only")]
        logs_only: bool,
    },
    /// Query package build status
    List {
        #[command(subcommand)]
        cmd: cmd::list::ListCmd,
    },
    /// Utility commands for debugging and data import/export
    Util {
        #[command(subcommand)]
        cmd: UtilCmd,
    },
    /// Run SQL commands against the database
    Db {
        /// SQL command to execute (omit for interactive mode)
        #[arg(value_name = "SQL")]
        sql: Option<String>,
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

#[derive(Debug, Subcommand)]
enum UtilCmd {
    /// Create and destroy build sandboxes
    Sandbox {
        #[command(subcommand)]
        cmd: SandboxCmd,
    },
    /// Import scan data (pscan or presolve format) into the database
    ///
    /// Accepts both raw pscan output from 'bmake pbulk-index' and presolve
    /// files that include resolved DEPENDS lines. This allows comparison
    /// of bob's dependency resolution against external resolvers.
    ImportScan {
        /// Path to the scan file (pscan or presolve format)
        file: PathBuf,
    },
    /// Output raw scan data from the database (without resolution)
    PrintPscan {
        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Output pbulk-compatible presolve data from cached scan data
    PrintPresolve {
        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Output the resolved dependency graph from cached scan data
    PrintDepGraph {
        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.downcast_ref::<Interrupted>().is_some() => ExitCode::from(EXIT_INTERRUPTED),
        Err(e) => {
            eprintln!("Error: {}", format_error(&e));
            ExitCode::FAILURE
        }
    }
}

fn format_error(e: &anyhow::Error) -> String {
    e.chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>()
        .join(": ")
}

fn run() -> Result<()> {
    let args = Args::parse();

    match args.cmd {
        Cmd::Init { dir: ref arg } => {
            Init::create(arg)?;
        }
        Cmd::Scan { scan_only } => {
            let runner = BuildRunner::new(args.config.as_deref())?;

            let mut scan = Scan::new(&runner.config);
            if let Some(pkgs) = runner.config.pkgpaths() {
                for p in pkgs {
                    scan.add(p);
                }
            }

            let sandbox = Sandbox::new(&runner.config);
            let mut scope = SandboxScope::new(sandbox, runner.state.clone());
            runner.run_scan_phase(&mut scan, &mut scope)?;
            drop(scope);

            let result = scan.resolve_with_report(&runner.db, runner.config.strict_scan())?;
            result.print_resolved();
            let up_to_date = if scan_only {
                None
            } else {
                Some(cmd::build::check_up_to_date(
                    &runner.config,
                    &runner.db,
                    &result,
                )?)
            };
            result.print_counts(up_to_date);
        }
        Cmd::Build {
            pkgpaths: cmdline_pkgs,
        } => {
            let runner = BuildRunner::new(args.config.as_deref())?;
            tracing::info!("Build command started");

            let mut scan = Scan::new(&runner.config);
            if cmdline_pkgs.is_empty() {
                if let Some(pkgs) = runner.config.pkgpaths() {
                    for p in pkgs {
                        scan.add(p);
                    }
                }
            } else {
                for p in &cmdline_pkgs {
                    match pkgsrc::PkgPath::new(p) {
                        Ok(pkgpath) => scan.add(&pkgpath),
                        Err(e) => bail!("Invalid PKGPATH '{}': {}", p, e),
                    }
                }
            }

            let sandbox = Sandbox::new(&runner.config);
            let mut scope = SandboxScope::new(sandbox, runner.state.clone());
            runner.run_scan_phase(&mut scan, &mut scope)?;
            let scan_result = scan.resolve_with_report(&runner.db, runner.config.strict_scan())?;
            let prior = runner.db.get_successful_packages().unwrap_or_default();
            cmd::build::check_up_to_date(&runner.config, &runner.db, &scan_result)?;
            let summary = cmd::build::run_build_with(
                &runner.config,
                &runner.db,
                &runner.state,
                scan_result,
                scope,
            )?;
            runner.update_pkg_summary(&prior, &summary);
        }
        Cmd::Rebuild {
            all,
            only,
            packages,
        } => {
            let runner = BuildRunner::new(args.config.as_deref())?;
            let prior = runner.db.get_successful_packages().unwrap_or_default();
            let buildable = cmd::rebuild::prepare(
                &runner.db,
                cmd::rebuild::RebuildArgs {
                    all,
                    only,
                    packages,
                },
            )?;
            let sandbox = Sandbox::new(&runner.config);
            let scope = SandboxScope::new(sandbox, runner.state.clone());
            let summary = runner.run_build(buildable, scope)?;
            runner.update_pkg_summary(&prior, &summary);
        }
        Cmd::Report => {
            let config = Config::load(args.config.as_deref())?;
            let db_path = config.dbdir().join("bob.db");

            if !db_path.exists() {
                bail!(
                    "No database found at {}.  Perform a build first.",
                    db_path.display()
                );
            }

            println!("Generating report...");
            let db = Database::open(config.dbdir())?;
            let report_path = config.logdir().join("report.html");
            report::write_html_report(&db, config.logdir(), &report_path)?;
            println!("HTML report written to: {}", report_path.display());
        }
        Cmd::Clean { logs_only } => {
            let config = Config::load(args.config.as_deref())?;
            let logdir = config.logdir();
            let dbdir = config.dbdir();

            if !logs_only {
                let _ = std::fs::remove_file(dbdir.join("bob.db"));
                let _ = std::fs::remove_file(dbdir.join("bob.log"));
            }
            if logdir.exists() {
                std::fs::remove_dir_all(logdir).context("Failed to remove log directory")?;
            }
        }
        Cmd::Db { sql } => {
            let config = Config::load(args.config.as_deref())?;
            let db = Database::open(config.dbdir())?;

            let Some(sql) = sql else {
                bail!("SQL command required");
            };

            db.execute_raw(&sql)?;
        }
        Cmd::List { cmd } => {
            let config = Config::load(args.config.as_deref())?;
            let db = Database::open(config.dbdir())?;
            cmd::list::run(&db, cmd)?;
        }
        Cmd::Util {
            cmd: UtilCmd::PrintDepGraph { output },
        } => {
            let config = Config::load(args.config.as_deref())?;
            let db = Database::open(config.dbdir())?;

            let count = db.count_packages()?;
            if count == 0 {
                bail!("No cached scan data found. Run 'bob scan' first.");
            }

            let mut scan = Scan::new(&config);
            scan.init_from_db(&db)?;

            let scan_data = db.get_all_scan_data()?;
            let result = scan.resolve(scan_data)?;

            // Build DAG output
            let mut edges: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for pkg in result.buildable() {
                let pkgname = pkg.pkgname();
                for dep in pkg.depends() {
                    edges.insert(format!("{} -> {}", dep, pkgname));
                }
            }
            let out: String = edges
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";

            // Write to file or stdout
            if let Some(path) = output {
                std::fs::write(&path, &out)?;
                println!("Wrote {} edges to {}", edges.len(), path.display());
            } else {
                print!("{}", out);
            }
        }
        Cmd::Util {
            cmd: UtilCmd::PrintPresolve { output },
        } => {
            let config = Config::load(args.config.as_deref())?;
            let db = Database::open(config.dbdir())?;

            let count = db.count_packages()?;
            if count == 0 {
                bail!("No cached scan data found. Run 'bob scan' first.");
            }

            let mut scan = Scan::new(&config);
            scan.init_from_db(&db)?;

            let scan_data = db.get_all_scan_data()?;
            let result = scan.resolve(scan_data)?;

            // Print unresolved dependency errors
            let errors: Vec<_> = result.errors().collect();
            if !errors.is_empty() {
                eprintln!("Unresolved dependencies:\n  {}", errors.join("\n  "));
            }

            // Build presolve output in original order
            let mut out = String::new();
            for pkg in &result.packages {
                out.push_str(&pkg.to_string());
            }

            // Write to file or stdout
            if let Some(path) = output {
                std::fs::write(&path, &out)?;
                let c = result.counts();
                let s = &c.skipped;
                let skipped = s.pkg_skip + s.pkg_fail + s.unresolved;
                println!(
                    "Wrote {} buildable, {} skipped to {}",
                    c.buildable,
                    skipped,
                    path.display()
                );
            } else {
                print!("{}", out);
            }
        }
        Cmd::Util {
            cmd: UtilCmd::ImportScan { file },
        } => {
            use indexmap::IndexMap;
            use pkgsrc::ScanIndex;
            use std::fs::File;
            use std::io::BufReader;

            let config = Config::load(args.config.as_deref())?;
            let db = Database::open(config.dbdir())?;

            println!("Importing scan data from {}", file.display());

            let f = File::open(&file)?;
            let reader = BufReader::new(f);

            // Parse all ScanIndex entries and group by pkgpath (preserving order)
            let mut by_pkgpath: IndexMap<String, Vec<ScanIndex>> = IndexMap::new();
            let mut errors: Vec<String> = Vec::new();
            for result in ScanIndex::from_reader(reader) {
                match result {
                    Ok(index) => {
                        let pkgpath = index
                            .pkg_location
                            .as_ref()
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "unknown".to_string());
                        by_pkgpath.entry(pkgpath).or_default().push(index);
                    }
                    Err(e) => {
                        errors.push(e.to_string());
                    }
                }
            }

            if !errors.is_empty() {
                eprintln!();
                for err in &errors {
                    eprintln!("{}", err);
                }
                if config.strict_scan() {
                    bail!("{} record(s) failed to parse", errors.len());
                }
                eprintln!(
                    "Warning: {} record(s) failed to parse, continuing anyway",
                    errors.len()
                );
                eprintln!();
            }

            // Clear existing data and import
            db.clear_scan()?;
            for (pkgpath, indexes) in &by_pkgpath {
                db.store_scan_pkgpath(pkgpath, indexes)?;
            }

            // Resolve dependencies (consistent with manual scan)
            let mut scan = Scan::new(&config);
            let result = scan.resolve_with_report(&db, config.strict_scan())?;
            result.print_resolved();
            result.print_counts(None);
        }
        Cmd::Util {
            cmd: UtilCmd::PrintPscan { output },
        } => {
            let config = Config::load(args.config.as_deref())?;
            let db = Database::open(config.dbdir())?;

            let packages = db.get_all_packages()?;
            if packages.is_empty() {
                bail!("No cached scan data found. Run 'bob scan' or 'bob util import-scan' first.");
            }

            // Collect all ScanIndex entries
            let mut out = String::new();
            let mut count = 0;
            for pkg in &packages {
                if let Ok(idx) = db.get_full_scan_index(pkg.id) {
                    out.push_str(&idx.to_string());
                    count += 1;
                }
            }

            // Write to file or stdout
            if let Some(path) = output {
                std::fs::write(&path, &out)?;
                println!("Wrote {} packages to {}", count, path.display());
            } else {
                print!("{}", out);
            }
        }
        Cmd::Util {
            cmd: UtilCmd::Sandbox {
                cmd: SandboxCmd::Create,
            },
        } => {
            logging::init_stderr_if_enabled();
            let config = Config::load(args.config.as_deref())?;
            let sandbox = Sandbox::new(&config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            sandbox.create_all(config.build_threads())?;
        }
        Cmd::Util {
            cmd: UtilCmd::Sandbox {
                cmd: SandboxCmd::Destroy,
            },
        } => {
            logging::init_stderr_if_enabled();
            let config = Config::load(args.config.as_deref())?;
            let sandbox = Sandbox::new(&config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            sandbox.destroy_all()?;
        }
        Cmd::Util {
            cmd: UtilCmd::Sandbox {
                cmd: SandboxCmd::List,
            },
        } => {
            let config = Config::load(args.config.as_deref())?;
            let sandbox = Sandbox::new(&config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            sandbox.list_all()?;
        }
    };

    Ok(())
}
