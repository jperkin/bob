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
use bob::RunContext;
use bob::build::{self, Build};
use bob::config::Config;
use bob::db::Database;
use bob::logging;
use bob::report;
use bob::sandbox::{Sandbox, SandboxScope};
use bob::scan::{Scan, ScanResult};
use clap::{Parser, Subcommand};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::error;

mod cmd;

/// Exit code when interrupted.  We do not know what exact signal this was.
const EXIT_INTERRUPTED: u8 = 128 + libc::SIGINT as u8;

/// Common context for build operations.
struct BuildRunner {
    config: Config,
    db: Database,
    ctx: RunContext,
}

impl BuildRunner {
    /// Set up the build environment: config, logging, validation, db, signals.
    fn new(config_path: Option<&Path>) -> Result<Self> {
        let config = Config::load(config_path)?;
        let logs_dir = config.logdir().join("bob");

        logging::init(&logs_dir, config.log_level())?;

        if let Err(errors) = config.validate() {
            eprintln!("Configuration errors:");
            for e in &errors {
                eprintln!("  - {}", e);
            }
            bail!("{} configuration error(s) found", errors.len());
        }

        let db_path = logs_dir.join("bob.db");
        let db = Database::open(&db_path)?;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let shutdown_for_handler = Arc::clone(&shutdown_flag);
        ctrlc::set_handler(move || {
            // Print message only on first interrupt (swap returns previous value)
            if !shutdown_for_handler.swap(true, Ordering::SeqCst) {
                eprintln!("\nInterrupted, shutting down...");
            }
        })
        .context("Failed to set signal handler")?;

        let ctx = RunContext::new(Arc::clone(&shutdown_flag));

        Ok(Self { config, db, ctx })
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
     * Check in advance whether packages are up-to-date, or a reason why they
     * need to be built, and store results.
     *
     * Determines whether each package's binary is current with its sources by
     * checking file hashes, CVS IDs, and dependency states. Packages verified
     * as up-to-date are recorded with `BuildOutcome::UpToDate` to skip during
     * build; others have their rebuild reason stored in the database.
     *
     * Processing uses topological waves to avoid redundant checks. Packages
     * are checked only after all their dependencies have been processed. When
     * a checked package needs rebuilding, all its dependents are immediately
     * marked for rebuild via propagation.
     */
    fn check_up_to_date(&self, scan_result: &bob::scan::ScanSummary) -> Result<usize> {
        let pkgsrc_env = match self.db.load_pkgsrc_env() {
            Ok(env) => env,
            Err(_) => {
                tracing::warn!("PkgsrcEnv not cached, skipping up-to-date check");
                return Ok(0);
            }
        };
        let packages_dir = pkgsrc_env.packages.join("All");
        let pkgsrc_dir = self.config.pkgsrc();

        let buildable: Vec<_> = scan_result.buildable().collect();
        let mut up_to_date_count = 0usize;

        self.db.clear_build_reasons()?;

        print!("Calculating package build status...");
        std::io::Write::flush(&mut std::io::stdout())?;
        let start = std::time::Instant::now();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.config.scan_threads())
            .build()
            .context("Failed to build thread pool for up-to-date check")?;

        /*
         * Build dependency graph restricted to buildable set. Forward deps
         * determine wave ordering, reverse deps enable propagation.
         */
        let buildable_names: HashSet<&str> =
            buildable.iter().map(|p| p.pkgname().pkgname()).collect();
        let pkg_by_name: HashMap<&str, &bob::scan::ResolvedPackage> = buildable
            .iter()
            .map(|&p| (p.pkgname().pkgname(), p))
            .collect();

        let forward_deps: HashMap<&str, Vec<&str>> = buildable
            .iter()
            .map(|p| {
                let deps: Vec<&str> = p
                    .depends()
                    .iter()
                    .map(|d| d.pkgname())
                    .filter(|d| buildable_names.contains(d))
                    .collect();
                (p.pkgname().pkgname(), deps)
            })
            .collect();

        let mut reverse_deps: HashMap<&str, Vec<&str>> = HashMap::new();
        for (pkg, deps) in &forward_deps {
            for dep in deps {
                reverse_deps.entry(*dep).or_default().push(*pkg);
            }
        }

        let mut remaining: HashSet<&str> = buildable_names.clone();
        let mut needs_rebuild: HashSet<&str> = HashSet::new();
        let mut propagated_from: HashMap<&str, &str> = HashMap::new();
        let mut checked_results: Vec<(
            &bob::scan::ResolvedPackage,
            anyhow::Result<Option<bob::BuildReason>>,
        )> = Vec::new();

        /*
         * Mark packages with missing binaries. Not propagated - dependents
         * will get their own reason (DependencyMissing) when checked.
         */
        for &pkgname in &buildable_names {
            let pkgfile = packages_dir.join(format!("{}.tgz", pkgname));
            if !pkgfile.exists() {
                needs_rebuild.insert(pkgname);
                self.db
                    .store_build_reason(pkgname, &bob::BuildReason::PackageNotFound.to_string())?;
            }
        }

        /*
         * Process in topological waves. Each wave contains packages whose
         * dependencies have all been processed. Packages already marked are
         * skipped; when a checked package needs rebuild, all transitive
         * dependents are marked with DependencyRefresh via propagation.
         */
        while !remaining.is_empty() {
            let ready: Vec<&str> = remaining
                .iter()
                .filter(|pkg| {
                    forward_deps[*pkg]
                        .iter()
                        .all(|dep| !remaining.contains(dep))
                })
                .copied()
                .collect();

            if ready.is_empty() {
                break;
            }

            let to_check: Vec<&str> = ready
                .iter()
                .filter(|pkg| !needs_rebuild.contains(*pkg))
                .copied()
                .collect();

            let wave_results: Vec<_> = pool.install(|| {
                to_check
                    .par_iter()
                    .map(|&pkgname| {
                        let pkg = pkg_by_name[pkgname];
                        let depends: Vec<&str> =
                            pkg.depends().iter().map(|d| d.pkgname()).collect();
                        let result =
                            bob::pkg_up_to_date(pkgname, &depends, &packages_dir, pkgsrc_dir);
                        (pkg, result)
                    })
                    .collect()
            });

            for (pkg, result) in wave_results {
                let pkgname = pkg.pkgname().pkgname();
                if matches!(&result, Ok(Some(_)) | Err(_)) {
                    needs_rebuild.insert(pkgname);
                    let mut worklist = vec![pkgname];
                    while let Some(dep) = worklist.pop() {
                        if let Some(dependents) = reverse_deps.get(dep) {
                            for &dependent in dependents {
                                if needs_rebuild.insert(dependent) {
                                    propagated_from.insert(dependent, dep);
                                    worklist.push(dependent);
                                }
                            }
                        }
                    }
                }
                checked_results.push((pkg, result));
            }

            for pkg in ready {
                remaining.remove(pkg);
            }
        }

        /*
         * Store results. Checked packages get their actual outcome (UpToDate
         * or their specific rebuild reason). Propagated packages (not checked)
         * get DependencyRefresh.
         */
        for (pkg, result) in checked_results {
            let pkgname = pkg.pkgname().pkgname();
            match result {
                Ok(None) => {
                    let build_result = bob::BuildResult {
                        pkgname: pkg.pkgname().clone(),
                        pkgpath: Some(pkg.pkgpath.clone()),
                        outcome: bob::BuildOutcome::UpToDate,
                        duration: std::time::Duration::ZERO,
                        log_dir: None,
                    };
                    self.db.store_build_by_name(&build_result)?;
                    up_to_date_count += 1;
                }
                Ok(Some(reason)) => {
                    self.db.store_build_reason(pkgname, &reason.to_string())?;
                }
                Err(e) => {
                    tracing::debug!(
                        pkgname,
                        error = %e,
                        "Error checking up-to-date status"
                    );
                    self.db
                        .store_build_reason(pkgname, &format!("check failed: {}", e))?;
                }
            }
        }

        for (pkgname, dep) in propagated_from {
            let reason = bob::BuildReason::DependencyRefresh(dep.to_string());
            self.db.store_build_reason(pkgname, &reason.to_string())?;
        }

        println!(" done ({:.1}s)", start.elapsed().as_secs_f32());

        Ok(up_to_date_count)
    }

    fn run_build_with(
        &mut self,
        scan_result: bob::scan::ScanSummary,
        scope: SandboxScope,
    ) -> Result<build::BuildSummary> {
        // Validate config before sandbox expansion
        if scan_result.count_buildable() == 0 {
            bail!("No packages to build");
        }

        let buildable: indexmap::IndexMap<_, _> = scan_result
            .buildable()
            .map(|p| (p.pkgname().clone(), p.clone()))
            .collect();

        let pkgsrc_env = self
            .db
            .load_pkgsrc_env()
            .context("PkgsrcEnv not cached - try 'bob clean' first")?;

        let mut build = Build::new(&self.config, pkgsrc_env, scope, buildable);

        // Load cached build results from database
        build.load_cached_from_db(&self.db)?;

        tracing::debug!("Calling build.start()");
        let build_start_time = std::time::Instant::now();
        let mut summary = build.start(&self.ctx, &self.db)?;
        tracing::debug!(
            elapsed_ms = build_start_time.elapsed().as_millis(),
            "build.start() returned"
        );

        // Check if we were interrupted. All builds that completed before the
        // interrupt have already been saved to the database inside build.start().
        // Builds that were in-progress when interrupted were killed and their
        // results discarded (not saved). This ensures:
        //   - Completed builds are preserved
        //   - Interrupted (partial) builds are not saved
        //   - Dependencies of interrupted builds are not saved
        if self.ctx.shutdown.load(Ordering::SeqCst) {
            return Err(Interrupted.into());
        }

        // Add pre-skipped/failed/unresolved packages from scan to summary
        for pkg in scan_result.packages.iter() {
            match pkg {
                ScanResult::Skipped {
                    pkgpath,
                    reason,
                    index,
                    ..
                } => {
                    let Some(pkgname) = index.as_ref().map(|i| &i.pkgname) else {
                        error!(%pkgpath, "Skipped package missing PKGNAME");
                        continue;
                    };
                    summary.results.push(build::BuildResult {
                        pkgname: pkgname.clone(),
                        pkgpath: Some(pkgpath.clone()),
                        outcome: build::BuildOutcome::Skipped(reason.clone()),
                        duration: std::time::Duration::ZERO,
                        log_dir: None,
                    });
                }
                ScanResult::ScanFail { pkgpath, error } => {
                    summary.scanfail.push((pkgpath.clone(), error.clone()));
                }
                ScanResult::Buildable(_) => {}
            }
        }
        Ok(summary)
    }

    /// Generate pkg_summary.gz for all successful packages.
    fn generate_pkg_summary(&self) {
        print!("Generating pkg_summary.gz...");
        if std::io::Write::flush(&mut std::io::stdout()).is_err() {
            return;
        }
        tracing::debug!("Generating pkg_summary.gz");
        let start = std::time::Instant::now();
        match bob::generate_pkg_summary(&self.db, self.config.build_threads()) {
            Ok(()) => {
                println!(" done ({:.1}s)", start.elapsed().as_secs_f32());
                tracing::debug!(
                    elapsed_ms = start.elapsed().as_millis(),
                    "Finished generating pkg_summary.gz"
                );
            }
            Err(e) => {
                println!();
                eprintln!("Warning: Failed to generate pkg_summary.gz: {}", e);
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
            let mut scope = SandboxScope::new(sandbox, runner.ctx.clone());
            runner.run_scan_phase(&mut scan, &mut scope)?;
            drop(scope);

            let result = scan.resolve_with_report(&runner.db, runner.config.strict_scan())?;
            result.print_resolved();
            let up_to_date = if scan_only {
                None
            } else {
                Some(runner.check_up_to_date(&result)?)
            };
            result.print_counts(up_to_date);
        }
        Cmd::Build {
            pkgpaths: cmdline_pkgs,
        } => {
            let mut runner = BuildRunner::new(args.config.as_deref())?;
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
            let mut scope = SandboxScope::new(sandbox, runner.ctx.clone());
            runner.run_scan_phase(&mut scan, &mut scope)?;
            let scan_result = scan.resolve_with_report(&runner.db, runner.config.strict_scan())?;
            runner.check_up_to_date(&scan_result)?;
            let summary = runner.run_build_with(scan_result, scope)?;
            if summary.counts().success > 0 {
                runner.generate_pkg_summary();
            }
        }
        Cmd::Rebuild {
            all,
            only,
            packages,
        } => {
            let runner = BuildRunner::new(args.config.as_deref())?;
            cmd::rebuild::run(
                &runner.config,
                &runner.db,
                &runner.ctx,
                cmd::rebuild::RebuildArgs {
                    all,
                    only,
                    packages,
                },
            )?;
        }
        Cmd::Report => {
            let config = Config::load(args.config.as_deref())?;
            let logdir = config.logdir();
            let db_path = logdir.join("bob").join("bob.db");

            if !db_path.exists() {
                bail!(
                    "No database found at {}.  Perform a build first.",
                    db_path.display()
                );
            }

            println!("Generating report...");
            let db = Database::open(&db_path)?;
            let report_path = logdir.join("report.html");
            report::write_html_report(&db, logdir, &report_path)?;
            println!("HTML report written to: {}", report_path.display());
        }
        Cmd::Clean { logs_only } => {
            let config = Config::load(args.config.as_deref())?;
            let logdir = config.logdir();

            if !logdir.exists() {
                return Ok(());
            }

            if logs_only {
                for entry in std::fs::read_dir(logdir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_dir() && entry.file_name() != "bob" {
                        std::fs::remove_dir_all(&path)
                            .with_context(|| format!("Failed to remove {}", path.display()))?;
                    }
                }
            } else {
                std::fs::remove_dir_all(logdir).context("Failed to remove logs directory")?;
            }
        }
        Cmd::Db { sql } => {
            let config = Config::load(args.config.as_deref())?;
            let db_path = config.logdir().join("bob").join("bob.db");
            let db = Database::open(&db_path)?;

            let Some(sql) = sql else {
                bail!("SQL command required");
            };

            db.execute_raw(&sql)?;
        }
        Cmd::List { cmd } => {
            let config = Config::load(args.config.as_deref())?;
            let db_path = config.logdir().join("bob").join("bob.db");
            let db = Database::open(&db_path)?;
            cmd::list::run(&db, cmd)?;
        }
        Cmd::Util {
            cmd: UtilCmd::PrintDepGraph { output },
        } => {
            let config = Config::load(args.config.as_deref())?;
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");
            let db = Database::open(&db_path)?;

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
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");
            let db = Database::open(&db_path)?;

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
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");
            let db = Database::open(&db_path)?;

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
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");
            let db = Database::open(&db_path)?;

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
