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
use bob::db::Database;
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

/// Exit code when interrupted.  We do not know what exact signal this was.
const EXIT_INTERRUPTED: i32 = 128 + libc::SIGINT;

/// Common context for build operations.
struct BuildRunner {
    config: Config,
    db: Database,
    ctx: RunContext,
}

impl BuildRunner {
    /// Set up the build environment: config, logging, validation, db, signals.
    fn new(
        config_path: Option<&Path>,
        verbose: bool,
        for_build: bool,
    ) -> Result<Self> {
        let config = Config::load(config_path, verbose)?;
        let logs_dir = config.logdir().join("bob");

        logging::init(&logs_dir, config.verbose())?;

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
        let sandbox_for_handler = Sandbox::new(&config);
        let sandbox_count = if for_build { config.build_threads() } else { 1 };

        ctrlc::set_handler(move || {
            shutdown_for_handler.store(true, Ordering::SeqCst);
            if sandbox_for_handler.enabled() {
                for i in 0..sandbox_count {
                    sandbox_for_handler.kill_processes_by_id(i);
                }
            }
        })
        .expect("Error setting signal handler");

        let stats_path = logs_dir.join("stats.jsonl");
        let stats = Stats::new(&stats_path)?;
        let ctx = RunContext::new(Arc::clone(&shutdown_flag))
            .with_stats(Arc::new(stats));

        Ok(Self { config, db, ctx })
    }

    /// Run the scan phase, returning the resolved scan result.
    fn run_scan(&self, scan: &mut Scan) -> Result<bob::scan::ScanResult> {
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
                println!(
                    "Resuming scan with {} pending dependencies",
                    pending_count
                );
            }
        }

        let interrupted = scan.start(&self.ctx, &self.db)?;

        if interrupted {
            self.flush_stats();
            std::process::exit(EXIT_INTERRUPTED);
        }

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
        drop(scan_errors);

        println!("Resolving dependencies...");
        let result = scan.resolve(&self.db)?;

        Ok(result)
    }

    /// Run the build phase, returning the build summary.
    fn run_build(
        &self,
        scan_result: bob::scan::ScanResult,
    ) -> Result<build::BuildSummary> {
        self.run_build_with(scan_result, build::BuildOptions::default())
    }

    fn run_build_with(
        &self,
        scan_result: bob::scan::ScanResult,
        options: build::BuildOptions,
    ) -> Result<build::BuildSummary> {
        if self.config.packages().is_none() {
            bail!("pkgsrc.packages must be set for build operations");
        }
        if self.config.pkgtools().is_none() {
            bail!("pkgsrc.pkgtools must be set for build operations");
        }
        if self.config.prefix().is_none() {
            bail!("pkgsrc.prefix must be set for build operations");
        }
        if self.config.tar().is_none() {
            bail!("pkgsrc.tar must be set for build operations");
        }
        if scan_result.buildable.is_empty() {
            bail!("No packages to build");
        }

        let mut build =
            Build::new(&self.config, scan_result.buildable.clone(), options);

        // Load cached build results from database
        build.load_cached_from_db(&self.db)?;

        tracing::debug!("Calling build.start()");
        let build_start_time = std::time::Instant::now();
        let mut summary = build.start(&self.ctx, &self.db)?;
        tracing::debug!(
            elapsed_ms = build_start_time.elapsed().as_millis(),
            "build.start() returned"
        );

        // Check if we were interrupted - results are already saved during build
        if self.ctx.shutdown.load(Ordering::SeqCst) {
            let sandbox = Sandbox::new(&self.config);
            if sandbox.enabled() {
                let _ = sandbox.destroy_all(self.config.build_threads());
            }
            std::process::exit(EXIT_INTERRUPTED);
        }

        // Store any remaining build results (most are saved during build)
        if !summary.results.is_empty() {
            print!("Saving {} build results...", summary.results.len());
            std::io::Write::flush(&mut std::io::stdout())?;
            tracing::debug!(
                result_count = summary.results.len(),
                "Storing build results to database"
            );
            let store_start = std::time::Instant::now();
            self.db.store_build_batch(&summary.results)?;
            println!(" done ({:.1}s)", store_start.elapsed().as_secs_f32());
            tracing::debug!(
                elapsed_ms = store_start.elapsed().as_millis(),
                "Finished storing build results"
            );
        }

        self.flush_stats();

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
                outcome: build::BuildOutcome::PreFailed(reason),
                duration: std::time::Duration::ZERO,
                log_dir: None,
            });
        }

        summary.scan_failed = scan_result.scan_failed;
        Ok(summary)
    }

    /// Flush stats if available.
    fn flush_stats(&self) {
        if let Some(ref s) = self.ctx.stats {
            s.flush();
        }
    }

    /// Generate and print the HTML report.
    fn generate_report(&self) {
        println!("Generating reports...");
        let logdir = self.config.logdir();
        let report_path = logdir.join("report.html");
        if let Err(e) =
            report::write_html_report(&self.db, logdir, &report_path)
        {
            eprintln!("Warning: Failed to write HTML report: {}", e);
        } else {
            println!("HTML report written to: {}", report_path.display());
        }
    }

    /// Look up pkgpath for a pkgname from database.
    fn find_pkgpath_for_pkgname(
        &self,
        pkgname: &str,
    ) -> Result<Option<pkgsrc::PkgPath>> {
        if let Some(pkg) = self.db.get_package_by_name(pkgname)? {
            return Ok(Some(pkgsrc::PkgPath::new(&pkg.pkgpath)?));
        }
        Ok(None)
    }

    /// Find all packages that depend on the given pkgpaths (reverse dependencies).
    /// Returns pkgnames of packages that should be rebuilt.
    fn find_dependents(
        &self,
        pkgpaths: &[&str],
    ) -> Result<(Vec<String>, std::collections::HashMap<String, String>)> {
        use std::collections::HashMap;

        // Get all packages for pkgname -> pkgpath mapping
        let all_packages = self.db.get_all_packages()?;
        let mut pkgname_to_pkgpath: HashMap<String, String> = HashMap::new();
        let mut pkgname_to_id: HashMap<String, i64> = HashMap::new();

        for pkg in &all_packages {
            pkgname_to_pkgpath.insert(pkg.pkgname.clone(), pkg.pkgpath.clone());
            pkgname_to_id.insert(pkg.pkgname.clone(), pkg.id);
        }

        // Find package IDs for the given pkgpaths
        let mut seed_ids: Vec<i64> = Vec::new();
        for pkgpath in pkgpaths {
            let packages = self.db.get_packages_by_path(pkgpath)?;
            for pkg in packages {
                seed_ids.push(pkg.id);
            }
        }

        // Use database to get all transitive reverse dependencies
        let mut to_clear: Vec<String> = Vec::new();
        for seed_id in seed_ids {
            let rev_deps = self.db.get_transitive_reverse_deps(seed_id)?;
            for dep_id in rev_deps {
                let pkgname = self.db.get_pkgname(dep_id)?;
                if !to_clear.contains(&pkgname) {
                    to_clear.push(pkgname);
                }
            }
        }

        Ok((to_clear, pkgname_to_pkgpath))
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

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Create a new configuration area
    Init { dir: PathBuf },
    /// Perform recursive scan of packages to calculate dependencies
    Scan,
    /// Build all scanned packages
    Build {
        /// Package paths to build (overrides config pkgpaths)
        #[arg(value_name = "PKGPATH")]
        pkgpaths: Vec<String>,
    },
    /// Rebuild specific packages, clearing cached results
    Rebuild {
        /// Force rebuild even if package is up-to-date
        #[arg(short, long)]
        force: bool,
        /// Package paths or package names to rebuild
        #[arg(required = true, value_name = "PKGPATH|PKGNAME")]
        packages: Vec<String>,
    },
    /// Clear all cached scan and build state from the database
    Clean,
    /// Run SQL commands against the database
    Db {
        /// SQL command to execute (omit for interactive mode)
        #[arg(value_name = "SQL")]
        sql: Option<String>,
    },
    /// Utility commands for debugging and data import/export
    Util {
        #[command(subcommand)]
        cmd: UtilCmd,
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
    /// Generate HTML report from existing logdir data
    GenerateReport,
    /// Create and destroy build sandboxes
    Sandbox {
        #[command(subcommand)]
        cmd: SandboxCmd,
    },
    /// Output the resolved dependency graph from cached scan data
    PrintDepGraph {
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
    /// Import a pbulk pscan file into the database for resolver comparison
    ImportPscan {
        /// Path to the pscan file
        file: PathBuf,
    },
    /// Output raw scan data from the database (without resolution)
    PrintPscan {
        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn print_summary(summary: &build::BuildSummary) {
    println!();
    println!("Build Summary");
    println!("=============");
    println!("  Succeeded:          {}", summary.success_count());
    println!("  Failed:             {}", summary.failed_count());
    println!("  Up-to-date:         {}", summary.up_to_date_count());
    println!("  Pre-failed:         {}", summary.prefailed_count());
    println!("  Indirect failed:    {}", summary.indirect_failed_count());
    println!("  Indirect prefailed: {}", summary.indirect_prefailed_count());
    if summary.scan_failed_count() > 0 {
        println!("  Scan failed:        {}", summary.scan_failed_count());
    }
    println!();
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.cmd {
        Cmd::Build { pkgpaths: cmdline_pkgs } => {
            let runner =
                BuildRunner::new(args.config.as_deref(), args.verbose, true)?;
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

            let scan_result = runner.run_scan(&mut scan)?;
            let summary = runner.run_build(scan_result)?;
            print_summary(&summary);
            runner.generate_report();
        }
        Cmd::Rebuild { force, packages } => {
            let runner =
                BuildRunner::new(args.config.as_deref(), args.verbose, true)?;

            // Convert packages to pkgpaths and collect for dependent lookup
            let mut pkgpaths_to_rebuild: Vec<String> = Vec::new();
            let mut scan = Scan::new(&runner.config);

            for pkg in &packages {
                if pkg.contains('/') {
                    match pkgsrc::PkgPath::new(pkg) {
                        Ok(pkgpath) => {
                            pkgpaths_to_rebuild.push(pkgpath.to_string());
                            scan.add(&pkgpath);
                        }
                        Err(e) => bail!("Invalid PKGPATH '{}': {}", pkg, e),
                    }
                } else {
                    match runner.find_pkgpath_for_pkgname(pkg)? {
                        Some(pkgpath) => {
                            pkgpaths_to_rebuild.push(pkgpath.to_string());
                            scan.add(&pkgpath);
                        }
                        None => bail!(
                            "Package '{}' not found in scan cache. \
                             Run 'bob scan' first or specify the full PKGPATH.",
                            pkg
                        ),
                    }
                }
            }

            // Clear cached build results for specified packages
            let mut cleared = 0;
            for pkg in &packages {
                if pkg.contains('/') {
                    cleared += runner.db.delete_build_by_pkgpath(pkg)?;
                } else if runner.db.delete_build_by_name(pkg)? {
                    cleared += 1;
                }
            }

            // Also clear dependents (packages that depend on what we're rebuilding)
            let pkgpath_refs: Vec<&str> =
                pkgpaths_to_rebuild.iter().map(|s| s.as_str()).collect();
            let (dependents, pkgname_to_pkgpath) =
                runner.find_dependents(&pkgpath_refs)?;
            for dep in &dependents {
                if runner.db.delete_build_by_name(dep)? {
                    cleared += 1;
                }
                if let Some(pkgpath) = pkgname_to_pkgpath.get(dep) {
                    if let Ok(pkgpath) = pkgsrc::PkgPath::new(pkgpath) {
                        scan.add(&pkgpath);
                    }
                }
            }

            if cleared > 0 {
                println!("Cleared {} cached build result(s)", cleared);
            }

            let scan_result = runner.run_scan(&mut scan)?;
            let options = build::BuildOptions { force_rebuild: force };
            let summary = runner.run_build_with(scan_result, options)?;
            print_summary(&summary);
        }
        Cmd::Util { cmd: UtilCmd::GenerateReport } => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let logdir = config.logdir();
            let logs_dir = logdir.join("bob");
            let db_path = logs_dir.join("bob.db");

            if !db_path.exists() {
                bail!(
                    "No database found at {}. Run a build first.",
                    db_path.display()
                );
            }

            println!("Generating reports...");
            let db = Database::open(&db_path)?;
            let report_path = logdir.join("report.html");
            report::write_html_report(&db, logdir, &report_path)?;
            println!("HTML report written to: {}", report_path.display());
        }
        Cmd::Init { dir: ref arg } => {
            Init::create(arg)?;
        }
        Cmd::Clean => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");
            let db = Database::open(&db_path)?;

            let scan_count = db.count_scan()?;
            let build_count = db.count_build()?;

            db.clear_scan()?;
            db.clear_build()?;

            println!(
                "Cleared {} cached scan entries and {} cached build entries",
                scan_count, build_count
            );
        }
        Cmd::Db { sql } => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let db_path = config.logdir().join("bob").join("bob.db");
            let db = Database::open(&db_path)?;

            let Some(sql) = sql else {
                bail!("SQL command required");
            };

            db.execute_raw(&sql)?;
        }
        Cmd::Util { cmd: UtilCmd::PrintDepGraph { output } } => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");
            let db = Database::open(&db_path)?;

            let count = db.count_packages()?;
            if count == 0 {
                bail!("No cached scan data found. Run 'bob scan' first.");
            }

            let mut scan = Scan::new(&config);
            scan.init_from_db(&db)?;

            let result = scan.resolve(&db)?;

            // Build DAG output
            let mut edges: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();
            for (pkgname, idx) in &result.buildable {
                for dep in &idx.depends {
                    edges.insert(format!("{} -> {}", dep, pkgname));
                }
            }
            let out: String =
                edges.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n")
                    + "\n";

            // Write to file or stdout
            if let Some(path) = output {
                std::fs::write(&path, &out)?;
                println!("Wrote {} edges to {}", edges.len(), path.display());
            } else {
                print!("{}", out);
            }
        }
        Cmd::Util { cmd: UtilCmd::PrintPresolve { output } } => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");
            let db = Database::open(&db_path)?;

            let count = db.count_packages()?;
            if count == 0 {
                bail!("No cached scan data found. Run 'bob scan' first.");
            }

            let mut scan = Scan::new(&config);
            scan.init_from_db(&db)?;

            let result = scan.resolve(&db)?;

            // Build presolve output in original order
            let mut out = String::new();
            for (idx, _reason) in &result.all_ordered {
                out.push_str(&idx.to_string());
            }

            // Write to file or stdout
            if let Some(path) = output {
                std::fs::write(&path, &out)?;
                println!(
                    "Wrote {} buildable, {} skipped to {}",
                    result.buildable.len(),
                    result.skipped.len(),
                    path.display()
                );
            } else {
                print!("{}", out);
            }
        }
        Cmd::Util { cmd: UtilCmd::ImportPscan { file } } => {
            use indexmap::IndexMap;
            use pkgsrc::ScanIndex;
            use std::fs::File;
            use std::io::BufReader;

            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");
            let db = Database::open(&db_path)?;

            println!("Importing pscan file: {}", file.display());

            let f = File::open(&file)?;
            let reader = BufReader::new(f);

            // Parse all ScanIndex entries and group by pkgpath (preserving order)
            let mut by_pkgpath: IndexMap<String, Vec<ScanIndex>> =
                IndexMap::new();
            let mut count = 0;
            let mut errors = 0;

            for result in ScanIndex::from_reader(reader) {
                match result {
                    Ok(index) => {
                        let pkgpath = index
                            .pkg_location
                            .as_ref()
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "unknown".to_string());
                        by_pkgpath.entry(pkgpath).or_default().push(index);
                        count += 1;
                    }
                    Err(e) => {
                        eprintln!("Parse error: {}", e);
                        errors += 1;
                    }
                }
            }

            if errors > 0 {
                eprintln!("Warning: {} parse errors", errors);
            }

            // Clear existing data and import
            db.clear_scan()?;
            for (pkgpath, indexes) in &by_pkgpath {
                db.store_scan_pkgpath(pkgpath, indexes)?;
            }

            println!(
                "Imported {} packages from {} package paths",
                count,
                by_pkgpath.len()
            );
        }
        Cmd::Util { cmd: UtilCmd::PrintPscan { output } } => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");
            let db = Database::open(&db_path)?;

            let packages = db.get_all_packages()?;
            if packages.is_empty() {
                bail!(
                    "No cached scan data found. Run 'bob scan' or 'bob util import-pscan' first."
                );
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
        Cmd::Util { cmd: UtilCmd::Sandbox { cmd: SandboxCmd::Create } } => {
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
        Cmd::Util { cmd: UtilCmd::Sandbox { cmd: SandboxCmd::Destroy } } => {
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
        Cmd::Util { cmd: UtilCmd::Sandbox { cmd: SandboxCmd::List } } => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let sandbox = Sandbox::new(&config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            sandbox.list_all(config.build_threads());
        }
        Cmd::Scan => {
            let runner =
                BuildRunner::new(args.config.as_deref(), args.verbose, false)?;

            let mut scan = Scan::new(&runner.config);
            if let Some(pkgs) = runner.config.pkgpaths() {
                for p in pkgs {
                    scan.add(p);
                }
            }

            // Fast path: for full tree scans with everything cached, just get count
            let buildable = if scan.is_full_tree()
                && runner.db.full_scan_complete()
                && runner.db.is_resolved()?
            {
                runner.db.get_buildable_count()? as usize
            } else {
                runner.run_scan(&mut scan)?.buildable.len()
            };
            let pkgpaths = runner.db.count_scan()?;
            println!(
                "Resolved {} buildable packages from {} package paths",
                buildable, pkgpaths
            );
        }
    };

    Ok(())
}
