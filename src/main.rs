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
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::error;

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
        .expect("Error setting signal handler");

        let ctx = RunContext::new(Arc::clone(&shutdown_flag));

        Ok(Self { config, db, ctx })
    }

    /**
     * Run scan phase with a provided scope (for scan+build flow).
     *
     * The scope is managed by the caller, allowing it to persist for a
     * subsequent build phase. Returns `Err(Interrupted)` if interrupted.
     */
    fn run_scan_with_scope(
        &self,
        scan: &mut Scan,
        scope: &mut SandboxScope,
    ) -> Result<bob::scan::ScanSummary> {
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
        drop(scan_errors);

        println!("Resolving dependencies...");
        let result = scan.resolve(&self.db)?;

        // Check for unresolved dependency errors
        let errors: Vec<_> = result.errors().collect();
        if !errors.is_empty() {
            eprintln!("Unresolved dependencies:\n  {}", errors.join("\n  "));
            if self.config.strict_scan() {
                bail!(
                    "Aborting due to unresolved dependencies (strict_scan enabled)"
                );
            }
        }

        Ok(result)
    }

    /**
     * Run scan phase standalone (creates its own scope).
     *
     * The scope is destroyed when this function returns (or on error).
     */
    fn run_scan(&self, scan: &mut Scan) -> Result<bob::scan::ScanSummary> {
        let sandbox = Sandbox::new(&self.config);
        let mut scope = SandboxScope::new(sandbox, self.ctx.clone());
        self.run_scan_with_scope(scan, &mut scope)
    }

    fn run_build_with(
        &mut self,
        scan_result: bob::scan::ScanSummary,
        options: build::BuildOptions,
        mut scope: SandboxScope,
    ) -> Result<build::BuildSummary> {
        // Validate config before sandbox expansion
        if scan_result.count_buildable() == 0 {
            bail!("No packages to build");
        }

        let buildable: indexmap::IndexMap<_, _> = scan_result
            .buildable()
            .map(|p| (p.pkgname().clone(), p.clone()))
            .collect();

        // Expand to build_threads sandboxes (creates any that don't exist)
        scope.ensure(self.config.build_threads())?;

        let pkgsrc_env = self
            .db
            .load_pkgsrc_env()
            .context("PkgsrcEnv not cached - try 'bob clean' first")?;

        let mut build =
            Build::new(&self.config, pkgsrc_env, scope, buildable, options);

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
                ScanResult::Skipped { pkgpath, reason, index, .. } => {
                    let Some(pkgname) = index.as_ref().map(|i| &i.pkgname)
                    else {
                        error!(pkgpath = %pkgpath, "Skipped package missing PKGNAME");
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

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Initialise a new build directory and configuration file
    Init { dir: PathBuf },
    /// Perform recursive scan of packages and resolve dependencies
    Scan,
    /// Build all scanned packages
    Build {
        /// Package paths to build (overrides config pkgpaths)
        #[arg(value_name = "PKGPATH")]
        pkgpaths: Vec<String>,
    },
    /// Rebuild specific packages
    Rebuild {
        /// Rebuild all packages from scan cache.
        #[arg(short, long)]
        all: bool,
        /// Force rebuild even if package is up-to-date
        #[arg(short, long)]
        force: bool,
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

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.downcast_ref::<Interrupted>().is_some() => {
            ExitCode::from(EXIT_INTERRUPTED)
        }
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args = Args::parse();

    match args.cmd {
        Cmd::Init { dir: ref arg } => {
            Init::create(arg)?;
        }
        Cmd::Scan => {
            let runner = BuildRunner::new(args.config.as_deref())?;

            let mut scan = Scan::new(&runner.config);
            if let Some(pkgs) = runner.config.pkgpaths() {
                for p in pkgs {
                    scan.add(p);
                }
            }

            let result = runner.run_scan(&mut scan)?;
            println!("{result}");
        }
        Cmd::Build { pkgpaths: cmdline_pkgs } => {
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
            let scan_result =
                runner.run_scan_with_scope(&mut scan, &mut scope)?;
            runner.run_build_with(
                scan_result,
                build::BuildOptions::default(),
                scope,
            )?;
            runner.generate_pkg_summary();
        }
        Cmd::Rebuild { all, force, packages } => {
            if !all && packages.is_empty() {
                bail!(
                    "Either specify packages to rebuild or use -a to rebuild all"
                );
            }

            let mut runner = BuildRunner::new(args.config.as_deref())?;

            let mut scan = Scan::new(&runner.config);

            if all {
                let cleared = runner.db.clear_builds()?;
                if cleared > 0 {
                    println!("Cleared {} cached build result(s)", cleared);
                }
                if let Some(pkgs) = runner.config.pkgpaths() {
                    for p in pkgs {
                        scan.add(p);
                    }
                }
            } else {
                // Convert packages to pkgpaths and collect for dependent lookup
                let mut pkgpaths_to_rebuild: Vec<String> = Vec::new();

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
                                 Run 'bob scan' first or specify the full \
                                 PKGPATH.",
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

                // Also clear dependents (packages that depend on what we're
                // rebuilding)
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
            }

            let sandbox = Sandbox::new(&runner.config);
            let mut scope = SandboxScope::new(sandbox, runner.ctx.clone());
            let scan_result =
                runner.run_scan_with_scope(&mut scan, &mut scope)?;
            let options = build::BuildOptions { force_rebuild: force };
            runner.run_build_with(scan_result, options, scope)?;
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
                        std::fs::remove_dir_all(&path).with_context(|| {
                            format!("Failed to remove {}", path.display())
                        })?;
                    }
                }
            } else {
                std::fs::remove_dir_all(logdir)
                    .context("Failed to remove logs directory")?;
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
        Cmd::Util { cmd: UtilCmd::PrintDepGraph { output } } => {
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

            let result = scan.resolve(&db)?;

            // Build DAG output
            let mut edges: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();
            for pkg in result.buildable() {
                let pkgname = pkg.pkgname();
                for dep in pkg.depends() {
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

            let result = scan.resolve(&db)?;

            // Print unresolved dependency errors
            let errors: Vec<_> = result.errors().collect();
            if !errors.is_empty() {
                eprintln!(
                    "Unresolved dependencies:\n  {}",
                    errors.join("\n  ")
                );
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
        Cmd::Util { cmd: UtilCmd::ImportPscan { file } } => {
            use indexmap::IndexMap;
            use pkgsrc::ScanIndex;
            use std::fs::File;
            use std::io::BufReader;

            let config = Config::load(args.config.as_deref())?;
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
            let config = Config::load(args.config.as_deref())?;
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
            logging::init_stderr_if_enabled();
            let config = Config::load(args.config.as_deref())?;
            let sandbox = Sandbox::new(&config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            sandbox.create_all(config.build_threads())?;
        }
        Cmd::Util { cmd: UtilCmd::Sandbox { cmd: SandboxCmd::Destroy } } => {
            logging::init_stderr_if_enabled();
            let config = Config::load(args.config.as_deref())?;
            let sandbox = Sandbox::new(&config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            sandbox.destroy_all(config.build_threads())?;
        }
        Cmd::Util { cmd: UtilCmd::Sandbox { cmd: SandboxCmd::List } } => {
            let config = Config::load(args.config.as_deref())?;
            let sandbox = Sandbox::new(&config);
            if !sandbox.enabled() {
                bail!("No sandboxes configured");
            }
            sandbox.list_all(config.build_threads());
        }
    };

    Ok(())
}
