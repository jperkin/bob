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
        // Check if a previous full scan completed
        if scan.is_full_tree() && self.db.full_scan_complete() {
            scan.set_full_scan_complete();
        }

        // Load cached scans
        let cached = self.db.get_all_scan()?;
        if !cached.is_empty() {
            let loaded = scan.load_cached(cached);
            if loaded > 0 {
                println!("Loaded {} cached package paths", loaded);
            }
        }

        let interrupted = scan.start(&self.ctx)?;

        // Store scan results
        for (pkgpath, indexes) in scan.completed() {
            if !indexes.is_empty() {
                self.db.store_scan_pkgpath(&pkgpath.to_string(), indexes)?;
            }
        }

        if interrupted {
            self.flush_stats();
            std::process::exit(EXIT_INTERRUPTED);
        }

        // Handle scan errors
        let scan_errors: Vec<_> = scan.scan_errors().collect();
        if !scan_errors.is_empty() {
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

        println!("Resolving dependencies...");
        scan.resolve()
    }

    /// Run the build phase, returning the build summary.
    fn run_build(
        &self,
        scan_result: bob::scan::ScanResult,
    ) -> Result<build::BuildSummary> {
        if scan_result.buildable.is_empty() {
            bail!("No packages to build");
        }

        let mut build = Build::new(&self.config, scan_result.buildable.clone());

        // Load cached build results
        let cached_build = self.db.get_all_build()?;
        if !cached_build.is_empty() {
            build.load_cached(cached_build);
        }

        let mut summary = build.start(&self.ctx)?;

        // Store build results
        for result in &summary.results {
            self.db.store_build_pkgname(result.pkgname.pkgname(), result)?;
        }

        self.flush_stats();

        // Check if we were interrupted
        if self.ctx.shutdown.load(Ordering::SeqCst) {
            let sandbox = Sandbox::new(&self.config);
            if sandbox.enabled() {
                let _ = sandbox.destroy_all(self.config.build_threads());
            }
            std::process::exit(EXIT_INTERRUPTED);
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
    fn generate_report(&self, summary: &build::BuildSummary) {
        println!("Generating reports...");
        let logdir = self.config.logdir();
        let report_path = logdir.join("report.html");
        if let Err(e) = report::write_html_report(summary, &report_path) {
            eprintln!("Warning: Failed to write HTML report: {}", e);
        } else {
            println!("HTML report written to: {}", report_path.display());
        }
    }

    /// Look up pkgpath for a pkgname from scan cache.
    fn find_pkgpath_for_pkgname(
        &self,
        pkgname: &str,
    ) -> Result<Option<pkgsrc::PkgPath>> {
        let cached = self.db.get_all_scan()?;
        for (_pkgpath, indexes) in &cached {
            for idx in indexes {
                if idx.pkgname.pkgname() == pkgname {
                    if let Some(ref loc) = idx.pkg_location {
                        return Ok(Some(loc.clone()));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Find all packages that depend on the given pkgpaths (reverse dependencies).
    /// Returns pkgnames of packages that should be rebuilt.
    fn find_dependents(
        &self,
        pkgpaths: &[&str],
    ) -> Result<(Vec<String>, std::collections::HashMap<String, String>)> {
        use std::collections::{HashMap, HashSet, VecDeque};

        let cached = self.db.get_all_scan()?;

        // Build reverse dependency map: pkgpath -> packages that depend on it
        let mut rev_deps: HashMap<String, Vec<String>> = HashMap::new();
        let mut pkgname_to_pkgpath: HashMap<String, String> = HashMap::new();

        for (_pkgpath, indexes) in &cached {
            for idx in indexes {
                let pkgname = idx.pkgname.pkgname().to_string();
                if let Some(ref loc) = idx.pkg_location {
                    pkgname_to_pkgpath
                        .entry(pkgname.clone())
                        .or_insert_with(|| loc.to_string());
                }
                if let Some(ref all_deps) = idx.all_depends {
                    for dep in all_deps {
                        rev_deps
                            .entry(dep.pkgpath().to_string())
                            .or_default()
                            .push(pkgname.clone());
                    }
                }
            }
        }

        // BFS to find all transitive dependents
        let mut to_clear: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> =
            pkgpaths.iter().map(|s| s.to_string()).collect();

        while let Some(pkgpath) = queue.pop_front() {
            if let Some(dependents) = rev_deps.get(&pkgpath) {
                for dep_pkgname in dependents {
                    if to_clear.insert(dep_pkgname.clone()) {
                        // Find the pkgpath for this dependent to continue traversal
                        if let Some(dep_path) =
                            pkgname_to_pkgpath.get(dep_pkgname)
                        {
                            queue.push_back(dep_path.clone());
                        }
                    }
                }
            }
        }

        Ok((to_clear.into_iter().collect(), pkgname_to_pkgpath))
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
        /// Package paths or package names to rebuild
        #[arg(required = true, value_name = "PKGPATH|PKGNAME")]
        packages: Vec<String>,
    },
    /// Clear all cached scan and build state from the database
    Clean,
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
            runner.generate_report(&summary);
        }
        Cmd::Rebuild { packages } => {
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
                } else if runner.db.delete_build_pkgname(pkg)? {
                    cleared += 1;
                }
            }

            // Also clear dependents (packages that depend on what we're rebuilding)
            let pkgpath_refs: Vec<&str> =
                pkgpaths_to_rebuild.iter().map(|s| s.as_str()).collect();
            let (dependents, pkgname_to_pkgpath) =
                runner.find_dependents(&pkgpath_refs)?;
            for dep in &dependents {
                if runner.db.delete_build_pkgname(dep)? {
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
            let summary = runner.run_build(scan_result)?;
            print_summary(&summary);
        }
        Cmd::Util { cmd: UtilCmd::GenerateReport } => {
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
        Cmd::Util { cmd: UtilCmd::PrintDepGraph { output } } => {
            let config = Config::load(args.config.as_deref(), args.verbose)?;
            let logs_dir = config.logdir().join("bob");
            let db_path = logs_dir.join("bob.db");
            let db = Database::open(&db_path)?;

            let cached = db.get_all_scan()?;
            if cached.is_empty() {
                bail!("No cached scan data found. Run 'bob scan' first.");
            }

            let mut scan = Scan::new(&config);
            scan.load_cached(cached);

            let result = scan.resolve()?;

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

            let cached = db.get_all_scan()?;
            if cached.is_empty() {
                bail!("No cached scan data found. Run 'bob scan' first.");
            }

            let mut scan = Scan::new(&config);
            scan.load_cached(cached);

            let result = scan.resolve()?;

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

            let cached = db.get_all_scan()?;
            if cached.is_empty() {
                bail!(
                    "No cached scan data found. Run 'bob scan' or 'bob util import-pscan' first."
                );
            }

            // Collect all ScanIndex entries
            let all_indexes: Vec<_> =
                cached.values().flat_map(|v| v.iter()).collect();

            // Build output
            let mut out = String::new();
            for idx in &all_indexes {
                out.push_str(&idx.to_string());
            }

            // Write to file or stdout
            if let Some(path) = output {
                std::fs::write(&path, &out)?;
                println!(
                    "Wrote {} packages to {}",
                    all_indexes.len(),
                    path.display()
                );
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

            let result = runner.run_scan(&mut scan)?;
            println!("Resolved {} buildable packages", result.buildable.len());
        }
    };

    Ok(())
}
