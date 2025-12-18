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

use crate::{Config, Sandbox};
use anyhow::{bail, Context};
use glob::Pattern;
use pkgsrc::{PkgName, PkgPath, ScanIndex};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, mpsc::Sender, Arc, Mutex};
use std::time::{Duration, Instant};

/// Format a ScanIndex as pbulk-index output for piping to scripts.
/// XXX: switch to simply calling display() once pkgsrc-rs is updated.
fn format_scan_index(idx: &ScanIndex) -> String {
    let mut out = String::new();

    out.push_str(&format!("PKGNAME={}\n", idx.pkgname.pkgname()));

    if let Some(ref loc) = idx.pkg_location {
        out.push_str(&format!("PKG_LOCATION={}\n", loc.as_path().display()));
    }

    if !idx.depends.is_empty() {
        let deps: Vec<&str> = idx.depends.iter().map(|d| d.pkgname()).collect();
        out.push_str(&format!("DEPENDS={}\n", deps.join(" ")));
    }

    if !idx.multi_version.is_empty() {
        out.push_str(&format!("MULTI_VERSION={}\n", idx.multi_version.join(" ")));
    }

    if let Some(ref bootstrap) = idx.bootstrap_pkg {
        out.push_str(&format!("BOOTSTRAP_PKG={}\n", bootstrap));
    }

    if let Some(ref phase) = idx.usergroup_phase {
        out.push_str(&format!("USERGROUP_PHASE={}\n", phase));
    }

    out
}

/// Outcome of a package build attempt.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum BuildOutcome {
    /// Package built successfully.
    Success,
    /// Package build failed with reason.
    Failed(String),
    /// Package was skipped with reason (e.g., dependency failed).
    Skipped(String),
}

/// Result of building a single package.
#[derive(Clone, Debug)]
pub struct BuildResult {
    /// Package name.
    pub pkgname: PkgName,
    /// Package path in pkgsrc.
    pub pkgpath: Option<PkgPath>,
    /// Build outcome.
    pub outcome: BuildOutcome,
    /// Build duration.
    pub duration: Duration,
    /// Path to build logs, if any.
    pub log_dir: Option<PathBuf>,
}

/// Summary of the entire build run.
#[derive(Clone, Debug)]
pub struct BuildSummary {
    /// Total duration of the build.
    pub duration: Duration,
    /// Individual build results.
    pub results: Vec<BuildResult>,
}

impl BuildSummary {
    /// Count of successfully built packages.
    pub fn success_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::Success))
            .count()
    }

    /// Count of failed packages.
    pub fn failed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::Failed(_)))
            .count()
    }

    /// Count of skipped packages.
    pub fn skipped_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::Skipped(_)))
            .count()
    }

    /// Get all failed results.
    pub fn failed(&self) -> Vec<&BuildResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::Failed(_)))
            .collect()
    }

    /// Get all successful results.
    pub fn succeeded(&self) -> Vec<&BuildResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::Success))
            .collect()
    }

    /// Get all skipped results.
    pub fn skipped(&self) -> Vec<&BuildResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::Skipped(_)))
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct Build {
    /**
     * Parsed [`Config`].
     */
    config: Config,
    /**
     * [`Sandbox`] configuration.
     */
    sandbox: Sandbox,
    /**
     * List of packages to build, as input from Scan::resolve.
     */
    scanpkgs: HashMap<PkgName, ScanIndex>,
}

#[derive(Debug)]
struct PackageBuild {
    id: usize,
    config: Config,
    pkginfo: ScanIndex,
    sandbox: Sandbox,
}

/// Helper for querying bmake variables with the correct environment.
struct MakeQuery<'a> {
    config: &'a Config,
    sandbox: &'a Sandbox,
    sandbox_id: usize,
    pkgpath: &'a PkgPath,
    env: &'a HashMap<String, String>,
}

impl<'a> MakeQuery<'a> {
    fn new(
        config: &'a Config,
        sandbox: &'a Sandbox,
        sandbox_id: usize,
        pkgpath: &'a PkgPath,
        env: &'a HashMap<String, String>,
    ) -> Self {
        Self {
            config,
            sandbox,
            sandbox_id,
            pkgpath,
            env,
        }
    }

    /// Query a bmake variable value.
    fn var(&self, name: &str) -> Option<String> {
        let pkgdir = self.config.pkgsrc().join(self.pkgpath.as_path());

        let mut cmd = if self.sandbox.enabled() {
            let mut c = Command::new("/usr/sbin/chroot");
            c.arg(self.sandbox.path(self.sandbox_id))
                .arg(self.config.make());
            c
        } else {
            Command::new(self.config.make())
        };

        cmd.arg("-C")
            .arg(&pkgdir)
            .arg("show-var")
            .arg(format!("VARNAME={}", name));

        // Pass env vars that may affect the variable value
        for (key, value) in self.env {
            cmd.env(key, value);
        }

        let output = cmd.output().ok()?;

        if !output.status.success() {
            return None;
        }

        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    }

    /// Query a bmake variable and return as PathBuf.
    fn var_path(&self, name: &str) -> Option<PathBuf> {
        self.var(name).map(PathBuf::from)
    }

    /// Get the WRKDIR for this package.
    fn wrkdir(&self) -> Option<PathBuf> {
        self.var_path("WRKDIR")
    }

    /// Get the WRKSRC for this package.
    #[allow(dead_code)]
    fn wrksrc(&self) -> Option<PathBuf> {
        self.var_path("WRKSRC")
    }

    /// Get the DESTDIR for this package.
    #[allow(dead_code)]
    fn destdir(&self) -> Option<PathBuf> {
        self.var_path("DESTDIR")
    }

    /// Get the PREFIX for this package.
    #[allow(dead_code)]
    fn prefix(&self) -> Option<PathBuf> {
        self.var_path("PREFIX")
    }

    /// Resolve a path to its actual location on the host filesystem.
    /// If sandboxed, prepends the sandbox root path.
    fn resolve_path(&self, path: &Path) -> PathBuf {
        if self.sandbox.enabled() {
            self.sandbox
                .path(self.sandbox_id)
                .join(path.strip_prefix("/").unwrap_or(path))
        } else {
            path.to_path_buf()
        }
    }
}

/// Result of a single package build attempt.
#[derive(Debug)]
enum PackageBuildResult {
    /// Build succeeded
    Success,
    /// Build failed
    Failed,
    /// Package was up-to-date, skipped
    Skipped,
}

impl PackageBuild {
    fn build(&self) -> anyhow::Result<PackageBuildResult> {
        let pkgname = self.pkginfo.pkgname.pkgname();

        let Some(pkgpath) = &self.pkginfo.pkg_location else {
            bail!("Could not get PKGPATH for {}", pkgname);
        };

        let bulklog = self.config.bulklog();
        let packages = self.config.packages();

        // Core environment vars that are always set
        let mut envs = vec![
            ("bob_bulklog", format!("{}", bulklog.display())),
            ("bob_make", format!("{}", self.config.make().display())),
            ("bob_packages", format!("{}", packages.display())),
            ("bob_pkgtools", format!("{}", self.config.pkgtools().display())),
            ("bob_pkgsrc", format!("{}", self.config.pkgsrc().display())),
            ("bob_prefix", format!("{}", self.config.prefix().display())),
            ("bob_tar", format!("{}", self.config.tar().display())),
            ("bob_unprivileged_user", self.config.unprivileged_user().to_string()),
        ];

        // Add script paths
        if let Some(pkg_up_to_date) = self.config.script("pkg-up-to-date") {
            envs.push((
                "PKG_UP_TO_DATE",
                format!("{}", pkg_up_to_date.display()),
            ));
        }

        // Get env vars from Lua config (function or table)
        let pkg_env = match self.config.get_pkg_env(&self.pkginfo) {
            Ok(env) => {
                for (key, value) in &env {
                    envs.push((Box::leak(key.clone().into_boxed_str()), value.clone()));
                }
                env
            }
            Err(_e) => {
                HashMap::new()
            }
        };

        // If we have save_wrkdir_patterns, tell the script not to clean so we can save files
        let patterns = self.config.save_wrkdir_patterns();
        if !patterns.is_empty() {
            envs.push(("SKIP_CLEAN", "1".to_string()));
        }

        let Some(pkg_build_path) = &self.config.script("pkg-build") else {
            bail!("No pkg-build script defined");
        };

        // Format ScanIndex as pbulk-index output for stdin
        let stdin_data = format_scan_index(&self.pkginfo);

        let child = self.sandbox.execute(self.id, pkg_build_path, envs, Some(&stdin_data))?;
        let output =
            child.wait_with_output().context("Failed to wait for pkg-build")?;

        let exit_code = output.status.code().context("Process terminated by signal")?;

        match exit_code {
            0 => {
                Ok(PackageBuildResult::Success)
            }
            42 => {
                Ok(PackageBuildResult::Skipped)
            }
            _ => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.is_empty() {
                    eprintln!("pkg-build stderr: {}", stderr);
                }

                // Save wrkdir files matching configured patterns, then clean up
                if !patterns.is_empty() {
                    self.save_wrkdir_files(pkgname, pkgpath, bulklog, patterns, &pkg_env);
                    self.run_clean(pkgpath);
                }
                Ok(PackageBuildResult::Failed)
            }
        }
    }

    /// Save files matching patterns from WRKDIR to bulklog on build failure.
    fn save_wrkdir_files(
        &self,
        pkgname: &str,
        pkgpath: &PkgPath,
        bulklog: &Path,
        patterns: &[String],
        pkg_env: &HashMap<String, String>,
    ) {
        let make = MakeQuery::new(&self.config, &self.sandbox, self.id, pkgpath, pkg_env);

        // Get WRKDIR
        let wrkdir = match make.wrkdir() {
            Some(w) => w,
            None => {
                return;
            }
        };

        // Resolve to actual filesystem path
        let wrkdir_path = make.resolve_path(&wrkdir);

        if !wrkdir_path.exists() {
            return;
        }

        let save_dir = bulklog.join(pkgname).join("wrkdir-files");
        if let Err(_e) = fs::create_dir_all(&save_dir) {
            return;
        }

        // Compile glob patterns
        let compiled_patterns: Vec<Pattern> = patterns
            .iter()
            .filter_map(|p| {
                Pattern::new(p).ok()
            })
            .collect();

        if compiled_patterns.is_empty() {
            return;
        }

        // Walk the wrkdir and find matching files
        let mut saved_count = 0;
        if let Err(_e) = walk_and_save(&wrkdir_path, &wrkdir_path, &save_dir, &compiled_patterns, &mut saved_count) {
        }

        if saved_count > 0 {
            println!("Saved {} wrkdir files for {} to {}", saved_count, pkgname, save_dir.display());
        }
    }

    /// Run bmake clean for a package.
    fn run_clean(&self, pkgpath: &PkgPath) {
        let pkgdir = self.config.pkgsrc().join(pkgpath.as_path());

        let _result = if self.sandbox.enabled() {
            Command::new("/usr/sbin/chroot")
                .arg(self.sandbox.path(self.id))
                .arg(self.config.make())
                .arg("-C")
                .arg(&pkgdir)
                .arg("clean")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
        } else {
            Command::new(self.config.make())
                .arg("-C")
                .arg(&pkgdir)
                .arg("clean")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
        };
    }
}

/// Recursively walk a directory and save files matching patterns.
fn walk_and_save(
    base: &Path,
    current: &Path,
    save_dir: &Path,
    patterns: &[Pattern],
    saved_count: &mut usize,
) -> std::io::Result<()> {
    if !current.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            walk_and_save(base, &path, save_dir, patterns, saved_count)?;
        } else if path.is_file() {
            // Get relative path from base
            let rel_path = path.strip_prefix(base).unwrap_or(&path);
            let rel_str = rel_path.to_string_lossy();

            // Check if any pattern matches
            for pattern in patterns {
                if pattern.matches(&rel_str) || pattern.matches(path.file_name().unwrap_or_default().to_string_lossy().as_ref()) {
                    // Create destination directory
                    let dest_path = save_dir.join(rel_path);
                    if let Some(parent) = dest_path.parent() {
                        fs::create_dir_all(parent)?;
                    }

                    // Copy the file
                    if let Err(_e) = fs::copy(&path, &dest_path) {
                    } else {
                        *saved_count += 1;
                    }
                    break; // Don't copy same file multiple times
                }
            }
        }
    }

    Ok(())
}

/**
 * Commands sent between the manager and clients.
 */
#[derive(Debug)]
enum ChannelCommand {
    /**
     * Client (with specified identifier) indicating they are ready for work.
     */
    ClientReady(usize),
    /**
     * Manager has no work available at the moment, try again later.
     */
    ComeBackLater,
    /**
     * Manager directing a client to build a specific package.
     */
    JobData(Box<PackageBuild>),
    /**
     * Client returning a successful package build with duration.
     */
    JobSuccess(PkgName, Duration),
    /**
     * Client returning a failed package build with duration.
     */
    JobFailed(PkgName, Duration),
    /**
     * Client returning a skipped package (up-to-date).
     */
    JobSkipped(PkgName),
    /**
     * Client returning an error during the package build.
     */
    JobError((PkgName, Duration, anyhow::Error)),
    /**
     * Manager directing a client to quit.
     */
    Quit,
    /**
     * Shutdown signal - workers should stop immediately.
     */
    Shutdown,
}

/**
 * Return the current build job status.
 */
#[derive(Debug)]
enum BuildStatus {
    /**
     * The next package ordered by priority is available for building.
     */
    Available(PkgName),
    /**
     * No packages are currently available for building, i.e. all remaining
     * packages have at least one dependency that is still unavailable.
     */
    NoneAvailable,
    /**
     * All package builds have been completed.
     */
    Done,
}

#[derive(Clone, Debug)]
struct BuildJobs {
    scanpkgs: HashMap<PkgName, ScanIndex>,
    incoming: HashMap<PkgName, HashSet<PkgName>>,
    running: HashSet<PkgName>,
    done: HashSet<PkgName>,
    failed: HashSet<PkgName>,
    results: Vec<BuildResult>,
    bulklog: PathBuf,
}

impl BuildJobs {
    /**
     * Mark a package as successful and remove it from pending dependencies.
     */
    fn mark_success(&mut self, pkgname: &PkgName, duration: Duration) {
        self.mark_done(pkgname, BuildOutcome::Success, duration);
    }

    /**
     * Mark a package as skipped (up-to-date) and remove it from pending dependencies.
     */
    fn mark_skipped(&mut self, pkgname: &PkgName) {
        self.mark_done(pkgname, BuildOutcome::Skipped("up-to-date".to_string()), Duration::ZERO);
    }

    fn mark_done(&mut self, pkgname: &PkgName, outcome: BuildOutcome, duration: Duration) {
        /*
         * Remove the package from the list of dependencies in all
         * packages it is listed in.  Once a package has no outstanding
         * dependencies remaining it is ready for building.
         */
        for dep in self.incoming.values_mut() {
            if dep.contains(pkgname) {
                dep.remove(pkgname);
            }
        }
        /*
         * The package was already removed from "incoming" when it started
         * building, so we only need to add it to "done".
         */
        self.done.insert(pkgname.clone());

        // Record the result
        let scanpkg = self.scanpkgs.get(pkgname);
        let log_dir = Some(self.bulklog.join(pkgname.pkgname()));
        self.results.push(BuildResult {
            pkgname: pkgname.clone(),
            pkgpath: scanpkg.and_then(|s| s.pkg_location.clone()),
            outcome,
            duration,
            log_dir,
        });
    }

    /**
     * Recursively mark a package and its dependents as failed.
     */
    fn mark_failure(&mut self, pkgname: &PkgName, duration: Duration) {
        let mut broken: HashSet<PkgName> = HashSet::new();
        let mut to_check: Vec<PkgName> = vec![];
        to_check.push(pkgname.clone());
        /*
         * Starting with the original failed package, recursively loop through
         * adding any packages that depend on it, adding them to broken.
         */
        loop {
            /* No packages left to check, we're done. */
            let Some(badpkg) = to_check.pop() else {
                break;
            };
            /* Already checked this package. */
            if broken.contains(&badpkg) {
                continue;
            }
            for (pkg, deps) in &self.incoming {
                if deps.contains(&badpkg) {
                    to_check.push(pkg.clone());
                }
            }
            broken.insert(badpkg);
        }
        /*
         * We now have a full HashSet of affected packages.  Remove them from
         * incoming and move to failed.  The original failed package will
         * already be removed from incoming, we rely on .remove() accepting
         * this.
         */
        let is_original = |p: &PkgName| p == pkgname;
        for pkg in broken {
            self.incoming.remove(&pkg);
            self.failed.insert(pkg.clone());

            // Record the result
            let scanpkg = self.scanpkgs.get(&pkg);
            let log_dir = Some(self.bulklog.join(pkg.pkgname()));
            let (outcome, dur) = if is_original(&pkg) {
                (BuildOutcome::Failed("Build failed".to_string()), duration)
            } else {
                (
                    BuildOutcome::Skipped(format!(
                        "Dependency {} failed",
                        pkgname.pkgname()
                    )),
                    Duration::ZERO,
                )
            };
            self.results.push(BuildResult {
                pkgname: pkg,
                pkgpath: scanpkg.and_then(|s| s.pkg_location.clone()),
                outcome,
                duration: dur,
                log_dir,
            });
        }
    }

    /**
     * Get next package status.
     */
    fn get_next_build(&self) -> BuildStatus {
        /*
         * If incoming is empty then we're done.
         */
        if self.incoming.is_empty() {
            return BuildStatus::Done;
        }

        /*
         * Get all packages in incoming that are cleared for building, ordered
         * by weighting.
         *
         * TODO: weighting should be the sum of all transitive dependencies.
         */
        let mut pkgs: Vec<(PkgName, usize)> = self
            .incoming
            .iter()
            .filter(|(_, v)| v.is_empty())
            .map(|(k, _)| {
                (
                    k.clone(),
                    self.scanpkgs
                        .get(k)
                        .unwrap()
                        .pbulk_weight
                        .clone()
                        .unwrap_or("100".to_string())
                        .parse()
                        .unwrap_or(100),
                )
            })
            .collect();

        /*
         * If no packages are returned then we're still waiting for
         * dependencies to finish.  Clients should keep retrying until this
         * changes.
         */
        if pkgs.is_empty() {
            return BuildStatus::NoneAvailable;
        }

        /*
         * Order packages by build weight and return the highest.
         */
        pkgs.sort_by_key(|&(_, weight)| std::cmp::Reverse(weight));
        BuildStatus::Available(pkgs[0].0.clone())
    }
}

fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if hours > 0 {
        format!("{}h{:02}m{:02}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m{:02}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

impl Build {
    pub fn new(
        config: &Config,
        scanpkgs: HashMap<PkgName, ScanIndex>,
    ) -> Build {
        let sandbox = Sandbox::new(config);
        Build { config: config.clone(), sandbox, scanpkgs }
    }

    pub fn start(&mut self, shutdown_flag: Arc<AtomicBool>) -> anyhow::Result<BuildSummary> {
        let started = Instant::now();

        println!("Building {} packages...", self.scanpkgs.len());

        /*
         * Populate BuildJobs.
         */
        let mut incoming: HashMap<PkgName, HashSet<PkgName>> = HashMap::new();
        for (pkgname, index) in &self.scanpkgs {
            let mut deps: HashSet<PkgName> = HashSet::new();
            for dep in &index.depends {
                deps.insert(dep.clone());
            }
            incoming.insert(pkgname.clone(), deps);
        }

        let running: HashSet<PkgName> = HashSet::new();
        let done: HashSet<PkgName> = HashSet::new();
        let failed: HashSet<PkgName> = HashSet::new();
        let results: Vec<BuildResult> = Vec::new();
        let bulklog = self.config.bulklog().clone();
        let jobs = BuildJobs {
            scanpkgs: self.scanpkgs.clone(),
            incoming,
            running,
            done,
            failed,
            results,
            bulklog,
        };

        if self.sandbox.enabled() {
            for i in 0..self.config.build_threads() {
                self.sandbox.create(i)?;
            }
        }

        /*
         * Configure a mananger channel.  This is used for clients to indicate
         * to the manager that they are ready for work.
         */
        let (manager_tx, manager_rx) = mpsc::channel::<ChannelCommand>();

        /*
         * Client threads.  Each client has its own channel to the manager,
         * with the client sending ready status on the manager channel, and
         * receiving instructions on its private channel.
         */
        let mut threads = vec![];
        let mut clients: HashMap<usize, Sender<ChannelCommand>> =
            HashMap::new();
        for i in 0..self.config.build_threads() {
            let (client_tx, client_rx) = mpsc::channel::<ChannelCommand>();
            clients.insert(i, client_tx);
            let manager_tx = manager_tx.clone();
            let thread = std::thread::spawn(move || loop {
                // Use send() which can fail if receiver is dropped (manager shutdown)
                if manager_tx.send(ChannelCommand::ClientReady(i)).is_err() {
                    break;
                }

                let Ok(msg) = client_rx.recv() else {
                    break;
                };

                match msg {
                    ChannelCommand::ComeBackLater => {
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    ChannelCommand::JobData(pkg) => {
                        let pkgname = pkg.pkginfo.pkgname.clone();
                        let build_start = Instant::now();
                        match pkg.build() {
                            Ok(PackageBuildResult::Success) => {
                                let duration = build_start.elapsed();
                                let _ = manager_tx
                                    .send(ChannelCommand::JobSuccess(
                                        pkgname, duration,
                                    ));
                            }
                            Ok(PackageBuildResult::Skipped) => {
                                let _ = manager_tx
                                    .send(ChannelCommand::JobSkipped(pkgname));
                            }
                            Ok(PackageBuildResult::Failed) => {
                                let duration = build_start.elapsed();
                                let _ = manager_tx
                                    .send(ChannelCommand::JobFailed(
                                        pkgname, duration,
                                    ));
                            }
                            Err(e) => {
                                let duration = build_start.elapsed();
                                let _ = manager_tx
                                    .send(ChannelCommand::JobError((
                                        pkgname, duration, e,
                                    )));
                            }
                        }
                        continue;
                    }
                    ChannelCommand::Quit | ChannelCommand::Shutdown => {
                        break;
                    }
                    _ => todo!(),
                }
            });
            threads.push(thread);
        }

        /*
         * Manager thread.  Read incoming commands from clients and reply
         * accordingly.  Returns the build results via a channel.
         */
        let config = self.config.clone();
        let sandbox = self.sandbox.clone();
        let shutdown_for_manager = Arc::clone(&shutdown_flag);
        let (results_tx, results_rx) = mpsc::channel::<Vec<BuildResult>>();
        let (interrupted_tx, interrupted_rx) = mpsc::channel::<bool>();
        let completed = Arc::new(Mutex::new(0usize));
        let skipped = Arc::new(Mutex::new(0usize));
        let failed_count = Arc::new(Mutex::new(0usize));
        let manager = std::thread::spawn(move || {
            let mut clients = clients.clone();
            let config = config.clone();
            let sandbox = sandbox.clone();
            let mut jobs = jobs.clone();
            let mut was_interrupted = false;

            loop {
                // Check shutdown flag periodically
                if shutdown_for_manager.load(Ordering::SeqCst) {
                    // Send shutdown to all remaining clients
                    for (_, client) in clients.drain() {
                        let _ = client.send(ChannelCommand::Shutdown);
                    }
                    was_interrupted = true;
                    break;
                }

                // Use recv_timeout to check shutdown flag periodically
                let command = match manager_rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(cmd) => cmd,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };

                match command {
                    ChannelCommand::ClientReady(c) => {
                        let client = clients.get(&c).unwrap();
                        match jobs.get_next_build() {
                            BuildStatus::Available(pkg) => {
                                let pkginfo = jobs.scanpkgs.get(&pkg).unwrap();
                                jobs.incoming.remove(&pkg);
                                jobs.running.insert(pkg.clone());

                                let _ = client
                                    .send(ChannelCommand::JobData(Box::new(
                                        PackageBuild {
                                            id: c,
                                            config: config.clone(),
                                            pkginfo: pkginfo.clone(),
                                            sandbox: sandbox.clone(),
                                        },
                                    )));
                            }
                            BuildStatus::NoneAvailable => {
                                let _ = client
                                    .send(ChannelCommand::ComeBackLater);
                            }
                            BuildStatus::Done => {
                                let _ = client.send(ChannelCommand::Quit);
                                clients.remove(&c);
                                if clients.is_empty() {
                                    break;
                                }
                            }
                        };
                    }
                    ChannelCommand::JobSuccess(pkgname, duration) => {
                        // Don't report if we're shutting down
                        if shutdown_for_manager.load(Ordering::SeqCst) {
                            continue;
                        }

                        jobs.mark_success(&pkgname, duration);
                        jobs.running.remove(&pkgname);

                        if let Ok(mut count) = completed.lock() {
                            *count += 1;
                        }
                        println!("Built {} ({})", pkgname.pkgname(), format_duration(duration));
                    }
                    ChannelCommand::JobSkipped(pkgname) => {
                        // Don't report if we're shutting down
                        if shutdown_for_manager.load(Ordering::SeqCst) {
                            continue;
                        }

                        jobs.mark_skipped(&pkgname);
                        jobs.running.remove(&pkgname);

                        if let Ok(mut count) = skipped.lock() {
                            *count += 1;
                        }
                        println!("Skipped {} (up-to-date)", pkgname.pkgname());
                    }
                    ChannelCommand::JobFailed(pkgname, duration) => {
                        // Don't report if we're shutting down
                        if shutdown_for_manager.load(Ordering::SeqCst) {
                            continue;
                        }

                        jobs.mark_failure(&pkgname, duration);
                        jobs.running.remove(&pkgname);

                        if let Ok(mut count) = failed_count.lock() {
                            *count += 1;
                        }
                        println!("Failed {} ({})", pkgname.pkgname(), format_duration(duration));
                    }
                    ChannelCommand::JobError((pkgname, duration, e)) => {
                        // Don't report if we're shutting down
                        if shutdown_for_manager.load(Ordering::SeqCst) {
                            continue;
                        }

                        jobs.mark_failure(&pkgname, duration);
                        jobs.running.remove(&pkgname);

                        if let Ok(mut count) = failed_count.lock() {
                            *count += 1;
                        }
                        eprintln!("Failed {} ({}): {}", pkgname.pkgname(), format_duration(duration), e);
                    }
                    _ => {}
                }
            }

            // Send results and interrupted status back
            let _ = results_tx.send(jobs.results);
            let _ = interrupted_tx.send(was_interrupted);
        });

        threads.push(manager);
        for thread in threads {
            thread.join().expect("thread panicked");
        }

        // Check if we were interrupted
        let was_interrupted = interrupted_rx.recv().unwrap_or(false);

        // Collect results from manager
        let results = results_rx.recv().unwrap_or_default();
        let summary = BuildSummary { duration: started.elapsed(), results };

        // Print summary
        if was_interrupted {
            println!("\nBuild interrupted!");
        } else {
            println!("\nBuild completed in {}", format_duration(summary.duration));
            println!("Success: {}, Failed: {}, Skipped: {}",
                summary.success_count(),
                summary.failed_count(),
                summary.skipped_count());
        }

        if self.sandbox.enabled() {
            for i in 0..self.config.build_threads() {
                self.sandbox.destroy(i)?;
            }
        }

        Ok(summary)
    }
}
