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

//! Parallel package builds.
//!
//! This module provides the [`Build`] struct for building packages in parallel
//! across multiple sandboxes. Packages are scheduled using a dependency graph
//! to ensure correct build order.
//!
//! # Build Process
//!
//! 1. Create build sandboxes (one per `build_threads`)
//! 2. Execute pre-build script in each sandbox
//! 3. Build packages in parallel, respecting dependencies
//! 4. Execute post-build script after each package
//! 5. Destroy sandboxes and generate report
//!
//! # Build Phases
//!
//! Each package goes through these phases in turn:
//!
//! - `pre-clean` - Clean any previous build artifacts
//! - `depends` - Install required dependencies
//! - `checksum` - Verify distfile checksums
//! - `configure` - Configure the build
//! - `build` - Compile the package
//! - `install` - Install to staging area
//! - `package` - Create binary package
//! - `deinstall` - Test package removal (non-bootstrap only)
//! - `clean` - Clean up build artifacts

use crate::config::{PkgsrcEnv, WrkObjKind};
use crate::makejobs::PkgMakeJobs;
use crate::sandbox::{CommandSetsid, SHUTDOWN_POLL_INTERVAL, SandboxScope, wait_with_shutdown};
use crate::scan::ResolvedPackage;
use crate::scheduler::Scheduler;
use crate::tui::{MultiProgress, REFRESH_INTERVAL, format_duration};
use crate::{Config, RunState, Sandbox};
use crate::{PackageCounts, PackageState};
use anyhow::{Context, bail};
use crossterm::event;
use glob::Pattern;
use indexmap::IndexMap;
use pkgsrc::archive::BinaryPackage;
use pkgsrc::digest::Digest;
use pkgsrc::metadata::FileRead;
use pkgsrc::{PkgName, PkgPath};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc, mpsc::Sender};
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, info_span, trace, warn};

fn epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// How often to batch and send build output lines to the UI channel.
/// This is the floor on log display responsiveness — output cannot appear
/// faster than this regardless of UI refresh rate. 100ms (10fps) is
/// imperceptible for build logs while reducing channel overhead.
const OUTPUT_BATCH_INTERVAL: Duration = Duration::from_millis(100);

/// How long a worker thread sleeps when told no work is available.
/// This prevents busy-spinning when all pending builds are blocked on
/// dependencies. 100ms balances responsiveness with CPU efficiency.
const WORKER_BACKOFF_INTERVAL: Duration = Duration::from_millis(100);

/**
 * Reason why a package needs to be built.
 *
 * Returned by [`pkg_up_to_date`] when a package is not current with its
 * sources. Used by `bob list tree -r` to show why packages need building.
 */
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildReason {
    /// Binary package file doesn't exist.
    PackageNotFound,
    /// A tracked source file no longer exists.
    BuildFileRemoved(String),
    /// A tracked source file has changed (hash or CVS ID mismatch).
    BuildFileChanged(String),
    /**
     * A single dependency was added.
     *
     * Currently unused.  pkgsrc's ALL_DEPENDS includes indirect
     * buildlink3 dependencies that are not recorded in the binary
     * package's BUILD_DEPENDS, so comparing the two sets produces
     * false "added" results.  To match pbulk behaviour, we only
     * check for removed or updated dependencies.
     *
     * Retained for future use if pkgsrc gains support for correctly
     * distinguishing direct vs indirect build dependencies.
     */
    DependencyAdded(String),
    /**
     * Multiple dependencies were added.
     *
     * See [`DependencyAdded`](Self::DependencyAdded) for why this is
     * currently unused.
     */
    DependenciesAdded(Vec<String>),
    /// A single dependency was removed.
    DependencyRemoved(String),
    /// Multiple dependencies were removed.
    DependenciesRemoved(Vec<String>),
    /// A single dependency was updated (pkgbase, old_ver, new_ver).
    DependencyUpdated(String, String, String),
    /// Multiple dependencies were updated.
    DependenciesUpdated(Vec<(String, String, String)>),
    /// Mixed dependency changes (updates, additions, removals).
    DependenciesChanged {
        updated: Vec<(String, String, String)>,
        added: Vec<String>,
        removed: Vec<String>,
    },
    /// A dependency package file is missing.
    DependencyMissing(String),
    /// A dependency is marked as refreshed (rebuild without changing version).
    DependencyRefresh(String),
}

impl std::fmt::Display for BuildReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildReason::PackageNotFound => write!(f, "package not found"),
            BuildReason::BuildFileRemoved(file) => {
                write!(f, "build file removed: {}", file)
            }
            BuildReason::BuildFileChanged(file) => {
                write!(f, "build file changed: {}", file)
            }
            BuildReason::DependencyAdded(dep) => {
                write!(f, "dependency added: {}", dep)
            }
            BuildReason::DependenciesAdded(deps) => {
                write!(f, "dependencies added: {}", deps.join(", "))
            }
            BuildReason::DependencyRemoved(dep) => {
                write!(f, "dependency removed: {}", dep)
            }
            BuildReason::DependenciesRemoved(deps) => {
                write!(f, "dependencies removed: {}", deps.join(", "))
            }
            BuildReason::DependencyUpdated(base, old, new) => {
                write!(f, "dependency updated: {} {} -> {}", base, old, new)
            }
            BuildReason::DependenciesUpdated(updates) => {
                let parts: Vec<String> = updates
                    .iter()
                    .map(|(base, old, new)| format!("{} {} -> {}", base, old, new))
                    .collect();
                write!(f, "dependencies updated: {}", parts.join(", "))
            }
            BuildReason::DependenciesChanged {
                updated,
                added,
                removed,
            } => {
                let mut parts = Vec::new();
                for r in removed {
                    parts.push(format!("-{}", r));
                }
                for a in added {
                    parts.push(format!("+{}", a));
                }
                for (base, old, new) in updated {
                    parts.push(format!("{} {} -> {}", base, old, new));
                }
                write!(f, "dependencies changed: {}", parts.join(", "))
            }
            BuildReason::DependencyMissing(dep) => {
                write!(f, "dependency missing: {}", dep)
            }
            BuildReason::DependencyRefresh(dep) => {
                write!(f, "dependency refreshed: {}", dep)
            }
        }
    }
}

/**
 * Check if a package binary is up-to-date with its sources.
 *
 * Returns `Ok(None)` if the package doesn't need rebuilding:
 * - Package file exists
 * - All tracked source files match (CVS ID or SHA256 hash)
 * - Dependencies match expected list
 * - No dependency package is newer than this package
 *
 * Returns `Ok(Some(reason))` if the package needs building, with the reason.
 *
 * This function is called during the scan phase to pre-compute which
 * packages need building, allowing `bob list tree` to show accurate
 * results and `bob build` to skip up-to-date packages entirely.
 */
pub fn pkg_up_to_date(
    pkgname: &str,
    depends: &[&str],
    packages_dir: &Path,
    pkgsrc_dir: &Path,
) -> anyhow::Result<Option<BuildReason>> {
    let pkgfile = packages_dir.join(format!("{}.tgz", pkgname));

    let pkgfile_mtime = match pkgfile.metadata().and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(_) => {
            debug!(path = %pkgfile.display(), "Package file not found");
            return Ok(Some(BuildReason::PackageNotFound));
        }
    };

    let pkg = BinaryPackage::open(&pkgfile)
        .with_context(|| format!("Failed to open package {}", pkgfile.display()))?;

    let build_version = pkg
        .build_version()
        .context("Failed to read BUILD_VERSION")?
        .unwrap_or_default();
    debug!(
        lines = build_version.lines().count(),
        "Checking BUILD_VERSION"
    );

    for line in build_version.lines() {
        let Some((file, file_id)) = line.split_once(':') else {
            continue;
        };
        let file_id = file_id.trim();
        if file.is_empty() || file_id.is_empty() {
            continue;
        }

        let src_file = pkgsrc_dir.join(file);
        if !src_file.exists() {
            debug!(file, "File removed");
            return Ok(Some(BuildReason::BuildFileRemoved(file.to_string())));
        }

        if file_id.starts_with("$NetBSD") {
            let Ok(content) = std::fs::read_to_string(&src_file) else {
                return Ok(Some(BuildReason::BuildFileRemoved(file.to_string())));
            };
            let id = content.lines().find_map(|line| {
                let start = line.find("$NetBSD")?;
                let end = line[start + 1..].find('$')?;
                Some(&line[start..start + end + 2])
            });
            if id != Some(file_id) {
                debug!(file, "CVS ID mismatch");
                return Ok(Some(BuildReason::BuildFileChanged(file.to_string())));
            }
        } else {
            let mut f = File::open(&src_file)
                .with_context(|| format!("Failed to open {}", src_file.display()))?;
            let hash = Digest::SHA256
                .hash_file(&mut f)
                .with_context(|| format!("Failed to digest {file}"))?;
            if hash != file_id {
                debug!(
                    file,
                    path = %src_file.display(),
                    expected = file_id,
                    actual = hash,
                    "Hash mismatch"
                );
                return Ok(Some(BuildReason::BuildFileChanged(file.to_string())));
            }
        }
    }

    let recorded_deps: HashSet<&str> = pkg
        .plist()
        .build_depends()
        .into_iter()
        .filter(|l| !l.is_empty())
        .collect();
    let expected_deps: HashSet<&str> = depends.iter().copied().collect();

    /*
     * Match pbulk behaviour: only check that each recorded dependency
     * still exists in the expected set.  Dependencies that appear in
     * ALL_DEPENDS but weren't recorded in the binary package (e.g.
     * indirect buildlink3 dependencies) are not grounds for a rebuild.
     */
    let removed_set: HashSet<&str> = recorded_deps.difference(&expected_deps).copied().collect();

    if !removed_set.is_empty() {
        let expected_by_base: HashMap<String, (&str, String)> = expected_deps
            .iter()
            .map(|&name| {
                let pkg = PkgName::new(name);
                (
                    pkg.pkgbase().to_string(),
                    (name, pkg.pkgversion().to_string()),
                )
            })
            .collect();

        let mut updated = Vec::new();
        let mut removed = Vec::new();

        for &name in &removed_set {
            let pkg = PkgName::new(name);
            if let Some((_, new_ver)) = expected_by_base.get(pkg.pkgbase()) {
                updated.push((
                    pkg.pkgbase().to_string(),
                    pkg.pkgversion().to_string(),
                    new_ver.clone(),
                ));
            } else {
                removed.push(name.to_string());
            }
        }

        debug!(?updated, ?removed, "Dependency list changed");
        let reason = if updated.is_empty() {
            if removed.len() == 1 {
                BuildReason::DependencyRemoved(removed.swap_remove(0))
            } else {
                BuildReason::DependenciesRemoved(removed)
            }
        } else if removed.is_empty() {
            if updated.len() == 1 {
                let (base, old, new) = updated.swap_remove(0);
                BuildReason::DependencyUpdated(base, old, new)
            } else {
                BuildReason::DependenciesUpdated(updated)
            }
        } else {
            BuildReason::DependenciesChanged {
                updated,
                added: Vec::new(),
                removed,
            }
        };
        return Ok(Some(reason));
    }

    for dep in &recorded_deps {
        let dep_pkg = packages_dir.join(format!("{}.tgz", dep));
        let dep_mtime = match dep_pkg.metadata().and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => {
                debug!(dep, "Dependency package missing");
                return Ok(Some(BuildReason::DependencyMissing((*dep).to_string())));
            }
        };
        if dep_mtime > pkgfile_mtime {
            debug!(dep, "Dependency is newer");
            return Ok(Some(BuildReason::DependencyRefresh((*dep).to_string())));
        }
    }

    debug!(pkgname, "Package is up-to-date");
    Ok(None)
}

/**
 * Build stages in order of execution.
 *
 * Discriminants match the `stage_types` lookup table in the database.
 */
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    strum::EnumProperty,
    strum::FromRepr,
    strum::IntoStaticStr,
    strum::VariantArray,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case", const_into_str)]
#[repr(i32)]
pub enum Stage {
    PreClean = 1,
    Depends = 2,
    Checksum = 3,
    Configure = 4,
    Build = 5,
    Install = 6,
    Package = 7,
    Deinstall = 8,
    Clean = 9,
}

/**
 * All stage columns are durations, so always right-aligned.
 */
impl crate::ColumnAlign for Stage {
    fn align(&self) -> crate::Align {
        crate::Align::Right
    }
}

/**
 * Metrics captured during a package build.
 */
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct PkgBuildStats {
    /// MAKE_JOBS used for this build.
    pub make_jobs: PkgMakeJobs,
    /// Last build stage attempted.
    pub stage: Option<Stage>,
    /// Per-stage wall-clock durations.
    pub stage_durations: Vec<(Stage, Duration)>,
    /// Per-stage CPU time (user+sys from wait4).
    pub stage_cpu_times: Vec<(Stage, Duration)>,
    /// WRKDIR size in bytes, measured before clean.
    pub disk_usage: Option<u64>,
    /// WRKOBJDIR type used for this build.
    pub wrkobjdir: Option<WrkObjKind>,
    /// Wall-clock duration for the entire build.
    pub duration: Duration,
    /// Unix epoch when the build started.
    pub timestamp: i64,
}

/// Result of a package build.
#[derive(Debug)]
enum PkgBuildResult {
    Success(PkgBuildStats),
    Failed(PkgBuildStats),
}

impl std::fmt::Display for PkgBuildResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success(_) => write!(f, "success"),
            Self::Failed(_) => write!(f, "failed"),
        }
    }
}

/// How to run a command.
#[derive(Debug, Clone, Copy)]
enum RunAs {
    Root,
    User,
}

/// Callback for status updates during build.
trait BuildCallback: Send {
    fn stage(&mut self, stage: &str);
}

/// Session-level build data shared across all package builds.
#[derive(Debug)]
struct BuildSession {
    config: Config,
    pkgsrc_env: PkgsrcEnv,
    sandbox: Sandbox,
    state: RunState,
    wrkobjdir_map: HashMap<PkgName, WrkObjKind>,
}

/// Package builder that executes build stages.
struct PkgBuilder<'a> {
    session: &'a BuildSession,
    sandbox_id: Option<usize>,
    worker_id: usize,
    pkginfo: &'a ResolvedPackage,
    logdir: PathBuf,
    build_user: Option<String>,
    envs: Vec<(String, String)>,
    output_tx: Option<Sender<ChannelCommand>>,
    make_jobs: PkgMakeJobs,
    wrkdir: Option<PathBuf>,
}

impl<'a> PkgBuilder<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        session: &'a BuildSession,
        sandbox_id: Option<usize>,
        worker_id: usize,
        pkginfo: &'a ResolvedPackage,
        envs: Vec<(String, String)>,
        output_tx: Option<Sender<ChannelCommand>>,
        make_jobs: PkgMakeJobs,
        wrkdir: Option<PathBuf>,
    ) -> Self {
        let logdir = session
            .config
            .logdir()
            .join(pkginfo.index.pkgname.pkgname());
        let build_user = session.config.build_user().map(|s| s.to_string());
        Self {
            session,
            sandbox_id,
            worker_id,
            pkginfo,
            logdir,
            build_user,
            envs,
            output_tx,
            make_jobs,
            wrkdir,
        }
    }

    /// Run the full build process.
    fn build<C: BuildCallback>(&self, callback: &mut C) -> anyhow::Result<PkgBuildResult> {
        let pkgname_str = self.pkginfo.pkgname().pkgname();
        let pkgpath = &self.pkginfo.pkgpath;

        let mut stats = PkgBuildStats {
            make_jobs: self.make_jobs,
            ..PkgBuildStats::default()
        };

        // Clean up and create log directory
        if self.logdir.exists() {
            fs::remove_dir_all(&self.logdir)?;
        }
        fs::create_dir_all(&self.logdir)?;

        // Create work.log and chown to build_user if set
        let work_log = self.logdir.join("work.log");
        File::create(&work_log)?;
        if let Some(ref user) = self.build_user {
            let bob_log = File::options()
                .create(true)
                .append(true)
                .open(self.logdir.join("bob.log"))?;
            let bob_log_err = bob_log.try_clone()?;
            let _ = Command::new("chown")
                .arg(user)
                .arg(&work_log)
                .stdout(bob_log)
                .stderr(bob_log_err)
                .status();
        }

        let pkgdir = self.session.config.pkgsrc().join(pkgpath.as_path());

        // Pre-clean
        let stage_start = Instant::now();
        stats.stage = Some(Stage::PreClean);
        callback.stage(Stage::PreClean.into_str());
        let (_, cpu_time) =
            self.run_make_stage(Stage::PreClean, &pkgdir, &["clean"], RunAs::Root, false)?;
        stats
            .stage_durations
            .push((Stage::PreClean, stage_start.elapsed()));
        stats.stage_cpu_times.push((Stage::PreClean, cpu_time));

        // Install dependencies
        if !self.pkginfo.depends().is_empty() {
            let stage_start = Instant::now();
            stats.stage = Some(Stage::Depends);
            callback.stage(Stage::Depends.into_str());
            let _ = self.write_stage(Stage::Depends);
            if !self.install_dependencies()? {
                stats
                    .stage_durations
                    .push((Stage::Depends, stage_start.elapsed()));
                return Ok(PkgBuildResult::Failed(stats));
            }
            stats
                .stage_durations
                .push((Stage::Depends, stage_start.elapsed()));
        }

        // Checksum
        let stage_start = Instant::now();
        stats.stage = Some(Stage::Checksum);
        callback.stage(Stage::Checksum.into_str());
        let (ok, cpu_time) =
            self.run_make_stage(Stage::Checksum, &pkgdir, &["checksum"], RunAs::Root, true)?;
        stats
            .stage_durations
            .push((Stage::Checksum, stage_start.elapsed()));
        stats.stage_cpu_times.push((Stage::Checksum, cpu_time));
        if !ok {
            return Ok(PkgBuildResult::Failed(stats));
        }

        let jobs_suffix = match (self.make_jobs.safe(), self.make_jobs.jobs()) {
            (false, Some(j)) => format!(" -j{}*", j),
            (true, Some(j)) => format!(" -j{}", j),
            (_, None) => String::new(),
        };
        stats.make_jobs = self.make_jobs;

        let stage_start = Instant::now();
        stats.stage = Some(Stage::Configure);
        callback.stage(Stage::Configure.into_str());
        let configure_log = self.logdir.join("configure.log");
        if !self.run_usergroup_if_needed(Stage::Configure, &pkgdir, &configure_log)? {
            stats
                .stage_durations
                .push((Stage::Configure, stage_start.elapsed()));
            return Ok(PkgBuildResult::Failed(stats));
        }
        let (ok, cpu_time) = self.run_make_stage(
            Stage::Configure,
            &pkgdir,
            &["configure"],
            self.build_run_as(),
            true,
        )?;
        stats
            .stage_durations
            .push((Stage::Configure, stage_start.elapsed()));
        stats.stage_cpu_times.push((Stage::Configure, cpu_time));
        if !ok {
            return Ok(PkgBuildResult::Failed(stats));
        }

        let build_phase_start = Instant::now();
        stats.stage = Some(Stage::Build);
        callback.stage(&format!("{}{}", Stage::Build.into_str(), jobs_suffix));
        let build_log = self.logdir.join("build.log");
        if !self.run_usergroup_if_needed(Stage::Build, &pkgdir, &build_log)? {
            stats
                .stage_durations
                .push((Stage::Build, build_phase_start.elapsed()));
            return Ok(PkgBuildResult::Failed(stats));
        }
        let (build_ok, cpu_time) =
            self.run_make_stage(Stage::Build, &pkgdir, &["all"], self.build_run_as(), true)?;
        stats
            .stage_durations
            .push((Stage::Build, build_phase_start.elapsed()));
        stats.stage_cpu_times.push((Stage::Build, cpu_time));
        if !build_ok {
            return Ok(PkgBuildResult::Failed(stats));
        }

        // Install
        let stage_start = Instant::now();
        stats.stage = Some(Stage::Install);
        callback.stage(Stage::Install.into_str());
        let install_log = self.logdir.join("install.log");
        if !self.run_usergroup_if_needed(Stage::Install, &pkgdir, &install_log)? {
            stats
                .stage_durations
                .push((Stage::Install, stage_start.elapsed()));
            return Ok(PkgBuildResult::Failed(stats));
        }
        let (ok, cpu_time) = self.run_make_stage(
            Stage::Install,
            &pkgdir,
            &["stage-install"],
            self.build_run_as(),
            true,
        )?;
        stats
            .stage_durations
            .push((Stage::Install, stage_start.elapsed()));
        stats.stage_cpu_times.push((Stage::Install, cpu_time));
        if !ok {
            return Ok(PkgBuildResult::Failed(stats));
        }

        // Package
        let stage_start = Instant::now();
        stats.stage = Some(Stage::Package);
        callback.stage(Stage::Package.into_str());
        let (ok, cpu_time) = self.run_make_stage(
            Stage::Package,
            &pkgdir,
            &["stage-package-create"],
            RunAs::Root,
            true,
        )?;
        stats
            .stage_durations
            .push((Stage::Package, stage_start.elapsed()));
        stats.stage_cpu_times.push((Stage::Package, cpu_time));
        if !ok {
            return Ok(PkgBuildResult::Failed(stats));
        }

        // Get the package file path
        let pkgfile = self.get_make_var(&pkgdir, "STAGE_PKGFILE")?;

        // Test package install (unless bootstrap package)
        let is_bootstrap = self.pkginfo.bootstrap_pkg() == Some("yes");
        if !is_bootstrap {
            if !self.pkg_add(&pkgfile)? {
                return Ok(PkgBuildResult::Failed(stats));
            }

            // Test package deinstall
            let stage_start = Instant::now();
            stats.stage = Some(Stage::Deinstall);
            callback.stage(Stage::Deinstall.into_str());
            let _ = self.write_stage(Stage::Deinstall);
            if !self.pkg_delete(pkgname_str)? {
                stats
                    .stage_durations
                    .push((Stage::Deinstall, stage_start.elapsed()));
                return Ok(PkgBuildResult::Failed(stats));
            }
            stats
                .stage_durations
                .push((Stage::Deinstall, stage_start.elapsed()));
        }

        // Save package to packages directory
        let packages_dir = self.session.pkgsrc_env.packages.join("All");
        fs::create_dir_all(&packages_dir)?;
        let dest = packages_dir.join(
            Path::new(&pkgfile)
                .file_name()
                .context("Invalid package file path")?,
        );
        // pkgfile is a path inside the sandbox; prepend sandbox path for host access
        let host_pkgfile = match self.sandbox_id {
            Some(id) => self
                .session
                .sandbox
                .path(id)
                .join(pkgfile.trim_start_matches('/')),
            None => PathBuf::from(&pkgfile),
        };
        fs::copy(&host_pkgfile, &dest)?;

        // Measure disk usage before clean destroys WRKDIR
        match self.wrkdir {
            Some(ref wrkdir) => match fs_extra::dir::get_size(wrkdir) {
                Ok(size) => {
                    debug!(wrkdir = %wrkdir.display(), size, "Measured WRKDIR disk usage");
                    stats.disk_usage = Some(size);
                }
                Err(e) => {
                    debug!(wrkdir = %wrkdir.display(), error = %e, "Failed to measure disk usage")
                }
            },
            None => debug!("No WRKDIR available for disk usage measurement"),
        }

        // Clean
        let stage_start = Instant::now();
        stats.stage = Some(Stage::Clean);
        callback.stage(Stage::Clean.into_str());
        let (_, cpu_time) =
            self.run_make_stage(Stage::Clean, &pkgdir, &["clean"], RunAs::Root, false)?;
        stats
            .stage_durations
            .push((Stage::Clean, stage_start.elapsed()));
        stats.stage_cpu_times.push((Stage::Clean, cpu_time));

        // Remove log directory on success
        let _ = fs::remove_dir_all(&self.logdir);

        Ok(PkgBuildResult::Success(stats))
    }

    /// Determine how to run build commands.
    fn build_run_as(&self) -> RunAs {
        if self.build_user.is_some() {
            RunAs::User
        } else {
            RunAs::Root
        }
    }

    /// Write the current stage to a .stage file.
    fn write_stage(&self, stage: Stage) -> anyhow::Result<()> {
        let stage_file = self.logdir.join(".stage");
        fs::write(&stage_file, stage.into_str())?;
        Ok(())
    }

    /// Run a make stage with output logging.
    fn run_make_stage(
        &self,
        stage: Stage,
        pkgdir: &Path,
        targets: &[&str],
        run_as: RunAs,
        include_make_flags: bool,
    ) -> anyhow::Result<(bool, Duration)> {
        self.run_make_stage_with_flags(stage, pkgdir, targets, run_as, include_make_flags, &[])
    }

    fn run_make_stage_with_flags(
        &self,
        stage: Stage,
        pkgdir: &Path,
        targets: &[&str],
        run_as: RunAs,
        include_make_flags: bool,
        extra_flags: &[&str],
    ) -> anyhow::Result<(bool, Duration)> {
        let _ = self.write_stage(stage);

        let logfile = self.logdir.join(format!("{}.log", stage.into_str()));
        let work_log = self.logdir.join("work.log");

        let owned_args =
            self.make_args(pkgdir, targets, include_make_flags, &work_log, extra_flags);

        let args: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();

        info!(stage = stage.into_str(), "Running make stage");

        let (status, cpu_time) =
            self.run_command_logged(self.session.config.make(), &args, run_as, &logfile)?;

        Ok((status.success(), cpu_time))
    }

    /// Run a command with output logged to a file.
    fn run_command_logged(
        &self,
        cmd: &Path,
        args: &[&str],
        run_as: RunAs,
        logfile: &Path,
    ) -> anyhow::Result<(ExitStatus, Duration)> {
        self.run_command_logged_with_env(cmd, args, run_as, logfile, &[])
    }

    fn run_command_logged_with_env(
        &self,
        cmd: &Path,
        args: &[&str],
        run_as: RunAs,
        logfile: &Path,
        extra_envs: &[(&str, &str)],
    ) -> anyhow::Result<(ExitStatus, Duration)> {
        let mut log = OpenOptions::new().create(true).append(true).open(logfile)?;

        // Write command being executed to the log file
        let _ = writeln!(log, "=> {:?} {:?}", cmd, args);
        let _ = log.flush();

        // Use tee-style pipe handling when output_tx is available for live view.
        // Otherwise use direct file redirection.
        if let Some(ref output_tx) = self.output_tx {
            // Wrap command in shell to merge stdout/stderr with 2>&1, like the
            // shell script's run_log function does.
            let shell_cmd = self.build_shell_command(cmd, args, run_as, extra_envs);
            let mut child = self
                .session
                .sandbox
                .command(self.sandbox_id, Path::new("/bin/sh"))
                .new_session()
                .arg("-c")
                .arg(&shell_cmd)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("Failed to spawn shell command")?;

            let stdout = child.stdout.take().unwrap();
            let output_tx = output_tx.clone();
            let worker_id = self.worker_id;
            let (tee_done_tx, tee_done_rx) = mpsc::sync_channel::<()>(1);

            // Spawn thread to read from pipe and tee to file + output channel.
            // Batch lines and throttle sends to reduce channel overhead.
            let tee_handle = std::thread::spawn(move || {
                let mut reader = BufReader::new(stdout);
                let mut buf = Vec::new();
                let mut batch = Vec::with_capacity(50);
                let mut last_send = Instant::now();
                let send_interval = OUTPUT_BATCH_INTERVAL;

                loop {
                    buf.clear();
                    match reader.read_until(b'\n', &mut buf) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(_) => break,
                    };
                    // Write raw bytes to log file to preserve original output
                    let _ = log.write_all(&buf);
                    // Convert to lossy UTF-8 for live view
                    let line = String::from_utf8_lossy(&buf);
                    let line = line.trim_end_matches('\n').to_string();
                    batch.push(line);

                    // Send batch if interval elapsed or batch is large
                    if last_send.elapsed() >= send_interval || batch.len() >= 50 {
                        let _ = output_tx.send(ChannelCommand::OutputLines(
                            worker_id,
                            std::mem::take(&mut batch),
                        ));
                        last_send = Instant::now();
                    }
                }

                // Send remaining lines
                if !batch.is_empty() {
                    let _ = output_tx.send(ChannelCommand::OutputLines(worker_id, batch));
                }
                let _ = tee_done_tx.send(());
            });

            let (status, cpu_time) = wait_with_shutdown(&mut child, &self.session.state)?;

            /*
             * Wait for the tee thread to see pipe EOF.  Normally this is
             * immediate, but if an orphaned process (or zombie) holds the
             * pipe open, time out rather than blocking forever.  The
             * detached thread is cleaned up at exit.
             */
            if tee_done_rx.recv_timeout(Duration::from_secs(5)).is_ok() {
                let _ = tee_handle.join();
            } else {
                warn!(
                    pkg = %self.pkginfo.index.pkgname,
                    "Tee thread stuck on pipe held by orphaned process, detaching"
                );
            }

            trace!(?cmd, ?status, "Command completed");
            Ok((status, cpu_time))
        } else {
            let (status, cpu_time) =
                self.spawn_command_to_file(cmd, args, run_as, extra_envs, log)?;
            trace!(?cmd, ?status, "Command completed");
            Ok((status, cpu_time))
        }
    }

    /// Spawn a command with stdout/stderr redirected to a file.
    fn spawn_command_to_file(
        &self,
        cmd: &Path,
        args: &[&str],
        run_as: RunAs,
        extra_envs: &[(&str, &str)],
        log: File,
    ) -> anyhow::Result<(ExitStatus, Duration)> {
        // Clone file handle for stderr (stdout and stderr both go to same file)
        let log_err = log.try_clone()?;

        match run_as {
            RunAs::Root => {
                let mut command = self.session.sandbox.command(self.sandbox_id, cmd);
                command.new_session();
                command.args(args);
                self.apply_envs(&mut command, extra_envs);
                let mut child = command
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(log))
                    .stderr(Stdio::from(log_err))
                    .spawn()
                    .with_context(|| format!("Failed to spawn {}", cmd.display()))?;
                wait_with_shutdown(&mut child, &self.session.state)
            }
            RunAs::User => {
                let user = self.build_user.as_ref().unwrap();
                let mut parts = Vec::with_capacity(args.len() + 1);
                parts.push(cmd.display().to_string());
                parts.extend(args.iter().map(|arg| arg.to_string()));
                let inner_cmd = parts
                    .iter()
                    .map(|part| Self::shell_escape(part))
                    .collect::<Vec<_>>()
                    .join(" ");
                let mut command = self
                    .session
                    .sandbox
                    .command(self.sandbox_id, Path::new("su"));
                command.new_session();
                command.arg(user).arg("-c").arg(&inner_cmd);
                self.apply_envs(&mut command, extra_envs);
                let mut child = command
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(log))
                    .stderr(Stdio::from(log_err))
                    .spawn()
                    .context("Failed to spawn su command")?;
                wait_with_shutdown(&mut child, &self.session.state)
            }
        }
    }

    /// Get a make variable value.
    fn get_make_var(&self, pkgdir: &Path, varname: &str) -> anyhow::Result<String> {
        let mut cmd = self
            .session
            .sandbox
            .command(self.sandbox_id, self.session.config.make());
        cmd.new_session();
        self.apply_envs(&mut cmd, &[]);

        let work_log = self.logdir.join("work.log");
        let make_args = self.make_args(
            pkgdir,
            &["show-var", &format!("VARNAME={}", varname)],
            true,
            &work_log,
            &[],
        );

        let bob_log = File::options()
            .create(true)
            .append(true)
            .open(self.logdir.join("bob.log"))?;
        let output = cmd.args(&make_args).stderr(Stdio::from(bob_log)).output()?;

        if !output.status.success() {
            bail!("Failed to get make variable {}", varname);
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Install package dependencies.
    fn install_dependencies(&self) -> anyhow::Result<bool> {
        let deps: Vec<String> = self
            .pkginfo
            .depends()
            .iter()
            .map(|d| d.to_string())
            .collect();

        let pkg_path = self.session.pkgsrc_env.packages.join("All");
        let logfile = self.logdir.join("depends.log");

        let mut args = vec![];
        for dep in &deps {
            args.push(dep.as_str());
        }

        let (status, _) = self.run_pkg_add_with_path(&args, &pkg_path, &logfile)?;
        Ok(status.success())
    }

    /// Run pkg_add with PKG_PATH set.
    fn run_pkg_add_with_path(
        &self,
        packages: &[&str],
        pkg_path: &Path,
        logfile: &Path,
    ) -> anyhow::Result<(ExitStatus, Duration)> {
        let pkg_add = self.session.pkgsrc_env.pkgtools.join("pkg_add");
        let pkg_dbdir = self.session.pkgsrc_env.pkg_dbdir.to_string_lossy();
        let pkg_path_value = pkg_path.to_string_lossy().to_string();
        let extra_envs = [("PKG_PATH", pkg_path_value.as_str())];

        let mut args = vec!["-K", &*pkg_dbdir];
        args.extend(packages.iter().copied());

        self.run_command_logged_with_env(&pkg_add, &args, RunAs::Root, logfile, &extra_envs)
    }

    /// Install a package file.
    fn pkg_add(&self, pkgfile: &str) -> anyhow::Result<bool> {
        let pkg_add = self.session.pkgsrc_env.pkgtools.join("pkg_add");
        let pkg_dbdir = self.session.pkgsrc_env.pkg_dbdir.to_string_lossy();
        let logfile = self.logdir.join("package.log");

        let (status, _) = self.run_command_logged(
            &pkg_add,
            &["-K", &*pkg_dbdir, pkgfile],
            RunAs::Root,
            &logfile,
        )?;

        Ok(status.success())
    }

    /// Delete an installed package.
    fn pkg_delete(&self, pkgname: &str) -> anyhow::Result<bool> {
        let pkg_delete = self.session.pkgsrc_env.pkgtools.join("pkg_delete");
        let pkg_dbdir = self.session.pkgsrc_env.pkg_dbdir.to_string_lossy();
        let logfile = self.logdir.join("deinstall.log");

        let (status, _) = self.run_command_logged(
            &pkg_delete,
            &["-K", &*pkg_dbdir, pkgname],
            RunAs::Root,
            &logfile,
        )?;

        Ok(status.success())
    }

    /// Run create-usergroup if needed based on usergroup_phase.
    fn run_usergroup_if_needed(
        &self,
        stage: Stage,
        pkgdir: &Path,
        logfile: &Path,
    ) -> anyhow::Result<bool> {
        let usergroup_phase = self.pkginfo.usergroup_phase().unwrap_or("");

        let should_run = match stage {
            Stage::Configure => usergroup_phase.ends_with("configure"),
            Stage::Build => usergroup_phase.ends_with("build"),
            Stage::Install => usergroup_phase == "pre-install",
            _ => false,
        };

        if !should_run {
            return Ok(true);
        }

        let mut args = vec!["-C", pkgdir.to_str().unwrap(), "create-usergroup"];
        if stage == Stage::Configure {
            args.push("clean");
        }

        let (status, _) =
            self.run_command_logged(self.session.config.make(), &args, RunAs::Root, logfile)?;
        Ok(status.success())
    }

    fn make_args(
        &self,
        pkgdir: &Path,
        targets: &[&str],
        include_make_flags: bool,
        work_log: &Path,
        extra_flags: &[&str],
    ) -> Vec<String> {
        let mut owned_args: Vec<String> =
            vec!["-C".to_string(), pkgdir.to_str().unwrap().to_string()];
        owned_args.extend(targets.iter().map(|s| s.to_string()));

        if include_make_flags {
            owned_args.push("BATCH=1".to_string());
            owned_args.push("DEPENDS_TARGET=/nonexistent".to_string());

            if let Some(multi_version) = self.pkginfo.multi_version() {
                for flag in multi_version {
                    owned_args.push(flag.clone());
                }
            }

            owned_args.push(format!("WRKLOG={}", work_log.display()));
        }

        owned_args.extend(extra_flags.iter().map(|s| s.to_string()));

        owned_args
    }

    fn apply_envs(&self, cmd: &mut Command, extra_envs: &[(&str, &str)]) {
        for (key, value) in &self.envs {
            cmd.env(key, value);
        }
        for (key, value) in extra_envs {
            cmd.env(key, value);
        }
    }

    fn shell_escape(value: &str) -> String {
        if value.is_empty() {
            return "''".to_string();
        }
        if value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.,/:=+@".contains(c))
        {
            return value.to_string();
        }
        let escaped = value.replace('\'', "'\\''");
        format!("'{}'", escaped)
    }

    /// Build a shell command string with environment, run_as handling, and 2>&1.
    fn build_shell_command(
        &self,
        cmd: &Path,
        args: &[&str],
        run_as: RunAs,
        extra_envs: &[(&str, &str)],
    ) -> String {
        let mut parts = Vec::new();

        // Add environment variables
        for (key, value) in &self.envs {
            parts.push(format!("{}={}", key, Self::shell_escape(value)));
        }
        for (key, value) in extra_envs {
            parts.push(format!("{}={}", key, Self::shell_escape(value)));
        }

        // Build the actual command
        let cmd_str = Self::shell_escape(&cmd.to_string_lossy());
        let args_str: Vec<String> = args.iter().map(|a| Self::shell_escape(a)).collect();

        match run_as {
            RunAs::Root => {
                parts.push(cmd_str);
                parts.extend(args_str);
            }
            RunAs::User => {
                let user = self.build_user.as_ref().unwrap();
                let inner_cmd = std::iter::once(cmd_str)
                    .chain(args_str)
                    .collect::<Vec<_>>()
                    .join(" ");
                parts.push("su".to_string());
                parts.push(Self::shell_escape(user));
                parts.push("-c".to_string());
                parts.push(Self::shell_escape(&inner_cmd));
            }
        }

        // Merge stdout/stderr
        parts.push("2>&1".to_string());
        parts.join(" ")
    }
}

/// Callback adapter that sends build updates through a channel.
struct ChannelCallback<'a> {
    sandbox_id: usize,
    status_tx: &'a Sender<ChannelCommand>,
}

impl<'a> ChannelCallback<'a> {
    fn new(sandbox_id: usize, status_tx: &'a Sender<ChannelCommand>) -> Self {
        Self {
            sandbox_id,
            status_tx,
        }
    }
}

impl<'a> BuildCallback for ChannelCallback<'a> {
    fn stage(&mut self, stage: &str) {
        let _ = self.status_tx.send(ChannelCommand::StageUpdate(
            self.sandbox_id,
            Some(stage.to_string()),
        ));
    }
}

/// Result of building a single package.
///
/// Contains the outcome, timing, and log location for a package build.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BuildResult {
    /// Package name with version (e.g., `mutt-2.2.12`).
    pub pkgname: PkgName,
    /// Package path in pkgsrc (e.g., `mail/mutt`).
    pub pkgpath: Option<PkgPath>,
    /// Package state.
    pub state: PackageState,
    /// Path to build logs directory, if available.
    ///
    /// For failed builds, this contains `pre-clean.log`, `build.log`, etc.
    /// Successful builds clean up their log directories.
    pub log_dir: Option<PathBuf>,
    /// Build-phase metrics (timing, parallelism).
    #[serde(flatten, default)]
    pub build_stats: PkgBuildStats,
}

impl BuildResult {
    /**
     * Build a history input record for actual builds (success/failed).
     * Returns None for skipped, up-to-date, or indirect outcomes.
     */
    pub fn history_input(&self) -> Option<crate::History> {
        match &self.state {
            PackageState::Success | PackageState::Failed(_) => {}
            _ => return None,
        }
        Some(crate::History {
            timestamp: self.build_stats.timestamp,
            pkgpath: self.pkgpath.as_ref()?.to_string(),
            pkgname: self.pkgname.pkgname().to_string(),
            pkgbase: self.pkgname.pkgbase().to_string(),
            outcome: self.state.clone(),
            stage: self.build_stats.stage,
            make_jobs: self.build_stats.make_jobs.jobs(),
            duration: self.build_stats.duration,
            disk_usage: self.build_stats.disk_usage,
            wrkobjdir: self.build_stats.wrkobjdir.clone(),
            stage_durations: self.build_stats.stage_durations.clone(),
            stage_cpu_times: self.build_stats.stage_cpu_times.clone(),
        })
    }
}

/// Counts of build results by state, plus scanfail total.
#[derive(Clone, Debug, Default)]
pub struct BuildCounts {
    /// Counts by [`PackageState`] variant.
    pub states: PackageCounts,
    /// Packages that failed to scan.
    pub scanfail: usize,
}

/// Summary of an entire build run.
#[derive(Clone, Debug)]
pub struct BuildSummary {
    /// Total duration of the build run.
    pub duration: Duration,
    /// Results for each package.
    pub results: Vec<BuildResult>,
    /// Packages that failed to scan (pkgpath, error message).
    pub scanfail: Vec<(PkgPath, String)>,
}

impl BuildSummary {
    /// Compute all counts in a single pass.
    pub fn counts(&self) -> BuildCounts {
        let mut c = BuildCounts {
            scanfail: self.scanfail.len(),
            ..Default::default()
        };
        for r in &self.results {
            c.states.add(&r.state);
        }
        c
    }

    /// Get all failed results (direct build failures only).
    pub fn failed(&self) -> Vec<&BuildResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.state, PackageState::Failed(_)))
            .collect()
    }

    /// Get all successful results.
    pub fn succeeded(&self) -> Vec<&BuildResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.state, PackageState::Success))
            .collect()
    }

    /// Get all skipped results.
    pub fn skipped(&self) -> Vec<&BuildResult> {
        self.results.iter().filter(|r| r.state.is_skip()).collect()
    }
}

/**
 * Parallel package build orchestrator.
 *
 * Schedules packages for building using a dependency DAG, distributes
 * work across sandbox worker threads, and collects results into a
 * [`BuildSummary`].
 *
 * Sandboxes are owned via [`SandboxScope`] and automatically cleaned
 * up on drop.
 */
#[derive(Debug)]
pub struct Build {
    /// Parsed [`Config`].
    config: Config,
    /// Pkgsrc environment variables.
    pkgsrc_env: PkgsrcEnv,
    /// Sandbox scope - owns created sandboxes, destroys on drop.
    scope: SandboxScope,
    /// List of packages to build, as input from Scan::resolve.
    scanpkgs: IndexMap<PkgName, ResolvedPackage>,
    /// Cached build results from previous run.
    cached: IndexMap<PkgName, BuildResult>,
}

/// Per-package build task sent to worker threads.
#[derive(Debug)]
struct PackageBuild {
    session: Arc<BuildSession>,
    sandbox_id: Option<usize>,
    worker_id: usize,
    pkginfo: ResolvedPackage,
    make_jobs: PkgMakeJobs,
}

/// Helper for querying bmake variables with the correct environment.
struct MakeQuery<'a> {
    session: &'a BuildSession,
    sandbox_id: Option<usize>,
    pkgpath: &'a PkgPath,
    env: &'a HashMap<String, String>,
}

impl<'a> MakeQuery<'a> {
    fn new(
        session: &'a BuildSession,
        sandbox_id: Option<usize>,
        pkgpath: &'a PkgPath,
        env: &'a HashMap<String, String>,
    ) -> Self {
        Self {
            session,
            sandbox_id,
            pkgpath,
            env,
        }
    }

    /// Query a bmake variable value.
    fn var(&self, name: &str) -> Option<String> {
        let pkgdir = self.session.config.pkgsrc().join(self.pkgpath.as_path());

        let mut cmd = self
            .session
            .sandbox
            .command(self.sandbox_id, self.session.config.make());
        cmd.new_session();
        cmd.arg("-C")
            .arg(&pkgdir)
            .arg("show-var")
            .arg(format!("VARNAME={}", name));

        // Pass env vars that may affect the variable value
        for (key, value) in self.env {
            cmd.env(key, value);
        }

        cmd.stderr(Stdio::piped());

        let output = cmd.output().ok()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                status = ?output.status.code(),
                stderr = %stderr.trim(),
                name,
                "show-var failed"
            );
            return None;
        }

        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if value.is_empty() { None } else { Some(value) }
    }

    /// Query multiple bmake variables in a single invocation.
    fn vars(&self, names: &[&str]) -> HashMap<String, String> {
        let pkgdir = self.session.config.pkgsrc().join(self.pkgpath.as_path());
        let varnames_arg = names.join(" ");

        let mut cmd = self
            .session
            .sandbox
            .command(self.sandbox_id, self.session.config.make());
        cmd.new_session();
        cmd.arg("-C")
            .arg(&pkgdir)
            .arg("show-vars")
            .arg(format!("VARNAMES={}", varnames_arg));

        for (key, value) in self.env {
            cmd.env(key, value);
        }

        cmd.stderr(Stdio::piped());

        let output = match cmd.output() {
            Ok(o) if o.status.success() => o,
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                warn!(
                    status = ?o.status.code(),
                    stderr = %stderr.trim(),
                    ?names,
                    "show-vars failed"
                );
                return HashMap::new();
            }
            Err(e) => {
                warn!(error = %e, ?names, "show-vars exec error");
                return HashMap::new();
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();

        let mut result = HashMap::new();
        for (name, value) in names.iter().zip(&lines) {
            let value = value.trim();
            if !value.is_empty() {
                result.insert(name.to_string(), value.to_string());
            }
        }
        result
    }

    /// Query a bmake variable and return as PathBuf.
    fn var_path(&self, name: &str) -> Option<PathBuf> {
        self.var(name).map(PathBuf::from)
    }

    /// Get the WRKDIR for this package.
    fn wrkdir(&self) -> Option<PathBuf> {
        self.var_path("WRKDIR")
    }

    /// Resolve a path to its actual location on the host filesystem.
    /// If sandboxed, prepends the sandbox root path.
    fn resolve_path(&self, path: &Path) -> PathBuf {
        match self.sandbox_id {
            Some(id) => self
                .session
                .sandbox
                .path(id)
                .join(path.strip_prefix("/").unwrap_or(path)),
            None => path.to_path_buf(),
        }
    }
}

impl PackageBuild {
    fn build(&mut self, status_tx: &Sender<ChannelCommand>) -> anyhow::Result<PkgBuildResult> {
        let pkgname = self.pkginfo.index.pkgname.pkgname();
        info!("Starting package build");

        let pkgpath = &self.pkginfo.pkgpath;

        let logdir = self.session.config.logdir();

        let pkg_env = self
            .session
            .config
            .get_pkg_env(&self.pkginfo)
            .map_err(|e| anyhow::anyhow!("Lua env config error: {e}"))?;

        let mut envs = self
            .session
            .config
            .script_env(Some(&self.session.pkgsrc_env));

        // Inject scheduler-computed WRKOBJDIR unless the user's env
        // function already set it (user overrides win).
        let wrkobjdir_kind = if !pkg_env.contains_key("WRKOBJDIR") {
            if let Some(kind) = self.session.wrkobjdir_map.get(&self.pkginfo.index.pkgname) {
                envs.push(("WRKOBJDIR".to_string(), kind.path().display().to_string()));
                Some(kind)
            } else {
                None
            }
        } else {
            None
        };

        for (key, value) in &pkg_env {
            envs.push((key.clone(), value.clone()));
        }

        let patterns = self.session.config.save_wrkdir_patterns();

        // Run pre-build script if defined (always runs).  The sandbox
        // is not usable until this completes.
        if !self.session.sandbox.run_pre_build(
            self.sandbox_id,
            &self.session.config,
            envs.clone(),
        )? {
            warn!("pre-build script failed");
        }

        if let Some(jobs) = self.make_jobs.allocated() {
            envs.push(("MAKE_JOBS".to_string(), jobs.to_string()));
        }

        let env_map: HashMap<String, String> = envs.iter().cloned().collect();
        let make = MakeQuery::new(&self.session, self.sandbox_id, pkgpath, &env_map);
        let vars = make.vars(&["_MAKE_JOBS_N", "WRKDIR"]);

        let wrkdir = Some(
            make.resolve_path(Path::new(
                vars.get("WRKDIR")
                    .ok_or_else(|| anyhow::anyhow!("failed to query WRKDIR"))?,
            )),
        );

        /* _MAKE_JOBS_N can be empty, e.g. if NO_BUILD=yes */
        if let Some(n) = vars.get("_MAKE_JOBS_N").and_then(|v| v.parse().ok()) {
            self.make_jobs.set_jobs(n);
        }

        // Run the build using PkgBuilder
        let builder = PkgBuilder::new(
            &self.session,
            self.sandbox_id,
            self.worker_id,
            &self.pkginfo,
            envs.clone(),
            Some(status_tx.clone()),
            self.make_jobs,
            wrkdir.clone(),
        );

        let mut callback = ChannelCallback::new(self.worker_id, status_tx);
        let result = builder.build(&mut callback);

        // Clear stage display
        let _ = status_tx.send(ChannelCommand::StageUpdate(self.worker_id, None));

        let measure_wrkdir = || -> Option<u64> {
            let w = wrkdir.as_ref()?;
            fs_extra::dir::get_size(w).ok()
        };
        let wrkobjdir = wrkobjdir_kind.cloned();

        let result = match result {
            Ok(PkgBuildResult::Success(mut stats)) => {
                info!("Package build completed successfully");
                stats.wrkobjdir = wrkobjdir;
                PkgBuildResult::Success(stats)
            }
            Ok(PkgBuildResult::Failed(mut stats)) => {
                error!("Package build failed");
                stats.disk_usage = measure_wrkdir();
                stats.wrkobjdir = wrkobjdir;
                self.cleanup_after_failure(status_tx, pkgname, pkgpath, logdir, patterns, &envs);
                PkgBuildResult::Failed(stats)
            }
            Err(e) => {
                error!(error = %e, "Package build error");
                let disk_usage = measure_wrkdir();
                self.cleanup_after_failure(status_tx, pkgname, pkgpath, logdir, patterns, &envs);
                PkgBuildResult::Failed(PkgBuildStats {
                    make_jobs: self.make_jobs,
                    disk_usage,
                    wrkobjdir,
                    ..PkgBuildStats::default()
                })
            }
        };

        // Run post-build script if defined (always runs regardless of result)
        match self
            .session
            .sandbox
            .run_post_build(self.sandbox_id, &self.session.config, envs)
        {
            Ok(true) => {}
            Ok(false) => warn!("post-build script failed"),
            Err(e) => {
                warn!(error = %e, "post-build script error")
            }
        }

        Ok(result)
    }

    /**
     * Perform cleanup after a build failure or error.  A successful build
     * will perform its own cleanup, while this one handles saving useful
     * logs from the build, etc.
     */
    fn cleanup_after_failure(
        &self,
        status_tx: &Sender<ChannelCommand>,
        pkgname: &str,
        pkgpath: &PkgPath,
        logdir: &Path,
        patterns: &[String],
        envs: &[(String, String)],
    ) {
        let _ = status_tx.send(ChannelCommand::StageUpdate(
            self.worker_id,
            Some("cleanup".to_string()),
        ));

        /*
         * Kill any orphaned processes in the sandbox before cleanup, as
         * occasionally builds leave some behind.
         */
        let kill_start = Instant::now();
        self.session.sandbox.kill_processes_by_id(self.sandbox_id);
        trace!(
            elapsed_ms = kill_start.elapsed().as_millis(),
            "kill_processes_by_id completed"
        );

        /*
         * Save any user-configured save_wrkdir_patterns.
         */
        if !patterns.is_empty() {
            let save_start = Instant::now();
            self.save_wrkdir_files(pkgname, pkgpath, logdir, patterns, envs);
            trace!(
                elapsed_ms = save_start.elapsed().as_millis(),
                "save_wrkdir_files completed"
            );
        }

        /*
         * Run the standard cleanup.
         */
        let clean_start = Instant::now();
        self.run_clean(pkgpath, envs);
        trace!(
            elapsed_ms = clean_start.elapsed().as_millis(),
            "run_clean completed"
        );
    }

    /// Save files matching patterns from WRKDIR to logdir on build failure.
    fn save_wrkdir_files(
        &self,
        pkgname: &str,
        pkgpath: &PkgPath,
        logdir: &Path,
        patterns: &[String],
        envs: &[(String, String)],
    ) {
        let env_map: HashMap<String, String> = envs.iter().cloned().collect();
        let make = MakeQuery::new(&self.session, self.sandbox_id, pkgpath, &env_map);

        // Get WRKDIR
        let wrkdir = match make.wrkdir() {
            Some(w) => w,
            None => {
                debug!(%pkgname, "Could not determine WRKDIR, skipping file save");
                return;
            }
        };

        // Resolve to actual filesystem path
        let wrkdir_path = make.resolve_path(&wrkdir);

        if !wrkdir_path.exists() {
            debug!(%pkgname, wrkdir = %wrkdir_path.display(), "WRKDIR does not exist, skipping file save");
            return;
        }

        let save_dir = logdir.join(pkgname).join("wrkdir-files");
        if let Err(e) = fs::create_dir_all(&save_dir) {
            warn!(%pkgname, error = %e, "Failed to create wrkdir-files directory");
            return;
        }

        // Compile glob patterns
        let compiled_patterns: Vec<Pattern> = patterns
            .iter()
            .filter_map(|p| {
                Pattern::new(p).ok().or_else(|| {
                    warn!(pattern = %p, "Invalid glob pattern");
                    None
                })
            })
            .collect();

        if compiled_patterns.is_empty() {
            return;
        }

        // Walk the wrkdir and find matching files
        let mut saved_count = 0;
        if let Err(e) = walk_and_save(
            &wrkdir_path,
            &wrkdir_path,
            &save_dir,
            &compiled_patterns,
            &mut saved_count,
        ) {
            warn!(%pkgname, error = %e, "Error while saving wrkdir files");
        }

        if saved_count > 0 {
            info!(%pkgname, count = saved_count, dest = %save_dir.display(), "Saved wrkdir files");
        }
    }

    /// Run bmake clean for a package.
    fn run_clean(&self, pkgpath: &PkgPath, envs: &[(String, String)]) {
        let pkgdir = self.session.config.pkgsrc().join(pkgpath.as_path());

        let mut cmd = self
            .session
            .sandbox
            .command(self.sandbox_id, self.session.config.make());
        cmd.new_session();
        cmd.arg("-C").arg(&pkgdir).arg("clean");
        for (key, value) in envs {
            cmd.env(key, value);
        }
        let result = cmd
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        if let Err(e) = result {
            debug!(error = %e, "Failed to run bmake clean");
        }
    }
}

/**
 * Recursively walk a directory and save files matching patterns.
 *
 * Uses `DirEntry::file_type()` which does not follow symlinks, avoiding
 * traversal outside the intended directory tree.
 */
fn walk_and_save(
    base: &Path,
    current: &Path,
    save_dir: &Path,
    patterns: &[Pattern],
    saved_count: &mut usize,
) -> std::io::Result<()> {
    if !current.symlink_metadata()?.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let path = entry.path();

        if ft.is_dir() {
            walk_and_save(base, &path, save_dir, patterns, saved_count)?;
        } else if ft.is_file() {
            let Some(rel_path) = path.strip_prefix(base).ok() else {
                continue;
            };
            let rel_str = rel_path.to_string_lossy();

            // Check if any pattern matches
            for pattern in patterns {
                if pattern.matches(&rel_str)
                    || pattern.matches(
                        path.file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .as_ref(),
                    )
                {
                    // Create destination directory
                    let dest_path = save_dir.join(rel_path);
                    if let Some(parent) = dest_path.parent() {
                        fs::create_dir_all(parent)?;
                    }

                    // Copy the file
                    if let Err(e) = fs::copy(&path, &dest_path) {
                        warn!(src = %path.display(),
                            dest = %dest_path.display(),
                            error = %e,
                            "Failed to copy file"
                        );
                    } else {
                        debug!(src = %path.display(),
                            dest = %dest_path.display(),
                            "Saved wrkdir file"
                        );
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
     * Client returning a successful package build.
     */
    JobSuccess(BuildResult),
    /**
     * Client returning a failed package build.
     */
    JobFailed(BuildResult),
    /**
     * Manager directing a client to quit.
     */
    Quit,
    /**
     * Shutdown signal - workers should stop immediately.
     */
    Shutdown,
    /**
     * Client reporting a stage update for a build.
     */
    StageUpdate(usize, Option<String>),
    /**
     * Client reporting output lines from a build.
     */
    OutputLines(usize, Vec<String>),
}

struct BuildJobs {
    scanpkgs: IndexMap<PkgName, ResolvedPackage>,
    scheduler: Scheduler<PkgName>,
    results: Vec<BuildResult>,
    logdir: PathBuf,
}

impl BuildJobs {
    /**
     * Mark a package as successful and remove it from pending dependencies.
     */
    fn mark_success(&mut self, result: BuildResult) {
        self.scheduler.mark_success(&result.pkgname);
        self.results.push(result);
    }

    /**
     * Recursively mark a package and its dependents as failed.
     */
    fn mark_failure(&mut self, result: BuildResult) {
        trace!(pkgname = %result.pkgname.pkgname(), "mark_failure called");
        let start = std::time::Instant::now();

        let indirect = self.scheduler.mark_failure(&result.pkgname);
        trace!(pkgname = %result.pkgname.pkgname(), broken_count = indirect.len() + 1, elapsed_ms = start.elapsed().as_millis(), "mark_failure found broken packages");

        let pkgname = result.pkgname.clone();
        self.results.push(result);

        for pkg in indirect {
            let scanpkg = self.scanpkgs.get(&pkg);
            let log_dir = Some(self.logdir.join(pkg.pkgname()));
            self.results.push(BuildResult {
                pkgname: pkg,
                pkgpath: scanpkg.map(|s| s.pkgpath.clone()),
                state: PackageState::IndirectFailed(format!(
                    "dependency {} failed",
                    pkgname.pkgname()
                )),
                log_dir,
                build_stats: PkgBuildStats::default(),
            });
        }
        trace!(pkgname = %pkgname.pkgname(), total_results = self.results.len(), elapsed_ms = start.elapsed().as_millis(), "mark_failure completed");
    }
}

impl Build {
    /**
     * Create a new build from scan results.
     *
     * The `scanpkgs` map should contain the buildable packages from
     * [`Scan::resolve`](crate::Scan). The `scope` owns the sandboxes
     * and will destroy them on drop.
     */
    pub fn new(
        config: &Config,
        pkgsrc_env: PkgsrcEnv,
        scope: SandboxScope,
        scanpkgs: IndexMap<PkgName, ResolvedPackage>,
    ) -> Build {
        info!(
            package_count = scanpkgs.len(),
            sandbox_enabled = scope.enabled(),
            build_threads = config.build_threads(),
            "Creating new Build instance"
        );
        for (pkgname, index) in &scanpkgs {
            debug!(pkgname = %pkgname.pkgname(),
                pkgpath = ?index.pkgpath,
                depends_count = index.depends().len(),
                depends = ?index.depends().iter().map(|d| d.pkgname()).collect::<Vec<_>>(),
                "Package in build queue"
            );
        }
        Build {
            config: config.clone(),
            pkgsrc_env,
            scope,
            scanpkgs,
            cached: IndexMap::new(),
        }
    }

    /// Load cached build results from database.
    ///
    /// Returns the number of packages loaded from cache. Only loads results
    /// for packages that are in our build queue.
    pub fn load_cached_from_db(&mut self, db: &crate::db::Database) -> anyhow::Result<usize> {
        let mut count = 0;
        for pkgname in self.scanpkgs.keys() {
            if let Some(pkg) = db.get_package_by_name(pkgname.pkgname())? {
                if let Some(result) = db.get_build_result(pkg.id)? {
                    self.cached.insert(pkgname.clone(), result);
                    count += 1;
                }
            }
        }
        if count > 0 {
            info!(
                cached_count = count,
                "Loaded cached build results from database"
            );
        }
        Ok(count)
    }

    /**
     * Run the build.
     *
     * Builds all packages in dependency order across parallel sandbox
     * workers. Respects the run state for graceful interruption.
     * Results are persisted to `db` as each package completes.
     */
    pub fn start(
        &mut self,
        state: &RunState,
        db: &crate::db::Database,
    ) -> anyhow::Result<BuildSummary> {
        let started = Instant::now();

        info!(package_count = self.scanpkgs.len(), "Build::start() called");

        let state_flag = state.clone();

        let results: Vec<BuildResult> = Vec::new();

        let mut scheduler = Scheduler::new(db)?;

        /*
         * Mark packages that aren't buildable (pre-skipped, pre-failed,
         * unresolved, etc.) as done in the scheduler so they are never
         * dispatched.  The scheduler includes all selected packages from
         * the DB; only the subset in scanpkgs needs building.
         */
        let all_pkgs: Vec<PkgName> = scheduler.iter().map(|sp| sp.pkg).collect();
        for pkg in &all_pkgs {
            if !self.scanpkgs.contains_key(pkg) {
                scheduler.mark_success(pkg);
            }
        }

        /*
         * Apply cached build results to the scheduler.
         */
        let mut cached_count = 0usize;
        let mut indirect_failed_count = 0usize;
        for (pkgname, result) in &self.cached {
            match result.state {
                PackageState::Success | PackageState::UpToDate => {
                    scheduler.mark_success(pkgname);
                }
                _ => {
                    let indirect = scheduler.mark_failure(pkgname);
                    indirect_failed_count += indirect
                        .iter()
                        .filter(|p| !self.cached.contains_key(*p))
                        .count();
                }
            }
            cached_count += 1;
        }

        if cached_count > 0 {
            println!("Loaded {} cached build results", cached_count);
        }

        info!(
            queued_count = scheduler.queued_count(),
            scanpkgs_count = self.scanpkgs.len(),
            cached_count = cached_count,
            "BuildJobs populated"
        );

        if scheduler.queued_count() == 0 {
            return Ok(BuildSummary {
                duration: started.elapsed(),
                results,
                scanfail: Vec::new(),
            });
        }

        let n = self.config.build_threads().min(scheduler.queued_count());
        if self.scope.enabled() && n > self.scope.count() {
            let to_create = n - self.scope.count();
            if to_create == 1 {
                print!("Creating sandbox...");
            } else {
                print!("Creating {} sandboxes...", to_create);
            }
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let start = std::time::Instant::now();
            self.scope.ensure(n)?;
            println!(" done ({:.1}s)", start.elapsed().as_secs_f32());
        }

        /*
         * Build wrkobjdir map from historical disk usage.
         *
         * If dynamic.wrkobjdir is configured, look up each package's
         * most recent disk usage and route large builds to disk.
         * Packages with no history or a recent failure default to
         * disk (safe choice since tmpfs is bounded).
         */
        let wrkobjdir_map: HashMap<PkgName, WrkObjKind> = if let Some(w) = self.config.wrkobjdir() {
            let usage = db.disk_usage_by_pkg_all();
            debug!(
                total_packages = self.scanpkgs.len(),
                history_entries = usage.len(),
                "WRKOBJDIR disk usage query results"
            );
            let mut map = HashMap::new();
            for pkgname in self.scanpkgs.keys() {
                let du = usage.get(pkgname.pkgbase()).copied();
                if let Some(kind) = w.route(du) {
                    map.insert(pkgname.clone(), kind);
                }
            }
            map
        } else {
            HashMap::new()
        };

        if let Some(jobs) = self.config.jobs() {
            scheduler.set_allocator(crate::makejobs::Allocator::new(n, jobs));
        }

        let logdir = self.config.logdir().clone();
        let jobs = BuildJobs {
            scanpkgs: self.scanpkgs.clone(),
            scheduler,
            results,
            logdir,
        };

        let cpu_sampler = crate::cpu::start_cpu_sampler();
        if cpu_sampler.is_some() {
            debug!("CPU usage sampler started");
        }

        println!("Building packages...");

        // Set up multi-line progress display using ratatui inline viewport
        let progress = Arc::new(Mutex::new(
            MultiProgress::new(
                "Building",
                "Built",
                self.scanpkgs.len(),
                n,
                self.config.tui(),
            )
            .context("Failed to initialize progress display")?,
        ));

        // Mark cached and indirect-failed packages in progress display
        if cached_count > 0 || indirect_failed_count > 0 {
            if let Ok(mut p) = progress.lock() {
                p.state_mut().cached = cached_count;
                p.state_mut().skipped = indirect_failed_count;
            }
        }

        // Flag to stop the refresh thread
        let stop_refresh = Arc::new(AtomicBool::new(false));

        // Spawn a thread to periodically refresh the display (for timer updates)
        let progress_refresh = Arc::clone(&progress);
        let stop_flag = Arc::clone(&stop_refresh);
        let state_for_refresh = state_flag.clone();
        let is_plain = progress.lock().map(|p| p.is_plain()).unwrap_or(false);
        let refresh_thread = std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) && !state_for_refresh.is_shutdown() {
                if is_plain {
                    std::thread::sleep(REFRESH_INTERVAL);
                    if let Ok(mut p) = progress_refresh.lock() {
                        let _ = p.render();
                    }
                } else {
                    let has_event = event::poll(REFRESH_INTERVAL).unwrap_or(false);
                    if let Ok(mut p) = progress_refresh.lock() {
                        if has_event {
                            let _ = p.handle_event();
                        }
                        let _ = p.render();
                    }
                }
            }
        });

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
        let mut clients: HashMap<usize, Sender<ChannelCommand>> = HashMap::new();
        for i in 0..n {
            let (client_tx, client_rx) = mpsc::channel::<ChannelCommand>();
            clients.insert(i, client_tx);
            let manager_tx = manager_tx.clone();
            let state_for_worker = state_flag.clone();
            let thread = std::thread::spawn(move || {
                loop {
                    if state_for_worker.is_shutdown() {
                        break;
                    }

                    // Use send() which can fail if receiver is dropped (manager shutdown)
                    if manager_tx.send(ChannelCommand::ClientReady(i)).is_err() {
                        break;
                    }

                    let Ok(msg) = client_rx.recv() else {
                        break;
                    };

                    match msg {
                        ChannelCommand::ComeBackLater => {
                            std::thread::sleep(WORKER_BACKOFF_INTERVAL);
                            continue;
                        }
                        ChannelCommand::JobData(mut pkg) => {
                            let pkgname = pkg.pkginfo.index.pkgname.clone();
                            let pkgpath = pkg.pkginfo.pkgpath.clone();
                            let span = info_span!(
                                "build",
                                sandbox_id = pkg.sandbox_id,
                                pkgpath = %pkgpath,
                                pkgname = %pkgname.pkgname(),
                            );
                            let _guard = span.enter();

                            let log_dir = pkg.session.config.logdir().join(pkgname.pkgname());
                            let timestamp = epoch_secs();
                            let build_start = Instant::now();
                            let result = pkg.build(&manager_tx);
                            let duration = build_start.elapsed();
                            trace!(
                                elapsed_ms = duration.as_millis(),
                                result = %result.as_ref().map_or("error".to_string(), |r| r.to_string()),
                                "Build finished"
                            );

                            let mut build_stats = match &result {
                                Ok(PkgBuildResult::Success(s) | PkgBuildResult::Failed(s)) => {
                                    s.clone()
                                }
                                Err(_) => PkgBuildStats::default(),
                            };
                            build_stats.duration = duration;
                            build_stats.timestamp = timestamp;

                            match result {
                                Ok(PkgBuildResult::Success(_)) => {
                                    let _ =
                                        manager_tx.send(ChannelCommand::JobSuccess(BuildResult {
                                            pkgname,
                                            pkgpath: Some(pkgpath),
                                            state: PackageState::Success,
                                            log_dir: Some(log_dir),
                                            build_stats,
                                        }));
                                }
                                Ok(PkgBuildResult::Failed(_)) => {
                                    let _ =
                                        manager_tx.send(ChannelCommand::JobFailed(BuildResult {
                                            pkgname,
                                            pkgpath: Some(pkgpath),
                                            state: PackageState::Failed("Build failed".to_string()),
                                            log_dir: Some(log_dir),
                                            build_stats,
                                        }));
                                }
                                Err(e) => {
                                    if !state_for_worker.is_shutdown() {
                                        tracing::error!(
                                            error = %e,
                                            pkgname = %pkgname.pkgname(),
                                            "Build error"
                                        );
                                        let _ = manager_tx.send(ChannelCommand::JobFailed(
                                            BuildResult {
                                                pkgname,
                                                pkgpath: Some(pkgpath),
                                                state: PackageState::Failed(e.to_string()),
                                                log_dir: Some(log_dir),
                                                build_stats,
                                            },
                                        ));
                                    }
                                }
                            }

                            if state_for_worker.is_shutdown() {
                                break;
                            }
                            continue;
                        }
                        ChannelCommand::Quit | ChannelCommand::Shutdown => {
                            break;
                        }
                        _ => break,
                    }
                }
            });
            threads.push(thread);
        }

        /*
         * Manager thread.  Read incoming commands from clients and reply
         * accordingly.  Returns the build results via a channel.
         */
        let session = Arc::new(BuildSession {
            config: self.config.clone(),
            pkgsrc_env: self.pkgsrc_env.clone(),
            sandbox: self.scope.sandbox().clone(),
            state: state_flag.clone(),
            wrkobjdir_map,
        });
        let sandbox_ids = self.scope.ids().map(|ids| ids.to_vec());
        let progress_clone = Arc::clone(&progress);
        let state_for_manager = state_flag.clone();
        let (results_tx, results_rx) = mpsc::channel::<Vec<BuildResult>>();
        // Channel for saving results to database as builds complete
        let (completed_tx, completed_rx) = mpsc::channel::<BuildResult>();
        let manager = std::thread::spawn(move || {
            let sandbox_ids = sandbox_ids;
            let mut clients = clients.clone();
            let mut jobs = jobs;
            let mut announced_interrupt = false;

            // Track which thread is building which package
            let mut thread_packages: HashMap<usize, PkgName> = HashMap::new();

            loop {
                if state_for_manager.is_shutdown() {
                    let was_first = if let Ok(mut p) = progress_clone.lock() {
                        p.finish_interrupted().unwrap_or(false)
                    } else {
                        false
                    };
                    if was_first {
                        eprintln!("Interrupted, shutting down...");
                    }
                    for (_, client) in clients.drain() {
                        let _ = client.send(ChannelCommand::Shutdown);
                    }
                    break;
                } else if state_for_manager.is_stopping() && !announced_interrupt {
                    if let Ok(mut p) = progress_clone.lock() {
                        p.announce_interrupt();
                    }
                    announced_interrupt = true;
                }

                let command = match manager_rx.recv_timeout(SHUTDOWN_POLL_INTERVAL) {
                    Ok(cmd) => cmd,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };

                match command {
                    ChannelCommand::ClientReady(c) if state_for_manager.is_stopping() => {
                        /*
                         * When stopping, don't start new builds -- send Quit
                         * so the worker exits after finishing its current job.
                         */
                        if let Ok(mut p) = progress_clone.lock() {
                            p.clear_output_buffer(c);
                            p.state_mut().set_worker_idle(c);
                            let _ = p.render();
                        }
                        if let Some(client) = clients.get(&c) {
                            let _ = client.send(ChannelCommand::Quit);
                        }
                        clients.remove(&c);
                        if clients.is_empty() {
                            break;
                        }
                    }
                    ChannelCommand::ClientReady(c) => {
                        let client = clients.get(&c).expect("client not in map");
                        match jobs.scheduler.poll() {
                            Poll::Ready(Some(sp)) => {
                                let pkginfo =
                                    jobs.scanpkgs.get(&sp.pkg).expect("pkg not in scanpkgs");

                                thread_packages.insert(c, sp.pkg.clone());
                                if let Ok(mut p) = progress_clone.lock() {
                                    p.clear_output_buffer(c);
                                    p.state_mut().set_worker_active(c, sp.pkg.pkgname());
                                    p.state_mut().increment_dispatched();
                                    if p.is_plain() {
                                        let _ = p.print_status("Building", sp.pkg.pkgname());
                                    }
                                    let _ = p.render();
                                }

                                let _ =
                                    client.send(ChannelCommand::JobData(Box::new(PackageBuild {
                                        session: Arc::clone(&session),
                                        sandbox_id: sandbox_ids.as_ref().map(|ids| ids[c]),
                                        worker_id: c,
                                        pkginfo: pkginfo.clone(),
                                        make_jobs: sp.make_jobs,
                                    })));
                            }
                            Poll::Ready(None) => {
                                if let Ok(mut p) = progress_clone.lock() {
                                    p.clear_output_buffer(c);
                                    p.state_mut().set_worker_idle(c);
                                    let _ = p.render();
                                }
                                let _ = client.send(ChannelCommand::Quit);
                                clients.remove(&c);
                                if clients.is_empty() {
                                    break;
                                }
                            }
                            Poll::Pending => {
                                if let Ok(mut p) = progress_clone.lock() {
                                    p.clear_output_buffer(c);
                                    p.state_mut().set_worker_idle(c);
                                    let _ = p.render();
                                }
                                let _ = client.send(ChannelCommand::ComeBackLater);
                            }
                        }
                    }
                    ChannelCommand::JobSuccess(result) => {
                        let pkgname = result.pkgname.clone();
                        let duration = result.build_stats.duration;
                        jobs.mark_success(result);

                        let sid = thread_packages
                            .iter()
                            .find(|(_, p)| *p == &pkgname)
                            .map(|(t, _)| *t);

                        if let Some(r) = jobs.results.last() {
                            let _ = completed_tx.send(r.clone());
                        }

                        if let Ok(mut p) = progress_clone.lock() {
                            let _ = p.print_status(
                                "Built",
                                &format!("{} ({})", pkgname.pkgname(), format_duration(duration)),
                            );
                            p.state_mut().increment_completed();
                            if let Some(sid) = sid {
                                p.clear_output_buffer(sid);
                                p.state_mut().set_worker_idle(sid);
                            }
                            let _ = p.render();
                        }

                        if let Some(sid) = sid {
                            thread_packages.remove(&sid);
                        }
                    }
                    ChannelCommand::JobFailed(result) => {
                        let pkgname = result.pkgname.clone();
                        let duration = result.build_stats.duration;
                        let results_before = jobs.results.len();
                        jobs.mark_failure(result);

                        let sid = thread_packages
                            .iter()
                            .find(|(_, p)| *p == &pkgname)
                            .map(|(t, _)| *t);

                        for r in jobs.results.iter().skip(results_before) {
                            let _ = completed_tx.send(r.clone());
                        }

                        let indirect_count = jobs.results.len() - results_before - 1;

                        if let Ok(mut p) = progress_clone.lock() {
                            let msg = if indirect_count > 0 {
                                format!(
                                    "{} ({}, breaks {})",
                                    pkgname.pkgname(),
                                    format_duration(duration),
                                    indirect_count
                                )
                            } else {
                                format!("{} ({})", pkgname.pkgname(), format_duration(duration))
                            };
                            let _ = p.print_status("Failed", &msg);
                            p.state_mut().increment_failed();
                            p.state_mut().skipped += indirect_count;
                            if let Some(sid) = sid {
                                p.clear_output_buffer(sid);
                                p.state_mut().set_worker_idle(sid);
                            }
                            let _ = p.render();
                        }

                        if let Some(sid) = sid {
                            thread_packages.remove(&sid);
                        }
                    }
                    ChannelCommand::StageUpdate(tid, stage) => {
                        if let Ok(mut p) = progress_clone.lock() {
                            p.state_mut().set_worker_stage(tid, stage.as_deref());
                            let _ = p.render();
                        }
                    }
                    ChannelCommand::OutputLines(tid, lines) => {
                        if let Ok(mut p) = progress_clone.lock() {
                            if let Some(buf) = p.output_buffer_mut(tid) {
                                for line in lines {
                                    buf.push(line);
                                }
                            }
                        }
                    }
                    ChannelCommand::ComeBackLater
                    | ChannelCommand::JobData(_)
                    | ChannelCommand::Quit
                    | ChannelCommand::Shutdown => {}
                }
            }

            debug!(
                result_count = jobs.results.len(),
                "Manager sending results back"
            );
            let _ = results_tx.send(jobs.results);
        });

        threads.push(manager);

        // Save completed results to database as they arrive.  The
        // completed_tx sender is owned by the manager thread; when it
        // exits (after all workers finish), the channel disconnects
        // and recv() returns Err, ending this loop.
        let mut saved_count = 0;
        let mut db_error: Option<anyhow::Error> = None;
        while let Ok(result) = completed_rx.recv() {
            if let Err(e) = db.store_build_by_name(&result) {
                warn!(
                    pkgname = %result.pkgname.pkgname(),
                    error = %e,
                    "Failed to save build result"
                );
                if db_error.is_none() {
                    db_error = Some(e);
                }
            } else {
                saved_count += 1;
            }

            if let Some(input) = result.history_input() {
                if let Err(e) = db.record_history(&input) {
                    warn!(
                        pkgname = %result.pkgname.pkgname(),
                        error = %e,
                        "Failed to save build history"
                    );
                }
            }
        }
        if saved_count > 0 {
            debug!(saved_count, "Saved build results to database");
        }

        debug!("Joining worker threads");
        let join_start = Instant::now();
        for thread in threads {
            if let Err(e) = thread.join() {
                warn!("Worker thread panicked: {:?}", e);
            }
        }
        debug!(
            elapsed_ms = join_start.elapsed().as_millis(),
            "Worker threads completed"
        );

        if let Some(sampler) = cpu_sampler {
            let samples = sampler.stop();
            if !samples.is_empty() {
                if let Err(e) = db.store_cpu_usage(&samples) {
                    warn!(error = %e, "Failed to save CPU usage samples");
                } else {
                    debug!(count = samples.len(), "Saved CPU usage samples");
                }
            }
        }

        // Stop the refresh thread
        stop_refresh.store(true, Ordering::Relaxed);
        let _ = refresh_thread.join();

        if let Ok(mut p) = progress.lock() {
            if state_flag.interrupted() {
                let _ = p.finish_interrupted();
            } else {
                let _ = p.finish();
            }
        }

        // Collect results from manager
        debug!("Collecting results from manager");
        let results = results_rx.recv().unwrap_or_default();
        debug!(
            result_count = results.len(),
            "Collected results from manager"
        );
        let summary = BuildSummary {
            duration: started.elapsed(),
            results,
            scanfail: Vec::new(),
        };

        if let Some(e) = db_error {
            return Err(e.context("Failed to persist build results to database"));
        }

        // Guard is dropped when Build goes out of scope, destroying sandboxes
        Ok(summary)
    }
}
