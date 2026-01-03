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
//!
//! # Example
//!
//! ```no_run
//! use bob::{Build, Config, Database, RunContext, Scan};
//! use std::sync::Arc;
//! use std::sync::atomic::AtomicBool;
//!
//! let config = Config::load(None, false)?;
//! let db_path = config.logdir().join("bob").join("bob.db");
//! let db = Database::open(&db_path)?;
//! let mut scan = Scan::new(&config);
//! // Add packages...
//! let ctx = RunContext::new(Arc::new(AtomicBool::new(false)));
//! scan.start(&ctx, &db)?;
//! let result = scan.resolve(&db)?;
//!
//! let mut build = Build::new(&config, result.buildable);
//! let summary = build.start(&ctx, &db)?;
//!
//! println!("Built {} packages", summary.success_count());
//! # Ok::<(), anyhow::Error>(())
//! ```

use crate::scan::ResolvedIndex;
use crate::scan::ScanFailure;
use crate::tui::{MultiProgress, format_duration};
use crate::{Config, RunContext, Sandbox};
use anyhow::{Context, bail};
use glob::Pattern;
use indexmap::IndexMap;
use pkgsrc::{PkgName, PkgPath};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc, mpsc::Sender};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

/// Build stages in order of execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    PreClean,
    Depends,
    Checksum,
    Configure,
    Build,
    Install,
    Package,
    Deinstall,
    Clean,
}

impl Stage {
    fn as_str(&self) -> &'static str {
        match self {
            Stage::PreClean => "pre-clean",
            Stage::Depends => "depends",
            Stage::Checksum => "checksum",
            Stage::Configure => "configure",
            Stage::Build => "build",
            Stage::Install => "install",
            Stage::Package => "package",
            Stage::Deinstall => "deinstall",
            Stage::Clean => "clean",
        }
    }
}

/// Result of a package build.
#[derive(Debug)]
enum PkgBuildResult {
    Success,
    Failed,
    Skipped,
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

/// Package builder that executes build stages.
struct PkgBuilder<'a> {
    config: &'a Config,
    sandbox: &'a Sandbox,
    sandbox_id: usize,
    pkginfo: &'a ResolvedIndex,
    logdir: PathBuf,
    build_user: Option<String>,
    pkg_up_to_date: Option<PathBuf>,
    envs: Vec<(String, String)>,
    output_tx: Option<Sender<ChannelCommand>>,
}

impl<'a> PkgBuilder<'a> {
    fn new(
        config: &'a Config,
        sandbox: &'a Sandbox,
        sandbox_id: usize,
        pkginfo: &'a ResolvedIndex,
        envs: Vec<(String, String)>,
        output_tx: Option<Sender<ChannelCommand>>,
    ) -> Self {
        let logdir = config.logdir().join(pkginfo.pkgname.pkgname());
        let build_user = config.build_user().map(|s| s.to_string());
        let pkg_up_to_date = config.script("pkg-up-to-date").cloned();
        Self {
            config,
            sandbox,
            sandbox_id,
            pkginfo,
            logdir,
            build_user,
            pkg_up_to_date,
            envs,
            output_tx,
        }
    }

    /// Check if the package is already up-to-date.
    fn check_up_to_date(&self) -> bool {
        let Some(script) = &self.pkg_up_to_date else {
            return false;
        };

        let pkgname = self.pkginfo.pkgname.pkgname();
        let deps: Vec<String> =
            self.pkginfo.depends.iter().map(|d| d.to_string()).collect();

        let mut cmd = if self.sandbox.enabled() {
            let mut c = Command::new("/usr/sbin/chroot");
            c.arg(self.sandbox.path(self.sandbox_id)).arg(script);
            c
        } else {
            Command::new(script)
        };

        self.apply_envs(&mut cmd, &[]);

        cmd.arg(pkgname);
        for dep in &deps {
            cmd.arg(dep);
        }

        match cmd.status() {
            Ok(status) => status.success(),
            Err(_) => false,
        }
    }

    /// Run the full build process.
    fn build<C: BuildCallback>(
        &self,
        callback: &mut C,
    ) -> anyhow::Result<PkgBuildResult> {
        let pkgname = self.pkginfo.pkgname.pkgname();
        let Some(pkgpath) = &self.pkginfo.pkg_location else {
            bail!("Could not get PKGPATH for {}", pkgname);
        };

        // Check if package is already up-to-date
        if self.check_up_to_date() {
            return Ok(PkgBuildResult::Skipped);
        }

        // Clean up and create log directory
        if self.logdir.exists() {
            fs::remove_dir_all(&self.logdir)?;
        }
        fs::create_dir_all(&self.logdir)?;

        // Create work.log and chown to build_user if set
        let work_log = self.logdir.join("work.log");
        File::create(&work_log)?;
        if let Some(ref user) = self.build_user {
            // Use chown command to set ownership
            let _ = Command::new("chown").arg(user).arg(&work_log).status();
        }

        let pkgdir = self.config.pkgsrc().join(pkgpath.as_path());

        // Pre-clean
        callback.stage(Stage::PreClean.as_str());
        self.run_make_stage(
            Stage::PreClean,
            &pkgdir,
            &["clean"],
            RunAs::Root,
            false,
        )?;

        // Install dependencies
        if !self.pkginfo.depends.is_empty() {
            callback.stage(Stage::Depends.as_str());
            let _ = self.write_stage(Stage::Depends);
            if !self.install_dependencies()? {
                return Ok(PkgBuildResult::Failed);
            }
        }

        // Checksum
        callback.stage(Stage::Checksum.as_str());
        if !self.run_make_stage(
            Stage::Checksum,
            &pkgdir,
            &["checksum"],
            RunAs::Root,
            true,
        )? {
            return Ok(PkgBuildResult::Failed);
        }

        // Configure
        callback.stage(Stage::Configure.as_str());
        let configure_log = self.logdir.join("configure.log");
        if !self.run_usergroup_if_needed(
            Stage::Configure,
            &pkgdir,
            &configure_log,
        )? {
            return Ok(PkgBuildResult::Failed);
        }
        if !self.run_make_stage(
            Stage::Configure,
            &pkgdir,
            &["configure"],
            self.build_run_as(),
            true,
        )? {
            return Ok(PkgBuildResult::Failed);
        }

        // Build
        callback.stage(Stage::Build.as_str());
        let build_log = self.logdir.join("build.log");
        if !self.run_usergroup_if_needed(Stage::Build, &pkgdir, &build_log)? {
            return Ok(PkgBuildResult::Failed);
        }
        if !self.run_make_stage(
            Stage::Build,
            &pkgdir,
            &["all"],
            self.build_run_as(),
            true,
        )? {
            return Ok(PkgBuildResult::Failed);
        }

        // Install
        callback.stage(Stage::Install.as_str());
        let install_log = self.logdir.join("install.log");
        if !self.run_usergroup_if_needed(
            Stage::Install,
            &pkgdir,
            &install_log,
        )? {
            return Ok(PkgBuildResult::Failed);
        }
        if !self.run_make_stage(
            Stage::Install,
            &pkgdir,
            &["stage-install"],
            self.build_run_as(),
            true,
        )? {
            return Ok(PkgBuildResult::Failed);
        }

        // Package
        callback.stage(Stage::Package.as_str());
        if !self.run_make_stage(
            Stage::Package,
            &pkgdir,
            &["stage-package-create"],
            RunAs::Root,
            true,
        )? {
            return Ok(PkgBuildResult::Failed);
        }

        // Get the package file path
        let pkgfile = self.get_make_var(&pkgdir, "STAGE_PKGFILE")?;

        // Test package install (unless bootstrap package)
        let is_bootstrap = self.pkginfo.bootstrap_pkg.as_deref() == Some("yes");
        if !is_bootstrap {
            if !self.pkg_add(&pkgfile)? {
                return Ok(PkgBuildResult::Failed);
            }

            // Test package deinstall
            callback.stage(Stage::Deinstall.as_str());
            let _ = self.write_stage(Stage::Deinstall);
            if !self.pkg_delete(pkgname)? {
                return Ok(PkgBuildResult::Failed);
            }
        }

        // Save package to packages directory
        let packages_dir = self.config.packages().join("All");
        fs::create_dir_all(&packages_dir)?;
        let dest = packages_dir.join(
            Path::new(&pkgfile)
                .file_name()
                .context("Invalid package file path")?,
        );
        // pkgfile is a path inside the sandbox; prepend sandbox path for host access
        let host_pkgfile = if self.sandbox.enabled() {
            self.sandbox
                .path(self.sandbox_id)
                .join(pkgfile.trim_start_matches('/'))
        } else {
            PathBuf::from(&pkgfile)
        };
        fs::copy(&host_pkgfile, &dest)?;

        // Clean
        callback.stage(Stage::Clean.as_str());
        let _ = self.run_make_stage(
            Stage::Clean,
            &pkgdir,
            &["clean"],
            RunAs::Root,
            false,
        );

        // Remove log directory on success
        let _ = fs::remove_dir_all(&self.logdir);

        Ok(PkgBuildResult::Success)
    }

    /// Determine how to run build commands.
    fn build_run_as(&self) -> RunAs {
        if self.build_user.is_some() { RunAs::User } else { RunAs::Root }
    }

    /// Write the current stage to a .stage file.
    fn write_stage(&self, stage: Stage) -> anyhow::Result<()> {
        let stage_file = self.logdir.join(".stage");
        fs::write(&stage_file, stage.as_str())?;
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
    ) -> anyhow::Result<bool> {
        // Write stage to .stage file
        let _ = self.write_stage(stage);

        let logfile = self.logdir.join(format!("{}.log", stage.as_str()));
        let work_log = self.logdir.join("work.log");

        let owned_args =
            self.make_args(pkgdir, targets, include_make_flags, &work_log);

        // Convert to slice of &str for the command
        let args: Vec<&str> = owned_args.iter().map(|s| s.as_str()).collect();

        debug!(stage = stage.as_str(), targets = ?targets, "Running make stage");

        let status = self.run_command_logged(
            self.config.make(),
            &args,
            run_as,
            &logfile,
        )?;

        Ok(status.success())
    }

    /// Run a command with output logged to a file.
    fn run_command_logged(
        &self,
        cmd: &Path,
        args: &[&str],
        run_as: RunAs,
        logfile: &Path,
    ) -> anyhow::Result<ExitStatus> {
        self.run_command_logged_with_env(cmd, args, run_as, logfile, &[])
    }

    fn run_command_logged_with_env(
        &self,
        cmd: &Path,
        args: &[&str],
        run_as: RunAs,
        logfile: &Path,
        extra_envs: &[(&str, &str)],
    ) -> anyhow::Result<ExitStatus> {
        use std::io::{BufRead, BufReader, Write};

        let mut log =
            OpenOptions::new().create(true).append(true).open(logfile)?;

        // Write command being executed to the log file
        let _ = writeln!(log, "=> {:?} {:?}", cmd, args);
        let _ = log.flush();

        // Use tee-style pipe handling when output_tx is available for live view.
        // Otherwise use direct file redirection.
        if let Some(ref output_tx) = self.output_tx {
            // Wrap command in shell to merge stdout/stderr with 2>&1, like the
            // shell script's run_log function does.
            let shell_cmd =
                self.build_shell_command(cmd, args, run_as, extra_envs);
            let mut child = if self.sandbox.enabled() {
                let sandbox_path = self.sandbox.path(self.sandbox_id);
                Command::new("/usr/sbin/chroot")
                    .arg(&sandbox_path)
                    .arg("/bin/sh")
                    .arg("-c")
                    .arg(&shell_cmd)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .context("Failed to spawn shell command")?
            } else {
                Command::new("/bin/sh")
                    .arg("-c")
                    .arg(&shell_cmd)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .context("Failed to spawn shell command")?
            };

            let stdout = child.stdout.take().unwrap();
            let output_tx = output_tx.clone();
            let sandbox_id = self.sandbox_id;

            // Spawn thread to read from pipe and tee to file + output channel.
            // Batch lines and throttle sends to reduce channel overhead.
            let tee_handle = std::thread::spawn(move || {
                let mut reader = BufReader::new(stdout);
                let mut buf = Vec::new();
                let mut batch = Vec::with_capacity(50);
                let mut last_send = Instant::now();
                let send_interval = Duration::from_millis(100);

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
                    if last_send.elapsed() >= send_interval || batch.len() >= 50
                    {
                        let _ = output_tx.send(ChannelCommand::OutputLines(
                            sandbox_id,
                            std::mem::take(&mut batch),
                        ));
                        last_send = Instant::now();
                    }
                }

                // Send remaining lines
                if !batch.is_empty() {
                    let _ = output_tx
                        .send(ChannelCommand::OutputLines(sandbox_id, batch));
                }
            });

            // Wait for command to exit
            let status = child.wait()?;

            // Reader thread will exit when pipe closes (process exits)
            let _ = tee_handle.join();

            trace!(cmd = ?cmd, status = ?status, "Command completed");
            Ok(status)
        } else {
            let status =
                self.spawn_command_to_file(cmd, args, run_as, extra_envs, log)?;
            trace!(cmd = ?cmd, status = ?status, "Command completed");
            Ok(status)
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
    ) -> anyhow::Result<ExitStatus> {
        // Clone file handle for stderr (stdout and stderr both go to same file)
        let log_err = log.try_clone()?;

        match run_as {
            RunAs::Root => {
                if self.sandbox.enabled() {
                    let sandbox_path = self.sandbox.path(self.sandbox_id);
                    let mut full_args: Vec<String> = vec![
                        sandbox_path.to_str().unwrap().to_string(),
                        cmd.to_str().unwrap().to_string(),
                    ];
                    full_args.extend(args.iter().map(|s| s.to_string()));
                    let mut command = Command::new("/usr/sbin/chroot");
                    command.args(&full_args);
                    self.apply_envs(&mut command, extra_envs);
                    command
                        .stdout(Stdio::from(log))
                        .stderr(Stdio::from(log_err))
                        .status()
                        .context("Failed to run chroot command")
                } else {
                    let mut command = Command::new(cmd);
                    command.args(args);
                    self.apply_envs(&mut command, extra_envs);
                    command
                        .stdout(Stdio::from(log))
                        .stderr(Stdio::from(log_err))
                        .status()
                        .with_context(|| {
                            format!("Failed to run {}", cmd.display())
                        })
                }
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
                if self.sandbox.enabled() {
                    let sandbox_path = self.sandbox.path(self.sandbox_id);
                    let mut command = Command::new("/usr/sbin/chroot");
                    command
                        .arg(&sandbox_path)
                        .arg("su")
                        .arg(user)
                        .arg("-c")
                        .arg(&inner_cmd);
                    self.apply_envs(&mut command, extra_envs);
                    command
                        .stdout(Stdio::from(log))
                        .stderr(Stdio::from(log_err))
                        .status()
                        .context("Failed to run chroot su command")
                } else {
                    let mut command = Command::new("su");
                    command.arg(user).arg("-c").arg(&inner_cmd);
                    self.apply_envs(&mut command, extra_envs);
                    command
                        .stdout(Stdio::from(log))
                        .stderr(Stdio::from(log_err))
                        .status()
                        .context("Failed to run su command")
                }
            }
        }
    }

    /// Get a make variable value.
    fn get_make_var(
        &self,
        pkgdir: &Path,
        varname: &str,
    ) -> anyhow::Result<String> {
        let mut cmd = if self.sandbox.enabled() {
            let mut c = Command::new("/usr/sbin/chroot");
            c.arg(self.sandbox.path(self.sandbox_id)).arg(self.config.make());
            c
        } else {
            Command::new(self.config.make())
        };

        self.apply_envs(&mut cmd, &[]);

        let work_log = self.logdir.join("work.log");
        let make_args = self.make_args(
            pkgdir,
            &["show-var", &format!("VARNAME={}", varname)],
            true,
            &work_log,
        );

        let output = cmd.args(&make_args).output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(varname, stderr = %stderr, "Failed to get make variable");
            bail!("Failed to get make variable {}: {}", varname, stderr.trim());
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Install package dependencies.
    fn install_dependencies(&self) -> anyhow::Result<bool> {
        let deps: Vec<String> =
            self.pkginfo.depends.iter().map(|d| d.to_string()).collect();

        let pkg_path = self.config.packages().join("All");
        let logfile = self.logdir.join("depends.log");

        let mut args = vec![];
        for dep in &deps {
            args.push(dep.as_str());
        }

        let status = self.run_pkg_add_with_path(&args, &pkg_path, &logfile)?;
        Ok(status.success())
    }

    /// Run pkg_add with PKG_PATH set.
    fn run_pkg_add_with_path(
        &self,
        packages: &[&str],
        pkg_path: &Path,
        logfile: &Path,
    ) -> anyhow::Result<ExitStatus> {
        let pkg_add = self.config.pkgtools().join("pkg_add");
        let pkg_path_value = pkg_path.to_string_lossy().to_string();
        let extra_envs = [("PKG_PATH", pkg_path_value.as_str())];

        self.run_command_logged_with_env(
            &pkg_add,
            packages,
            RunAs::Root,
            logfile,
            &extra_envs,
        )
    }

    /// Install a package file.
    fn pkg_add(&self, pkgfile: &str) -> anyhow::Result<bool> {
        let pkg_add = self.config.pkgtools().join("pkg_add");
        let logfile = self.logdir.join("package.log");

        let status = self.run_command_logged(
            &pkg_add,
            &[pkgfile],
            RunAs::Root,
            &logfile,
        )?;

        Ok(status.success())
    }

    /// Delete an installed package.
    fn pkg_delete(&self, pkgname: &str) -> anyhow::Result<bool> {
        let pkg_delete = self.config.pkgtools().join("pkg_delete");
        let logfile = self.logdir.join("deinstall.log");

        let status = self.run_command_logged(
            &pkg_delete,
            &[pkgname],
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
        let usergroup_phase =
            self.pkginfo.usergroup_phase.as_deref().unwrap_or("");

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

        let status = self.run_command_logged(
            self.config.make(),
            &args,
            RunAs::Root,
            logfile,
        )?;
        Ok(status.success())
    }

    fn make_args(
        &self,
        pkgdir: &Path,
        targets: &[&str],
        include_make_flags: bool,
        work_log: &Path,
    ) -> Vec<String> {
        let mut owned_args: Vec<String> =
            vec!["-C".to_string(), pkgdir.to_str().unwrap().to_string()];
        owned_args.extend(targets.iter().map(|s| s.to_string()));

        if include_make_flags {
            owned_args.push("BATCH=1".to_string());
            owned_args.push("DEPENDS_TARGET=/nonexistent".to_string());

            if let Some(ref multi_version) = self.pkginfo.multi_version {
                for flag in multi_version {
                    owned_args.push(flag.clone());
                }
            }

            owned_args.push(format!("WRKLOG={}", work_log.display()));
        }

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
        let args_str: Vec<String> =
            args.iter().map(|a| Self::shell_escape(a)).collect();

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
        Self { sandbox_id, status_tx }
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

/// Outcome of a package build attempt.
///
/// Used in [`BuildResult`] to indicate whether the build succeeded, failed,
/// or was skipped.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum BuildOutcome {
    /// Package built and packaged successfully.
    Success,
    /// Package build failed.
    ///
    /// The string contains the failure reason (e.g., "Failed in build phase").
    Failed(String),
    /// Package did not need to be built - we already have a binary package
    /// for this revision.
    UpToDate,
    /// Package is marked with PKG_SKIP_REASON or PKG_FAIL_REASON so cannot
    /// be built.
    ///
    /// The string contains the skip/fail reason.
    PreFailed(String),
    /// Package depends on a different package that has Failed.
    ///
    /// The string contains the name of the failed dependency.
    IndirectFailed(String),
    /// Package depends on a different package that has PreFailed.
    ///
    /// The string contains the name of the pre-failed dependency.
    IndirectPreFailed(String),
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
    /// Build outcome (success, failure, or skipped).
    pub outcome: BuildOutcome,
    /// Time spent building this package.
    pub duration: Duration,
    /// Path to build logs directory, if available.
    ///
    /// For failed builds, this contains `pre-clean.log`, `build.log`, etc.
    /// Successful builds clean up their log directories.
    pub log_dir: Option<PathBuf>,
}

/// Summary of an entire build run.
///
/// Contains timing information and results for all packages.
///
/// # Example
///
/// ```no_run
/// # use bob::BuildSummary;
/// # fn example(summary: &BuildSummary) {
/// println!("Succeeded: {}", summary.success_count());
/// println!("Failed: {}", summary.failed_count());
/// println!("Up-to-date: {}", summary.up_to_date_count());
/// println!("Duration: {:?}", summary.duration);
///
/// for result in summary.failed() {
///     println!("  {} failed", result.pkgname.pkgname());
/// }
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct BuildSummary {
    /// Total duration of the build run.
    pub duration: Duration,
    /// Results for each package.
    pub results: Vec<BuildResult>,
    /// Packages that failed to scan (bmake pbulk-index failed).
    pub scan_failed: Vec<ScanFailure>,
}

impl BuildSummary {
    /// Count of successfully built packages.
    pub fn success_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::Success))
            .count()
    }

    /// Count of failed packages (direct build failures only).
    pub fn failed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::Failed(_)))
            .count()
    }

    /// Count of up-to-date packages (already have binary package).
    pub fn up_to_date_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::UpToDate))
            .count()
    }

    /// Count of pre-failed packages (PKG_SKIP_REASON/PKG_FAIL_REASON).
    pub fn prefailed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::PreFailed(_)))
            .count()
    }

    /// Count of indirect failed packages (depend on Failed).
    pub fn indirect_failed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::IndirectFailed(_)))
            .count()
    }

    /// Count of indirect pre-failed packages (depend on PreFailed).
    pub fn indirect_prefailed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::IndirectPreFailed(_)))
            .count()
    }

    /// Count of packages that failed to scan.
    pub fn scan_failed_count(&self) -> usize {
        self.scan_failed.len()
    }

    /// Get all failed results (direct build failures only).
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

    /// Get all up-to-date results.
    pub fn up_to_date(&self) -> Vec<&BuildResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::UpToDate))
            .collect()
    }

    /// Get all pre-failed results.
    pub fn prefailed(&self) -> Vec<&BuildResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::PreFailed(_)))
            .collect()
    }

    /// Get all indirect failed results.
    pub fn indirect_failed(&self) -> Vec<&BuildResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::IndirectFailed(_)))
            .collect()
    }

    /// Get all indirect pre-failed results.
    pub fn indirect_prefailed(&self) -> Vec<&BuildResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, BuildOutcome::IndirectPreFailed(_)))
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct Build {
    /// Parsed [`Config`].
    config: Config,
    /// [`Sandbox`] configuration.
    sandbox: Sandbox,
    /// List of packages to build, as input from Scan::resolve.
    scanpkgs: IndexMap<PkgName, ResolvedIndex>,
    /// Cached build results from previous run.
    cached: IndexMap<PkgName, BuildResult>,
}

#[derive(Debug)]
struct PackageBuild {
    id: usize,
    config: Config,
    pkginfo: ResolvedIndex,
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
        Self { config, sandbox, sandbox_id, pkgpath, env }
    }

    /// Query a bmake variable value.
    fn var(&self, name: &str) -> Option<String> {
        let pkgdir = self.config.pkgsrc().join(self.pkgpath.as_path());

        let mut cmd = if self.sandbox.enabled() {
            let mut c = Command::new("/usr/sbin/chroot");
            c.arg(self.sandbox.path(self.sandbox_id)).arg(self.config.make());
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

        cmd.stderr(Stdio::null());

        let output = cmd.output().ok()?;

        if !output.status.success() {
            return None;
        }

        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if value.is_empty() { None } else { Some(value) }
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
    fn build(
        &self,
        status_tx: &Sender<ChannelCommand>,
    ) -> anyhow::Result<PackageBuildResult> {
        let pkgname = self.pkginfo.pkgname.pkgname();
        info!(pkgname = %pkgname,
            sandbox_id = self.id,
            "Starting package build"
        );

        let Some(pkgpath) = &self.pkginfo.pkg_location else {
            error!(pkgname = %pkgname, "Could not get PKGPATH for package");
            bail!("Could not get PKGPATH for {}", pkgname);
        };

        let logdir = self.config.logdir();

        // Get env vars from Lua config for wrkdir saving and build environment
        let pkg_env = match self.config.get_pkg_env(&self.pkginfo) {
            Ok(env) => env,
            Err(e) => {
                error!(pkgname = %pkgname, error = %e, "Failed to get env from Lua config");
                HashMap::new()
            }
        };

        let mut envs = self.config.script_env();
        for (key, value) in &pkg_env {
            envs.push((key.clone(), value.clone()));
        }

        let patterns = self.config.save_wrkdir_patterns();

        // Run pre-build script if defined (always runs)
        if let Some(pre_build) = self.config.script("pre-build") {
            debug!(pkgname = %pkgname, "Running pre-build script");
            let child = self.sandbox.execute(
                self.id,
                pre_build,
                envs.clone(),
                None,
                None,
            )?;
            let output = child
                .wait_with_output()
                .context("Failed to wait for pre-build")?;
            if !output.status.success() {
                warn!(pkgname = %pkgname, exit_code = ?output.status.code(), "pre-build script failed");
            }
        }

        // Run the build using PkgBuilder
        let builder = PkgBuilder::new(
            &self.config,
            &self.sandbox,
            self.id,
            &self.pkginfo,
            envs.clone(),
            Some(status_tx.clone()),
        );

        let mut callback = ChannelCallback::new(self.id, status_tx);
        let result = builder.build(&mut callback);

        // Clear stage display
        let _ = status_tx.send(ChannelCommand::StageUpdate(self.id, None));

        let result = match &result {
            Ok(PkgBuildResult::Success) => {
                info!(pkgname = %pkgname, "package build completed successfully");
                PackageBuildResult::Success
            }
            Ok(PkgBuildResult::Skipped) => {
                info!(pkgname = %pkgname, "package build skipped (up-to-date)");
                PackageBuildResult::Skipped
            }
            Ok(PkgBuildResult::Failed) => {
                error!(pkgname = %pkgname, "package build failed");
                // Show cleanup stage to user
                let _ = status_tx.send(ChannelCommand::StageUpdate(
                    self.id,
                    Some("cleanup".to_string()),
                ));
                // Kill any orphaned processes in the sandbox before cleanup.
                // Failed builds may leave processes running that would block
                // subsequent commands like bmake show-var or bmake clean.
                debug!(pkgname = %pkgname, "Calling kill_processes_by_id");
                let kill_start = Instant::now();
                self.sandbox.kill_processes_by_id(self.id);
                debug!(pkgname = %pkgname, elapsed_ms = kill_start.elapsed().as_millis(), "kill_processes_by_id completed");
                // Save wrkdir files matching configured patterns, then clean up
                if !patterns.is_empty() {
                    debug!(pkgname = %pkgname, "Calling save_wrkdir_files");
                    let save_start = Instant::now();
                    self.save_wrkdir_files(
                        pkgname, pkgpath, logdir, patterns, &pkg_env,
                    );
                    debug!(pkgname = %pkgname, elapsed_ms = save_start.elapsed().as_millis(), "save_wrkdir_files completed");
                    debug!(pkgname = %pkgname, "Calling run_clean");
                    let clean_start = Instant::now();
                    self.run_clean(pkgpath, &envs);
                    debug!(pkgname = %pkgname, elapsed_ms = clean_start.elapsed().as_millis(), "run_clean completed");
                } else {
                    debug!(pkgname = %pkgname, "Calling run_clean (no patterns)");
                    let clean_start = Instant::now();
                    self.run_clean(pkgpath, &envs);
                    debug!(pkgname = %pkgname, elapsed_ms = clean_start.elapsed().as_millis(), "run_clean completed");
                }
                PackageBuildResult::Failed
            }
            Err(e) => {
                error!(pkgname = %pkgname, error = %e, "package build error");
                // Show cleanup stage to user
                let _ = status_tx.send(ChannelCommand::StageUpdate(
                    self.id,
                    Some("cleanup".to_string()),
                ));
                // Kill any orphaned processes in the sandbox before cleanup.
                // Failed builds may leave processes running that would block
                // subsequent commands like bmake show-var or bmake clean.
                debug!(pkgname = %pkgname, "Calling kill_processes_by_id");
                let kill_start = Instant::now();
                self.sandbox.kill_processes_by_id(self.id);
                debug!(pkgname = %pkgname, elapsed_ms = kill_start.elapsed().as_millis(), "kill_processes_by_id completed");
                // Save wrkdir files matching configured patterns, then clean up
                if !patterns.is_empty() {
                    debug!(pkgname = %pkgname, "Calling save_wrkdir_files");
                    let save_start = Instant::now();
                    self.save_wrkdir_files(
                        pkgname, pkgpath, logdir, patterns, &pkg_env,
                    );
                    debug!(pkgname = %pkgname, elapsed_ms = save_start.elapsed().as_millis(), "save_wrkdir_files completed");
                    debug!(pkgname = %pkgname, "Calling run_clean");
                    let clean_start = Instant::now();
                    self.run_clean(pkgpath, &envs);
                    debug!(pkgname = %pkgname, elapsed_ms = clean_start.elapsed().as_millis(), "run_clean completed");
                } else {
                    debug!(pkgname = %pkgname, "Calling run_clean (no patterns)");
                    let clean_start = Instant::now();
                    self.run_clean(pkgpath, &envs);
                    debug!(pkgname = %pkgname, elapsed_ms = clean_start.elapsed().as_millis(), "run_clean completed");
                }
                PackageBuildResult::Failed
            }
        };

        // Run post-build script if defined (always runs regardless of result)
        if let Some(post_build) = self.config.script("post-build") {
            debug!(pkgname = %pkgname, script = %post_build.display(), "Running post-build script");
            match self.sandbox.execute(self.id, post_build, envs, None, None) {
                Ok(child) => {
                    debug!(pkgname = %pkgname, pid = ?child.id(), "post-build spawned, waiting");
                    match child.wait_with_output() {
                        Ok(output) => {
                            debug!(pkgname = %pkgname, exit_code = ?output.status.code(), "post-build completed");
                            if !output.status.success() {
                                warn!(pkgname = %pkgname, exit_code = ?output.status.code(), "post-build script failed");
                            }
                        }
                        Err(e) => {
                            warn!(pkgname = %pkgname, error = %e, "Failed to wait for post-build");
                        }
                    }
                }
                Err(e) => {
                    warn!(pkgname = %pkgname, error = %e, "Failed to spawn post-build script");
                }
            }
        }

        Ok(result)
    }

    /// Save files matching patterns from WRKDIR to logdir on build failure.
    fn save_wrkdir_files(
        &self,
        pkgname: &str,
        pkgpath: &PkgPath,
        logdir: &Path,
        patterns: &[String],
        pkg_env: &HashMap<String, String>,
    ) {
        let make = MakeQuery::new(
            &self.config,
            &self.sandbox,
            self.id,
            pkgpath,
            pkg_env,
        );

        // Get WRKDIR
        let wrkdir = match make.wrkdir() {
            Some(w) => w,
            None => {
                debug!(pkgname = %pkgname, "Could not determine WRKDIR, skipping file save");
                return;
            }
        };

        // Resolve to actual filesystem path
        let wrkdir_path = make.resolve_path(&wrkdir);

        if !wrkdir_path.exists() {
            debug!(pkgname = %pkgname,
                wrkdir = %wrkdir_path.display(),
                "WRKDIR does not exist, skipping file save"
            );
            return;
        }

        let save_dir = logdir.join(pkgname).join("wrkdir-files");
        if let Err(e) = fs::create_dir_all(&save_dir) {
            warn!(pkgname = %pkgname,
                error = %e,
                "Failed to create wrkdir-files directory"
            );
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
            warn!(pkgname = %pkgname,
                error = %e,
                "Error while saving wrkdir files"
            );
        }

        if saved_count > 0 {
            info!(pkgname = %pkgname,
                count = saved_count,
                dest = %save_dir.display(),
                "Saved wrkdir files"
            );
        }
    }

    /// Run bmake clean for a package.
    fn run_clean(&self, pkgpath: &PkgPath, envs: &[(String, String)]) {
        let pkgdir = self.config.pkgsrc().join(pkgpath.as_path());

        let result = if self.sandbox.enabled() {
            let mut cmd = Command::new("/usr/sbin/chroot");
            cmd.arg(self.sandbox.path(self.id))
                .arg(self.config.make())
                .arg("-C")
                .arg(&pkgdir)
                .arg("clean");
            for (key, value) in envs {
                cmd.env(key, value);
            }
            cmd.stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
        } else {
            let mut cmd = Command::new(self.config.make());
            cmd.arg("-C").arg(&pkgdir).arg("clean");
            for (key, value) in envs {
                cmd.env(key, value);
            }
            cmd.stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
        };

        if let Err(e) = result {
            debug!(error = %e, "Failed to run bmake clean");
        }
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
    /**
     * Client reporting a stage update for a build.
     */
    StageUpdate(usize, Option<String>),
    /**
     * Client reporting output lines from a build.
     */
    OutputLines(usize, Vec<String>),
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
    scanpkgs: IndexMap<PkgName, ResolvedIndex>,
    incoming: HashMap<PkgName, HashSet<PkgName>>,
    /// Reverse dependency map: package -> packages that depend on it.
    /// Precomputed for O(1) lookup in mark_failure instead of O(n) scan.
    reverse_deps: HashMap<PkgName, HashSet<PkgName>>,
    /// Effective weight: package's PBULK_WEIGHT + sum of weights of all
    /// transitive dependents. Precomputed for efficient build ordering.
    effective_weights: HashMap<PkgName, usize>,
    running: HashSet<PkgName>,
    done: HashSet<PkgName>,
    failed: HashSet<PkgName>,
    results: Vec<BuildResult>,
    logdir: PathBuf,
    /// Number of packages loaded from cache.
    #[allow(dead_code)]
    cached_count: usize,
}

impl BuildJobs {
    /**
     * Mark a package as successful and remove it from pending dependencies.
     */
    fn mark_success(&mut self, pkgname: &PkgName, duration: Duration) {
        self.mark_done(pkgname, BuildOutcome::Success, duration);
    }

    fn mark_up_to_date(&mut self, pkgname: &PkgName) {
        self.mark_done(pkgname, BuildOutcome::UpToDate, Duration::ZERO);
    }

    /**
     * Mark a package as done and remove it from pending dependencies.
     */
    fn mark_done(
        &mut self,
        pkgname: &PkgName,
        outcome: BuildOutcome,
        duration: Duration,
    ) {
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
        let log_dir = Some(self.logdir.join(pkgname.pkgname()));
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
        debug!(pkgname = %pkgname.pkgname(), "mark_failure called");
        let start = std::time::Instant::now();
        let mut broken: HashSet<PkgName> = HashSet::new();
        let mut to_check: Vec<PkgName> = vec![];
        to_check.push(pkgname.clone());
        /*
         * Starting with the original failed package, recursively loop through
         * adding any packages that depend on it, adding them to broken.
         * Uses precomputed reverse_deps for O(1) lookup instead of O(n) scan.
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
            /* Add all packages that depend on this one. */
            if let Some(dependents) = self.reverse_deps.get(&badpkg) {
                for pkg in dependents {
                    to_check.push(pkg.clone());
                }
            }
            broken.insert(badpkg);
        }
        debug!(pkgname = %pkgname.pkgname(), broken_count = broken.len(), elapsed_ms = start.elapsed().as_millis(), "mark_failure found broken packages");
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
            let log_dir = Some(self.logdir.join(pkg.pkgname()));
            let (outcome, dur) = if is_original(&pkg) {
                (BuildOutcome::Failed("Build failed".to_string()), duration)
            } else {
                (
                    BuildOutcome::IndirectFailed(pkgname.pkgname().to_string()),
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
        debug!(pkgname = %pkgname.pkgname(), total_results = self.results.len(), elapsed_ms = start.elapsed().as_millis(), "mark_failure completed");
    }

    /**
     * Recursively mark a package as pre-failed and its dependents as
     * indirect-pre-failed.
     */
    #[allow(dead_code)]
    fn mark_prefailed(&mut self, pkgname: &PkgName, reason: String) {
        let mut broken: HashSet<PkgName> = HashSet::new();
        let mut to_check: Vec<PkgName> = vec![];
        to_check.push(pkgname.clone());

        loop {
            let Some(badpkg) = to_check.pop() else {
                break;
            };
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

        let is_original = |p: &PkgName| p == pkgname;
        for pkg in broken {
            self.incoming.remove(&pkg);
            self.failed.insert(pkg.clone());

            let scanpkg = self.scanpkgs.get(&pkg);
            let log_dir = Some(self.logdir.join(pkg.pkgname()));
            let outcome = if is_original(&pkg) {
                BuildOutcome::PreFailed(reason.clone())
            } else {
                BuildOutcome::IndirectPreFailed(pkgname.pkgname().to_string())
            };
            self.results.push(BuildResult {
                pkgname: pkg,
                pkgpath: scanpkg.and_then(|s| s.pkg_location.clone()),
                outcome,
                duration: Duration::ZERO,
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
         * by effective weight (own weight + transitive dependents' weights).
         */
        let mut pkgs: Vec<(PkgName, usize)> = self
            .incoming
            .iter()
            .filter(|(_, v)| v.is_empty())
            .map(|(k, _)| {
                (k.clone(), *self.effective_weights.get(k).unwrap_or(&100))
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

impl Build {
    pub fn new(
        config: &Config,
        scanpkgs: IndexMap<PkgName, ResolvedIndex>,
    ) -> Build {
        let sandbox = Sandbox::new(config);
        info!(
            package_count = scanpkgs.len(),
            sandbox_enabled = sandbox.enabled(),
            build_threads = config.build_threads(),
            "Creating new Build instance"
        );
        for (pkgname, index) in &scanpkgs {
            debug!(pkgname = %pkgname.pkgname(),
                pkgpath = ?index.pkg_location,
                depends_count = index.depends.len(),
                depends = ?index.depends.iter().map(|d| d.pkgname()).collect::<Vec<_>>(),
                "Package in build queue"
            );
        }
        Build {
            config: config.clone(),
            sandbox,
            scanpkgs,
            cached: IndexMap::new(),
        }
    }

    /// Load cached build results from database.
    ///
    /// Returns the number of packages loaded from cache. Only loads results
    /// for packages that are in our build queue.
    pub fn load_cached_from_db(
        &mut self,
        db: &crate::db::Database,
    ) -> anyhow::Result<usize> {
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

    /// Access completed build results.
    pub fn cached(&self) -> &IndexMap<PkgName, BuildResult> {
        &self.cached
    }

    pub fn start(
        &mut self,
        ctx: &RunContext,
        db: &crate::db::Database,
    ) -> anyhow::Result<BuildSummary> {
        let started = Instant::now();

        info!(package_count = self.scanpkgs.len(), "Build::start() called");

        let shutdown_flag = Arc::clone(&ctx.shutdown);
        let stats = ctx.stats.clone();

        /*
         * Populate BuildJobs.
         */
        debug!("Populating BuildJobs from scanpkgs");
        let mut incoming: HashMap<PkgName, HashSet<PkgName>> = HashMap::new();
        let mut reverse_deps: HashMap<PkgName, HashSet<PkgName>> =
            HashMap::new();
        for (pkgname, index) in &self.scanpkgs {
            let mut deps: HashSet<PkgName> = HashSet::new();
            for dep in &index.depends {
                deps.insert(dep.clone());
                // Build reverse dependency map: dep -> packages that depend on it
                reverse_deps
                    .entry(dep.clone())
                    .or_default()
                    .insert(pkgname.clone());
            }
            trace!(pkgname = %pkgname.pkgname(),
                deps_count = deps.len(),
                deps = ?deps.iter().map(|d| d.pkgname()).collect::<Vec<_>>(),
                "Adding package to incoming build queue"
            );
            incoming.insert(pkgname.clone(), deps);
        }

        /*
         * Process cached build results.
         */
        let mut done: HashSet<PkgName> = HashSet::new();
        let mut failed: HashSet<PkgName> = HashSet::new();
        let results: Vec<BuildResult> = Vec::new();
        let mut cached_count = 0usize;

        for (pkgname, result) in &self.cached {
            match result.outcome {
                BuildOutcome::Success | BuildOutcome::UpToDate => {
                    // Completed package - remove from incoming, add to done
                    incoming.remove(pkgname);
                    done.insert(pkgname.clone());
                    // Remove from deps of other packages
                    for deps in incoming.values_mut() {
                        deps.remove(pkgname);
                    }
                    // Don't add to results - already in database
                    cached_count += 1;
                }
                BuildOutcome::Failed(_)
                | BuildOutcome::PreFailed(_)
                | BuildOutcome::IndirectFailed(_)
                | BuildOutcome::IndirectPreFailed(_) => {
                    // Failed package - remove from incoming, add to failed
                    incoming.remove(pkgname);
                    failed.insert(pkgname.clone());
                    // Don't add to results - already in database
                    cached_count += 1;
                }
            }
        }

        if cached_count > 0 {
            println!("Loaded {} cached build results", cached_count);
        }

        info!(
            incoming_count = incoming.len(),
            scanpkgs_count = self.scanpkgs.len(),
            cached_count = cached_count,
            "BuildJobs populated"
        );

        if incoming.is_empty() {
            return Ok(BuildSummary {
                duration: started.elapsed(),
                results,
                scan_failed: Vec::new(),
            });
        }

        /*
         * Compute effective weights for build ordering.  The effective weight
         * is the package's own PBULK_WEIGHT plus the sum of weights of all
         * packages that transitively depend on it.  This prioritises building
         * packages that unblock the most downstream work.
         */
        let get_weight = |pkg: &PkgName| -> usize {
            self.scanpkgs
                .get(pkg)
                .and_then(|idx| idx.pbulk_weight.as_ref())
                .and_then(|w| w.parse().ok())
                .unwrap_or(100)
        };

        let mut effective_weights: HashMap<PkgName, usize> = HashMap::new();
        let mut pending: HashMap<&PkgName, usize> = incoming
            .keys()
            .map(|p| (p, reverse_deps.get(p).map_or(0, |s| s.len())))
            .collect();
        let mut queue: VecDeque<&PkgName> = pending
            .iter()
            .filter(|(_, c)| **c == 0)
            .map(|(&p, _)| p)
            .collect();
        while let Some(pkg) = queue.pop_front() {
            let mut total = get_weight(pkg);
            if let Some(dependents) = reverse_deps.get(pkg) {
                for dep in dependents {
                    total += effective_weights.get(dep).unwrap_or(&0);
                }
            }
            effective_weights.insert(pkg.clone(), total);
            for dep in incoming.get(pkg).iter().flat_map(|s| s.iter()) {
                if let Some(c) = pending.get_mut(dep) {
                    *c -= 1;
                    if *c == 0 {
                        queue.push_back(dep);
                    }
                }
            }
        }

        let running: HashSet<PkgName> = HashSet::new();
        let logdir = self.config.logdir().clone();
        let jobs = BuildJobs {
            scanpkgs: self.scanpkgs.clone(),
            incoming,
            reverse_deps,
            effective_weights,
            running,
            done,
            failed,
            results,
            logdir,
            cached_count,
        };

        // Create sandboxes before starting progress display
        if self.sandbox.enabled() {
            println!("Creating sandboxes...");
            for i in 0..self.config.build_threads() {
                if let Err(e) = self.sandbox.create(i) {
                    // Rollback: destroy sandboxes including the failed one (may be partial)
                    for j in (0..=i).rev() {
                        if let Err(destroy_err) = self.sandbox.destroy(j) {
                            eprintln!(
                                "Warning: failed to destroy sandbox {}: {}",
                                j, destroy_err
                            );
                        }
                    }
                    return Err(e);
                }
            }
        }

        println!("Building packages...");

        // Set up multi-line progress display using ratatui inline viewport
        let progress = Arc::new(Mutex::new(
            MultiProgress::new(
                "Building",
                "Built",
                self.scanpkgs.len(),
                self.config.build_threads(),
            )
            .expect("Failed to initialize progress display"),
        ));

        // Mark cached packages in progress display
        if cached_count > 0 {
            if let Ok(mut p) = progress.lock() {
                p.state_mut().cached = cached_count;
            }
        }

        // Flag to stop the refresh thread
        let stop_refresh = Arc::new(AtomicBool::new(false));

        // Spawn a thread to periodically refresh the display (for timer updates)
        let progress_refresh = Arc::clone(&progress);
        let stop_flag = Arc::clone(&stop_refresh);
        let shutdown_for_refresh = Arc::clone(&shutdown_flag);
        let refresh_thread = std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed)
                && !shutdown_for_refresh.load(Ordering::SeqCst)
            {
                if let Ok(mut p) = progress_refresh.lock() {
                    // Check for keyboard events (like 'v' for view toggle)
                    let _ = p.poll_events();
                    let _ = p.render_throttled();
                }
                std::thread::sleep(Duration::from_millis(50));
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
        let mut clients: HashMap<usize, Sender<ChannelCommand>> =
            HashMap::new();
        for i in 0..self.config.build_threads() {
            let (client_tx, client_rx) = mpsc::channel::<ChannelCommand>();
            clients.insert(i, client_tx);
            let manager_tx = manager_tx.clone();
            let thread = std::thread::spawn(move || {
                loop {
                    // Use send() which can fail if receiver is dropped (manager shutdown)
                    if manager_tx.send(ChannelCommand::ClientReady(i)).is_err()
                    {
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
                            trace!(pkgname = %pkgname.pkgname(), worker = i, "Worker starting build");
                            let build_start = Instant::now();
                            let result = pkg.build(&manager_tx);
                            let duration = build_start.elapsed();
                            trace!(pkgname = %pkgname.pkgname(), worker = i, elapsed_ms = duration.as_millis(), "Worker build() returned");
                            match result {
                                Ok(PackageBuildResult::Success) => {
                                    trace!(pkgname = %pkgname.pkgname(), "Worker sending JobSuccess");
                                    let _ = manager_tx.send(
                                        ChannelCommand::JobSuccess(
                                            pkgname, duration,
                                        ),
                                    );
                                }
                                Ok(PackageBuildResult::Skipped) => {
                                    trace!(pkgname = %pkgname.pkgname(), "Worker sending JobSkipped");
                                    let _ = manager_tx.send(
                                        ChannelCommand::JobSkipped(pkgname),
                                    );
                                }
                                Ok(PackageBuildResult::Failed) => {
                                    trace!(pkgname = %pkgname.pkgname(), "Worker sending JobFailed");
                                    let _ = manager_tx.send(
                                        ChannelCommand::JobFailed(
                                            pkgname, duration,
                                        ),
                                    );
                                }
                                Err(e) => {
                                    trace!(pkgname = %pkgname.pkgname(), "Worker sending JobError");
                                    let _ = manager_tx.send(
                                        ChannelCommand::JobError((
                                            pkgname, duration, e,
                                        )),
                                    );
                                }
                            }
                            continue;
                        }
                        ChannelCommand::Quit | ChannelCommand::Shutdown => {
                            break;
                        }
                        _ => todo!(),
                    }
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
        let progress_clone = Arc::clone(&progress);
        let shutdown_for_manager = Arc::clone(&shutdown_flag);
        let stats_for_manager = stats.clone();
        let (results_tx, results_rx) = mpsc::channel::<Vec<BuildResult>>();
        let (interrupted_tx, interrupted_rx) = mpsc::channel::<bool>();
        // Channel for completed results to save immediately
        let (completed_tx, completed_rx) = mpsc::channel::<BuildResult>();
        let manager = std::thread::spawn(move || {
            let mut clients = clients.clone();
            let config = config.clone();
            let sandbox = sandbox.clone();
            let mut jobs = jobs.clone();
            let mut was_interrupted = false;
            let stats = stats_for_manager;

            // Track which thread is building which package
            let mut thread_packages: HashMap<usize, PkgName> = HashMap::new();

            loop {
                // Check shutdown flag periodically
                if shutdown_for_manager.load(Ordering::SeqCst) {
                    // Suppress all further output
                    if let Ok(mut p) = progress_clone.lock() {
                        p.state_mut().suppress();
                    }
                    // Send shutdown to all remaining clients
                    for (_, client) in clients.drain() {
                        let _ = client.send(ChannelCommand::Shutdown);
                    }
                    was_interrupted = true;
                    break;
                }

                // Use recv_timeout to check shutdown flag periodically
                let command =
                    match manager_rx.recv_timeout(Duration::from_millis(50)) {
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

                                // Update thread progress
                                thread_packages.insert(c, pkg.clone());
                                if let Ok(mut p) = progress_clone.lock() {
                                    p.clear_output_buffer(c);
                                    p.state_mut()
                                        .set_worker_active(c, pkg.pkgname());
                                    let _ = p.render_throttled();
                                }

                                let _ = client.send(ChannelCommand::JobData(
                                    Box::new(PackageBuild {
                                        id: c,
                                        config: config.clone(),
                                        pkginfo: pkginfo.clone(),
                                        sandbox: sandbox.clone(),
                                    }),
                                ));
                            }
                            BuildStatus::NoneAvailable => {
                                if let Ok(mut p) = progress_clone.lock() {
                                    p.clear_output_buffer(c);
                                    p.state_mut().set_worker_idle(c);
                                    let _ = p.render_throttled();
                                }
                                let _ =
                                    client.send(ChannelCommand::ComeBackLater);
                            }
                            BuildStatus::Done => {
                                if let Ok(mut p) = progress_clone.lock() {
                                    p.clear_output_buffer(c);
                                    p.state_mut().set_worker_idle(c);
                                    let _ = p.render_throttled();
                                }
                                let _ = client.send(ChannelCommand::Quit);
                                clients.remove(&c);
                                if clients.is_empty() {
                                    break;
                                }
                            }
                        };
                    }
                    ChannelCommand::JobSuccess(pkgname, duration) => {
                        // Record stats even if shutting down
                        if let Some(ref s) = stats {
                            let pkgpath = jobs
                                .scanpkgs
                                .get(&pkgname)
                                .and_then(|idx| idx.pkg_location.as_ref())
                                .map(|p| {
                                    p.as_path().to_string_lossy().to_string()
                                });
                            s.build(
                                pkgname.pkgname(),
                                pkgpath.as_deref(),
                                duration,
                                "success",
                            );
                        }

                        jobs.mark_success(&pkgname, duration);
                        jobs.running.remove(&pkgname);

                        // Send result for immediate saving
                        if let Some(result) = jobs.results.last() {
                            let _ = completed_tx.send(result.clone());
                        }

                        // Don't update UI if we're shutting down
                        if shutdown_for_manager.load(Ordering::SeqCst) {
                            continue;
                        }

                        // Find which thread completed and mark idle
                        if let Ok(mut p) = progress_clone.lock() {
                            let _ = p.print_status(&format!(
                                "       Built {} ({})",
                                pkgname.pkgname(),
                                format_duration(duration)
                            ));
                            p.state_mut().increment_completed();
                            for (tid, pkg) in &thread_packages {
                                if pkg == &pkgname {
                                    p.clear_output_buffer(*tid);
                                    p.state_mut().set_worker_idle(*tid);
                                    break;
                                }
                            }
                            let _ = p.render_throttled();
                        }
                    }
                    ChannelCommand::JobSkipped(pkgname) => {
                        // Record stats even if shutting down
                        if let Some(ref s) = stats {
                            let pkgpath = jobs
                                .scanpkgs
                                .get(&pkgname)
                                .and_then(|idx| idx.pkg_location.as_ref())
                                .map(|p| {
                                    p.as_path().to_string_lossy().to_string()
                                });
                            s.build(
                                pkgname.pkgname(),
                                pkgpath.as_deref(),
                                Duration::ZERO,
                                "skipped",
                            );
                        }

                        jobs.mark_up_to_date(&pkgname);
                        jobs.running.remove(&pkgname);

                        // Send result for immediate saving
                        if let Some(result) = jobs.results.last() {
                            let _ = completed_tx.send(result.clone());
                        }

                        // Don't update UI if we're shutting down
                        if shutdown_for_manager.load(Ordering::SeqCst) {
                            continue;
                        }

                        // Find which thread completed and mark idle
                        if let Ok(mut p) = progress_clone.lock() {
                            let _ = p.print_status(&format!(
                                "     Skipped {} (up-to-date)",
                                pkgname.pkgname()
                            ));
                            p.state_mut().increment_skipped();
                            for (tid, pkg) in &thread_packages {
                                if pkg == &pkgname {
                                    p.clear_output_buffer(*tid);
                                    p.state_mut().set_worker_idle(*tid);
                                    break;
                                }
                            }
                            let _ = p.render_throttled();
                        }
                    }
                    ChannelCommand::JobFailed(pkgname, duration) => {
                        // Record stats even if shutting down
                        if let Some(ref s) = stats {
                            let pkgpath = jobs
                                .scanpkgs
                                .get(&pkgname)
                                .and_then(|idx| idx.pkg_location.as_ref())
                                .map(|p| {
                                    p.as_path().to_string_lossy().to_string()
                                });
                            s.build(
                                pkgname.pkgname(),
                                pkgpath.as_deref(),
                                duration,
                                "failed",
                            );
                        }

                        let results_before = jobs.results.len();
                        jobs.mark_failure(&pkgname, duration);
                        jobs.running.remove(&pkgname);

                        // Send all new results for immediate saving
                        for result in jobs.results.iter().skip(results_before) {
                            let _ = completed_tx.send(result.clone());
                        }

                        // Don't update UI if we're shutting down
                        if shutdown_for_manager.load(Ordering::SeqCst) {
                            continue;
                        }

                        // Find which thread failed and mark idle
                        if let Ok(mut p) = progress_clone.lock() {
                            let _ = p.print_status(&format!(
                                "      Failed {} ({})",
                                pkgname.pkgname(),
                                format_duration(duration)
                            ));
                            p.state_mut().increment_failed();
                            for (tid, pkg) in &thread_packages {
                                if pkg == &pkgname {
                                    p.clear_output_buffer(*tid);
                                    p.state_mut().set_worker_idle(*tid);
                                    break;
                                }
                            }
                            let _ = p.render_throttled();
                        }
                    }
                    ChannelCommand::JobError((pkgname, duration, e)) => {
                        // Record stats even if shutting down
                        if let Some(ref s) = stats {
                            let pkgpath = jobs
                                .scanpkgs
                                .get(&pkgname)
                                .and_then(|idx| idx.pkg_location.as_ref())
                                .map(|p| {
                                    p.as_path().to_string_lossy().to_string()
                                });
                            s.build(
                                pkgname.pkgname(),
                                pkgpath.as_deref(),
                                duration,
                                "error",
                            );
                        }

                        let results_before = jobs.results.len();
                        jobs.mark_failure(&pkgname, duration);
                        jobs.running.remove(&pkgname);

                        // Send all new results for immediate saving
                        for result in jobs.results.iter().skip(results_before) {
                            let _ = completed_tx.send(result.clone());
                        }

                        // Don't update UI if we're shutting down
                        if shutdown_for_manager.load(Ordering::SeqCst) {
                            tracing::error!(error = %e, pkgname = %pkgname.pkgname(), "Build error");
                            continue;
                        }

                        // Find which thread errored and mark idle
                        if let Ok(mut p) = progress_clone.lock() {
                            let _ = p.print_status(&format!(
                                "      Failed {} ({})",
                                pkgname.pkgname(),
                                format_duration(duration)
                            ));
                            p.state_mut().increment_failed();
                            for (tid, pkg) in &thread_packages {
                                if pkg == &pkgname {
                                    p.clear_output_buffer(*tid);
                                    p.state_mut().set_worker_idle(*tid);
                                    break;
                                }
                            }
                            let _ = p.render_throttled();
                        }
                        tracing::error!(error = %e, pkgname = %pkgname.pkgname(), "Build error");
                    }
                    ChannelCommand::StageUpdate(tid, stage) => {
                        if let Ok(mut p) = progress_clone.lock() {
                            p.state_mut()
                                .set_worker_stage(tid, stage.as_deref());
                            let _ = p.render_throttled();
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
                    _ => {}
                }
            }

            // Send results and interrupted status back
            debug!(
                result_count = jobs.results.len(),
                "Manager sending results back"
            );
            let _ = results_tx.send(jobs.results);
            let _ = interrupted_tx.send(was_interrupted);
        });

        threads.push(manager);
        debug!("Waiting for worker threads to complete");
        let join_start = Instant::now();
        for thread in threads {
            thread.join().expect("thread panicked");
        }
        debug!(
            elapsed_ms = join_start.elapsed().as_millis(),
            "Worker threads completed"
        );

        // Save all completed results to database immediately
        let mut saved_count = 0;
        while let Ok(result) = completed_rx.try_recv() {
            if let Err(e) = db.store_build_by_name(&result) {
                warn!(
                    pkgname = %result.pkgname.pkgname(),
                    error = %e,
                    "Failed to save build result"
                );
            } else {
                saved_count += 1;
            }
        }
        if saved_count > 0 {
            debug!(saved_count, "Saved build results to database");
        }

        // Stop the refresh thread
        stop_refresh.store(true, Ordering::Relaxed);
        let _ = refresh_thread.join();

        // Check if we were interrupted
        let was_interrupted = interrupted_rx.recv().unwrap_or(false);

        // Print appropriate summary
        if let Ok(mut p) = progress.lock() {
            if was_interrupted {
                let _ = p.finish_interrupted();
            } else {
                let _ = p.finish();
            }
        }

        // Collect results from manager
        debug!("Collecting results from manager");
        let results = results_rx.recv().unwrap_or_default();
        debug!(result_count = results.len(), "Collected results from manager");
        let summary = BuildSummary {
            duration: started.elapsed(),
            results,
            scan_failed: Vec::new(),
        };

        if self.sandbox.enabled() {
            debug!("Destroying sandboxes");
            let destroy_start = Instant::now();
            self.sandbox.destroy_all(self.config.build_threads())?;
            debug!(
                elapsed_ms = destroy_start.elapsed().as_millis(),
                "Sandboxes destroyed"
            );
        }

        Ok(summary)
    }
}
