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

//! Sandbox creation and management.
//!
//! This module provides the [`Sandbox`] struct for creating isolated build
//! environments using chroot. The implementation varies by platform but
//! presents a uniform interface.
//!
//! # Platform Support
//!
//! | Platform | Implementation |
//! |----------|---------------|
//! | Linux | Mount namespaces + chroot |
//! | macOS | bindfs/devfs + chroot |
//! | NetBSD | Native mounts + chroot |
//! | illumos/Solaris | Platform mounts + chroot |
//!
//! # Sandbox Lifecycle
//!
//! 1. **Create**: Set up the sandbox directory and perform configured actions
//! 2. **Execute**: Run build scripts inside the sandbox via chroot
//! 3. **Destroy**: Reverse actions and clean up the sandbox directory
//!
//! # Configuration
//!
//! Sandboxes are configured in the `sandboxes` section of the Lua config file.
//! See the [`action`](crate::action) module for available actions.
//!
//! ```lua
//! sandboxes = {
//!     basedir = "/data/chroot",
//!     actions = {
//!         { action = "mount", fs = "proc", dir = "/proc" },
//!         { action = "mount", fs = "dev", dir = "/dev" },
//!         { action = "mount", fs = "bind", dir = "/usr/bin", opts = "ro" },
//!         { action = "copy", dir = "/etc" },
//!     },
//! }
//! ```
//!
//! # Multiple Sandboxes
//!
//! Multiple sandboxes can be created for parallel builds. Each sandbox is
//! identified by an integer ID (0, 1, 2, ...) and created as a subdirectory
//! of `basedir`.
//!
//! With `build_threads = 4`, sandboxes are created at:
//! - `/data/chroot/0`
//! - `/data/chroot/1`
//! - `/data/chroot/2`
//! - `/data/chroot/3`
#[cfg(target_os = "linux")]
mod sandbox_linux;
#[cfg(target_os = "macos")]
mod sandbox_macos;
#[cfg(target_os = "netbsd")]
mod sandbox_netbsd;
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
mod sandbox_sunos;

use crate::action::{ActionType, FSType};
use crate::config::Config;
use crate::{Interrupted, RunContext};
use anyhow::{Result, bail};
use rayon::prelude::*;
use std::fs;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};
use tracing::{debug, info, info_span, warn};

/// How often to check the shutdown flag while waiting for something else.
/// This determines the maximum latency between Ctrl+C and response.
/// 100ms provides responsive feel without excessive polling overhead.
pub(crate) const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Maximum number of retries when killing processes in a sandbox.
/// Uses exponential backoff: 64ms, 128ms, 256ms, 512ms, 1024ms = ~2s total.
pub(crate) const KILL_PROCESSES_MAX_RETRIES: u32 = 5;
pub(crate) const KILL_PROCESSES_INITIAL_DELAY_MS: u64 = 64;

/*
 * Poll for child process exit while checking a shutdown flag.  If shutdown
 * is requested, kill the child and return an error.
 */
pub fn wait_with_shutdown(
    child: &mut Child,
    shutdown: &AtomicBool,
) -> Result<ExitStatus> {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Interrupted by shutdown");
        }
        match child.try_wait()? {
            Some(status) => return Ok(status),
            None => std::thread::sleep(SHUTDOWN_POLL_INTERVAL),
        }
    }
}

/*
 * Wait for child process exit while checking a shutdown flag, returning
 * the full output (stdout/stderr).  If shutdown is requested, kill the
 * child and return an error.
 *
 * Uses a single helper thread that calls wait_with_output() (which handles
 * pipe draining correctly via internal threads).  The main thread polls a
 * channel for results while checking the shutdown flag.  This avoids the
 * polling latency of try_wait() while still allowing shutdown interruption.
 */
pub fn wait_output_with_shutdown(
    child: Child,
    shutdown: &AtomicBool,
) -> Result<Output> {
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });

    loop {
        if shutdown.load(Ordering::SeqCst) {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
            let _ = rx.recv();
            bail!("Interrupted by shutdown");
        }
        match rx.recv_timeout(SHUTDOWN_POLL_INTERVAL) {
            Ok(result) => return result.map_err(Into::into),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                bail!("wait thread disconnected unexpectedly");
            }
        }
    }
}

/// Build sandbox manager.
#[derive(Clone, Debug, Default)]
pub struct Sandbox {
    config: Config,
}

impl Sandbox {
    /**
     * Create a new [`Sandbox`] instance.  This is used even if sandboxes have
     * not been enabled, as it provides a consistent interface to run commands
     * through using [`execute`].  If sandboxes are enabled then commands are
     * executed via `chroot(8)`, otherwise they are executed directly.
     *
     * [`execute`]: Sandbox::execute
     */
    pub fn new(config: &Config) -> Sandbox {
        Sandbox { config: config.clone() }
    }

    /// Return whether sandboxes have been enabled.
    ///
    /// This is based on whether a valid `sandboxes` section has been
    /// specified in the config file.
    pub fn enabled(&self) -> bool {
        self.config.sandboxes().is_some()
    }

    fn basedir(&self) -> Option<&PathBuf> {
        self.config.sandboxes().as_ref().map(|s| &s.basedir)
    }

    /**
     * Return full path to a sandbox by id.
     */
    pub fn path(&self, id: usize) -> PathBuf {
        let sandbox = &self.config.sandboxes().as_ref().unwrap();
        let mut p = PathBuf::from(&sandbox.basedir);
        p.push(id.to_string());
        p
    }

    /**
     * Create a Command that runs in the sandbox (via chroot) if enabled,
     * or directly if sandboxes are disabled.
     */
    pub fn command(&self, id: usize, cmd: &Path) -> Command {
        if self.enabled() {
            let mut c = Command::new("/usr/sbin/chroot");
            c.arg(self.path(id)).arg(cmd);
            c
        } else {
            Command::new(cmd)
        }
    }

    /**
     * Kill all processes in a sandbox by id.
     * This is used for graceful shutdown on Ctrl+C.
     */
    pub fn kill_processes_by_id(&self, id: usize) {
        if !self.enabled() {
            return;
        }
        let sandbox = self.path(id);
        if sandbox.exists() {
            let span = info_span!("kill_processes", sandbox_id = id);
            let _guard = span.enter();
            self.kill_processes(&sandbox);
        }
    }

    /**
     * Return full path to a specified mount point in a sandbox.
     * The returned path is guaranteed to be within the sandbox directory.
     */
    fn mountpath(&self, id: usize, mnt: &PathBuf) -> PathBuf {
        /*
         * Note that .push() on a PathBuf will replace the path if
         * it is absolute, so we need to trim any leading "/".
         */
        let mut p = self.path(id);
        match mnt.strip_prefix("/") {
            Ok(s) => p.push(s),
            Err(_) => p.push(mnt),
        };
        p
    }

    /**
     * Verify that a path is safely contained within the sandbox.
     * This prevents path traversal attacks via ".." or symlinks.
     * Returns error if the path escapes the sandbox boundary.
     */
    fn verify_path_in_sandbox(&self, id: usize, path: &Path) -> Result<()> {
        let sandbox_root = self.path(id);
        // Canonicalize both paths to resolve any ".." or symlinks
        // Note: canonicalize requires the path to exist, so we check
        // the parent directory for paths that don't exist yet
        let canonical_sandbox =
            sandbox_root.canonicalize().unwrap_or(sandbox_root.clone());

        // For the target path, try to canonicalize what exists
        let canonical_path = if path.exists() {
            path.canonicalize()?
        } else {
            // Path doesn't exist yet, check its parent
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    let canonical_parent = parent.canonicalize()?;
                    if !canonical_parent.starts_with(&canonical_sandbox) {
                        bail!(
                            "Path escapes sandbox: {} is not within {}",
                            path.display(),
                            sandbox_root.display()
                        );
                    }
                }
            }
            return Ok(());
        };

        if !canonical_path.starts_with(&canonical_sandbox) {
            bail!(
                "Path escapes sandbox: {} resolves to {} which is not within {}",
                path.display(),
                canonical_path.display(),
                canonical_sandbox.display()
            );
        }
        Ok(())
    }

    /*
     * Marker directory functions for sandbox lifecycle management.
     *
     * Each sandbox has a .bob directory that marks it as bob-managed.
     * Inside .bob, a "created" directory indicates successful creation.
     * This two-stage marker allows detecting incomplete sandboxes.
     */
    fn bobmarker(&self, id: usize) -> PathBuf {
        self.path(id).join(".bob")
    }

    fn lockpath(&self, id: usize) -> PathBuf {
        self.bobmarker(id).join("created")
    }

    fn create_marker(&self, id: usize) -> Result<()> {
        Ok(fs::create_dir(self.bobmarker(id))?)
    }

    fn create_lock(&self, id: usize) -> Result<()> {
        Ok(fs::create_dir(self.lockpath(id))?)
    }

    fn delete_lock(&self, id: usize) -> Result<()> {
        let lockdir = self.lockpath(id);
        if lockdir.exists() {
            fs::remove_dir(&lockdir)?;
        }
        let bobmarker = self.bobmarker(id);
        if bobmarker.exists() {
            fs::remove_dir(&bobmarker)?;
        }
        Ok(())
    }

    fn is_bob_sandbox(&self, id: usize) -> bool {
        self.bobmarker(id).exists()
    }

    fn is_sandbox_complete(&self, id: usize) -> bool {
        self.lockpath(id).exists()
    }

    /**
     * Discover all bob-managed sandboxes by scanning basedir.
     * Returns sorted list of sandbox IDs.
     */
    fn discover_sandboxes(&self) -> Result<Vec<usize>> {
        let Some(basedir) = self.basedir() else {
            return Ok(vec![]);
        };
        if !basedir.exists() {
            return Ok(vec![]);
        }
        let mut ids = Vec::new();
        for entry in fs::read_dir(basedir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Ok(id) = name.parse::<usize>() else {
                continue;
            };
            if self.is_bob_sandbox(id) {
                ids.push(id);
            }
        }
        ids.sort();
        Ok(ids)
    }

    /**
     * Create a single sandbox by id.
     * If the sandbox already exists and is valid (has lock), this is a no-op.
     */
    pub fn create(&self, id: usize) -> Result<()> {
        let sandbox = self.path(id);
        if sandbox.exists() {
            if self.is_sandbox_complete(id) {
                return Ok(());
            }
            bail!(
                "Sandbox exists but is incomplete: {}.\n\
                 Run 'bob util sandbox destroy' first.",
                sandbox.display()
            );
        }
        fs::create_dir_all(&sandbox)?;
        self.create_marker(id)?;
        self.perform_actions(id)?;
        self.create_lock(id)?;
        Ok(())
    }

    /**
     * Execute a script file with supplied environment variables and optional
     * stdin data.
     *
     * If protected is true, the process is placed in its own process group
     * to isolate it from terminal signals (Ctrl+C). Use this for cleanup
     * scripts that must complete even during shutdown.
     */
    pub fn execute(
        &self,
        id: usize,
        script: &Path,
        envs: Vec<(String, String)>,
        stdin_data: Option<&str>,
        protected: bool,
    ) -> Result<Child> {
        use std::io::Write;

        let mut cmd = self.command(id, script);
        cmd.current_dir("/");

        for (key, val) in envs {
            cmd.env(key, val);
        }

        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        }

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        if protected {
            cmd.process_group(0);
        }

        let mut child = cmd.spawn()?;

        if let Some(data) = stdin_data {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(data.as_bytes())?;
            }
        }

        Ok(child)
    }

    /**
     * Execute inline script content via /bin/sh.
     */
    pub fn execute_script(
        &self,
        id: usize,
        content: &str,
        envs: Vec<(String, String)>,
    ) -> Result<Child> {
        use std::io::Write;

        let mut cmd = self.command(id, Path::new("/bin/sh"));
        cmd.current_dir("/").arg("-s");

        for (key, val) in envs {
            cmd.env(key, val);
        }

        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(content.as_bytes())?;
        }

        Ok(child)
    }

    /**
     * Execute a command directly without shell interpretation.
     */
    pub fn execute_command<I, S>(
        &self,
        id: usize,
        cmd: &Path,
        args: I,
        envs: Vec<(String, String)>,
    ) -> Result<Child>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let mut command = self.command(id, cmd);
        command.args(args);
        for (key, val) in envs {
            command.env(key, val);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(Into::into)
    }

    /**
     * Run the pre-build script if configured.
     * Returns Ok(true) if script ran successfully or wasn't configured,
     * Ok(false) if script failed.
     */
    pub fn run_pre_build(
        &self,
        id: usize,
        config: &Config,
        envs: Vec<(String, String)>,
    ) -> Result<bool> {
        if let Some(script) = config.script("pre-build") {
            info!(script = %script.display(), "Running pre-build script");
            let child = self.execute(id, script, envs, None, false)?;
            let output = child.wait_with_output()?;
            if output.status.success() {
                info!(script = %script.display(), result = "success", "Finished running pre-build script");
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                warn!(
                    script = %script.display(),
                    result = "failed",
                    stdout = %stdout.trim(),
                    stderr = %stderr.trim(),
                    "Finished running pre-build script"
                );
                return Ok(false);
            }
        }
        Ok(true)
    }

    /**
     * Run the post-build script if configured.
     * Returns Ok(true) if script ran successfully or wasn't configured,
     * Ok(false) if script failed.
     *
     * Post-build scripts run with signal protection (process_group(0)) to
     * ensure cleanup completes even during shutdown from Ctrl+C.
     */
    pub fn run_post_build(
        &self,
        id: usize,
        config: &Config,
        envs: Vec<(String, String)>,
    ) -> Result<bool> {
        if let Some(script) = config.script("post-build") {
            info!(script = %script.display(), "Running post-build script");
            // Use protected=true to ensure cleanup completes during shutdown
            let child = self.execute(id, script, envs, None, true)?;
            let output = child.wait_with_output()?;
            if output.status.success() {
                info!(script = %script.display(), result = "success", "Finished running post-build script");
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                warn!(
                    script = %script.display(),
                    result = "failed",
                    stdout = %stdout.trim(),
                    stderr = %stderr.trim(),
                    "Finished running post-build script"
                );
                return Ok(false);
            }
        }
        Ok(true)
    }

    /**
     * Destroy a single sandbox by id.
     */
    pub fn destroy(&self, id: usize) -> anyhow::Result<()> {
        let sandbox = self.path(id);
        if !sandbox.exists() {
            return Ok(());
        }
        self.delete_lock(id)?;
        self.reverse_actions(id)?;
        /*
         * Final cleanup: kill any remaining processes before removing the
         * sandbox directory.  Per-mount killing already happened in
         * reverse_actions(), but this catches anything that slipped through.
         */
        self.kill_processes(&sandbox);
        /*
         * After unmounting, try to remove the sandbox directory.  Use
         * remove_empty_hierarchy which only removes empty directories.
         * If any files remain, it will fail - this is intentional as it
         * likely means a mount is still active or cleanup actions are
         * missing from the config.
         */
        if sandbox.exists() {
            self.remove_empty_hierarchy(&sandbox)?;
        }
        Ok(())
    }

    /**
     * Create all sandboxes in parallel, rolling back on failure.
     */
    pub fn create_all(&self, count: usize) -> Result<()> {
        if count == 1 {
            print!("Creating sandbox...");
        } else {
            print!("Creating {} sandboxes...", count);
        }
        let _ = std::io::stdout().flush();
        let start = Instant::now();
        let results: Vec<(usize, Result<()>)> =
            (0..count).into_par_iter().map(|i| (i, self.create(i))).collect();
        let mut first_error: Option<anyhow::Error> = None;
        for (i, result) in &results {
            if let Err(e) = result {
                if first_error.is_none() {
                    first_error = Some(anyhow::anyhow!("sandbox {}: {}", i, e));
                }
            }
        }
        if let Some(e) = first_error {
            println!();
            for (i, _) in &results {
                if let Err(destroy_err) = self.destroy(*i) {
                    eprintln!(
                        "Warning: failed to destroy sandbox {}: {}",
                        i, destroy_err
                    );
                }
            }
            return Err(e);
        }
        println!(" done ({:.1}s)", start.elapsed().as_secs_f32());
        Ok(())
    }

    /**
     * Destroy all discovered sandboxes in parallel.  Runs post-build cleanup
     * on each sandbox first, then destroys them.  Continue on errors to ensure
     * all sandboxes are attempted, printing each error as it occurs.
     */
    pub fn destroy_all(&self) -> Result<()> {
        let sandboxes = self.discover_sandboxes()?;
        if sandboxes.is_empty() {
            return Ok(());
        }
        let envs = self.config.script_env(None);
        for &id in &sandboxes {
            if self.path(id).exists() {
                match self.run_post_build(id, &self.config, envs.clone()) {
                    Ok(true) => {}
                    Ok(false) => {
                        warn!("post-build script failed for sandbox {}", id)
                    }
                    Err(e) => {
                        warn!(error = %e, sandbox = id, "post-build script error")
                    }
                }
            }
        }
        if sandboxes.len() == 1 {
            print!("Destroying sandbox...");
        } else {
            print!("Destroying {} sandboxes...", sandboxes.len());
        }
        let _ = std::io::stdout().flush();
        let start = Instant::now();
        let results: Vec<(usize, Result<()>)> =
            sandboxes.into_par_iter().map(|i| (i, self.destroy(i))).collect();
        let mut failed = 0;
        for (i, result) in results {
            if let Err(e) = result {
                if failed == 0 {
                    println!();
                }
                eprintln!("sandbox {}: {}", i, e);
                failed += 1;
            }
        }
        if failed == 0 {
            println!(" done ({:.1}s)", start.elapsed().as_secs_f32());
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to destroy {} sandbox{}.\n\
                 Remove unexpected files, then run 'bob util sandbox destroy'.",
                failed,
                if failed == 1 { "" } else { "es" }
            ))
        }
    }

    /**
     * List all discovered sandboxes.
     */
    pub fn list_all(&self) -> Result<()> {
        for id in self.discover_sandboxes()? {
            let sandbox = self.path(id);
            if self.is_sandbox_complete(id) {
                println!("{}", sandbox.display())
            } else {
                println!("{} (incomplete)", sandbox.display())
            }
        }
        Ok(())
    }

    /**
     * Count discovered sandboxes (complete or incomplete).
     */
    pub fn count_existing(&self) -> Result<usize> {
        Ok(self.discover_sandboxes()?.len())
    }

    /*
     * Remove any empty directories from a mount point up to the root of the
     * sandbox.
     */
    fn remove_empty_dirs(&self, id: usize, mountpoint: &Path) {
        for p in mountpoint.ancestors() {
            /*
             * Sanity check we are within the chroot.
             */
            if !p.starts_with(self.path(id)) {
                break;
            }
            /*
             * Go up to next parent if this path does not exist.
             */
            if !p.exists() {
                continue;
            }
            /*
             * Otherwise attempt to remove.  If this fails then skip any
             * parent directories.
             */
            if fs::remove_dir(p).is_err() {
                break;
            }
        }
    }

    /// Remove a directory hierarchy only if it contains nothing but empty
    /// directories and symlinks. Walks depth-first. Removes symlinks and
    /// empty directories. Fails if any regular files, device nodes, pipes,
    /// sockets, or other non-removable entries are encountered.
    #[allow(clippy::only_used_in_recursion)]
    fn remove_empty_hierarchy(&self, path: &Path) -> Result<()> {
        // Use symlink_metadata to not follow symlinks
        let meta = fs::symlink_metadata(path)?;

        if meta.is_symlink() {
            // Symlinks can be removed
            fs::remove_file(path).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to remove symlink {}: {}",
                    path.display(),
                    e
                )
            })?;
            return Ok(());
        }

        if !meta.is_dir() {
            // Regular file, device node, pipe, socket, etc. - fail
            bail!(
                "Cannot remove sandbox: non-directory exists at {}",
                path.display()
            );
        }

        // It's a directory - process contents first (depth-first)
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            self.remove_empty_hierarchy(&entry.path())?;
        }

        // Directory should now be empty, remove it
        fs::remove_dir(path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to remove directory {}: {}. Directory may not be empty.",
                path.display(),
                e
            )
        })
    }

    ///
    /// Iterate over the supplied array of actions in order.  If at any
    /// point a problem is encountered we immediately bail.
    ///
    fn perform_actions(&self, id: usize) -> Result<()> {
        let Some(sandbox) = &self.config.sandboxes() else {
            bail!(
                "Internal error: trying to perform actions when sandboxes disabled."
            );
        };
        for action in sandbox.actions.iter() {
            action.validate()?;
            let action_type = action.action_type()?;

            // For mount/copy actions, dest defaults to src (src is more readable)
            let src = action.src().or(action.dest());
            let dest =
                action.dest().or(action.src()).map(|d| self.mountpath(id, d));
            if let Some(ref dest_path) = dest {
                self.verify_path_in_sandbox(id, dest_path)?;
            }

            let mut opts = vec![];
            if let Some(o) = action.opts() {
                for opt in o.split(' ').collect::<Vec<&str>>() {
                    opts.push(opt);
                }
            }

            let status = match action_type {
                ActionType::Mount => {
                    let fs_type = action.fs_type()?;
                    let src = src.ok_or_else(|| {
                        anyhow::anyhow!("mount action requires src or dest")
                    })?;
                    let dest = dest.ok_or_else(|| {
                        anyhow::anyhow!("mount action requires dest")
                    })?;
                    if action.ifexists() && !src.exists() {
                        debug!(
                            sandbox = id,
                            action = "mount",
                            fs = ?fs_type,
                            src = %src.display(),
                            "Skipped (source does not exist)"
                        );
                        continue;
                    }
                    debug!(
                        sandbox = id,
                        action = "mount",
                        fs = ?fs_type,
                        src = %src.display(),
                        dest = %dest.display(),
                        "Mounting"
                    );
                    match fs_type {
                        FSType::Bind => self.mount_bindfs(src, &dest, &opts)?,
                        FSType::Dev => self.mount_devfs(src, &dest, &opts)?,
                        FSType::Fd => self.mount_fdfs(src, &dest, &opts)?,
                        FSType::Nfs => self.mount_nfs(src, &dest, &opts)?,
                        FSType::Proc => self.mount_procfs(src, &dest, &opts)?,
                        FSType::Tmp => self.mount_tmpfs(src, &dest, &opts)?,
                    }
                }
                ActionType::Copy => {
                    let src = src.ok_or_else(|| {
                        anyhow::anyhow!("copy action requires src or dest")
                    })?;
                    let dest = dest.ok_or_else(|| {
                        anyhow::anyhow!("copy action requires dest")
                    })?;
                    debug!(
                        sandbox = id,
                        action = "copy",
                        src = %src.display(),
                        dest = %dest.display(),
                        "Copying"
                    );
                    copy_dir::copy_dir(src, &dest)?;
                    None
                }
                ActionType::Cmd => {
                    if let Some(create_cmd) = action.create_cmd() {
                        debug!(
                            sandbox = id,
                            action = "cmd",
                            cmd = create_cmd,
                            chroot = action.chroot(),
                            "Running create command"
                        );
                        self.run_action_cmd(id, create_cmd, action.chroot())?
                    } else {
                        None
                    }
                }
                ActionType::Symlink => {
                    let src = action.src().ok_or_else(|| {
                        anyhow::anyhow!("symlink action requires src")
                    })?;
                    let dest = action.dest().ok_or_else(|| {
                        anyhow::anyhow!("symlink action requires dest")
                    })?;
                    let dest_path = self.mountpath(id, dest);
                    debug!(
                        sandbox = id,
                        action = "symlink",
                        src = %src.display(),
                        dest = %dest_path.display(),
                        "Creating symlink"
                    );
                    if let Some(parent) = dest_path.parent() {
                        if !parent.exists() {
                            fs::create_dir_all(parent)?;
                        }
                    }
                    std::os::unix::fs::symlink(src, &dest_path)?;
                    None
                }
            };
            if let Some(s) = status {
                if !s.success() {
                    bail!("Sandbox action failed");
                }
            }
        }
        Ok(())
    }

    /**
     * Run a custom action command.
     *
     * When `chroot` is false (default), the command runs on the host system
     * with the sandbox root as the working directory.
     *
     * When `chroot` is true, the command runs inside the sandbox via chroot
     * with `/` as the working directory.
     *
     * Stdio is captured to prevent commands like `su` from trying to interact
     * with the terminal. Output is logged on failure.
     */
    fn run_action_cmd(
        &self,
        id: usize,
        cmd: &str,
        chroot: bool,
    ) -> Result<Option<std::process::ExitStatus>> {
        let sandbox_path = self.path(id);
        let output = if chroot {
            Command::new("/usr/sbin/chroot")
                .arg(&sandbox_path)
                .arg("/bin/sh")
                .arg("-c")
                .arg(cmd)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .output()?
        } else {
            Command::new("/bin/sh")
                .arg("-c")
                .arg(cmd)
                .env("bob_sandbox_path", &sandbox_path)
                .current_dir(&sandbox_path)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .output()?
        };

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stdout.is_empty() {
                warn!(cmd, stdout = %stdout.trim(), "Action command output");
            }
            if !stderr.is_empty() {
                warn!(cmd, stderr = %stderr.trim(), "Action command error");
            }
        }

        Ok(Some(output.status))
    }

    fn reverse_actions(&self, id: usize) -> anyhow::Result<()> {
        let Some(sandbox) = &self.config.sandboxes() else {
            bail!(
                "Internal error: trying to reverse actions when sandboxes disabled."
            );
        };
        for action in sandbox.actions.iter().rev() {
            let action_type = action.action_type()?;
            // dest defaults to src if not specified
            let dest =
                action.dest().or(action.src()).map(|d| self.mountpath(id, d));

            match action_type {
                ActionType::Cmd => {
                    if let Some(destroy_cmd) = action.destroy_cmd() {
                        debug!(
                            sandbox = id,
                            action = "cmd",
                            cmd = destroy_cmd,
                            chroot = action.chroot(),
                            "Running destroy command"
                        );
                        let status = self.run_action_cmd(
                            id,
                            destroy_cmd,
                            action.chroot(),
                        )?;
                        if let Some(s) = status {
                            if !s.success() {
                                bail!(
                                    "Failed to run destroy command: exit code {:?}",
                                    s.code()
                                );
                            }
                        }
                    }
                }
                ActionType::Copy => {
                    let Some(mntdest) = dest else { continue };
                    if !mntdest.exists() {
                        self.remove_empty_dirs(id, &mntdest);
                        continue;
                    }
                    if fs::remove_dir(&mntdest).is_ok() {
                        continue;
                    }
                    /*
                     * Use remove_dir_recursive which fails if non-empty
                     * directories remain, rather than blindly deleting.
                     * First verify the path is within the sandbox.
                     */
                    debug!(
                        sandbox = id,
                        action = "copy",
                        dest = %mntdest.display(),
                        "Removing copied directory"
                    );
                    self.verify_path_in_sandbox(id, &mntdest)?;
                    self.remove_dir_recursive(&mntdest)?;
                    self.remove_empty_dirs(id, &mntdest);
                }
                ActionType::Symlink => {
                    let Some(mntdest) = dest else { continue };
                    if mntdest.is_symlink() {
                        debug!(
                            sandbox = id,
                            action = "symlink",
                            dest = %mntdest.display(),
                            "Removing symlink"
                        );
                        fs::remove_file(&mntdest)?;
                    }
                    self.remove_empty_dirs(id, &mntdest);
                }
                ActionType::Mount => {
                    let Some(mntdest) = dest else { continue };
                    let fs_type = action.fs_type()?;

                    let src = action.src().or(action.dest());
                    if let Some(src) = src {
                        if action.ifexists() && !src.exists() {
                            continue;
                        }
                    }

                    /*
                     * If the mount point itself does not exist then do not try to
                     * unmount it, but do try to clean up any empty parent
                     * directories up to the root.
                     */
                    if !mntdest.exists() {
                        self.remove_empty_dirs(id, &mntdest);
                        continue;
                    }

                    /*
                     * Before trying to unmount, try just removing the directory,
                     * in case it was never mounted in the first place.  Avoids
                     * errors trying to unmount a file system that isn't mounted.
                     */
                    if fs::remove_dir(&mntdest).is_ok() {
                        continue;
                    }

                    /*
                     * Kill any processes using this mount point before
                     * attempting to unmount.
                     */
                    self.kill_processes_for_path(&mntdest);

                    /*
                     * Unmount the filesystem.  Check return codes and bail on
                     * failure - it is critical that all mounts are successfully
                     * unmounted before we attempt to remove the sandbox directory.
                     */
                    debug!(
                        sandbox = id,
                        action = "mount",
                        fs = ?fs_type,
                        dest = %mntdest.display(),
                        "Unmounting"
                    );
                    let status = match fs_type {
                        FSType::Bind => self.unmount_bindfs(&mntdest)?,
                        FSType::Dev => self.unmount_devfs(&mntdest)?,
                        FSType::Fd => self.unmount_fdfs(&mntdest)?,
                        FSType::Nfs => self.unmount_nfs(&mntdest)?,
                        FSType::Proc => self.unmount_procfs(&mntdest)?,
                        FSType::Tmp => self.unmount_tmpfs(&mntdest)?,
                    };
                    if let Some(s) = status {
                        if !s.success() {
                            bail!("Failed to unmount {}", mntdest.display());
                        }
                    }
                    self.remove_empty_dirs(id, &mntdest);
                }
            }
        }
        Ok(())
    }

    /**
     * Recursively remove a directory by walking it depth-first and removing
     * files and empty directories.  Unlike remove_dir_all, this will fail
     * if it encounters a non-empty directory that cannot be removed, which
     * would indicate an active mount point.
     *
     * IMPORTANT: This function explicitly does NOT follow symlinks to avoid
     * deleting files outside the sandbox via symlink attacks.
     */
    #[allow(clippy::only_used_in_recursion)]
    fn remove_dir_recursive(&self, path: &Path) -> Result<()> {
        // Use symlink_metadata to check type WITHOUT following symlinks
        let meta = fs::symlink_metadata(path)?;
        if meta.is_symlink() {
            // Remove the symlink itself, don't follow it
            fs::remove_file(path)?;
            return Ok(());
        }
        if !meta.is_dir() {
            fs::remove_file(path)?;
            return Ok(());
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            // Use file_type() from DirEntry which doesn't follow symlinks
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                // Remove symlink itself, don't follow
                fs::remove_file(&entry_path)?;
            } else if file_type.is_dir() {
                self.remove_dir_recursive(&entry_path)?;
            } else {
                fs::remove_file(&entry_path)?;
            }
        }
        fs::remove_dir(path)?;
        Ok(())
    }
}

/**
 * RAII scope for sandbox lifecycle management.
 *
 * Creates sandboxes on demand via `ensure()`, destroys them on drop.
 * This ensures sandboxes are always cleaned up, even on error paths.
 * If sandboxes are disabled, all operations are no-ops.
 */
#[derive(Debug)]
pub struct SandboxScope {
    sandbox: Sandbox,
    count: usize,
    ctx: RunContext,
}

impl SandboxScope {
    /**
     * Create a new scope with no sandboxes.
     *
     * Use `ensure()` to create sandboxes when needed.
     */
    pub fn new(sandbox: Sandbox, ctx: RunContext) -> Self {
        Self { sandbox, count: 0, ctx }
    }

    /**
     * Ensure sandboxes 0..n exist.
     *
     * Creates any missing sandboxes in parallel. If sandboxes are disabled
     * or n <= current count, this is a no-op.
     *
     * On error or interrupt, newly created sandboxes are rolled back but
     * previously existing sandboxes remain (they'll be cleaned up on drop).
     */
    pub fn ensure(&mut self, n: usize) -> Result<()> {
        if !self.sandbox.enabled() || n <= self.count {
            return Ok(());
        }
        let to_create = n - self.count;
        if to_create == 1 {
            print!("Creating sandbox...");
        } else {
            print!("Creating {} sandboxes...", to_create);
        }
        let _ = std::io::stdout().flush();
        let start = Instant::now();
        let results: Vec<(usize, Result<()>)> = (self.count..n)
            .into_par_iter()
            .map(|i| (i, self.sandbox.create(i)))
            .collect();

        // Check for interrupt - roll back newly created sandboxes
        if self.ctx.shutdown.load(Ordering::SeqCst) {
            for (i, result) in &results {
                if result.is_ok() {
                    let _ = self.sandbox.destroy(*i);
                }
            }
            return Err(Interrupted.into());
        }

        let mut first_error: Option<anyhow::Error> = None;
        for (i, result) in &results {
            if let Err(e) = result {
                if first_error.is_none() {
                    first_error = Some(anyhow::anyhow!("sandbox {}: {}", i, e));
                }
            }
        }
        if let Some(e) = first_error {
            println!();
            for (i, _) in &results {
                if let Err(destroy_err) = self.sandbox.destroy(*i) {
                    eprintln!(
                        "Warning: failed to destroy sandbox {}: {}",
                        i, destroy_err
                    );
                }
            }
            return Err(e);
        }
        println!(" done ({:.1}s)", start.elapsed().as_secs_f32());
        self.count = n;
        Ok(())
    }

    /// Access the underlying sandbox for operations.
    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    /// Return whether sandboxes are enabled.
    pub fn enabled(&self) -> bool {
        self.sandbox.enabled()
    }

    /// Access the shutdown flag.
    pub fn shutdown(&self) -> &Arc<AtomicBool> {
        &self.ctx.shutdown
    }
}

impl Drop for SandboxScope {
    fn drop(&mut self) {
        if self.sandbox.enabled() && self.count > 0 {
            if let Err(e) = self.sandbox.destroy_all() {
                eprintln!("Warning: failed to destroy sandboxes: {}", e);
            }
        }
    }
}
