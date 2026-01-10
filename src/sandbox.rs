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
//!     basedir = "/data/chroot/bob",
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
//! - `/data/chroot/bob/0`
//! - `/data/chroot/bob/1`
//! - `/data/chroot/bob/2`
//! - `/data/chroot/bob/3`
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
use anyhow::{Result, bail};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

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
     * Functions to create/destroy lock directory inside a sandbox to
     * indicate that it has successfully been created.  An empty directory
     * is used as it provides a handy way to guarantee(?) atomicity.
     */
    fn lockpath(&self, id: usize) -> PathBuf {
        let mut p = self.path(id);
        p.push(".created");
        p
    }
    fn create_lock(&self, id: usize) -> Result<()> {
        Ok(fs::create_dir(self.lockpath(id))?)
    }
    fn delete_lock(&self, id: usize) -> Result<()> {
        let lockdir = self.lockpath(id);
        if lockdir.exists() {
            fs::remove_dir(self.lockpath(id))?
        }
        Ok(())
    }

    /**
     * Create a single sandbox by id.
     * If the sandbox already exists and is valid (has lock), this is a no-op.
     */
    pub fn create(&self, id: usize) -> Result<()> {
        let sandbox = self.path(id);
        if sandbox.exists() {
            if self.lockpath(id).exists() {
                // Sandbox already exists and is valid
                return Ok(());
            }
            bail!(
                "Sandbox exists but is incomplete: {}. Destroy it first.",
                sandbox.display()
            );
        }
        fs::create_dir_all(&sandbox)?;
        self.perform_actions(id)?;
        self.create_lock(id)?;
        Ok(())
    }

    /**
     * Execute a script file with supplied environment variables and optional
     * stdin data. If status_fd is provided, it will be passed to the child
     * process via the bob_status_fd environment variable.
     */
    pub fn execute(
        &self,
        id: usize,
        script: &Path,
        mut envs: Vec<(String, String)>,
        stdin_data: Option<&str>,
        status_fd: Option<i32>,
    ) -> Result<Child> {
        use std::io::Write;

        let mut cmd = self.command(id, script);
        cmd.current_dir("/");

        if let Some(fd) = status_fd {
            envs.push(("bob_status_fd".to_string(), fd.to_string()));
        }

        for (key, val) in envs {
            cmd.env(key, val);
        }

        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        }

        // Script handles its own output redirection to log files
        cmd.stdout(Stdio::null()).stderr(Stdio::null());

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
            let child = self.execute(id, script, envs, None, None)?;
            let output = child.wait_with_output()?;
            return Ok(output.status.success());
        }
        Ok(true)
    }

    /**
     * Run the post-build script if configured.
     * Returns Ok(true) if script ran successfully or wasn't configured,
     * Ok(false) if script failed.
     */
    pub fn run_post_build(
        &self,
        id: usize,
        config: &Config,
        envs: Vec<(String, String)>,
    ) -> Result<bool> {
        if let Some(script) = config.script("post-build") {
            let child = self.execute(id, script, envs, None, None)?;
            let output = child.wait_with_output()?;
            return Ok(output.status.success());
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
        self.kill_processes(&sandbox);
        self.delete_lock(id)?;
        self.reverse_actions(id)?;
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
     * Create all sandboxes, rolling back on failure.
     */
    pub fn create_all(&self, count: usize) -> Result<()> {
        for i in 0..count {
            if let Err(e) = self.create(i) {
                // Rollback: destroy sandboxes including the failed one (may be partial)
                for j in (0..=i).rev() {
                    if let Err(destroy_err) = self.destroy(j) {
                        eprintln!(
                            "Warning: failed to destroy sandbox {}: {}",
                            j, destroy_err
                        );
                    }
                }
                return Err(e);
            }
        }
        Ok(())
    }

    /**
     * Destroy all sandboxes.  Continue on errors to ensure all sandboxes
     * are attempted, printing each error as it occurs.
     */
    pub fn destroy_all(&self, count: usize) -> Result<()> {
        let mut failed = 0;
        for i in 0..count {
            if let Err(e) = self.destroy(i) {
                eprintln!("sandbox {}: {}", i, e);
                failed += 1;
            }
        }
        if failed == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to destroy {} sandbox{}\nRemove unexpected files, then run 'bob util sandbox destroy'",
                failed,
                if failed == 1 { "" } else { "es" }
            ))
        }
    }

    /**
     * List all sandboxes.
     */
    pub fn list_all(&self, count: usize) {
        for i in 0..count {
            let sandbox = self.path(i);
            if sandbox.exists() {
                if self.lockpath(i).exists() {
                    println!("{}", sandbox.display())
                } else {
                    println!("{} (incomplete)", sandbox.display())
                }
            }
        }
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
                        continue;
                    }
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
                    copy_dir::copy_dir(src, &dest)?;
                    None
                }
                ActionType::Cmd => {
                    if let Some(create_cmd) = action.create_cmd() {
                        self.run_action_cmd(id, create_cmd, action.cwd())?
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
                    // Create parent directory if needed
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

    /// Run a custom action command.
    /// The command is run via /bin/sh -c with environment variables set.
    /// If cwd is specified, the directory is created if it doesn't exist.
    fn run_action_cmd(
        &self,
        id: usize,
        cmd: &str,
        cwd: Option<&PathBuf>,
    ) -> Result<Option<std::process::ExitStatus>> {
        let sandbox_path = self.path(id);
        let work_dir = if let Some(c) = cwd {
            self.mountpath(id, c)
        } else {
            sandbox_path.clone()
        };
        self.verify_path_in_sandbox(id, &work_dir)?;

        // Create the working directory if it doesn't exist
        if !work_dir.exists() {
            fs::create_dir_all(&work_dir)?;
        }

        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(cmd)
            .current_dir(&work_dir)
            .status()?;

        Ok(Some(status))
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
                    // For cmd actions, we run the destroy command
                    if let Some(destroy_cmd) = action.destroy_cmd() {
                        let status =
                            self.run_action_cmd(id, destroy_cmd, action.cwd())?;
                        if let Some(s) = status {
                            if !s.success() {
                                bail!(
                                    "Failed to run destroy command: exit code {:?}",
                                    s.code()
                                );
                            }
                        }
                    }
                    // Clean up cwd directory if it was created
                    if let Some(cwd) = action.cwd() {
                        let cwd_path = self.mountpath(id, cwd);
                        self.remove_empty_dirs(id, &cwd_path);
                    }
                }
                ActionType::Copy => {
                    // Copied directories need to be removed
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
                    self.verify_path_in_sandbox(id, &mntdest)?;
                    self.remove_dir_recursive(&mntdest)?;
                    self.remove_empty_dirs(id, &mntdest);
                }
                ActionType::Symlink => {
                    // Remove the symlink
                    let Some(mntdest) = dest else { continue };
                    if mntdest.is_symlink() {
                        fs::remove_file(&mntdest)?;
                    }
                    self.remove_empty_dirs(id, &mntdest);
                }
                ActionType::Mount => {
                    // For mount actions, we need to unmount
                    let Some(mntdest) = dest else { continue };
                    let fs_type = action.fs_type()?;

                    // If ifexists was set and src doesn't exist, the mount was skipped
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
                     * Unmount the filesystem.  Check return codes and bail on
                     * failure - it is critical that all mounts are successfully
                     * unmounted before we attempt to remove the sandbox directory.
                     */
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
