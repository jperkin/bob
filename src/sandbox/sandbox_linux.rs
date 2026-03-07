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

use crate::sandbox::{self, Sandbox};
use anyhow::Context;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use tracing::{debug, info, warn};

impl Sandbox {
    /// Mount using `/bin/mount -t <fstype> [opts] <source> <dest>`.
    fn mount_fs(
        fstype: &str,
        source: &str,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        let mut args = vec!["-t", fstype];
        args.extend(opts.iter().copied());
        args.push(source);
        sandbox::run_mount_cmd("/bin/mount", &args, dest)
    }

    /// Mount using `/bin/mount -o <opts_str> <source> <dest>`.
    fn mount_bind(
        source: &str,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        let mut mount_opts = vec!["bind"];
        mount_opts.extend(opts.iter().copied());
        let opts_str = mount_opts.join(",");
        sandbox::run_mount_cmd("/bin/mount", &["-o", &opts_str, source], dest)
    }

    pub fn mount_bindfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        let src_str = src.to_string_lossy();
        Self::mount_bind(&src_str, dest, opts)
    }

    pub fn mount_devfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        Self::mount_fs("devtmpfs", "devtmpfs", dest, opts)
    }

    pub fn mount_fdfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        Self::mount_bind("/dev/fd", dest, opts)
    }

    pub fn mount_nfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        let src_str = src.to_string_lossy();
        Self::mount_fs("nfs", &src_str, dest, opts)
    }

    pub fn mount_procfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        Self::mount_fs("proc", "proc", dest, opts)
    }

    pub fn mount_tmpfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        sandbox::prepare_mount_dest(dest)?;
        let cmd = "/bin/mount";
        let mut args = vec!["-t", "tmpfs"];
        let mut mount_opts: Vec<String> = vec![];
        for opt in opts {
            if opt.starts_with("size=") || opt.starts_with("mode=") {
                mount_opts.push(opt.to_string());
            }
        }
        let opts_str = mount_opts.join(",");
        if !mount_opts.is_empty() {
            args.push("-o");
            args.push(&opts_str);
        }
        Ok(Some(
            Command::new(cmd)
                .args(&args)
                .arg("tmpfs")
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    fn unmount_common(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        let cmd = "/bin/umount";
        // Use process_group(0) to put umount in its own process group.
        // This prevents it from receiving SIGINT when the user presses Ctrl+C,
        // ensuring cleanup can complete even during repeated interrupts.
        Ok(Some(
            Command::new(cmd)
                .arg(dest)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    pub fn unmount_bindfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_devfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_fdfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_nfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_procfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_tmpfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    /**
     * Kill processes using a specific mount point.
     *
     * Uses fuser -km (Linux mount point mode + kill) to identify and kill
     * processes using the mount point.
     */
    pub fn kill_processes_for_path(&self, path: &Path) {
        for iteration in 0..super::KILL_PROCESSES_MAX_RETRIES {
            let output = Command::new("fuser")
                .arg("-m")
                .arg(path)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .process_group(0)
                .output();

            let Ok(out) = output else { return };

            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.split_whitespace().next().is_none() {
                return;
            }

            debug!(path = %path.display(), "Killing processes for mount");

            let _ = Command::new("fuser")
                .arg("-km")
                .arg(path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .status();

            let delay_ms = super::KILL_PROCESSES_INITIAL_DELAY_MS << iteration;
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
    }

    /// Kill all processes with open file handles within a sandbox path.
    ///
    /// Uses procfs to scan all processes for file descriptors, cwd, or root
    /// that point into the sandbox directory. This is more thorough than
    /// `fuser` which only checks the exact path, not files within subdirs.
    pub fn kill_processes(&self, sandbox: &Path) {
        for iteration in 0..super::KILL_PROCESSES_MAX_RETRIES {
            let mut killed: Vec<i32> = Vec::new();

            // Scan all processes
            if let Ok(procs) = procfs::process::all_processes() {
                for proc in procs.flatten() {
                    if Self::process_uses_path(&proc, sandbox).is_some() {
                        killed.push(proc.pid);
                        unsafe {
                            libc::kill(proc.pid, libc::SIGKILL);
                        }
                    }
                }
            }

            if killed.is_empty() {
                debug!(retries = iteration, "No processes found in sandbox");
                return;
            }

            let pids: Vec<String> = killed.iter().map(|p| p.to_string()).collect();
            info!(pids = %pids.join(" "), "Killed processes using sandbox");

            // Give processes a moment to die (exponential backoff)
            let delay_ms = super::KILL_PROCESSES_INITIAL_DELAY_MS << iteration;
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
        // Get info about remaining processes for the warning
        let proc_info = Self::get_process_info(sandbox);
        warn!(
            max_retries = super::KILL_PROCESSES_MAX_RETRIES,
            remaining = %proc_info,
            "Gave up killing processes after max retries"
        );
    }

    /// Get info about processes using files in a directory.
    fn get_process_info(sandbox: &Path) -> String {
        let mut info = Vec::new();
        if let Ok(procs) = procfs::process::all_processes() {
            for proc in procs.flatten() {
                if Self::process_uses_path(&proc, sandbox).is_some() {
                    let cmdline = proc
                        .cmdline()
                        .map(|c| c.join(" "))
                        .unwrap_or_else(|_| String::from("?"));
                    info.push(format!("pid={} cmd='{}'", proc.pid, cmdline));
                }
            }
        }
        if info.is_empty() {
            String::from("(none)")
        } else {
            info.join(", ")
        }
    }

    /// Check if a process has any references to paths under the given directory.
    /// Returns Some(reason) describing why the process matches, or None.
    fn process_uses_path(proc: &procfs::process::Process, dir: &Path) -> Option<String> {
        // Check cwd
        if let Ok(cwd) = proc.cwd() {
            if cwd.starts_with(dir) {
                return Some(format!("cwd={}", cwd.display()));
            }
        }

        // Check root (chroot)
        if let Ok(root) = proc.root() {
            if root.starts_with(dir) {
                return Some(format!("root={}", root.display()));
            }
        }

        // Check all open file descriptors
        if let Ok(fds) = proc.fd() {
            for fd in fds.flatten() {
                if let procfs::process::FDTarget::Path(path) = fd.target {
                    if path.starts_with(dir) {
                        return Some(format!("fd={}", path.display()));
                    }
                }
            }
        }

        None
    }
}
