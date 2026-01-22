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

use crate::sandbox::Sandbox;
use anyhow::{Context, bail};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitStatus};
use tracing::{debug, info, warn};

impl Sandbox {
    pub fn mount_bindfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest)?;
        let cmd = "/sbin/mount_null";
        Ok(Some(
            Command::new(cmd)
                .args(opts)
                .arg(src)
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    /*
     * NetBSD does not have a devfs.  Use a 'cmd' action with MAKEDEV instead.
     */
    pub fn mount_devfs(
        &self,
        _src: &Path,
        _dest: &Path,
        _opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        bail!(
            "NetBSD does not support 'dev' mounts. Use a 'cmd' action with MAKEDEV instead."
        )
    }

    pub fn mount_fdfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest)?;
        let cmd = "/sbin/mount_fdesc";
        Ok(Some(
            Command::new(cmd)
                .args(opts)
                .arg("fdesc")
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    pub fn mount_nfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest)?;
        let cmd = "/sbin/mount_nfs";
        Ok(Some(
            Command::new(cmd)
                .args(opts)
                .arg(src)
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    pub fn mount_procfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest)?;
        let cmd = "/sbin/mount_procfs";
        Ok(Some(
            Command::new(cmd)
                .args(opts)
                .arg("/proc")
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    pub fn mount_tmpfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest)?;
        let cmd = "/sbin/mount_tmpfs";
        Ok(Some(
            Command::new(cmd)
                .args(opts)
                .arg("tmpfs")
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    /*
     * General unmount routine common to file system types that involve
     * mounted file systems.
     *
     * Use process_group(0) to put umount in its own process group.
     * This prevents it from receiving SIGINT when the user presses Ctrl+C,
     * ensuring cleanup can complete even during repeated interrupts.
     */
    fn unmount_common(
        &self,
        dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        let cmd = "/sbin/umount";
        Ok(Some(
            Command::new(cmd)
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    pub fn unmount_bindfs(
        &self,
        dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_devfs(
        &self,
        _dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        // Should never be called since mount_devfs bails
        bail!(
            "NetBSD does not support 'dev' mounts. Use a 'cmd' action with MAKEDEV instead."
        )
    }

    pub fn unmount_fdfs(
        &self,
        dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_nfs(
        &self,
        dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_procfs(
        &self,
        dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_tmpfs(
        &self,
        dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    /**
     * Kill processes using a specific mount point.
     *
     * Uses fuser -ck (BSD mount point mode + kill) to identify and kill
     * processes using the mount point.
     */
    pub fn kill_processes_for_path(&self, path: &Path) {
        for iteration in 0..super::KILL_PROCESSES_MAX_RETRIES {
            let output = Command::new("fuser")
                .arg("-c")
                .arg(path)
                .process_group(0)
                .output();

            let Ok(out) = output else { return };

            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.split_whitespace().next().is_none() {
                return;
            }

            debug!(path = %path.display(), "Killing processes for mount");

            let _ = Command::new("fuser")
                .arg("-ck")
                .arg(path)
                .stderr(std::process::Stdio::null())
                .process_group(0)
                .status();

            let delay_ms = super::KILL_PROCESSES_INITIAL_DELAY_MS << iteration;
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
    }

    /// Kill all processes with open file handles within a sandbox path.
    pub fn kill_processes(&self, sandbox: &Path) {
        for iteration in 0..super::KILL_PROCESSES_MAX_RETRIES {
            // Use fstat to find processes using files under the sandbox
            // Use process_group(0) to isolate from terminal signals
            let output =
                Command::new("fstat").arg(sandbox).process_group(0).output();
            let Ok(out) = output else {
                return;
            };

            let stdout = String::from_utf8_lossy(&out.stdout);
            // fstat output: USER CMD PID FD MOUNT ...
            // Collect unique PIDs from column 3
            let pids: Vec<&str> = stdout
                .lines()
                .skip(1)
                .filter_map(|line| line.split_whitespace().nth(2))
                .collect();

            // No processes found, we're done
            if pids.is_empty() {
                debug!(retries = iteration, "No processes found in sandbox");
                return;
            }

            info!(pids = %pids.join(" "), "Killed processes using sandbox");

            let _ = Command::new("kill")
                .arg("-9")
                .args(&pids)
                .stderr(std::process::Stdio::null())
                .process_group(0)
                .status();

            // Give processes a moment to die (exponential backoff)
            let delay_ms = super::KILL_PROCESSES_INITIAL_DELAY_MS << iteration;
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
        // Get info about remaining processes for the warning
        let proc_info = self.get_process_info(sandbox);
        warn!(
            max_retries = super::KILL_PROCESSES_MAX_RETRIES,
            remaining = %proc_info,
            "Gave up killing processes after max retries"
        );
    }

    /// Get info about processes using files in a directory.
    fn get_process_info(&self, sandbox: &Path) -> String {
        // Get PIDs using fstat
        let output =
            Command::new("fstat").arg(sandbox).process_group(0).output();
        let Ok(out) = output else {
            return String::from("(failed to query)");
        };

        let stdout = String::from_utf8_lossy(&out.stdout);
        let pids: Vec<&str> = stdout
            .lines()
            .skip(1)
            .filter_map(|line| line.split_whitespace().nth(2))
            .collect();

        if pids.is_empty() {
            return String::from("(none)");
        }

        let ps_output = Command::new("ps")
            .arg("-ww")
            .arg("-o")
            .arg("pid,args")
            .arg("-p")
            .arg(pids.join(","))
            .process_group(0)
            .output();

        match ps_output {
            Ok(out) => String::from_utf8_lossy(&out.stdout)
                .lines()
                .skip(1)
                .filter_map(|line| {
                    let mut parts = line.split_whitespace();
                    let pid = parts.next()?;
                    let cmd: String = parts.collect::<Vec<_>>().join(" ");
                    Some(format!("pid={} cmd='{}'", pid, cmd))
                })
                .collect::<Vec<_>>()
                .join(", "),
            Err(_) => pids
                .iter()
                .map(|p| format!("pid={}", p))
                .collect::<Vec<_>>()
                .join(", "),
        }
    }
}
