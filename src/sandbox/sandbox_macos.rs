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
use std::process::{Command, ExitStatus, Stdio};
use tracing::{debug, info, warn};

/// Processes that should not be killed during sandbox cleanup.
/// These are system daemons that hold file handles but cannot be killed.
const PROCESS_SKIP_LIST: &[&str] = &[
    "kextd",
    "mds",
    "mds_stores",
    "mdworker",
    "mdworker_shared",
    "notifyd",
];

impl Sandbox {
    pub fn mount_bindfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
        let cmd = self.config.bindfs();
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

    pub fn mount_devfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
        let cmd = "/sbin/mount_devfs";
        Ok(Some(
            Command::new(cmd)
                .arg("devfs")
                .args(opts)
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    pub fn mount_fdfs(
        &self,
        _src: &Path,
        _dest: &Path,
        _opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        bail!("fd mounts are not supported on macOS");
    }

    pub fn mount_nfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
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
        _dest: &Path,
        _opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        bail!("procfs mounts are not supported on macOS");
    }

    pub fn mount_tmpfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
        let cmd = "/sbin/mount_tmpfs";
        Ok(Some(
            Command::new(cmd)
                .args(opts)
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
     * Uses diskutil unmount with retries (every second, up to 3 minutes).
     * Use process_group(0) to put diskutil in its own process group,
     * preventing it from receiving SIGINT when the user presses Ctrl+C.
     */
    fn unmount_common(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        let cmd = "/usr/sbin/diskutil";
        let max_retries = 180;
        let mut last_status = None;

        for attempt in 0..max_retries {
            let status = Command::new(cmd)
                .arg("unmount")
                .arg(dest)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?;

            if status.success() {
                if attempt > 0 {
                    debug!(
                        path = %dest.display(),
                        retries = attempt,
                        "Unmount succeeded after retries"
                    );
                }
                return Ok(Some(status));
            }

            last_status = Some(status);

            if attempt < max_retries - 1 {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }

        Ok(last_status)
    }

    pub fn unmount_bindfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_devfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        let cmd = "/sbin/umount";
        Ok(Some(
            Command::new(cmd)
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    /* Not actually supported but try to unmount it anyway. */
    pub fn unmount_fdfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_nfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    /* Not actually supported but try to unmount it anyway. */
    pub fn unmount_procfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_tmpfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    /**
     * Kill processes using a specific mount point.
     *
     * Uses fuser -c (mount point mode on BSD) to identify processes, filters
     * out processes in PROCESS_SKIP_LIST, then kills the remaining processes.
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
            let pids: Vec<&str> = stdout.split_whitespace().collect();

            if pids.is_empty() {
                return;
            }

            let pids_to_kill = self.filter_skip_list(&pids);

            if pids_to_kill.is_empty() {
                debug!(
                    path = %path.display(),
                    "All processes in skip list, skipping"
                );
                return;
            }

            debug!(
                path = %path.display(),
                pids = %pids_to_kill.join(" "),
                "Killing processes for mount"
            );

            let _ = Command::new("kill")
                .arg("-9")
                .args(&pids_to_kill)
                .stderr(std::process::Stdio::null())
                .process_group(0)
                .status();

            let delay_ms = super::KILL_PROCESSES_INITIAL_DELAY_MS << iteration;
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
    }

    /**
     * Filter PIDs, removing any in PROCESS_SKIP_LIST by checking process names.
     */
    fn filter_skip_list(&self, pids: &[&str]) -> Vec<String> {
        if PROCESS_SKIP_LIST.is_empty() {
            return pids.iter().map(|s| (*s).to_string()).collect();
        }

        let output = Command::new("ps")
            .arg("-o")
            .arg("pid=,comm=")
            .arg("-p")
            .arg(pids.join(","))
            .process_group(0)
            .output();

        let Ok(out) = output else {
            return pids.iter().map(|s| (*s).to_string()).collect();
        };

        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let pid = parts.next()?;
                let comm = parts.next()?;
                if PROCESS_SKIP_LIST.contains(&comm) {
                    debug!(pid, name = comm, "Skipping protected process");
                    return None;
                }
                Some(pid.to_string())
            })
            .collect()
    }

    /// Kill all processes with open file handles within a sandbox path.
    pub fn kill_processes(&self, sandbox: &Path) {
        for iteration in 0..super::KILL_PROCESSES_MAX_RETRIES {
            // Use lsof to find processes using files under the sandbox
            // Use process_group(0) to isolate from terminal signals
            let output = Command::new("lsof")
                .arg("+D")
                .arg(sandbox)
                .process_group(0)
                .output();
            let Ok(out) = output else {
                return;
            };

            let stdout = String::from_utf8_lossy(&out.stdout);
            // lsof output: COMMAND PID USER ...
            // Collect unique PIDs from column 2
            let pids: Vec<&str> = stdout
                .lines()
                .skip(1)
                .filter_map(|line| line.split_whitespace().nth(1))
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
        // Get PIDs using lsof
        let output = Command::new("lsof")
            .arg("+D")
            .arg(sandbox)
            .process_group(0)
            .output();
        let Ok(out) = output else {
            return String::from("(failed to query)");
        };

        let stdout = String::from_utf8_lossy(&out.stdout);
        let pids: Vec<&str> = stdout
            .lines()
            .skip(1)
            .filter_map(|line| line.split_whitespace().nth(1))
            .collect();

        super::format_process_info(&pids)
    }
}
