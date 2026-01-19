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
        let cmd = "/sbin/mount";
        Ok(Some(
            Command::new(cmd)
                .arg("-F")
                .arg("lofs")
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
        _dest: &Path,
        _opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        bail!("Use bind mounts for /dev")
    }

    pub fn mount_fdfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest)?;
        let cmd = "/sbin/mount";
        Ok(Some(
            Command::new(cmd)
                .arg("-F")
                .arg("fd")
                .args(opts)
                .arg("fd")
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
        let cmd = "/sbin/mount";
        Ok(Some(
            Command::new(cmd)
                .arg("-F")
                .arg("nfs")
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
        let cmd = "/sbin/mount";
        Ok(Some(
            Command::new(cmd)
                .arg("-F")
                .arg("proc")
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
        let cmd = "/sbin/mount";
        Ok(Some(
            Command::new(cmd)
                .arg("-F")
                .arg("tmpfs")
                .args(opts)
                .arg("swap")
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
        dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
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

    /// Kill all processes with open file handles within a sandbox path.
    pub fn kill_processes(&self, sandbox: &Path) {
        use std::process::Stdio;

        for iteration in 0..super::KILL_PROCESSES_MAX_RETRIES {
            // Query fuser first to get PIDs for logging
            let output = Command::new("fuser")
                .arg(sandbox)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .process_group(0)
                .output();

            // Check if any processes are using the sandbox
            let has_processes = match &output {
                Ok(out) => out.status.success(),
                Err(_) => return,
            };

            if !has_processes {
                debug!(retries = iteration, "No processes found in sandbox");
                return;
            }

            // Log the PIDs being killed
            if let Ok(out) = &output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let pids: Vec<&str> = stdout.split_whitespace().collect();
                if !pids.is_empty() {
                    info!(pids = %pids.join(" "), "Killed processes using sandbox");
                }
            }

            // Use fuser -k to kill all processes using files under the sandbox
            // Use process_group(0) to isolate from terminal signals
            let _ = Command::new("fuser")
                .arg("-k")
                .arg(sandbox)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
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
        use std::process::Stdio;

        // Get PIDs using fuser
        let output = Command::new("fuser")
            .arg(sandbox)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .output();
        let Ok(out) = output else {
            return String::from("(failed to query)");
        };

        let stdout = String::from_utf8_lossy(&out.stdout);
        let pids: Vec<&str> = stdout.split_whitespace().collect();

        if pids.is_empty() {
            return String::from("(none)");
        }

        // Use pargs to get full command line (ps truncates on illumos)
        let mut info = Vec::new();
        for pid in &pids {
            let pargs_output =
                Command::new("pargs").arg(pid).process_group(0).output();
            match pargs_output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let args: Vec<&str> = stdout
                        .lines()
                        .filter_map(|l| l.strip_prefix("argv["))
                        .filter_map(|l| l.split("]: ").nth(1))
                        .collect();
                    info.push(format!("pid={} cmd='{}'", pid, args.join(" ")));
                }
                Err(_) => info.push(format!("pid={}", pid)),
            }
        }
        if info.is_empty() { String::from("(none)") } else { info.join(", ") }
    }
}
