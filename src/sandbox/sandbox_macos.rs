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
use tracing::debug;

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
     * Find PIDs of processes using files under the sandbox path.
     *
     * Uses `fuser` which matches by path, not filesystem.  Filters out
     * system daemons (Spotlight, notification services, etc.) that hold
     * file handles but must not be killed.
     */
    pub(super) fn find_pids(&self, sandbox: &Path) -> Vec<String> {
        const SKIP_LIST: &[&str] = &[
            "kextd",
            "mds",
            "mds_stores",
            "mdworker",
            "mdworker_shared",
            "notifyd",
        ];

        let output = Command::new("fuser")
            .arg(sandbox)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .output();
        let Ok(out) = output else { return vec![] };
        if !out.status.success() {
            return vec![];
        }
        let pids: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        if pids.is_empty() {
            return vec![];
        }

        let ps_output = Command::new("ps")
            .arg("-o")
            .arg("pid=,comm=")
            .arg("-p")
            .arg(pids.join(","))
            .process_group(0)
            .output();
        let Ok(ps_out) = ps_output else { return pids };

        String::from_utf8_lossy(&ps_out.stdout)
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let pid = parts.next()?;
                let comm = parts.next()?;
                if SKIP_LIST.contains(&comm) {
                    debug!(pid, name = comm, "Skipping protected process");
                    None
                } else {
                    Some(pid.to_string())
                }
            })
            .collect()
    }
}
