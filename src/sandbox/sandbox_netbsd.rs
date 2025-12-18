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

use crate::sandbox::Sandbox;
use anyhow::{bail, Context};
use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus};

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
        bail!("NetBSD does not support 'dev' mounts. Use a 'cmd' action with MAKEDEV instead.")
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
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    /*
     * General unmount routine common to file system types that involve
     * mounted file systems.
     */
    fn unmount_common(
        &self,
        dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        let cmd = "/sbin/umount";
        Ok(Some(
            Command::new(cmd)
                .arg(dest)
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
        bail!("NetBSD does not support 'dev' mounts. Use a 'cmd' action with MAKEDEV instead.")
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

    /// Kill all processes using files within a sandbox path.
    pub fn kill_processes(&self, sandbox: &Path) {
        // Use fstat to find processes and kill them
        let output = Command::new("fstat")
            .arg(sandbox)
            .output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines().skip(1) {
                // fstat output: USER CMD PID FD MOUNT ...
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let Ok(pid) = parts[2].parse::<i32>() {
                        let _ = Command::new("kill")
                            .arg("-9")
                            .arg(pid.to_string())
                            .status();
                    }
                }
            }
        }

        // Give processes a moment to die
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
