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
use anyhow::Context;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

impl Sandbox {
    pub fn mount_bindfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
        let cmd = "/bin/mount";
        // Build mount options: start with "bind", add any user-specified opts
        let mut mount_opts = vec!["bind"];
        mount_opts.extend(opts.iter().copied());
        let opts_str = mount_opts.join(",");
        Ok(Some(
            Command::new(cmd)
                .arg("-o")
                .arg(&opts_str)
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
        let cmd = "/bin/mount";
        Ok(Some(
            Command::new(cmd)
                .arg("-t")
                .arg("devtmpfs")
                .args(opts)
                .arg("devtmpfs")
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    pub fn mount_fdfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
        let cmd = "/bin/mount";
        // Build mount options: start with "bind", add any user-specified opts
        let mut mount_opts = vec!["bind"];
        mount_opts.extend(opts.iter().copied());
        let opts_str = mount_opts.join(",");
        Ok(Some(
            Command::new(cmd)
                .arg("-o")
                .arg(&opts_str)
                .arg("/dev/fd")
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
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
        let cmd = "/bin/mount";
        Ok(Some(
            Command::new(cmd)
                .arg("-t")
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
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
        let cmd = "/bin/mount";
        Ok(Some(
            Command::new(cmd)
                .arg("-t")
                .arg("proc")
                .args(opts)
                .arg("proc")
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
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
        let cmd = "/bin/mount";
        let mut c = Command::new(cmd);
        c.args(["-t", "tmpfs"]);
        let mount_opts: Vec<&str> = opts
            .iter()
            .filter(|o| o.starts_with("size=") || o.starts_with("mode="))
            .copied()
            .collect();
        if !mount_opts.is_empty() {
            c.args(["-o", &mount_opts.join(",")]);
        }
        c.arg("tmpfs").arg(dest).process_group(0);
        Ok(Some(
            c.status().context(format!("Unable to execute {}", cmd))?,
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
}
