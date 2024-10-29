/*
 * Copyright (c) 2024 Jonathan Perkin <jonathan@perkin.org.uk>
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
use std::path::Path;
use std::process::{Command, ExitStatus};

impl Sandbox {
    pub fn mount_bindfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &Vec<&str>,
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
     * NetBSD does not have a devfs but we provide support for MAKEDEV as a
     * convenience.
     */
    pub fn mount_devfs(
        &self,
        _src: &Path,
        dest: &Path,
        _opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest)?;
        fs::copy("/dev/MAKEDEV", dest.join("MAKEDEV"))?;
        fs::copy("/dev/MAKEDEV.local", dest.join("MAKEDEV.local"))?;
        let cmd = "./MAKEDEV";
        Ok(Some(
            Command::new(cmd)
                .arg("all")
                .current_dir(dest)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    pub fn mount_fdfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &Vec<&str>,
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
        opts: &Vec<&str>,
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
        opts: &Vec<&str>,
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
        opts: &Vec<&str>,
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
        dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::remove_dir_all(dest)?;
        Ok(None)
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
}
