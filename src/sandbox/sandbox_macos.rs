/*
 * Copyright (c) 2023 Jonathan Perkin <jonathan@perkin.org.uk>
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

/*
 * Sandbox module for macOS.
 */
use crate::mount;
use crate::sandbox::Sandbox;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

impl Sandbox {
    pub fn mount_bindfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &Vec<&str>,
    ) -> mount::Result<Output> {
        fs::create_dir_all(dest)?;
        match Command::new("bindfs")
            .args(opts)
            .arg(src)
            .arg(dest)
            .output()
        {
            Ok(s) => {
                if s.status.success() {
                    Ok(s)
                } else {
                    fs::remove_dir(dest)?;
                    Err(mount::MountError::Process(s))
                }
            }
            Err(e) => {
                fs::remove_dir(dest)?;
                eprintln!(
                    "Failed to launch bindfs.  Is it installed in $PATH?"
                );
                Err(mount::MountError::Io(e))
            }
        }
    }

    pub fn mount_devfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &Vec<&str>,
    ) -> mount::Result<Output> {
        fs::create_dir_all(dest)?;
        match Command::new("/sbin/mount_devfs")
            .arg("devfs")
            .args(opts)
            .arg(dest)
            .output()
        {
            Ok(s) => {
                if s.status.success() {
                    Ok(s)
                } else {
                    fs::remove_dir(dest)?;
                    Err(mount::MountError::Process(s))
                }
            }
            Err(e) => {
                fs::remove_dir(dest)?;
                Err(mount::MountError::Io(e))
            }
        }
    }

    pub fn mount_nfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &Vec<&str>,
    ) -> mount::Result<Output> {
        fs::create_dir_all(dest)?;
        match Command::new("/sbin/mount_nfs")
            .args(opts)
            .arg(src)
            .arg(dest)
            .output()
        {
            Ok(s) => {
                if s.status.success() {
                    Ok(s)
                } else {
                    fs::remove_dir(dest)?;
                    Err(mount::MountError::Process(s))
                }
            }
            Err(e) => {
                fs::remove_dir(dest)?;
                Err(mount::MountError::Io(e))
            }
        }
    }

    pub fn mount_tmpfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &Vec<&str>,
    ) -> mount::Result<Output> {
        fs::create_dir_all(dest)?;
        match Command::new("/sbin/mount_tmpfs")
            .args(opts)
            .arg(dest)
            .output()
        {
            Ok(s) => {
                if s.status.success() {
                    Ok(s)
                } else {
                    fs::remove_dir(dest)?;
                    Err(mount::MountError::Process(s))
                }
            }
            Err(e) => {
                fs::remove_dir(dest)?;
                Err(mount::MountError::Io(e))
            }
        }
    }

    /*
     * General unmount routine common to file system types that involve
     * mounted file systems.
     */
    fn unmount_common(&self, dest: &Path) -> mount::Result<()> {
        /*
         * First try to simply remove the directory, in case the file
         * system was manually unmounted or similar.
         */
        if fs::remove_dir(dest).is_ok() {
            return Ok(());
        }
        /*
         * macOS is notorious for not unmounting file systems, even with
         * "diskutil unmount force" in some cases, so for now we just skip
         * straight to "umount -f" which appears to work.
         */
        match Command::new("/sbin/umount").arg("-f").arg(dest).output() {
            Ok(s) => {
                if s.status.success() {
                    Ok(())
                } else {
                    Err(mount::MountError::Process(s))
                }
            }
            Err(e) => Err(mount::MountError::Io(e)),
        }
    }

    pub fn unmount_bindfs(&self, dest: &Path) -> mount::Result<()> {
        self.unmount_common(dest)
    }

    pub fn unmount_devfs(&self, dest: &Path) -> mount::Result<()> {
        self.unmount_common(dest)
    }

    pub fn unmount_nfs(&self, dest: &Path) -> mount::Result<()> {
        self.unmount_common(dest)
    }

    pub fn unmount_tmpfs(&self, dest: &Path) -> mount::Result<()> {
        self.unmount_common(dest)
    }
}
