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
 * Sandbox module for illumos.
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
        match Command::new("/sbin/mount")
            .arg("-F")
            .arg("lofs")
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

    pub fn mount_devfs(
        &self,
        _src: &Path,
        _dest: &Path,
        _opts: &[&str],
    ) -> mount::Result<Output> {
        Err(mount::MountError::Unsupported(
            "Use bind mounts for /dev".to_string(),
        ))
    }

    pub fn mount_fdfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &Vec<&str>,
    ) -> mount::Result<Output> {
        fs::create_dir_all(dest)?;
        match Command::new("/sbin/mount")
            .arg("-F")
            .arg("fd")
            .args(opts)
            .arg("fd")
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
        match Command::new("/sbin/mount")
            .arg("-F")
            .arg("nfs")
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

    pub fn mount_procfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &Vec<&str>,
    ) -> mount::Result<Output> {
        fs::create_dir_all(dest)?;
        match Command::new("/sbin/mount")
            .arg("-F")
            .arg("proc")
            .args(opts)
            .arg("/proc")
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
        match Command::new("/sbin/mount")
            .arg("-F")
            .arg("tmpfs")
            .args(opts)
            .arg("swap")
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
        match Command::new("/sbin/umount").arg(dest).output() {
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

    pub fn unmount_fdfs(&self, dest: &Path) -> mount::Result<()> {
        self.unmount_common(dest)
    }

    pub fn unmount_nfs(&self, dest: &Path) -> mount::Result<()> {
        self.unmount_common(dest)
    }

    pub fn unmount_procfs(&self, dest: &Path) -> mount::Result<()> {
        self.unmount_common(dest)
    }

    pub fn unmount_tmpfs(&self, dest: &Path) -> mount::Result<()> {
        self.unmount_common(dest)
    }
}
