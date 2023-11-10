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
 * Sandbox creation and management.  Implementation is done on a per-OS
 * basis due to significant differences between them, but the presentation
 * to the user should be uniform.
 */
#[cfg(target_os = "macos")]
mod sandbox_macos;
#[cfg(target_os = "netbsd")]
mod sandbox_netbsd;
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
mod sandbox_sunos;

use crate::mount;
use serde_derive::Deserialize;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, SandboxError>;

#[derive(Debug)]
pub enum SandboxError {
    /// Sandbox already exists
    Exists(PathBuf),
    /// I/O failure creating or removing sandbox
    Io(std::io::Error),
    /// A mount error
    MountError(mount::MountError),
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Sandbox {
    basedir: PathBuf,
    count: Option<u64>,
    mounts: Option<Vec<mount::Mount>>,
}

impl From<std::io::Error> for SandboxError {
    fn from(err: std::io::Error) -> Self {
        SandboxError::Io(err)
    }
}

impl From<mount::MountError> for SandboxError {
    fn from(err: mount::MountError) -> Self {
        SandboxError::MountError(err)
    }
}

impl std::error::Error for SandboxError {}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SandboxError::Exists(s) => {
                write!(f, "sandbox already exists: {}", s.display())
            }
            SandboxError::Io(s) => {
                write!(f, "I/O error: {}", s)
            }
            SandboxError::MountError(s) => {
                write!(f, "mount error: {}", s)
            }
        }
    }
}

impl Sandbox {
    ///
    /// Return configured number of sandboxes.
    ///
    pub fn count(&self) -> u64 {
        self.count.unwrap_or(1)
    }

    ///
    /// Return full path to a sandbox by id.
    ///
    pub fn path(&self, id: u64) -> PathBuf {
        let mut p = PathBuf::from(&self.basedir);
        p.push(id.to_string());
        p
    }

    ///
    /// Return full path to a specified mount point in a sandbox.
    ///
    pub fn mountpath(&self, id: u64, mnt: &PathBuf) -> PathBuf {
        /*
         * Note that .push() on a PathBuf will replace the path if
         * it is absolute, so we need to trim any leading "/".
         */
        let mut p = self.path(id);
        match mnt.strip_prefix("/") {
            Ok(s) => p.push(s),
            Err(_) => p.push(mnt),
        };
        p
    }

    /*
     * Functions to create/destroy lock directory inside a sandbox to
     * indicate that it has successfully been created.  An empty directory
     * is used as it provides a handy way to guarantee(?) atomicity.
     */
    fn lockpath(&self, id: u64) -> PathBuf {
        let mut p = self.path(id);
        p.push(".created");
        p
    }
    fn create_lock(&self, id: u64) -> Result<()> {
        Ok(fs::create_dir(self.lockpath(id))?)
    }
    fn delete_lock(&self, id: u64) -> Result<()> {
        let lockdir = self.lockpath(id);
        if lockdir.exists() {
            fs::remove_dir(self.lockpath(id))?
        }
        Ok(())
    }

    ///
    /// Create a single sandbox by id.
    ///
    pub fn create(&self, id: u64) -> Result<()> {
        let sandbox = self.path(id);
        if sandbox.exists() {
            return Err(SandboxError::Exists(sandbox));
        }
        self.mount(id)?;
        self.create_lock(id)?;
        Ok(())
    }

    ///
    /// Destroy a single sandbox by id.
    ///
    pub fn destroy(&self, id: u64) -> Result<()> {
        let sandbox = self.path(id);
        if !sandbox.exists() {
            return Ok(());
        }
        self.delete_lock(id)?;
        self.unmount(id)?;
        if sandbox.exists() {
            fs::remove_dir(sandbox)?;
        }
        Ok(())
    }

    ///
    /// Create all sandboxes.
    ///
    pub fn create_all(&self) -> Result<()> {
        for i in 0..self.count() {
            self.create(i)?;
        }
        Ok(())
    }

    ///
    /// Destroy all sandboxes.
    ///
    pub fn destroy_all(&self) -> Result<()> {
        for i in 0..self.count() {
            self.destroy(i)?;
        }
        Ok(())
    }

    ///
    /// List all sandboxes.
    ///
    pub fn list_all(&self) {
        for i in 0..self.count() {
            let sandbox = self.path(i);
            if sandbox.exists() {
                if self.lockpath(i).exists() {
                    println!("{}", sandbox.display())
                } else {
                    println!("{} (incomplete)", sandbox.display())
                }
            }
        }
    }

    /*
     * Remove any empty directories from a mount point up to the root of the
     * sandbox.
     */
    fn remove_empty_dirs(&self, id: u64, mountpoint: &Path) {
        for p in mountpoint.ancestors() {
            /*
             * Sanity check we are within the chroot.
             */
            if !p.starts_with(self.path(id)) {
                break;
            }
            /*
             * Go up to next parent if this path does not exist.
             */
            if !p.exists() {
                continue;
            }
            /*
             * Otherwise attempt to remove.  If this fails then skip any
             * parent directories.
             */
            if fs::remove_dir(p).is_err() {
                break;
            }
        }
    }

    ///
    /// Iterate over the supplied array of mount points in order.  If at any
    /// point we encounter a problem then the successful mounts are rolled
    /// back and an error returned.
    ///
    fn mount(&self, id: u64) -> Result<()> {
        if let Some(mounts) = &self.mounts {
            for m in mounts.iter() {
                /* src is optional, and defaults to dest */
                let mntsrc = match m.src() {
                    Some(s) => s,
                    None => m.dest(),
                };
                let mntdest = self.mountpath(id, m.dest());
                let mut mntopts = vec![];
                if let Some(opts) = m.opts() {
                    for opt in opts.split(' ').collect::<Vec<&str>>() {
                        mntopts.push(opt);
                    }
                }
                let status = match m.fstype() {
                    Ok(mount::FSType::Bind) => {
                        self.mount_bindfs(mntsrc, &mntdest, &mntopts)
                    }
                    Ok(mount::FSType::Dev) => {
                        self.mount_devfs(mntsrc, &mntdest, &mntopts)
                    }
                    Ok(mount::FSType::Nfs) => {
                        self.mount_nfs(mntsrc, &mntdest, &mntopts)
                    }
                    Ok(mount::FSType::Tmp) => {
                        self.mount_tmpfs(mntsrc, &mntdest, &mntopts)
                    }
                    Err(e) => Err(e),
                };
                if let Err(e) = status {
                    return Err(SandboxError::MountError(e));
                }
            }
        }
        Ok(())
    }

    fn unmount(&self, id: u64) -> mount::Result<()> {
        let mut res: mount::Result<()> = Ok(());
        if let Some(mounts) = &self.mounts {
            for m in mounts.iter().rev() {
                let mntdest = self.mountpath(id, m.dest());
                /*
                 * If the mount point itself does not exist then do not try to
                 * unmount it, but do try to clean up any empty parent
                 * directories up to the root.
                 */
                if !mntdest.exists() {
                    self.remove_empty_dirs(id, &mntdest);
                    continue;
                }
                let status = match m.fstype() {
                    Ok(mount::FSType::Bind) => self.unmount_bindfs(&mntdest),
                    Ok(mount::FSType::Dev) => self.unmount_devfs(&mntdest),
                    Ok(mount::FSType::Nfs) => self.unmount_nfs(&mntdest),
                    Ok(mount::FSType::Tmp) => self.unmount_tmpfs(&mntdest),
                    _ => {
                        Err(mount::MountError::Unsupported(m.fs().to_string()))
                    }
                };
                if let Err(e) = status {
                    eprintln!(
                        "WARNING: Unable to unmount {}: {}",
                        &mntdest.display(),
                        e
                    );
                    res = Err(e);
                } else {
                    self.remove_empty_dirs(id, &mntdest);
                }
            }
        }
        res
    }
}
