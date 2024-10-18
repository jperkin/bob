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
use anyhow::{bail, Result};
use serde_derive::Deserialize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Sandbox {
    basedir: PathBuf,
    chroot: Option<bool>,
    mounts: Option<Vec<mount::Mount>>,
}

impl Sandbox {
    /**
     * Create an empty [`Sandbox`].  This isn't as useless as it sounds - by
     * directing all operations via the sandbox we can do things like call
     * [`execute`] as a unified interface whether using chroots or not, and
     * allow testing and development to just run things directly rather than
     * requiring root access.
     */
    pub fn new() -> Sandbox {
        Sandbox { ..Default::default() }
    }

    pub fn chrooted(&self) -> bool {
        self.chroot.unwrap_or(true)
    }

    /**
     * Return full path to a sandbox by id.
     */
    pub fn path(&self, id: usize) -> PathBuf {
        let mut p = PathBuf::from(&self.basedir);
        p.push(id.to_string());
        p
    }

    /**
     * Return full path to a specified mount point in a sandbox.
     */
    pub fn mountpath(&self, id: usize, mnt: &PathBuf) -> PathBuf {
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
    fn lockpath(&self, id: usize) -> PathBuf {
        let mut p = self.path(id);
        p.push(".created");
        p
    }
    fn create_lock(&self, id: usize) -> Result<()> {
        Ok(fs::create_dir(self.lockpath(id))?)
    }
    fn delete_lock(&self, id: usize) -> Result<()> {
        let lockdir = self.lockpath(id);
        if lockdir.exists() {
            fs::remove_dir(self.lockpath(id))?
        }
        Ok(())
    }

    /**
     * Create a single sandbox by id.
     */
    pub fn create(&self, id: usize) -> Result<()> {
        let sandbox = self.path(id);
        if sandbox.exists() {
            bail!("Sandbox already exists: {}", sandbox.display());
        }
        fs::create_dir_all(sandbox)?;
        self.mount(id)?;
        self.create_lock(id)?;
        Ok(())
    }

    /**
     * Execute the supplied script.  If [`Sandbox`] is fully specified then
     */
    pub fn execute(&self, id: usize, script: &str) -> Result<Child> {
        let mut child = if self.chrooted() {
            Command::new("/usr/sbin/chroot")
                .current_dir("/")
                .arg(self.path(id))
                .arg("/bin/sh")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?
        } else {
            Command::new("/bin/sh")
                .current_dir(self.path(id))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?
        };

        let script = script.to_string();
        let mut stdin = child.stdin.take().expect("Failed to open stdin");
        std::thread::spawn(move || {
            stdin.write_all(script.as_bytes()).expect("Failed to read stdin");
        });
        Ok(child)
    }
    ///
    /// Destroy a single sandbox by id.
    ///
    pub fn destroy(&self, id: usize) -> anyhow::Result<()> {
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
    pub fn create_all(&self, count: usize) -> Result<()> {
        for i in 0..count {
            self.create(i)?;
        }
        Ok(())
    }

    ///
    /// Destroy all sandboxes.
    ///
    pub fn destroy_all(&self, count: usize) -> Result<()> {
        for i in 0..count {
            self.destroy(i)?;
        }
        Ok(())
    }

    ///
    /// List all sandboxes.
    ///
    pub fn list_all(&self, count: usize) {
        for i in 0..count {
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
    fn remove_empty_dirs(&self, id: usize, mountpoint: &Path) {
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
    /// point a problem is encountered we immediately bail.
    ///
    fn mount(&self, id: usize) -> Result<()> {
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
                let status = match m.fstype()? {
                    mount::FSType::Bind => {
                        self.mount_bindfs(mntsrc, &mntdest, &mntopts)?
                    }
                    mount::FSType::Dev => {
                        self.mount_devfs(mntsrc, &mntdest, &mntopts)?
                    }
                    mount::FSType::Fd => {
                        self.mount_fdfs(mntsrc, &mntdest, &mntopts)?
                    }
                    mount::FSType::Nfs => {
                        self.mount_nfs(mntsrc, &mntdest, &mntopts)?
                    }
                    mount::FSType::Proc => {
                        self.mount_procfs(mntsrc, &mntdest, &mntopts)?
                    }
                    mount::FSType::Tmp => {
                        self.mount_tmpfs(mntsrc, &mntdest, &mntopts)?
                    }
                };
                if let Some(s) = status {
                    if !s.success() {
                        bail!("Sandbox creation failed");
                    }
                }
            }
        }
        Ok(())
    }

    fn unmount(&self, id: usize) -> anyhow::Result<()> {
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

                /*
                 * Before trying to unmount, try just removing the directory,
                 * in case it was never mounted in the first place.  Avoids
                 * errors trying to unmount a file system that isn't mounted.
                 */
                if fs::remove_dir(&mntdest).is_ok() {
                    continue;
                }

                /*
                 * Report failures but don't bail.
                 */
                match m.fstype()? {
                    mount::FSType::Bind => self.unmount_bindfs(&mntdest)?,
                    mount::FSType::Dev => self.unmount_devfs(&mntdest)?,
                    mount::FSType::Fd => self.unmount_fdfs(&mntdest)?,
                    mount::FSType::Nfs => self.unmount_nfs(&mntdest)?,
                    mount::FSType::Proc => self.unmount_procfs(&mntdest)?,
                    mount::FSType::Tmp => self.unmount_tmpfs(&mntdest)?,
                };
                self.remove_empty_dirs(id, &mntdest);
            }
        }
        Ok(())
    }
}
