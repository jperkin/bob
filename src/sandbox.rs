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

use crate::config::Config;
use crate::mount::FSType;
use anyhow::{bail, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/**
 * [Sandbox] implementation.
 */
#[derive(Clone, Debug, Default)]
pub struct Sandbox {
    config: Config,
}

impl Sandbox {
    /**
     * Create a new [`Sandbox`] instance.  This is used even if sandboxes have
     * not been enabled, as it provides a consistent interface to run commands
     * through using [`execute`].  If sandboxes are enabled then commands are
     * executed via `chroot(8)`, otherwise they are executed directly.
     *
     * [`execute`]: Sandbox::execute
     */
    pub fn new(config: &Config) -> Sandbox {
        Sandbox { config: config.clone() }
    }

    /**
     * Return whether sandboxes have been enabled.  This is based on whether
     * a valid [sandboxes] section has been specified in the config file.
     */
    pub fn enabled(&self) -> bool {
        self.config.sandboxes().is_some()
    }

    /**
     * Return full path to a sandbox by id.
     */
    fn path(&self, id: usize) -> PathBuf {
        let sandbox = &self.config.sandboxes().as_ref().unwrap();
        let mut p = PathBuf::from(&sandbox.basedir);
        p.push(id.to_string());
        p
    }

    /**
     * Return full path to a specified mount point in a sandbox.
     */
    fn mountpath(&self, id: usize, mnt: &PathBuf) -> PathBuf {
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
     * Execute a script file with supplied environment variables.
     */
    pub fn execute(
        &self,
        id: usize,
        script: &Path,
        envs: Vec<(&str, String)>,
    ) -> Result<Child> {
        let child = if self.enabled() {
            let mut cmd = Command::new("/usr/sbin/chroot");
            cmd.current_dir("/").arg(self.path(id)).arg(script);
            for (key, val) in envs {
                cmd.env(key, val);
            }
            cmd.stdout(Stdio::piped()).spawn()?
        } else {
            let mut cmd = Command::new(script);
            for (key, val) in envs {
                cmd.env(key, val);
            }
            cmd.stdout(Stdio::piped()).spawn()?
        };
        Ok(child)
    }

    /**
     * Destroy a single sandbox by id.
     */
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

    /**
     * Create all sandboxes.
     */
    pub fn create_all(&self, count: usize) -> Result<()> {
        for i in 0..count {
            self.create(i)?;
        }
        Ok(())
    }

    /**
     * Destroy all sandboxes.
     */
    pub fn destroy_all(&self, count: usize) -> Result<()> {
        for i in 0..count {
            self.destroy(i)?;
        }
        Ok(())
    }

    /**
     * List all sandboxes.
     */
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
        let Some(sandbox) = &self.config.sandboxes() else {
            bail!("Internal error: trying to mount when sandboxes disabled.");
        };
        for m in sandbox.mounts.iter() {
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
                FSType::Bind => {
                    self.mount_bindfs(mntsrc, &mntdest, &mntopts)?
                }
                FSType::Dev => self.mount_devfs(mntsrc, &mntdest, &mntopts)?,
                FSType::Fd => self.mount_fdfs(mntsrc, &mntdest, &mntopts)?,
                FSType::Nfs => self.mount_nfs(mntsrc, &mntdest, &mntopts)?,
                FSType::Proc => {
                    self.mount_procfs(mntsrc, &mntdest, &mntopts)?
                }
                FSType::Tmp => self.mount_tmpfs(mntsrc, &mntdest, &mntopts)?,
            };
            if let Some(s) = status {
                if !s.success() {
                    bail!("Sandbox creation failed");
                }
            }
        }
        Ok(())
    }

    fn unmount(&self, id: usize) -> anyhow::Result<()> {
        let Some(sandbox) = &self.config.sandboxes() else {
            bail!("Internal error: trying to unmount when sandboxes disabled.");
        };
        for m in sandbox.mounts.iter().rev() {
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
                FSType::Bind => self.unmount_bindfs(&mntdest)?,
                FSType::Dev => self.unmount_devfs(&mntdest)?,
                FSType::Fd => self.unmount_fdfs(&mntdest)?,
                FSType::Nfs => self.unmount_nfs(&mntdest)?,
                FSType::Proc => self.unmount_procfs(&mntdest)?,
                FSType::Tmp => self.unmount_tmpfs(&mntdest)?,
            };
            self.remove_empty_dirs(id, &mntdest);
        }
        Ok(())
    }
}
