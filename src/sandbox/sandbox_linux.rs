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
use anyhow::Context;
use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

impl Sandbox {
    pub fn mount_bindfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest)?;
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
        fs::create_dir_all(dest)?;
        let cmd = "/bin/mount";
        Ok(Some(
            Command::new(cmd)
                .arg("-t")
                .arg("devtmpfs")
                .args(opts)
                .arg("devtmpfs")
                .arg(dest)
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
        fs::create_dir_all(dest)?;
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
        let cmd = "/bin/mount";
        Ok(Some(
            Command::new(cmd)
                .arg("-t")
                .arg("nfs")
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
        let cmd = "/bin/mount";
        Ok(Some(
            Command::new(cmd)
                .arg("-t")
                .arg("proc")
                .args(opts)
                .arg("proc")
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
        let cmd = "/bin/mount";
        let mut args = vec!["-t", "tmpfs"];
        // Convert opts to mount -o style if they look like size options
        let mut mount_opts: Vec<String> = vec![];
        for opt in opts {
            if opt.starts_with("size=") || opt.starts_with("mode=") {
                mount_opts.push(opt.to_string());
            }
        }
        if !mount_opts.is_empty() {
            args.push("-o");
        }
        let opts_str = mount_opts.join(",");
        Ok(Some(
            Command::new(cmd)
                .args(&args)
                .arg(if !mount_opts.is_empty() { &opts_str } else { "" })
                .arg("tmpfs")
                .arg(dest)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    fn unmount_common(
        &self,
        dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        let cmd = "/bin/umount";
        Ok(Some(
            Command::new(cmd)
                .arg(dest)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
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

    /// Kill all processes using files within a sandbox path.
    ///
    /// Loop until no processes remain to handle the race condition where new
    /// processes can spawn between listing and killing.
    pub fn kill_processes(&self, sandbox: &Path) {
        const MAX_RETRIES: u32 = 10;

        for _ in 0..MAX_RETRIES {
            // Use fuser -k to kill all processes using files under the sandbox
            let _ = Command::new("fuser")
                .arg("-k")
                .arg(sandbox)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            // Give processes a moment to die
            std::thread::sleep(std::time::Duration::from_millis(100));

            // Check if any processes are still using the sandbox
            let status = Command::new("fuser")
                .arg(sandbox)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            // fuser exits 0 if processes found, 1 if none found
            if let Ok(s) = status {
                if !s.success() {
                    // No processes found, we're done
                    return;
                }
            } else {
                // fuser failed to run, bail out
                return;
            }
        }
    }
}
