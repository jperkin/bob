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
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use tracing::trace;

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
        fs::create_dir_all(dest)?;
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
        fs::create_dir_all(dest)?;
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
        fs::create_dir_all(dest)?;
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
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    fn unmount_common(
        &self,
        dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
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

    /// Kill all processes with open file handles within a sandbox path.
    ///
    /// Uses procfs to scan all processes for file descriptors, cwd, or root
    /// that point into the sandbox directory. This is more thorough than
    /// `fuser` which only checks the exact path, not files within subdirs.
    pub fn kill_processes(&self, sandbox: &Path) {
        for iteration in 0..super::KILL_PROCESSES_MAX_RETRIES {
            let mut found_any = false;

            // Scan all processes
            if let Ok(procs) = procfs::process::all_processes() {
                for proc in procs.flatten() {
                    if let Some(reason) =
                        Self::process_uses_path(&proc, sandbox)
                    {
                        found_any = true;
                        let comm =
                            proc.stat().map(|s| s.comm).unwrap_or_default();
                        trace!(
                            pid = proc.pid,
                            comm = %comm,
                            reason = %reason,
                            iteration,
                            "Killing process using sandbox"
                        );
                        unsafe {
                            libc::kill(proc.pid, libc::SIGKILL);
                        }
                    }
                }
            }

            if !found_any {
                trace!(sandbox = %sandbox.display(), iteration, "No processes found using sandbox");
                return;
            }

            // Give processes a moment to die
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        trace!(
            sandbox = %sandbox.display(),
            max_retries = super::KILL_PROCESSES_MAX_RETRIES,
            "Gave up killing processes after max retries"
        );
    }

    /// Check if a process has any references to paths under the given directory.
    /// Returns Some(reason) describing why the process matches, or None.
    fn process_uses_path(
        proc: &procfs::process::Process,
        dir: &Path,
    ) -> Option<String> {
        // Check cwd
        if let Ok(cwd) = proc.cwd() {
            if cwd.starts_with(dir) {
                return Some(format!("cwd={}", cwd.display()));
            }
        }

        // Check root (chroot)
        if let Ok(root) = proc.root() {
            if root.starts_with(dir) {
                return Some(format!("root={}", root.display()));
            }
        }

        // Check all open file descriptors
        if let Ok(fds) = proc.fd() {
            for fd in fds.flatten() {
                if let procfs::process::FDTarget::Path(path) = fd.target {
                    if path.starts_with(dir) {
                        return Some(format!("fd={}", path.display()));
                    }
                }
            }
        }

        None
    }
}
