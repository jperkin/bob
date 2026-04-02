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
use anyhow::{Context, bail};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use tracing::{debug, warn};

impl Sandbox {
    pub fn mount_bindfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
        let cmd = self.config.bindfs();
        /*
         * pre_exec raises the NOFILE limit for the bindfs process so it
         * does not run out of file descriptors when mounting large
         * directory trees (e.g. Xcode SDKs).  The unsafe block is
         * required by the pre_exec API; setrlimit is async-signal-safe.
         */
        Ok(Some(unsafe {
            Command::new(cmd)
                .args(opts)
                .arg(src)
                .arg(dest)
                .process_group(0)
                .pre_exec(|| {
                    let mut rlim = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
                        rlim.rlim_cur = rlim.rlim_max;
                        libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
                    }
                    Ok(())
                })
                .status()
                .context(format!("Unable to execute {}", cmd))?
        }))
    }

    pub fn mount_devfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
        let cmd = "/sbin/mount_devfs";
        Ok(Some(
            Command::new(cmd)
                .arg("devfs")
                .args(opts)
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    pub fn mount_fdfs(
        &self,
        _src: &Path,
        _dest: &Path,
        _opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        bail!("fd mounts are not supported on macOS");
    }

    pub fn mount_nfs(
        &self,
        src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
        let cmd = "/sbin/mount_nfs";
        Ok(Some(
            Command::new(cmd)
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
        _dest: &Path,
        _opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        bail!("procfs mounts are not supported on macOS");
    }

    pub fn mount_tmpfs(
        &self,
        _src: &Path,
        dest: &Path,
        opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        fs::create_dir_all(dest).with_context(|| format!("Failed to create {}", dest.display()))?;
        let cmd = "/sbin/mount_tmpfs";
        Ok(Some(
            Command::new(cmd)
                .args(opts)
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    /*
     * General unmount routine common to file system types that involve
     * mounted file systems.
     *
     * Uses diskutil unmount with retries (every second, up to 3 minutes).
     * Use process_group(0) to put diskutil in its own process group,
     * preventing it from receiving SIGINT when the user presses Ctrl+C.
     */
    fn unmount_common(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        let cmd = "/usr/sbin/diskutil";
        let max_retries = 180;
        let mut last_status = None;

        for attempt in 0..max_retries {
            let status = Command::new(cmd)
                .arg("unmount")
                .arg(dest)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?;

            if status.success() {
                if attempt > 0 {
                    debug!(
                        path = %dest.display(),
                        retries = attempt,
                        "Unmount succeeded after retries"
                    );
                }
                return Ok(Some(status));
            }

            last_status = Some(status);

            if attempt < max_retries - 1 {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }

        Ok(last_status)
    }

    pub fn unmount_bindfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_devfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        let cmd = "/sbin/umount";
        Ok(Some(
            Command::new(cmd)
                .arg(dest)
                .process_group(0)
                .status()
                .context(format!("Unable to execute {}", cmd))?,
        ))
    }

    /* Not actually supported but try to unmount it anyway. */
    pub fn unmount_fdfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_nfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    /* Not actually supported but try to unmount it anyway. */
    pub fn unmount_procfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    pub fn unmount_tmpfs(&self, dest: &Path) -> anyhow::Result<Option<ExitStatus>> {
        self.unmount_common(dest)
    }

    /**
     * Configure mDNSResponder to listen on a Unix socket inside the sandbox,
     * enabling DNS resolution within the chroot.
     *
     * macOS does not support name resolution inside a chroot by default
     * because the mDNSResponder listening socket is not available.  This
     * method modifies the mDNSResponder launchd plist to add an additional
     * Unix socket listener inside the sandbox.
     *
     * Uses a lock directory for concurrency safety when multiple sandboxes
     * are being created simultaneously.
     */
    pub fn create_mdns_listener(&self, id: usize) -> anyhow::Result<()> {
        let sandbox_path = self.path(id);
        let sock_path = sandbox_path.join("var/run/mDNSResponder");
        let plist = Path::new("/var/run/com.apple.mDNSResponder.plist");
        let plist_system = Path::new("/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist");
        let pb = Path::new("/usr/libexec/PlistBuddy");
        let entry = "Sockets:Listeners";

        fs::create_dir_all(sandbox_path.join("var/run"))?;

        let add_plist = sandbox_path.join("var/run/add.plist");
        fs::write(
            &add_plist,
            format!(
                "<array>\n\
                 \t<dict>\n\
                 \t\t<key>SockFamily</key>\n\
                 \t\t<string>Unix</string>\n\
                 \t\t<key>SockPathName</key>\n\
                 \t\t<string>{}</string>\n\
                 \t\t<key>SockPathMode</key>\n\
                 \t\t<integer>438</integer>\n\
                 \t</dict>\n\
                 </array>\n",
                sock_path.display()
            ),
        )?;

        let lock = Path::new("/tmp/updatemdns.lock");
        let _guard = MdnsLock::acquire(lock)?;

        if !plist.exists() {
            fs::copy(plist_system, plist).with_context(|| {
                format!(
                    "Failed to copy {} to {}",
                    plist_system.display(),
                    plist.display()
                )
            })?;

            let import_plist = sandbox_path.join("var/run/import.plist");
            let output = Command::new(pb)
                .args([
                    "-x",
                    "-c",
                    &format!("Print {entry}"),
                    &plist.display().to_string(),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .output()
                .context("Failed to run PlistBuddy")?;
            if !output.status.success() {
                bail!(
                    "PlistBuddy Print failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            fs::write(&import_plist, &output.stdout)?;

            let plist_str = plist.display().to_string();
            let import_str = import_plist.display().to_string();
            let status = Command::new(pb)
                .args([
                    "-c",
                    &format!("Delete {entry}"),
                    "-c",
                    &format!("Add {entry} array"),
                    "-c",
                    &format!("Add {entry}:0 dict"),
                    "-c",
                    &format!("Merge {import_str} {entry}:0"),
                    "-c",
                    "Save",
                    &plist_str,
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .process_group(0)
                .status()
                .context("Failed to run PlistBuddy")?;
            if !status.success() {
                bail!("PlistBuddy failed to convert Listeners to array");
            }
            let _ = fs::remove_file(&import_plist);

            let _ = Command::new("/bin/launchctl")
                .args(["unload", &plist_system.display().to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .status();
            let status = Command::new("/bin/launchctl")
                .args(["load", "-w", &plist_str])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .process_group(0)
                .status()
                .context("Failed to run launchctl load")?;
            if !status.success() {
                bail!("launchctl load failed for {}", plist.display());
            }
        }

        let plist_str = plist.display().to_string();
        let status = Command::new(pb)
            .args([
                "-c",
                &format!("Merge {} {entry}", add_plist.display()),
                &plist_str,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0)
            .status()
            .context("Failed to run PlistBuddy")?;
        if !status.success() {
            bail!("PlistBuddy Merge failed");
        }

        Self::reload_mdns(plist)?;
        let _ = fs::remove_file(&add_plist);
        Ok(())
    }

    /**
     * Remove the mDNSResponder listener socket for this sandbox.
     */
    pub fn destroy_mdns_listener(&self, id: usize) -> anyhow::Result<()> {
        let sandbox_path = self.path(id);
        let sock_path = sandbox_path.join("var/run/mDNSResponder");
        let plist = Path::new("/var/run/com.apple.mDNSResponder.plist");
        let pb = Path::new("/usr/libexec/PlistBuddy");
        let entry = "Sockets:Listeners";

        if !plist.exists() {
            return Ok(());
        }

        let lock = Path::new("/tmp/updatemdns.lock");
        let _guard = MdnsLock::acquire(lock)?;

        let output = Command::new(pb)
            .args([
                "-c",
                &format!("Print {entry}"),
                &plist.display().to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .output()
            .context("Failed to run PlistBuddy")?;
        if !output.status.success() {
            return Ok(());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let entries: Vec<_> = stdout.lines().filter(|l| l.contains("Dict {")).collect();
        let sock_str = sock_path.display().to_string();
        let plist_str = plist.display().to_string();

        for i in 0..entries.len() {
            let output = Command::new(pb)
                .args(["-c", &format!("Print {entry}:{i}:SockPathName"), &plist_str])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .process_group(0)
                .output()?;
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if path == sock_str {
                let status = Command::new(pb)
                    .args(["-c", &format!("Delete {entry}:{i}"), &plist_str])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .process_group(0)
                    .status()?;
                if !status.success() {
                    warn!(sandbox = id, "Failed to remove mDNS listener entry");
                }
                break;
            }
        }

        Self::reload_mdns(plist)?;
        Ok(())
    }

    /**
     * Unload and reload the mDNSResponder plist.
     */
    fn reload_mdns(plist: &Path) -> anyhow::Result<()> {
        let plist_str = plist.display().to_string();
        let _ = Command::new("/bin/launchctl")
            .args(["unload", &plist_str])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .status();
        let status = Command::new("/bin/launchctl")
            .args(["load", "-w", &plist_str])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0)
            .status()
            .context("Failed to run launchctl")?;
        if !status.success() {
            bail!("launchctl load failed for {}", plist.display());
        }
        Ok(())
    }

    /**
     * Find PIDs of processes using files under the sandbox path.
     *
     * Uses `fuser` which matches by path, not filesystem.  Filters out
     * system daemons (Spotlight, notification services, etc.) that hold
     * file handles but must not be killed.
     */
    pub(super) fn find_pids(&self, sandbox: &Path) -> Vec<String> {
        const SKIP_LIST: &[&str] = &[
            "kextd",
            "mds",
            "mds_stores",
            "mdworker",
            "mdworker_shared",
            "notifyd",
        ];

        let output = Command::new("fuser")
            .arg(sandbox)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .output();
        let Ok(out) = output else { return vec![] };
        if !out.status.success() {
            return vec![];
        }
        let pids: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        if pids.is_empty() {
            return vec![];
        }

        let ps_output = Command::new("ps")
            .arg("-o")
            .arg("pid=,comm=")
            .arg("-p")
            .arg(pids.join(","))
            .process_group(0)
            .output();
        let Ok(ps_out) = ps_output else { return pids };

        String::from_utf8_lossy(&ps_out.stdout)
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let pid = parts.next()?;
                let comm = parts.next()?;
                if SKIP_LIST.contains(&comm) {
                    debug!(pid, name = comm, "Skipping protected process");
                    None
                } else {
                    Some(pid.to_string())
                }
            })
            .collect()
    }
}

/**
 * RAII lock guard for mDNSResponder plist modification.
 *
 * Uses `mkdir` for atomic lock acquisition.  Automatically removes the
 * lock directory on drop.
 */
struct MdnsLock {
    path: PathBuf,
}

impl MdnsLock {
    fn acquire(path: &Path) -> anyhow::Result<Self> {
        use std::hash::BuildHasher;
        let max_retries = 60;
        let hasher = std::collections::hash_map::RandomState::new();
        for attempt in 1..=max_retries {
            if fs::create_dir(path).is_ok() {
                return Ok(Self {
                    path: path.to_path_buf(),
                });
            }
            if attempt < max_retries {
                let ms = 500 + (hasher.hash_one(attempt) % 500);
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
        }
        bail!(
            "Failed to acquire mDNS lock at {} after {} attempts",
            path.display(),
            max_retries
        );
    }
}

impl Drop for MdnsLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}
