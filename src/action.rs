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

//! Sandbox action configuration.
//!
//! This module defines the types used to configure sandbox setup and per-build
//! actions.  Actions are specified in the `sandboxes.setup` and
//! `sandboxes.build` tables of the Lua configuration file.
//!
//! # Action Types
//!
//! Five action types are supported:
//!
//! - **mount**: Mount a filesystem inside the sandbox
//! - **copy**: Copy files or directories into the sandbox
//! - **symlink**: Create a symbolic link inside the sandbox
//! - **cmd**: Execute shell commands during setup/teardown
//! - **macos-mdns-listener**: Configure macOS DNS resolution (no-op elsewhere)
//!
//! # Execution Order
//!
//! Actions are processed in order during sandbox creation, and in reverse order
//! during sandbox destruction.
//!
//! # Configuration Examples
//!
//! ```lua
//! sandboxes = {
//!     basedir = "/data/chroot",
//!     setup = {
//!         -- Mount procfs
//!         { action = "mount", fs = "proc", dir = "/proc" },
//!
//!         -- Mount devfs
//!         { action = "mount", fs = "dev", dir = "/dev" },
//!
//!         -- Mount tmpfs with size limit
//!         { action = "mount", fs = "tmp", dir = "/tmp", opts = "size=1G" },
//!
//!         -- Read-only bind mount from host
//!         { action = "mount", fs = "bind", dir = "/usr/bin", opts = "ro" },
//!
//!         -- Copy /etc into sandbox
//!         { action = "copy", dir = "/etc" },
//!
//!         -- Create symbolic link
//!         { action = "symlink", src = "usr/bin", dest = "/bin" },
//!
//!         -- Run command inside sandbox via chroot
//!         { action = "cmd", chroot = true, create = "mkdir -m 1777 /var/tmp" },
//!
//!         -- Run command on host (working directory is sandbox root on host)
//!         { action = "cmd", create = "touch .stamp" },
//!
//!         -- Run different commands on create and destroy
//!         { action = "cmd", chroot = true,
//!           create = "mkdir -p /home/builder",
//!           destroy = "rm -rf /home/builder" },
//!
//!         -- Only mount if source exists on host
//!         { action = "mount", fs = "bind", dir = "/opt/local",
//!           only = { exists = "/opt/local" } },
//!
//!         -- Only run if pkgsrc.build_user is set
//!         { action = "cmd", chroot = true,
//!           only = { set = "pkgsrc.build_user" },
//!           create = [[
//!                 mkdir -p ${bob_build_user_home}
//!                 chown ${bob_build_user} ${bob_build_user_home}
//!           ]],
//!           destroy = "rm -rf ${bob_build_user_home}" },
//!
//!         -- Only run for `bob sandbox shell` interactive sessions
//!         { action = "copy", src = os.getenv("HOME") .. "/.vimrc",
//!           dest = "/root/.vimrc",
//!           only = { environment = "dev" } },
//!
//!         -- Enable DNS resolution inside sandbox (macOS only)
//!         { action = "macos-mdns-listener" },
//!     },
//! }
//! ```
//!
//! # Environment Variables
//!
//! Shell commands executed by `cmd` actions receive these `bob_*` environment
//! variables.  Sandbox actions always receive the base set; build actions
//! also receive the pkgsrc-derived variables once the bootstrap kit has been
//! unpacked.
//!
//! | Variable | Description |
//! |----------|-------------|
//! | `bob_logdir` | Path to the build logs directory. |
//! | `bob_make` | Path to the bmake binary. |
//! | `bob_pkgsrc` | Path to the pkgsrc source tree. |
//! | `bob_build_user` | Unprivileged build user (if configured). |
//! | `bob_build_user_home` | Home directory of the build user (if configured). |
//! | `bob_bootstrap` | Path to the bootstrap tarball (if configured). |
//! | `bob_sandbox_path` | Absolute host path to the sandbox root (non-chroot commands only). |
//! | `bob_sandbox_id` | Numeric sandbox id (`bob sandbox shell` only). |
//! | `bob_packages` | Path to the packages directory (after bootstrap). |
//! | `bob_pkgtools` | Path to the pkg tools directory (after bootstrap). |
//! | `bob_prefix` | Installation prefix (after bootstrap). |
//! | `bob_pkg_dbdir` | PKG_DBDIR from pkgsrc (after bootstrap). |
//! | `bob_pkg_refcount_dbdir` | PKG_REFCOUNT_DBDIR from pkgsrc (after bootstrap). |
//!
//! Any variables listed in `pkgsrc.cachevars` are also available.
//!
//! # Common Fields
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `dir` | string | Shorthand when `src` and `dest` are the same path |
//! | `src` | string | Source path on the host system |
//! | `dest` | string | Destination path inside the sandbox |
//! | `only` | table | Conditional predicates restricting when this action runs.  See [Conditional Actions](#conditional-actions). |
//!
//! # Conditional Actions
//!
//! Any action may include an `only = { ... }` table whose entries restrict
//! when the action runs.  All present predicates must match for the action
//! to be applied; an action without `only` runs unconditionally.
//!
//! | Predicate | Type | Description |
//! |-----------|------|-------------|
//! | `environment` | string | `"build"` to run only for automated build operations, or `"dev"` to run only for `bob sandbox shell` interactive sessions.  Mirrors the `sandboxes.environment.{build,dev}` distinction. |
//! | `set` | string | Dotted Lua config path (e.g. `"pkgsrc.build_user"`).  Action is dropped at config load time if the variable is not set. |
//! | `exists` | string | Host filesystem path.  Action is skipped at run time if the path does not exist. |

use anyhow::{Context, Error, bail};
use mlua::{Result as LuaResult, Table};
use std::path::PathBuf;
use std::str::FromStr;

/// The execution context of a sandbox operation.
///
/// Actions can be conditionally restricted to one context via the
/// `only.context` field.  Actions without an `only.context` predicate
/// run in both contexts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ActionContext {
    /// Automated build operations (`bob build`, `bob sandbox create`,
    /// `bob sandbox destroy`).
    #[default]
    Build,
    /// Interactive `bob sandbox shell` sessions.
    Dev,
}

/// Runtime predicates for an action's `only = { ... }` table.
///
/// All present predicates must match for the action to run.  An empty
/// `Only` (the default) imposes no restrictions.
///
/// The `set` predicate (a dotted Lua config-var path) is checked at
/// config parse time, and actions whose `set` is unsatisfied are dropped
/// before they ever reach the runner.  Only `environment` and `exists`
/// are stored here for runtime evaluation.
#[derive(Clone, Debug, Default)]
pub struct Only {
    /// If set, the action only runs in this execution environment.
    /// Mirrors the `environment.build` / `environment.dev` distinction
    /// from the sandbox config.
    pub environment: Option<ActionContext>,
    /// If set, the action only runs when this host path exists at the
    /// time the action runner reaches it.
    pub exists: Option<PathBuf>,
}

impl Only {
    /// Returns true if the action should run in the given environment.
    pub fn matches(&self, env: ActionContext) -> bool {
        if let Some(want) = self.environment {
            if want != env {
                return false;
            }
        }
        if let Some(path) = &self.exists {
            if !path.exists() {
                return false;
            }
        }
        true
    }
}

/// A sandbox action configuration.
///
/// Actions define how sandboxes are set up and torn down. Each action specifies
/// an operation to perform (mount, copy, symlink, or cmd) along with the
/// parameters needed for that operation.
///
/// Actions are processed in order during sandbox creation and in reverse order
/// during destruction.
///
/// # Fields
///
/// The available fields depend on the action type:
///
/// ## Mount Actions
///
/// | Field | Required | Description |
/// |-------|----------|-------------|
/// | `fs` | yes | Filesystem type (bind, dev, fd, nfs, proc, tmp) |
/// | `dir` or `src`/`dest` | yes | Mount point path |
/// | `opts` | no | Mount options (e.g., "ro", "size=1G") |
///
/// ## Copy Actions
///
/// | Field | Required | Description |
/// |-------|----------|-------------|
/// | `dir` or `src`/`dest` | yes | Path to copy |
///
/// ## Symlink Actions
///
/// | Field | Required | Description |
/// |-------|----------|-------------|
/// | `src` | yes | Link target (what the symlink points to) |
/// | `dest` | yes | Link name (the symlink itself) |
///
/// ## Cmd Actions
///
/// | Field | Required | Description |
/// |-------|----------|-------------|
/// | `create` | no | Command to run during sandbox creation |
/// | `destroy` | no | Command to run during sandbox destruction |
/// | `chroot` | no | If true, run command inside sandbox chroot (default: false) |
///
/// When `chroot = true`, commands run inside the sandbox via chroot with `/`
/// as the working directory. Use `cd /path &&` in the command if a different
/// working directory is needed.
///
/// When `chroot = false` (default), commands run on the host system with the
/// sandbox root as the working directory.
#[derive(Clone, Debug, Default)]
pub struct Action {
    action: String,
    fs: Option<String>,
    src: Option<PathBuf>,
    dest: Option<PathBuf>,
    opts: Option<String>,
    create: Option<String>,
    destroy: Option<String>,
    chroot: bool,
    only: Only,
}

/// The type of sandbox action to perform.
///
/// Used internally to dispatch action handling.
#[derive(Debug, PartialEq, strum::EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum ActionType {
    /// Mount a filesystem inside the sandbox.
    Mount,
    /// Copy files or directories from host into sandbox.
    Copy,
    /// Execute shell commands during creation and/or destruction.
    Cmd,
    /// Create a symbolic link inside the sandbox.
    Symlink,
    /// Configure macOS mDNSResponder for DNS resolution inside the sandbox.
    ///
    /// On create, adds a Unix socket listener to the mDNSResponder launchd
    /// plist so that DNS resolution works inside the chroot.  On destroy,
    /// removes the listener entry.  No-op on non-macOS platforms.
    ///
    /// No additional fields are required.
    #[strum(serialize = "macos-mdns-listener")]
    MacosMdnsListener,
}

/// Filesystem types for mount actions.
///
/// These map to platform-specific mount implementations. Not all filesystem
/// types are supported on all platforms; see individual variants for details.
///
/// # Filesystem Types
///
/// | Type | Aliases | Linux | macOS | NetBSD | illumos |
/// |------|---------|-------|-------|--------|---------|
/// | `bind` | `lofs`, `loop`, `null` | Yes | Yes | Yes | Yes |
/// | `dev` | | Yes | Yes | No | No |
/// | `fd` | | Yes | No | Yes | Yes |
/// | `nfs` | | Yes | Yes | Yes | Yes |
/// | `proc` | | Yes | No | Yes | Yes |
/// | `tmp` | | Yes | Yes | Yes | Yes |
#[derive(Debug, PartialEq, strum::EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum FSType {
    /// Bind mount from host filesystem.
    ///
    /// Makes a directory from the host visible inside the sandbox. Use
    /// `opts = "ro"` for read-only access.
    ///
    /// Aliases: `lofs`, `loop`, `null` (for cross-platform compatibility).
    ///
    /// | Platform | Implementation |
    /// |----------|----------------|
    /// | Linux | `mount -o bind` |
    /// | macOS | `bindfs` (requires installation) |
    /// | NetBSD | `mount_null` |
    /// | illumos | `mount -F lofs` |
    #[strum(
        serialize = "bind",
        serialize = "lofs",
        serialize = "loop",
        serialize = "null"
    )]
    Bind,

    /// Device filesystem.
    ///
    /// Provides `/dev` device nodes inside the sandbox.
    ///
    /// | Platform | Implementation |
    /// |----------|----------------|
    /// | Linux | `devtmpfs` |
    /// | macOS | `devfs` |
    /// | NetBSD | Not supported. Use a `cmd` action with `MAKEDEV` instead. |
    /// | illumos | Not supported. Use a `bind` mount of `/dev` instead. |
    Dev,

    /// File descriptor filesystem.
    ///
    /// Provides `/dev/fd` entries for accessing open file descriptors.
    ///
    /// | Platform | Implementation |
    /// |----------|----------------|
    /// | Linux | Bind mount of `/dev/fd` |
    /// | macOS | Not supported. |
    /// | NetBSD | `mount_fdesc` |
    /// | illumos | `mount -F fd` |
    Fd,

    /// Network File System mount.
    ///
    /// Mounts an NFS export inside the sandbox. The `src` field must be an
    /// NFS path in the form `host:/path`.
    ///
    /// | Platform | Implementation |
    /// |----------|----------------|
    /// | Linux | `mount -t nfs` |
    /// | macOS | `mount_nfs` |
    /// | NetBSD | `mount_nfs` |
    /// | illumos | `mount -F nfs` |
    Nfs,

    /// Process filesystem.
    ///
    /// Provides `/proc` entries for process information. Required by many
    /// build tools and commands.
    ///
    /// | Platform | Implementation |
    /// |----------|----------------|
    /// | Linux | `mount -t proc` |
    /// | macOS | Not supported. |
    /// | NetBSD | `mount_procfs` |
    /// | illumos | `mount -F proc` |
    Proc,

    /// Temporary filesystem.
    ///
    /// Memory-backed filesystem. Contents are lost when unmounted. Use
    /// `opts = "size=1G"` to limit size (Linux, NetBSD). Useful for `/tmp`
    /// and build directories.
    ///
    /// | Platform | Implementation |
    /// |----------|----------------|
    /// | Linux | `mount -t tmpfs` |
    /// | macOS | `mount_tmpfs` |
    /// | NetBSD | `mount_tmpfs` |
    /// | illumos | `mount -F tmpfs` |
    Tmp,
}

impl Action {
    pub fn from_lua(t: &Table) -> LuaResult<Self> {
        // "dir" can be used as shorthand when src and dest are the same
        let dir = t.get::<Option<String>>("dir")?.map(PathBuf::from);
        let src = t
            .get::<Option<String>>("src")?
            .map(PathBuf::from)
            .or_else(|| dir.clone());
        let dest = t
            .get::<Option<String>>("dest")?
            .map(PathBuf::from)
            .or_else(|| dir.clone());

        Ok(Self {
            action: t.get("action")?,
            fs: t.get("fs").ok(),
            src,
            dest,
            opts: t.get("opts").ok(),
            create: t.get("create").ok(),
            destroy: t.get("destroy").ok(),
            chroot: t.get("chroot").unwrap_or(false),
            only: Only::default(),
        })
    }

    /// Replace this action's runtime `only` predicate.  Used by
    /// `parse_actions` after it processes the parse-time `only.set`
    /// check.
    pub fn set_only(&mut self, only: Only) {
        self.only = only;
    }

    pub fn only(&self) -> &Only {
        &self.only
    }

    pub fn src(&self) -> Option<&PathBuf> {
        self.src.as_ref()
    }

    pub fn dest(&self) -> Option<&PathBuf> {
        self.dest.as_ref()
    }

    pub fn action_type(&self) -> Result<ActionType, Error> {
        ActionType::from_str(&self.action)
            .context(format!("unsupported action type '{}'", self.action))
    }

    pub fn fs_type(&self) -> Result<FSType, Error> {
        match &self.fs {
            Some(fs) => FSType::from_str(fs).context(format!("unsupported filesystem type '{fs}'")),
            None => bail!("'mount' action requires 'fs' field"),
        }
    }

    pub fn opts(&self) -> Option<&String> {
        self.opts.as_ref()
    }

    pub fn create_cmd(&self) -> Option<&String> {
        self.create.as_ref()
    }

    pub fn destroy_cmd(&self) -> Option<&String> {
        self.destroy.as_ref()
    }

    pub fn chroot(&self) -> bool {
        self.chroot
    }

    /// Validate the action configuration.
    /// Returns an error if the action is misconfigured.
    pub fn validate(&self) -> Result<(), Error> {
        let action_type = self.action_type()?;

        match action_type {
            ActionType::Cmd => {
                if self.create.is_none() && self.destroy.is_none() {
                    bail!("'cmd' action requires 'create' or 'destroy' command");
                }
            }
            ActionType::Mount => {
                // mount requires fs and either src or dest
                if self.fs.is_none() {
                    bail!("'mount' action requires 'fs' field");
                }
                self.fs_type()?; // Validate fs type
                if self.src.is_none() && self.dest.is_none() {
                    bail!("'mount' action requires 'src' or 'dest' path");
                }
            }
            ActionType::Copy => {
                // copy requires src or dest
                if self.src.is_none() && self.dest.is_none() {
                    bail!("'copy' action requires 'src' or 'dest' path");
                }
            }
            ActionType::Symlink => {
                // symlink requires both src and dest
                if self.src.is_none() {
                    bail!("'symlink' action requires 'src' (link target)");
                }
                if self.dest.is_none() {
                    bail!("'symlink' action requires 'dest' (link name)");
                }
            }
            ActionType::MacosMdnsListener => {}
        }

        Ok(())
    }
}
