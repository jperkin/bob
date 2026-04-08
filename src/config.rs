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

//! Configuration file parsing (Lua format).
//!
//! Bob uses Lua configuration files for maximum flexibility. The configuration
//! defines paths to pkgsrc, packages to build, sandbox setup, and per-build actions.
//!
//! # Configuration File Structure
//!
//! A configuration file has five main sections:
//!
//! - [`options`](#options-section) - General build options (optional)
//! - [`pkgsrc`](#pkgsrc-section) - pkgsrc paths and package list (required)
//! - [`sandboxes`](#sandboxes-section) - Sandbox configuration (optional)
//! - [`dynamic`](#dynamic-section) - Dynamic resource allocation (optional)
//! - [`publish`](#publish-section) - Remote publishing configuration (optional)
//!
//! # Options Section
//!
//! The `options` section is optional. All fields have defaults.
//!
//! | Field | Type | Default | Description |
//! |-------|------|---------|-------------|
//! | `build_threads` | integer | 1 | Number of parallel build sandboxes. Each sandbox builds one package at a time. |
//! | `dbdir` | string | "./db" | Directory for bob state files (database, tracing log). Relative to config file directory. |
//! | `logdir` | string | `dbdir/logs` | Directory for per-package build logs. Failed builds leave logs here; successful builds clean up. |
//! | `scan_threads` | integer | 1 | Number of parallel scan processes for dependency discovery. |
//! | `strict_scan` | boolean | false | If true, abort on scan errors. If false, continue and report failures separately. |
//! | `log_level` | string | "info" | Log level: "trace", "debug", "info", "warn", or "error". Can be overridden by `RUST_LOG` env var. |
//!
//! # Pkgsrc Section
//!
//! The `pkgsrc` section is required and defines paths to pkgsrc components.
//!
//! ## Required Fields
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `basedir` | string | Absolute path to the pkgsrc source tree (e.g., `/data/pkgsrc`). |
//! | `make` | string | Absolute path to the bmake binary (e.g., `/usr/pkg/bin/bmake`). |
//!
//! ## Optional Fields
//!
//! | Field | Type | Default | Description |
//! |-------|------|---------|-------------|
//! | `bootstrap` | string | none | Path to a bootstrap tarball. Required on non-NetBSD systems. Unpacked into each sandbox before builds. |
//! | `build_user` | string | none | Unprivileged user to run builds as. If set, builds run as this user instead of root. |
//! | `cachevars` | table | (OS-specific) | List of pkgsrc variable names to fetch once and cache. These are set in the environment for scans and builds. If set, replaces the built-in defaults. |
//! | `pkgpaths` | table | `{}` | List of package paths to build (e.g., `{"mail/mutt", "www/curl"}`). Dependencies are discovered automatically. |
//! | `save_wrkdir_patterns` | table | `{}` | Glob patterns for files to preserve from WRKDIR on build failure (e.g., `{"**/config.log"}`). |
//!
//! Per-package make variables should be set in pkgsrc's `mk.conf`, not in
//! bob.  Bob does not provide a per-package environment override mechanism.
//!
//! # Sandboxes Section
//!
//! The `sandboxes` section is optional. When present, builds run in isolated
//! chroot environments.
//!
//! | Field | Type | Required | Description |
//! |-------|------|----------|-------------|
//! | `basedir` | string | yes | Base directory for sandbox roots. Sandboxes are created as numbered subdirectories (`basedir/0`, `basedir/1`, etc.). |
//! | `setup` | table | no | Actions to perform during sandbox creation and destruction. See the [`action`](crate::action) module for details. |
//! | `hooks` | table | no | Per-package hook actions. Any "create" action runs after bob's internal pre-build (unpacks bootstrap kit if needed); any "destroy" action runs before bob's internal post-build (wipes PREFIX and PKG_DBDIR). |
//! | `environment` | table | no | Environment variables for sandbox processes. If omitted, the parent environment is inherited unchanged. See [Environment](#environment). |
//!
//! ## Environment
//!
//! Controls how environment variables are set for processes running inside
//! sandboxes.  When this section is omitted, sandbox processes inherit bob's
//! parent environment unchanged.
//!
//! `environment` contains two independent sub-tables, `build` and `dev`,
//! one for each context bob runs processes in.  They have an identical
//! shape (`clear`, `inherit`, `vars`) but are configured separately so
//! that interactive development conveniences cannot leak into automated
//! builds.  Either sub-table can be omitted; an omitted context inherits
//! bob's parent environment unchanged.
//!
//! - `build` is used by every operation that `bob build` performs: sandbox
//!   setup, pre- and post-build hooks, and the package builds themselves.
//!   Values are passed directly to each process as literal strings; no
//!   shell ever evaluates them.  This context typically wants a strict,
//!   minimal environment for build reproducibility.
//!
//! - `dev` is used only by interactive `bob sandbox shell` sessions.
//!   Bob writes the values into a small init script
//!   (`<sandbox>/.bob/shell-init`) that the chrooted shell runs at startup,
//!   one `export NAME=value` line per entry.  Each value is emitted
//!   verbatim, so what you write must be a valid shell assignment
//!   right-hand side -- in particular, values containing whitespace or
//!   shell metacharacters need to be quoted by the user.  Values can
//!   reference `bob_*` variables (or any other shell variables) using
//!   ordinary shell syntax, for example `PATH = "${bob_prefix}/bin:..."`.
//!   This context typically wants a more generous `inherit` list (e.g.
//!   `EDITOR`, `PAGER`, locale variables) than `build`, since interactive
//!   sessions benefit from the developer's normal environment.  See the
//!   [`action`](crate::action) module for the full list of `bob_*`
//!   variables.
//!
//! Each `build`/`dev` sub-table has the following fields:
//!
//! | Field | Type | Default | Description |
//! |-------|------|---------|-------------|
//! | `clear` | boolean | `true` | Start each sandbox process with an empty environment.  Set to `false` to inherit bob's full parent environment instead. |
//! | `inherit` | table | `{}` | When `clear` is `true`, names of variables to copy from bob's parent environment. |
//! | `vars` | table | `{}` | Variables to set in this context.  In `build` these are literal strings; in `dev` they are written verbatim into the init script. |
//!
//! The `dev` sub-table additionally accepts:
//!
//! | Field | Type | Default | Description |
//! |-------|------|---------|-------------|
//! | `shell` | string | `/bin/sh` | Path to the interactive shell binary used for the dev session.  The path is resolved inside the sandbox chroot, so the binary must exist there (typically arranged by a `setup` action that mounts or copies it). |

use crate::action::Action;
use crate::sandbox::Sandbox;
use anyhow::{Context, Result, anyhow, bail};
use mlua::{Lua, Result as LuaResult, Table, Value};
use pkgsrc::PkgPath;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

/// Environment variables retrieved from pkgsrc.
///
/// These values are queried from pkgsrc's mk.conf via bmake and represent
/// the actual paths pkgsrc is configured to use. This struct is created
/// after sandbox setup and passed to build operations.
#[derive(Clone, Debug)]
pub struct PkgsrcEnv {
    /// PACKAGES directory for binary packages.
    pub packages: PathBuf,
    /// PKG_TOOLS_BIN directory containing pkg_add, pkg_delete, etc.
    pub pkgtools: PathBuf,
    /// PREFIX installation directory.
    pub prefix: PathBuf,
    /// PKG_DBDIR for installed package database.
    pub pkg_dbdir: PathBuf,
    /// PKG_REFCOUNT_DBDIR for refcounted files database.
    pub pkg_refcount_dbdir: PathBuf,
    /// Platform and build metadata from pkgsrc (non-empty values only).
    pub metadata: HashMap<String, String>,
    /// Cached pkgsrc variables from the `cachevars` config option.
    pub cachevars: HashMap<String, String>,
}

impl PkgsrcEnv {
    /// Fetch pkgsrc environment variables by querying bmake.
    ///
    /// This must be called after sandbox 0 is created if sandboxes are enabled,
    /// since bmake may only exist inside the sandbox.
    pub fn fetch(config: &Config, sandbox: &Sandbox, id: Option<usize>) -> Result<Self> {
        const REQUIRED_VARS: &[&str] = &[
            "PACKAGES",
            "PKG_DBDIR",
            "PKG_REFCOUNT_DBDIR",
            "PKG_TOOLS_BIN",
            "PREFIX",
        ];

        const METADATA_VARS: &[&str] = &[
            "ABI",
            "CC_VERSION",
            "LOWER_VARIANT_VERSION",
            "MACHINE_ARCH",
            "OPSYS",
            "OS_VARIANT",
            "OS_VERSION",
            "PKGINFODIR",
            "PKGMANDIR",
            "PKGSRC_COMPILER",
            "SYSCONFBASE",
            "VARBASE",
        ];

        let cachevar_names: Vec<&str> = if !config.cachevars().is_empty() {
            config.cachevars().iter().map(|s| s.as_str()).collect()
        } else {
            let mut v = vec!["NATIVE_OPSYS", "NATIVE_OPSYS_VERSION", "NATIVE_OS_VERSION"];
            if cfg!(target_os = "netbsd") {
                v.push("HOST_MACHINE_ARCH");
            }
            if cfg!(any(target_os = "illumos", target_os = "solaris")) {
                v.push("_UNAME_V");
            }
            v
        };

        let mut all_varnames: Vec<&str> = REQUIRED_VARS.to_vec();
        all_varnames.extend_from_slice(METADATA_VARS);
        all_varnames.extend_from_slice(&cachevar_names);

        let varnames_arg = all_varnames.join(" ");
        let script = format!(
            "cd {}/pkgtools/pkg_install && {} show-vars VARNAMES=\"{}\"\n",
            config.pkgsrc().display(),
            config.make().display(),
            varnames_arg
        );

        let child = sandbox.execute_script(id, &script, vec![])?;
        let output = child
            .wait_with_output()
            .context("Failed to execute bmake show-vars")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to query pkgsrc variables: {}", stderr.trim());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();

        if lines.len() != all_varnames.len() {
            bail!(
                "Expected {} variables from pkgsrc, got {}",
                all_varnames.len(),
                lines.len()
            );
        }

        let mut values: HashMap<&str, &str> = HashMap::new();
        for (varname, value) in all_varnames.iter().zip(&lines) {
            values.insert(varname, value);
        }

        for varname in REQUIRED_VARS {
            if values.get(varname).is_none_or(|v| v.is_empty()) {
                bail!("pkgsrc returned empty value for {}", varname);
            }
        }

        let mut metadata: HashMap<String, String> = HashMap::new();
        for varname in METADATA_VARS {
            if let Some(value) = values.get(varname) {
                if !value.is_empty() {
                    metadata.insert((*varname).to_string(), (*value).to_string());
                }
            }
        }

        let mut cachevars: HashMap<String, String> = HashMap::new();
        for varname in &cachevar_names {
            if let Some(value) = values.get(varname) {
                if !value.is_empty() {
                    cachevars.insert((*varname).to_string(), (*value).to_string());
                }
            }
        }

        Ok(PkgsrcEnv {
            packages: PathBuf::from(values["PACKAGES"]),
            pkgtools: PathBuf::from(values["PKG_TOOLS_BIN"]),
            prefix: PathBuf::from(values["PREFIX"]),
            pkg_dbdir: PathBuf::from(values["PKG_DBDIR"]),
            pkg_refcount_dbdir: PathBuf::from(values["PKG_REFCOUNT_DBDIR"]),
            metadata,
            cachevars,
        })
    }

    /// Derive the platform string from metadata variables.
    ///
    /// Uses OS_VARIANT if available (e.g., "SmartOS 20241212T000748Z/x86_64"),
    /// otherwise falls back to OPSYS (e.g., "NetBSD 10.1/x86_64").
    /// Returns None if the required variables are not available.
    pub fn platform(&self) -> Option<String> {
        let arch = self.metadata.get("MACHINE_ARCH")?;
        if let (Some(variant), Some(version)) = (
            self.metadata.get("OS_VARIANT"),
            self.metadata.get("LOWER_VARIANT_VERSION"),
        ) {
            Some(format!("{} {}/{}", variant, version, arch))
        } else {
            let opsys = self.metadata.get("OPSYS")?;
            let version = self.metadata.get("OS_VERSION")?;
            Some(format!("{} {}/{}", opsys, version, arch))
        }
    }
}

/// Main configuration structure.
#[derive(Clone, Debug, Default)]
pub struct Config {
    file: ConfigFile,
    dbdir: PathBuf,
    logdir: PathBuf,
    log_level: String,
}

/// Parsed configuration file contents.
#[derive(Clone, Debug, Default)]
pub struct ConfigFile {
    /// The `options` section.
    pub options: Option<Options>,
    /// The `pkgsrc` section.
    pub pkgsrc: Pkgsrc,
    /// The `sandboxes` section.
    pub sandboxes: Option<Sandboxes>,
    /// The `dynamic` section.
    pub dynamic: Option<DynamicConfig>,
    /// The `publish` section.
    pub publish: Option<Publish>,
}

/// General build options from the `options` section.
///
/// All fields are optional; defaults are used when not specified:
/// - `build_threads`: 1
/// - `scan_threads`: 1
/// - `log_level`: "info"
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Number of parallel build sandboxes.
    pub build_threads: Option<usize>,
    /// Directory for bob state files (database, tracing log).
    pub dbdir: Option<PathBuf>,
    /// Directory for build logs (defaults to `dbdir/logs`).
    pub logdir: Option<PathBuf>,
    /// Number of parallel scan processes.
    pub scan_threads: Option<usize>,
    /// If true, abort on scan errors. If false, continue and report failures.
    pub strict_scan: Option<bool>,
    /// Log level: "trace", "debug", "info", "warn", or "error".
    pub log_level: Option<String>,
    /// Enable TUI progress display (default: true). Set to false for plain output.
    pub tui: Option<bool>,
}

/// Dynamic resource allocation from the `dynamic` section.
///
/// Controls dynamic CPU and disk allocation informed by build history.
///
/// - `jobs`: Total MAKE_JOBS budget to distribute across concurrent builds.
///   Set this to the number of available CPU threads.  The allocator will
///   slightly over-allocate to ensure optimal throughput during serial
///   build phases.
/// - `wrkobjdir`: Optional automatic WRKOBJDIR selection based on historical
///   disk usage, routing large builds to disk and small builds to tmpfs.
#[derive(Clone, Debug)]
pub struct DynamicConfig {
    /// Total MAKE_JOBS budget.
    pub jobs: Option<usize>,
    /// Optional WRKOBJDIR routing based on historical disk usage.
    pub wrkobjdir: Option<WrkObjDir>,
}

/// WRKOBJDIR routing configuration.
///
/// When both `tmpfs` and `disk` are set with a `threshold`, packages
/// whose historical disk usage exceeds `threshold` build in `disk`
/// and everything else builds in `tmpfs`.  When only one path is set,
/// all builds use that path.
#[derive(Clone, Debug)]
pub struct WrkObjDir {
    /// Fast (tmpfs) WRKOBJDIR for builds under threshold.
    pub tmpfs: Option<PathBuf>,
    /// Disk-backed WRKOBJDIR for large builds.
    pub disk: Option<PathBuf>,
    /// Size threshold in bytes for routing between tmpfs and disk.
    pub threshold: Option<u64>,
    /// Use historical disk usage for routing even when the previous
    /// build failed.  Without this, a failed build always routes to
    /// disk regardless of recorded size.
    pub use_failed_history: bool,
}

impl WrkObjDir {
    /// Route a package to tmpfs or disk based on historical disk usage.
    pub fn route(&self, disk_usage: Option<u64>) -> Option<WrkObjKind> {
        match (&self.tmpfs, &self.disk, self.threshold) {
            (Some(tmpfs), Some(disk), Some(threshold)) => match disk_usage {
                Some(size) if size <= threshold => Some(WrkObjKind::Tmpfs(tmpfs.clone())),
                _ => Some(WrkObjKind::Disk(disk.clone())),
            },
            (Some(dir), None, _) => Some(WrkObjKind::Tmpfs(dir.clone())),
            (None, Some(dir), _) => Some(WrkObjKind::Disk(dir.clone())),
            _ => None,
        }
    }
}

/**
 * A resolved WRKOBJDIR assignment for a single package.
 */
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, strum::Display, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum WrkObjKind {
    Tmpfs(PathBuf),
    Disk(PathBuf),
}

impl WrkObjKind {
    pub fn path(&self) -> &Path {
        match self {
            Self::Tmpfs(p) | Self::Disk(p) => p,
        }
    }
}

/// Publishing configuration from the `publish` section.
///
/// Controls how binary packages and reports are published to remote servers.
/// Each sub-section configures its own rsync arguments since the appropriate
/// defaults differ: binary packages are already compressed and don't benefit
/// from rsync's `-z`, while text-heavy report directories do.
#[derive(Clone, Debug)]
pub struct Publish {
    /// Path to rsync binary (default: "rsync").
    pub rsync: PathBuf,
    /// Package publishing configuration.
    pub packages: Option<PublishPackages>,
    /// Report publishing configuration.
    pub report: Option<PublishReport>,
}

/// Package publishing configuration.
///
/// Supports two modes:
///
/// - **Direct**: `tmppath` is unset.  rsync writes straight to `path`.
/// - **Atomic**: `tmppath` is set.  rsync writes to `tmppath` with
///   `--link-dest=path` (unchanged files become hardlinks), then a
///   shell script (`swapcmd`) atomically swaps `tmppath` into `path`.
///
/// Restricted packages (NO_BIN_ON_FTP) are automatically excluded.
#[derive(Clone, Debug)]
pub struct PublishPackages {
    /// Remote hostname.
    pub host: String,
    /// Remote user (if unset, relies on ssh config).
    pub user: Option<String>,
    /// Remote path to the live published directory.
    pub path: String,
    /// Optional remote path for staging during sync.  If set, enables
    /// atomic-swap mode: rsync writes here with `--link-dest=path`,
    /// then `swapcmd` moves it into place.
    pub tmppath: Option<String>,
    /// Optional shell script run via ssh on the remote host after rsync
    /// completes.  Only meaningful when `tmppath` is set.  Either a
    /// literal string or a [`ScriptValue`] bundling the script with
    /// environment variables.
    pub swapcmd: Option<ScriptValue>,
    /// Minimum successful package count required before publishing.
    pub minimum: Option<usize>,
    /// Glob patterns that must match at least one successful package.
    pub required: Vec<String>,
    /// rsync arguments for package publishing.  Default
    /// `"-av --delete-excluded -e ssh"`: no `-z` since binary packages
    /// are already compressed.
    pub rsync_args: String,
}

/// Report publishing configuration.
#[derive(Clone, Debug)]
pub struct PublishReport {
    /// Remote hostname.
    pub host: String,
    /// Remote user (if unset, relies on ssh config).
    pub user: Option<String>,
    /// Remote directory path for report upload.
    pub path: String,
    /// Public URL where the report is accessible.
    pub url: Option<String>,
    /// rsync arguments for report publishing.  Default
    /// `"-avz --delete-excluded -e ssh"`: includes `-z` since reports
    /// are mostly text and benefit from compression.
    pub rsync_args: String,
    /// Override auto-detected branch name for reports and email.
    pub branch: Option<String>,
    /// Email sender in "Name <addr>" format.
    pub from: Option<String>,
    /// Email recipients.
    pub to: Vec<String>,
}

/// pkgsrc-related configuration from the `pkgsrc` section.
///
/// # Required Fields
///
/// - `basedir`: Path to pkgsrc source tree
/// - `make`: Path to bmake binary
///
/// # Optional Fields
///
/// - `bootstrap`: Path to bootstrap tarball (required on non-NetBSD systems)
/// - `build_user`: Unprivileged user for builds
/// - `pkgpaths`: List of packages to build
/// - `save_wrkdir_patterns`: Glob patterns for files to save on build failure
#[derive(Clone, Debug, Default)]
pub struct Pkgsrc {
    /// Path to pkgsrc source tree.
    pub basedir: PathBuf,
    /// Path to bootstrap tarball (required on non-NetBSD).
    pub bootstrap: Option<PathBuf>,
    /// Unprivileged user for builds.
    pub build_user: Option<String>,
    /// Home directory of build_user (resolved from password database).
    pub build_user_home: Option<PathBuf>,
    /// Path to bmake binary.
    pub make: PathBuf,
    /// List of packages to build.
    pub pkgpaths: Option<Vec<PkgPath>>,
    /// Glob patterns for files to save from WRKDIR on failure.
    pub save_wrkdir_patterns: Vec<String>,
    /// pkgsrc variables to cache and re-set in each environment run.
    pub cachevars: Vec<String>,
}

/// Environment configuration from `sandboxes.environment`.
///
/// Wraps two independent per-context configurations: `build` (for every
/// operation driven by `bob build`) and `dev` (for interactive sandbox
/// sessions used during pkgsrc development).  See the module-level
/// documentation for the full description.
///
/// Either context can be `None`, meaning bob's parent environment is
/// inherited unchanged for that context.
#[derive(Clone, Debug, Default)]
pub struct Environment {
    /// Build-time environment context.  When `None`, bob's parent
    /// environment is inherited unchanged for build operations.
    pub build: Option<EnvContext>,
    /// Interactive (dev) environment context.  When `None`, bob's
    /// parent environment is inherited unchanged for the interactive
    /// session.
    pub dev: Option<EnvContext>,
}

/// A single environment context (`environment.build` or `environment.dev`).
///
/// Each context has its own `clear`/`inherit`/`vars` policy so that the
/// build and dev contexts can be configured independently.
#[derive(Clone, Debug)]
pub struct EnvContext {
    /// Whether to start processes in this context with an empty
    /// environment.  Defaults to `true`.  When `false`, bob's full
    /// parent environment is inherited instead.
    pub clear: bool,
    /// When `clear` is `true`, names of variables to copy from bob's
    /// parent environment.
    pub inherit: Vec<String>,
    /// Variables to set in this context.  For `build`, values are
    /// literal strings.  For `dev`, values are written verbatim into
    /// the wrapper init script so they can reference `bob_*` and other
    /// shell variables but must be quoted by the user if they contain
    /// whitespace or shell metacharacters.
    pub vars: HashMap<String, String>,
    /// Path to the interactive shell binary for the dev sandbox
    /// session.  Only meaningful in `environment.dev`; ignored in
    /// `environment.build`.  Defaults to `/bin/sh`.  The path is
    /// resolved inside the sandbox chroot.
    pub shell: Option<PathBuf>,
}

impl Default for EnvContext {
    fn default() -> Self {
        Self {
            clear: true,
            inherit: Vec::new(),
            vars: HashMap::new(),
            shell: None,
        }
    }
}

/// Sandbox configuration from the `sandboxes` section.
///
/// When this section is present in the configuration, builds are performed
/// in isolated chroot environments.
///
/// # Example
///
/// ```lua
/// sandboxes = {
///     basedir = "/data/chroot",
///     setup = {
///         { action = "mount", fs = "proc", dir = "/proc" },
///         { action = "copy", dir = "/etc" },
///     },
/// }
/// ```
#[derive(Clone, Debug, Default)]
pub struct Sandboxes {
    /// Base directory for sandbox roots (e.g., `/data/chroot`).
    ///
    /// Individual sandboxes are created as numbered subdirectories:
    /// `basedir/0`, `basedir/1`, etc.
    pub basedir: PathBuf,
    /// Actions to perform during sandbox creation and destruction.
    pub setup: Vec<Action>,
    /**
     * Per-package hook actions.  Any "create" action runs after bob's
     * internal pre-build (unpacks bootstrap kit if needed); any "destroy"
     * action runs before bob's internal post-build (wipes PREFIX and
     * PKG_DBDIR).
     */
    pub hooks: Vec<Action>,
    /// Environment variables for sandbox processes.
    pub environment: Option<Environment>,
    /// Path to bindfs binary (defaults to "bindfs").
    pub bindfs: String,
}

impl Config {
    /// Load configuration from a Lua file.
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to configuration file, or `None` to use `./config.lua`
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration file doesn't exist or contains
    /// invalid Lua syntax.
    pub fn load(config_path: Option<&Path>) -> Result<Config> {
        let filename = match config_path {
            Some(path) => {
                if path.is_relative() {
                    std::env::current_dir()
                        .context("Unable to determine current directory")?
                        .join(path)
                } else {
                    path.to_path_buf()
                }
            }
            None => default_config_path()?,
        };

        if !filename.exists() {
            anyhow::bail!(
                "Configuration file {} does not exist.\n\
                 Run 'bob init' to create a default configuration.",
                filename.display()
            );
        }

        /*
         * Parse configuration file as Lua.
         */
        let file = load_lua(&filename)
            .map_err(|e| anyhow!(e))
            .with_context(|| {
                format!(
                    "Unable to parse Lua configuration file {}",
                    filename.display()
                )
            })?;

        let base_dir = filename.parent().unwrap_or_else(|| Path::new("."));

        /*
         * Validate bootstrap path exists if specified.
         */
        if let Some(ref bootstrap) = file.pkgsrc.bootstrap {
            if !bootstrap.exists() {
                anyhow::bail!(
                    "pkgsrc.bootstrap file {} does not exist",
                    bootstrap.display()
                );
            }
        }

        /*
         * Resolve dbdir: explicit value from options, or the platform
         * default data directory.  Relative paths are resolved against
         * the config file directory.
         */
        let raw_dbdir = file.options.as_ref().and_then(|o| o.dbdir.clone());
        let dbdir = match raw_dbdir {
            Some(p) if p.is_absolute() => p,
            Some(p) => base_dir.join(p),
            None => default_data_dir()?,
        };

        /*
         * Default logdir to dbdir/logs if not explicitly set.
         */
        let logdir = file
            .options
            .as_ref()
            .and_then(|o| o.logdir.clone())
            .unwrap_or_else(|| dbdir.join("logs"));

        /*
         * Set log_level from config file, defaulting to "info".
         */
        let log_level = if let Some(opts) = &file.options {
            opts.log_level.clone().unwrap_or_else(|| "info".to_string())
        } else {
            "info".to_string()
        };

        Ok(Config {
            file,
            dbdir,
            logdir,
            log_level,
        })
    }

    pub fn build_threads(&self) -> usize {
        if let Some(opts) = &self.file.options {
            opts.build_threads.unwrap_or(1)
        } else {
            1
        }
    }

    pub fn scan_threads(&self) -> usize {
        if let Some(opts) = &self.file.options {
            opts.scan_threads.unwrap_or(1)
        } else {
            1
        }
    }

    pub fn strict_scan(&self) -> bool {
        if let Some(opts) = &self.file.options {
            opts.strict_scan.unwrap_or(false)
        } else {
            false
        }
    }

    pub fn jobs(&self) -> Option<usize> {
        self.file.dynamic.as_ref().and_then(|s| s.jobs)
    }

    pub fn wrkobjdir(&self) -> Option<&WrkObjDir> {
        self.file
            .dynamic
            .as_ref()
            .and_then(|s| s.wrkobjdir.as_ref())
    }

    pub fn hooks(&self) -> &[Action] {
        match &self.file.sandboxes {
            Some(sandboxes) => &sandboxes.hooks,
            None => &[],
        }
    }

    pub fn make(&self) -> &PathBuf {
        &self.file.pkgsrc.make
    }

    pub fn pkgpaths(&self) -> &Option<Vec<PkgPath>> {
        &self.file.pkgsrc.pkgpaths
    }

    pub fn pkgsrc(&self) -> &PathBuf {
        &self.file.pkgsrc.basedir
    }

    pub fn sandboxes(&self) -> &Option<Sandboxes> {
        &self.file.sandboxes
    }

    pub fn environment(&self) -> Option<&Environment> {
        self.file
            .sandboxes
            .as_ref()
            .and_then(|s| s.environment.as_ref())
    }

    pub fn publish(&self) -> Option<&Publish> {
        self.file.publish.as_ref()
    }

    pub fn report_branch(&self) -> Option<&str> {
        self.file
            .publish
            .as_ref()
            .and_then(|p| p.report.as_ref())
            .and_then(|r| r.branch.as_deref())
    }

    pub fn bindfs(&self) -> &str {
        self.file
            .sandboxes
            .as_ref()
            .map(|s| s.bindfs.as_str())
            .unwrap_or("bindfs")
    }

    pub fn log_level(&self) -> &str {
        &self.log_level
    }

    pub fn tui(&self) -> bool {
        self.file
            .options
            .as_ref()
            .and_then(|o| o.tui)
            .unwrap_or(true)
    }

    pub fn dbdir(&self) -> &PathBuf {
        &self.dbdir
    }

    pub fn logdir(&self) -> &PathBuf {
        &self.logdir
    }

    pub fn save_wrkdir_patterns(&self) -> &[String] {
        self.file.pkgsrc.save_wrkdir_patterns.as_slice()
    }

    pub fn build_user(&self) -> Option<&str> {
        self.file.pkgsrc.build_user.as_deref()
    }

    pub fn build_user_home(&self) -> Option<&Path> {
        self.file.pkgsrc.build_user_home.as_deref()
    }

    pub fn bootstrap(&self) -> Option<&PathBuf> {
        self.file.pkgsrc.bootstrap.as_ref()
    }

    /// Return list of pkgsrc variable names to cache.
    pub fn cachevars(&self) -> &[String] {
        self.file.pkgsrc.cachevars.as_slice()
    }

    /// Return environment variables for script execution.
    ///
    /// If `pkgsrc_env` is provided, includes the pkgsrc-derived variables
    /// (packages, pkgtools, prefix, pkg_dbdir, pkg_refcount_dbdir) as well
    /// as the cached variables from the `cachevars` config option.
    pub fn script_env(&self, pkgsrc_env: Option<&PkgsrcEnv>) -> Vec<(String, String)> {
        let mut envs = vec![
            (
                "bob_logdir".to_string(),
                format!("{}", self.logdir().display()),
            ),
            ("bob_make".to_string(), format!("{}", self.make().display())),
            (
                "bob_pkgsrc".to_string(),
                format!("{}", self.pkgsrc().display()),
            ),
        ];
        if let Some(env) = pkgsrc_env {
            envs.push((
                "bob_packages".to_string(),
                env.packages.display().to_string(),
            ));
            envs.push((
                "bob_pkgtools".to_string(),
                env.pkgtools.display().to_string(),
            ));
            envs.push(("bob_prefix".to_string(), env.prefix.display().to_string()));
            envs.push((
                "bob_pkg_dbdir".to_string(),
                env.pkg_dbdir.display().to_string(),
            ));
            envs.push((
                "bob_pkg_refcount_dbdir".to_string(),
                env.pkg_refcount_dbdir.display().to_string(),
            ));
            for (key, value) in &env.cachevars {
                envs.push((key.clone(), value.clone()));
            }
        }
        if let Some(build_user) = self.build_user() {
            envs.push(("bob_build_user".to_string(), build_user.to_string()));
        }
        if let Some(home) = self.build_user_home() {
            envs.push((
                "bob_build_user_home".to_string(),
                home.display().to_string(),
            ));
        }
        if let Some(bootstrap) = self.bootstrap() {
            envs.push((
                "bob_bootstrap".to_string(),
                format!("{}", bootstrap.display()),
            ));
        }
        envs
    }

    /// Validate the configuration, checking that required paths and files exist.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors: Vec<String> = Vec::new();

        // Check pkgsrc directory exists
        if !self.file.pkgsrc.basedir.exists() {
            errors.push(format!(
                "pkgsrc basedir does not exist: {}",
                self.file.pkgsrc.basedir.display()
            ));
        }

        // Check make binary exists (only on host if sandboxes not enabled)
        // When sandboxes are enabled, the make binary is inside the sandbox
        if self.file.sandboxes.is_none() && !self.file.pkgsrc.make.exists() {
            errors.push(format!(
                "make binary does not exist: {}",
                self.file.pkgsrc.make.display()
            ));
        }

        // Check sandbox basedir is writable if sandboxes enabled
        if let Some(sandboxes) = &self.file.sandboxes {
            // Check parent directory exists or can be created
            if let Some(parent) = sandboxes.basedir.parent() {
                if !parent.exists() {
                    errors.push(format!(
                        "Sandbox basedir parent does not exist: {}",
                        parent.display()
                    ));
                }
            }
        }

        // Check dbdir can be created
        if let Some(parent) = self.dbdir.parent() {
            if !parent.exists() {
                errors.push(format!(
                    "dbdir parent directory does not exist: {}",
                    parent.display()
                ));
            }
        }

        // Thread counts must be at least 1
        if let Some(opts) = &self.file.options {
            if opts.build_threads == Some(0) {
                errors.push("build_threads must be at least 1".to_string());
            }
            if opts.scan_threads == Some(0) {
                errors.push("scan_threads must be at least 1".to_string());
            }
        }

        // Dynamic resource allocation validation
        if let Some(dyn_cfg) = &self.file.dynamic {
            if dyn_cfg.jobs == Some(0) {
                errors.push("dynamic.jobs must be at least 1".to_string());
            }
            if let Some(w) = &dyn_cfg.wrkobjdir {
                if w.tmpfs.is_none() && w.disk.is_none() {
                    errors.push(
                        "dynamic.wrkobjdir requires at least one of tmpfs or disk".to_string(),
                    );
                }
                if w.tmpfs.is_some() && w.disk.is_some() && w.threshold.is_none() {
                    errors.push(
                        "dynamic.wrkobjdir.threshold is required when both \
                         tmpfs and disk are set"
                            .to_string(),
                    );
                }
            }
        }

        if let Some(publish) = &self.file.publish {
            if let Some(pkgs) = &publish.packages {
                if pkgs.host.is_empty() {
                    errors.push("publish.packages.host must not be empty".to_string());
                }
                if pkgs.path.is_empty() {
                    errors.push("publish.packages.path must not be empty".to_string());
                }
                if let Some(tmppath) = &pkgs.tmppath {
                    if tmppath.is_empty() {
                        errors.push("publish.packages.tmppath must not be empty".to_string());
                    }
                }
            }
            if let Some(report) = &publish.report {
                if report.host.is_empty() {
                    errors.push("publish.report.host must not be empty".to_string());
                }
                if report.path.is_empty() {
                    errors.push("publish.report.path must not be empty".to_string());
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/**
 * Return the default configuration file path.
 *
 * If `BOB_SYSCONFDIR` was set at compile time (e.g. by pkgsrc to
 * `/usr/pkg/etc/bob`), uses `$BOB_SYSCONFDIR/config.lua`.  Otherwise
 * uses the XDG config directory (`~/.config/bob/config.lua`).
 */
pub fn default_config_path() -> Result<PathBuf> {
    let dir = match option_env!("BOB_SYSCONFDIR") {
        Some(dir) => PathBuf::from(dir),
        None => {
            let xdg = xdg::BaseDirectories::new();
            let config_home = xdg
                .config_home
                .context("Unable to determine XDG config directory (HOME not set?)")?;
            config_home.join("bob")
        }
    };
    Ok(dir.join("config.lua"))
}

/**
 * Return the default data directory for databases and logs.
 *
 * If `BOB_DATADIR` was set at compile time (e.g. by pkgsrc to
 * `/var/db/bob`), uses that directly.  Otherwise uses the XDG data
 * directory (`~/.local/share/bob`).
 */
pub fn default_data_dir() -> Result<PathBuf> {
    match option_env!("BOB_DATADIR") {
        Some(dir) => Ok(PathBuf::from(dir)),
        None => {
            let xdg = xdg::BaseDirectories::new();
            let dir = xdg
                .data_home
                .context("Unable to determine XDG data directory (HOME not set?)")?;
            Ok(dir.join("bob"))
        }
    }
}

/// Load and parse a Lua configuration file.
fn load_lua(filename: &Path) -> Result<ConfigFile, String> {
    let lua = Lua::new();

    // Add config directory to package.path so require() finds relative modules
    if let Some(config_dir) = filename.parent() {
        let globals = lua.globals();
        let pkg: Table = globals
            .get("package")
            .map_err(|e| format!("Failed to get package table: {}", e))?;
        let existing: String = pkg
            .get("path")
            .map_err(|e| format!("Failed to get package.path: {}", e))?;
        let new_path = format!("{}/?.lua;{}", config_dir.display(), existing);
        pkg.set("path", new_path)
            .map_err(|e| format!("Failed to set package.path: {}", e))?;
    }

    // Load built-in helper functions
    lua.load(include_str!("funcs.lua"))
        .exec()
        .map_err(|e| format!("Failed to load helper functions: {}", e))?;

    lua.load(filename)
        .exec()
        .map_err(|e| format!("Lua execution error: {}", e))?;

    // Get the global table (Lua script should set global variables)
    let globals = lua.globals();

    reject_old_config(&globals)?;

    // Parse each section
    let options =
        parse_options(&globals).map_err(|e| format!("Error parsing options config: {}", e))?;
    let pkgsrc =
        parse_pkgsrc(&globals).map_err(|e| format!("Error parsing pkgsrc config: {}", e))?;
    let sandboxes =
        parse_sandboxes(&globals).map_err(|e| format!("Error parsing sandboxes config: {}", e))?;
    let dynamic =
        parse_dynamic(&globals).map_err(|e| format!("Error parsing dynamic config: {}", e))?;
    let publish =
        parse_publish(&globals).map_err(|e| format!("Error parsing publish config: {}", e))?;

    Ok(ConfigFile {
        options,
        pkgsrc,
        sandboxes,
        dynamic,
        publish,
    })
}

/// Build the migration error message for an unsupported config key.
fn old_config_error(key: &str) -> String {
    format!(
        "\n\n\
        '{}' is no longer a supported configuration key.\n\n\
        The configuration file format and the default location have changed.  Run\n\
        'bob init' to generate a new file and merge any changes required for your\n\
        setup.  See https://docs.rs/bob/latest/bob/config/ for more information.",
        key
    )
}

/**
 * Check for config keys from older versions and produce a helpful error
 * directing users to regenerate their config with `bob init`.
 */
fn reject_old_config(globals: &Table) -> Result<(), String> {
    let old_top_level = ["scripts", "environment"];
    for key in &old_top_level {
        let val: Value = globals
            .get(*key)
            .map_err(|e| format!("Error reading config: {}", e))?;
        if !val.is_nil() {
            return Err(old_config_error(key));
        }
    }

    let sandboxes: Value = globals
        .get("sandboxes")
        .map_err(|e| format!("Error reading config: {}", e))?;
    if let Some(table) = sandboxes.as_table() {
        // `actions` was the original action list field, before the
        // split into `setup`/`build`.  `build` was the per-package
        // action list before it was renamed to `hooks`.
        for key in ["actions", "build"] {
            let val: Value = table
                .get(key)
                .map_err(|e| format!("Error reading config: {}", e))?;
            if !val.is_nil() {
                return Err(old_config_error(&format!("sandboxes.{}", key)));
            }
        }

        // `sandboxes.environment` previously had top-level `clear`,
        // `inherit`, and `set` fields.  These are now nested inside
        // per-context sub-tables (`build` and `dev`), each of which
        // has its own `clear`, `inherit`, and `vars`.
        let env: Value = table
            .get("environment")
            .map_err(|e| format!("Error reading config: {}", e))?;
        if let Some(env_table) = env.as_table() {
            for key in ["clear", "inherit", "set"] {
                let val: Value = env_table
                    .get(key)
                    .map_err(|e| format!("Error reading config: {}", e))?;
                if !val.is_nil() {
                    return Err(old_config_error(&format!("sandboxes.environment.{}", key)));
                }
            }
        }
    }

    let pkgsrc: Value = globals
        .get("pkgsrc")
        .map_err(|e| format!("Error reading config: {}", e))?;
    if let Some(table) = pkgsrc.as_table() {
        for key in ["env", "logdir"] {
            let val: Value = table
                .get(key)
                .map_err(|e| format!("Error reading config: {}", e))?;
            if !val.is_nil() {
                return Err(old_config_error(&format!("pkgsrc.{}", key)));
            }
        }
    }

    let publish: Value = globals
        .get("publish")
        .map_err(|e| format!("Error reading config: {}", e))?;
    if let Some(table) = publish.as_table() {
        let val: Value = table
            .get("rsync_args")
            .map_err(|e| format!("Error reading config: {}", e))?;
        if !val.is_nil() {
            return Err(old_config_error("publish.rsync_args"));
        }
    }

    Ok(())
}

fn parse_options(globals: &Table) -> LuaResult<Option<Options>> {
    let options: Value = globals.get("options")?;
    if options.is_nil() {
        return Ok(None);
    }

    let table = options
        .as_table()
        .ok_or_else(|| mlua::Error::runtime("'options' must be a table"))?;

    const KNOWN_KEYS: &[&str] = &[
        "build_threads",
        "dbdir",
        "log_level",
        "logdir",
        "scan_threads",
        "tui",
        "strict_scan",
    ];
    warn_unknown_keys(table, "options", KNOWN_KEYS);

    let dbdir: Option<PathBuf> = table.get::<Option<String>>("dbdir")?.map(PathBuf::from);
    let logdir: Option<PathBuf> = table.get::<Option<String>>("logdir")?.map(PathBuf::from);

    Ok(Some(Options {
        build_threads: table.get::<Option<usize>>("build_threads")?,
        dbdir,
        logdir,
        scan_threads: table.get::<Option<usize>>("scan_threads")?,
        strict_scan: table.get::<Option<bool>>("strict_scan")?,
        log_level: table.get::<Option<String>>("log_level")?,
        tui: table.get::<Option<bool>>("tui")?,
    }))
}

/// Warn about unknown keys in a Lua table.
fn warn_unknown_keys(table: &Table, table_name: &str, known_keys: &[&str]) {
    for (key, _) in table.pairs::<String, Value>().flatten() {
        if !known_keys.contains(&key.as_str()) {
            eprintln!("Warning: unknown config key '{}.{}'", table_name, key);
        }
    }
}

fn get_required_string(table: &Table, field: &str) -> LuaResult<String> {
    let value: Value = table.get(field)?;
    match value {
        Value::String(s) => Ok(s.to_str()?.to_string()),
        Value::Integer(n) => Ok(n.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Nil => Err(mlua::Error::runtime(format!(
            "missing required field '{}'",
            field
        ))),
        _ => Err(mlua::Error::runtime(format!(
            "field '{}' must be a string, got {}",
            field,
            value.type_name()
        ))),
    }
}

/**
 * A shell script bundled with the environment variables that should be
 * set when it runs.  Used for script-typed config fields like
 * `publish.packages.swapcmd` and the `create`/`destroy` fields of
 * sandbox setup actions.
 */
#[derive(Clone, Debug, Default)]
pub struct ScriptValue {
    pub run: String,
    pub env: Vec<(String, String)>,
}

/**
 * Read a script-typed config field.  Accepts two forms:
 *
 * - A literal string (no env vars).
 * - A function returning the result of `scriptenv(run, env)`, so the
 *   env values can reference other config sections after the whole
 *   config has loaded.
 *
 * Returns Ok(None) if the field is nil or the script body is empty.
 */
pub(crate) fn get_optional_script(table: &Table, field: &str) -> LuaResult<Option<ScriptValue>> {
    let value: Value = table.get(field)?;
    let sv = match value {
        Value::Nil => return Ok(None),
        Value::String(s) => ScriptValue {
            run: s.to_str()?.to_string(),
            env: Vec::new(),
        },
        Value::Function(f) => {
            let result: Table = f
                .call(())
                .map_err(|e| mlua::Error::runtime(format!("'{}' function failed: {}", field, e)))?;
            script_value_from_table(field, &result)?
        }
        _ => {
            return Err(mlua::Error::runtime(format!(
                "field '{}' must be a string or function, got {}",
                field,
                value.type_name()
            )));
        }
    };
    if sv.run.is_empty() {
        Ok(None)
    } else {
        Ok(Some(sv))
    }
}

fn script_value_from_table(field: &str, t: &Table) -> LuaResult<ScriptValue> {
    let run: String = t.get::<Option<String>>("run")?.ok_or_else(|| {
        mlua::Error::runtime(format!("'{}' table must have a 'run' string field", field))
    })?;
    let env = match t.get::<Value>("env")? {
        Value::Nil => Vec::new(),
        Value::Table(et) => {
            let mut pairs: Vec<(String, String)> = Vec::new();
            for entry in et.pairs::<String, Value>() {
                let (k, v) = entry?;
                if !is_valid_env_key(&k) {
                    return Err(mlua::Error::runtime(format!(
                        "'{}.env' key '{}' is not a valid shell identifier \
                         (must match [A-Za-z_][A-Za-z0-9_]*)",
                        field, k
                    )));
                }
                let v = match v {
                    Value::String(s) => s.to_str()?.to_string(),
                    Value::Integer(n) => n.to_string(),
                    Value::Number(n) => n.to_string(),
                    Value::Boolean(b) => b.to_string(),
                    _ => {
                        return Err(mlua::Error::runtime(format!(
                            "'{}.env.{}' must be a string, number, or boolean, got {}",
                            field,
                            k,
                            v.type_name()
                        )));
                    }
                };
                pairs.push((k, v));
            }
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            pairs
        }
        _ => {
            return Err(mlua::Error::runtime(format!(
                "'{}.env' must be a table",
                field
            )));
        }
    };
    Ok(ScriptValue { run, env })
}

/**
 * A valid shell identifier matches [A-Za-z_][A-Za-z0-9_]*.  Used to
 * validate env var names so they can be safely interpolated into shell
 * preludes and referenced as ${name} from script bodies.
 */
fn is_valid_env_key(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse a human-readable size string into bytes.
///
/// Accepts integer suffixes K, M, G, T (case-insensitive) with optional
/// fractional parts (e.g. "1.5G"), or bare byte counts.
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size string".to_string());
    }

    let (num_str, multiplier) = match s.as_bytes().last() {
        Some(b'K' | b'k') => (&s[..s.len() - 1], 1024u64),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1024u64 * 1024),
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1024u64 * 1024 * 1024),
        Some(b'T' | b't') => (&s[..s.len() - 1], 1024u64 * 1024 * 1024 * 1024),
        _ => (s, 1u64),
    };

    if multiplier > 1 {
        let n: f64 = num_str
            .parse()
            .map_err(|_| format!("invalid size: '{}'", s))?;
        if n < 0.0 {
            return Err(format!("negative size: '{}'", s));
        }
        Ok((n * multiplier as f64) as u64)
    } else {
        s.parse::<u64>()
            .map_err(|_| format!("invalid size: '{}'", s))
    }
}

/**
 * Look up a user's home directory from the password database.
 */
fn get_home_dir(username: &str) -> Result<PathBuf, String> {
    let cname = CString::new(username).map_err(|_| format!("invalid username: '{}'", username))?;
    // SAFETY: getpwnam is called with a valid C string.
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    if pw.is_null() {
        return Err(format!(
            "user '{}' not found in password database",
            username
        ));
    }
    // SAFETY: pw is non-null and pw_dir is a valid C string.
    let home = unsafe { CStr::from_ptr((*pw).pw_dir) };
    let path = home
        .to_str()
        .map_err(|_| format!("non-UTF-8 home directory for user '{}'", username))?;
    Ok(PathBuf::from(path))
}

fn parse_dynamic(globals: &Table) -> LuaResult<Option<DynamicConfig>> {
    let value: Value = globals.get("dynamic")?;
    if value.is_nil() {
        return Ok(None);
    }

    let table = value
        .as_table()
        .ok_or_else(|| mlua::Error::runtime("'dynamic' must be a table"))?;

    const KNOWN_KEYS: &[&str] = &["jobs", "wrkobjdir"];
    warn_unknown_keys(table, "dynamic", KNOWN_KEYS);

    let jobs: Option<usize> = table.get::<Option<usize>>("jobs")?;

    let wrkobjdir = match table.get::<Value>("wrkobjdir")? {
        Value::Nil => None,
        Value::Table(t) => {
            const WRK_KEYS: &[&str] = &["tmpfs", "disk", "threshold", "use_failed_history"];
            warn_unknown_keys(&t, "dynamic.wrkobjdir", WRK_KEYS);

            let tmpfs: Option<PathBuf> = t.get::<Option<String>>("tmpfs")?.map(PathBuf::from);
            let disk: Option<PathBuf> = t.get::<Option<String>>("disk")?.map(PathBuf::from);
            let threshold: Option<u64> = t
                .get::<Option<String>>("threshold")?
                .map(|s| {
                    parse_size(&s).map_err(|e| {
                        mlua::Error::runtime(format!("dynamic.wrkobjdir.threshold: {}", e))
                    })
                })
                .transpose()?;
            let use_failed_history =
                matches!(t.get::<Option<bool>>("use_failed_history")?, Some(true));

            Some(WrkObjDir {
                tmpfs,
                disk,
                threshold,
                use_failed_history,
            })
        }
        _ => return Err(mlua::Error::runtime("dynamic.wrkobjdir must be a table")),
    };

    Ok(Some(DynamicConfig { jobs, wrkobjdir }))
}

fn parse_pkgsrc(globals: &Table) -> LuaResult<Pkgsrc> {
    let pkgsrc: Table = globals.get("pkgsrc")?;

    const KNOWN_KEYS: &[&str] = &[
        "basedir",
        "bootstrap",
        "build_user",
        "build_user_home",
        "cachevars",
        "make",
        "pkgpaths",
        "save_wrkdir_patterns",
    ];
    warn_unknown_keys(&pkgsrc, "pkgsrc", KNOWN_KEYS);

    let basedir = get_required_string(&pkgsrc, "basedir")?;
    let bootstrap: Option<PathBuf> = pkgsrc
        .get::<Option<String>>("bootstrap")?
        .map(PathBuf::from);
    let build_user: Option<String> = pkgsrc.get::<Option<String>>("build_user")?;
    let build_user_home = if let Some(ref user) = build_user {
        if let Some(explicit) = pkgsrc.get::<Option<String>>("build_user_home")? {
            Some(PathBuf::from(explicit))
        } else {
            let home = get_home_dir(user)
                .map_err(|e| mlua::Error::runtime(format!("pkgsrc.build_user: {}", e)))?;
            pkgsrc.set("build_user_home", home.display().to_string())?;
            Some(home)
        }
    } else {
        None
    };
    let make = get_required_string(&pkgsrc, "make")?;

    let pkgpaths: Option<Vec<PkgPath>> = match pkgsrc.get::<Value>("pkgpaths")? {
        Value::Nil => None,
        Value::Table(t) => {
            let mut paths = Vec::new();
            for (i, val) in t.sequence_values::<Value>().enumerate() {
                let val = val.map_err(|e| {
                    mlua::Error::runtime(format!("pkgsrc.pkgpaths[{}]: {}", i + 1, e))
                })?;
                let Value::String(s) = val else {
                    return Err(mlua::Error::runtime(format!(
                        "pkgsrc.pkgpaths[{}]: expected string",
                        i + 1
                    )));
                };
                let s = s.to_str().map_err(|e| {
                    mlua::Error::runtime(format!("pkgsrc.pkgpaths[{}]: {}", i + 1, e))
                })?;
                match PkgPath::new(&s) {
                    Ok(p) => paths.push(p),
                    Err(e) => {
                        return Err(mlua::Error::runtime(format!(
                            "pkgsrc.pkgpaths[{}]: invalid pkgpath '{}': {}",
                            i + 1,
                            s,
                            e
                        )));
                    }
                }
            }
            if paths.is_empty() { None } else { Some(paths) }
        }
        _ => None,
    };

    let save_wrkdir_patterns: Vec<String> = match pkgsrc.get::<Value>("save_wrkdir_patterns")? {
        Value::Nil => Vec::new(),
        Value::Table(t) => t
            .sequence_values::<String>()
            .filter_map(|r| r.ok())
            .collect(),
        _ => Vec::new(),
    };

    let cachevars: Vec<String> = match pkgsrc.get::<Value>("cachevars")? {
        Value::Nil => Vec::new(),
        Value::Table(t) => t
            .sequence_values::<String>()
            .filter_map(|r| r.ok())
            .collect(),
        _ => Vec::new(),
    };

    Ok(Pkgsrc {
        basedir: PathBuf::from(basedir),
        bootstrap,
        build_user,
        build_user_home,
        cachevars,
        make: PathBuf::from(make),
        pkgpaths,
        save_wrkdir_patterns,
    })
}

fn parse_sandboxes(globals: &Table) -> LuaResult<Option<Sandboxes>> {
    let sandboxes: Value = globals.get("sandboxes")?;
    if sandboxes.is_nil() {
        return Ok(None);
    }

    let table = sandboxes
        .as_table()
        .ok_or_else(|| mlua::Error::runtime("'sandboxes' must be a table"))?;

    const KNOWN_KEYS: &[&str] = &["basedir", "bindfs", "environment", "hooks", "setup"];
    warn_unknown_keys(table, "sandboxes", KNOWN_KEYS);

    let basedir: String = table.get("basedir")?;
    let bindfs: String = table
        .get::<Option<String>>("bindfs")?
        .unwrap_or_else(|| String::from("bindfs"));

    let setup = parse_action_list(table, globals, "setup", "sandboxes.setup")?;
    let hooks = parse_action_list(table, globals, "hooks", "sandboxes.hooks")?;
    let environment = parse_environment(table)?;

    Ok(Some(Sandboxes {
        basedir: PathBuf::from(basedir),
        setup,
        hooks,
        environment,
        bindfs,
    }))
}

fn parse_action_list(
    table: &Table,
    globals: &Table,
    key: &str,
    label: &str,
) -> LuaResult<Vec<Action>> {
    let value: Value = table.get(key)?;
    if value.is_nil() {
        return Ok(Vec::new());
    }
    let actions_table = value
        .as_table()
        .ok_or_else(|| mlua::Error::runtime(format!("'{label}' must be a table")))?;
    parse_actions(actions_table, globals)
}

fn parse_actions(table: &Table, globals: &Table) -> LuaResult<Vec<Action>> {
    let mut actions = Vec::new();
    for v in table.sequence_values::<Table>() {
        let action_table = v?;

        // The `ifset` and `ifexists` action fields were replaced by
        // `only = { set = ... }` and `only = { exists = ... }`
        // respectively.  Reject the old form so users don't silently
        // lose their conditionals.
        for key in ["ifset", "ifexists"] {
            let val: Value = action_table.get(key)?;
            if !val.is_nil() {
                return Err(mlua::Error::runtime(old_config_error(key)));
            }
        }

        match parse_action_only(&action_table, globals)? {
            Some(only) => {
                let mut action = Action::from_lua(&action_table)?;
                action.set_only(only);
                actions.push(action);
            }
            None => {
                // The parse-time `only.set` check failed: drop the action.
            }
        }
    }
    Ok(actions)
}

/// Parse the `only = { ... }` predicate table for an action.
///
/// Returns `Some(only)` if the action should be kept (with the runtime
/// predicates populated), or `None` if a parse-time predicate (`set`)
/// failed and the action should be dropped.  Actions without an `only`
/// table return `Some(Only::default())`.
fn parse_action_only(
    action_table: &Table,
    globals: &Table,
) -> LuaResult<Option<crate::action::Only>> {
    use crate::action::{ActionContext, Only};

    let only_value: Value = action_table.get("only")?;
    let only_table = match only_value {
        Value::Nil => return Ok(Some(Only::default())),
        Value::Table(t) => t,
        _ => {
            return Err(mlua::Error::runtime("'only' must be a table of predicates"));
        }
    };

    const ONLY_KEYS: &[&str] = &["environment", "set", "exists"];
    warn_unknown_keys(&only_table, "only", ONLY_KEYS);

    let mut only = Only::default();

    if let Some(env_str) = only_table.get::<Option<String>>("environment")? {
        let env = match env_str.as_str() {
            "build" => ActionContext::Build,
            "dev" => ActionContext::Dev,
            other => {
                return Err(mlua::Error::runtime(format!(
                    "'only.environment' must be 'build' or 'dev', got '{}'",
                    other
                )));
            }
        };
        only.environment = Some(env);
    }

    // `set` is checked at parse time against the Lua globals; if the
    // referenced var is unset, the action is dropped entirely.
    if let Some(varpath) = only_table.get::<Option<String>>("set")? {
        if resolve_lua_var(globals, &varpath).is_none() {
            return Ok(None);
        }
    }

    if let Some(path_str) = only_table.get::<Option<String>>("exists")? {
        only.exists = Some(PathBuf::from(path_str));
    }

    Ok(Some(only))
}

/**
 * Resolve a dotted variable path (e.g. "pkgsrc.build_user") by
 * walking the Lua globals table.
 */
fn resolve_lua_var(globals: &Table, path: &str) -> Option<String> {
    let mut parts = path.split('.');
    let first = parts.next()?;
    let mut current: Value = globals.get(first).ok()?;
    for key in parts {
        match current {
            Value::Table(t) => {
                current = t.get(key).ok()?;
            }
            _ => return None,
        }
    }
    match current {
        Value::String(s) => Some(s.to_str().ok()?.to_string()),
        Value::Integer(n) => Some(n.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn parse_publish(globals: &Table) -> LuaResult<Option<Publish>> {
    let value: Value = globals.get("publish")?;
    if value.is_nil() {
        return Ok(None);
    }

    let table = value
        .as_table()
        .ok_or_else(|| mlua::Error::runtime("'publish' must be a table"))?;

    const KNOWN_KEYS: &[&str] = &["packages", "report", "rsync"];
    warn_unknown_keys(table, "publish", KNOWN_KEYS);

    let rsync: PathBuf = table
        .get::<Option<String>>("rsync")?
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("rsync"));

    let packages = match table.get::<Value>("packages")? {
        Value::Nil => None,
        Value::Table(t) => {
            const PKG_KEYS: &[&str] = &[
                "host",
                "minimum",
                "path",
                "required",
                "rsync_args",
                "swapcmd",
                "tmppath",
                "user",
            ];
            warn_unknown_keys(&t, "publish.packages", PKG_KEYS);

            let host: String = t
                .get::<Option<String>>("host")?
                .ok_or_else(|| mlua::Error::runtime("publish.packages.host is required"))?;
            let user: Option<String> = t.get::<Option<String>>("user")?;
            let path: String = t
                .get::<Option<String>>("path")?
                .ok_or_else(|| mlua::Error::runtime("publish.packages.path is required"))?;
            let tmppath: Option<String> = t
                .get::<Option<String>>("tmppath")?
                .filter(|s| !s.is_empty());
            let swapcmd: Option<ScriptValue> = get_optional_script(&t, "swapcmd")?;
            let minimum: Option<usize> = t.get::<Option<usize>>("minimum")?;
            let required: Vec<String> = match t.get::<Value>("required")? {
                Value::Nil => Vec::new(),
                Value::Table(r) => r
                    .sequence_values::<String>()
                    .collect::<LuaResult<Vec<_>>>()?,
                _ => {
                    return Err(mlua::Error::runtime(
                        "publish.packages.required must be a table",
                    ));
                }
            };
            let rsync_args: String = t
                .get::<Option<String>>("rsync_args")?
                .unwrap_or_else(|| "-av --delete-excluded -e ssh".to_string());

            if swapcmd.is_some() && tmppath.is_none() {
                return Err(mlua::Error::runtime(
                    "publish.packages.swapcmd requires tmppath to be set",
                ));
            }

            Some(PublishPackages {
                host,
                user,
                path,
                tmppath,
                swapcmd,
                minimum,
                required,
                rsync_args,
            })
        }
        _ => return Err(mlua::Error::runtime("publish.packages must be a table")),
    };

    let report = match table.get::<Value>("report")? {
        Value::Nil => None,
        Value::Table(t) => {
            const RPT_KEYS: &[&str] = &[
                "branch",
                "from",
                "host",
                "path",
                "rsync_args",
                "to",
                "url",
                "user",
            ];
            warn_unknown_keys(&t, "publish.report", RPT_KEYS);

            let host: String = t
                .get::<Option<String>>("host")?
                .ok_or_else(|| mlua::Error::runtime("publish.report.host is required"))?;
            let user: Option<String> = t.get::<Option<String>>("user")?;
            let path: String = t
                .get::<Option<String>>("path")?
                .ok_or_else(|| mlua::Error::runtime("publish.report.path is required"))?;
            let url: Option<String> = t.get::<Option<String>>("url")?;
            let rsync_args: String = t
                .get::<Option<String>>("rsync_args")?
                .unwrap_or_else(|| "-avz --delete-excluded -e ssh".to_string());
            let branch: Option<String> =
                t.get::<Option<String>>("branch")?.filter(|s| !s.is_empty());
            let from: Option<String> = t.get::<Option<String>>("from")?;
            let to: Vec<String> = match t.get::<Value>("to")? {
                Value::Nil => Vec::new(),
                Value::String(s) => vec![s.to_string_lossy().to_string()],
                Value::Table(r) => r
                    .sequence_values::<String>()
                    .collect::<LuaResult<Vec<_>>>()?,
                _ => {
                    return Err(mlua::Error::runtime(
                        "publish.report.to must be a string or table",
                    ));
                }
            };

            Some(PublishReport {
                host,
                user,
                path,
                url,
                rsync_args,
                branch,
                from,
                to,
            })
        }
        _ => return Err(mlua::Error::runtime("publish.report must be a table")),
    };

    Ok(Some(Publish {
        rsync,
        packages,
        report,
    }))
}

fn parse_environment(globals: &Table) -> LuaResult<Option<Environment>> {
    let environment: Value = globals.get("environment")?;
    if environment.is_nil() {
        return Ok(None);
    }

    let table = environment
        .as_table()
        .ok_or_else(|| mlua::Error::runtime("'environment' must be a table"))?;

    const KNOWN_KEYS: &[&str] = &["build", "dev"];
    warn_unknown_keys(table, "environment", KNOWN_KEYS);

    let build = parse_env_context(table, "build")?;
    let dev = parse_env_context(table, "dev")?;

    Ok(Some(Environment { build, dev }))
}

fn parse_env_context(parent: &Table, name: &str) -> LuaResult<Option<EnvContext>> {
    let value: Value = parent.get(name)?;
    let table = match value {
        Value::Nil => return Ok(None),
        Value::Table(t) => t,
        _ => {
            return Err(mlua::Error::runtime(format!(
                "'environment.{}' must be a table",
                name
            )));
        }
    };

    let qualified = format!("environment.{}", name);
    let known_keys: &[&str] = match name {
        "dev" => &["clear", "inherit", "vars", "shell"],
        _ => &["clear", "inherit", "vars"],
    };
    warn_unknown_keys(&table, &qualified, known_keys);

    let clear: bool = table.get::<Option<bool>>("clear")?.unwrap_or(true);

    let inherit: Vec<String> = match table.get::<Value>("inherit")? {
        Value::Nil => Vec::new(),
        Value::Table(t) => t
            .sequence_values::<String>()
            .filter_map(|r| r.ok())
            .collect(),
        _ => {
            return Err(mlua::Error::runtime(format!(
                "'{}.inherit' must be a table",
                qualified
            )));
        }
    };

    let vars: HashMap<String, String> = match table.get::<Value>("vars")? {
        Value::Nil => HashMap::new(),
        Value::Table(t) => {
            let mut map = HashMap::new();
            for pair in t.pairs::<String, String>() {
                let (k, v) = pair?;
                map.insert(k, v);
            }
            map
        }
        _ => {
            return Err(mlua::Error::runtime(format!(
                "'{}.vars' must be a table",
                qualified
            )));
        }
    };

    let shell: Option<PathBuf> = if name == "dev" {
        table.get::<Option<String>>("shell")?.map(PathBuf::from)
    } else {
        None
    };

    Ok(Some(EnvContext {
        clear,
        inherit,
        vars,
        shell,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_config(lua_src: &str) -> Result<Config, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path = dir.path().join("config.lua");
        std::fs::write(&path, lua_src).map_err(|e| e.to_string())?;
        Config::load(Some(&path)).map_err(|e| e.to_string())
    }

    const MINIMAL: &str = r#"
        pkgsrc = {
            basedir = "/usr/pkgsrc",
            make = "/usr/bin/make",
        }
    "#;

    fn with_options(options: &str) -> String {
        format!("{MINIMAL}\noptions = {{ {options} }}")
    }

    fn with_dynamic(dynamic: &str) -> String {
        format!("{MINIMAL}\ndynamic = {{ {dynamic} }}")
    }

    #[test]
    fn options_valid_types() {
        let cfg = load_config(&with_options("build_threads = 4, scan_threads = 2"));
        assert!(cfg.is_ok());
        let cfg = cfg.ok();
        assert_eq!(cfg.as_ref().map(|c| c.build_threads()), Some(4));
        assert_eq!(cfg.as_ref().map(|c| c.scan_threads()), Some(2));
    }

    #[test]
    fn options_wrong_type_errors() {
        let cfg = load_config(&with_options("build_threads = \"eight\""));
        assert!(cfg.is_err(), "expected error, got: {:?}", cfg);
    }

    #[test]
    fn options_missing_is_default() {
        let cfg = load_config(MINIMAL);
        assert!(cfg.is_ok());
        let cfg = cfg.ok();
        assert_eq!(cfg.as_ref().map(|c| c.build_threads()), Some(1));
    }

    #[test]
    fn dynamic_jobs_wrong_type_errors() {
        let cfg = load_config(&with_dynamic("jobs = \"lots\""));
        assert!(cfg.is_err(), "expected error, got: {:?}", cfg);
    }

    #[test]
    fn pkgpaths_valid() {
        let lua = format!("{MINIMAL}\npkgsrc.pkgpaths = {{ \"devel/cmake\", \"lang/rust\" }}");
        let cfg = load_config(&lua);
        assert!(cfg.is_ok(), "expected ok, got: {:?}", cfg);
    }

    #[test]
    fn pkgpaths_invalid_errors() {
        let lua = format!("{MINIMAL}\npkgsrc.pkgpaths = {{ \"mail\" }}");
        let cfg = load_config(&lua);
        assert!(cfg.is_err(), "expected error, got: {:?}", cfg);
    }

    #[test]
    fn pkgpaths_wrong_type_errors() {
        let lua = format!("{MINIMAL}\npkgsrc.pkgpaths = {{ 42 }}");
        let cfg = load_config(&lua);
        assert!(cfg.is_err(), "expected error, got: {:?}", cfg);
    }
}
