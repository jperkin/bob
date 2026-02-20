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
//! defines paths to pkgsrc, packages to build, sandbox setup, and build scripts.
//!
//! # Configuration File Structure
//!
//! A configuration file has five main sections:
//!
//! - [`options`](#options-section) - General build options (optional)
//! - [`environment`](#environment-section) - Environment variable configuration (optional)
//! - [`pkgsrc`](#pkgsrc-section) - pkgsrc paths and package list (required)
//! - [`scripts`](#scripts-section) - Build script paths (required)
//! - [`sandboxes`](#sandboxes-section) - Sandbox configuration (optional)
//!
//! # Options Section
//!
//! The `options` section is optional. All fields have defaults.
//!
//! | Field | Type | Default | Description |
//! |-------|------|---------|-------------|
//! | `build_threads` | integer | 1 | Number of parallel build sandboxes. Each sandbox builds one package at a time. |
//! | `dbdir` | string | "./db" | Directory for bob state files (database, tracing log). Relative to config file directory. |
//! | `scan_threads` | integer | 1 | Number of parallel scan processes for dependency discovery. |
//! | `strict_scan` | boolean | false | If true, abort on scan errors. If false, continue and report failures separately. |
//! | `log_level` | string | "info" | Log level: "trace", "debug", "info", "warn", or "error". Can be overridden by `RUST_LOG` env var. |
//!
//! # Environment Section
//!
//! The `environment` section is optional. It controls the environment variables
//! available to processes executed inside sandboxes.
//!
//! If this section is omitted, the parent environment is inherited unchanged.
//! If present, `clear` defaults to true and the environment is cleared before
//! applying the configured variables.
//!
//! | Field | Type | Default | Description |
//! |-------|------|---------|-------------|
//! | `clear` | boolean | true | If true, clear the environment. If false, inherit the full parent environment. |
//! | `inherit` | table | `{}` | Variable names to copy from the parent environment (only used when `clear = true`). |
//! | `set` | table | `{}` | Variables to set explicitly as key-value pairs. |
//!
//! To configure a minimal, controlled environment:
//!
//! ```lua
//! environment = {
//!     inherit = { "TERM", "HOME" },
//!     set = {
//!         PATH = "/sbin:/bin:/usr/sbin:/usr/bin",
//!     },
//! }
//! ```
//!
//! ## Precedence
//!
//! Variables are applied in this order (later values override earlier):
//!
//! 1. `inherit` - copied from parent process (only if `clear = true`)
//! 2. `set` - explicitly configured values
//! 3. `pkgsrc.cachevars` - values fetched from pkgsrc
//! 4. `pkgsrc.env` - per-package overrides
//! 5. `bob_*` - internal variables (always set, cannot be overridden)
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
//! | `logdir` | string | `dbdir/logs` | Directory for per-package build logs. Failed builds leave logs here; successful builds clean up. |
//! | `cachevars` | table | `{}` | List of pkgsrc variable names to fetch once and cache. These are set in the environment for scans and builds (e.g., `{"NATIVE_OPSYS", "NATIVE_OS_VERSION"}`). |
//! | `env` | function or table | `{}` | Environment variables for builds. Can be a table of key-value pairs, or a function receiving package metadata and returning a table. See [Environment Function](#environment-function). |
//! | `pkgpaths` | table | `{}` | List of package paths to build (e.g., `{"mail/mutt", "www/curl"}`). Dependencies are discovered automatically. |
//! | `save_wrkdir_patterns` | table | `{}` | Glob patterns for files to preserve from WRKDIR on build failure (e.g., `{"**/config.log"}`). |
//! | `tar` | string | `tar` | Path to a tar binary capable of extracting the bootstrap kit. Defaults to `tar` in PATH. |
//!
//! ## Environment Function
//!
//! The `env` field can be a function that returns environment variables for each
//! package build. The function receives a `pkg` table with the following fields:
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `pkgname` | string | Package name with version (e.g., `mutt-2.2.12`). |
//! | `pkgpath` | string | Package path in pkgsrc (e.g., `mail/mutt`). |
//! | `all_depends` | string | Space-separated list of all transitive dependency paths. |
//! | `depends` | string | Space-separated list of direct dependency package names. |
//! | `scan_depends` | string | Space-separated list of scan-time dependency paths. |
//! | `categories` | string | Package categories from `CATEGORIES`. |
//! | `maintainer` | string | Package maintainer email from `MAINTAINER`. |
//! | `bootstrap_pkg` | string | Value of `BOOTSTRAP_PKG` if set. |
//! | `usergroup_phase` | string | Value of `USERGROUP_PHASE` if set. |
//! | `use_destdir` | string | Value of `USE_DESTDIR`. |
//! | `multi_version` | string | Value of `MULTI_VERSION` if set. |
//! | `pbulk_weight` | string | Value of `PBULK_WEIGHT` if set. |
//! | `pkg_skip_reason` | string | Value of `PKG_SKIP_REASON` if set. |
//! | `pkg_fail_reason` | string | Value of `PKG_FAIL_REASON` if set. |
//! | `no_bin_on_ftp` | string | Value of `NO_BIN_ON_FTP` if set. |
//! | `restricted` | string | Value of `RESTRICTED` if set. |
//!
//! # Scripts Section
//!
//! The `scripts` section defines paths to build scripts. Relative paths are
//! resolved from the configuration file's directory.
//!
//! | Script | Required | Description |
//! |--------|----------|-------------|
//! | `pre-build` | no | Executed before each package build. Used for per-build sandbox setup (e.g., unpacking bootstrap kit). Receives environment variables listed in [Script Environment](#script-environment). |
//! | `post-build` | no | Executed after each package build completes (success or failure). |
//!
//! ## Script Environment
//!
//! Build scripts receive these environment variables:
//!
//! | Variable | Description |
//! |----------|-------------|
//! | `bob_logdir` | Path to the build logs directory. |
//! | `bob_make` | Path to the bmake binary. |
//! | `bob_packages` | Path to the packages directory. |
//! | `bob_pkg_dbdir` | PKG_DBDIR from pkgsrc. |
//! | `bob_pkg_refcount_dbdir` | PKG_REFCOUNT_DBDIR from pkgsrc. |
//! | `bob_pkgtools` | Path to the pkg tools directory. |
//! | `bob_pkgsrc` | Path to the pkgsrc source tree. |
//! | `bob_prefix` | Installation prefix. |
//! | `bob_tar` | Path to the tar binary. |
//! | `bob_build_user` | Unprivileged build user, if configured. |
//! | `bob_bootstrap` | Path to the bootstrap tarball, if configured. |
//!
//! # Sandboxes Section
//!
//! The `sandboxes` section is optional. When present, builds run in isolated
//! chroot environments.
//!
//! | Field | Type | Required | Description |
//! |-------|------|----------|-------------|
//! | `basedir` | string | yes | Base directory for sandbox roots. Sandboxes are created as numbered subdirectories (`basedir/0`, `basedir/1`, etc.). |
//! | `actions` | table | yes | List of actions to perform during sandbox setup. See the [`action`](crate::action) module for details. |

use crate::action::Action;
use crate::sandbox::Sandbox;
use crate::scan::ResolvedPackage;
use anyhow::{Context, Result, anyhow, bail};
use mlua::{Lua, RegistryKey, Result as LuaResult, Table, Value};
use pkgsrc::PkgPath;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
    /// Cached pkgsrc variables from the `cachevars` config option.
    pub cachevars: HashMap<String, String>,
}

impl PkgsrcEnv {
    /// Fetch pkgsrc environment variables by querying bmake.
    ///
    /// This must be called after sandbox 0 is created if sandboxes are enabled,
    /// since bmake may only exist inside the sandbox.
    pub fn fetch(config: &Config, sandbox: &Sandbox) -> Result<Self> {
        const REQUIRED_VARS: &[&str] = &[
            "PACKAGES",
            "PKG_DBDIR",
            "PKG_REFCOUNT_DBDIR",
            "PKG_TOOLS_BIN",
            "PREFIX",
        ];

        let user_cachevars = config.cachevars();
        let mut all_varnames: Vec<&str> = REQUIRED_VARS.to_vec();
        for v in user_cachevars {
            all_varnames.push(v.as_str());
        }

        let varnames_arg = all_varnames.join(" ");
        let script = format!(
            "cd {}/pkgtools/pkg_install && {} show-vars VARNAMES=\"{}\"\n",
            config.pkgsrc().display(),
            config.make().display(),
            varnames_arg
        );

        let child = sandbox.execute_script(0, &script, vec![])?;
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

        let mut cachevars: HashMap<String, String> = HashMap::new();
        for varname in user_cachevars {
            if let Some(value) = values.get(varname.as_str()) {
                if !value.is_empty() {
                    cachevars.insert(varname.clone(), (*value).to_string());
                }
            }
        }

        Ok(PkgsrcEnv {
            packages: PathBuf::from(values["PACKAGES"]),
            pkgtools: PathBuf::from(values["PKG_TOOLS_BIN"]),
            prefix: PathBuf::from(values["PREFIX"]),
            pkg_dbdir: PathBuf::from(values["PKG_DBDIR"]),
            pkg_refcount_dbdir: PathBuf::from(values["PKG_REFCOUNT_DBDIR"]),
            cachevars,
        })
    }
}

/// Holds the Lua state for evaluating env functions.
#[derive(Clone)]
pub struct LuaEnv {
    lua: Arc<Mutex<Lua>>,
    env_key: Option<Arc<RegistryKey>>,
}

impl std::fmt::Debug for LuaEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LuaEnv")
            .field("has_env", &self.env_key.is_some())
            .finish()
    }
}

impl Default for LuaEnv {
    fn default() -> Self {
        Self {
            lua: Arc::new(Mutex::new(Lua::new())),
            env_key: None,
        }
    }
}

impl LuaEnv {
    /// Get environment variables for a package by calling the env function.
    /// Returns a HashMap of VAR_NAME -> value.
    pub fn get_env(&self, pkg: &ResolvedPackage) -> Result<HashMap<String, String>, String> {
        let Some(env_key) = &self.env_key else {
            return Ok(HashMap::new());
        };

        let lua = self
            .lua
            .lock()
            .map_err(|e| format!("Lua lock error: {}", e))?;

        // Get the env value from registry
        let env_value: Value = lua
            .registry_value(env_key)
            .map_err(|e| format!("Failed to get env from registry: {}", e))?;

        let idx = &pkg.index;

        let result_table: Table = match env_value {
            // If it's a function, call it with pkg info
            Value::Function(func) => {
                let pkg_table = lua
                    .create_table()
                    .map_err(|e| format!("Failed to create table: {}", e))?;

                // Set all ScanIndex fields
                pkg_table
                    .set("pkgname", idx.pkgname.to_string())
                    .map_err(|e| format!("Failed to set pkgname: {}", e))?;
                pkg_table
                    .set("pkgpath", pkg.pkgpath.as_path().display().to_string())
                    .map_err(|e| format!("Failed to set pkgpath: {}", e))?;
                pkg_table
                    .set(
                        "all_depends",
                        idx.all_depends
                            .as_ref()
                            .map(|deps| {
                                deps.iter()
                                    .map(|d| d.pkgpath().as_path().display().to_string())
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default(),
                    )
                    .map_err(|e| format!("Failed to set all_depends: {}", e))?;
                pkg_table
                    .set(
                        "pkg_skip_reason",
                        idx.pkg_skip_reason.clone().unwrap_or_default(),
                    )
                    .map_err(|e| format!("Failed to set pkg_skip_reason: {}", e))?;
                pkg_table
                    .set(
                        "pkg_fail_reason",
                        idx.pkg_fail_reason.clone().unwrap_or_default(),
                    )
                    .map_err(|e| format!("Failed to set pkg_fail_reason: {}", e))?;
                pkg_table
                    .set(
                        "no_bin_on_ftp",
                        idx.no_bin_on_ftp.clone().unwrap_or_default(),
                    )
                    .map_err(|e| format!("Failed to set no_bin_on_ftp: {}", e))?;
                pkg_table
                    .set("restricted", idx.restricted.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set restricted: {}", e))?;
                pkg_table
                    .set("categories", idx.categories.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set categories: {}", e))?;
                pkg_table
                    .set("maintainer", idx.maintainer.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set maintainer: {}", e))?;
                pkg_table
                    .set("use_destdir", idx.use_destdir.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set use_destdir: {}", e))?;
                pkg_table
                    .set(
                        "bootstrap_pkg",
                        idx.bootstrap_pkg.clone().unwrap_or_default(),
                    )
                    .map_err(|e| format!("Failed to set bootstrap_pkg: {}", e))?;
                pkg_table
                    .set(
                        "usergroup_phase",
                        idx.usergroup_phase.clone().unwrap_or_default(),
                    )
                    .map_err(|e| format!("Failed to set usergroup_phase: {}", e))?;
                pkg_table
                    .set(
                        "scan_depends",
                        idx.scan_depends
                            .as_ref()
                            .map(|deps| {
                                deps.iter()
                                    .map(|p| p.display().to_string())
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default(),
                    )
                    .map_err(|e| format!("Failed to set scan_depends: {}", e))?;
                pkg_table
                    .set("pbulk_weight", idx.pbulk_weight.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set pbulk_weight: {}", e))?;
                pkg_table
                    .set(
                        "multi_version",
                        idx.multi_version
                            .as_ref()
                            .map(|v| v.join(" "))
                            .unwrap_or_default(),
                    )
                    .map_err(|e| format!("Failed to set multi_version: {}", e))?;
                pkg_table
                    .set(
                        "depends",
                        pkg.depends()
                            .iter()
                            .map(|d| d.to_string())
                            .collect::<Vec<_>>()
                            .join(" "),
                    )
                    .map_err(|e| format!("Failed to set depends: {}", e))?;

                func.call(pkg_table)
                    .map_err(|e| format!("Failed to call env function: {}", e))?
            }
            // If it's a table, use it directly
            Value::Table(t) => t,
            Value::Nil => return Ok(HashMap::new()),
            _ => return Err("env must be a function or table".to_string()),
        };

        // Convert Lua table to HashMap
        let mut env = HashMap::new();
        for pair in result_table.pairs::<String, String>() {
            let (k, v) = pair.map_err(|e| format!("Failed to iterate env table: {}", e))?;
            env.insert(k, v);
        }

        Ok(env)
    }
}

/// Main configuration structure.
#[derive(Clone, Debug, Default)]
pub struct Config {
    file: ConfigFile,
    dbdir: PathBuf,
    logdir: PathBuf,
    log_level: String,
    lua_env: LuaEnv,
}

/// Parsed configuration file contents.
#[derive(Clone, Debug, Default)]
pub struct ConfigFile {
    /// The `options` section.
    pub options: Option<Options>,
    /// The `pkgsrc` section.
    pub pkgsrc: Pkgsrc,
    /// The `scripts` section (script name -> path).
    pub scripts: HashMap<String, PathBuf>,
    /// The `sandboxes` section.
    pub sandboxes: Option<Sandboxes>,
    /// The `environment` section.
    pub environment: Option<Environment>,
}

/// General build options from the `options` section.
///
/// All fields are optional; defaults are used when not specified:
/// - `build_threads`: 1
/// - `scan_threads`: 1
/// - `log_level`: "info"
/// - `dynamic_jobs`: disabled
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Number of parallel build sandboxes.
    pub build_threads: Option<usize>,
    /// Directory for bob state files (database, tracing log).
    pub dbdir: Option<PathBuf>,
    /// Dynamic MAKE_JOBS allocation settings.
    pub dynamic_jobs: Option<DynamicJobs>,
    /// Number of parallel scan processes.
    pub scan_threads: Option<usize>,
    /// If true, abort on scan errors. If false, continue and report failures.
    pub strict_scan: Option<bool>,
    /// Log level: "trace", "debug", "info", "warn", or "error".
    pub log_level: Option<String>,
}

/// Dynamic MAKE_JOBS configuration.
///
/// Controls how MAKE_JOBS is distributed across concurrent builds based
/// on package weight. The `max` field is the total CPU budget, and `min`
/// is reserved per build thread to guarantee a minimum allocation.
#[derive(Clone, Debug)]
pub struct DynamicJobs {
    /// Total CPU budget to distribute.
    pub max: usize,
    /// Minimum MAKE_JOBS reserved per build thread.
    pub min: usize,
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
/// - `logdir`: Directory for build logs (defaults to `dbdir/logs`)
/// - `pkgpaths`: List of packages to build
/// - `save_wrkdir_patterns`: Glob patterns for files to save on build failure
/// - `tar`: Path to tar binary (defaults to `tar`)
#[derive(Clone, Debug, Default)]
pub struct Pkgsrc {
    /// Path to pkgsrc source tree.
    pub basedir: PathBuf,
    /// Path to bootstrap tarball (required on non-NetBSD).
    pub bootstrap: Option<PathBuf>,
    /// Unprivileged user for builds.
    pub build_user: Option<String>,
    /// Directory for build logs (defaults to dbdir/logs).
    pub logdir: Option<PathBuf>,
    /// Path to bmake binary.
    pub make: PathBuf,
    /// List of packages to build.
    pub pkgpaths: Option<Vec<PkgPath>>,
    /// Glob patterns for files to save from WRKDIR on failure.
    pub save_wrkdir_patterns: Vec<String>,
    /// pkgsrc variables to cache and re-set in each environment run.
    pub cachevars: Vec<String>,
    /// Path to tar binary (defaults to `tar` in PATH).
    pub tar: Option<PathBuf>,
}

/// Environment configuration from the `environment` section.
///
/// Controls the environment variables available to sandbox processes.
///
/// If this section is omitted from the config, the parent environment is
/// inherited unchanged.  If present, `clear` defaults to true and the
/// environment is cleared before applying the configured variables.
///
/// # Example
///
/// ```lua
/// environment = {
///     inherit = { "TERM", "HOME" },
///     set = {
///         PATH = "/sbin:/bin:/usr/sbin:/usr/bin",
///     },
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Environment {
    /// If true (default), clear the environment before setting variables.
    /// If false, inherit the full parent environment.
    pub clear: bool,
    /// Variable names to copy from the parent environment (when `clear = true`).
    pub inherit: Vec<String>,
    /// Variables to set explicitly.
    pub set: HashMap<String, String>,
}

impl Default for Environment {
    fn default() -> Self {
        Self {
            clear: true,
            inherit: Vec::new(),
            set: HashMap::new(),
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
///     actions = {
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
    /// Actions to perform during sandbox setup/teardown.
    ///
    /// See [`Action`] for details.
    pub actions: Vec<Action>,
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
        /*
         * Load user-supplied configuration file, or the default location.
         */
        let filename = if let Some(path) = config_path {
            if path.is_relative() {
                std::env::current_dir()
                    .context("Unable to determine current directory")?
                    .join(path)
            } else {
                path.to_path_buf()
            }
        } else {
            std::env::current_dir()
                .context("Unable to determine current directory")?
                .join("config.lua")
        };

        /* A configuration file is mandatory. */
        if !filename.exists() {
            anyhow::bail!("Configuration file {} does not exist", filename.display());
        }

        /*
         * Parse configuration file as Lua.
         */
        let (mut file, lua_env) =
            load_lua(&filename)
                .map_err(|e| anyhow!(e))
                .with_context(|| {
                    format!(
                        "Unable to parse Lua configuration file {}",
                        filename.display()
                    )
                })?;

        /*
         * Parse scripts section.  Paths are resolved relative to config dir
         * if not absolute.
         */
        let base_dir = filename.parent().unwrap_or_else(|| Path::new("."));
        let mut newscripts: HashMap<String, PathBuf> = HashMap::new();
        for (k, v) in &file.scripts {
            let fullpath = if v.is_relative() {
                base_dir.join(v)
            } else {
                v.clone()
            };
            newscripts.insert(k.clone(), fullpath);
        }
        file.scripts = newscripts;

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
         * Resolve dbdir: explicit value from options, or default to
         * "./db" relative to the config file directory.  Relative paths
         * are resolved against the config directory.
         */
        let raw_dbdir = file.options.as_ref().and_then(|o| o.dbdir.clone());
        let dbdir = match raw_dbdir {
            Some(p) if p.is_absolute() => p,
            Some(p) => base_dir.join(p),
            None => base_dir.join("db"),
        };

        /*
         * Default logdir to dbdir/logs if not explicitly set.
         */
        let logdir = file
            .pkgsrc
            .logdir
            .clone()
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
            lua_env,
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

    pub fn dynamic_jobs(&self) -> Option<&DynamicJobs> {
        self.file
            .options
            .as_ref()
            .and_then(|o| o.dynamic_jobs.as_ref())
    }

    pub fn script(&self, key: &str) -> Option<&PathBuf> {
        self.file.scripts.get(key)
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
        self.file.environment.as_ref()
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

    pub fn dbdir(&self) -> &PathBuf {
        &self.dbdir
    }

    pub fn logdir(&self) -> &PathBuf {
        &self.logdir
    }

    pub fn save_wrkdir_patterns(&self) -> &[String] {
        self.file.pkgsrc.save_wrkdir_patterns.as_slice()
    }

    pub fn tar(&self) -> Option<&PathBuf> {
        self.file.pkgsrc.tar.as_ref()
    }

    pub fn build_user(&self) -> Option<&str> {
        self.file.pkgsrc.build_user.as_deref()
    }

    pub fn bootstrap(&self) -> Option<&PathBuf> {
        self.file.pkgsrc.bootstrap.as_ref()
    }

    /// Return list of pkgsrc variable names to cache.
    pub fn cachevars(&self) -> &[String] {
        self.file.pkgsrc.cachevars.as_slice()
    }

    /// Get environment variables for a package from the Lua env function/table.
    pub fn get_pkg_env(
        &self,
        pkg: &ResolvedPackage,
    ) -> Result<std::collections::HashMap<String, String>, String> {
        self.lua_env.get_env(pkg)
    }

    /// Return environment variables for script execution.
    ///
    /// If `pkgsrc_env` is provided, includes the pkgsrc-derived variables
    /// (packages, pkgtools, prefix, pkg_dbdir, pkg_refcount_dbdir).
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
        let tar_value = self
            .tar()
            .map(|t| t.display().to_string())
            .unwrap_or_else(|| "tar".to_string());
        envs.push(("bob_tar".to_string(), tar_value));
        if let Some(build_user) = self.build_user() {
            envs.push(("bob_build_user".to_string(), build_user.to_string()));
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

        // Check scripts exist
        for (name, path) in &self.file.scripts {
            if !path.exists() {
                errors.push(format!(
                    "Script '{}' does not exist: {}",
                    name,
                    path.display()
                ));
            } else if !path.is_file() {
                errors.push(format!(
                    "Script '{}' is not a file: {}",
                    name,
                    path.display()
                ));
            }
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
            if let Some(ref dj) = opts.dynamic_jobs {
                if dj.max < 1 {
                    errors.push("dynamic_jobs.max must be at least 1".to_string());
                }
                if dj.min < 1 {
                    errors.push("dynamic_jobs.min must be at least 1".to_string());
                }
                if dj.min > dj.max {
                    errors.push("dynamic_jobs.min must not exceed dynamic_jobs.max".to_string());
                }
            }
            if opts.scan_threads == Some(0) {
                errors.push("scan_threads must be at least 1".to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Load a Lua configuration file and return a ConfigFile and LuaEnv.
fn load_lua(filename: &Path) -> Result<(ConfigFile, LuaEnv), String> {
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

    // Parse each section
    let options =
        parse_options(&globals).map_err(|e| format!("Error parsing options config: {}", e))?;
    let pkgsrc_table: Table = globals
        .get("pkgsrc")
        .map_err(|e| format!("Error getting pkgsrc config: {}", e))?;
    let pkgsrc =
        parse_pkgsrc(&globals).map_err(|e| format!("Error parsing pkgsrc config: {}", e))?;
    let scripts =
        parse_scripts(&globals).map_err(|e| format!("Error parsing scripts config: {}", e))?;
    let sandboxes =
        parse_sandboxes(&globals).map_err(|e| format!("Error parsing sandboxes config: {}", e))?;
    let environment = parse_environment(&globals)
        .map_err(|e| format!("Error parsing environment config: {}", e))?;

    // Store env function/table in registry if it exists
    let env_key = if let Ok(env_value) = pkgsrc_table.get::<Value>("env") {
        if !env_value.is_nil() {
            let key = lua
                .create_registry_value(env_value)
                .map_err(|e| format!("Failed to store env in registry: {}", e))?;
            Some(Arc::new(key))
        } else {
            None
        }
    } else {
        None
    };

    let lua_env = LuaEnv {
        lua: Arc::new(Mutex::new(lua)),
        env_key,
    };

    let config = ConfigFile {
        options,
        pkgsrc,
        scripts,
        sandboxes,
        environment,
    };

    Ok((config, lua_env))
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
        "dynamic_jobs",
        "log_level",
        "scan_threads",
        "strict_scan",
    ];
    warn_unknown_keys(table, "options", KNOWN_KEYS);

    let dynamic_jobs = match table.get::<Value>("dynamic_jobs")? {
        Value::Table(t) => {
            let max: usize = t
                .get("max")
                .map_err(|_| mlua::Error::runtime("dynamic_jobs.max is required"))?;
            let min: usize = t
                .get("min")
                .map_err(|_| mlua::Error::runtime("dynamic_jobs.min is required"))?;
            Some(DynamicJobs { max, min })
        }
        Value::Nil => None,
        _ => {
            return Err(mlua::Error::runtime(
                "dynamic_jobs must be a table with 'max' and 'min'",
            ));
        }
    };

    let dbdir: Option<PathBuf> = table.get::<Option<String>>("dbdir")?.map(PathBuf::from);

    Ok(Some(Options {
        build_threads: table.get("build_threads").ok(),
        dbdir,
        dynamic_jobs,
        scan_threads: table.get("scan_threads").ok(),
        strict_scan: table.get("strict_scan").ok(),
        log_level: table.get("log_level").ok(),
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

fn parse_pkgsrc(globals: &Table) -> LuaResult<Pkgsrc> {
    let pkgsrc: Table = globals.get("pkgsrc")?;

    const KNOWN_KEYS: &[&str] = &[
        "basedir",
        "bootstrap",
        "build_user",
        "cachevars",
        "env",
        "logdir",
        "make",
        "pkgpaths",
        "save_wrkdir_patterns",
        "tar",
    ];
    warn_unknown_keys(&pkgsrc, "pkgsrc", KNOWN_KEYS);

    let basedir = get_required_string(&pkgsrc, "basedir")?;
    let bootstrap: Option<PathBuf> = pkgsrc
        .get::<Option<String>>("bootstrap")?
        .map(PathBuf::from);
    let build_user: Option<String> = pkgsrc.get::<Option<String>>("build_user")?;
    let logdir: Option<PathBuf> = pkgsrc.get::<Option<String>>("logdir")?.map(PathBuf::from);
    let make = get_required_string(&pkgsrc, "make")?;
    let tar: Option<PathBuf> = pkgsrc.get::<Option<String>>("tar")?.map(PathBuf::from);

    let pkgpaths: Option<Vec<PkgPath>> = match pkgsrc.get::<Value>("pkgpaths")? {
        Value::Nil => None,
        Value::Table(t) => {
            let paths: Vec<PkgPath> = t
                .sequence_values::<String>()
                .filter_map(|r| r.ok())
                .filter_map(|s| PkgPath::new(&s).ok())
                .collect();
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
        cachevars,
        logdir,
        make: PathBuf::from(make),
        pkgpaths,
        save_wrkdir_patterns,
        tar,
    })
}

fn parse_scripts(globals: &Table) -> LuaResult<HashMap<String, PathBuf>> {
    let scripts: Value = globals.get("scripts")?;
    if scripts.is_nil() {
        return Ok(HashMap::new());
    }

    let table = scripts
        .as_table()
        .ok_or_else(|| mlua::Error::runtime("'scripts' must be a table"))?;

    let mut result = HashMap::new();
    for pair in table.pairs::<String, String>() {
        let (k, v) = pair?;
        result.insert(k, PathBuf::from(v));
    }

    Ok(result)
}

fn parse_sandboxes(globals: &Table) -> LuaResult<Option<Sandboxes>> {
    let sandboxes: Value = globals.get("sandboxes")?;
    if sandboxes.is_nil() {
        return Ok(None);
    }

    let table = sandboxes
        .as_table()
        .ok_or_else(|| mlua::Error::runtime("'sandboxes' must be a table"))?;

    const KNOWN_KEYS: &[&str] = &["actions", "basedir", "bindfs"];
    warn_unknown_keys(table, "sandboxes", KNOWN_KEYS);

    let basedir: String = table.get("basedir")?;
    let bindfs: String = table
        .get::<Option<String>>("bindfs")?
        .unwrap_or_else(|| String::from("bindfs"));

    let actions_value: Value = table.get("actions")?;
    let actions = if actions_value.is_nil() {
        Vec::new()
    } else {
        let actions_table = actions_value
            .as_table()
            .ok_or_else(|| mlua::Error::runtime("'sandboxes.actions' must be a table"))?;
        parse_actions(actions_table, globals)?
    };

    Ok(Some(Sandboxes {
        basedir: PathBuf::from(basedir),
        actions,
        bindfs,
    }))
}

fn parse_actions(table: &Table, globals: &Table) -> LuaResult<Vec<Action>> {
    let mut actions = Vec::new();
    for v in table.sequence_values::<Table>() {
        let mut action = Action::from_lua(&v?)?;
        if let Some(varpath) = action.ifset().map(String::from) {
            match resolve_lua_var(globals, &varpath) {
                Some(val) => action.substitute_var(&varpath, &val),
                None => continue,
            }
        }
        actions.push(action);
    }
    Ok(actions)
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

fn parse_environment(globals: &Table) -> LuaResult<Option<Environment>> {
    let environment: Value = globals.get("environment")?;
    if environment.is_nil() {
        return Ok(None);
    }

    let table = environment
        .as_table()
        .ok_or_else(|| mlua::Error::runtime("'environment' must be a table"))?;

    const KNOWN_KEYS: &[&str] = &["clear", "inherit", "set"];
    warn_unknown_keys(table, "environment", KNOWN_KEYS);

    let clear: bool = table.get::<Option<bool>>("clear")?.unwrap_or(true);

    let inherit: Vec<String> = match table.get::<Value>("inherit")? {
        Value::Nil => Vec::new(),
        Value::Table(t) => t
            .sequence_values::<String>()
            .filter_map(|r| r.ok())
            .collect(),
        _ => {
            return Err(mlua::Error::runtime(
                "'environment.inherit' must be a table",
            ));
        }
    };

    let set: HashMap<String, String> = match table.get::<Value>("set")? {
        Value::Nil => HashMap::new(),
        Value::Table(t) => {
            let mut map = HashMap::new();
            for pair in t.pairs::<String, String>() {
                let (k, v) = pair?;
                map.insert(k, v);
            }
            map
        }
        _ => return Err(mlua::Error::runtime("'environment.set' must be a table")),
    };

    Ok(Some(Environment {
        clear,
        inherit,
        set,
    }))
}
