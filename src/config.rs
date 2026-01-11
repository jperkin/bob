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

//! Configuration file parsing (Lua format).
//!
//! Bob uses Lua configuration files for maximum flexibility. The configuration
//! defines paths to pkgsrc, packages to build, sandbox setup, and build scripts.
//!
//! # Configuration File Structure
//!
//! A configuration file has four main sections:
//!
//! - [`options`](#options-section) - General build options (optional)
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
//! | `scan_threads` | integer | 1 | Number of parallel scan processes for dependency discovery. |
//! | `strict_scan` | boolean | false | If true, abort on scan errors. If false, continue and report failures separately. |
//! | `verbose` | boolean | false | Enable verbose output. Can be overridden by the `-v` command line flag. |
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
//! | `logdir` | string | Directory for all logs. Per-package build logs go in subdirectories. Failed builds leave logs here; successful builds clean up. |
//! | `make` | string | Absolute path to the bmake binary (e.g., `/usr/pkg/bin/bmake`). |
//!
//! ## Optional Fields
//!
//! | Field | Type | Default | Description |
//! |-------|------|---------|-------------|
//! | `bootstrap` | string | none | Path to a bootstrap tarball. Required on non-NetBSD systems. Unpacked into each sandbox before builds. |
//! | `tar` | string | none | Absolute path to a tar binary capable of extracting the bootstrap kit. Required when `bootstrap` is set. |
//! | `build_user` | string | none | Unprivileged user to run builds as. If set, builds run as this user instead of root. |
//! | `pkgpaths` | table | `{}` | List of package paths to build (e.g., `{"mail/mutt", "www/curl"}`). Dependencies are discovered automatically. |
//! | `save_wrkdir_patterns` | table | `{}` | Glob patterns for files to preserve from WRKDIR on build failure (e.g., `{"**/config.log"}`). |
//! | `env` | function or table | `{}` | Environment variables for builds. Can be a table of key-value pairs, or a function receiving package metadata and returning a table. See [Environment Function](#environment-function). |
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
//! | `bob_logdir` | Path to the log directory. |
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
//! | `bob_status_fd` | File descriptor for sending status messages back to bob. |
//!
//! ## Status Messages
//!
//! Scripts can send status updates to bob by writing to the file descriptor
//! in `bob_status_fd`:
//!
//! | Message | Description |
//! |---------|-------------|
//! | `stage:<name>` | Build entered a new phase (e.g., `stage:configure`). Displayed in the TUI. |
//! | `skipped` | Package was skipped (e.g., already up-to-date). |
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
}

impl PkgsrcEnv {
    /// Fetch pkgsrc environment variables by querying bmake.
    ///
    /// This must be called after sandbox 0 is created if sandboxes are enabled,
    /// since bmake may only exist inside the sandbox.
    pub fn fetch(config: &Config, sandbox: &Sandbox) -> Result<Self> {
        const VARNAMES: &[&str] = &[
            "PACKAGES",
            "PKG_DBDIR",
            "PKG_REFCOUNT_DBDIR",
            "PKG_TOOLS_BIN",
            "PREFIX",
        ];

        let varnames_arg = VARNAMES.join(" ");
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

        if lines.len() != VARNAMES.len() {
            bail!(
                "Expected {} variables from pkgsrc, got {}",
                VARNAMES.len(),
                lines.len()
            );
        }

        let mut values: HashMap<&str, &str> = HashMap::new();
        for (varname, value) in VARNAMES.iter().zip(lines) {
            if value.is_empty() {
                bail!("pkgsrc returned empty value for {}", varname);
            }
            values.insert(varname, value);
        }

        Ok(PkgsrcEnv {
            packages: PathBuf::from(values["PACKAGES"]),
            pkgtools: PathBuf::from(values["PKG_TOOLS_BIN"]),
            prefix: PathBuf::from(values["PREFIX"]),
            pkg_dbdir: PathBuf::from(values["PKG_DBDIR"]),
            pkg_refcount_dbdir: PathBuf::from(values["PKG_REFCOUNT_DBDIR"]),
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
        Self { lua: Arc::new(Mutex::new(Lua::new())), env_key: None }
    }
}

impl LuaEnv {
    /// Get environment variables for a package by calling the env function.
    /// Returns a HashMap of VAR_NAME -> value.
    pub fn get_env(
        &self,
        pkg: &ResolvedPackage,
    ) -> Result<HashMap<String, String>, String> {
        let Some(env_key) = &self.env_key else {
            return Ok(HashMap::new());
        };

        let lua =
            self.lua.lock().map_err(|e| format!("Lua lock error: {}", e))?;

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
                                    .map(|d| {
                                        d.pkgpath()
                                            .as_path()
                                            .display()
                                            .to_string()
                                    })
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
                    .map_err(|e| {
                        format!("Failed to set pkg_skip_reason: {}", e)
                    })?;
                pkg_table
                    .set(
                        "pkg_fail_reason",
                        idx.pkg_fail_reason.clone().unwrap_or_default(),
                    )
                    .map_err(|e| {
                        format!("Failed to set pkg_fail_reason: {}", e)
                    })?;
                pkg_table
                    .set(
                        "no_bin_on_ftp",
                        idx.no_bin_on_ftp.clone().unwrap_or_default(),
                    )
                    .map_err(|e| {
                        format!("Failed to set no_bin_on_ftp: {}", e)
                    })?;
                pkg_table
                    .set(
                        "restricted",
                        idx.restricted.clone().unwrap_or_default(),
                    )
                    .map_err(|e| format!("Failed to set restricted: {}", e))?;
                pkg_table
                    .set(
                        "categories",
                        idx.categories.clone().unwrap_or_default(),
                    )
                    .map_err(|e| format!("Failed to set categories: {}", e))?;
                pkg_table
                    .set(
                        "maintainer",
                        idx.maintainer.clone().unwrap_or_default(),
                    )
                    .map_err(|e| format!("Failed to set maintainer: {}", e))?;
                pkg_table
                    .set(
                        "use_destdir",
                        idx.use_destdir.clone().unwrap_or_default(),
                    )
                    .map_err(|e| format!("Failed to set use_destdir: {}", e))?;
                pkg_table
                    .set(
                        "bootstrap_pkg",
                        idx.bootstrap_pkg.clone().unwrap_or_default(),
                    )
                    .map_err(|e| {
                        format!("Failed to set bootstrap_pkg: {}", e)
                    })?;
                pkg_table
                    .set(
                        "usergroup_phase",
                        idx.usergroup_phase.clone().unwrap_or_default(),
                    )
                    .map_err(|e| {
                        format!("Failed to set usergroup_phase: {}", e)
                    })?;
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
                    .map_err(|e| {
                        format!("Failed to set scan_depends: {}", e)
                    })?;
                pkg_table
                    .set(
                        "pbulk_weight",
                        idx.pbulk_weight.clone().unwrap_or_default(),
                    )
                    .map_err(|e| {
                        format!("Failed to set pbulk_weight: {}", e)
                    })?;
                pkg_table
                    .set(
                        "multi_version",
                        idx.multi_version
                            .as_ref()
                            .map(|v| v.join(" "))
                            .unwrap_or_default(),
                    )
                    .map_err(|e| {
                        format!("Failed to set multi_version: {}", e)
                    })?;
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

                func.call(pkg_table).map_err(|e| {
                    format!("Failed to call env function: {}", e)
                })?
            }
            // If it's a table, use it directly
            Value::Table(t) => t,
            Value::Nil => return Ok(HashMap::new()),
            _ => return Err("env must be a function or table".to_string()),
        };

        // Convert Lua table to HashMap
        let mut env = HashMap::new();
        for pair in result_table.pairs::<String, String>() {
            let (k, v) = pair
                .map_err(|e| format!("Failed to iterate env table: {}", e))?;
            env.insert(k, v);
        }

        Ok(env)
    }
}

/// Main configuration structure.
#[derive(Clone, Debug, Default)]
pub struct Config {
    file: ConfigFile,
    filename: PathBuf,
    verbose: bool,
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
}

/// General build options from the `options` section.
///
/// All fields are optional; defaults are used when not specified:
/// - `build_threads`: 1
/// - `scan_threads`: 1
/// - `verbose`: false
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Number of parallel build sandboxes.
    pub build_threads: Option<usize>,
    /// Number of parallel scan processes.
    pub scan_threads: Option<usize>,
    /// If true, abort on scan errors. If false, continue and report failures.
    pub strict_scan: Option<bool>,
    /// Enable verbose output.
    pub verbose: Option<bool>,
}

/// pkgsrc-related configuration from the `pkgsrc` section.
///
/// # Required Fields
///
/// - `basedir`: Path to pkgsrc source tree
/// - `logdir`: Directory for logs
/// - `make`: Path to bmake binary
///
/// # Optional Fields
///
/// - `bootstrap`: Path to bootstrap tarball (required on non-NetBSD systems)
/// - `build_user`: Unprivileged user for builds
/// - `pkgpaths`: List of packages to build
/// - `save_wrkdir_patterns`: Glob patterns for files to save on build failure
/// - `tar`: Path to tar binary (required when bootstrap is configured)
#[derive(Clone, Debug, Default)]
pub struct Pkgsrc {
    /// Path to pkgsrc source tree.
    pub basedir: PathBuf,
    /// Path to bootstrap tarball (required on non-NetBSD).
    pub bootstrap: Option<PathBuf>,
    /// Unprivileged user for builds.
    pub build_user: Option<String>,
    /// Directory for logs.
    pub logdir: PathBuf,
    /// Path to bmake binary.
    pub make: PathBuf,
    /// List of packages to build.
    pub pkgpaths: Option<Vec<PkgPath>>,
    /// Glob patterns for files to save from WRKDIR on failure.
    pub save_wrkdir_patterns: Vec<String>,
    /// Environment variables for scan processes.
    pub scanenv: HashMap<String, String>,
    /// Path to tar binary (required when bootstrap is configured).
    pub tar: Option<PathBuf>,
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
///     basedir = "/data/chroot/bob",
///     actions = {
///         { action = "mount", fs = "proc", dir = "/proc" },
///         { action = "copy", dir = "/etc" },
///     },
/// }
/// ```
#[derive(Clone, Debug, Default)]
pub struct Sandboxes {
    /// Base directory for sandbox roots (e.g., `/data/chroot/bob`).
    ///
    /// Individual sandboxes are created as numbered subdirectories:
    /// `basedir/0`, `basedir/1`, etc.
    pub basedir: PathBuf,
    /// Actions to perform during sandbox setup/teardown.
    ///
    /// See [`Action`] for details.
    pub actions: Vec<Action>,
}

impl Config {
    /// Load configuration from a Lua file.
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to configuration file, or `None` to use `./config.lua`
    /// * `verbose` - Enable verbose output (overrides config file setting)
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration file doesn't exist or contains
    /// invalid Lua syntax.
    pub fn load(config_path: Option<&Path>, verbose: bool) -> Result<Config> {
        /*
         * Load user-supplied configuration file, or the default location.
         */
        let filename = if let Some(path) = config_path {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .context("Unable to determine current directory")?
                .join("config.lua")
        };

        /* A configuration file is mandatory. */
        if !filename.exists() {
            anyhow::bail!(
                "Configuration file {} does not exist",
                filename.display()
            );
        }

        /*
         * Parse configuration file as Lua.
         */
        let (mut file, lua_env) =
            load_lua(&filename).map_err(|e| anyhow!(e)).with_context(|| {
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
            let fullpath =
                if v.is_relative() { base_dir.join(v) } else { v.clone() };
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
         * Set verbose from command line option, falling back to config file.
         */
        let verbose = if verbose {
            true
        } else if let Some(v) = &file.options {
            v.verbose.unwrap_or(false)
        } else {
            false
        };

        Ok(Config {
            file,
            filename,
            verbose,
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

    pub fn verbose(&self) -> bool {
        self.verbose
    }

    /// Return the path to the configuration file.
    pub fn config_path(&self) -> Option<&Path> {
        if self.filename.as_os_str().is_empty() {
            None
        } else {
            Some(&self.filename)
        }
    }

    pub fn logdir(&self) -> &PathBuf {
        &self.file.pkgsrc.logdir
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
    pub fn script_env(&self, pkgsrc_env: Option<&PkgsrcEnv>) -> Vec<(String, String)> {
        let mut envs = vec![
            ("bob_logdir".to_string(), format!("{}", self.logdir().display())),
            ("bob_make".to_string(), format!("{}", self.make().display())),
            ("bob_pkgsrc".to_string(), format!("{}", self.pkgsrc().display())),
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
        }
        if let Some(tar) = self.tar() {
            envs.push(("bob_tar".to_string(), format!("{}", tar.display())));
        }
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

    /// Return environment variables for scan processes.
    pub fn scan_env(&self) -> Vec<(String, String)> {
        self.file
            .pkgsrc
            .scanenv
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
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

        // Check logdir can be created
        if let Some(parent) = self.file.pkgsrc.logdir.parent() {
            if !parent.exists() {
                errors.push(format!(
                    "logdir parent directory does not exist: {}",
                    parent.display()
                ));
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }
}

/// Load a Lua configuration file and return a ConfigFile and LuaEnv.
fn load_lua(filename: &Path) -> Result<(ConfigFile, LuaEnv), String> {
    let lua = Lua::new();

    // Add config directory to package.path so require() finds relative modules
    if let Some(config_dir) = filename.parent() {
        let path_setup = format!(
            "package.path = '{}' .. '/?.lua;' .. package.path",
            config_dir.display()
        );
        lua.load(&path_setup)
            .exec()
            .map_err(|e| format!("Failed to set package.path: {}", e))?;
    }

    lua.load(filename)
        .exec()
        .map_err(|e| format!("Lua execution error: {}", e))?;

    // Get the global table (Lua script should set global variables)
    let globals = lua.globals();

    // Parse each section
    let options = parse_options(&globals)
        .map_err(|e| format!("Error parsing options config: {}", e))?;
    let pkgsrc_table: Table = globals
        .get("pkgsrc")
        .map_err(|e| format!("Error getting pkgsrc config: {}", e))?;
    let pkgsrc = parse_pkgsrc(&globals)
        .map_err(|e| format!("Error parsing pkgsrc config: {}", e))?;
    let scripts = parse_scripts(&globals)
        .map_err(|e| format!("Error parsing scripts config: {}", e))?;
    let sandboxes = parse_sandboxes(&globals)
        .map_err(|e| format!("Error parsing sandboxes config: {}", e))?;

    // Store env function/table in registry if it exists
    let env_key = if let Ok(env_value) = pkgsrc_table.get::<Value>("env") {
        if !env_value.is_nil() {
            let key = lua.create_registry_value(env_value).map_err(|e| {
                format!("Failed to store env in registry: {}", e)
            })?;
            Some(Arc::new(key))
        } else {
            None
        }
    } else {
        None
    };

    let lua_env = LuaEnv { lua: Arc::new(Mutex::new(lua)), env_key };

    let config = ConfigFile { options, pkgsrc, scripts, sandboxes };

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

    const KNOWN_KEYS: &[&str] =
        &["build_threads", "scan_threads", "strict_scan", "verbose"];
    warn_unknown_keys(table, "options", KNOWN_KEYS);

    Ok(Some(Options {
        build_threads: table.get("build_threads").ok(),
        scan_threads: table.get("scan_threads").ok(),
        strict_scan: table.get("strict_scan").ok(),
        verbose: table.get("verbose").ok(),
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
        "env",
        "logdir",
        "make",
        "pkgpaths",
        "save_wrkdir_patterns",
        "scanenv",
        "tar",
    ];
    warn_unknown_keys(&pkgsrc, "pkgsrc", KNOWN_KEYS);

    let basedir = get_required_string(&pkgsrc, "basedir")?;
    let bootstrap: Option<PathBuf> =
        pkgsrc.get::<Option<String>>("bootstrap")?.map(PathBuf::from);
    let build_user: Option<String> =
        pkgsrc.get::<Option<String>>("build_user")?;
    let logdir = get_required_string(&pkgsrc, "logdir")?;
    let make = get_required_string(&pkgsrc, "make")?;
    let tar: Option<PathBuf> =
        pkgsrc.get::<Option<String>>("tar")?.map(PathBuf::from);

    let pkgpaths: Option<Vec<PkgPath>> =
        match pkgsrc.get::<Value>("pkgpaths")? {
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

    let save_wrkdir_patterns: Vec<String> =
        match pkgsrc.get::<Value>("save_wrkdir_patterns")? {
            Value::Nil => Vec::new(),
            Value::Table(t) => {
                t.sequence_values::<String>().filter_map(|r| r.ok()).collect()
            }
            _ => Vec::new(),
        };

    let scanenv: HashMap<String, String> =
        match pkgsrc.get::<Value>("scanenv")? {
            Value::Nil => HashMap::new(),
            Value::Table(t) => {
                t.pairs::<String, String>().filter_map(|r| r.ok()).collect()
            }
            _ => HashMap::new(),
        };

    Ok(Pkgsrc {
        basedir: PathBuf::from(basedir),
        bootstrap,
        build_user,
        logdir: PathBuf::from(logdir),
        make: PathBuf::from(make),
        pkgpaths,
        save_wrkdir_patterns,
        scanenv,
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

    const KNOWN_KEYS: &[&str] = &["actions", "basedir"];
    warn_unknown_keys(table, "sandboxes", KNOWN_KEYS);

    let basedir: String = table.get("basedir")?;

    let actions_value: Value = table.get("actions")?;
    let actions = if actions_value.is_nil() {
        Vec::new()
    } else {
        let actions_table = actions_value.as_table().ok_or_else(|| {
            mlua::Error::runtime("'sandboxes.actions' must be a table")
        })?;
        parse_actions(actions_table)?
    };

    Ok(Some(Sandboxes { basedir: PathBuf::from(basedir), actions }))
}

fn parse_actions(table: &Table) -> LuaResult<Vec<Action>> {
    table.sequence_values::<Table>().map(|v| Action::from_lua(&v?)).collect()
}
