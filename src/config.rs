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
//! The Config module is responsible for reading a mandatory configuration file,
//! parsing command line arguments related to configuration, and producing a
//! Config struct that combines the two for the rest of the program to use.

use crate::action::Action;
use crate::Args;
use mlua::{Lua, RegistryKey, Result as LuaResult, Table, Value};
use pkgsrc::{PkgPath, ScanIndex};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::{anyhow, Context, Result};
use std::sync::{Arc, Mutex};

extern crate dirs;


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
    pub fn get_env(&self, idx: &ScanIndex) -> Result<HashMap<String, String>, String> {
        let Some(env_key) = &self.env_key else {
            return Ok(HashMap::new());
        };

        let lua = self.lua.lock().map_err(|e| format!("Lua lock error: {}", e))?;

        // Get the env value from registry
        let env_value: Value = lua
            .registry_value(env_key)
            .map_err(|e| format!("Failed to get env from registry: {}", e))?;

        let result_table: Table = match env_value {
            // If it's a function, call it with pkg info
            Value::Function(func) => {
                let pkg_table = lua.create_table().map_err(|e| format!("Failed to create table: {}", e))?;

                // Set all ScanIndex fields
                pkg_table.set("pkgname", idx.pkgname.pkgname())
                    .map_err(|e| format!("Failed to set pkgname: {}", e))?;
                pkg_table.set("pkgpath", idx.pkg_location.as_ref().map(|p| p.as_path().display().to_string()).unwrap_or_default())
                    .map_err(|e| format!("Failed to set pkgpath: {}", e))?;
                pkg_table.set("all_depends", idx.all_depends.iter().map(|d| d.pkgpath().as_path().display().to_string()).collect::<Vec<_>>().join(" "))
                    .map_err(|e| format!("Failed to set all_depends: {}", e))?;
                pkg_table.set("pkg_skip_reason", idx.pkg_skip_reason.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set pkg_skip_reason: {}", e))?;
                pkg_table.set("pkg_fail_reason", idx.pkg_fail_reason.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set pkg_fail_reason: {}", e))?;
                pkg_table.set("no_bin_on_ftp", idx.no_bin_on_ftp.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set no_bin_on_ftp: {}", e))?;
                pkg_table.set("restricted", idx.restricted.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set restricted: {}", e))?;
                pkg_table.set("categories", idx.categories.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set categories: {}", e))?;
                pkg_table.set("maintainer", idx.maintainer.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set maintainer: {}", e))?;
                pkg_table.set("use_destdir", idx.use_destdir.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set use_destdir: {}", e))?;
                pkg_table.set("bootstrap_pkg", idx.bootstrap_pkg.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set bootstrap_pkg: {}", e))?;
                pkg_table.set("usergroup_phase", idx.usergroup_phase.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set usergroup_phase: {}", e))?;
                pkg_table.set("scan_depends", idx.scan_depends.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(" "))
                    .map_err(|e| format!("Failed to set scan_depends: {}", e))?;
                pkg_table.set("pbulk_weight", idx.pbulk_weight.clone().unwrap_or_default())
                    .map_err(|e| format!("Failed to set pbulk_weight: {}", e))?;
                pkg_table.set("multi_version", idx.multi_version.join(" "))
                    .map_err(|e| format!("Failed to set multi_version: {}", e))?;
                pkg_table.set("depends", idx.depends.iter().map(|d| d.pkgname()).collect::<Vec<_>>().join(" "))
                    .map_err(|e| format!("Failed to set depends: {}", e))?;

                func.call(pkg_table).map_err(|e| format!("Failed to call env function: {}", e))?
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

#[derive(Clone, Debug, Default)]
pub struct Config {
    file: ConfigFile,
    filename: PathBuf,
    verbose: bool,
    lua_env: LuaEnv,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigFile {
    pub options: Option<Options>,
    pub pkgsrc: Pkgsrc,
    pub scripts: HashMap<String, PathBuf>,
    pub sandboxes: Option<Sandboxes>,
}

#[derive(Clone, Debug, Default)]
pub struct Options {
    pub build_threads: Option<usize>,
    pub scan_threads: Option<usize>,
    pub verbose: Option<bool>,
}

///
/// pkgsrc-related configuration variables.
///
#[derive(Clone, Debug, Default)]
pub struct Pkgsrc {
    pub basedir: PathBuf,
    pub bootstrap: Option<PathBuf>,
    pub build_user: Option<String>,
    pub bulklog: PathBuf,
    pub make: PathBuf,
    pub packages: PathBuf,
    pub pkgtools: PathBuf,
    pub pkgpaths: Option<Vec<PkgPath>>,
    pub prefix: PathBuf,
    pub report_dir: Option<PathBuf>,
    pub save_wrkdir_patterns: Vec<String>,
    pub tar: PathBuf,
}

///
/// Optional sandboxes section
///
#[derive(Clone, Debug, Default)]
pub struct Sandboxes {
    pub basedir: PathBuf,
    pub actions: Vec<Action>,
}

impl Config {
    pub fn load(args: &Args) -> Result<Config> {
        let mut config: Config = Default::default();

        /*
         * Load user-supplied configuration file, or the default location based
         * on the `dirs` module.
         */
        config.filename = if args.config.is_some() {
            args.config.clone().unwrap()
        } else {
            let config_dir = dirs::config_dir()
                .ok_or_else(|| anyhow!("Unable to determine configuration directory"))?;
            config_dir.join("bob.lua")
        };

        /* A configuration file is mandatory. */
        if !config.filename.exists() {
            anyhow::bail!("Configuration file {} does not exist", config.filename.display());
        }

        /*
         * Parse configuration file as Lua.
         */
        let (cfg, lua_env) = load_lua(&config.filename)
            .map_err(|e| anyhow!(e))
            .with_context(|| format!("Unable to parse Lua configuration file {}", config.filename.display()))?;
        config.file = cfg;
        config.lua_env = lua_env;

        /*
         * Parse scripts section.  Paths are resolved relative to config dir
         * if not absolute.
         */
        let mut newscripts: HashMap<String, PathBuf> = HashMap::new();
        for (k, v) in &config.file.scripts {
            let base_dir = config.filename.parent().unwrap_or_else(|| Path::new("."));
            let fullpath = if v.is_relative() {
                base_dir.join(v)
            } else {
                v.clone()
            };
            newscripts.insert(k.clone(), fullpath);
        }
        /*
         * Overwrite scripts map, we're done with the input.
         */
        config.file.scripts = newscripts;

        /*
         * Set any top-level Config variables that can be set either via the
         * command line or configuration file, preferring command line options.
         */
        if args.verbose {
            config.verbose = true
        } else if let Some(v) = &config.file.options {
            config.verbose = v.verbose.unwrap_or(false);
        }

        Ok(config)
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

    pub fn bulklog(&self) -> &PathBuf {
        &self.file.pkgsrc.bulklog
    }

    pub fn packages(&self) -> &PathBuf {
        &self.file.pkgsrc.packages
    }

    pub fn pkgtools(&self) -> &PathBuf {
        &self.file.pkgsrc.pkgtools
    }

    pub fn prefix(&self) -> &PathBuf {
        &self.file.pkgsrc.prefix
    }

    #[allow(dead_code)]
    pub fn report_dir(&self) -> Option<&PathBuf> {
        self.file.pkgsrc.report_dir.as_ref()
    }

    pub fn save_wrkdir_patterns(&self) -> &[String] {
        self.file.pkgsrc.save_wrkdir_patterns.as_slice()
    }

    pub fn tar(&self) -> &PathBuf {
        &self.file.pkgsrc.tar
    }

    pub fn build_user(&self) -> Option<&str> {
        self.file.pkgsrc.build_user.as_deref()
    }

    pub fn bootstrap(&self) -> Option<&PathBuf> {
        self.file.pkgsrc.bootstrap.as_ref()
    }

    /// Get environment variables for a package from the Lua env function/table.
    pub fn get_pkg_env(&self, idx: &ScanIndex) -> Result<std::collections::HashMap<String, String>, String> {
        self.lua_env.get_env(idx)
    }

    /// Return environment variables for script execution.
    pub fn script_env(&self) -> Vec<(String, String)> {
        let mut envs = vec![
            ("bob_bulklog".to_string(), format!("{}", self.bulklog().display())),
            ("bob_make".to_string(), format!("{}", self.make().display())),
            ("bob_packages".to_string(), format!("{}", self.packages().display())),
            ("bob_pkgtools".to_string(), format!("{}", self.pkgtools().display())),
            ("bob_pkgsrc".to_string(), format!("{}", self.pkgsrc().display())),
            ("bob_prefix".to_string(), format!("{}", self.prefix().display())),
            ("bob_tar".to_string(), format!("{}", self.tar().display())),
        ];
        if let Some(build_user) = self.build_user() {
            envs.push(("bob_build_user".to_string(), build_user.to_string()));
        }
        if let Some(bootstrap) = self.bootstrap() {
            envs.push(("bob_bootstrap".to_string(), format!("{}", bootstrap.display())));
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

        // Check bulklog dir can be created
        if let Some(parent) = self.file.pkgsrc.bulklog.parent() {
            if !parent.exists() {
                errors.push(format!(
                    "Bulklog parent directory does not exist: {}",
                    parent.display()
                ));
            }
        }

        // Check packages dir can be created
        if let Some(parent) = self.file.pkgsrc.packages.parent() {
            if !parent.exists() {
                errors.push(format!(
                    "Packages parent directory does not exist: {}",
                    parent.display()
                ));
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
    let options = parse_options(&globals).map_err(|e| format!("Error parsing options: {}", e))?;
    let pkgsrc_table: Table = globals.get("pkgsrc").map_err(|e| format!("Error getting pkgsrc: {}", e))?;
    let pkgsrc = parse_pkgsrc(&globals).map_err(|e| format!("Error parsing pkgsrc: {}", e))?;
    let scripts = parse_scripts(&globals).map_err(|e| format!("Error parsing scripts: {}", e))?;
    let sandboxes =
        parse_sandboxes(&globals).map_err(|e| format!("Error parsing sandboxes: {}", e))?;

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
    };

    Ok((config, lua_env))
}

fn parse_options(globals: &Table) -> LuaResult<Option<Options>> {
    let options: Value = globals.get("options")?;
    if options.is_nil() {
        return Ok(None);
    }

    let table = options.as_table().ok_or_else(|| {
        mlua::Error::runtime("options must be a table")
    })?;

    Ok(Some(Options {
        build_threads: table.get("build_threads").ok(),
        scan_threads: table.get("scan_threads").ok(),
        verbose: table.get("verbose").ok(),
    }))
}

fn parse_pkgsrc(globals: &Table) -> LuaResult<Pkgsrc> {
    let pkgsrc: Table = globals.get("pkgsrc")?;

    let basedir: String = pkgsrc.get("basedir")?;
    let bootstrap: Option<PathBuf> = pkgsrc
        .get::<Option<String>>("bootstrap")?
        .map(PathBuf::from);
    let build_user: Option<String> = pkgsrc.get::<Option<String>>("build_user")?;
    let bulklog: String = pkgsrc.get("bulklog")?;
    let make: String = pkgsrc.get("make")?;
    let packages: String = pkgsrc.get("packages")?;
    let pkgtools: String = pkgsrc.get("pkgtools")?;
    let prefix: String = pkgsrc.get("prefix")?;
    let tar: String = pkgsrc.get("tar")?;

    let pkgpaths: Option<Vec<PkgPath>> = match pkgsrc.get::<Value>("pkgpaths")? {
        Value::Nil => None,
        Value::Table(t) => {
            let paths: Vec<PkgPath> = t
                .sequence_values::<String>()
                .filter_map(|r| r.ok())
                .filter_map(|s| PkgPath::new(&s).ok())
                .collect();
            if paths.is_empty() {
                None
            } else {
                Some(paths)
            }
        }
        _ => None,
    };

    let report_dir: Option<PathBuf> = pkgsrc
        .get::<Option<String>>("report_dir")?
        .map(PathBuf::from);

    let save_wrkdir_patterns: Vec<String> = match pkgsrc.get::<Value>("save_wrkdir_patterns")? {
        Value::Nil => Vec::new(),
        Value::Table(t) => t.sequence_values::<String>().filter_map(|r| r.ok()).collect(),
        _ => Vec::new(),
    };

    Ok(Pkgsrc {
        basedir: PathBuf::from(basedir),
        bootstrap,
        build_user,
        bulklog: PathBuf::from(bulklog),
        make: PathBuf::from(make),
        packages: PathBuf::from(packages),
        pkgtools: PathBuf::from(pkgtools),
        pkgpaths,
        prefix: PathBuf::from(prefix),
        report_dir,
        save_wrkdir_patterns,
        tar: PathBuf::from(tar),
    })
}

fn parse_scripts(globals: &Table) -> LuaResult<HashMap<String, PathBuf>> {
    let scripts: Value = globals.get("scripts")?;
    if scripts.is_nil() {
        return Ok(HashMap::new());
    }

    let table = scripts.as_table().ok_or_else(|| {
        mlua::Error::runtime("scripts must be a table")
    })?;

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

    let table = sandboxes.as_table().ok_or_else(|| {
        mlua::Error::runtime("sandboxes must be a table")
    })?;

    let basedir: String = table.get("basedir")?;

    let actions_value: Value = table.get("actions")?;
    let actions = if actions_value.is_nil() {
        Vec::new()
    } else {
        let actions_table = actions_value.as_table().ok_or_else(|| {
            mlua::Error::runtime("sandboxes.actions must be a table")
        })?;
        parse_actions(actions_table)?
    };

    Ok(Some(Sandboxes {
        basedir: PathBuf::from(basedir),
        actions,
    }))
}

fn parse_actions(table: &Table) -> LuaResult<Vec<Action>> {
    table
        .sequence_values::<Table>()
        .map(|v| Action::from_lua(&v?))
        .collect()
}
