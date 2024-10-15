/*
 * Copyright (c) 2023 Jonathan Perkin <jonathan@perkin.org.uk>
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
 * The Config module is responsible for reading a mandatory configuration file,
 * parsing command line arguments related to configuration, and producing a
 * Config struct that combines the two for the rest of the program to use.
 */

use crate::{Args, Sandbox};
use pkgsrc::PkgPath;
use serde::Deserialize;
use std::fs;

use std::path::PathBuf;
use std::process::exit;

extern crate dirs;
extern crate toml;

#[derive(Clone, Debug, Default)]
pub struct Config {
    file: ConfigFile,
    filename: PathBuf,
    ///
    /// Variables that can be set either through the configuration file or the
    /// command line, with the latter taking preference.
    ///
    verbose: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ConfigFile {
    options: Option<Options>,
    pkgsrc: Pkgsrc,
    sandbox: Option<Sandbox>,
}

///
/// General configuration variables.
///
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Options {
    build_threads: Option<usize>,
    scan_threads: Option<usize>,
    /// Enable verbose output.
    verbose: Option<bool>,
}

///
/// pkgsrc-related configuration variables.
///
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Pkgsrc {
    basedir: PathBuf,
    make: PathBuf,
    pkgpaths: Option<Vec<PkgPath>>,
}

impl Config {
    pub fn load(args: &Args) -> Result<Config, std::io::Error> {
        let mut config: Config = Default::default();

        /*
         * Load user-supplied configuration file, or the default location based
         * on the `dirs` module.
         */
        config.filename = if args.config.is_some() {
            args.config.clone().unwrap()
        } else {
            dirs::config_dir().unwrap().join("bob.toml")
        };

        /* A configuration file is mandatory. */
        if !config.filename.exists() {
            eprintln!(
                "ERROR: Configuration file {} does not exist",
                config.filename.display()
            );
            exit(1);
        }

        /*
         * Read configuration file and parse directly into new ConfigFile.
         */
        let cfgstr = &fs::read_to_string(&config.filename)?;
        config.file = match toml::from_str(cfgstr) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("ERROR: Unable to parse configuration file!");
                eprintln!(" file: {}", config.filename.display());
                eprintln!("  err: {}", e.message());
                eprintln!(
                    "   at: {} (offset {:?})",
                    &cfgstr[e.span().unwrap()],
                    e.span().unwrap()
                );
                exit(1);
            }
        };

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

    pub fn make(&self) -> &PathBuf {
        &self.file.pkgsrc.make
    }

    pub fn pkgpaths(&self) -> &Option<Vec<PkgPath>> {
        &self.file.pkgsrc.pkgpaths
    }

    pub fn pkgsrc(&self) -> &PathBuf {
        &self.file.pkgsrc.basedir
    }

    pub fn sandbox(&self) -> &Option<Sandbox> {
        &self.file.sandbox
    }

    pub fn verbose(&self) -> bool {
        self.verbose
    }
}
