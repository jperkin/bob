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

use crate::Args;
use serde_derive::Deserialize;
use std::fs;
use std::path::PathBuf;

extern crate dirs;
extern crate toml;

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    file: ConfigFile,
    filename: PathBuf,
    verbose: bool,
}

#[derive(Debug, Default, Deserialize)]
struct ConfigFile {
    mounts: Option<Vec<Mount>>,
    pkgpaths: Option<Vec<String>>,
    pkgsrc: PathBuf,
    sandbox: PathBuf,
    verbose: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Mount {
    dir: PathBuf,
    fs: String,
    opts: Option<String>,
}

impl Config {
    pub fn load(args: &Args) -> Result<Config, std::io::Error> {
        let mut config: Config = Default::default();

        /*
         * Load user-supplied configuration file, or the default location based
         * on the `dirs` module.
         */
        config.filename = if args.config.is_some() {
            PathBuf::from(args.config.clone().unwrap())
        } else {
            dirs::config_dir().unwrap().join("bob.toml")
        };

        /* A configuration file is mandatory. */
        if !config.filename.exists() {
            eprintln!(
                "ERROR: Configuration file {} does not exist",
                config.filename.display()
            );
            std::process::exit(1);
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
                std::process::exit(1);
            }
        };

        /*
         * Set any top-level Config variables that can be set either via the
         * command line or configuration file, preferring command line options.
         */
        config.verbose = args.verbose || config.file.verbose.unwrap_or(false);

        Ok(config)
    }

    pub fn mounts(&self) -> &Option<Vec<Mount>> {
        &self.file.mounts
    }

    pub fn pkgpaths(&self) -> &Option<Vec<String>> {
        &self.file.pkgpaths
    }

    pub fn pkgsrc(&self) -> &PathBuf {
        &self.file.pkgsrc
    }

    pub fn sandbox(&self) -> &PathBuf {
        &self.file.sandbox
    }
}

impl Mount {
    pub fn dir(&self) -> &PathBuf {
        &self.dir
    }

    pub fn fs(&self) -> &String {
        &self.fs
    }

    pub fn opts(&self) -> &Option<String> {
        &self.opts
    }
}
