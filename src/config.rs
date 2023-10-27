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
 * The Config module is responsible for taking an optional configuration file
 * and command line arguments, and producing a configuration object that merges
 * the two for the rest of the program to use.
 */

use crate::Args;
use serde_derive::Deserialize;
use std::fs;
use std::path::PathBuf;

extern crate dirs;
extern crate toml;

#[derive(Debug, Deserialize)]
pub struct Config {
    filename: PathBuf,
    verbose: bool,
}

#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    verbose: Option<bool>,
}

impl Config {
    pub fn load(args: &Args) -> Result<Config, std::io::Error> {
        /*
         * Initialise a Config struct with default values.
         */
        let mut config = Config {
            filename: PathBuf::new(),
            verbose: false,
        };

        /*
         * Load user-supplied configuration file, or the default location based
         * on the `dirs` module.
         */
        config.filename = if args.config.is_some() {
            PathBuf::from(args.config.clone().unwrap())
        } else {
            dirs::config_dir().unwrap().join("bob.toml")
        };

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
        let cfgfile: ConfigFile =
            toml::from_str(&fs::read_to_string(&config.filename)?).unwrap();

        /*
         * Set Config variables, preferring command line options.
         */
        config.verbose = args.verbose || cfgfile.verbose.unwrap_or(false);

        Ok(config)
    }
}
