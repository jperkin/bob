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

/*!
 * Configuration directory initialisation.
 *
 * Creates a new bob configuration directory with a platform-appropriate
 * `config.lua`.
 */

use anyhow::bail;
use std::env;
use std::fs;
use std::path::PathBuf;

/**
 * Configuration directory generator for `bob init`.
 */
pub struct Init {}

impl Init {
    /**
     * Create a new configuration directory at `dir`.
     *
     * Generates a platform-specific `config.lua`.  The directory must not
     * already exist or must be empty.
     */
    pub fn create(dir: &PathBuf) -> anyhow::Result<()> {
        let dir = if dir.is_absolute() {
            dir.to_path_buf()
        } else {
            env::current_dir()?.join(dir)
        };
        if dir.exists() {
            if !dir.is_dir() {
                bail!("{} exists and is not a directory", dir.display());
            }
            if fs::read_dir(&dir)?.next().is_some() {
                bail!("{} exists and is not empty", dir.display());
            }
        }

        println!(
            "Initialising new configuration directory {}:",
            dir.display()
        );

        let confstr = match env::consts::OS {
            "illumos" => include_str!("../config/illumos.lua"),
            "linux" => include_str!("../config/linux.lua"),
            "macos" => include_str!("../config/macos.lua"),
            "netbsd" => include_str!("../config/netbsd.lua"),
            "solaris" => include_str!("../config/illumos.lua"),
            os => {
                eprintln!(
                    "WARNING: OS '{}' not explicitly supported, using generic config",
                    os
                );
                include_str!("../config/generic.lua")
            }
        };

        let conffile = dir.join("config.lua");
        fs::create_dir_all(conffile.parent().unwrap())?;
        fs::write(&conffile, confstr)?;
        println!("\t{}", conffile.display());

        Ok(())
    }
}
