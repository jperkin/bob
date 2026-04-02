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
 * Configuration file initialisation.
 *
 * Creates a platform-appropriate `config.lua` configuration file.
 */

use crate::config::default_config_path;
use anyhow::{Context, bail};
use std::env;
use std::fs;
use std::path::Path;

/**
 * Configuration file generator for `bob init`.
 */
pub struct Init {}

impl Init {
    /**
     * Create a new configuration file.
     *
     * If `config_path` is provided, writes to that path.  Otherwise
     * writes to the platform default location.  The file must not
     * already exist.
     */
    pub fn create(config_path: Option<&Path>) -> anyhow::Result<()> {
        let path = match config_path {
            Some(p) => {
                if p.is_relative() {
                    env::current_dir()?.join(p)
                } else {
                    p.to_path_buf()
                }
            }
            None => default_config_path()?,
        };

        if path.exists() {
            bail!("Configuration file {} already exists", path.display());
        }

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

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        fs::write(&path, confstr)?;
        println!("Created {}", path.display());

        Ok(())
    }
}
