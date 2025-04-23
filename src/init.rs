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

use anyhow::bail;
use rust_embed::RustEmbed;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, RustEmbed)]
#[folder = "scripts/"]
struct Scripts;

pub struct Init {}

impl Init {
    pub fn create(dir: &PathBuf) -> anyhow::Result<()> {
        let initdir = if dir.is_absolute() {
            dir.to_path_buf()
        } else {
            env::current_dir()?.join(dir)
        };
        if initdir.exists() {
            bail!("{} already exists", initdir.display());
        }

        println!("Initialising new configuration directory:");

        let confstr = match env::consts::OS {
            "illumos" => include_str!("../config/illumos.toml"),
            "macos" => include_str!("../config/macos.toml"),
            "netbsd" => include_str!("../config/netbsd.toml"),
            "solaris" => include_str!("../config/illumos.toml"),
            os => {
                eprintln!("WARNING: OS '{}' not explicitly supported, using generic config", os);
                include_str!("../config/generic.toml")
            }
        };

        let conffile = initdir.join("config.toml");
        fs::create_dir_all(conffile.parent().unwrap())?;
        fs::write(&conffile, confstr)?;
        println!("\t{}", conffile.display());

        for script in Scripts::iter() {
            if let Some(content) = Scripts::get(&script) {
                let fp = initdir.join("scripts").join(&*script);
                fs::create_dir_all(fp.parent().unwrap())?;
                fs::write(&fp, content.data)?;
                println!("\t{}", fp.display());
            }
        }

        Ok(())
    }
}
