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
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Debug, RustEmbed)]
#[folder = "scripts/"]
struct Scripts;

pub fn init(dir: &PathBuf) -> anyhow::Result<()> {
    let initdir = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        env::current_dir()?.join(dir)
    };
    if initdir.exists() {
        if !initdir.is_dir() {
            bail!("{} exists and is not a directory", initdir.display());
        }
        if fs::read_dir(&initdir)?.next().is_some() {
            bail!("{} exists and is not empty", initdir.display());
        }
    }

    let Some(initdir_str) = initdir.to_str() else {
        bail!("Sorry, configuration directory must be valid UTF-8");
    };

    println!("Initialising new configuration directory {}:", initdir_str);

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

    let confstr = confstr.replace("@INITDIR@", initdir_str);
    let conffile = initdir.join("config.lua");
    fs::create_dir_all(conffile.parent().unwrap())?;
    fs::write(&conffile, confstr)?;
    println!("\t{}", conffile.display());

    for script in Scripts::iter() {
        if let Some(content) = Scripts::get(&script) {
            let fp = initdir.join("scripts").join(&*script);
            fs::create_dir_all(fp.parent().unwrap())?;
            fs::write(&fp, content.data)?;
            #[cfg(unix)]
            {
                let mut perms = fs::metadata(&fp)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&fp, perms)?;
            }
            println!("\t{}", fp.display());
        }
    }

    Ok(())
}
