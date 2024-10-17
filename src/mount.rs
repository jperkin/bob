/*
 * Copyright (c) 2024 Jonathan Perkin <jonathan@perkin.org.uk>
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

use anyhow::{bail, Error};
use serde_derive::Deserialize;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Mount {
    src: Option<PathBuf>,
    dest: PathBuf,
    fs: String,
    opts: Option<String>,
}

#[derive(Debug)]
pub enum FSType {
    Bind,
    Dev,
    Fd,
    Nfs,
    Proc,
    Tmp,
}

impl FromStr for FSType {
    type Err = Error;

    fn from_str(fs: &str) -> Result<Self, Self::Err> {
        match fs {
            "bind" => Ok(FSType::Bind),
            "dev" => Ok(FSType::Dev),
            "fd" => Ok(FSType::Fd),
            "nfs" => Ok(FSType::Nfs),
            "proc" => Ok(FSType::Proc),
            "tmp" => Ok(FSType::Tmp),
            /*
             * Aliases for mount types across different systems.
             */
            "lofs" => Ok(FSType::Bind),
            "loop" => Ok(FSType::Bind),
            "null" => Ok(FSType::Bind),
            _ => bail!("Unsupported file system type '{}'", fs),
        }
    }
}

impl Mount {
    pub fn src(&self) -> &Option<PathBuf> {
        &self.src
    }

    pub fn dest(&self) -> &PathBuf {
        &self.dest
    }

    pub fn fstype(&self) -> Result<FSType, Error> {
        FSType::from_str(&self.fs)
    }

    pub fn opts(&self) -> &Option<String> {
        &self.opts
    }
}
