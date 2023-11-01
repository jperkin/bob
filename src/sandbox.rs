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

use crate::config::Mount;
use std::path::PathBuf;

#[derive(Debug, Default)]
pub struct Sandbox {
    basedir: PathBuf,
}

impl Sandbox {
    pub fn new(basedir: &PathBuf) -> Sandbox {
        Sandbox {
            basedir: basedir.clone(),
        }
    }

    pub fn basedir(&self) -> &PathBuf {
        &self.basedir
    }

    pub fn mount(&self, mounts: &Vec<Mount>) -> Result<(), std::io::Error> {
        for (_, m) in mounts.iter().enumerate() {
            println!(
                "mount {} on {}{} (opts: {:?})",
                m.fs(),
                self.basedir().display(),
                m.dir().display(),
                m.opts()
            );
        }
        Ok(())
    }

    pub fn unmount(&self, mounts: &Vec<Mount>) -> Result<(), std::io::Error> {
        for (_, m) in mounts.iter().rev().enumerate() {
            println!(
                "unmount {} from {}{}",
                m.fs(),
                self.basedir().display(),
                m.dir().display(),
            );
        }
        Ok(())
    }
}
