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

use anyhow::{bail, Error};
use mlua::{Result as LuaResult, Table};
use std::path::PathBuf;
use std::str::FromStr;

/// A sandbox action - either a filesystem mount, copy, or custom command.
///
/// Actions are performed in order during sandbox creation, and in reverse
/// order during sandbox destruction.
#[derive(Clone, Debug, Default)]
pub struct Action {
    /// The action type: "mount", "copy", or "cmd"
    action: String,
    /// Filesystem type for "mount" action (e.g., "bind", "proc", "tmp", "null")
    fs: Option<String>,
    /// Source path (optional, defaults to dest for mounts)
    src: Option<PathBuf>,
    /// Destination path within the sandbox
    dest: Option<PathBuf>,
    /// Mount options (for mount actions)
    opts: Option<String>,
    /// Command to run during creation (for "cmd" action)
    create: Option<String>,
    /// Command to run during destruction (for "cmd" action)
    destroy: Option<String>,
    /// Working directory for commands, relative to sandbox root (for "cmd" action)
    cwd: Option<PathBuf>,
}

/// The type of action to perform.
#[derive(Debug, PartialEq)]
pub enum ActionType {
    /// Mount a filesystem
    Mount,
    /// Copy files/directories into sandbox
    Copy,
    /// Custom command with create/destroy pair
    Cmd,
    /// Create a symbolic link
    Symlink,
}

/// The type of filesystem to mount.
#[derive(Debug, PartialEq)]
pub enum FSType {
    /// Bind mount (lofs, null, loop are aliases)
    Bind,
    /// Mount devfs/devtmpfs
    Dev,
    /// Mount fdfs/fdescfs
    Fd,
    /// NFS mount
    Nfs,
    /// Mount procfs
    Proc,
    /// Mount tmpfs
    Tmp,
}

impl FromStr for ActionType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mount" => Ok(ActionType::Mount),
            "copy" => Ok(ActionType::Copy),
            "cmd" => Ok(ActionType::Cmd),
            "symlink" => Ok(ActionType::Symlink),
            _ => bail!("Unsupported action type '{}' (expected 'mount', 'copy', 'cmd', or 'symlink')", s),
        }
    }
}

impl FromStr for FSType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bind" => Ok(FSType::Bind),
            "dev" => Ok(FSType::Dev),
            "fd" => Ok(FSType::Fd),
            "nfs" => Ok(FSType::Nfs),
            "proc" => Ok(FSType::Proc),
            "tmp" => Ok(FSType::Tmp),
            /*
             * Aliases for bind mount types across different systems.
             */
            "lofs" => Ok(FSType::Bind),
            "loop" => Ok(FSType::Bind),
            "null" => Ok(FSType::Bind),
            _ => bail!("Unsupported filesystem type '{}'", s),
        }
    }
}

impl Action {
    pub fn from_lua(t: &Table) -> LuaResult<Self> {
        // "dir" can be used as shorthand when src and dest are the same
        let dir = t.get::<Option<String>>("dir")?.map(PathBuf::from);
        let src = t.get::<Option<String>>("src")?.map(PathBuf::from).or_else(|| dir.clone());
        let dest = t.get::<Option<String>>("dest")?.map(PathBuf::from).or_else(|| dir.clone());

        Ok(Self {
            action: t.get("action")?,
            fs: t.get("fs").ok(),
            src,
            dest,
            opts: t.get("opts").ok(),
            create: t.get("create").ok(),
            destroy: t.get("destroy").ok(),
            cwd: t.get::<Option<String>>("cwd")?.map(PathBuf::from),
        })
    }

    pub fn src(&self) -> Option<&PathBuf> {
        self.src.as_ref()
    }

    pub fn dest(&self) -> Option<&PathBuf> {
        self.dest.as_ref()
    }

    pub fn action_type(&self) -> Result<ActionType, Error> {
        ActionType::from_str(&self.action)
    }

    pub fn fs_type(&self) -> Result<FSType, Error> {
        match &self.fs {
            Some(fs) => FSType::from_str(fs),
            None => bail!("'mount' action requires 'fs' field"),
        }
    }

    pub fn opts(&self) -> Option<&String> {
        self.opts.as_ref()
    }

    pub fn create_cmd(&self) -> Option<&String> {
        self.create.as_ref()
    }

    pub fn destroy_cmd(&self) -> Option<&String> {
        self.destroy.as_ref()
    }

    pub fn cwd(&self) -> Option<&PathBuf> {
        self.cwd.as_ref()
    }

    /// Validate the action configuration.
    /// Returns an error if the action is misconfigured.
    pub fn validate(&self) -> Result<(), Error> {
        let action_type = self.action_type()?;

        match action_type {
            ActionType::Cmd => {
                if self.create.is_none() && self.destroy.is_none() {
                    bail!("'cmd' action requires 'create' or 'destroy' command");
                }
            }
            ActionType::Mount => {
                // mount requires fs and either src or dest
                if self.fs.is_none() {
                    bail!("'mount' action requires 'fs' field");
                }
                self.fs_type()?; // Validate fs type
                if self.src.is_none() && self.dest.is_none() {
                    bail!("'mount' action requires 'src' or 'dest' path");
                }
            }
            ActionType::Copy => {
                // copy requires src or dest
                if self.src.is_none() && self.dest.is_none() {
                    bail!("'copy' action requires 'src' or 'dest' path");
                }
            }
            ActionType::Symlink => {
                // symlink requires both src and dest
                if self.src.is_none() {
                    bail!("'symlink' action requires 'src' (link target)");
                }
                if self.dest.is_none() {
                    bail!("'symlink' action requires 'dest' (link name)");
                }
            }
        }

        Ok(())
    }
}
