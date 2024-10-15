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

mod config;
mod mount;
mod sandbox;
mod scan;

use crate::config::Config;
use crate::sandbox::Sandbox;
use crate::scan::Scan;
use anyhow::Result;
use clap::{Parser, Subcommand};
use pkgsrc::PkgPath;
use std::path::PathBuf;
use std::str;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Use the specified configuration file instead of the default path
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Build all packages as defined by the configuration file
    Build,
    /// Create and destroy build sandboxes
    Sandbox {
        #[command(subcommand)]
        cmd: SandboxCmd,
    },
}

#[derive(Debug, Subcommand)]
enum SandboxCmd {
    /// Create all sandboxes
    Create,
    /// Destroy all sandboxes
    Destroy,
    /// List currently created sandboxes
    List,
}

fn build_package(config: &Config, pkgpath: &PkgPath) {
    println!(
        "Building {}/{}",
        config.pkgsrc().display(),
        pkgpath.as_path().display()
    );
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config = Config::load(&args)?;

    match args.cmd {
        Cmd::Build => {
            let mut scan = Scan::new(
                config.pkgsrc(),
                config.make(),
                config.scan_threads(),
            );
            if let Some(pkgs) = config.pkgpaths() {
                for p in pkgs {
                    scan.add(p);
                }
            }
            scan.start()?;
            for pkgpath in scan.resolve()? {
                build_package(&config, pkgpath);
            }
        }
        Cmd::Sandbox {
            cmd: SandboxCmd::Create,
        } => {
            if let Some(s) = &config.sandbox() {
                if config.verbose() {
                    println!("Creating sandboxes");
                }
                s.create_all(config.build_threads())?;
            }
        }
        Cmd::Sandbox {
            cmd: SandboxCmd::Destroy,
        } => {
            if let Some(s) = &config.sandbox() {
                if config.verbose() {
                    println!("Destroying sandboxes");
                }
                s.destroy_all(config.build_threads())?;
            }
        }
        Cmd::Sandbox {
            cmd: SandboxCmd::List,
        } => {
            if let Some(s) = &config.sandbox() {
                s.list_all(config.build_threads());
            }
        }
    };

    Ok(())
}
