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

use crate::Sandbox;
use anyhow::bail;
use indicatif::{HumanCount, HumanDuration, ProgressBar, ProgressStyle};
use pkgsrc::{PkgName, ScanIndex};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Default)]
pub struct Build {
    /**
     * Location of pkgsrc
     */
    pkgsrc: PathBuf,
    /**
     * Path to `make` or `bmake` executable.
     */
    make: PathBuf,
    /**
     * Number of parallel make threads to execute (effectively the number
     * of sandboxes to create).
     */
    threads: usize,
    /**
     * [`Sandbox`] configuration.
     */
    sandbox: Sandbox,
    /**
     * List of packages to build, as input from Scan::resolve.
     */
    scanpkgs: HashMap<PkgName, ScanIndex>,
}

impl Build {
    pub fn new(
        path: &Path,
        make: &Path,
        threads: usize,
        sandbox: Sandbox,
        scanpkgs: HashMap<PkgName, ScanIndex>,
    ) -> Build {
        Build {
            pkgsrc: path.to_path_buf(),
            make: make.to_path_buf(),
            threads,
            sandbox,
            scanpkgs,
        }
    }

    pub fn start(&mut self) -> anyhow::Result<()> {
        let started = Instant::now();
        let style = ProgressStyle::with_template(
            "{prefix:>12} [{bar:57}] {pos}/{len} [{wide_msg}]",
        )
        .unwrap()
        .progress_chars("=> ");
        let progress =
            ProgressBar::new(0).with_prefix("Building").with_style(style);

        rayon::ThreadPoolBuilder::new()
            .num_threads(self.threads)
            .build()
            .unwrap();

        let mut status: HashMap<PkgName, HashSet<PkgName>> = HashMap::new();
        for (pkgname, index) in &self.scanpkgs {
            let mut deps: HashSet<PkgName> = HashSet::new();
            for dep in &index.depends {
                deps.insert(dep.clone());
            }
            status.insert(pkgname.clone(), deps);
        }

        // If the number of packages overflows a u64 then we have a problem!
        progress.inc_length(status.len().try_into().unwrap());

        if self.sandbox.enabled() {
            for i in 0..self.threads {
                self.sandbox.create(i)?;
            }
        }

        loop {
            /*
             * Get all packages where the DEPENDS HashSet is empty, i.e. they
             * are cleared for building.
             */
            let pkgs: Vec<PkgName> = status
                .iter()
                .filter(|(_, v)| v.is_empty())
                .map(|(k, _)| k.clone())
                .collect();
            /*
             * If no packages are available we're done.
             *
             * TODO: enum to distinguish busy from done
             */
            if pkgs.is_empty() {
                assert!(status.is_empty());
                break;
            }

            for pkg in pkgs {
                progress.set_message(String::from(pkg.pkgname()));
                progress.inc(1);
                self.build_package(&pkg)?;
                /*
                 * Remove successful package from all DEPENDS.
                 *
                 * TODO: If failure, move all these packages recursively to
                 * some other list.
                 */
                for entry in status.values_mut() {
                    if entry.contains(&pkg) {
                        entry.remove(&pkg);
                    }
                }
                /*
                 * Remove this package from the current list.
                 */
                status.remove(&pkg);
            }
        }

        if self.sandbox.enabled() {
            for i in 0..self.threads {
                self.sandbox.destroy(i)?;
            }
        }

        progress.finish_and_clear();
        if progress.length() > Some(0) {
            println!(
                "Built {} packages in {}",
                HumanCount(progress.length().unwrap()),
                HumanDuration(started.elapsed()),
            );
        }

        Ok(())
    }

    fn build_package(&self, pkgname: &PkgName) -> anyhow::Result<()> {
        let Some(index) = self.scanpkgs.get(pkgname) else {
            bail!("ERROR: Inconsistency detected in pkgdata");
        };
        let Some(pkgpath) = &index.pkg_location else {
            bail!("ERROR: Could not get PKGPATH for {}", pkgname.pkgname());
        };
        let _build_script = format!(
            "cd {}/{} && {} package",
            self.pkgsrc.display(),
            pkgpath.as_path().display(),
            self.make.display()
        );
        /*
         * TODO: actually build! just fake work for now.
         */
        let duration = std::time::Duration::from_millis(100);
        std::thread::sleep(duration);
        Ok(())
    }
}
