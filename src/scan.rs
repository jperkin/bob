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
 * Scan a set of pkgsrc package paths to calculate a full dependency tree
 * of builds to perform.
 */
use crate::Sandbox;
use anyhow::{Context, Result};
use indicatif::{HumanCount, HumanDuration, ProgressBar, ProgressStyle};
use petgraph::algo::toposort;
use petgraph::graphmap::DiGraphMap;
use petgraph::Direction;
use pkgsrc::{Depend, PkgName, PkgPath, ScanIndex};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Default)]
pub struct Scan {
    /// Location of pkgsrc
    pkgsrc: PathBuf,
    /**
     * Path to `make` or `bmake` executable.
     */
    make: PathBuf,
    /**
     * Number of parallel make threads to execute.
     */
    threads: usize,
    /**
     * [`Sandbox`] configuration.
     */
    sandbox: Sandbox,
    /**
     * Incoming queue of PKGPATH to process.
     */
    incoming: HashSet<PkgPath>,
    /**
     * Completed PKGPATH scans.  With MULTI_VERSION there may be multiple
     * packages produced by a single PKGPATH (e.g. py*-foo), hence why there
     * is a [`Vec`] of [`ScanIndex`]s.
     */
    done: HashMap<PkgPath, Vec<ScanIndex>>,
}

impl Scan {
    pub fn new(
        path: &Path,
        make: &Path,
        threads: usize,
        sandbox: Sandbox,
    ) -> Scan {
        Scan {
            pkgsrc: path.to_path_buf(),
            make: make.to_path_buf(),
            threads,
            sandbox,
            ..Default::default()
        }
    }

    pub fn add(&mut self, pkgpath: &PkgPath) {
        self.incoming.insert(pkgpath.clone());
    }

    pub fn start(&mut self) -> anyhow::Result<()> {
        let started = Instant::now();
        let style = ProgressStyle::with_template(
            "{prefix:>12} [{bar:57}] {pos}/{len} [{wide_msg}]",
        )
        .unwrap()
        .progress_chars("=> ");
        let progress = ProgressBar::new(0)
            .with_prefix("Scanning")
            .with_style(style);

        rayon::ThreadPoolBuilder::new()
            .num_threads(self.threads)
            .build_global()
            .unwrap();

        // If the number of packages overflows a u64 then we have a problem!
        progress.inc_length(self.incoming.len().try_into().unwrap());

        /*
         * Only a single sandbox is required, 'make pbulk-index' can safely be
         * run in parallel inside one sandbox.
         */
        self.sandbox.create(0)?;

        /*
         * Continuously iterate over incoming queue, moving to done once
         * processed, and adding any dependencies to incoming to be processed
         * next.
         */
        loop {
            /*
             * Store the PKGPATHs that are currently being processed in a
             * HashSet for a nice progress bar status.
             */
            let curpaths: Arc<Mutex<HashSet<String>>> =
                Arc::new(Mutex::new(HashSet::new()));

            /*
             * Convert the incoming HashSet into a Vec for parallel processing.
             */
            let mut parpaths: Vec<(PkgPath, Result<Vec<ScanIndex>>)> = vec![];
            for pkgpath in &self.incoming {
                parpaths.push((pkgpath.clone(), Ok(vec![])));
            }

            parpaths.par_iter_mut().for_each(|pkg| {
                let (pkgpath, result) = pkg;
                let pathname = pkgpath.as_path().to_string_lossy().to_string();
                let curpaths = Arc::clone(&curpaths);

                /*
                 * Add PKGPATH to the progress bar, perform the scan and save
                 * the result, remove PKGPATH from the progress bar, before
                 * finally updating the progress counter.
                 */
                {
                    let mut curpaths = curpaths.lock().unwrap();
                    curpaths.insert(pathname.clone());
                    let msg: String =
                        curpaths.iter().cloned().collect::<Vec<_>>().join(", ");
                    progress.set_message(msg);
                }
                *result = self
                    .scan_pkgpath(pkgpath)
                    .context(format!("Scan failed for {}", pathname));
                progress.inc(1);
                {
                    let mut curpaths = curpaths.lock().unwrap();
                    curpaths.remove(&pathname);
                    let msg: String =
                        curpaths.iter().cloned().collect::<Vec<_>>().join(", ");
                    progress.set_message(msg);
                }
            });

            /*
             * Look through the results we just processed for any new PKGPATH
             * entries in DEPENDS that we have not seen before (neither in
             * done nor incoming).
             */
            let mut new_incoming: HashSet<PkgPath> = HashSet::new();
            for (pkgpath, scanpkgs) in parpaths.drain(..) {
                let scanpkgs = scanpkgs?;
                self.done.insert(pkgpath.clone(), scanpkgs.clone());
                for pkg in scanpkgs {
                    for dep in pkg.all_depends {
                        if !self.done.contains_key(dep.pkgpath())
                            && !self.incoming.contains(dep.pkgpath())
                            && new_incoming.insert(dep.pkgpath().clone())
                        {
                            progress.inc_length(1);
                        }
                    }
                }
            }

            /*
             * We're finished with the current incoming, replace it with the
             * new incoming list.  If it is empty then we've already processed
             * all known PKGPATHs and are done.
             */
            self.incoming = new_incoming;
            if self.incoming.is_empty() {
                break;
            }
        }

        self.sandbox.destroy(0)?;

        progress.finish_and_clear();
        if progress.length() > Some(0) {
            println!(
                "Scanned {} packages in {}",
                HumanCount(progress.length().unwrap()),
                HumanDuration(started.elapsed()),
            );
        }

        Ok(())
    }

    /**
     * Scan a single PKGPATH, returning a [`Vec`] of [`ScanIndex`] results,
     * as multi-version packages may return multiple results.
     */
    pub fn scan_pkgpath(
        &self,
        pkgpath: &PkgPath,
    ) -> anyhow::Result<Vec<ScanIndex>> {
        let mut pkgname: Option<PkgName> = None;
        let mut depends: Vec<Depend> = vec![];
        let pkgdir = self.pkgsrc.join(pkgpath.as_path());
        let script = format!(
            "cd {} && {} pbulk-index",
            pkgdir.display(),
            &self.make.display()
        );
        let mut child = self.sandbox.execute(0, &script)?;
        let stdout = child
            .stdout
            .take()
            .context("Unable to read sandbox child process")?;
        let reader = BufReader::new(stdout);
        let mut index = ScanIndex::from_reader(reader)?;
        /*
         * Set PKGPATH (PKG_LOCATION) as for some reason pbulk-index doesn't.
         */
        for pkg in &mut index {
            pkg.pkg_location = Some(pkgpath.clone())
        }

        Ok(index)
    }

    pub fn resolve(&self) -> Result<Vec<&PkgPath>> {
        let mut graph = DiGraphMap::new();
        for (pkgpath, pkgs) in &self.done {
            for pkg in pkgs {
                for dep in &pkg.all_depends {
                    graph.add_edge(dep.pkgpath(), pkgpath, ());
                }
            }
        }
        /*
         * Verify that the graph is acyclic.
         *
         * TODO: print circular dependencies if found.
         */
        let sorted = match toposort(&graph, None) {
            Ok(sort) => sort,
            Err(_) => {
                eprintln!("Circular dependencies detected");
                std::process::exit(1);
            }
        };

        /*
         * The graph is sorted, but we also need to calculate levels for each
         * package so that we can build packages at the same level in parallel
         * if possible.
         */
        let mut pkglevel: HashMap<&PkgPath, usize> = HashMap::new();
        for &node in &sorted {
            pkglevel.insert(node, 0);
        }
        for &node in &sorted {
            for dep in graph.neighbors_directed(node, Direction::Incoming) {
                let new_level = pkglevel[&dep] + 1;
                pkglevel
                    .entry(node)
                    .and_modify(|level| *level = (*level).max(new_level));
            }
        }

        /*
         * Now that the levels have been calculated, use a BTreeMap to store
         * them ordered by level for processing, one level at a time.
         *
         * TODO: Improve algorithm so that packages at higher levels can start
         * before the current level has finished if all their dependencies have
         * been satisfied.
         */
        let mut pkgtree: BTreeMap<usize, Vec<&PkgPath>> = BTreeMap::new();
        for (node, &level) in &pkglevel {
            pkgtree.entry(level).or_default().push(*node);
        }

        let mut pkgpaths: Vec<&PkgPath> = vec![];
        for level in pkgtree.values() {
            for pkg in level {
                pkgpaths.push(pkg);
            }
        }
        Ok(pkgpaths)
    }
}
