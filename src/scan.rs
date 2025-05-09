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

use crate::{Config, Sandbox};
use anyhow::{bail, Context, Result};
use indicatif::{HumanCount, HumanDuration, ProgressBar, ProgressStyle};
use petgraph::graphmap::DiGraphMap;
use pkgsrc::{Depend, PkgName, PkgPath, ScanIndex};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::io::BufReader;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Default)]
pub struct Scan {
    /**
     * Parsed [`Config`].
     */
    config: Config,
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
    /**
     * Resolved packages, indexed by PKGNAME.
     */
    resolved: HashMap<PkgName, ScanIndex>,
}

impl Scan {
    pub fn new(config: &Config) -> Scan {
        let sandbox = Sandbox::new(config);
        Scan { config: config.clone(), sandbox, ..Default::default() }
    }

    pub fn add(&mut self, pkgpath: &PkgPath) {
        self.incoming.insert(pkgpath.clone());
    }

    pub fn start(&mut self) -> anyhow::Result<()> {
        let started = Instant::now();
        let style = ProgressStyle::with_template(
            "{prefix:>12} [{bar:28}] {pos}/{len} [{wide_msg}]",
        )
        .unwrap()
        .progress_chars("=> ");
        let progress =
            ProgressBar::new(0).with_prefix("Scanning").with_style(style);

        rayon::ThreadPoolBuilder::new()
            .num_threads(self.config.scan_threads())
            .build()
            .unwrap();

        // If the number of packages overflows a u64 then we have a problem!
        progress.inc_length(self.incoming.len().try_into().unwrap());

        /*
         * Only a single sandbox is required, 'make pbulk-index' can safely be
         * run in parallel inside one sandbox.
         */
        if self.sandbox.enabled() {
            self.sandbox.create(0)?;
        }

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

        if self.sandbox.enabled() {
            self.sandbox.destroy(0)?;
        }

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
        let envs = vec![
            ("BOB_BMAKE", format!("{}", self.config.make().display())),
            ("BOB_PKGPATH", format!("{}", pkgpath.as_path().display())),
            ("BOB_PKGSRCDIR", format!("{}", self.config.pkgsrc().display())),
        ];
        let Some(pkg_scan) = &self.config.script("pkg-scan") else {
            bail!("No pkg-scan script defined");
        };
        let mut scan_script = String::new();
        for (key, val) in &envs {
            writeln!(scan_script, "{}='{}'", key, val)?;
        }
        for (key, _) in &envs {
            writeln!(scan_script, "export {}", key)?;
        }
        scan_script.push_str(pkg_scan);
        let child = self.sandbox.execute(0, &scan_script)?;
        let output = child.wait_with_output()?;
        let reader = BufReader::new(&output.stdout[..]);
        let mut index = ScanIndex::from_reader(reader)?;
        /*
         * Set PKGPATH (PKG_LOCATION) as for some reason pbulk-index doesn't.
         */
        for pkg in &mut index {
            pkg.pkg_location = Some(pkgpath.clone())
        }

        Ok(index)
    }

    /**
     * Resolve the list of scanned packages, by ensuring all of the [`Depend`]
     * patterns in `all_depends` match a found package, and that there are no
     * circular dependencies.  The best match for each is stored in the
     * `depends` for the package in question.
     *
     * Return a reference to a [`HashMap`] which maps the unique `PKGNAME` to
     * build along with its [`ScanIndex`].  This can then be used to build all
     * packages.
     */
    pub fn resolve(&mut self) -> Result<&HashMap<PkgName, ScanIndex>> {
        /*
         * Populate the resolved hash.  This becomes our new working set,
         * with a flat mapping of PKGNAME -> ScanIndex.
         *
         * self.done must no longer be used after this point, as its ScanIndex
         * entries are out of date (do not have depends set, for example).
         * Maybe at some point we'll handle lifetimes properly and just have
         * one canonical index.
         *
         * Also create a simple HashSet for looking up known PKGNAME for
         * matches.
         */
        let mut pkgnames: HashSet<PkgName> = HashSet::new();
        for index in self.done.values() {
            for pkg in index {
                pkgnames.insert(pkg.pkgname.clone());
                self.resolved.insert(pkg.pkgname.clone(), pkg.clone());
            }
        }

        /*
         * Keep a cache of best Depend => PkgName matches we've already seen
         * as it's likely the same patterns will be used in multiple places.
         */
        let mut match_cache: HashMap<Depend, PkgName> = HashMap::new();

        for pkg in self.resolved.values_mut() {
            for depend in &pkg.all_depends {
                /*
                 * Check for cached DEPENDS match first.  If found, use it.
                 */
                if let Some(pkgname) = match_cache.get(depend) {
                    pkg.depends.push(pkgname.clone().clone());
                    continue;
                }
                /*
                 * Find best DEPENDS match out of all known PKGNAME.
                 */
                let mut best: Option<&PkgName> = None;
                for candidate in &pkgnames {
                    if depend.pattern().matches(candidate.pkgname()) {
                        if let Some(current) = best {
                            best = match depend.pattern().best_match(
                                current.pkgname(),
                                candidate.pkgname(),
                            ) {
                                Some(m) if m == current.pkgname() => {
                                    Some(current)
                                }
                                Some(m) if m == candidate.pkgname() => {
                                    Some(candidate)
                                }
                                Some(_) => todo!(),
                                None => None,
                            };
                        } else {
                            best = Some(candidate);
                        }
                    }
                }
                /*
                 * If we found a match, save it and add to the cache,
                 * otherwise error.
                 *
                 * TODO: we should batch up errors and continue so that we
                 * don't have to re-run multiple times to find all errors.
                 */
                if let Some(pkgname) = best {
                    pkg.depends.push(pkgname.clone());
                    match_cache.insert(depend.clone(), pkgname.clone());
                } else {
                    bail!(
                        "No match found for {} in {}",
                        depend.pattern().pattern(),
                        pkg.pkgname.pkgname()
                    );
                }
            }
        }

        /*
         * Verify that the graph is acyclic.
         */
        let mut graph = DiGraphMap::new();
        for (pkgname, index) in &self.resolved {
            for dep in &index.depends {
                graph.add_edge(dep.pkgname(), pkgname.pkgname(), ());
            }
        }
        if let Some(cycle) = find_cycle(&graph) {
            let mut err = "Circular dependencies detected:\n".to_string();
            for n in cycle.iter().rev() {
                err.push_str(&format!("\t{}\n", n));
            }
            err.push_str(&format!("\t{}", cycle.last().unwrap()));
            bail!(err);
        }

        Ok(&self.resolved)
    }
}

pub fn find_cycle<'a>(
    graph: &'a DiGraphMap<&'a str, ()>,
) -> Option<Vec<&'a str>> {
    let mut visited = HashSet::new();
    let mut in_stack = HashSet::new();
    let mut stack = Vec::new();

    for node in graph.nodes() {
        if visited.contains(&node) {
            continue;
        }
        let cycle = dfs(graph, node, &mut visited, &mut stack, &mut in_stack);
        if cycle.is_some() {
            return cycle;
        }
    }
    None
}

fn dfs<'a>(
    graph: &'a DiGraphMap<&'a str, ()>,
    node: &'a str,
    visited: &mut HashSet<&'a str>,
    stack: &mut Vec<&'a str>,
    in_stack: &mut HashSet<&'a str>,
) -> Option<Vec<&'a str>> {
    visited.insert(node);
    stack.push(node);
    in_stack.insert(node);
    for neighbor in graph.neighbors(node) {
        if in_stack.contains(neighbor) {
            if let Some(pos) = stack.iter().position(|&n| n == neighbor) {
                return Some(stack[pos..].to_vec());
            }
        } else if !visited.contains(neighbor) {
            let cycle = dfs(graph, neighbor, visited, stack, in_stack);
            if cycle.is_some() {
                return cycle;
            }
        }
    }
    stack.pop();
    in_stack.remove(node);
    None
}
