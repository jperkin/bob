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
use pkgsrc::PkgName;
use pkgsrc::{Depend, DependError};
use pkgsrc::{PkgPath, PkgPathError};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::string::FromUtf8Error;

use petgraph::algo::toposort;
use petgraph::graphmap::DiGraphMap;
use petgraph::Direction;

pub type Result<T> = std::result::Result<T, ScanError>;

///
/// ScanVariable contains all possible keys printed by "bmake pbulk-index",
/// though for now we are only interested in PKGNAME and ALL_DEPENDS.
///
#[derive(Debug)]
pub enum ScanVariable {
    PkgName,
    AllDepends,
    PkgSkipReason,
    PkgFailReason,
    NoBinOnFtp,
    Restricted,
    Categories,
    Maintainer,
    UseDestdir,
    BootstrapPkg,
    UserGroupPhase,
    ScanDepends,
    MultiVersion,
}

impl FromStr for ScanVariable {
    type Err = ScanError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "PKGNAME" => Ok(ScanVariable::PkgName),
            "ALL_DEPENDS" => Ok(ScanVariable::AllDepends),
            "PKG_SKIP_REASON" => Ok(ScanVariable::PkgSkipReason),
            "PKG_FAIL_REASON" => Ok(ScanVariable::PkgFailReason),
            "NO_BIN_ON_FTP" => Ok(ScanVariable::NoBinOnFtp),
            "RESTRICTED" => Ok(ScanVariable::Restricted),
            "CATEGORIES" => Ok(ScanVariable::Categories),
            "MAINTAINER" => Ok(ScanVariable::Maintainer),
            "USE_DESTDIR" => Ok(ScanVariable::UseDestdir),
            "BOOTSTRAP_PKG" => Ok(ScanVariable::BootstrapPkg),
            "USERGROUP_PHASE" => Ok(ScanVariable::UserGroupPhase),
            "SCAN_DEPENDS" => Ok(ScanVariable::ScanDepends),
            "MULTI_VERSION" => Ok(ScanVariable::MultiVersion),
            _ => Err(ScanError::ParseVariable(s.to_string())),
        }
    }
}

///
/// ScanError enumerates possible scan failures.
///
#[derive(Debug)]
pub enum ScanError {
    Depend(DependError),
    Io(std::io::Error),
    ParseLine(String),
    ParseVariable(String),
    PkgPath(PkgPathError),
    Utf8(FromUtf8Error),
}

impl std::error::Error for ScanError {}

impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        ScanError::Io(err)
    }
}

impl From<PkgPathError> for ScanError {
    fn from(err: PkgPathError) -> Self {
        ScanError::PkgPath(err)
    }
}

impl From<DependError> for ScanError {
    fn from(err: DependError) -> Self {
        ScanError::Depend(err)
    }
}

impl From<FromUtf8Error> for ScanError {
    fn from(err: FromUtf8Error) -> Self {
        ScanError::Utf8(err)
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Depend(s) => {
                write!(f, "invalid DEPENDS: {:?}", s)
            }
            ScanError::ParseLine(s) => {
                write!(f, "unable to parse line: {:?}", s)
            }
            ScanError::ParseVariable(s) => {
                write!(f, "unsupported variable: {:?}", s)
            }
            ScanError::PkgPath(s) => {
                write!(f, "invalid PKGPATH: {:?}", s)
            }
            ScanError::Io(s) => {
                write!(f, "I/O error: {:?}", s)
            }
            ScanError::Utf8(s) => {
                write!(f, "UTF8 parse error: {:?}", s)
            }
        }
    }
}

/**
 * [`ScanPackage`] contains the output from `bmake pbulk-index` for a single
 * `PKGPATH`.
 *
 * Note that the output may contain multiple entries in the case of
 * `MULTI_VERSION` support, so any parser should verify whether `pkgname` has
 * already been set and create a new entry.
 *
 * For now the only fields we are interested in are `PKGNAME` and
 * `ALL_DEPENDS`.
 */
#[derive(Debug, Hash, PartialEq)]
struct ScanPackage {
    pkgpath: PkgPath,
    pkgname: PkgName,
    depends: Vec<Depend>,
}

#[derive(Debug, Default)]
pub struct Scan {
    /// Location of pkgsrc
    pkgsrc: PathBuf,
    /**
     * Incoming queue of PKGPATH to process.
     */
    incoming: HashSet<PkgPath>,
    /**
     * Completed PKGPATH scans.  With MULTI_VERSION there may be multiple
     * packages produced by a single PKGPATH (e.g. py*-foo), hence why there
     * is a [`Vec`] of [`ScanPackage`]s.
     */
    done: HashMap<PkgPath, Vec<ScanPackage>>,
}

impl Scan {
    pub fn new(path: &Path) -> Scan {
        Scan {
            pkgsrc: path.to_path_buf(),
            ..Default::default()
        }
    }

    pub fn add(&mut self, pkgpath: &PkgPath) {
        self.incoming.insert(pkgpath.clone());
    }

    pub fn start(&mut self) -> Result<()> {
        /*
         * Continuously iterate over incoming queue, moving to done once
         * processed, and adding any dependencies to incoming to be processed
         * next.
         */
        loop {
            /*
             * As we are borrowing from incoming, keep track of any new
             * PKGPATH that need to be added to it separately, then add them
             * (if necessary) once incoming has been drained.
             */
            let mut add_to_incoming: Vec<PkgPath> = vec![];
            for pkgpath in self.incoming.drain() {
                /* Already in done?  Nothing to do. */
                if self.done.contains_key(&pkgpath) {
                    continue;
                }

                /*
                 * Get PKGNAME and _ALL_DEPENDS from "pbulk-index" output.
                 */
                let cmd = Command::new("/opt/pkg/bin/bmake")
                    .current_dir(self.pkgsrc.join(pkgpath.as_path()))
                    .arg("pbulk-index")
                    .output()?;
                let output = String::from_utf8(cmd.stdout)?;

                let mut pkgname: Option<PkgName> = None;
                let mut depends: Vec<Depend> = vec![];
                for line in output.lines() {
                    let v: Vec<&str> = line.splitn(2, '=').collect();
                    if v.len() != 2 {
                        return Err(ScanError::ParseLine(line.to_string()));
                    }
                    let key = ScanVariable::from_str(v[0])?;
                    match key {
                        ScanVariable::PkgName => {
                            /*
                             * With MULTI_VERSION we will see multiple PKGNAME
                             * entries combined in the same pbulk-index output,
                             * so if we've already set PKGNAME then insert the
                             * current entry and start a new one.
                             */
                            if let Some(p) = pkgname {
                                let scanpkg = ScanPackage {
                                    pkgname: p,
                                    depends,
                                    pkgpath: pkgpath.clone(),
                                };
                                if let Some(entry) = self.done.get_mut(&pkgpath)
                                {
                                    entry.push(scanpkg);
                                } else {
                                    self.done
                                        .insert(pkgpath.clone(), vec![scanpkg]);
                                }
                            }
                            pkgname = Some(PkgName::new(v[1]));
                            depends = vec![];
                        }
                        ScanVariable::AllDepends => {
                            for p in v[1].split(' ').filter(|s| !s.is_empty()) {
                                /*
                                 * If the DEPENDS path hasn't been seen yet, add
                                 * it to incoming.
                                 */
                                let dep = Depend::new(p)?;
                                if !&self.done.contains_key(dep.pkgpath()) {
                                    add_to_incoming.push(dep.pkgpath().clone());
                                }
                                depends.push(dep);
                            }
                        }
                        /* Currently we ignore all other fields. */
                        _ => {}
                    }
                }

                if let Some(p) = pkgname {
                    let scanpkg = ScanPackage {
                        pkgname: p,
                        depends,
                        pkgpath: pkgpath.clone(),
                    };
                    if let Some(entry) = self.done.get_mut(&pkgpath) {
                        entry.push(scanpkg);
                    } else {
                        self.done.insert(pkgpath.clone(), vec![scanpkg]);
                    }
                }
            }

            /*
             * Incoming has been drained.  If there are new PKGPATH to process
             * add them now.  If incoming is still empty afterwards then we
             * are done.
             */
            for pkgpath in add_to_incoming {
                if !self.done.contains_key(&pkgpath) {
                    self.incoming.insert(pkgpath);
                }
            }
            if self.incoming.is_empty() {
                break;
            }
        }

        Ok(())
    }

    pub fn resolve(&self) -> Result<Vec<&PkgPath>> {
        let mut graph = DiGraphMap::new();
        for (pkgpath, pkgs) in &self.done {
            for pkg in pkgs {
                for dep in &pkg.depends {
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
