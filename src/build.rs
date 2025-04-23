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
use anyhow::{bail, Context};
use indicatif::{HumanCount, HumanDuration, ProgressBar, ProgressStyle};
use pkgsrc::{PkgName, ScanIndex};
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::io::Read;
use std::sync::{mpsc, mpsc::Sender};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct Build {
    /**
     * Parsed [`Config`].
     */
    config: Config,
    /**
     * [`Sandbox`] configuration.
     */
    sandbox: Sandbox,
    /**
     * List of packages to build, as input from Scan::resolve.
     */
    scanpkgs: HashMap<PkgName, ScanIndex>,
}

#[derive(Debug)]
struct PackageBuild {
    id: usize,
    config: Config,
    pkginfo: ScanIndex,
    sandbox: Sandbox,
}

impl PackageBuild {
    fn build(&self) -> anyhow::Result<i32> {
        let pkgname = self.pkginfo.pkgname.pkgname();
        let Some(pkgpath) = &self.pkginfo.pkg_location else {
            bail!("Could not get PKGPATH for {}", pkgname);
        };
        let envs = vec![
            ("BOB_BMAKE", format!("{}", self.config.make().display())),
            ("BOB_PKGPATH", format!("{}", pkgpath.as_path().display())),
            ("BOB_PKGSRCDIR", format!("{}", self.config.pkgsrc().display())),
        ];
        let Some(pkg_build) = &self.config.script("pkg-build") else {
            bail!("No pkg-build script defined");
        };
        let mut build_script = String::new();
        for (key, val) in &envs {
            writeln!(build_script, "{}='{}'", key, val)?;
        }
        for (key, _) in &envs {
            writeln!(build_script, "export {}", key)?;
        }
        build_script.push_str(pkg_build);
        let mut child = self.sandbox.execute(self.id, &build_script)?;
        let mut stdout =
            child.stdout.take().context("Could not read stdout")?;
        let res = child.wait().context("Could not wait for child")?;
        let mut out = String::new();
        stdout.read_to_string(&mut out)?;
        res.code().context("proc failed")
    }
}

/**
 * Commands sent between the manager and clients.
 */
#[derive(Debug)]
enum ChannelCommand {
    /**
     * Client (with specified identifier) indicating they are ready for work.
     */
    ClientReady(usize),
    /**
     * Manager has no work available at the moment, try again later.
     */
    ComeBackLater,
    /**
     * Manager directing a client to build a specific package.
     */
    JobData(Box<PackageBuild>),
    /**
     * Client returning a successful package build.
     */
    JobSuccess(PkgName),
    /**
     * Client returning a failed package build.
     */
    JobFailed(PkgName),
    /**
     * Client returning an error during the package build.
     */
    JobError((PkgName, anyhow::Error)),
    /**
     * Manager directing a client to quit.
     */
    Quit,
}

/**
 * Return the current build job status.
 */
#[derive(Debug)]
enum BuildStatus {
    /**
     * The next package ordered by priority is available for building.
     */
    Available(PkgName),
    /**
     * No packages are currently available for building, i.e. all remaining
     * packages have at least one dependency that is still unavailable.
     */
    NoneAvailable,
    /**
     * All package builds have been completed.
     */
    Done,
}

#[derive(Clone, Debug)]
struct BuildJobs {
    scanpkgs: HashMap<PkgName, ScanIndex>,
    incoming: HashMap<PkgName, HashSet<PkgName>>,
    running: HashSet<PkgName>,
    done: HashSet<PkgName>,
    failed: HashSet<PkgName>,
}

impl BuildJobs {
    /**
     * Mark a package as successful and remove it from pending dependencies.
     */
    fn mark_success(&mut self, pkgname: &PkgName) {
        /*
         * Remove the successful package from the list of dependencies in all
         * packages it is listed in.  Once a package has no outstanding
         * dependencies remaining it is ready for building.
         */
        for dep in self.incoming.values_mut() {
            if dep.contains(pkgname) {
                dep.remove(pkgname);
            }
        }
        /*
         * The package was already removed from "incoming" when it started
         * building, so we only need to add it to "done".
         */
        self.done.insert(pkgname.clone());
    }

    /**
     * Recursively mark a package and its dependents as failed.
     */
    fn mark_failure(&mut self, pkgname: &PkgName) {
        let mut broken: HashSet<PkgName> = HashSet::new();
        let mut to_check: Vec<PkgName> = vec![];
        to_check.push(pkgname.clone());
        /*
         * Starting with the original failed package, recursively loop through
         * adding any packages that depend on it, adding them to broken.
         */
        loop {
            /* No packages left to check, we're done. */
            let Some(badpkg) = to_check.pop() else {
                break;
            };
            /* Already checked this package. */
            if broken.contains(&badpkg) {
                continue;
            }
            for (pkg, deps) in &self.incoming {
                if deps.contains(&badpkg) {
                    to_check.push(pkg.clone());
                }
            }
            broken.insert(badpkg);
        }
        /*
         * We now have a full HashSet of affected packages.  Remove them from
         * incoming and move to failed.  The original failed package will
         * already be removed from incoming, we rely on .remove() accepting
         * this.
         */
        for pkg in broken {
            self.incoming.remove(&pkg);
            self.failed.insert(pkg);
        }
    }

    /**
     * Get next package status.
     */
    fn get_next_build(&self) -> BuildStatus {
        /*
         * If incoming is empty then we're done.
         */
        if self.incoming.is_empty() {
            return BuildStatus::Done;
        }

        /*
         * Get all packages in incoming that are cleared for building, ordered
         * by weighting.
         *
         * TODO: weighting should be the sum of all transitive dependencies.
         */
        let mut pkgs: Vec<(PkgName, usize)> = self
            .incoming
            .iter()
            .filter(|(_, v)| v.is_empty())
            .map(|(k, _)| {
                (
                    k.clone(),
                    self.scanpkgs
                        .get(k)
                        .unwrap()
                        .pbulk_weight
                        .clone()
                        .unwrap_or("100".to_string())
                        .parse()
                        .unwrap_or(100),
                )
            })
            .collect();

        /*
         * If no packages are returned then we're still waiting for
         * dependencies to finish.  Clients should keep retrying until this
         * changes.
         */
        if pkgs.is_empty() {
            return BuildStatus::NoneAvailable;
        }

        /*
         * Order packages by build weight and return the highest.
         */
        pkgs.sort_by_key(|&(_, weight)| std::cmp::Reverse(weight));
        BuildStatus::Available(pkgs[0].0.clone())
    }
}

impl Build {
    pub fn new(
        config: &Config,
        scanpkgs: HashMap<PkgName, ScanIndex>,
    ) -> Build {
        let sandbox = Sandbox::new(config);
        Build { config: config.clone(), sandbox, scanpkgs }
    }

    pub fn start(&mut self) -> anyhow::Result<()> {
        let started = Instant::now();
        let style = ProgressStyle::with_template(
            "{prefix:>12} [{bar:28}] {pos}/{len} [{wide_msg}]",
        )
        .unwrap()
        .progress_chars("=> ");
        let progress =
            ProgressBar::new(0).with_prefix("Building").with_style(style);

        /*
         * Populate BuildJobs.
         */
        let mut incoming: HashMap<PkgName, HashSet<PkgName>> = HashMap::new();
        for (pkgname, index) in &self.scanpkgs {
            let mut deps: HashSet<PkgName> = HashSet::new();
            for dep in &index.depends {
                deps.insert(dep.clone());
            }
            incoming.insert(pkgname.clone(), deps);
        }

        // If the number of packages overflows a u64 then we have a problem!
        progress.inc_length(incoming.len().try_into().unwrap());

        let running: HashSet<PkgName> = HashSet::new();
        let done: HashSet<PkgName> = HashSet::new();
        let failed: HashSet<PkgName> = HashSet::new();
        let jobs = BuildJobs {
            scanpkgs: self.scanpkgs.clone(),
            incoming,
            running,
            done,
            failed,
        };

        if self.sandbox.enabled() {
            for i in 0..self.config.build_threads() {
                self.sandbox.create(i)?;
            }
        }

        /*
         * Configure a mananger channel.  This is used for clients to indicate
         * to the manager that they are ready for work.
         */
        let (manager_tx, manager_rx) = mpsc::channel::<ChannelCommand>();

        /*
         * Client threads.  Each client has its own channel to the manager,
         * with the client sending ready status on the manager channel, and
         * receiving instructions on its private channel.
         */
        let mut threads = vec![];
        let mut clients: HashMap<usize, Sender<ChannelCommand>> =
            HashMap::new();
        for i in 0..self.config.build_threads() {
            let (client_tx, client_rx) = mpsc::channel::<ChannelCommand>();
            clients.insert(i, client_tx);
            let manager_tx = manager_tx.clone();
            let thread = std::thread::spawn(move || loop {
                manager_tx.send(ChannelCommand::ClientReady(i)).unwrap();

                let Ok(msg) = client_rx.recv() else {
                    break;
                };

                match msg {
                    ChannelCommand::ComeBackLater => {
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    ChannelCommand::JobData(pkg) => {
                        let pkgname = pkg.pkginfo.pkgname.clone();
                        match pkg.build() {
                            Ok(0) => {
                                manager_tx
                                    .send(ChannelCommand::JobSuccess(pkgname))
                                    .unwrap();
                            }
                            Ok(_) => {
                                manager_tx
                                    .send(ChannelCommand::JobFailed(pkgname))
                                    .unwrap();
                            }
                            Err(e) => manager_tx
                                .send(ChannelCommand::JobError((pkgname, e)))
                                .unwrap(),
                        }
                        continue;
                    }
                    ChannelCommand::Quit => {
                        break;
                    }
                    _ => todo!(),
                }
            });
            threads.push(thread);
        }

        /*
         * Manager thread.  Read incoming commands from clients and reply
         * accordingly.
         */
        let config = self.config.clone();
        let sandbox = self.sandbox.clone();
        let manager = std::thread::spawn(move || {
            let mut clients = clients.clone();
            let config = config.clone();
            let sandbox = sandbox.clone();
            let mut jobs = jobs.clone();

            let update_progress = |f: &HashSet<PkgName>| {
                let mut inprog: Vec<String> =
                    f.iter().map(|x| x.pkgname().to_string()).collect();
                inprog.sort();
                let msg = inprog.join(", ");
                progress.set_message(msg);
            };

            for command in manager_rx {
                match command {
                    ChannelCommand::ClientReady(c) => {
                        let client = clients.get(&c).unwrap();
                        match jobs.get_next_build() {
                            BuildStatus::Available(pkg) => {
                                let pkginfo = jobs.scanpkgs.get(&pkg).unwrap();
                                jobs.incoming.remove(&pkg);
                                jobs.running.insert(pkg);
                                update_progress(&jobs.running);
                                progress.inc(1);
                                client
                                    .send(ChannelCommand::JobData(Box::new(
                                        PackageBuild {
                                            id: c,
                                            config: config.clone(),
                                            pkginfo: pkginfo.clone(),
                                            sandbox: sandbox.clone(),
                                        },
                                    )))
                                    .unwrap();
                            }
                            BuildStatus::NoneAvailable => {
                                client
                                    .send(ChannelCommand::ComeBackLater)
                                    .unwrap();
                            }
                            BuildStatus::Done => {
                                client.send(ChannelCommand::Quit).unwrap();
                                clients.remove(&c);
                                if clients.is_empty() {
                                    break;
                                }
                            }
                        };
                    }
                    ChannelCommand::JobSuccess(pkgname) => {
                        jobs.mark_success(&pkgname);
                        jobs.running.remove(&pkgname);
                        update_progress(&jobs.running);
                    }
                    ChannelCommand::JobFailed(pkgname) => {
                        jobs.mark_failure(&pkgname);
                        jobs.running.remove(&pkgname);
                        update_progress(&jobs.running);
                    }
                    ChannelCommand::JobError((pkgname, e)) => {
                        jobs.mark_failure(&pkgname);
                        jobs.running.remove(&pkgname);
                        update_progress(&jobs.running);
                        /*
                         * TODO: do something about the error.
                         */
                        dbg!(&e);
                    }
                    _ => todo!(),
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
        });

        threads.push(manager);
        for thread in threads {
            thread.join().expect("thread panicked");
        }

        if self.sandbox.enabled() {
            for i in 0..self.config.build_threads() {
                self.sandbox.destroy(i)?;
            }
        }

        Ok(())
    }
}
