/*
 * Copyright (c) 2026 Jonathan Perkin <jonathan@perkin.org.uk>
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

/*!
 * Implementation of the `bob rebuild` command.
 *
 * Provides three modes of operation:
 * - `bob rebuild X` - rebuild X and everything that depends on X
 * - `bob rebuild --only X` - rebuild just X (with warning)
 * - `bob rebuild -a` - rebuild all previously failed packages
 */

use std::collections::HashSet;

use anyhow::{Context, Result, bail};

use bob::RunContext;
use bob::build::Build;
use bob::config::Config;
use bob::db::Database;
use bob::sandbox::{Sandbox, SandboxScope};

/**
 * Arguments for the rebuild command.
 */
pub struct RebuildArgs {
    pub all: bool,
    pub only: bool,
    pub packages: Vec<String>,
}

/**
 * Run the rebuild command.
 */
pub fn run(config: &Config, db: &Database, ctx: &RunContext, args: RebuildArgs) -> Result<()> {
    let targets = collect_targets(db, &args)?;

    let mut to_rebuild: HashSet<String> = targets.iter().cloned().collect();

    if args.only {
        eprintln!("Warning: rebuilding without dependents may cause inconsistent packages");
    } else {
        for target in &targets {
            if let Some(pkg) = db.get_package_by_name(target)? {
                for dep_id in db.get_transitive_reverse_deps(pkg.id)? {
                    to_rebuild.insert(db.get_pkgname(dep_id)?);
                }
            }
        }
    }

    let cleared = clear_build_cache(db, &to_rebuild)?;
    if cleared > 0 {
        println!("Cleared {} cached build result(s)", cleared);
    }

    let all_resolved = db
        .load_resolved_packages()
        .context("No scan data cached - run 'bob scan' first")?;

    let buildable: indexmap::IndexMap<_, _> = all_resolved
        .into_iter()
        .filter(|p| to_rebuild.contains(p.pkgname().pkgname()))
        .map(|p| (p.pkgname().clone(), p))
        .collect();

    if buildable.is_empty() {
        bail!("No buildable packages found");
    }

    let pkgsrc_env = db
        .load_pkgsrc_env()
        .context("PkgsrcEnv not cached - try 'bob clean' first")?;

    let sandbox = Sandbox::new(config);
    let scope = SandboxScope::new(sandbox, ctx.clone());
    let mut build = Build::new(config, pkgsrc_env, scope, buildable);
    build.load_cached_from_db(db)?;
    build.start(ctx, db)?;

    Ok(())
}

/**
 * Collect target packages to rebuild based on command arguments.
 */
fn collect_targets(db: &Database, args: &RebuildArgs) -> Result<Vec<String>> {
    if args.all {
        if !args.packages.is_empty() {
            bail!("Cannot specify packages with --all");
        }
        let failed = db.get_failed_packages()?;
        if failed.is_empty() {
            println!("No failed packages to rebuild");
            std::process::exit(0);
        }
        println!("Found {} failed package(s) to rebuild", failed.len());
        return Ok(failed);
    }

    if args.packages.is_empty() {
        bail!("Specify packages to rebuild, or use --all for failed packages");
    }

    let mut result = Vec::new();
    for pkg in &args.packages {
        if pkg.contains('/') {
            let db_pkgs = db.get_packages_by_path(pkg)?;
            if db_pkgs.is_empty() {
                bail!("Package '{}' not in scan cache. Run 'bob scan' first.", pkg);
            }
            result.extend(db_pkgs.into_iter().map(|p| p.pkgname));
        } else {
            if db.get_package_by_name(pkg)?.is_none() {
                bail!("Package '{}' not in scan cache. Run 'bob scan' first.", pkg);
            }
            result.push(pkg.clone());
        }
    }
    Ok(result)
}

/**
 * Clear build cache for the specified packages.
 */
fn clear_build_cache(db: &Database, packages: &HashSet<String>) -> Result<usize> {
    let mut cleared = 0;
    for pkgname in packages {
        if db.delete_build_by_name(pkgname)? {
            cleared += 1;
        }
    }
    Ok(cleared)
}
