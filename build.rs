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

/*
 * Encode an appropriate version for this build, reflecting whether it is a
 * clean tagged release or built from a specific revision and/or dirty.
 */

use std::process::Command;

fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let version = match describe(dir) {
        Some(v) => {
            rerun(dir);
            v
        }
        None => env!("CARGO_PKG_VERSION").to_string(),
    };
    println!("cargo:rustc-env=BOB_VERSION={version}");
}

fn describe(dir: &str) -> Option<String> {
    let top = git(dir, &["rev-parse", "--show-toplevel"])?;
    if std::fs::canonicalize(top).ok()? != std::fs::canonicalize(dir).ok()? {
        return None;
    }
    let rev = git(dir, &["describe", "--always", "--dirty", "--exclude=*"])?;
    if !rev.ends_with("-dirty")
        && let Some(tag) = git(dir, &["describe", "--tags", "--exact-match"])
    {
        return Some(tag.strip_prefix('v').unwrap_or(&tag).to_string());
    }
    Some(format!("{}-{}", env!("CARGO_PKG_VERSION"), rev))
}

/*
 * Re-run when anything the version depends on changes: HEAD/reflog/refs for
 * commits and tags, the index, and every tracked file for the dirty check.
 * --git-path resolves metadata for worktrees and submodules.
 */
fn rerun(dir: &str) {
    for p in ["HEAD", "logs/HEAD", "index", "refs", "packed-refs"] {
        if let Some(path) = git(dir, &["rev-parse", "--git-path", p]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if let Some(files) = git(dir, &["ls-files", "--full-name"]) {
        for f in files.lines() {
            println!("cargo:rerun-if-changed={dir}/{f}");
        }
    }
}

fn git(dir: &str, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}
