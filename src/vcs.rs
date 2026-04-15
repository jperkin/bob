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
 * Version control system metadata.
 *
 * Auto-detects repository information from a path, trying git first
 * then falling back to CVS.  Used to populate build reports with
 * repository details (remote URL, branch, revision).
 */

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tracing::debug;

/**
 * Metadata extracted from a version control repository.
 */
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VcsInfo {
    /// Version control system type.
    #[serde(skip_serializing_if = "Option::is_none", rename = "format")]
    pub vcs: Option<String>,
    /// Remote URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_url: Option<String>,
    /// Local branch name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_branch: Option<String>,
    /// Remote tracking branch name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_branch: Option<String>,
    /// Short commit/revision identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// Full commit hash (git only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_full: Option<String>,
}

impl VcsInfo {
    /**
     * Auto-detect VCS metadata from the given path.
     *
     * Tries git first, then CVS.  Returns a default (empty) `VcsInfo`
     * if no VCS is detected.
     */
    pub fn from_path(path: &Path) -> Self {
        if let Some(info) = Self::try_git(path) {
            debug!(
                vcs = "git",
                local_branch = ?info.local_branch,
                remote_branch = ?info.remote_branch,
                revision = ?info.revision,
                remote = ?info.remote_url,
                "Detected repository"
            );
            return info;
        }

        if let Some(info) = Self::try_cvs(path) {
            debug!(
                vcs = "cvs",
                remote_branch = ?info.remote_branch,
                remote = ?info.remote_url,
                "Detected repository"
            );
            return info;
        }

        debug!(path = %path.display(), "No VCS detected");
        Self::default()
    }

    /**
     * Returns true if VCS information was successfully detected.
     */
    pub fn is_detected(&self) -> bool {
        self.vcs.is_some()
    }

    /**
     * Return an HTTPS web URL for the repository, if derivable.
     *
     * Converts SSH URLs (e.g., `git@github.com:user/repo.git`) to
     * HTTPS equivalents using `gix::Url` for parsing.  Returns None
     * for non-git VCS, local paths, or unparseable URLs.
     */
    pub fn web_url(&self) -> Option<String> {
        if self.vcs.as_deref() != Some("git") {
            return None;
        }
        let url_str = self.remote_url.as_deref()?;
        let url = gix::url::parse(url_str.into()).ok()?;
        let host = url.host()?;
        let path = url.path.to_string();
        let path = path.trim_start_matches('/');
        match url.scheme {
            gix::url::Scheme::Https | gix::url::Scheme::Http => {
                Some(format!("{}://{}/{}", url.scheme, host, path))
            }
            gix::url::Scheme::Ssh => Some(format!("https://{}/{}", host, path)),
            _ => None,
        }
    }

    fn try_git(path: &Path) -> Option<Self> {
        let repo = gix::discover(path).ok()?;

        let head = repo.head().ok()?;
        let local_branch = head.referent_name().map(|r| r.shorten().to_string());

        let head_id = head.id();
        let revision_full = head_id.map(|id| id.to_string());
        let revision = revision_full
            .as_ref()
            .map(|s| s[..s.len().min(12)].to_string());

        let (remote_name, remote_branch) = if let Some(ref local) = local_branch {
            let config = repo.config_snapshot();
            let remote = config
                .string(format!("branch.{}.remote", local).as_str())
                .map(|v| v.to_string());
            let branch = config
                .string(format!("branch.{}.merge", local).as_str())
                .map(|v| {
                    let s = v.to_string();
                    s.trim_start_matches("refs/heads/").to_string()
                });
            (remote, branch)
        } else {
            (None, None)
        };

        let remote_url = remote_name
            .or_else(|| {
                repo.remote_names()
                    .into_iter()
                    .next()
                    .map(|n| n.to_string())
            })
            .and_then(|name| repo.find_remote(name.as_str()).ok())
            .and_then(|r| r.url(gix::remote::Direction::Fetch).cloned())
            .map(|url| {
                let s = url.to_bstring().to_string();
                s.trim_end_matches(".git").to_string()
            });

        Some(Self {
            vcs: Some("git".to_string()),
            remote_url,
            local_branch,
            remote_branch,
            revision,
            revision_full,
        })
    }

    /**
     * Build a commit URL for a single revision, if a web URL is derivable.
     */
    pub fn commit_url(&self, sha: &str) -> Option<String> {
        Some(format!("{}/commit/{}", self.web_url()?, sha))
    }

    fn try_cvs(path: &Path) -> Option<Self> {
        let root_path = path.join("CVS/Root");
        let remote_url = std::fs::read_to_string(root_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;

        /*
         * CVS/Tag format: T<tagname> for branch tags, N<tagname> for
         * non-branch tags, D<date> for date.  No file means the main
         * trunk, which CVS calls "HEAD".
         */
        let tag_path = path.join("CVS/Tag");
        let remote_branch = std::fs::read_to_string(tag_path)
            .ok()
            .map(|s| s.trim().to_string())
            .and_then(|s| {
                s.strip_prefix('T')
                    .or_else(|| s.strip_prefix('N'))
                    .map(|tag| tag.to_string())
            })
            .or_else(|| Some("HEAD".to_string()));

        Some(Self {
            vcs: Some("cvs".to_string()),
            remote_url: Some(remote_url),
            local_branch: None,
            remote_branch,
            revision: None,
            revision_full: None,
        })
    }
}

/**
 * A single commit's display info, used by the build report's "Commits"
 * column to show what changed in a pkgpath since the previous build.
 */
#[derive(Clone, Debug)]
pub struct CommitInfo {
    /// Author "username" -- the local part of the email if the email
    /// looks valid, otherwise the display name.
    pub author: String,
    /// Full commit SHA, used to construct commit URLs.
    pub sha_full: String,
    /// Shortened SHA for display, the shortest unique abbreviation in
    /// the repository (typically 7 characters, longer if needed).
    pub sha_short: String,
}

/**
 * Walk the git history between two revisions and group commits by the
 * pkgpath they touched.  For each commit reachable from `new_rev` but
 * not from `old_rev`, the changed file list is examined and the commit
 * is recorded against any pkgpath whose subtree contains a changed
 * file.
 *
 * Returns an empty map if the repository is not git, if either revision
 * cannot be resolved, or if the walk fails.  Errors during the walk
 * itself propagate.
 *
 * Commits are returned in the order produced by `rev_walk`, which is
 * topological/reverse-chronological -- newest first.
 */
pub fn commits_for_pkgpaths(
    repo_path: &Path,
    old_rev: &str,
    new_rev: &str,
    pkgpaths: &HashSet<String>,
) -> anyhow::Result<HashMap<String, Vec<CommitInfo>>> {
    let mut result: HashMap<String, Vec<CommitInfo>> = HashMap::new();
    if pkgpaths.is_empty() {
        return Ok(result);
    }

    let repo = gix::discover(repo_path)
        .with_context(|| format!("Failed to open git repository at {}", repo_path.display()))?;

    let new_id = repo
        .rev_parse_single(new_rev)
        .with_context(|| format!("Failed to resolve revision {}", new_rev))?
        .detach();
    let old_id = repo
        .rev_parse_single(old_rev)
        .with_context(|| format!("Failed to resolve revision {}", old_rev))?
        .detach();

    let walk = repo
        .rev_walk([new_id])
        .with_hidden([old_id])
        .all()
        .context("Failed to start revision walk")?;

    let mut walk_count = 0usize;
    let mut match_count = 0usize;
    for info in walk {
        let info = info.context("Revision walk error")?;
        walk_count += 1;
        let commit = info
            .object()
            .with_context(|| format!("Failed to load commit {}", info.id))?;

        let author = extract_author(&commit);
        let sha_full = info.id.to_string();
        let sha_short = info.id.to_hex_with_len(7).to_string();

        let new_tree = commit.tree().context("Failed to load commit tree")?;
        let parent_id = commit.parent_ids().next();
        let parent_tree = parent_id
            .and_then(|pid| pid.object().ok())
            .and_then(|o| o.try_into_commit().ok())
            .and_then(|c| c.tree().ok());
        let touched = changed_pkgpaths(&repo, &new_tree, parent_tree.as_ref(), pkgpaths)?;

        if touched.is_empty() {
            continue;
        }
        match_count += 1;
        let entry = CommitInfo {
            author,
            sha_full,
            sha_short,
        };
        for pkgpath in touched {
            result.entry(pkgpath).or_default().push(entry.clone());
        }
    }

    tracing::debug!(walk_count, match_count, "commits_for_pkgpaths walk complete");
    Ok(result)
}

/**
 * Diff `new_tree` against `old_tree` (or the empty tree if `None`) and
 * return the set of pkgpaths whose subtrees contain at least one changed
 * file.  A pkgpath is matched if it is the leading directory prefix of
 * any changed file's path.
 */
fn changed_pkgpaths(
    repo: &gix::Repository,
    new_tree: &gix::Tree<'_>,
    old_tree: Option<&gix::Tree<'_>>,
    pkgpaths: &HashSet<String>,
) -> anyhow::Result<HashSet<String>> {
    use gix::object::tree::diff::Change;
    use std::ops::ControlFlow;

    let mut touched: HashSet<String> = HashSet::new();
    let empty_tree;
    let lhs = match old_tree {
        Some(t) => t,
        None => {
            empty_tree = repo.empty_tree();
            &empty_tree
        }
    };

    let mut platform = lhs.changes().context("Failed to start tree diff")?;
    platform
        .for_each_to_obtain_tree(new_tree, |change| {
            let path: String = match change {
                Change::Addition { location, .. }
                | Change::Deletion { location, .. }
                | Change::Modification { location, .. } => location.to_string(),
                Change::Rewrite {
                    location,
                    source_location,
                    ..
                } => {
                    if let Some(pp) = pkgpath_for(source_location.to_string().as_str()) {
                        if pkgpaths.contains(&pp) {
                            touched.insert(pp);
                        }
                    }
                    location.to_string()
                }
            };
            if let Some(pp) = pkgpath_for(&path) {
                if pkgpaths.contains(&pp) {
                    touched.insert(pp);
                }
            }
            Ok::<_, std::convert::Infallible>(ControlFlow::Continue(()))
        })
        .context("Tree diff failed")?;

    Ok(touched)
}

/**
 * Extract the pkgpath from a file path: the first two path components,
 * joined with `/`.  Returns None if the path doesn't have at least two
 * components.
 */
fn pkgpath_for(path: &str) -> Option<String> {
    let mut parts = path.splitn(3, '/');
    let category = parts.next()?;
    let pkg = parts.next()?;
    if category.is_empty() || pkg.is_empty() {
        return None;
    }
    Some(format!("{}/{}", category, pkg))
}

/**
 * Extract a "username" from a commit author signature.  Prefers the
 * local part of the email address if it looks valid, falling back to
 * the display name.
 */
fn extract_author(commit: &gix::Commit<'_>) -> String {
    let Ok(sig) = commit.author() else {
        return String::new();
    };
    let email = sig.email.to_string();
    if let Some((local, _)) = email.split_once('@') {
        if !local.is_empty() {
            return local.to_string();
        }
    }
    sig.name.to_string()
}
