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

use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::debug;

/**
 * Metadata extracted from a version control repository.
 */
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VcsInfo {
    /// Version control system type.
    #[serde(skip_serializing_if = "Option::is_none")]
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
