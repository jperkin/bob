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

//! Unified package state.
//!
//! [`PackageState`] represents every possible state of a package across
//! the scan and build lifecycle, ordered by discovery phase.
//!
//! [`PackageStateKind`] is the plain discriminant enum, used for status
//! labels, database IDs, and parsing without needing a full instance.

use std::str::FromStr;
use strum::{EnumCount, IntoEnumIterator};

/// Plain discriminant for [`PackageState`], ordered by lifecycle phase.
///
/// Derives provide kebab-case status labels ([`IntoStaticStr`]/[`EnumString`]),
/// integer conversion ([`FromRepr`] with `#[repr(i32)]`), and iteration
/// ([`EnumIter`]).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    strum::EnumCount,
    strum::EnumIter,
    strum::EnumString,
    strum::FromRepr,
    strum::AsRefStr,
    strum::IntoStaticStr,
)]
#[strum(serialize_all = "kebab-case")]
#[repr(i32)]
pub enum PackageStateKind {
    PreSkipped = 0,
    PreFailed = 1,
    Unresolved = 2,
    IndirectPreSkipped = 3,
    IndirectPreFailed = 4,
    IndirectUnresolved = 5,
    Pending = 6,
    UpToDate = 7,
    Success = 8,
    Failed = 9,
    IndirectFailed = 10,
}

/// State of a package across the scan and build lifecycle.
///
/// Variants are ordered by the phase in which they are first assigned:
///
/// 1. **Scan** -- `PreSkipped`, `PreFailed`
/// 2. **Resolution** -- `Unresolved`
/// 3. **Propagation** -- `IndirectPreSkipped`, `IndirectPreFailed`, `IndirectUnresolved`
/// 4. **Buildable** -- `Pending`
/// 5. **Up-to-date check** -- `UpToDate`
/// 6. **Build** -- `Success`, `Failed`
/// 7. **Build propagation** -- `IndirectFailed`
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PackageState {
    /// Skipped due to PKG_SKIP_REASON.
    PreSkipped(String),
    /// Skipped due to PKG_FAIL_REASON.
    PreFailed(String),
    /// Has unresolved dependencies.
    Unresolved(String),
    /// Blocked by a pre-skipped dependency.
    IndirectPreSkipped(String),
    /// Blocked by a pre-failed dependency.
    IndirectPreFailed(String),
    /// Blocked by a dependency with unresolved deps.
    IndirectUnresolved(String),
    /// Buildable, awaiting build.
    Pending,
    /// Binary package already exists and is current.
    UpToDate,
    /// Built successfully.
    Success,
    /// Build failed.
    Failed(String),
    /// Blocked by a dependency that failed to build.
    IndirectFailed(String),
}

impl PackageState {
    /// The plain discriminant for this state.
    pub fn kind(&self) -> PackageStateKind {
        match self {
            Self::PreSkipped(_) => PackageStateKind::PreSkipped,
            Self::PreFailed(_) => PackageStateKind::PreFailed,
            Self::Unresolved(_) => PackageStateKind::Unresolved,
            Self::IndirectPreSkipped(_) => PackageStateKind::IndirectPreSkipped,
            Self::IndirectPreFailed(_) => PackageStateKind::IndirectPreFailed,
            Self::IndirectUnresolved(_) => PackageStateKind::IndirectUnresolved,
            Self::Pending => PackageStateKind::Pending,
            Self::UpToDate => PackageStateKind::UpToDate,
            Self::Success => PackageStateKind::Success,
            Self::Failed(_) => PackageStateKind::Failed,
            Self::IndirectFailed(_) => PackageStateKind::IndirectFailed,
        }
    }

    /// Construct from a kind and optional detail string.
    fn from_kind(kind: PackageStateKind, detail: String) -> Self {
        match kind {
            PackageStateKind::PreSkipped => Self::PreSkipped(detail),
            PackageStateKind::PreFailed => Self::PreFailed(detail),
            PackageStateKind::Unresolved => Self::Unresolved(detail),
            PackageStateKind::IndirectPreSkipped => Self::IndirectPreSkipped(detail),
            PackageStateKind::IndirectPreFailed => Self::IndirectPreFailed(detail),
            PackageStateKind::IndirectUnresolved => Self::IndirectUnresolved(detail),
            PackageStateKind::Pending => Self::Pending,
            PackageStateKind::UpToDate => Self::UpToDate,
            PackageStateKind::Success => Self::Success,
            PackageStateKind::Failed => Self::Failed(detail),
            PackageStateKind::IndirectFailed => Self::IndirectFailed(detail),
        }
    }

    /// Kebab-case status label.
    pub fn status(&self) -> &'static str {
        self.kind().into()
    }

    /// Database integer ID, matching variant order.
    pub fn db_id(&self) -> i32 {
        self.kind() as i32
    }

    /// Reconstruct from DB integer + optional detail string.
    pub fn from_db(id: i32, detail: Option<String>) -> Option<Self> {
        PackageStateKind::from_repr(id).map(|k| Self::from_kind(k, detail.unwrap_or_default()))
    }

    /// Parse a status string into a default (empty-detail) instance.
    pub fn from_status(s: &str) -> Option<Self> {
        PackageStateKind::from_str(s)
            .ok()
            .map(|k| Self::from_kind(k, String::new()))
    }

    /// The detail/reason string, if any.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Pending | Self::UpToDate | Self::Success => None,
            Self::PreSkipped(s)
            | Self::PreFailed(s)
            | Self::Unresolved(s)
            | Self::IndirectPreSkipped(s)
            | Self::IndirectPreFailed(s)
            | Self::IndirectUnresolved(s)
            | Self::Failed(s)
            | Self::IndirectFailed(s) => Some(s),
        }
    }

    /// True for skip-phase states (not success, failed, or up-to-date).
    pub fn is_skip(&self) -> bool {
        !matches!(self, Self::Success | Self::Failed(_) | Self::UpToDate)
    }

    /// True for direct skip reasons (PreSkipped/PreFailed/Unresolved).
    pub fn is_direct_skip(&self) -> bool {
        matches!(
            self,
            Self::PreSkipped(_) | Self::PreFailed(_) | Self::Unresolved(_)
        )
    }

    /// Map a skip state to its indirect equivalent, with new detail.
    pub fn indirect(&self, detail: String) -> Self {
        match self {
            Self::PreSkipped(_) | Self::IndirectPreSkipped(_) => Self::IndirectPreSkipped(detail),
            Self::PreFailed(_) | Self::IndirectPreFailed(_) => Self::IndirectPreFailed(detail),
            Self::Unresolved(_) | Self::IndirectUnresolved(_) => Self::IndirectUnresolved(detail),
            Self::IndirectFailed(_) => Self::IndirectFailed(detail),
            other => other.clone(),
        }
    }

    /// Generate SQL VALUES for the outcome_types lookup table.
    ///
    /// Excludes Pending since that is not stored in the database.
    pub fn db_values() -> String {
        PackageStateKind::iter()
            .filter(|k| *k != PackageStateKind::Pending)
            .map(|k| {
                let s: &'static str = k.into();
                format!("({}, '{}')", k as i32, s)
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Counts of packages by [`PackageStateKind`].
///
/// Backed by an array indexed by the kind discriminant, so adding a new
/// variant to [`PackageStateKind`] automatically extends the counts with
/// no additional code.
#[derive(Clone, Debug)]
pub struct PackageCounts([usize; PackageStateKind::COUNT]);

impl Default for PackageCounts {
    fn default() -> Self {
        Self([0; PackageStateKind::COUNT])
    }
}

impl PackageCounts {
    /// Increment the counter for this state.
    pub fn add(&mut self, state: &PackageState) {
        self.0[state.kind() as usize] += 1;
    }
}

impl std::ops::Index<PackageStateKind> for PackageCounts {
    type Output = usize;
    fn index(&self, kind: PackageStateKind) -> &usize {
        &self.0[kind as usize]
    }
}

impl std::fmt::Display for PackageState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unresolved(detail) => write!(f, "Could not resolve: {}", detail),
            other => match other.detail() {
                Some(d) if !d.is_empty() => write!(f, "{}", d),
                _ => write!(f, "{}", other.status()),
            },
        }
    }
}
