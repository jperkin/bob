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
    Hash,
    PartialEq,
    Eq,
    strum::EnumCount,
    strum::EnumIter,
    strum::EnumProperty,
    strum::EnumString,
    strum::FromRepr,
    strum::AsRefStr,
    strum::IntoStaticStr,
)]
#[strum(serialize_all = "kebab-case")]
#[repr(i32)]
pub enum PackageStateKind {
    #[strum(props(pbulk = "prefailed", desc = "PKG_SKIP_REASON set"))]
    PreSkipped = 0,
    #[strum(props(pbulk = "prefailed", desc = "PKG_FAIL_REASON set"))]
    PreFailed = 1,
    #[strum(props(pbulk = "prefailed", desc = "Has unresolved dependencies"))]
    Unresolved = 2,
    #[strum(props(pbulk = "indirect-prefailed", desc = "Blocked by pre-skipped package"))]
    IndirectPreSkipped = 3,
    #[strum(props(pbulk = "indirect-prefailed", desc = "Blocked by pre-failed package"))]
    IndirectPreFailed = 4,
    #[strum(props(
        pbulk = "indirect-prefailed",
        desc = "Blocked by package with unresolved dependencies"
    ))]
    IndirectUnresolved = 5,
    #[strum(props(pbulk = "open", desc = "Ready to build"))]
    Pending = 6,
    #[strum(props(pbulk = "done", desc = "Binary already exists"))]
    UpToDate = 7,
    #[strum(props(pbulk = "done", desc = "Built successfully"))]
    Success = 8,
    #[strum(props(pbulk = "failed", desc = "Build attempted and failed"))]
    Failed = 9,
    #[strum(props(
        pbulk = "indirect-failed",
        desc = "Blocked by package that failed to build"
    ))]
    IndirectFailed = 10,
}

impl PackageStateKind {
    /// One-line description of the state, from the `desc` strum property.
    pub fn desc(self) -> &'static str {
        use strum::EnumProperty;
        self.get_str("desc").expect("desc prop")
    }
}

/// Aliases for filtering on multiple [`PackageStateKind`] values at once.
///
/// Used by the `bob status -s` filter and by aggregated count output.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    strum::EnumIter,
    strum::EnumProperty,
    strum::EnumString,
    strum::AsRefStr,
    strum::IntoStaticStr,
)]
#[strum(serialize_all = "kebab-case")]
pub enum PackageStateAlias {
    #[strum(props(desc = "Any pre-skipped or pre-failed package"))]
    Skipped,
    #[strum(props(desc = "Any package blocked by another"))]
    Blocked,
}

impl PackageStateAlias {
    /// The set of [`PackageStateKind`] values this alias expands to.
    pub fn expands_to(self) -> &'static [PackageStateKind] {
        use PackageStateKind::*;
        match self {
            Self::Skipped => &[PreSkipped, PreFailed],
            Self::Blocked => &[
                IndirectPreSkipped,
                IndirectPreFailed,
                IndirectUnresolved,
                IndirectFailed,
            ],
        }
    }

    /// One-line description of the alias.
    pub fn desc(self) -> &'static str {
        use strum::EnumProperty;
        self.get_str("desc").expect("desc prop")
    }
}

/**
 * Parse a status filter string into one or more [`PackageStateKind`] values.
 *
 * Accepts either a canonical kind name (e.g. `pre-failed`) or an alias
 * (e.g. `blocked`), returning the expanded set of kinds.
 */
pub fn parse_status_filter(s: &str) -> Result<Vec<PackageStateKind>, String> {
    if let Ok(k) = s.parse::<PackageStateKind>() {
        return Ok(vec![k]);
    }
    if let Ok(a) = s.parse::<PackageStateAlias>() {
        return Ok(a.expands_to().to_vec());
    }
    Err(format!("unknown status '{s}'"))
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

    /**
     * pbulk-compatible BUILD_STATUS value.
     */
    pub fn pbulk_status(&self) -> &'static str {
        use strum::EnumProperty;
        self.kind().get_str("pbulk").expect("pbulk prop")
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

    /// Packages with a successful outcome: freshly built (`Success`) plus
    /// already-current binaries (`UpToDate`).
    pub fn successful(&self) -> usize {
        self[PackageStateKind::Success] + self[PackageStateKind::UpToDate]
    }

    /// Packages that failed to build.
    pub fn failed(&self) -> usize {
        self[PackageStateKind::Failed]
    }

    /// Packages whose existing binary was up to date.
    pub fn up_to_date(&self) -> usize {
        self[PackageStateKind::UpToDate]
    }

    /// Sum of counts for all kinds in an alias expansion.
    pub fn count_alias(&self, alias: PackageStateAlias) -> usize {
        alias.expands_to().iter().map(|k| self[*k]).sum()
    }

    /// Packages not attempted: skip/fail reasons and indirect
    /// dependents of failed or masked packages.  Does not include
    /// Unresolved (those appear in scan failures).
    pub fn masked(&self) -> usize {
        use PackageStateKind::*;
        self[PreSkipped]
            + self[PreFailed]
            + self[IndirectPreSkipped]
            + self[IndirectPreFailed]
            + self[IndirectUnresolved]
            + self[IndirectFailed]
    }

    /// Total packages: successful + failed + masked.
    /// Excludes scan failures and unresolved (listed separately).
    pub fn total(&self) -> usize {
        self.successful() + self.failed() + self.masked()
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
        match self.detail() {
            Some(d) if !d.is_empty() => write!(f, "{}", d),
            _ => write!(f, "{}", self.status()),
        }
    }
}
