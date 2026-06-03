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
 * Types representing package state across the scan and build lifecycle.
 *
 * [`PackageState`] enumerates the states a package can be in.  A package may
 * transition between states as it moves through the lifecycle.
 *
 * [`PackageCounts`] is a simple tally indexed by [`PackageState`], helpful
 * for ensuring consistent and accurate counts where required.
 */

use strum::VariantArray;

/**
 * Current state of a package across the scan and build lifecycle.
 *
 * Variants are ordered by the phase in which they are first assigned.
 */
#[derive(
    Clone,
    Copy,
    Debug,
    Hash,
    PartialEq,
    Eq,
    strum::VariantArray,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::FromRepr,
    serde::Serialize,
    serde::Deserialize,
)]
#[strum(serialize_all = "kebab-case")]
#[repr(i32)]
pub enum PackageState {
    /// Package has `PKG_SKIP_REASON` set.
    PreSkipped = 0,
    /// Package has `PKG_FAIL_REASON` set.
    PreFailed = 1,
    /// Package has unresolved dependencies, or could not otherwise be scanned.
    Unresolved = 2,
    /// Package is blocked by a [`PreSkipped`](Self::PreSkipped) dependency.
    IndirectPreSkipped = 3,
    /// Package is blocked by a [`PreFailed`](Self::PreFailed) dependency.
    IndirectPreFailed = 4,
    /// Package is blocked by an [`Unresolved`](Self::Unresolved) dependency.
    IndirectUnresolved = 5,
    /// Package is buildable, awaiting build.
    Pending = 6,
    /// Binary package already exists and is current.
    UpToDate = 7,
    /// Package built successfully.
    Success = 8,
    /// Package build was attempted but failed.
    Failed = 9,
    /// Package is blocked by a [`Failed`](Self::Failed) dependency.
    IndirectFailed = 10,
}

impl PackageState {
    /**
     * The integer encoding for this state.  The mapping is stable:
     * existing values must never change.
     *
     * # Examples
     *
     * ```
     * use bob::pkgstate::PackageState;
     *
     * assert_eq!(PackageState::Success.id(), 8);
     * ```
     */
    pub fn id(self) -> i32 {
        self as i32
    }

    /**
     * State label.  bob aims for a more consistent and comprehensive map of
     * display strings than pbulk.  [`as_pbulk_str`](Self::as_pbulk_str) is
     * provided for pbulk compatible output strings, e.g. `BUILD_STATUS` in
     * reports.
     *
     * Note that the labels are derived using strum directly from the member
     * name, using the so-called "kebab-case" format.
     *
     * # Examples
     *
     * ```
     * use bob::pkgstate::PackageState;
     *
     * assert_eq!(PackageState::PreSkipped.as_str(), "pre-skipped");
     * assert_eq!(PackageState::IndirectPreSkipped.as_str(), "indirect-pre-skipped");
     * ```
     */
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    /**
     * pbulk-compatible `BUILD_STATUS` output format.  Should only be used
     * where 100% compatibility with pbulk is required, e.g. in the machine
     * readable report that is consumed by external tools.
     *
     * # Examples
     *
     * ```
     * use bob::pkgstate::PackageState;
     *
     * // pbulk does not support PKG_SKIP_REASON as a separate status
     * assert_eq!(PackageState::PreSkipped.as_pbulk_str(), "prefailed");
     * assert_eq!(PackageState::IndirectPreSkipped.as_pbulk_str(), "indirect-prefailed");
     * ```
     */
    pub fn as_pbulk_str(self) -> &'static str {
        match self {
            Self::PreSkipped | Self::PreFailed | Self::Unresolved => "prefailed",
            Self::IndirectPreSkipped | Self::IndirectPreFailed | Self::IndirectUnresolved => {
                "indirect-prefailed"
            }
            Self::Pending => "open",
            Self::UpToDate | Self::Success => "done",
            Self::Failed => "failed",
            Self::IndirectFailed => "indirect-failed",
        }
    }

    /**
     * State description for CLI usage output.  Matches the corresponding
     * variant's documentation, without the trailing period or link markup.
     *
     * # Examples
     *
     * ```
     * use bob::pkgstate::PackageState;
     *
     * assert_eq!(PackageState::Success.desc(), "Package built successfully");
     * ```
     */
    pub fn desc(self) -> &'static str {
        match self {
            Self::PreSkipped => "Package has PKG_SKIP_REASON set",
            Self::PreFailed => "Package has PKG_FAIL_REASON set",
            Self::Unresolved => {
                "Package has unresolved dependencies, or could not otherwise be scanned"
            }
            Self::IndirectPreSkipped => "Package is blocked by a PreSkipped dependency",
            Self::IndirectPreFailed => "Package is blocked by a PreFailed dependency",
            Self::IndirectUnresolved => "Package is blocked by an Unresolved dependency",
            Self::Pending => "Package is buildable, awaiting build",
            Self::UpToDate => "Binary package already exists and is current",
            Self::Success => "Package built successfully",
            Self::Failed => "Package build was attempted but failed",
            Self::IndirectFailed => "Package is blocked by a Failed dependency",
        }
    }

    /**
     * A successful outcome (freshly built or existing package is up-to-date).
     *
     * # Examples
     *
     * ```
     * use bob::pkgstate::PackageState;
     *
     * assert!(PackageState::Success.is_success());
     * assert!(PackageState::UpToDate.is_success());
     * assert!(!PackageState::Failed.is_success());
     * ```
     */
    pub fn is_success(self) -> bool {
        matches!(self, Self::Success | Self::UpToDate)
    }

    /**
     * Package was marked pre-skipped or pre-failed at scan time.
     *
     * # Examples
     *
     * ```
     * use bob::pkgstate::PackageState;
     *
     * assert!(PackageState::PreSkipped.is_skipped());
     * assert!(PackageState::PreFailed.is_skipped());
     * assert!(!PackageState::Failed.is_skipped());
     * ```
     */
    pub fn is_skipped(self) -> bool {
        matches!(self, Self::PreSkipped | Self::PreFailed)
    }

    /**
     * Package build is blocked by another package (any indirect variant).
     *
     * # Examples
     *
     * ```
     * use bob::pkgstate::PackageState;
     *
     * assert!(PackageState::IndirectFailed.is_blocked());
     * assert!(!PackageState::Failed.is_blocked());
     * ```
     */
    pub fn is_blocked(self) -> bool {
        matches!(
            self,
            Self::IndirectPreSkipped
                | Self::IndirectPreFailed
                | Self::IndirectUnresolved
                | Self::IndirectFailed
        )
    }

    /**
     * Package build cannot be attempted.  Equal to
     * [`is_skipped`](Self::is_skipped) || [`is_blocked`](Self::is_blocked).
     *
     * # Examples
     *
     * ```
     * use bob::pkgstate::PackageState;
     *
     * assert!(PackageState::PreSkipped.is_masked());
     * assert!(PackageState::IndirectFailed.is_masked());
     * assert!(!PackageState::Pending.is_masked());
     * ```
     */
    pub fn is_masked(self) -> bool {
        self.is_skipped() || self.is_blocked()
    }

    /**
     * Map a scan-time skip state to its indirect equivalent.
     * Non-skip variants are returned unchanged.
     */
    pub fn indirect(self) -> Self {
        match self {
            Self::PreSkipped | Self::IndirectPreSkipped => Self::IndirectPreSkipped,
            Self::PreFailed | Self::IndirectPreFailed => Self::IndirectPreFailed,
            Self::Unresolved | Self::IndirectUnresolved => Self::IndirectUnresolved,
            _ => self,
        }
    }
}

impl TryFrom<i32> for PackageState {
    type Error = String;

    fn try_from(id: i32) -> Result<Self, Self::Error> {
        Self::from_repr(id).ok_or_else(|| format!("unknown outcome id {id}"))
    }
}

/**
 * Counts of packages by [`PackageState`], backed by a fixed-size
 * array indexed by variant position.  Bob has a variety of counter displays,
 * and this ensures they are all consistent.
 *
 * # Examples
 *
 * ```
 * use bob::pkgstate::{PackageCounts, PackageState};
 *
 * let mut counts = PackageCounts::default();
 * counts.add(PackageState::Success);
 * counts.add(PackageState::UpToDate);
 * counts.add(PackageState::Failed);
 *
 * assert_eq!(counts[PackageState::Success], 1);
 * assert_eq!(counts.count(PackageState::is_success), 2);
 * ```
 */
#[derive(Clone, Debug)]
pub struct PackageCounts([usize; PackageState::VARIANTS.len()]);

impl Default for PackageCounts {
    fn default() -> Self {
        Self([0; PackageState::VARIANTS.len()])
    }
}

impl PackageCounts {
    /**
     * Increment the counter for this state.
     *
     * # Examples
     *
     * ```
     * use bob::pkgstate::{PackageCounts, PackageState};
     *
     * let mut counts = PackageCounts::default();
     * counts.add(PackageState::Success);
     * assert_eq!(counts[PackageState::Success], 1);
     * ```
     */
    pub fn add(&mut self, state: PackageState) {
        self.0[state as usize] += 1;
    }

    /**
     * Sum the counts of all states matching the predicate.
     *
     * # Examples
     *
     * ```
     * use bob::pkgstate::{PackageCounts, PackageState};
     *
     * let mut counts = PackageCounts::default();
     * counts.add(PackageState::Success);
     * counts.add(PackageState::UpToDate);
     * assert_eq!(counts.count(PackageState::is_success), 2);
     * ```
     */
    pub fn count(&self, pred: impl Fn(PackageState) -> bool) -> usize {
        PackageState::VARIANTS
            .iter()
            .copied()
            .filter(|k| pred(*k))
            .map(|k| self[k])
            .sum()
    }

    /**
     * Count of successful packages (freshly built or already up-to-date).
     */
    pub fn successful(&self) -> usize {
        self.count(PackageState::is_success)
    }

    /**
     * Count of packages whose build was attempted and failed directly.
     */
    pub fn failed(&self) -> usize {
        self[PackageState::Failed]
    }

    /**
     * Count of masked packages (skipped, or blocked by another package).
     */
    pub fn masked(&self) -> usize {
        self.count(PackageState::is_masked)
    }

    /**
     * Total packages with a reported outcome, as shown in report summaries:
     * [`successful`](Self::successful) + [`failed`](Self::failed) +
     * [`masked`](Self::masked).
     */
    pub fn total(&self) -> usize {
        self.successful() + self.failed() + self.masked()
    }
}

impl std::ops::Index<PackageState> for PackageCounts {
    type Output = usize;
    fn index(&self, state: PackageState) -> &usize {
        &self.0[state as usize]
    }
}
