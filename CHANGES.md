# Changelog

## Version 0.8.1 (2026-02-06)

* Fix output ordering of 'bob list status' to ensure it is identical to build
  order, and improve performance.

## Version 0.8.0 (2026-02-06)

* Now published as `bob` on crates.io, thanks Wyatt!

* Rewrite up-to-date checks in native Rust using features from pkgsrc-rs,
  removing the dependency on `pkg_install` tools, and allowing full package
  status to be calculated (in parallel) up-front.  This provides significant
  performance improvements, and the paves the way for the powerful `status`
  command described below.

* Consolidate `bob list` subcommands into `bob list status` with filtering.
  Filter by status with `-s` (repeatable or comma-separated), customise column
  selection with `-o`, and filter packages by regex.  Include reasons where
  appropriate for the status calculation.

* Add `bob list tree` to show dependency tree in topological order.  Use `-f`
  to select output format (`utf8`, `ascii`, `none`), `-a` to include up-to-date
  packages, and `-p` for pkgpath output.  Optional package argument filters by
  regex.

* Add `bob scan --scan-only` to skip up-to-date checking, if the user does not
  plan to perform any builds and wishes only to verify a coherent pkgsrc tree.

* Move `--path` flag from global `bob list` to individual subcommands (`tree`,
  `blockers`, `blocked-by`) as `-p`.

* Support non-terminal plain output mode.

* Provide comprehensive scan and build result variants to cover all cases.

* Add `examples/scan.lua` for scan-only configurations.

* Various robustness and security improvements.

## Version 0.7.0 (2026-01-30)

* Add `bob list` command for querying package status.

* Add `environment` config section for controlling the sandbox process
  environment.  Set up default strict environments to avoid host pollution.

* Add `ifset` conditional field on sandbox actions, with `{var}` variable
  substitution.  Used by example configs to automatically create `build_user`
  home directories.

* Add `read_pkgpaths(file)` Lua function for loading package lists from files.

* Unify sandbox lifecycle.  The scan sandbox is now reused for subsequent
  builds, avoiding an unnecessary destroy/create cycle between scan and build.

* Defer dependency discovery for limited scans, only scanning dependency
  pkgpaths when resolution determines they are needed.  This matches pbulk
  behaviour, and can slightly reduce the number of packages that are built.

* Overhaul sandbox discovery and cleanup.  More reliable detection of old or
  incomplete sandboxes.

* Improve macOS sandbox support: switch to `diskutil unmount` with retry logic,
  per-mount process killing with system daemon filtering, and `mdns-listener`
  script for DNS resolution inside chroots.

* Add `bindfs` sandbox config option for specifying the bindfs binary path.

* Improve error messages throughout, with full error chain context for sandbox
  operations and clean single-line error display.

* Add `bob_sandbox_path` environment variable for non-chroot `cmd` actions.

* Rename `bob util import-pscan` to `bob util import-scan`, which now supports
  both `pscan` and `presolve` files from pbulk.

* Enable crossterm `use-dev-tty`, fixing TUI issues with piped input.

## Version 0.6.0 (2026-01-20)

* Overhaul pkgsrc variable configuration.  Variables are fetched directly via
  `show-vars` at the start of a run, leaving `mk.conf` to be the single source
  of truth.  Rename `scanenv` to `cachevars`, which is now simply a list of
  variable names to fetch and cache.

* Collapse idle workers in the TUI, leaving more vertical space for active
  build logs.  More efficient TUI updates and refresh handling.

* Add `rebuild -a` flag to rebuild all packages, clearing any cached build
  results but reusing the scan and dependency resolution.

* Add `pkg_summary.gz` generation with `FILE_CKSUM` support.

* Add `chroot` flag to `cmd` actions to run commands inside sandbox.  Remove
  `cwd` argument, the semantics were too confusing with too much magic.

* Parallel sandbox creation/destruction, and parallel package discovery during
  full scans.

* Execute bmake directly rather than via shell for scan phase.

* Overhaul logging: use `log_level` in config, override with `RUST_LOG`.
  Improve many output messages and ensure consistency.

* Improve sandbox shutdown and cleanup reliability, especially during
  interruptions.

* `bob clean` now removes the entire log directory, `bob clean -l` removes just
  the package log directories.

* `bob db` no longer prints column headers.

* Add `bob report` command.  HTML reports are no longer generated
  automatically.

* Default `tar` to "tar" in PATH, only required when bootstrap is enabled.

## Version 0.5.0 (2026-01-08)

* Add `bob db` command for arbitrary SQL queries.

* Improve scan performance and pbulk compatibility with regards to resolver
  failures.  Add `strict_scan` to configure whether resolver errors are fatal.

* Allow simpler configs if running in scan-only mode.  Improve error messages
  for config issues.

* Remove stats module, statistics are now recorded to the database.

* Various report and TUI fixes.

## Version 0.4.0 (2026-01-03)

* Rewrite pkg-build and pkg-up-to-date scripts in native Rust to improve
  reliability.  Fixes various issues with exit status not being tracked
  correctly.

* Overhaul database architecture and improve scan caching, including fast
  path for completed full scans and better support for resuming builds.

* Add `rebuild` command and pkgpath argument support for `build`.

* Various bug fixes plus improvements to the log viewer and report.

## Version 0.3.0 (2026-01-01)

* Package resolver is now 100% bug-for-bug compatible with pbulk, generating
  identical `presolve` files.  Bob may now be suitable for building a full
  pkgsrc tree, though this is currently untested.

* Add database support for caching scan and build results.  Interrupted
  operations will now resume from where they left off.

* Add `bob clean` command to clear database state ready for building against
  an updated pkgsrc.

* Add and move various utility commands to under `bob util ...` subcommand.

* Allow `bob init` to run on an existing empty directory.

* Fix log handling when retrying builds.

## Version 0.2.0 (2025-12-24)

* Support full pkgsrc tree scans.  Various fixes and enhancements to scans,
  including signal handling support, resolve logs, and a new `strict_scan`
  option.

* Add stats module for performance analysis.

* Add new `scanenv` configuration table.  Useful for inserting environment
  variables that are calculated before `mk.conf` is loaded and avoid expensive
  forks for every package scan.

## Version 0.1.0 (2025-12-22)

* First version that is considered to be minimally useful for users to start
  building packages.  Sandbox support for NetBSD, Linux, illumos, and macOS.
