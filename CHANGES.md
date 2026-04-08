# Changelog

## Version 0.99.1 (2026-04-08)

* Minor improvements to error handling and package description.

## Version 0.99.0 (2026-04-08)

* New `bob publish` command for publishing binary packages and HTML reports
  to a remote host.  Supports both direct rsync and a staging mode using
  `--link-dest` for atomic updates with a user-supplied swap command run over
  ssh.  Reports include build summaries, package history, and machine-readable
  output, and `--dry-run` is supported.

* New `bob log` and `bob diff` commands.  `log` shows build failure logs by
  pkgname or pkgpath regex with optional stage selection.  `diff` compares two
  historical builds and shows what changed.

* Bob now uses standard XDG paths for config and data, with `BOB_SYSCONFDIR`
  and `BOB_DATADIR` overrides.  The requirement to run from the same directory
  as `config.lua` is gone, default `cachevars` are built in, and `-c` is now a
  global flag usable with any subcommand.

* Substantial sandbox config restructure.  `sandboxes.actions` is now
  `sandboxes.setup`, the top-level `environment` section has moved into
  `sandboxes` and is split into per-context `build` and `dev` sub-tables,
  per-action `ifset`/`ifexists` are replaced with a unified `only = { ... }`
  predicate, `pkgsrc.env` has been removed, and `pkgsrc.logdir` is now
  `options.logdir`.

* The `scripts` config section has been removed; pre/post-build scripts
  are now native Rust, and arbitrary commands can be run via the new
  `sandboxes.hooks` action list.  A new `scriptenv()` Lua helper bundles a
  shell script body with the environment variables it needs, so script bodies
  can reference config values from anywhere without declaration order issues.

* `bob list blockers` and `bob list blocked-by` accept regex patterns
  consistent with other `bob list` subcommands.  New `use_failed_history`
  option to include failed builds when routing `WRKOBJDIR` between tmpfs and
  disk.  Scan failures are now persisted in the database and included in
  reports.  Up-to-date checking has temporarily reverted to matching pbulk
  behaviour due to unnecessary rebuilds when `USE_INDIRECT_DEPENDS` is enabled.

* Significant number of minor tweaks, bug fixes, reliability improvements,
  and performance optimisations.

## Version 0.9.0 (2026-03-25)

* Support for dynamic `MAKE_JOBS` and `WRKOBJDIR` based on historical build
  data.  `MAKE_JOBS` is tuned based on previous CPU usage (i.e. bigger builds
  get higher allocations), and WRKOBJDIR routes to disk or tmpfs based on a
  selected threshold and previous successful WRKDIR sizes.

* New `bob history` command to show per-build metrics from a persistent
  historical build database.

* Move `bob sandbox` and `bob status` back to top-level commands as they are
  used so frequently.  New `bob sandbox exec` command for interactive build
  sessions inside a temporary sandbox.

* Many minor improvements, consistent argument support, and output format
  support for all commands.

* New `bob util presolve` command for quick comparisons with `pbulk-resolve`.
  Updating to newer pkgsrc-rs also improves dependency resolution performance,
  bob now being 70x faster than pbulk for a full tree resolution.

* Ctrl-C now supports graceful shutdown on first signal, with in-progress
  builds allowed to finish before exiting.  A second subsequent Ctrl-C will
  proceed to an interrupted shutdown.

* Generate `pkg_summary.zst`, stop generating `FILE_CKSUM` entries (slows down
  generation and is currently unused, can be added back in future if required).

* Significant number of minor tweaks, bug fixes, reliability improvements, and
  performance optimisations.

## Version 0.8.1 (2026-02-06)

* Fix output ordering of `bob list status` to ensure it is identical to build
  order, and improve performance.

## Version 0.8.0 (2026-02-06)

* Now published as `bob` on crates.io, thanks Wyatt!

* Rewrite up-to-date checks in native Rust using features from pkgsrc-rs,
  removing the dependency on `pkg_install` tools, and allowing full package
  status to be calculated (in parallel) up-front.  This provides significant
  performance improvements, and paves the way for the powerful `status` command
  described below.

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

* Overhaul `bob rebuild` to ensure it only acts upon scanned packages and
  improve semantics.  Remove `-f`: if you ask for a package to be rebuilt then
  it is rebuilt.  Add `--only` with a warning that it will leave packages in an
  inconsistent state.

* Support non-terminal plain output mode.

* Provide comprehensive scan and build result variants to cover all cases.

* Add [examples/scan.lua](examples/scan.lua) for scan-only configurations.

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
