# Changelog

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
