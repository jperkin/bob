# Changelog

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
