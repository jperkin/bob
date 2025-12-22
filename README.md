# Bob - A Package Builder

[![Crates.io](https://img.shields.io/crates/v/pkgbob.svg)](https://crates.io/crates/pkgbob)
[![Documentation](https://docs.rs/pkgbob/badge.svg)](https://docs.rs/pkgbob)
[![License](https://img.shields.io/crates/l/pkgbob.svg)](https://github.com/jperkin/bob)

Bob's goal is to become a simple but powerful, complete, and user-friendly
utility for building pkgsrc packages.

## Status

- [x] Basic app, config files, etc.
- [x] Sandboxes implemented for illumos, macOS, NetBSD, and Linux.
- [x] Threaded scan and build processes inside sandboxes.
- [x] Scan resolution / DAG.
- [x] Ratatui-based terminal interface showing current progress.
- [x] Basic HTML reports.

Bob should work pretty much out-of-the-box on NetBSD, Linux, and illumos.

Bob works on macOS, but due to Apple, there is a lot of additional sandbox work
to do before things work correctly (e.g. name resolution inside chroot).  This
will be implemented in due course.

## Getting Started

Install bob.

```
$ cargo install pkgbob
```

Generate directory containing the configuration file and build scripts.  This
is also where by default all data will be generated.

```
$ bob init /bob
```

Customise the config.  The defaults are designed to work mostly out of the
box, but you are likely to want to change some things, for example which
packages to build.

```
$ cd /bob
$ vi config.lua
```

On non-NetBSD systems you will also need a pkgsrc bootstrap kit.  By default
bob will look for `bootstrap.tar.gz` inside the init directory.

When you are happy with the configuration:

```
$ bob build
```

Bob will proceed to:

* Create a single sandbox under `sandboxes.basedir`.
* Launch `options.scan_threads` number of scan processes inside the sandbox,
  scanning the package directories defined in `pkgsrc.pkgpaths`, recursively
  discovering dependencies until a full dependency tree has been calculated.
* Resolve the scan (ensure that all scanned packages are discoverable).
* Destroy the scan sandbox, and create `options.build_threads` number of build
  sandboxes.
* Launch a build process in sandbox, building packages bottom-up until all have
  been processed.
* Destroy the build sandboxes and generate a summary and HTML report.

During the build phase you can press 'v' to toggle between the default inline
progress bars and a full-screen paned layout that shows live build logs to
track progress.

## Design Goals

There are two main methods currently used to update a pkgsrc installation.

Update-in-place using tools such as `pkg_chk` or `pkg_rolling-replace`.
These tools operate directly on the target host, upgrading packages in
turn.  These are the simplest to set up and use, and so are reasonable
popular amongst users, but have some major drawbacks:

 * Upgrading in place means that if a build error is encountered, the
   system may be left in a degraded state until the issue is fixed.

 * Building directly on the system may end up finding tools and libraries on
   the host system that wouldn't be found otherwise, which may mask issues that
   would be exposed when building in a clean environment.

 * Only one build can happen at a time, and dependency issues aren't discovered
   until build time.

Bulk builds using `pbulk` allow packages to be built inside clean sandboxes,
and with the appropriate patches mean that builds can be performed in parallel.
These solve a number of the problems with update-in-place builds, but do have
their own drawbacks:

 * Historically pbulk has been notoriously difficult to set up and configure,
   and any runtime problems can be very hard to diagnose.

 * A separate pkgsrc prefix (e.g. `/usr/pbulk`) is required to hold pbulk and
   associated tools.

 * Support for concurrent builds and sandbox configuration is left to external
   patches and the user to configure manually, and it can be very easy to
   accidentally trash your system.

Bob aims to combine these methods into a best-of-both approach:

 * Automatically set up build sandboxes, hiding away all of the complexity
   involved trying to support multiple operating systems.

 * Perform a pbulk-style scan of the requested packages to ensure all of the
   dependencies are correct.

 * Build packages inside sandboxes, using a directed acyclic graph to perform
   builds in the correct order, and take advantage of parallel builds where
   possible.

 * Provide a very flexible configuration interface for local customisation.

all with a user-friendly and easy to configure interface.
