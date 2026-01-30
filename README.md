# Bob - A Package Builder

[![Crates.io](https://img.shields.io/crates/v/pkgbob.svg)](https://crates.io/crates/pkgbob)
[![Documentation](https://docs.rs/pkgbob/badge.svg)](https://docs.rs/pkgbob)
[![License](https://img.shields.io/crates/l/pkgbob.svg)](https://github.com/jperkin/bob)

Bob is a powerful and user-friendly utility for building pkgsrc packages inside
sandboxes.

## Screencasts

- Example build session

  [![Example build session](https://jperkin.github.io/bob/assets/build.gif)](https://asciinema.org/a/763171)

- Live build log viewer

  [![Live build log viewer](https://jperkin.github.io/bob/assets/panes.gif)](https://asciinema.org/a/763316)

## Features

- [x] Powerful and fast, but easy to use.
- [x] Native sandbox implementation for common operating systems.
- [x] Threaded scan and build processes inside concurrent sandboxes.
- [x] [Ratatui](https://ratatui.rs)-based user interface.
- [x] Simple, flexible, and powerful Lua-based configuration.
- [x] Easily support multiple build configurations.

Bob works out-of-the-box on NetBSD, Linux, macOS[^1], and illumos.

[^1] Requires MacFUSE and bindfs due to macOS limitations.

## Getting Started

Install bob, or upgrade an existing install to the latest release.

```
$ cargo install pkgbob
```

Create configuration directory.  This is also where by default all log data
will be generated.  `/data/bob` here is used as an example, but this can be any
location.

You may wish to build multiple package sets (e.g. `netbsd-x86_64` and
`netbsd-i386`) in which case you can simply create a configuration directory
for each set.

```
$ bob init /data/bob
Initialising new configuration directory /data/bob:
        /data/bob/config.lua
        /data/bob/scripts/post-build
        /data/bob/scripts/pre-build
```

Customise the config.  The defaults are designed to work out of the box, but
you are likely to want to change some things, for example which packages to
build, enable an unprivileged build user, or add any additional mount points
required.

```
$ cd /data/bob
$ vi config.lua
```

On non-NetBSD systems you will also need a pkgsrc bootstrap kit.  By default
bob will look for `bootstrap.tar.gz` inside the init directory.

When you are happy with the configuration:

```
$ bob build
```

will proceed to build all of the packages you have requested.  At the end of a
successful build run bob will automatically create a `pkg_summary.gz` file, so
if you have configured [pkgin](https://github.com/NetBSDfr/pkgin) to look
there, a full upgrade to the latest pkgsrc packages is as simple as:

```
$ bob build && pkgin upgrade
```

During the build phase you can press 'v' to toggle between the default inline
progress bars and a full-screen paned layout that shows live build logs to
track progress.

Bob should handle interruptions gracefully, and automatically clean up
sandboxes, etc.  If the build is interrupted, you can resume with `bob build,
and bob should continue from where it left off.

After a build has completed, and some time later you wish to update pkgsrc to
build updated packages, you will first need to run:

```
$ bob clean
```

to clear the previous database state, before running a new `bob build`.

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

Bob combines these methods into a best-of-both approach:

 * Automatically set up build sandboxes, hiding away all of the complexity
   involved trying to support multiple operating systems.

 * Perform a pbulk-style scan of the requested packages to ensure all of the
   dependencies are correct.

 * Build packages inside sandboxes, using a directed acyclic graph to perform
   builds in the correct order, and take advantage of parallel builds where
   possible.

 * Provide a very flexible configuration interface for local customisation.

all with a user-friendly and easy to configure interface.
