# Bob - A Package Builder

Bob's goal is to become a simple but powerful, complete, and user-friendly
utility for building pkgsrc packages.

## Status

- [x] Basic app, config files, etc.
- [x] Sandboxes implemented for illumos, macOS, NetBSD.
- [x] Threaded scan processes (missing some variables).
- [x] Scan resolution / DAG (about 80% complete).
- [ ] Build processes in sandboxes.
- [ ] Nice full-screen UI / reports / etc.

Presently you can use `bob` to create sandboxes and perform a multi-threaded
scan of specified `PKGPATH`s (with a nice progress bar), and it will determine
the correct order to build the packages in, but does not yet actually build
them.

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

 * Support for concurrent builds and sandbox configuration is left to external
   patches and the user to configure manually.

 * A separate tool such as `pkgin` needs to be used to upgrade the system using
   the resulting packages.

Bob aims to combine these methods into a best-of-both approach:

 * Automatically set up build sandboxes, hiding away all of the complexity
   involved trying to support multiple operating systems.

 * Perform a pbulk-style scan of the requested packages to ensure all of the
   dependencies are correct.

 * Build packages inside sandboxes, using a directed acyclic graph to perform
   builds in the correct order, and take advantage of parallel builds where
   possible.

all with a user-friendly and easy to configure interface.
