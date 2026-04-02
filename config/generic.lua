--[[
  Generic configuration file for unsupported systems.

  Does not provide a sandboxes section as they are highly OS-specific.  As such
  this is only really useful for performing pkgsrc scans.  Do not try to use it
  for builds as without sandboxes your installed packages will be removed.
]]

-- General configuration variables.
options = {
    build_threads = 4,
    scan_threads = 4,
    -- Log level: error, warn, info, debug, trace.  Override with RUST_LOG env.
    log_level = "info",
}

--[[
  Dynamic resource allocation settings.  Uses statistics from the history db,
  knowledge of upcoming builds, and package weight to make informed choices for
  what MAKE_JOBS and WRKOBJDIR should be set to for each package build.

  If you set MAKE_JOBS or WRKOBJDIR in mk.conf then you must use ?= so that
  bob's environment settings take precedence.

  On first builds with no history, conservative values are used.

dynamic = {
    jobs = 16,
    wrkobjdir = {
        tmpfs = "/tmp/work",
        disk = "/home/builder/work",
        threshold = "1G",
    },
}
]]

-- Variables that configure pkgsrc, where it is, what packages to build, etc.
pkgsrc = {
    basedir = "/usr/pkgsrc",
    -- bootstrap = "/path/to/bootstrap.tar.gz",
    make = "/usr/pkg/bin/bmake",
    -- or pkgpaths = read_pkgpaths("/path/to/file"),
    pkgpaths = {
        "mail/mutt",
        "sysutils/coreutils",
    },

    --[[
      It is strongly recommended to set up an unprivileged user to perform
      builds.  If this is enabled, there is an action below to automatically
      create the user home directory.  If build_user_home is not set it is
      retrieved via getpwnam(3).

    build_user = "builder",
    build_user_home = "/home/builder",
    ]]

    --[[
      On build failure, save files matching these glob patterns from WRKDIR.

    save_wrkdir_patterns = {
        "**/CMakeError.log",
        "**/CMakeOutput.log",
        "**/config.log",
        "**/meson-log.txt",
    },
    ]]
}
