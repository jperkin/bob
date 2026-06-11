--[[
  Generic configuration file for unsupported systems.

  Does not provide a sandboxes section as they are highly OS-specific.  As such
  this is only really useful for performing pkgsrc scans.  Do not try to use it
  for builds as without sandboxes your installed packages will be removed.

  Full reference for every section, action, and variable:
  https://docs.rs/bob/latest/bob/config/
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

        -- By default, builds that failed previously will be assigned to disk
        -- as we cannot guarantee they will fit tmpfs.  Set failed_threshold
        -- to override this when the failed disk usage is under the threshold.
        -- Recommended to be around 50% of the main threshold.
        failed_threshold = "500M",

        -- Some builds use significantly more disk space during the build than
        -- is left at the end when the WRKDIR usage calculations are recorded.
        -- There is no way to accurately catch this, so always_disk forces the
        -- list of specified pkgpaths to always be assigned to disk.
        always_disk = {
            "sysutils/ansible",
        },
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

--[[
  Configure pkg_summary generation.  These are the default values.  Enable
  include_restricted if you are not going to publish the packages and want
  restricted NO_BIN_ON_* packages to be included in the pkg_summary file.

summary = {
    include_restricted = false,
    file_cksum = false,
    compression = { "gz", "zst" },
}
]]
