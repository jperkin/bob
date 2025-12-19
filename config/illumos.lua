-- Example configuration file for illumos.

-- Common variables
local initdir = "@INITDIR@"

-- General configuration variables.
options = {
    build_threads = 4,
    scan_threads = 4,
    verbose = true,
}

-- Variables that configure pkgsrc, where it is, what packages to build, etc.
pkgsrc = {
    basedir = "/usr/pkgsrc",
    bootstrap = initdir .. "/bootstrap.tar.gz",
    bulklog = initdir .. "/bulklog",
    make = "/opt/pkg/bin/bmake",
    packages = initdir .. "/packages",
    pkgtools = "/opt/pkg/sbin",
    pkgpaths = {
        "mail/mutt",
        "sysutils/coreutils",
    },
    prefix = "/opt/pkg",
    tar = "/usr/bin/tar",

    -- It is strongly recommended to set up an unprivileged user to perform
    -- builds. If you do, ensure that their home directory is created inside
    -- the sandbox and that work directories are writeable.
    -- build_user = "builder",

    -- Set environment variables for each build. The pkg object allows you to
    -- perform powerful matching against data from the scan to set variables
    -- on a per-package basis.
    env = function(pkg)
        local env = {}
        env.DISTDIR = initdir .. "/distfiles"
        env.WRKOBJDIR = "/tmp/bob-work"

        -- Set MAKE_JOBS higher for lang/rust builds
        -- if pkg.pkgpath == "lang/rust" then
        --     env.MAKE_JOBS = "8"
        -- end

        -- Use disk-based WRKOBJDIR for packages that depend on Go
        -- if pkg.scan_depends:match("/lang/go/") then
        --     env.WRKOBJDIR = "/home/builder/build-disk"
        -- end

        return env
    end,
}

scripts = {
    ["pre-build"] = initdir .. "/scripts/pre-build",
    ["pkg-build"] = initdir .. "/scripts/pkg-build",
    ["post-build"] = initdir .. "/scripts/post-build",
    ["pkg-up-to-date"] = initdir .. "/scripts/pkg-up-to-date",
}

-- The sandboxes section defines where sandboxes should be created, and how file
-- systems and ancilliary data should be created.
--
-- The number of sandboxes that will be created is build_threads if set,
-- otherwise 1.
--
-- During creation the actions list is processed in order, and when destroying
-- sandboxes it is processed in reverse order.
sandboxes = {
    basedir = "/chroot",

    actions = {
        { action = "mount", fs = "lofs", dir = "/devices", opts = "-o ro" },
        { action = "mount", fs = "lofs", dir = "/dev", opts = "-o ro" },
        { action = "mount", fs = "fd", dir = "/dev/fd" },
        { action = "mount", fs = "proc", dir = "/proc" },
        { action = "mount", fs = "tmp", dir = "/tmp", opts = "-o size=1g" },
        { action = "mount", fs = "tmp", dir = "/var/tmp", opts = "-o size=1g"  },

        -- System directories (read-only for safety)
        { action = "mount", fs = "lofs", dir = "/lib", opts = "-o ro" },
        { action = "mount", fs = "lofs", dir = "/sbin", opts = "-o ro" },
        { action = "mount", fs = "lofs", dir = "/usr", opts = "-o ro" },
        { action = "mount", fs = "lofs", src = "/usr/bin", dest = "/bin", opts = "-o ro" },

        -- Directory where this config and support scripts live.
        { action = "mount", fs = "lofs", dir = initdir },
    },
}
