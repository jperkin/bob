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
    unprivileged_user = "pbulk",

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
        --     env.WRKOBJDIR = "/home/pbulk/build-disk"
        -- end

        return env
    end,
}

scripts = {
    ["pkg-build"] = initdir .. "/scripts/pkg-build",
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
        { action = "mount", fs = "lofs", dest = "/devices", opts = "-o ro" },
        { action = "mount", fs = "lofs", dest = "/dev", opts = "-o ro" },
        { action = "mount", fs = "fd", dest = "/dev/fd" },
        { action = "mount", fs = "proc", dest = "/proc" },
        { action = "mount", fs = "tmp", dest = "/tmp", opts = "-o size=1024k" },
        { action = "mount", fs = "tmp", dest = "/var/tmp" },

        -- System directories (read-only for safety)
        { action = "mount", fs = "lofs", dest = "/lib", opts = "-o ro" },
        { action = "mount", fs = "lofs", dest = "/sbin", opts = "-o ro" },
        { action = "mount", fs = "lofs", dest = "/usr", opts = "-o ro" },
        { action = "mount", fs = "lofs", dest = "/bin", src = "/usr/bin", opts = "-o ro" },

        -- Directory where this config and support scripts live.
        { action = "mount", fs = "lofs", src = initdir },
    },
}
