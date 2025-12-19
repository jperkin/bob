-- Example configuration file for macOS.

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
        env.MAKE_JOBS = 2
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
    basedir = "/Volumes/data/chroot",

    actions = {
        { action = "mount", fs = "dev", dir = "/dev" },
        { action = "mount", fs = "tmp", dir = "/tmp", opts = "-e -s 384m" },
        { action = "mount", fs = "tmp", dir = "/var", opts = "-e -s 512m" },
        { action = "cmd", create = "chmod 1777 tmp var/tmp" },

        -- Read-only system mounts.
        { action = "mount", fs = "bind", dir = "/Library", opts = "-r" },
        { action = "mount", fs = "bind", dir = "/System", opts = "-r" },
        { action = "mount", fs = "bind", dir = "/bin", opts = "-r" },
        { action = "mount", fs = "bind", src = "/private/etc", dest = "/etc", opts = "-r" },
        { action = "mount", fs = "bind", dir = "/sbin", opts = "-r" },
        { action = "mount", fs = "bind", dir = "/usr", opts = "-r" },

        -- Postfix spool needs to be read-write
        { action = "mount", fs = "bind", dir = "/private/var/spool/postfix" },

        -- Directory where this config and support scripts live.
        { action = "mount", fs = "bind", dir = initdir },
    },
}
