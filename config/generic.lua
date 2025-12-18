-- Generic configuration file for unsupported systems.
-- Does not provide a sandboxes section as it is highly OS-specific.

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
    make = "/usr/pkg/bin/bmake",
    packages = initdir .. "/packages",
    pkgtools = "/usr/pkg/sbin",
    pkgpaths = {
        "mail/mutt",
        "sysutils/coreutils",
    },
    prefix = "/usr/pkg",
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
