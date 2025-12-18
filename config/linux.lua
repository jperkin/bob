-- Example configuration file for Linux (Lua format).

-- Common variables
local pkgsrc_dir = "/data/git/pkgsrc"
local initdir = "@INITDIR@"

-- General configuration variables.
options = {
    build_threads = 4,
    scan_threads = 4,
    verbose = true,
}

-- Variables that configure pkgsrc, where it is, what packages to build, etc.
pkgsrc = {
    basedir = pkgsrc_dir,
    bulklog = initdir .. "/bulklog",
    make = "/usr/pkg/bin/bmake",
    packages = initdir .. "/packages",
    pkgtools = "/usr/pkg/sbin",
    pkgpaths = { "mail/mutt" },
    prefix = "/usr/pkg",
    report_dir = initdir .. "/reports",
    tar = "/bin/tar",
    unprivileged_user = "pbulk",

    -- On build failure, save files matching these glob patterns from WRKDIR.
    save_wrkdir_patterns = {
        "**/config.log",
        "**/CMakeError.log",
        "**/CMakeOutput.log",
        "**/meson-log.txt",
    },

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
    basedir = "/data/chroot/bob",

    actions = {
        { action = "mount", fs = "proc", dest = "/proc" },
        { action = "mount", fs = "dev", dest = "/dev" },
        { action = "mount", fs = "tmp", dest = "/tmp", opts = "size=2G" },
        { action = "mount", fs = "tmp", dest = "/var/tmp", opts = "size=1G" },
        { action = "mount", fs = "bind", src = "/usr/bin", opts = "ro" },
        { action = "mount", fs = "bind", src = "/usr/sbin", opts = "ro" },
        { action = "mount", fs = "bind", src = "/usr/lib", opts = "ro" },
        { action = "mount", fs = "bind", src = "/usr/lib64", opts = "ro" },
        { action = "mount", fs = "bind", src = "/usr/libexec", opts = "ro" },
        { action = "mount", fs = "bind", src = "/usr/include", opts = "ro" },
        { action = "mount", fs = "bind", src = "/usr/share", opts = "ro" },

        { action = "copy", dest = "/etc" },

        { action = "symlink", src = "usr/bin", dest = "/bin" },
        { action = "symlink", src = "usr/lib", dest = "/lib" },
        { action = "symlink", src = "usr/lib64", dest = "/lib64" },
        { action = "symlink", src = "usr/sbin", dest = "/sbin" },

        { action = "mount", fs = "bind", src = pkgsrc_dir, opts = "ro" },

        -- Bob config directory (contains bulklog, packages, distfiles, scripts)
        { action = "mount", fs = "bind", src = initdir },

        -- Unpack bootstrap kit
        { action = "cmd", cwd = "/",
          create = "tar -zxf " .. initdir .. "/bootstrap.tar.gz",
          destroy = "rm -rf usr/pkg" },
    },
}
