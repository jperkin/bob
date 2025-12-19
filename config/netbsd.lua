-- Example configuration file for NetBSD.

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
    make = "/usr/bin/make",
    packages = initdir .. "/packages",
    pkgtools = "/usr/sbin",
    pkgpaths = {
        "mail/mutt",
        "sysutils/coreutils",
    },
    prefix = "/usr/pkg",
    tar = "/bin/tar",

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
    basedir = "/data/chroot",

    actions = {
        -- NetBSD does not have devfs; device nodes are created via MAKEDEV.
        -- The cwd is relative to the sandbox (e.g., /dev means $SANDBOX/dev).
        -- Commands run on the host, so /dev/MAKEDEV refers to the host file.
        { action = "cmd", cwd = "/dev",
          create = "cp /dev/MAKEDEV /dev/MAKEDEV.local . && ./MAKEDEV all",
          destroy = "rm -rf *" },

        { action = "mount", fs = "proc", dest = "/proc" },
        { action = "mount", fs = "tmp", dest = "/tmp", opts = "-s 1024k" },
        { action = "mount", fs = "tmp", dest = "/var/tmp" },

	{ action = "copy", dest = "/etc" },

        -- System directories (read-only for safety)
        { action = "mount", fs = "null", dest = "/bin", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/sbin", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/libexec", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/lib", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/usr/X11R7", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/usr/bin", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/usr/games", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/usr/include", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/usr/lib", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/usr/libdata", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/usr/libexec", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/usr/share", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/usr/sbin", opts = "-o ro" },
        { action = "mount", fs = "null", dest = "/var/mail", opts = "-o ro" },

	{ action = "mount", fs = "null", dest = pkgsrc.basedir, opts = "-o ro" },

        -- Directory where this config and support scripts live.
        { action = "mount", fs = "null", src = initdir },
    },
}
