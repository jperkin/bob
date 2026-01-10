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
    logdir = initdir .. "/logs",
    make = "/usr/bin/make",
    pkgpaths = {
        "mail/mutt",
        "sysutils/coreutils",
    },

    -- It is strongly recommended to set up an unprivileged user to perform
    -- builds. If you do, ensure that their home directory is created inside
    -- the sandbox and that work directories are writeable.
    -- build_user = "builder",

    -- Set environment variables for scan processes. This is deliberately
    -- separate from env as only a few specific variables are useful here.
    -- Only add pre-computed variables to avoid forking and speed up scans.
    scanenv = {
        NATIVE_OPSYS = "NetBSD",
        -- NATIVE_OPSYS_VERSION = "<insert correct value>",
        -- NATIVE_OS_VERSION = "<insert correct value>",
    },

    -- Set environment variables for each build. The pkg object allows you to
    -- perform powerful matching against data from the scan to set variables
    -- on a per-package basis.
    env = function(pkg)
        local env = {}
        env.MAKE_JOBS = 2

        -- Set MAKE_JOBS higher for lang/rust builds
        -- if pkg.pkgpath == "lang/rust" then
        --     env.MAKE_JOBS = "8"
        -- end

        return env
    end,
}

scripts = {
    ["pre-build"] = initdir .. "/scripts/pre-build",
    ["post-build"] = initdir .. "/scripts/post-build",
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

        { action = "mount", fs = "proc", dir = "/proc" },
        { action = "mount", fs = "tmp", dir = "/tmp" },
        { action = "mount", fs = "tmp", dir = "/var/tmp" },
        { action = "cmd", create = "chmod 1777 tmp var/tmp" },

        { action = "copy", dir = "/etc" },

        -- System directories (read-only for safety)
        { action = "mount", fs = "null", dir = "/bin", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/sbin", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/libexec", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/lib", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/usr/X11R7", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/usr/bin", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/usr/games", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/usr/include", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/usr/lib", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/usr/libdata", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/usr/libexec", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/usr/share", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/usr/sbin", opts = "-o ro" },
        { action = "mount", fs = "null", dir = "/var/mail", opts = "-o ro" },

        -- It is recommended to mount pkgsrc read-only, but you will first need
        -- to configure DISTDIR, PACKAGES, and WRKOBJDIR to other directories.
        { action = "mount", fs = "null", dir = pkgsrc.basedir },

        -- Directory where this config and support scripts live.
        { action = "mount", fs = "null", dir = initdir },
    },
}
