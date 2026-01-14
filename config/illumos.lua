-- Example configuration file for illumos.

-- Configuration format version (required).
config_version = 1

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
    logdir = initdir .. "/logs",
    make = "/opt/pkg/bin/bmake",
    pkgpaths = {
        "mail/mutt",
        "sysutils/coreutils",
    },
    tar = "/usr/bin/tar",

    -- It is strongly recommended to set up an unprivileged user to perform
    -- builds. If you do, ensure that their home directory is created inside
    -- the sandbox and that work directories are writeable.
    -- build_user = "builder",

    -- Set environment variables for scan processes. This is deliberately
    -- separate from env as only a few specific variables are useful here.
    -- Only add pre-computed variables to avoid forking and speed up scans.
    scanenv = {
        NATIVE_OPSYS = "SunOS",
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
    basedir = "/chroot",

    actions = {
        -- /devices is optional depending on if this is a global zone or not
        { action = "mount", fs = "lofs", dir = "/devices", opts = "-o ro", ifexists = true },
        { action = "mount", fs = "lofs", dir = "/dev", opts = "-o ro" },
        { action = "mount", fs = "fd", dir = "/dev/fd" },
        { action = "mount", fs = "proc", dir = "/proc" },

        { action = "mount", fs = "tmp", dir = "/tmp", opts = "-o size=1g" },
        { action = "mount", fs = "tmp", dir = "/var/tmp", opts = "-o size=1g"  },
        { action = "cmd", create = "chmod 1777 tmp var/tmp" },

        { action = "mount", fs = "lofs", dir = "/lib", opts = "-o ro" },
        { action = "mount", fs = "lofs", dir = "/sbin", opts = "-o ro" },
        { action = "mount", fs = "lofs", dir = "/usr", opts = "-o ro" },
        { action = "symlink", src = "usr/bin", dest = "/bin" },

        { action = "copy", dir = "/etc" },

        -- It is recommended to mount pkgsrc read-only, but you will first need
        -- to configure DISTDIR, PACKAGES, and WRKOBJDIR to other directories.
        { action = "mount", fs = "lofs", dir = pkgsrc.basedir },

        -- Directory where this config and support scripts live.
        { action = "mount", fs = "lofs", dir = initdir },
    },
}
