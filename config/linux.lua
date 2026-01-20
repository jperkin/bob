-- Example configuration file for Linux (Lua format).

-- Common variables
local initdir = "@INITDIR@"

-- General configuration variables.
options = {
    build_threads = 4,
    scan_threads = 4,
    -- Log level: error, warn, info, debug, trace. Override with RUST_LOG env.
    log_level = "info",
}

-- Variables that configure pkgsrc, where it is, what packages to build, etc.
pkgsrc = {
    basedir = "/data/pkgsrc",
    bootstrap = initdir .. "/bootstrap.tar.gz",
    logdir = initdir .. "/logs",
    make = "/usr/pkg/bin/bmake",
    pkgpaths = { "mail/mutt" },
    tar = "/bin/tar",

    -- It is strongly recommended to set up an unprivileged user to perform
    -- builds. If you do, ensure that their home directory is created inside
    -- the sandbox and that work directories are writeable.
    -- build_user = "builder",

    -- On build failure, save files matching these glob patterns from WRKDIR.
    save_wrkdir_patterns = {
        "**/config.log",
        "**/CMakeError.log",
        "**/CMakeOutput.log",
        "**/meson-log.txt",
    },

    -- List of pkgsrc variables to fetch once and cache. These are then set in
    -- the environment for scans and builds, avoiding expensive forks. Only add
    -- variables that are calculated prior to mk.conf being included.
    cachevars = {
        "NATIVE_OPSYS",
        "NATIVE_OPSYS_VERSION",
        "NATIVE_OS_VERSION",
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
        { action = "mount", fs = "proc", dir = "/proc" },
        { action = "mount", fs = "dev", dir = "/dev" },

        { action = "mount", fs = "tmp", dir = "/tmp", opts = "size=1G" },
        { action = "mount", fs = "tmp", dir = "/var/tmp", opts = "size=1G" },

        { action = "mount", fs = "bind", dir = "/usr/bin", opts = "ro" },
        { action = "mount", fs = "bind", dir = "/usr/sbin", opts = "ro" },
        { action = "mount", fs = "bind", dir = "/usr/lib", opts = "ro" },
        { action = "mount", fs = "bind", dir = "/usr/lib64", opts = "ro" },
        { action = "mount", fs = "bind", dir = "/usr/libexec", opts = "ro" },
        { action = "mount", fs = "bind", dir = "/usr/include", opts = "ro" },
        { action = "mount", fs = "bind", dir = "/usr/share", opts = "ro" },

        { action = "copy", dir = "/etc" },

        { action = "symlink", src = "usr/bin", dest = "/bin" },
        { action = "symlink", src = "usr/lib", dest = "/lib" },
        { action = "symlink", src = "usr/lib64", dest = "/lib64" },
        { action = "symlink", src = "usr/sbin", dest = "/sbin" },

        -- At this point everything should be set up so that chrooted commands
        -- will execute successfully.  Perform additional chroot setup.
        { action = "cmd", chroot = true, create = "chmod 1777 /tmp /var/tmp" },

        -- It is recommended to mount pkgsrc read-only, but you will first need
        -- to configure DISTDIR, PACKAGES, and WRKOBJDIR to other directories.
        { action = "mount", fs = "bind", dir = pkgsrc.basedir },

        -- Directory where this config and support scripts live.
        { action = "mount", fs = "bind", dir = initdir },
    },
}
