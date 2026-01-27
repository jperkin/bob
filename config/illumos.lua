-- Example configuration file for illumos.

-- Common variables
local initdir = "@INITDIR@"

-- General configuration variables.
options = {
    build_threads = 4,
    scan_threads = 4,
    -- Log level: error, warn, info, debug, trace.  Override with RUST_LOG env.
    log_level = "info",
}

-- Environment variables for sandbox processes.  It is recommended to be as
-- strict as possible, as pollution from the user environment can negatively
-- impact builds.
environment = {
    clear = true,
    inherit = { "TERM", "HOME" },
    set = {
        PATH = "/sbin:/usr/bin:/usr/sbin",
    },
}

-- Variables that configure pkgsrc, where it is, what packages to build, etc.
pkgsrc = {
    basedir = "/usr/pkgsrc",
    bootstrap = initdir .. "/bootstrap.tar.gz",
    logdir = initdir .. "/logs",
    make = "/opt/pkg/bin/bmake",
    -- or pkgpaths = read_pkgpaths("/path/to/file"),
    pkgpaths = {
        "mail/mutt",
        "sysutils/coreutils",
    },
    tar = "/usr/bin/tar",

    -- It is strongly recommended to set up an unprivileged user to perform
    -- builds.  If you do, ensure that their home directory is created inside
    -- the sandbox and that work directories are writeable.
    -- build_user = "builder",

    -- List of pkgsrc variables to fetch once and cache.  These are then set in
    -- the environment for scans and builds, avoiding expensive forks.  Only add
    -- variables that are calculated prior to mk.conf being included.
    cachevars = {
        "NATIVE_OPSYS",
        "NATIVE_OPSYS_VERSION",
        "NATIVE_OS_VERSION",
    },

    -- On build failure, save files matching these glob patterns from WRKDIR.
    -- save_wrkdir_patterns = {
    --     "**/CMakeError.log",
    --     "**/CMakeOutput.log",
    --     "**/config.log",
    --     "**/meson-log.txt",
    -- },

    -- Set environment variables for each build.  The pkg object allows you to
    -- perform powerful matching against data from the scan to set variables
    -- on a per-package basis.  Ensure you set variables in mk.conf using ?=
    -- to allow these overrides to take effect.
    env = function(pkg)
        local env = {}
        -- As an example, let's say your default WRKOBJDIR is tmpfs.  This will
        -- override that to use a disk-backed location for any package written
        -- in Go, as they often have much larger space requirements.
        -- if pkg.scan_depends:match("/lang/go/") then
        --     env.WRKOBJDIR = "/home/builder/build-disk"
        -- end
        return env
    end,
}

-- These scripts are executed during sandbox creation and destruction, as well
-- as before and after every single package build.
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
        -- /devices is optional depending on if this is a global zone or not
        { action = "mount", fs = "lofs", dir = "/devices", opts = "-o ro", ifexists = true },
        { action = "mount", fs = "lofs", dir = "/dev", opts = "-o ro" },
        { action = "mount", fs = "fd", dir = "/dev/fd" },
        { action = "mount", fs = "proc", dir = "/proc" },

        { action = "mount", fs = "tmp", dir = "/tmp", opts = "-o size=1g" },
        { action = "mount", fs = "tmp", dir = "/var/tmp", opts = "-o size=1g"  },

        { action = "mount", fs = "lofs", dir = "/lib", opts = "-o ro" },
        { action = "mount", fs = "lofs", dir = "/sbin", opts = "-o ro" },
        { action = "mount", fs = "lofs", dir = "/usr", opts = "-o ro" },
        { action = "symlink", src = "usr/bin", dest = "/bin" },

        { action = "copy", dir = "/etc" },

        -- At this point everything should be set up so that chrooted commands
        -- will execute successfully.  Perform additional chroot setup.
        { action = "cmd", chroot = true, create = "chmod 1777 /tmp /var/tmp" },

        -- It is recommended to mount pkgsrc read-only, but you will first need
        -- to configure DISTDIR, PACKAGES, and WRKOBJDIR to other directories.
        { action = "mount", fs = "lofs", dir = pkgsrc.basedir },

        -- Directory where this config and support scripts live.
        { action = "mount", fs = "lofs", dir = initdir },
    },
}
