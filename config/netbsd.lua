-- Example configuration file for NetBSD.

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
        PATH = "/sbin:/bin:/usr/sbin:/usr/bin",
    },
}

-- Variables that configure pkgsrc, where it is, what packages to build, etc.
pkgsrc = {
    basedir = "/usr/pkgsrc",
    make = "/usr/bin/make",
    -- or pkgpaths = read_pkgpaths("/path/to/file"),
    pkgpaths = {
        "mail/mutt",
        "sysutils/coreutils",
    },

    -- It is strongly recommended to set up an unprivileged user to perform
    -- builds.  If this is enabled, there is an action below to automatically
    -- create the user home directory.
    -- build_user = "builder",

    -- List of pkgsrc variables to fetch once and cache.  These are then set in
    -- the environment for scans and builds, avoiding expensive forks.  Only add
    -- variables that are calculated prior to mk.conf being included.
    cachevars = {
        "HOST_MACHINE_ARCH",
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
        -- Configure NetBSD device nodes.  Note that it is too early to be able
        -- to execute commands inside chroot context, so this is done carefully
        -- outside the chroot.
        { action = "cmd",
          create = "mkdir dev && cp /dev/MAKEDEV /dev/MAKEDEV.local dev/"
                .. " && cd dev && ./MAKEDEV all",
          destroy = "rm -rf dev" },

        { action = "mount", fs = "proc", dir = "/proc" },

        { action = "mount", fs = "tmp", dir = "/tmp", opts = "-s 1G" },
        { action = "mount", fs = "tmp", dir = "/var/tmp", opts = "-s 1G" },

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

        { action = "copy", dir = "/etc" },

        -- At this point everything should be set up so that chrooted commands
        -- will execute successfully.  Perform additional chroot setup.
        { action = "cmd", chroot = true, create = "chmod 1777 /tmp /var/tmp" },

        -- Configure build user home directory if enabled.
        { action = "cmd", chroot = true, ifset = "pkgsrc.build_user", create = [[
                user="{pkgsrc.build_user}"
                homedir=$(su ${user} -c 'echo ${HOME}')
                mkdir -p ${homedir}
                chown ${user} ${homedir}
        ]] },

        -- It is recommended to mount pkgsrc read-only, but you will first need
        -- to configure DISTDIR, PACKAGES, and WRKOBJDIR to other directories.
        { action = "mount", fs = "null", dir = pkgsrc.basedir },

        -- Directory where this config and support scripts live.
        { action = "mount", fs = "null", dir = initdir },
    },
}
