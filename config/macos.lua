-- Example configuration file for macOS.

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
    basedir = "/Volumes/data/pkgsrc",
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
        --     env.WRKOBJDIR = "/Users/builder/build-disk"
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
    basedir = "/Volumes/data/chroot",
    -- If bindfs is not in PATH you can set it here.
    -- bindfs = "/usr/local/bin/bindfs",

    actions = {
        { action = "mount", fs = "dev", dir = "/dev" },
        { action = "mount", fs = "tmp", dir = "/tmp", opts = "-e -s 384m" },
        { action = "mount", fs = "tmp", dir = "/var", opts = "-e -s 512m" },
        { action = "cmd", create = "mkdir var/tmp" },

        -- Read-only system mounts.
        { action = "mount", fs = "bind", dir = "/Library", opts = "-r" },
        { action = "mount", fs = "bind", dir = "/System", opts = "-r" },
        { action = "mount", fs = "bind", dir = "/bin", opts = "-r" },
        { action = "mount", fs = "bind", src = "/private/etc", dest = "/etc", opts = "-r" },
        { action = "mount", fs = "bind", dir = "/sbin", opts = "-r" },
        { action = "mount", fs = "bind", dir = "/usr", opts = "-r" },

        -- Postfix spool needs to be read-write
        { action = "mount", fs = "bind", dir = "/private/var/spool/postfix" },

        -- Enable DNS resolution via mDNSResponder socket per-sandbox
        { action = "cmd", create = initdir .. "/scripts/mdns-listener create",
                         destroy = initdir .. "/scripts/mdns-listener destroy" },

        -- At this point everything should be set up so that chrooted commands
        -- will execute successfully.  Perform additional chroot setup.
        { action = "cmd", chroot = true, create = [[
                chmod 1777 /tmp /var/tmp
                mkdir -p $(getconf DARWIN_USER_TEMP_DIR)
                # If you enable a builder user then uncomment these
                #homedir=$(su builder -c 'echo $HOME')
                #tempdir=$(su builder -c 'getconf DARWIN_USER_TEMP_DIR')
                #mkdir -p ${homedir}/build $tempdir
                #chown -R builder $homedir $tempdir
		]] },

        -- It is recommended to mount pkgsrc read-only, but you will first need
        -- to configure DISTDIR, PACKAGES, and WRKOBJDIR to other directories.
        { action = "mount", fs = "bind", dir = pkgsrc.basedir },

        -- Directory where this config and support scripts live.
        { action = "mount", fs = "bind", dir = initdir },
    },
}
