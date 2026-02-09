-- Generic configuration file for unsupported systems.
-- Does not provide a sandboxes section as it is highly OS-specific.

-- Common variables
local initdir = "@INITDIR@"

-- General configuration variables.
options = {
    build_threads = 4,
    scan_threads = 4,
    -- Log level: error, warn, info, debug, trace.  Override with RUST_LOG env.
    log_level = "info",
}

-- Variables that configure pkgsrc, where it is, what packages to build, etc.
pkgsrc = {
    basedir = "/usr/pkgsrc",
    bootstrap = initdir .. "/bootstrap.tar.gz",
    make = "/usr/pkg/bin/bmake",
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
