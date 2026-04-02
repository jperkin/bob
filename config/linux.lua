--[[
  Example configuration file for Linux.

  This is designed to work out of the box (you will need to supply a working
  bootstrap kit), but you will almost certainly want to customise it for
  optimum performance.
]]

-- General configuration variables.
options = {
    build_threads = 4,
    scan_threads = 4,
    -- Log level: error, warn, info, debug, trace.  Override with RUST_LOG env.
    log_level = "info",
}

--[[
  Dynamic resource allocation settings.  Uses statistics from the history db,
  knowledge of upcoming builds, and package weight to make informed choices for
  what MAKE_JOBS and WRKOBJDIR should be set to for each package build.

  If you set MAKE_JOBS or WRKOBJDIR in mk.conf then you must use ?= so that
  bob's environment settings take precedence.

  On first builds with no history, conservative values are used.

dynamic = {
    jobs = 16,
    wrkobjdir = {
        tmpfs = "/tmp/work",
        disk = "/home/builder/work",
        threshold = "1G",
    },
}
]]

-- Variables that configure pkgsrc, where it is, what packages to build, etc.
pkgsrc = {
    basedir = "/usr/pkgsrc",
    -- bootstrap = "/path/to/bootstrap.tar.gz",
    make = "/usr/pkg/bin/bmake",
    -- or pkgpaths = read_pkgpaths("/path/to/file"),
    pkgpaths = {
        "mail/mutt",
        "sysutils/coreutils",
    },

    --[[
      It is strongly recommended to set up an unprivileged user to perform
      builds.  If this is enabled, there is an action below to automatically
      create the user home directory.  If build_user_home is not set it is
      retrieved via getpwnam(3).

    build_user = "builder",
    build_user_home = "/home/builder",
    ]]

    -- List of pkgsrc variables to fetch once and cache.  These are then set in
    -- the environment for scans and builds, avoiding expensive forks.  Only add
    -- variables that are calculated prior to mk.conf being included.
    cachevars = {
        "NATIVE_OPSYS",
        "NATIVE_OPSYS_VERSION",
        "NATIVE_OS_VERSION",
    },

    --[[
      On build failure, save files matching these glob patterns from WRKDIR.

    save_wrkdir_patterns = {
        "**/CMakeError.log",
        "**/CMakeOutput.log",
        "**/config.log",
        "**/meson-log.txt",
    },
    ]]
}

-- The sandboxes section defines where, and how, sandboxes will be created.
sandboxes = {
    basedir = "/data/chroot",

    --[[
      Environment variable configuration for sandboxed processes.  It is
      recommended to be as strict as possible, as pollution from the user
      environment can negatively impact builds.
    ]]
    environment = {
        clear = true,
        inherit = { "TERM", "HOME" },
        set = {
            PATH = "/sbin:/bin:/usr/sbin:/usr/bin",
        },
    },

    --[[
      List of actions to apply for each sandbox.  During creation these actions
      are performed in order, and during destruction they are performed in
      reverse order.
    ]]
    setup = {
        { action = "mount", fs = "dev", dir = "/dev" },
        { action = "mount", fs = "proc", dir = "/proc" },

        { action = "mount", fs = "tmp", dir = "/tmp", opts = "size=1G" },
        { action = "mount", fs = "tmp", dir = "/var", opts = "size=1G" },

        { action = "mount", fs = "bind", dir = "/usr/bin", opts = "ro" },
        { action = "mount", fs = "bind", dir = "/usr/sbin", opts = "ro" },
        { action = "mount", fs = "bind", dir = "/usr/lib", opts = "ro" },
        { action = "mount", fs = "bind", dir = "/usr/lib64", opts = "ro" },
        { action = "mount", fs = "bind", dir = "/usr/libexec", opts = "ro" },
        { action = "mount", fs = "bind", dir = "/usr/include", opts = "ro" },
        { action = "mount", fs = "bind", dir = "/usr/share", opts = "ro" },

        { action = "symlink", src = "usr/bin", dest = "/bin" },
        { action = "symlink", src = "usr/lib", dest = "/lib" },
        { action = "symlink", src = "usr/lib64", dest = "/lib64" },
        { action = "symlink", src = "usr/sbin", dest = "/sbin" },

        { action = "copy", dir = "/etc" },

        -- At this point everything should be set up so that chrooted commands
        -- will execute successfully.  Perform additional chroot setup.
        { action = "cmd", chroot = true,
          create = "mkdir -m 1777 /var/tmp; chmod 1777 /tmp" },

        -- Configure build user home directory if enabled.  Bob automatically
        -- sets bob_build_user* variables when the build user is configured,
        -- and the scripts are executed with 'set -eu', so these should be safe.
        { action = "cmd", ifset = "pkgsrc.build_user",
          create = [[
                mkdir -p ${bob_sandbox_path}${bob_build_user_home}
                chown ${bob_build_user} ${bob_sandbox_path}${bob_build_user_home}
          ]],
          destroy = "rm -rf ${bob_sandbox_path}${bob_build_user_home}" },

        -- It is recommended to mount pkgsrc read-only, but you will first need
        -- to configure DISTDIR, PACKAGES, and WRKOBJDIR to other directories.
        { action = "mount", fs = "bind", dir = pkgsrc.basedir },
    },

    --[[
      Custom actions to run before and after each individual build.  Any create
      action will run after the internal pre-build script (unpacks bootstrap kit
      if needed), and any destroy action runs before the internal post-build
      script (wipes PREFIX and PKG_DBDIR).

    build = {
        -- As an example, ensure clean passwd file and /tmp for each build.
        { action = "cmd",
          create = "cp /etc/passwd ${bob_sandbox_path}/etc/passwd",
          destroy = "rm -rf ${bob_sandbox_path}/tmp/*",
        },
    },
    ]]
}
