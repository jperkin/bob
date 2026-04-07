--[[
  Example configuration file for NetBSD.

  This is designed to work out of the box, but you will almost certainly want
  to customise it for optimum performance.
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
    make = "/usr/bin/make",
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
      recommended to be as strict as possible, especially in the "build"
      section used by production build sandboxes, as pollution from the user
      environment can negatively impact builds.  The "dev" section used by
      "bob sandbox exec" is primarily for interactive pkgsrc work, and you
      may want to set useful variables to suit the development environment.
    ]]
    environment = {
        build = {
            clear = true,
            inherit = { "TERM", "HOME" },
            vars = {
                PATH = "/sbin:/bin:/usr/sbin:/usr/bin",
            },
        },
        dev = {
            clear = true,
            inherit = { "TERM", "HOME" },
            vars = {
                BINPKG_SITES = "${bob_packages}",
                DEPENDS_TARGET = "bin-install",
                PATH = "${bob_prefix}/sbin:${bob_prefix}/bin:/sbin:/bin:/usr/sbin:/usr/bin",
                PS1 = [["sandbox:${bob_sandbox_id} "'${PWD}# ']],
            },
        },
    },

    --[[
      List of actions to apply for each sandbox.  During creation these actions
      are performed in order, and during destruction they are performed in
      reverse order.
    ]]
    setup = {
        -- Configure NetBSD device nodes.  Note that it is too early to be able
        -- to execute commands inside chroot context, so this is done carefully
        -- outside the chroot.
        { action = "cmd",
          create = "mkdir dev && cp /dev/MAKEDEV /dev/MAKEDEV.local dev/"
                .. " && cd dev && ./MAKEDEV all",
          destroy = "rm -rf dev" },

        { action = "mount", fs = "proc", dir = "/proc" },

        { action = "mount", fs = "tmp", dir = "/tmp", opts = "-s 1G" },
        { action = "mount", fs = "tmp", dir = "/var", opts = "-s 1G" },

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
        { action = "cmd", chroot = true,
          create = "mkdir -m 1777 /var/tmp; chmod 1777 /tmp" },

        -- Configure build user home directory if enabled.  Bob automatically
        -- sets bob_build_user* variables when the build user is configured,
        -- and the scripts are executed with 'set -eu', so these should be safe.
        { action = "cmd", only = { set = "pkgsrc.build_user" },
          create = [[
                mkdir -p ${bob_sandbox_path}${bob_build_user_home}
                chown ${bob_build_user} ${bob_sandbox_path}${bob_build_user_home}
          ]],
          destroy = "rm -rf ${bob_sandbox_path}${bob_build_user_home}" },

        -- It is recommended to mount pkgsrc read-only, but you will first need
        -- to configure DISTDIR, PACKAGES, and WRKOBJDIR to other directories.
        { action = "mount", fs = "null", dir = pkgsrc.basedir },
    },

    --[[
      Per-package hook actions.  Any create action will run after the internal
      pre-build script (unpacks bootstrap kit if needed), and any destroy
      action runs before the internal post-build script (wipes PREFIX and
      PKG_DBDIR).

    hooks = {
        -- As an example, ensure clean passwd file and /tmp for each build.
        { action = "cmd",
          create = "cp /etc/passwd ${bob_sandbox_path}/etc/passwd",
          destroy = "rm -rf ${bob_sandbox_path}/tmp/*",
        },
    },
    ]]
}
