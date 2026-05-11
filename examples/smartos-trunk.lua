--[[
  Live configuration file used by the daily SmartOS trunk bulk builds.  The
  host is an AMD EPYC 7302P: 16 cores, 32 threads, 128GB RAM.

  With a decent amount of RAM and no restrictions on the size of the tmpfs
  mounts, the wrkobjdir settings are tuned to ensure the vast majority of
  builds are performed on tmpfs, including enabling use_failed_history.

  24 build threads means that the majority of packages are given MAKE_JOBS=2
  by the dynamic scheduler, but this ensures the best overall throughput as
  most builds struggle to benefit from additional cores.  Larger builds will
  be assigned up to around 8 cores dynamically based on their CPU history.

  These builds are triggered by Jenkins, which checks out the latest revision
  as a detached head.  This means we need to set the branch name, as git is
  unable to determine it reliably.  This is what the GIT_BRANCH section is
  doing, as well as stripping the "origin/" remote, leaving just "trunk".
]]

options = {
    build_threads = 18,
    scan_threads = 32,
    log_level = "debug",
}

publish = {
    report = {
        from = "Jonathan Perkin <jperkin@pkgsrc.org>",
        to = "pkgsrc-bulk@pkgsrc.org",
        host = "reports.pkgci.org",
        path = "www/SmartOS/upstream/trunk",
        url = "https://reports.pkgci.org/SmartOS/upstream/trunk",
    },
}

--[[
  Jenkins checks out the latest upstream revision, so we need to set branch
  name as git cannot determine it.  Only do this if GIT_BRANCH is set in the
  environment.  Strip leading remote e.g. "origin/", leaving just "trunk".
]]
local git_branch = os.getenv("GIT_BRANCH")
if git_branch then
    publish.report.branch = git_branch:gsub("^[^/]*/", "")
end

dynamic = {
    jobs = 32,
    wrkobjdir = {
        tmpfs = "/tmp/work",
        disk = "/home/pbulk/work",
        threshold = "4G",
        failed_threshold = "4G",
    },
}

pkgsrc = {
    basedir = "/data/jenkins/workspace/pkgsrc-upstream-trunk",
    bootstrap = "/data/packages/SmartOS/bootstrap-pbulk/bootstrap-upstream-trunk.tar.gz",
    make = "/opt/pkg/bin/bmake",
    build_user = "pbulk",
}

sandboxes = {
    basedir = "/data/chroot",

    environment = {
        build = {
            clear = true,
            inherit = { "TERM", "HOME" },
            vars = {
                PATH = "/sbin:/usr/bin:/usr/sbin:/opt/tools/bin",
            },
        },
        dev = {
            clear = true,
            inherit = { "TERM", "HOME" },
            shell = "/bin/bash",
            vars = {
                BINPKG_SITES = "${bob_packages}",
                DEPENDS_TARGET = "bin-install",
                PATH = "${bob_prefix}/sbin:${bob_prefix}/bin:/sbin:/usr/bin:/usr/sbin:/opt/tools/bin",
                PS1 = [["sandbox:${bob_sandbox_id} "'${PWD}# ']],
            },
        },
    },

    setup = {
        { action = "mount", fs = "lofs", dir = "/devices", opts = "-o ro",
          only = { exists = "/devices" } },
        { action = "mount", fs = "lofs", dir = "/dev", opts = "-o ro" },
        { action = "mount", fs = "fd", dir = "/dev/fd" },
        { action = "mount", fs = "proc", dir = "/proc" },

        { action = "mount", fs = "tmp", dir = "/tmp" },
        { action = "mount", fs = "tmp", dir = "/var" },

        { action = "mount", fs = "lofs", dir = "/lib", opts = "-o ro" },
        { action = "mount", fs = "lofs", dir = "/sbin", opts = "-o ro" },
        { action = "mount", fs = "lofs", dir = "/usr", opts = "-o ro" },
        { action = "symlink", src = "usr/bin", dest = "/bin" },

        { action = "copy", dir = "/etc" },

        { action = "mount", fs = "tmp", dir = "/opt/pkg" },
        { action = "mount", fs = "tmp", dir = "/etc/opt/pkg" },

        { action = "cmd", chroot = true, create = [[
            mkdir -m 1777 /var/tmp; chmod 1777 /tmp
            mkdir -m 1775 /var/adm; chown root:sys /var/adm
            touch /var/adm/utmpx; chown root:bin /var/adm/utmpx
            mkdir -m 1775 /var/logadm
            mkdir -m 1777 /var/mail
            mkdir -p -m 0770 /var/spool/clientmqueue
            chown smmsp:smmsp /var/spool/clientmqueue
            mkdir -p -m 0755 /var/spool/locks
            chown uucp:uucp /var/spool/clientmqueue
          ]] },

        { action = "cmd", only = { set = "pkgsrc.build_user" }, create = [[
            mkdir -p ${bob_sandbox_path}${bob_build_user_home}
            chown ${bob_build_user} ${bob_sandbox_path}${bob_build_user_home}
          ]],
          destroy = "rm -rf ${bob_sandbox_path}${bob_build_user_home}" },

        { action = "mount", fs = "lofs", dir = pkgsrc.basedir, opts = "-o ro" },
        { action = "mount", fs = "lofs", dir = "/data/pkgsrc", opts = "-o ro" },
        { action = "mount", fs = "lofs", dir = "/data/distfiles" },
        { action = "mount", fs = "lofs", dir = "/data/packages" },

        { action = "cmd", chroot = true, create = [[
            gtar -zxpf /data/packages/SmartOS/bootstrap-pbulk/bootstrap-trunk-tools.tar.gz -C /
            PKG_PATH=/data/packages/SmartOS/trunk/tools/All /opt/tools/sbin/pkg_add \
                ctftools flex gcc14 gtexinfo libtool-base nbpatch smartos-build-tools xz
          ]] },
        { action = "cmd", destroy = "rm -rf ${bob_sandbox_path}/opt/tools" },

        -- Additional packages in development environments.
        { action = "cmd", chroot = true, only = { environment = "dev" }, create = dedent [[
            PKG_PATH=/data/packages/SmartOS/trunk/tools/All /opt/tools/sbin/pkg_add \
                git-base nodejs pkglint zsh
            ed /opt/tools/etc/mk.conf <<-EOF
            /^.include/d
            w
            q
            EOF
          ]] },
    },
    --[[
      As the main bootstrap kit is extracted AFTER the sandbox setup actions run, these
      modifications to the bootstrap files need to be done as a pre-build hook.
    ]]
    hooks = {
        { action = "cmd", chroot = true, only = { environment = "dev" },
          create = string.format(dedent([[
            cat >>/etc/opt/pkg/mk.conf <<-EOF
            MAKE_JOBS=%d
            EOF
            cat >>/etc/opt/pkg/pkg_install.conf <<-EOF
            PKG_PATH=/data/packages/SmartOS/upstream/trunk/All
            EOF
            # Sometimes pkgdiff might not be available, ignore errors
            /opt/pkg/sbin/pkg_add pkgdiff || true
          ]]), dynamic.jobs) },
    }
}
