-- Simple, minimal config for local scan only.  Useful for verifying that all
-- pkgsrc packages are consistent, with no unresolved dependencies.
--
--     $ bob -c scan.lua scan
--

options = {
    scan_threads = 8,
}

pkgsrc = {
    basedir = "/usr/pkgsrc",
    logdir = "/tmp/scan",
    make = "/usr/bin/make",
    cachevars = {
        "HOST_MACHINE_ARCH",
        "NATIVE_OPSYS",
        "NATIVE_OPSYS_VERSION",
        "NATIVE_OS_VERSION",
    },
}
