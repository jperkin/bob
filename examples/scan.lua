-- Simple, minimal config for local scan only.  Useful for verifying that all
-- pkgsrc packages are consistent, with no unresolved dependencies.

options = {
    scan_threads = 8,
    strict_scan = true,
}

pkgsrc = {
    basedir = "/usr/pkgsrc",
    make = "/usr/bin/make",
}
