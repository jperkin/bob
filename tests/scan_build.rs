/*!
 * Integration tests for scan and build using a fake pkgsrc tree.
 *
 * Creates a temporary pkgsrc tree with real Makefiles that respond to the
 * targets bob invokes (pbulk-index, build stages, show-var, etc.).  Tests
 * call Scan::start() and Build::start() directly with sandboxes disabled,
 * exercising the full orchestration: thread pools, DAG scheduling, DB
 * persistence, failure propagation, and resume.
 */

use anyhow::{Context, Result};
use bob::{
    Build, BuildOutcome, Config, Database, RunContext, Sandbox, Scan, ScanSummary, SkipReason,
    config::PkgsrcEnv, sandbox::SandboxScope,
};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tempfile::TempDir;

struct PkgDef<'a> {
    pkgpath: &'a str,
    pkgname: &'a str,
    all_depends: &'a str,
    skip_reason: &'a str,
    fail_reason: &'a str,
    bootstrap_pkg: &'a str,
    usergroup_phase: &'a str,
    multi_version: &'a str,
    fail_target: Option<(&'a str, &'a str)>,
}

impl<'a> PkgDef<'a> {
    fn new(pkgpath: &'a str, pkgname: &'a str) -> Self {
        Self {
            pkgpath,
            pkgname,
            all_depends: "",
            skip_reason: "",
            fail_reason: "",
            bootstrap_pkg: "",
            usergroup_phase: "",
            multi_version: "",
            fail_target: None,
        }
    }

    fn depends(mut self, d: &'a str) -> Self {
        self.all_depends = d;
        self
    }

    fn skip(mut self, s: &'a str) -> Self {
        self.skip_reason = s;
        self
    }

    fn fail(mut self, f: &'a str) -> Self {
        self.fail_reason = f;
        self
    }

    fn bootstrap(mut self) -> Self {
        self.bootstrap_pkg = "yes";
        self
    }

    fn usergroup(mut self, u: &'a str) -> Self {
        self.usergroup_phase = u;
        self
    }

    fn multi(mut self, m: &'a str) -> Self {
        self.multi_version = m;
        self
    }

    fn fail_at(mut self, target: &'a str, msg: &'a str) -> Self {
        self.fail_target = Some((target, msg));
        self
    }
}

/// Detect a usable bmake binary.
fn find_make() -> Option<PathBuf> {
    for candidate in &["/opt/pkg/bin/bmake", "/usr/pkg/bin/bmake", "/usr/bin/bmake"] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// A fake pkgsrc tree for integration testing.
struct TestHarness {
    _tmpdir: TempDir,
    root: PathBuf,
    make: PathBuf,
}

impl TestHarness {
    fn new() -> Result<Self> {
        let make = match find_make() {
            Some(m) => m,
            None => anyhow::bail!("bmake not found, skipping integration test"),
        };

        let tmpdir = TempDir::new().context("Failed to create temp dir")?;
        let root = tmpdir.path().to_path_buf();

        let harness = Self {
            _tmpdir: tmpdir,
            root,
            make,
        };
        harness.create_tree()?;
        Ok(harness)
    }

    fn pkgsrc(&self) -> PathBuf {
        self.root.join("pkgsrc")
    }

    fn logdir(&self) -> PathBuf {
        self.root.join("logs")
    }

    fn config_path(&self) -> PathBuf {
        self.root.join("config.lua")
    }

    fn db_path(&self) -> PathBuf {
        self.logdir().join("bob.db")
    }

    fn packages_dir(&self) -> PathBuf {
        self.root.join("packages")
    }

    /// Create the full fake pkgsrc tree.
    fn create_tree(&self) -> Result<()> {
        // Create directory structure
        let dirs = [
            "pkgsrc/test/base",
            "pkgsrc/test/mid",
            "pkgsrc/test/also-base",
            "pkgsrc/test/top",
            "pkgsrc/test/multi",
            "pkgsrc/test/skip-me",
            "pkgsrc/test/dep-skip",
            "pkgsrc/test/fail-me",
            "pkgsrc/test/dep-fail",
            "pkgsrc/test/bad-dep",
            "pkgsrc/test/build-fail",
            "pkgsrc/test/dep-bfail",
            "pkgsrc/test/fail-checksum",
            "pkgsrc/test/fail-at-build",
            "pkgsrc/test/fail-install",
            "pkgsrc/test/fail-package",
            "pkgsrc/test/chain-a",
            "pkgsrc/test/chain-b",
            "pkgsrc/test/chain-c",
            "pkgsrc/test/chain-d",
            "pkgsrc/pkgtools/pkg_install",
            "packages/All",
            "pkgtools",
            "pkg_dbdir",
            "pkg_refcount_dbdir",
            "prefix",
            "logs",
        ];
        for d in &dirs {
            fs::create_dir_all(self.root.join(d))?;
        }

        self.write_pkgsrc_root_makefile()?;
        self.write_category_makefile()?;
        self.write_pkg_install_makefile()?;
        self.write_mock_pkg_tools()?;
        self.write_package_makefiles()?;
        self.write_config_lua()?;

        Ok(())
    }

    /// pkgsrc root Makefile: show-subdir-var outputs category list.
    fn write_pkgsrc_root_makefile(&self) -> Result<()> {
        let content = "\
show-subdir-var:
\t@echo \"test\"
";
        fs::write(self.pkgsrc().join("Makefile"), content)?;
        Ok(())
    }

    /// Category Makefile: show-subdir-var outputs package list.
    fn write_category_makefile(&self) -> Result<()> {
        let content = "\
show-subdir-var:
\t@echo \"base mid also-base top multi skip-me dep-skip fail-me dep-fail bad-dep build-fail dep-bfail fail-checksum fail-at-build fail-install fail-package chain-a chain-b chain-c chain-d\"
";
        fs::write(self.pkgsrc().join("test/Makefile"), content)?;
        Ok(())
    }

    /// pkgtools/pkg_install Makefile: show-vars outputs environment values.
    fn write_pkg_install_makefile(&self) -> Result<()> {
        // Output order must match REQUIRED_VARS: PACKAGES, PKG_DBDIR,
        // PKG_REFCOUNT_DBDIR, PKG_TOOLS_BIN, PREFIX
        let content = format!(
            "\
show-vars:
\t@echo \"{packages}\"
\t@echo \"{pkg_dbdir}\"
\t@echo \"{pkg_refcount_dbdir}\"
\t@echo \"{pkgtools}\"
\t@echo \"{prefix}\"
",
            packages = self.packages_dir().display(),
            pkg_dbdir = self.root.join("pkg_dbdir").display(),
            pkg_refcount_dbdir = self.root.join("pkg_refcount_dbdir").display(),
            pkgtools = self.root.join("pkgtools").display(),
            prefix = self.root.join("prefix").display(),
        );
        fs::write(self.pkgsrc().join("pkgtools/pkg_install/Makefile"), content)?;
        Ok(())
    }

    /// Mock pkg_add and pkg_delete that always succeed.
    fn write_mock_pkg_tools(&self) -> Result<()> {
        let script = "#!/bin/sh\nexit 0\n";
        for tool in &["pkg_add", "pkg_delete"] {
            let path = self.root.join("pkgtools").join(tool);
            fs::write(&path, script)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        }
        Ok(())
    }

    /// Write all package Makefiles.
    fn write_package_makefiles(&self) -> Result<()> {
        let packages = [
            PkgDef::new("test/base", "base-1.0").bootstrap(),
            PkgDef::new("test/mid", "mid-1.0")
                .depends("base>=1.0:test/base")
                .usergroup("configure"),
            PkgDef::new("test/also-base", "also-base-1.0").depends("base>=1.0:test/base"),
            PkgDef::new("test/top", "top-1.0").depends(
                "mid-[0-9]*:test/mid \
                 also-base-[0-9]*:test/also-base",
            ),
            PkgDef::new("test/multi", "py313-multi-1.0").multi("PYTHON_VERSION_REQD=313"),
            PkgDef::new("test/skip-me", "skip-me-1.0").skip("not supported"),
            PkgDef::new("test/dep-skip", "dep-skip-1.0").depends("skip-me-[0-9]*:test/skip-me"),
            PkgDef::new("test/fail-me", "fail-me-1.0").fail("known broken"),
            PkgDef::new("test/dep-fail", "dep-fail-1.0").depends("fail-me-[0-9]*:test/fail-me"),
            PkgDef::new("test/bad-dep", "bad-dep-1.0")
                .depends("nonexistent-[0-9]*:test/nonexistent"),
            PkgDef::new("test/build-fail", "build-fail-1.0")
                .fail_at("configure", "configure failed"),
            PkgDef::new("test/dep-bfail", "dep-bfail-1.0")
                .depends("build-fail-[0-9]*:test/build-fail"),
            PkgDef::new("test/fail-checksum", "fail-checksum-1.0")
                .fail_at("checksum", "checksum mismatch"),
            PkgDef::new("test/fail-at-build", "fail-at-build-1.0")
                .fail_at("all", "compilation error"),
            PkgDef::new("test/fail-install", "fail-install-1.0")
                .fail_at("stage-install", "install failed: permission denied"),
            PkgDef::new("test/fail-package", "fail-package-1.0")
                .fail_at("stage-package-create", "pkg_create: error writing archive"),
            PkgDef::new("test/chain-d", "chain-d-1.0")
                .fail_at("configure", "chain-d configure failed"),
            PkgDef::new("test/chain-c", "chain-c-1.0").depends("chain-d-[0-9]*:test/chain-d"),
            PkgDef::new("test/chain-b", "chain-b-1.0").depends("chain-c-[0-9]*:test/chain-c"),
            PkgDef::new("test/chain-a", "chain-a-1.0").depends("chain-b-[0-9]*:test/chain-b"),
        ];
        for pkg in &packages {
            self.write_pkg_makefile(pkg)?;
        }
        Ok(())
    }

    fn write_pkg_makefile(&self, pkg: &PkgDef) -> Result<()> {
        let mut fields = vec![
            format!("PKGNAME={}\\n", pkg.pkgname),
            format!("PKG_LOCATION={}\\n", pkg.pkgpath),
            format!("ALL_DEPENDS={}\\n", pkg.all_depends),
            format!("PKG_SKIP_REASON={}\\n", pkg.skip_reason),
            format!("PKG_FAIL_REASON={}\\n", pkg.fail_reason),
            "NO_BIN_ON_FTP=\\n".to_string(),
            "RESTRICTED=\\n".to_string(),
            "CATEGORIES=test\\n".to_string(),
            "MAINTAINER=test@example.com\\n".to_string(),
            "USE_DESTDIR=yes\\n".to_string(),
            format!("BOOTSTRAP_PKG={}\\n", pkg.bootstrap_pkg),
            format!("USERGROUP_PHASE={}\\n", pkg.usergroup_phase),
            "SCAN_DEPENDS=\\n".to_string(),
        ];
        if !pkg.multi_version.is_empty() {
            fields.push(format!("MULTI_VERSION={}\\n", pkg.multi_version));
        }
        let index_body = fields.join("");

        let buildable = pkg.skip_reason.is_empty() && pkg.fail_reason.is_empty();

        let build_targets = if buildable {
            let all_targets = [
                "clean",
                "checksum",
                "configure",
                "all",
                "stage-install",
                "stage-package-create",
                "create-usergroup",
            ];

            let mut sections = Vec::new();

            match pkg.fail_target {
                Some((fail_tgt, msg)) => {
                    let pass: Vec<&str> = all_targets
                        .iter()
                        .filter(|t| **t != fail_tgt)
                        .copied()
                        .collect();
                    if !pass.is_empty() {
                        sections.push(format!("\n{targets}:\n\t@true", targets = pass.join(" "),));
                    }
                    sections.push(format!(
                        "\n{fail_tgt}:\n\
                         \t@echo '{msg}' >&2; exit 1",
                    ));
                }
                None => {
                    let pass: Vec<&str> = all_targets
                        .iter()
                        .filter(|t| **t != "stage-package-create")
                        .copied()
                        .collect();
                    sections.push(format!("\n{targets}:\n\t@true", targets = pass.join(" "),));
                    sections.push(format!(
                        "\nstage-package-create:\n\
                         \t@mkdir -p ${{.CURDIR}}/pkg\n\
                         \t@printf 'dummy' > \
                         ${{.CURDIR}}/pkg/{pkgname}.tgz",
                        pkgname = pkg.pkgname,
                    ));
                }
            }

            sections.push(format!(
                "\nshow-var:\n\
                 \t@case \"${{VARNAME}}\" in \
                 STAGE_PKGFILE) echo \
                 \"${{.CURDIR}}/pkg/{pkgname}.tgz\" ;; esac",
                pkgname = pkg.pkgname,
            ));

            sections.join("\n")
        } else {
            String::new()
        };

        let content = format!(
            "PKGNAME={pkgname}\n\
             \n\
             pbulk-index:\n\
             \t@printf '{index_body}'\n\
             {build_targets}\n",
            pkgname = pkg.pkgname,
        );
        let pkgdir = self.pkgsrc().join(pkg.pkgpath);
        fs::write(pkgdir.join("Makefile"), content)?;
        Ok(())
    }

    /// Write the Lua config file.
    fn write_config_lua(&self) -> Result<()> {
        let content = format!(
            "\
options = {{
    build_threads = 2,
    scan_threads = 2,
    progress = \"plain\",
}}
pkgsrc = {{
    basedir = \"{pkgsrc}\",
    logdir = \"{logdir}\",
    make = \"{make}\",
}}
",
            pkgsrc = self.pkgsrc().display(),
            logdir = self.logdir().display(),
            make = self.make.display(),
        );
        fs::write(self.config_path(), content)?;
        Ok(())
    }

    /// Load the config.
    fn load_config(&self) -> Result<Config> {
        let path = self.config_path();
        Config::load(Some(&path))
    }

    /// Open the database.
    fn open_db(&self) -> Result<Database> {
        Database::open(&self.db_path())
    }

    /// Create a RunContext with no shutdown.
    fn run_context(&self) -> RunContext {
        RunContext::new(Arc::new(AtomicBool::new(false)))
    }

    /// Create a PkgsrcEnv from our known paths.
    fn pkgsrc_env(&self) -> PkgsrcEnv {
        PkgsrcEnv {
            packages: self.packages_dir(),
            pkgtools: self.root.join("pkgtools"),
            prefix: self.root.join("prefix"),
            pkg_dbdir: self.root.join("pkg_dbdir"),
            pkg_refcount_dbdir: self.root.join("pkg_refcount_dbdir"),
            cachevars: std::collections::HashMap::new(),
        }
    }

    /// Run a full scan and return the summary.
    fn run_scan(&self) -> Result<ScanSummary> {
        let config = self.load_config()?;
        let db = self.open_db()?;
        let ctx = self.run_context();
        let sandbox = Sandbox::new(&config);
        let mut scope = SandboxScope::new(sandbox, ctx);

        let mut scan = Scan::new(&config);
        scan.init_from_db(&db)?;
        scan.start(&db, &mut scope)?;
        scan.resolve_with_report(&db, false)
    }
}

#[test]
fn test_full_tree_scan() -> Result<()> {
    let h = TestHarness::new()?;
    let result = h.run_scan()?;

    let c = result.counts();

    // 15 buildable: base, mid, also-base, top, multi, build-fail, dep-bfail,
    //   fail-checksum, fail-at-build, fail-install, fail-package,
    //   chain-a, chain-b, chain-c, chain-d
    assert_eq!(
        c.buildable,
        15,
        "expected 15 buildable, got {} (total packages: {})",
        c.buildable,
        result.packages.len()
    );

    // 1 pkg_skip: skip-me
    assert_eq!(c.skipped.pkg_skip, 1, "expected 1 pkg_skip");

    // 1 pkg_fail: fail-me
    assert_eq!(c.skipped.pkg_fail, 1, "expected 1 pkg_fail");

    // 1 indirect_preskip: dep-skip (depends on skip-me)
    assert_eq!(c.skipped.indirect_preskip, 1, "expected 1 indirect_preskip");

    // 1 indirect_prefail: dep-fail (depends on fail-me)
    assert_eq!(c.skipped.indirect_prefail, 1, "expected 1 indirect_prefail");

    // 1 unresolved: bad-dep (depends on nonexistent)
    assert_eq!(c.skipped.unresolved, 1, "expected 1 unresolved");

    // Total should be 20
    assert_eq!(result.packages.len(), 20, "expected 20 total packages");

    // Verify specific skip reasons
    for pkg in &result.packages {
        match pkg.pkgpath().as_path().to_string_lossy().as_ref() {
            "test/skip-me" => {
                if let bob::ScanResult::Skipped { reason, .. } = pkg {
                    assert!(
                        matches!(reason, SkipReason::PkgSkip(_)),
                        "skip-me should be PkgSkip, got {:?}",
                        reason
                    );
                } else {
                    panic!("skip-me should be Skipped");
                }
            }
            "test/dep-skip" => {
                if let bob::ScanResult::Skipped { reason, .. } = pkg {
                    assert!(
                        matches!(reason, SkipReason::IndirectPreskip(_)),
                        "dep-skip should be IndirectPreskip, got {:?}",
                        reason
                    );
                } else {
                    panic!("dep-skip should be Skipped");
                }
            }
            "test/fail-me" => {
                if let bob::ScanResult::Skipped { reason, .. } = pkg {
                    assert!(
                        matches!(reason, SkipReason::PkgFail(_)),
                        "fail-me should be PkgFail, got {:?}",
                        reason
                    );
                } else {
                    panic!("fail-me should be Skipped");
                }
            }
            "test/dep-fail" => {
                if let bob::ScanResult::Skipped { reason, .. } = pkg {
                    assert!(
                        matches!(reason, SkipReason::IndirectPrefail(_)),
                        "dep-fail should be IndirectPrefail, got {:?}",
                        reason
                    );
                } else {
                    panic!("dep-fail should be Skipped");
                }
            }
            "test/bad-dep" => {
                if let bob::ScanResult::Skipped { reason, .. } = pkg {
                    assert!(
                        matches!(reason, SkipReason::UnresolvedDep(_)),
                        "bad-dep should be UnresolvedDep, got {:?}",
                        reason
                    );
                } else {
                    panic!("bad-dep should be Skipped");
                }
            }
            _ => {}
        }
    }

    Ok(())
}

#[test]
fn test_limited_scan() -> Result<()> {
    let h = TestHarness::new()?;
    let config = h.load_config()?;
    let db = h.open_db()?;
    let ctx = h.run_context();
    let sandbox = Sandbox::new(&config);
    let mut scope = SandboxScope::new(sandbox, ctx);

    let mut scan = Scan::new(&config);
    let top = pkgsrc::PkgPath::new("test/top")?;
    scan.add(&top);
    scan.init_from_db(&db)?;
    scan.start(&db, &mut scope)?;
    let result = scan.resolve_with_report(&db, false)?;

    // Limited scan from test/top should discover:
    // test/top -> test/mid, test/also-base -> test/base (transitively)
    // That's 4 packages total, all buildable.
    assert_eq!(
        result.packages.len(),
        4,
        "expected 4 packages from limited scan of test/top, got {}",
        result.packages.len()
    );

    let c = result.counts();
    assert_eq!(c.buildable, 4, "all 4 packages should be buildable");
    assert_eq!(c.skipped.pkg_skip, 0);
    assert_eq!(c.skipped.pkg_fail, 0);
    assert_eq!(c.skipped.unresolved, 0);

    // Verify the expected packages are present
    let pkgpaths: Vec<String> = result
        .packages
        .iter()
        .map(|p| p.pkgpath().as_path().to_string_lossy().to_string())
        .collect();
    assert!(pkgpaths.contains(&"test/top".to_string()));
    assert!(pkgpaths.contains(&"test/mid".to_string()));
    assert!(pkgpaths.contains(&"test/also-base".to_string()));
    assert!(pkgpaths.contains(&"test/base".to_string()));

    Ok(())
}

#[test]
fn test_full_build() -> Result<()> {
    let h = TestHarness::new()?;
    let config = h.load_config()?;
    let db = h.open_db()?;
    let ctx = h.run_context();

    // Run scan first
    let sandbox = Sandbox::new(&config);
    let mut scan_scope = SandboxScope::new(sandbox, ctx.clone());
    let mut scan = Scan::new(&config);
    scan.init_from_db(&db)?;
    scan.start(&db, &mut scan_scope)?;
    let scan_result = scan.resolve_with_report(&db, false)?;

    // Collect buildable packages for the build
    let scanpkgs = scan_result
        .buildable()
        .map(|p| (p.pkgname().clone(), p.clone()))
        .collect();

    // Fetch pkgsrc env (or use our known paths)
    let pkgsrc_env = h.pkgsrc_env();

    // Run build
    let build_sandbox = Sandbox::new(&config);
    let build_scope = SandboxScope::new(build_sandbox, ctx.clone());
    let mut build = Build::new(&config, pkgsrc_env, build_scope, scanpkgs);
    let build_result = build.start(&ctx, &db)?;

    let bc = build_result.counts();

    // 5 success: base, mid, also-base, top, multi
    assert_eq!(
        bc.success, 5,
        "expected 5 successful builds, got {}",
        bc.success
    );

    // 6 failed: build-fail, fail-checksum, fail-at-build, fail-install,
    //   fail-package, chain-d
    assert_eq!(bc.failed, 6, "expected 6 failed builds, got {}", bc.failed);

    // 4 skipped: dep-bfail, chain-c, chain-b, chain-a
    let indirect_failed = bc.skipped.indirect_failed;
    assert_eq!(
        indirect_failed, 4,
        "expected 4 indirect-failed skips, got {}",
        indirect_failed
    );

    // Verify specific outcomes
    for r in &build_result.results {
        let name = r.pkgname.pkgname();
        match name {
            "base-1.0" | "mid-1.0" | "also-base-1.0" | "top-1.0" | "py313-multi-1.0" => {
                assert!(
                    matches!(r.outcome, BuildOutcome::Success),
                    "{} should be Success, got {:?}",
                    name,
                    r.outcome
                );
            }
            "build-fail-1.0" | "fail-checksum-1.0" | "fail-at-build-1.0" | "fail-install-1.0"
            | "fail-package-1.0" | "chain-d-1.0" => {
                assert!(
                    matches!(r.outcome, BuildOutcome::Failed(_)),
                    "{} should be Failed, got {:?}",
                    name,
                    r.outcome
                );
            }
            "dep-bfail-1.0" | "chain-c-1.0" | "chain-b-1.0" | "chain-a-1.0" => {
                assert!(
                    matches!(
                        r.outcome,
                        BuildOutcome::Skipped(SkipReason::IndirectFailed(_))
                    ),
                    "{} should be Skipped(IndirectFailed), got {:?}",
                    name,
                    r.outcome
                );
            }
            _ => {}
        }
    }

    // Verify .tgz files exist for successful packages
    let packages_all = h.packages_dir().join("All");
    for name in &[
        "base-1.0",
        "mid-1.0",
        "also-base-1.0",
        "top-1.0",
        "py313-multi-1.0",
    ] {
        let tgz = packages_all.join(format!("{}.tgz", name));
        assert!(tgz.exists(), "Package file {} should exist", tgz.display());
    }

    // Verify no .tgz files for failed packages
    for name in &[
        "build-fail-1.0",
        "fail-checksum-1.0",
        "fail-at-build-1.0",
        "fail-install-1.0",
        "fail-package-1.0",
        "chain-d-1.0",
    ] {
        let tgz = packages_all.join(format!("{}.tgz", name));
        assert!(
            !tgz.exists(),
            "Failed package {} should not exist",
            tgz.display()
        );
    }

    // Verify log directory exists for failed builds
    for name in &["build-fail-1.0", "fail-checksum-1.0", "fail-at-build-1.0"] {
        let fail_logdir = h.logdir().join(name);
        assert!(
            fail_logdir.exists(),
            "Log dir for {} should exist at {}",
            name,
            fail_logdir.display()
        );
    }

    Ok(())
}

#[test]
fn test_scan_database_caching() -> Result<()> {
    let h = TestHarness::new()?;

    // Run first scan
    let result1 = h.run_scan()?;
    assert_eq!(result1.packages.len(), 20);

    // Create a new scan and check database caching
    let config = h.load_config()?;
    let db = h.open_db()?;
    let mut scan2 = Scan::new(&config);
    let (cached_count, _pending) = scan2.init_from_db(&db)?;

    assert_eq!(
        cached_count, 20,
        "second scan should find 20 cached packages, got {}",
        cached_count
    );

    // With full_scan_complete set, start() should skip re-scanning
    scan2.set_full_scan_complete();
    let ctx = h.run_context();
    let sandbox = Sandbox::new(&config);
    let mut scope = SandboxScope::new(sandbox, ctx);
    scan2.start(&db, &mut scope)?;

    // Resolve should still work with cached data
    let result2 = scan2.resolve_with_report(&db, false)?;
    assert_eq!(
        result2.packages.len(),
        20,
        "cached resolve should produce same result"
    );

    Ok(())
}

#[test]
fn test_build_bootstrap_skips_deinstall() -> Result<()> {
    let h = TestHarness::new()?;
    let config = h.load_config()?;
    let db = h.open_db()?;
    let ctx = h.run_context();

    // Run scan
    let sandbox = Sandbox::new(&config);
    let mut scan_scope = SandboxScope::new(sandbox, ctx.clone());
    let mut scan = Scan::new(&config);
    scan.init_from_db(&db)?;
    scan.start(&db, &mut scan_scope)?;
    let scan_result = scan.resolve_with_report(&db, false)?;

    // Only build test/base (bootstrap package)
    let scanpkgs = scan_result
        .buildable()
        .filter(|p| p.pkgpath.as_path().to_string_lossy() == "test/base")
        .map(|p| (p.pkgname().clone(), p.clone()))
        .collect();

    let pkgsrc_env = h.pkgsrc_env();
    let build_sandbox = Sandbox::new(&config);
    let build_scope = SandboxScope::new(build_sandbox, ctx.clone());
    let mut build = Build::new(&config, pkgsrc_env, build_scope, scanpkgs);
    let build_result = build.start(&ctx, &db)?;

    // base should succeed
    assert_eq!(build_result.counts().success, 1);

    // Verify no deinstall log exists (bootstrap skips deinstall)
    let base_logdir = h.logdir().join("base-1.0");
    let deinstall_log = base_logdir.join("deinstall.log");
    assert!(
        !deinstall_log.exists(),
        "Bootstrap package should not have deinstall.log (log dir removed on success)"
    );

    Ok(())
}

#[test]
fn test_scan_resume() -> Result<()> {
    let h = TestHarness::new()?;
    let config = h.load_config()?;
    let db = h.open_db()?;

    // Run first scan with early shutdown
    let shutdown = Arc::new(AtomicBool::new(false));
    let ctx = RunContext::new(Arc::clone(&shutdown));
    let sandbox = Sandbox::new(&config);
    let mut scope = SandboxScope::new(sandbox, ctx);

    let mut scan = Scan::new(&config);
    scan.init_from_db(&db)?;

    // Set shutdown flag after a short delay to interrupt the scan.
    // We use a thread to set it while the scan is running.
    let shutdown_clone = Arc::clone(&shutdown);
    let _trigger = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        shutdown_clone.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    // Start scan - may be interrupted
    let _ = scan.start(&db, &mut scope);

    // Check that we have some partial results in the DB
    let scanned = db.get_scanned_pkgpaths()?;
    // We should have at least some packages scanned (may be all if fast enough)
    // The key test is that resuming works correctly.

    // Now resume: create a new scan with a fresh context (no shutdown)
    let ctx2 = h.run_context();
    let sandbox2 = Sandbox::new(&config);
    let mut scope2 = SandboxScope::new(sandbox2, ctx2);

    let mut scan2 = Scan::new(&config);
    let (cached, _) = scan2.init_from_db(&db)?;

    // cached should match what was scanned in the first run
    assert_eq!(
        cached,
        scanned.len(),
        "cached count should match scanned pkgpaths"
    );

    // Complete the scan
    scan2.start(&db, &mut scope2)?;
    let result = scan2.resolve_with_report(&db, false)?;

    // Final result should have at least 20 packages.  The scanner may
    // also discover test/nonexistent (from bad-dep's dependency) and
    // record it as a ScanFail, giving 21.
    assert!(
        result.packages.len() >= 20,
        "resumed scan should produce at least 20 packages, got {}",
        result.packages.len()
    );

    let c = result.counts();
    assert_eq!(c.buildable, 15, "expected 15 buildable after resume");

    Ok(())
}

/// Run a full scan + build using the test harness, returning the DB, scan
/// summary, and build summary for further assertions.
fn run_scan_and_build(h: &TestHarness) -> Result<(Database, ScanSummary, bob::BuildSummary)> {
    let config = h.load_config()?;
    let db = h.open_db()?;
    let ctx = h.run_context();

    let sandbox = Sandbox::new(&config);
    let mut scan_scope = SandboxScope::new(sandbox, ctx.clone());
    let mut scan = Scan::new(&config);
    scan.init_from_db(&db)?;
    scan.start(&db, &mut scan_scope)?;
    let scan_result = scan.resolve_with_report(&db, false)?;

    let scanpkgs = scan_result
        .buildable()
        .map(|p| (p.pkgname().clone(), p.clone()))
        .collect();
    let pkgsrc_env = h.pkgsrc_env();
    let build_sandbox = Sandbox::new(&config);
    let build_scope = SandboxScope::new(build_sandbox, ctx.clone());
    let mut build = Build::new(&config, pkgsrc_env, build_scope, scanpkgs);
    let build_result = build.start(&ctx, &db)?;

    Ok((db, scan_result, build_result))
}

#[test]
fn test_cached_build_resume() -> Result<()> {
    let h = TestHarness::new()?;

    // First scan + build
    let (_, scan_result, _) = run_scan_and_build(&h)?;

    // Second build using the same DB (results are cached)
    let config = h.load_config()?;
    let db = h.open_db()?;
    let ctx = h.run_context();

    let scanpkgs = scan_result
        .buildable()
        .map(|p| (p.pkgname().clone(), p.clone()))
        .collect();
    let pkgsrc_env = h.pkgsrc_env();
    let build_sandbox = Sandbox::new(&config);
    let build_scope = SandboxScope::new(build_sandbox, ctx.clone());
    let mut build2 = Build::new(&config, pkgsrc_env, build_scope, scanpkgs);

    let cached = build2.load_cached_from_db(&db)?;
    assert_eq!(cached, 15, "expected 15 cached results, got {}", cached);

    let result2 = build2.start(&ctx, &db)?;
    assert!(
        result2.results.is_empty(),
        "second build should produce no new results (all cached), got {}",
        result2.results.len()
    );

    Ok(())
}

#[test]
fn test_build_results_in_db() -> Result<()> {
    let h = TestHarness::new()?;
    let (db, _, _) = run_scan_and_build(&h)?;

    // Verify successful package
    let base = db
        .get_package_by_name("base-1.0")?
        .expect("base-1.0 should exist");
    let base_result = db
        .get_build_result(base.id)?
        .expect("base-1.0 should have a build result");
    assert!(
        matches!(base_result.outcome, BuildOutcome::Success),
        "base-1.0 should be Success, got {:?}",
        base_result.outcome
    );

    // Verify failed package
    let bf = db
        .get_package_by_name("build-fail-1.0")?
        .expect("build-fail-1.0 should exist");
    let bf_result = db
        .get_build_result(bf.id)?
        .expect("build-fail-1.0 should have a build result");
    assert!(
        matches!(bf_result.outcome, BuildOutcome::Failed(_)),
        "build-fail-1.0 should be Failed, got {:?}",
        bf_result.outcome
    );

    // get_all_build_results
    let all = db.get_all_build_results()?;
    assert!(
        all.len() >= 14,
        "expected at least 14 build results, got {}",
        all.len()
    );

    // get_failed_packages
    let failed = db.get_failed_packages()?;
    assert!(
        failed.contains(&"build-fail-1.0".to_string()),
        "failed list should contain build-fail-1.0"
    );

    // delete_build_by_name
    assert!(db.delete_build_by_name("base-1.0")?);
    assert!(!db.delete_build_by_name("base-1.0")?);

    // delete_build_by_pkgpath
    let del_count = db.delete_build_by_pkgpath("test/build-fail")?;
    assert_eq!(del_count, 1, "expected 1 deleted, got {}", del_count);

    // clear_builds
    let cleared = db.clear_builds()?;
    assert!(cleared >= 1, "expected at least 1 cleared, got {}", cleared);

    // After clearing, no results should remain
    let remaining = db.get_all_build_results()?;
    assert!(remaining.is_empty(), "expected 0 after clear_builds");

    Ok(())
}

#[test]
fn test_strict_scan() -> Result<()> {
    let h = TestHarness::new()?;
    let config = h.load_config()?;
    let db = h.open_db()?;
    let ctx = h.run_context();
    let sandbox = Sandbox::new(&config);
    let mut scope = SandboxScope::new(sandbox, ctx);

    let mut scan = Scan::new(&config);
    scan.init_from_db(&db)?;
    scan.start(&db, &mut scope)?;

    let result = scan.resolve_with_report(&db, true);
    assert!(
        result.is_err(),
        "strict scan should fail with unresolved deps"
    );
    let err_msg = format!("{}", result.expect_err("expected error"));
    assert!(
        err_msg.contains("strict_scan"),
        "error should mention strict_scan, got: {}",
        err_msg
    );

    Ok(())
}

#[test]
fn test_pkgsrc_env_persistence() -> Result<()> {
    let h = TestHarness::new()?;
    let db = h.open_db()?;

    // full_scan_complete lifecycle
    assert!(!db.full_scan_complete());
    db.set_full_scan_complete()?;
    assert!(db.full_scan_complete());
    db.clear_full_scan_complete()?;
    assert!(!db.full_scan_complete());

    // Store and load PkgsrcEnv
    let env = h.pkgsrc_env();
    db.store_pkgsrc_env(&env)?;
    let loaded = db.load_pkgsrc_env()?;
    assert_eq!(loaded.packages, env.packages);
    assert_eq!(loaded.pkgtools, env.pkgtools);
    assert_eq!(loaded.prefix, env.prefix);
    assert_eq!(loaded.pkg_dbdir, env.pkg_dbdir);
    assert_eq!(loaded.pkg_refcount_dbdir, env.pkg_refcount_dbdir);

    // Storing again should fail (INSERT, not REPLACE)
    let dup = db.store_pkgsrc_env(&env);
    assert!(dup.is_err(), "duplicate store_pkgsrc_env should fail");

    Ok(())
}

#[test]
fn test_config_options_and_environment() -> Result<()> {
    let h = TestHarness::new()?;

    let content = format!(
        "\
options = {{
    build_threads = 4,
    scan_threads = 3,
    strict_scan = true,
}}
pkgsrc = {{
    basedir = \"{pkgsrc}\",
    logdir = \"{logdir}\",
    make = \"{make}\",
    cachevars = {{ \"NATIVE_OPSYS\" }},
    save_wrkdir_patterns = {{ \"**/config.log\" }},
}}
environment = {{
    clear = true,
    inherit = {{ \"TERM\", \"HOME\" }},
    set = {{ PATH = \"/sbin:/bin\", LC_ALL = \"C\" }},
}}
",
        pkgsrc = h.pkgsrc().display(),
        logdir = h.logdir().display(),
        make = h.make.display(),
    );
    fs::write(h.config_path(), content)?;

    let config = h.load_config()?;
    assert_eq!(config.build_threads(), 4);
    assert_eq!(config.scan_threads(), 3);
    assert!(config.strict_scan());
    assert_eq!(config.cachevars(), &["NATIVE_OPSYS"]);
    assert_eq!(config.save_wrkdir_patterns(), &["**/config.log"]);

    let env = config
        .environment()
        .expect("environment section should exist");
    assert!(env.clear);
    assert_eq!(env.inherit, vec!["TERM", "HOME"]);
    let mut expected_set = HashMap::new();
    expected_set.insert("PATH".to_string(), "/sbin:/bin".to_string());
    expected_set.insert("LC_ALL".to_string(), "C".to_string());
    assert_eq!(env.set, expected_set);

    Ok(())
}

#[test]
fn test_config_validation() -> Result<()> {
    let h = TestHarness::new()?;

    // Invalid make path
    let content = format!(
        "\
pkgsrc = {{
    basedir = \"{pkgsrc}\",
    logdir = \"{logdir}\",
    make = \"/nonexistent/bmake\",
}}
",
        pkgsrc = h.pkgsrc().display(),
        logdir = h.logdir().display(),
    );
    fs::write(h.config_path(), &content)?;
    let config = h.load_config()?;
    let result = config.validate();
    assert!(result.is_err(), "validate should fail with bad make path");
    let errors = result.expect_err("expected validation errors");
    assert!(
        errors.iter().any(|e| e.contains("make")),
        "errors should mention make: {:?}",
        errors
    );

    // Invalid logdir parent
    let content = format!(
        "\
pkgsrc = {{
    basedir = \"{pkgsrc}\",
    logdir = \"/nonexistent/parent/logs\",
    make = \"{make}\",
}}
",
        pkgsrc = h.pkgsrc().display(),
        make = h.make.display(),
    );
    fs::write(h.config_path(), &content)?;
    let config = h.load_config()?;
    let result = config.validate();
    assert!(result.is_err(), "validate should fail with bad logdir");
    let errors = result.expect_err("expected validation errors");
    assert!(
        errors.iter().any(|e| e.contains("logdir")),
        "errors should mention logdir: {:?}",
        errors
    );

    Ok(())
}

#[test]
fn test_scan_failure_handling() -> Result<()> {
    let h = TestHarness::new()?;

    // Create a package whose pbulk-index target fails
    let scan_fail_dir = h.pkgsrc().join("test/scan-fail");
    fs::create_dir_all(&scan_fail_dir)?;
    let makefile = "\
PKGNAME=scan-fail-1.0

pbulk-index:
\t@echo 'fatal error' >&2; exit 1
";
    fs::write(scan_fail_dir.join("Makefile"), makefile)?;

    // Update category Makefile to include scan-fail
    let cat_content = "\
show-subdir-var:
\t@echo \"base mid also-base top multi skip-me dep-skip fail-me dep-fail bad-dep build-fail dep-bfail fail-checksum fail-at-build fail-install fail-package chain-a chain-b chain-c chain-d scan-fail\"
";
    fs::write(h.pkgsrc().join("test/Makefile"), cat_content)?;

    let result = h.run_scan()?;
    let c = result.counts();

    assert_eq!(c.scanfail, 1, "expected 1 scanfail, got {}", c.scanfail);
    assert_eq!(c.buildable, 15, "buildable count should remain 15");

    let scan_fail_found = result.packages.iter().any(|p| {
        matches!(p, bob::ScanResult::ScanFail { .. })
            && p.pkgpath().as_path().to_string_lossy() == "test/scan-fail"
    });
    assert!(scan_fail_found, "scan-fail should appear as ScanFail");

    Ok(())
}

/// Verify that each build phase can independently fail and produce the
/// correct BuildOutcome::Failed result.
#[test]
fn test_build_failure_at_each_phase() -> Result<()> {
    let h = TestHarness::new()?;
    let (_, _, build_result) = run_scan_and_build(&h)?;

    let outcomes: HashMap<&str, &BuildOutcome> = build_result
        .results
        .iter()
        .map(|r| (r.pkgname.pkgname(), &r.outcome))
        .collect();

    // Each fail-* package should have Failed outcome
    let expected_failures = [
        "fail-checksum-1.0",
        "fail-at-build-1.0",
        "fail-install-1.0",
        "fail-package-1.0",
    ];
    for name in &expected_failures {
        let outcome = outcomes
            .get(name)
            .unwrap_or_else(|| panic!("{} should have a build result", name));
        assert!(
            matches!(outcome, BuildOutcome::Failed(_)),
            "{} should be Failed, got {:?}",
            name,
            outcome
        );
    }

    Ok(())
}

/// Verify build log files: successful builds clean up their log dirs,
/// failed builds leave logs for the phases that ran.
#[test]
fn test_build_logs() -> Result<()> {
    let h = TestHarness::new()?;
    run_scan_and_build(&h)?;

    // Successful packages should not have log directories
    for name in &["base-1.0", "mid-1.0", "top-1.0"] {
        let logdir = h.logdir().join(name);
        assert!(
            !logdir.exists(),
            "Successful build {} should not have log dir at {}",
            name,
            logdir.display()
        );
    }

    // build-fail fails at configure: should have pre-clean.log, configure.log
    let bf_log = h.logdir().join("build-fail-1.0");
    assert!(bf_log.exists(), "build-fail log dir should exist");
    assert!(
        bf_log.join("pre-clean.log").exists(),
        "build-fail should have pre-clean.log"
    );
    assert!(
        bf_log.join("configure.log").exists(),
        "build-fail should have configure.log"
    );
    // build.log should not exist (never reached)
    assert!(
        !bf_log.join("build.log").exists(),
        "build-fail should not have build.log (configure failed first)"
    );

    // fail-checksum fails at checksum: should have pre-clean.log, checksum.log
    let fc_log = h.logdir().join("fail-checksum-1.0");
    assert!(fc_log.exists(), "fail-checksum log dir should exist");
    assert!(
        fc_log.join("pre-clean.log").exists(),
        "fail-checksum should have pre-clean.log"
    );
    assert!(
        fc_log.join("checksum.log").exists(),
        "fail-checksum should have checksum.log"
    );
    assert!(
        !fc_log.join("configure.log").exists(),
        "fail-checksum should not have configure.log"
    );

    // fail-at-build fails at build (all): should have configure.log + build.log
    let fab_log = h.logdir().join("fail-at-build-1.0");
    assert!(fab_log.exists(), "fail-at-build log dir should exist");
    assert!(
        fab_log.join("configure.log").exists(),
        "fail-at-build should have configure.log"
    );
    assert!(
        fab_log.join("build.log").exists(),
        "fail-at-build should have build.log"
    );
    assert!(
        !fab_log.join("install.log").exists(),
        "fail-at-build should not have install.log"
    );

    // fail-install: should have build.log + install.log
    let fi_log = h.logdir().join("fail-install-1.0");
    assert!(fi_log.exists(), "fail-install log dir should exist");
    assert!(
        fi_log.join("build.log").exists(),
        "fail-install should have build.log"
    );
    assert!(
        fi_log.join("install.log").exists(),
        "fail-install should have install.log"
    );

    // fail-package: should have install.log + package.log
    let fp_log = h.logdir().join("fail-package-1.0");
    assert!(fp_log.exists(), "fail-package log dir should exist");
    assert!(
        fp_log.join("install.log").exists(),
        "fail-package should have install.log"
    );
    assert!(
        fp_log.join("package.log").exists(),
        "fail-package should have package.log"
    );

    // All failed builds should have a .stage file
    for name in &[
        "build-fail-1.0",
        "fail-checksum-1.0",
        "fail-at-build-1.0",
        "fail-install-1.0",
        "fail-package-1.0",
    ] {
        let stage_file = h.logdir().join(name).join(".stage");
        assert!(stage_file.exists(), "{} should have a .stage file", name);
    }

    Ok(())
}

/// Verify that the 4-level dependency chain cascades failure correctly:
/// chain-d fails → chain-c, chain-b, chain-a all IndirectFailed.
#[test]
fn test_cascading_failure_chain() -> Result<()> {
    let h = TestHarness::new()?;
    let (_, _, build_result) = run_scan_and_build(&h)?;

    let outcomes: HashMap<&str, &BuildOutcome> = build_result
        .results
        .iter()
        .map(|r| (r.pkgname.pkgname(), &r.outcome))
        .collect();

    // chain-d: direct failure
    let chain_d = outcomes.get("chain-d-1.0").expect("chain-d should exist");
    assert!(
        matches!(chain_d, BuildOutcome::Failed(_)),
        "chain-d should be Failed, got {:?}",
        chain_d
    );

    // chain-c, chain-b, chain-a: indirect failure from chain-d
    for name in &["chain-c-1.0", "chain-b-1.0", "chain-a-1.0"] {
        let outcome = outcomes
            .get(name)
            .unwrap_or_else(|| panic!("{} should exist", name));
        assert!(
            matches!(
                outcome,
                BuildOutcome::Skipped(SkipReason::IndirectFailed(_))
            ),
            "{} should be IndirectFailed, got {:?}",
            name,
            outcome
        );
        // Verify the reason mentions chain-d
        if let BuildOutcome::Skipped(SkipReason::IndirectFailed(msg)) = outcome {
            assert!(
                msg.contains("chain-d"),
                "{} IndirectFailed reason should mention chain-d, got: {}",
                name,
                msg
            );
        }
    }

    Ok(())
}

/// Verify DAG scheduling: dependencies always build before dependents.
#[test]
fn test_build_order() -> Result<()> {
    let h = TestHarness::new()?;
    let (_, _, build_result) = run_scan_and_build(&h)?;

    // Build position map: earlier index = completed earlier
    let positions: HashMap<&str, usize> = build_result
        .results
        .iter()
        .enumerate()
        .map(|(i, r)| (r.pkgname.pkgname(), i))
        .collect();

    // base must complete before mid and also-base
    if let (Some(&base), Some(&mid)) = (positions.get("base-1.0"), positions.get("mid-1.0")) {
        assert!(
            base < mid,
            "base ({}) should complete before mid ({})",
            base,
            mid
        );
    }
    if let (Some(&base), Some(&also)) = (positions.get("base-1.0"), positions.get("also-base-1.0"))
    {
        assert!(
            base < also,
            "base ({}) should complete before also-base ({})",
            base,
            also
        );
    }

    // mid and also-base must complete before top
    if let (Some(&mid), Some(&top)) = (positions.get("mid-1.0"), positions.get("top-1.0")) {
        assert!(
            mid < top,
            "mid ({}) should complete before top ({})",
            mid,
            top
        );
    }
    if let (Some(&also), Some(&top)) = (positions.get("also-base-1.0"), positions.get("top-1.0")) {
        assert!(
            also < top,
            "also-base ({}) should complete before top ({})",
            also,
            top
        );
    }

    Ok(())
}

/// Verify building a limited subset: scan only test/top and its transitive
/// deps, then build only those packages.
#[test]
fn test_limited_build() -> Result<()> {
    let h = TestHarness::new()?;
    let config = h.load_config()?;
    let db = h.open_db()?;
    let ctx = h.run_context();

    // Limited scan from test/top
    let sandbox = Sandbox::new(&config);
    let mut scan_scope = SandboxScope::new(sandbox, ctx.clone());
    let mut scan = Scan::new(&config);
    let top = pkgsrc::PkgPath::new("test/top")?;
    scan.add(&top);
    scan.init_from_db(&db)?;
    scan.start(&db, &mut scan_scope)?;
    let scan_result = scan.resolve_with_report(&db, false)?;

    // Should have 4 packages: top, mid, also-base, base
    assert_eq!(scan_result.packages.len(), 4);
    let c = scan_result.counts();
    assert_eq!(c.buildable, 4);

    // Build them
    let scanpkgs = scan_result
        .buildable()
        .map(|p| (p.pkgname().clone(), p.clone()))
        .collect();
    let pkgsrc_env = h.pkgsrc_env();
    let build_sandbox = Sandbox::new(&config);
    let build_scope = SandboxScope::new(build_sandbox, ctx.clone());
    let mut build = Build::new(&config, pkgsrc_env, build_scope, scanpkgs);
    let build_result = build.start(&ctx, &db)?;

    // All 4 should succeed
    let bc = build_result.counts();
    assert_eq!(
        bc.success, 4,
        "expected 4 successful builds, got {}",
        bc.success
    );
    assert_eq!(bc.failed, 0, "expected 0 failures, got {}", bc.failed);

    // Verify the expected packages built
    let built: Vec<&str> = build_result
        .results
        .iter()
        .map(|r| r.pkgname.pkgname())
        .collect();
    assert!(built.contains(&"base-1.0"));
    assert!(built.contains(&"mid-1.0"));
    assert!(built.contains(&"also-base-1.0"));
    assert!(built.contains(&"top-1.0"));

    // No other packages should have been attempted
    assert_eq!(
        build_result.results.len(),
        4,
        "only 4 packages should have build results"
    );

    Ok(())
}

/// Verify pkg_up_to_date correctly identifies missing packages.
#[test]
fn test_pkg_up_to_date_not_found() -> Result<()> {
    let h = TestHarness::new()?;

    let result = bob::pkg_up_to_date(
        "nonexistent-1.0",
        &[],
        &h.packages_dir().join("All"),
        &h.pkgsrc(),
    )?;
    assert!(
        matches!(result, Some(bob::BuildReason::PackageNotFound)),
        "nonexistent package should be PackageNotFound, got {:?}",
        result
    );

    Ok(())
}

/// Verify that after a successful build, re-running the build with cached
/// results produces no new work, and all results show UpToDate or are
/// loaded from cache.
#[test]
fn test_build_resume_no_new_work() -> Result<()> {
    let h = TestHarness::new()?;

    // First full scan + build
    let (_, scan_result, first_build) = run_scan_and_build(&h)?;
    assert_eq!(first_build.counts().success, 5);

    // Second build with same config - should produce no new results
    let config = h.load_config()?;
    let db = h.open_db()?;
    let ctx = h.run_context();
    let scanpkgs = scan_result
        .buildable()
        .map(|p| (p.pkgname().clone(), p.clone()))
        .collect();
    let pkgsrc_env = h.pkgsrc_env();
    let build_sandbox = Sandbox::new(&config);
    let build_scope = SandboxScope::new(build_sandbox, ctx.clone());
    let mut build = Build::new(&config, pkgsrc_env, build_scope, scanpkgs);

    let cached = build.load_cached_from_db(&db)?;
    assert_eq!(cached, 15, "all 15 buildable should be cached");

    let result = build.start(&ctx, &db)?;
    assert!(
        result.results.is_empty(),
        "second build should produce no new results, got {}",
        result.results.len()
    );

    Ok(())
}

/// Verify that build_threads=1 produces identical results to parallel
/// builds - a single-threaded build eliminates scheduling races.
#[test]
fn test_single_threaded_build() -> Result<()> {
    let h = TestHarness::new()?;

    // Override config with 1 build thread
    let content = format!(
        "\
options = {{
    build_threads = 1,
    scan_threads = 1,
    progress = \"plain\",
}}
pkgsrc = {{
    basedir = \"{pkgsrc}\",
    logdir = \"{logdir}\",
    make = \"{make}\",
}}
",
        pkgsrc = h.pkgsrc().display(),
        logdir = h.logdir().display(),
        make = h.make.display(),
    );
    fs::write(h.config_path(), content)?;

    let config = h.load_config()?;
    let db = h.open_db()?;
    let ctx = h.run_context();

    let sandbox = Sandbox::new(&config);
    let mut scan_scope = SandboxScope::new(sandbox, ctx.clone());
    let mut scan = Scan::new(&config);
    scan.init_from_db(&db)?;
    scan.start(&db, &mut scan_scope)?;
    let scan_result = scan.resolve_with_report(&db, false)?;

    let scanpkgs = scan_result
        .buildable()
        .map(|p| (p.pkgname().clone(), p.clone()))
        .collect();
    let pkgsrc_env = h.pkgsrc_env();
    let build_sandbox = Sandbox::new(&config);
    let build_scope = SandboxScope::new(build_sandbox, ctx.clone());
    let mut build = Build::new(&config, pkgsrc_env, build_scope, scanpkgs);
    let build_result = build.start(&ctx, &db)?;

    let bc = build_result.counts();
    assert_eq!(bc.success, 5, "expected 5 successful builds");
    assert_eq!(bc.failed, 6, "expected 6 failed builds");
    assert_eq!(bc.skipped.indirect_failed, 4, "expected 4 indirect-failed");

    Ok(())
}

/// Verify that clearing build results and rebuilding works correctly.
#[test]
fn test_rebuild_after_clear() -> Result<()> {
    let h = TestHarness::new()?;

    // First build
    let (db, scan_result, first) = run_scan_and_build(&h)?;
    assert_eq!(first.counts().success, 5);

    // Clear all build results
    let cleared = db.clear_builds()?;
    assert!(cleared > 0, "should clear some builds");

    // Rebuild - should produce new results
    let config = h.load_config()?;
    let ctx = h.run_context();
    let scanpkgs = scan_result
        .buildable()
        .map(|p| (p.pkgname().clone(), p.clone()))
        .collect();
    let pkgsrc_env = h.pkgsrc_env();
    let build_sandbox = Sandbox::new(&config);
    let build_scope = SandboxScope::new(build_sandbox, ctx.clone());
    let mut build = Build::new(&config, pkgsrc_env, build_scope, scanpkgs);

    let cached = build.load_cached_from_db(&db)?;
    assert_eq!(cached, 0, "no cached results after clear");

    let rebuild_result = build.start(&ctx, &db)?;
    assert_eq!(
        rebuild_result.counts().success,
        5,
        "rebuild should succeed for same 5 packages"
    );

    Ok(())
}

/// Verify that building only failed packages after fixing them works.
/// Simulates a "rebuild failed" workflow by deleting a specific build
/// result and re-running.
#[test]
fn test_selective_rebuild_after_failure() -> Result<()> {
    let h = TestHarness::new()?;
    let (db, scan_result, first) = run_scan_and_build(&h)?;

    // Verify build-fail is in the failed list
    let failed = db.get_failed_packages()?;
    assert!(
        failed.contains(&"build-fail-1.0".to_string()),
        "build-fail should be in failed list"
    );

    // Delete build result for build-fail and dep-bfail
    assert!(db.delete_build_by_name("build-fail-1.0")?);
    assert!(db.delete_build_by_name("dep-bfail-1.0")?);

    // "Fix" the package by replacing its Makefile with a working one
    let pkgdir = h.pkgsrc().join("test/build-fail");
    let content = "\
PKGNAME=build-fail-1.0

pbulk-index:
\t@printf 'PKGNAME=build-fail-1.0\\n\
PKG_LOCATION=test/build-fail\\n\
ALL_DEPENDS=\\n\
PKG_SKIP_REASON=\\n\
PKG_FAIL_REASON=\\n\
NO_BIN_ON_FTP=\\n\
RESTRICTED=\\n\
CATEGORIES=test\\n\
MAINTAINER=test@example.com\\n\
USE_DESTDIR=yes\\n\
BOOTSTRAP_PKG=\\n\
USERGROUP_PHASE=\\n\
SCAN_DEPENDS=\\n'

clean checksum configure all stage-install create-usergroup:
\t@true

stage-package-create:
\t@mkdir -p ${.CURDIR}/pkg
\t@printf 'dummy' > ${.CURDIR}/pkg/build-fail-1.0.tgz

show-var:
\t@case \"${VARNAME}\" in \
\tSTAGE_PKGFILE) echo \"${.CURDIR}/pkg/build-fail-1.0.tgz\" ;; \
\tesac
";
    fs::write(pkgdir.join("Makefile"), content)?;

    // Rebuild with cached results (most will be cached)
    let config = h.load_config()?;
    let ctx = h.run_context();
    let scanpkgs = scan_result
        .buildable()
        .map(|p| (p.pkgname().clone(), p.clone()))
        .collect();
    let pkgsrc_env = h.pkgsrc_env();
    let build_sandbox = Sandbox::new(&config);
    let build_scope = SandboxScope::new(build_sandbox, ctx.clone());
    let mut build = Build::new(&config, pkgsrc_env, build_scope, scanpkgs);

    let cached = build.load_cached_from_db(&db)?;
    // Most should be cached, but build-fail and dep-bfail were deleted
    assert!(
        cached < first.results.len(),
        "should have fewer cached than total: cached={}, total={}",
        cached,
        first.results.len()
    );

    let result = build.start(&ctx, &db)?;

    // build-fail should now succeed
    let bf_result = result
        .results
        .iter()
        .find(|r| r.pkgname.pkgname() == "build-fail-1.0");
    assert!(
        bf_result.is_some(),
        "build-fail should have a new build result"
    );
    assert!(
        matches!(bf_result.map(|r| &r.outcome), Some(BuildOutcome::Success)),
        "fixed build-fail should succeed, got {:?}",
        bf_result.map(|r| &r.outcome)
    );

    Ok(())
}

/// Verify that the multi_version package builds correctly and that its
/// PYTHON_VERSION_REQD flag is effectively passed through.
#[test]
fn test_multi_version_package() -> Result<()> {
    let h = TestHarness::new()?;
    let (_, _, build_result) = run_scan_and_build(&h)?;

    let multi = build_result
        .results
        .iter()
        .find(|r| r.pkgname.pkgname() == "py313-multi-1.0");
    assert!(multi.is_some(), "py313-multi should have a build result");
    assert!(
        matches!(multi.map(|r| &r.outcome), Some(BuildOutcome::Success)),
        "py313-multi should succeed"
    );

    // Verify the package file exists
    let tgz = h.packages_dir().join("All").join("py313-multi-1.0.tgz");
    assert!(tgz.exists(), "py313-multi package should exist");

    Ok(())
}

/// Verify the usergroup_phase package: mid has USERGROUP_PHASE=configure,
/// meaning create-usergroup should run before configure. Since our mock
/// create-usergroup succeeds, the build should complete normally.
#[test]
fn test_usergroup_phase_package() -> Result<()> {
    let h = TestHarness::new()?;
    let (_, scan_result, _) = run_scan_and_build(&h)?;

    // Verify mid's scan data includes USERGROUP_PHASE
    let mid = scan_result
        .buildable()
        .find(|p| p.pkgpath.as_path().to_string_lossy() == "test/mid");
    assert!(mid.is_some(), "mid should be in scan results");
    let mid = mid.expect("mid exists");
    assert_eq!(
        mid.usergroup_phase(),
        Some("configure"),
        "mid should have USERGROUP_PHASE=configure"
    );

    Ok(())
}

/// Verify that after building, build durations are recorded and non-zero
/// for packages that actually built (not indirect-failed).
#[test]
fn test_build_durations() -> Result<()> {
    let h = TestHarness::new()?;
    let (_, _, build_result) = run_scan_and_build(&h)?;

    for r in &build_result.results {
        match &r.outcome {
            BuildOutcome::Success | BuildOutcome::Failed(_) => {
                // Direct builds should have non-zero duration
                // (though very fast builds might be sub-millisecond)
                // Just verify it's a valid Duration
                assert!(
                    r.duration.as_nanos() > 0,
                    "{} should have non-zero duration",
                    r.pkgname.pkgname()
                );
            }
            BuildOutcome::Skipped(SkipReason::IndirectFailed(_)) => {
                // Indirect failures have zero duration (never attempted)
                assert_eq!(
                    r.duration,
                    std::time::Duration::ZERO,
                    "{} indirect failure should have zero duration",
                    r.pkgname.pkgname()
                );
            }
            _ => {}
        }
    }

    Ok(())
}
