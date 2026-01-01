use anyhow::Result;
use bob::Scan;
use indexmap::IndexMap;
use pkgsrc::{Depend, PkgName, PkgPath, ScanIndex};

fn make_pkg(name: &str, path: &str) -> Result<ScanIndex> {
    Ok(ScanIndex {
        pkgname: PkgName::new(name),
        pkg_location: Some(PkgPath::new(path)?),
        all_depends: None,
        pkg_skip_reason: None,
        pkg_fail_reason: None,
        categories: None,
        maintainer: None,
        use_destdir: None,
        bootstrap_pkg: None,
        usergroup_phase: None,
        scan_depends: None,
        pbulk_weight: None,
        multi_version: None,
        no_bin_on_ftp: None,
        restricted: None,
    })
}

fn make_pkg_with_deps(
    name: &str,
    path: &str,
    deps: Vec<&str>,
) -> Result<ScanIndex> {
    let mut deps_vec = Vec::new();
    for d in deps {
        deps_vec.push(Depend::new(d)?);
    }
    Ok(ScanIndex { all_depends: Some(deps_vec), ..make_pkg(name, path)? })
}

fn make_pkg_skipped(name: &str, path: &str, reason: &str) -> Result<ScanIndex> {
    Ok(ScanIndex {
        pkg_skip_reason: Some(reason.to_string()),
        ..make_pkg(name, path)?
    })
}

fn make_pkg_failed(name: &str, path: &str, reason: &str) -> Result<ScanIndex> {
    Ok(ScanIndex {
        pkg_fail_reason: Some(reason.to_string()),
        ..make_pkg(name, path)?
    })
}

fn build_cache(
    packages: Vec<ScanIndex>,
) -> Result<IndexMap<PkgPath, Vec<ScanIndex>>> {
    let mut cache: IndexMap<PkgPath, Vec<ScanIndex>> = IndexMap::new();
    for pkg in packages {
        let path = pkg.pkg_location.clone().ok_or_else(|| {
            anyhow::anyhow!("test package missing pkg_location")
        })?;
        cache.entry(path).or_default().push(pkg);
    }
    Ok(cache)
}

fn setup_scan(packages: Vec<ScanIndex>) -> Result<Scan> {
    let mut scan = Scan::default();
    for pkg in &packages {
        if let Some(ref path) = pkg.pkg_location {
            scan.add(path);
        }
    }
    scan.load_cached(build_cache(packages)?);
    Ok(scan)
}

#[test]
fn single_package_no_deps() -> Result<()> {
    let pkg1 = make_pkg("libnbcompat-20251029", "pkgtools/libnbcompat")?;

    let mut scan = setup_scan(vec![pkg1])?;
    let res = scan.resolve()?;

    assert_eq!(res.buildable.len(), 1);
    assert!(res.buildable.contains_key(&PkgName::new("libnbcompat-20251029")));
    assert!(res.skipped.is_empty());
    Ok(())
}

#[test]
fn single_package_dep() -> Result<()> {
    let pkg1 = make_pkg("libnbcompat-20251029", "pkgtools/libnbcompat")?;
    let pkg2 = make_pkg_with_deps(
        "cwrappers-20220403",
        "pkgtools/cwrappers",
        vec!["libnbcompat>=20221013:../../pkgtools/libnbcompat"],
    )?;

    let mut scan = setup_scan(vec![pkg1, pkg2])?;
    let res = scan.resolve()?;

    assert_eq!(res.buildable.len(), 2);
    let resolved = res
        .buildable
        .get(&PkgName::new("cwrappers-20220403"))
        .ok_or_else(|| anyhow::anyhow!("cwrappers not found"))?;
    assert_eq!(resolved.depends.len(), 1);
    assert_eq!(resolved.depends[0], PkgName::new("libnbcompat-20251029"));
    Ok(())
}

#[test]
fn best_match_highest_version() -> Result<()> {
    let pkg1 = make_pkg("bar-1.0", "cat/bar")?;
    let pkg2 = make_pkg("bar-2.0", "cat/bar")?;
    let pkg3 = make_pkg_with_deps(
        "foo-1.0",
        "cat/foo",
        vec!["bar-[0-9]*:../../cat/bar"],
    )?;

    let mut scan = setup_scan(vec![pkg1, pkg2, pkg3])?;
    let res = scan.resolve()?;

    assert_eq!(res.buildable.len(), 3);
    let resolved = res
        .buildable
        .get(&PkgName::new("foo-1.0"))
        .ok_or_else(|| anyhow::anyhow!("foo not found"))?;
    assert_eq!(resolved.depends.len(), 1);
    assert_eq!(resolved.depends[0], PkgName::new("bar-2.0"));
    Ok(())
}

#[test]
fn best_match_prefers_larger_name_on_tie() -> Result<()> {
    let pkg1 = make_pkg("mpg123-1.33.4", "audio/mpg123")?;
    let pkg2 = make_pkg("mpg123-esound-1.33.4", "audio/mpg123-esound")?;
    let pkg3 = make_pkg("mpg123-nas-1.33.4", "audio/mpg123-nas")?;
    let pkg4 = make_pkg_with_deps(
        "gqmpeg-0.91.1nb52",
        "audio/gqmpeg-devel",
        vec!["mpg123{,-esound,-nas}>=0.59.18:../../audio/mpg123"],
    )?;

    let mut scan = setup_scan(vec![pkg1, pkg2, pkg3, pkg4])?;
    let res = scan.resolve()?;

    let resolved = res
        .buildable
        .get(&PkgName::new("gqmpeg-0.91.1nb52"))
        .ok_or_else(|| anyhow::anyhow!("gqmpeg not found"))?;
    assert_eq!(resolved.depends[0], PkgName::new("mpg123-nas-1.33.4"));
    Ok(())
}

#[test]
fn skip_propagation_from_skip_reason() -> Result<()> {
    let pkg1 = make_pkg_skipped("bar-1.0", "cat/bar", "not supported")?;
    let pkg2 = make_pkg_with_deps(
        "foo-1.0",
        "cat/foo",
        vec!["bar-[0-9]*:../../cat/bar"],
    )?;

    let mut scan = setup_scan(vec![pkg1, pkg2])?;
    let res = scan.resolve()?;

    assert!(res.buildable.is_empty());
    assert_eq!(res.skipped.len(), 2);
    Ok(())
}

#[test]
fn skip_propagation_from_fail_reason() -> Result<()> {
    let pkg1 = make_pkg_failed("bar-1.0", "cat/bar", "build fails")?;
    let pkg2 = make_pkg_with_deps(
        "foo-1.0",
        "cat/foo",
        vec!["bar-[0-9]*:../../cat/bar"],
    )?;

    let mut scan = setup_scan(vec![pkg1, pkg2])?;
    let res = scan.resolve()?;

    assert!(res.buildable.is_empty());
    assert_eq!(res.skipped.len(), 2);
    Ok(())
}

#[test]
fn unresolvable_dependency() -> Result<()> {
    let pkg1 = make_pkg_with_deps(
        "foo-1.0",
        "cat/foo",
        vec!["bar-[0-9]*:../../cat/bar"],
    )?;

    let mut scan = setup_scan(vec![pkg1])?;
    let res = scan.resolve();

    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(err.contains("bar"));
    Ok(())
}

#[test]
fn circular_dependency() -> Result<()> {
    let pkg1 = make_pkg_with_deps(
        "foo-1.0",
        "cat/foo",
        vec!["bar-[0-9]*:../../cat/bar"],
    )?;
    let pkg2 = make_pkg_with_deps(
        "bar-1.0",
        "cat/bar",
        vec!["foo-[0-9]*:../../cat/foo"],
    )?;

    let mut scan = setup_scan(vec![pkg1, pkg2])?;
    let res = scan.resolve();

    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(err.contains("Circular"));
    Ok(())
}

#[test]
fn transitive_skip_propagation() -> Result<()> {
    let pkg1 = make_pkg_skipped("baz-1.0", "cat/baz", "broken")?;
    let pkg2 = make_pkg_with_deps(
        "bar-1.0",
        "cat/bar",
        vec!["baz-[0-9]*:../../cat/baz"],
    )?;
    let pkg3 = make_pkg_with_deps(
        "foo-1.0",
        "cat/foo",
        vec!["bar-[0-9]*:../../cat/bar"],
    )?;

    let mut scan = setup_scan(vec![pkg1, pkg2, pkg3])?;
    let res = scan.resolve()?;

    assert!(res.buildable.is_empty());
    assert_eq!(res.skipped.len(), 3);
    Ok(())
}

#[test]
fn mixed_buildable_and_skipped() -> Result<()> {
    let pkg1 = make_pkg("good-1.0", "cat/good")?;
    let pkg2 = make_pkg_skipped("bad-1.0", "cat/bad", "broken")?;

    let mut scan = setup_scan(vec![pkg1, pkg2])?;
    let res = scan.resolve()?;

    assert_eq!(res.buildable.len(), 1);
    assert!(res.buildable.contains_key(&PkgName::new("good-1.0")));
    assert_eq!(res.skipped.len(), 1);
    Ok(())
}

#[test]
fn diamond_dependency() -> Result<()> {
    let pkg1 = make_pkg("base-1.0", "cat/base")?;
    let pkg2 = make_pkg_with_deps(
        "left-1.0",
        "cat/left",
        vec!["base-[0-9]*:../../cat/base"],
    )?;
    let pkg3 = make_pkg_with_deps(
        "right-1.0",
        "cat/right",
        vec!["base-[0-9]*:../../cat/base"],
    )?;
    let pkg4 = make_pkg_with_deps(
        "top-1.0",
        "cat/top",
        vec!["left-[0-9]*:../../cat/left", "right-[0-9]*:../../cat/right"],
    )?;

    let mut scan = setup_scan(vec![pkg1, pkg2, pkg3, pkg4])?;
    let res = scan.resolve()?;

    assert_eq!(res.buildable.len(), 4);
    let resolved = res
        .buildable
        .get(&PkgName::new("top-1.0"))
        .ok_or_else(|| anyhow::anyhow!("top not found"))?;
    assert_eq!(resolved.depends.len(), 2);
    Ok(())
}

#[test]
fn resolve_reports_pattern_error_on_overflow_version() -> Result<()> {
    let pkg1 = make_pkg("lib-1.0", "libs/lib")?;
    let pkg2 = make_pkg("lib-20251208143052123456", "libs/lib")?;
    let pkg3 = make_pkg_with_deps(
        "app-1.0",
        "cat/app",
        vec!["lib-[0-9]*:../../libs/lib"],
    )?;

    let mut scan = setup_scan(vec![pkg1, pkg2, pkg3])?;
    let res = scan.resolve();

    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(err.contains("Pattern error for lib-[0-9]*"));
    assert!(err.contains("app-1.0"));
    Ok(())
}
