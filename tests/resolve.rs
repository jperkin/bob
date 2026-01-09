//! Integration tests for dependency resolution using real pkgsrc scan data.

use anyhow::Result;
use bob::Scan;
use bob::db::Database;
use bob::scan::ScanSummary;
use indexmap::IndexMap;
use pkgsrc::ScanIndex;
use std::fs::File;
use std::io::BufReader;
use std::sync::OnceLock;
use tempfile::TempDir;

const PSCAN_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pscan.zstd");

/// Cached scan result and import count, initialized once.
static SCAN_DATA: OnceLock<(ScanSummary, usize)> = OnceLock::new();

/// Get or initialize the scan result (imports pscan and resolves once).
fn get_scan_result() -> &'static (ScanSummary, usize) {
    SCAN_DATA.get_or_init(|| {
        let tmp = TempDir::new().expect("failed to create tempdir");
        let db_path = tmp.path().join("test.db");
        let db = Database::open(&db_path).expect("failed to open db");

        let count =
            import_pscan(&db, PSCAN_PATH).expect("failed to import pscan");

        let mut scan = Scan::default();
        scan.init_from_db(&db).expect("failed to init scan");
        let result = scan.resolve(&db).expect("failed to resolve");

        (result, count)
    })
}

/// Import a zstd-compressed pscan file into a database.
fn import_pscan(db: &Database, path: &str) -> Result<usize> {
    let file = File::open(path)?;
    let decoder = zstd::stream::Decoder::new(file)?;
    let reader = BufReader::new(decoder);

    let mut by_pkgpath: IndexMap<String, Vec<ScanIndex>> = IndexMap::new();
    let mut count = 0;

    for result in ScanIndex::from_reader(reader) {
        let index = result?;
        let pkgpath = index
            .pkg_location
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        by_pkgpath.entry(pkgpath).or_default().push(index);
        count += 1;
    }

    db.clear_scan()?;
    for (pkgpath, indexes) in &by_pkgpath {
        db.store_scan_pkgpath(pkgpath, indexes)?;
    }

    Ok(count)
}

#[test]
fn resolve_full_tree() -> Result<()> {
    let (result, imported) = get_scan_result();

    assert_eq!(*imported, 29022, "expected 29022 packages in pscan");

    // Verify counts match expected values from this dataset
    let c = result.counts();
    assert_eq!(c.buildable, 27370);
    assert_eq!(c.skipped.pkg_skip, 1148);
    assert_eq!(c.skipped.pkg_fail, 175);
    assert_eq!(c.skipped.indirect_skip, 277);
    assert_eq!(c.skipped.indirect_fail, 46);
    assert_eq!(c.skipped.unresolved, 6);

    // Total should match imported count
    assert_eq!(result.packages.len(), *imported);

    Ok(())
}

#[test]
fn resolve_presolve_output() -> Result<()> {
    use std::io::BufRead;

    let (result, _) = get_scan_result();

    // Stream expected baseline
    let expected_path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/presolve.zstd");
    let file = File::open(expected_path)?;
    let decoder = zstd::stream::Decoder::new(file)?;
    let mut expected_lines = BufReader::new(decoder).lines();

    // Compare line by line, streaming both sides
    let mut line_num = 0;
    for pkg in &result.packages {
        for actual_line in pkg.to_string().lines() {
            line_num += 1;
            match expected_lines.next() {
                Some(Ok(expected_line)) if expected_line == actual_line => {}
                Some(Ok(expected_line)) => {
                    panic!(
                        "presolve mismatch at line {}:\n  expected: {}\n  actual:   {}",
                        line_num, expected_line, actual_line
                    );
                }
                Some(Err(e)) => panic!("error reading expected: {}", e),
                None => panic!(
                    "actual output has more lines than expected (line {})",
                    line_num
                ),
            }
        }
    }

    // Check for trailing expected lines
    if let Some(line) = expected_lines.next() {
        panic!(
            "expected output has more lines than actual (line {}): {}",
            line_num + 1,
            line?
        );
    }

    Ok(())
}

#[test]
fn resolve_errors_accurate() -> Result<()> {
    use std::collections::HashSet;

    let (result, _) = get_scan_result();

    let unresolved = [
        ("py311-buildbot-[0-9]*", "py311-buildbot-badges-2.6.0nb1"),
        ("py311-buildbot-[0-9]*", "py311-buildbot-waterfall-view-2.6.0nb1"),
        ("py311-stevedore>=1.20.0", "py311-e3-core-22.10.0nb3"),
        ("py312-daemon>=2.3.0", "py312-libagent-0.15.0"),
        ("py313-daemon>=2.3.0", "py313-libagent-0.15.0"),
        ("py314-daemon>=2.3.0", "py314-libagent-0.15.0"),
    ];

    let expected: HashSet<String> = unresolved
        .iter()
        .map(|(dep, pkg)| {
            format!("No match found for dependency {dep} of package {pkg}")
        })
        .collect();

    let actual: HashSet<String> = result.errors().map(String::from).collect();

    assert_eq!(actual, expected);

    Ok(())
}

/// Parse synthetic scan data from text format.
fn parse_scan_data(data: &str) -> Vec<(String, ScanIndex)> {
    let reader = std::io::BufReader::new(data.as_bytes());
    ScanIndex::from_reader(reader)
        .map(|r| {
            let index = r.expect("failed to parse scan index");
            let pkgpath = index
                .pkg_location
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            (pkgpath, index)
        })
        .collect()
}

/// Import synthetic scan data into a database.
fn import_synthetic(db: &Database, data: &str) -> Result<()> {
    db.clear_scan()?;
    for (pkgpath, index) in parse_scan_data(data) {
        db.store_scan_pkgpath(&pkgpath, &[index])?;
    }
    Ok(())
}

#[test]
fn resolve_circular_dependencies() -> Result<()> {
    // Circular: A -> B -> C -> A
    let data = r#"PKGNAME=a-1.0
PKG_LOCATION=test/a
ALL_DEPENDS=b-[0-9]*:test/b
PKG_SKIP_REASON=
PKG_FAIL_REASON=
PKGNAME=b-1.0
PKG_LOCATION=test/b
ALL_DEPENDS=c-[0-9]*:test/c
PKG_SKIP_REASON=
PKG_FAIL_REASON=
PKGNAME=c-1.0
PKG_LOCATION=test/c
ALL_DEPENDS=a-[0-9]*:test/a
PKG_SKIP_REASON=
PKG_FAIL_REASON=
"#;

    let tmp = TempDir::new()?;
    let db_path = tmp.path().join("test.db");
    let db = Database::open(&db_path)?;

    import_synthetic(&db, data)?;

    let mut scan = Scan::default();
    scan.init_from_db(&db)?;
    let result = scan.resolve(&db);

    // Should fail with circular dependency error
    assert!(result.is_err(), "circular dependencies should be detected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Circular dependencies detected"),
        "error should mention circular dependencies: {err}"
    );

    Ok(())
}
