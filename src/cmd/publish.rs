/*
 * Copyright (c) 2026 Jonathan Perkin <jonathan@perkin.org.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*!
 * Implementation of the `bob publish` command.
 *
 * Package publishing uses rsync with `--link-dest` for space-efficient
 * atomic updates.  The flow is:
 *
 * 1. Rsync to a temporary staging directory with `--link-dest` pointing
 *    at the current live directory (unchanged files become hardlinks).
 * 2. Atomically swap the staging directory into place via ssh, removing
 *    the previous live directory.
 *
 * Restricted packages (those with `NO_BIN_ON_FTP` set) are excluded
 * from the upload filter list.
 *
 * Report publishing generates HTML, text, and machine-readable reports
 * then rsyncs the log directory to a remote server.  The build ID is
 * appended to the remote path so each run gets its own directory.
 */

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use glob::Pattern;
use tracing::{debug, info};

use bob::build::{BuildResult, BuildSummary, PkgBuildStats};
use bob::config::{Config, Publish, PublishPackages};
use bob::db::Database;
use bob::{PackageState, PackageStateKind};

struct PublishResult {
    uploaded: usize,
    restricted: usize,
}

pub fn run(
    config: &Config,
    db: &Database,
    packages: bool,
    report: bool,
    email: bool,
    dry_run: bool,
) -> Result<()> {
    let build_id = db.build_id()?;

    if packages {
        let result = publish_packages(config, db, dry_run)?;
        println!(
            "Published {} packages ({} restricted excluded)",
            result.uploaded, result.restricted
        );
    }

    if report || email {
        generate_reports(config, db, &build_id)?;
    }

    if report {
        publish_report(config, &build_id, dry_run)?;
    }

    if email {
        send_email(config, db, &build_id, dry_run)?;
    }

    Ok(())
}

fn publish_packages(config: &Config, db: &Database, dry_run: bool) -> Result<PublishResult> {
    let publish = config
        .publish()
        .ok_or_else(|| anyhow::anyhow!("No publish section in configuration"))?;
    let packages = publish
        .packages
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No publish.packages section in configuration"))?;

    let pkgsrc_env = db.load_pkgsrc_env()?;
    let successful = db.get_successful_packages()?;

    validate_pre_publish(packages, &successful)?;

    println!("Publishing packages...");

    let restricted = db.get_restricted_packages()?;
    if !restricted.is_empty() {
        info!(count = restricted.len(), "Excluding restricted packages");
    }

    let uploadable: Vec<&String> = successful
        .iter()
        .filter(|p| !restricted.contains(p.as_str()))
        .collect();

    info!(
        total = successful.len(),
        uploadable = uploadable.len(),
        restricted = restricted.len(),
        "Package counts"
    );

    let filter_path = config.dbdir().join("rsync-filter");
    write_rsync_filter(&uploadable, &filter_path)?;

    let result = run_rsync(
        publish,
        packages,
        &filter_path,
        &pkgsrc_env.packages,
        dry_run,
    );

    let _ = std::fs::remove_file(&filter_path);
    result?;

    run_ssh_swap(publish, packages, dry_run)?;

    Ok(PublishResult {
        uploaded: uploadable.len(),
        restricted: restricted.len(),
    })
}

fn generate_reports(config: &Config, db: &Database, build_id: &str) -> Result<()> {
    let publish = config
        .publish()
        .ok_or_else(|| anyhow::anyhow!("No publish section in configuration"))?;
    let report_cfg = publish
        .report
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No publish.report section in configuration"))?;

    let pkgsrc_env = db.load_pkgsrc_env()?;
    let vcs_info = db.load_vcs_info().unwrap_or_default();
    let logdir = config.logdir();

    std::fs::create_dir_all(logdir)
        .with_context(|| format!("Failed to create {}", logdir.display()))?;

    write_variables_json(&pkgsrc_env, &vcs_info, logdir)?;

    let report_path = logdir.join("report.html");
    let report_meta = ReportMeta {
        build_id,
        pkgsrc_env: &pkgsrc_env,
        vcs_info: &vcs_info,
    };

    let report_url = report_cfg
        .url
        .as_ref()
        .map(|u| format!("{}/{}", u, build_id));

    println!("Generating report...");
    write_html_report(db, logdir, &report_path, &report_meta)?;
    write_machine_report(db, logdir)?;
    write_text_report(db, logdir, &report_meta, report_url.as_deref())?;

    Ok(())
}

fn publish_report(config: &Config, build_id: &str, dry_run: bool) -> Result<()> {
    let publish = config
        .publish()
        .ok_or_else(|| anyhow::anyhow!("No publish section in configuration"))?;
    let report_cfg = publish
        .report
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No publish.report section in configuration"))?;

    let logdir = config.logdir();
    let rsync_args = report_cfg
        .rsync_args
        .as_deref()
        .unwrap_or(&publish.rsync_args);

    let target = format!(
        "{}:{}/{}",
        format_remote(&report_cfg.host, report_cfg.user.as_deref()),
        report_cfg.path,
        build_id
    );

    info!(
        target = %target,
        source = %logdir.display(),
        build_id = %build_id,
        "Publishing report"
    );

    let mut cmd = Command::new(&publish.rsync);
    for arg in rsync_args.split_whitespace() {
        cmd.arg(arg);
    }
    if dry_run {
        cmd.arg("--dry-run");
    }
    cmd.arg(".").arg(&target);
    cmd.current_dir(logdir);

    debug!(cmd = ?cmd, "Running rsync for report");
    let status = cmd.status().context("Failed to execute rsync")?;
    if !status.success() {
        bail!(
            "rsync failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }

    if !dry_run {
        let report_url = report_cfg
            .url
            .as_ref()
            .map(|u| format!("{}/{}", u, build_id));
        if let Some(url) = &report_url {
            println!("Report available at: {}/report.html", url);
        }
    }

    Ok(())
}

// ========================================================================
// PRE-PUBLISH VALIDATION
// ========================================================================

fn send_email(config: &Config, db: &Database, build_id: &str, dry_run: bool) -> Result<()> {
    let publish = config
        .publish()
        .ok_or_else(|| anyhow::anyhow!("No publish section in configuration"))?;
    let report_cfg = publish
        .report
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No publish.report section in configuration"))?;

    let from_str = report_cfg
        .from
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("publish.report.from is required for email"))?;
    if report_cfg.to.is_empty() {
        bail!("publish.report.to is required for email");
    }

    let pkgsrc_env = db.load_pkgsrc_env()?;
    let vcs_info = db.load_vcs_info().unwrap_or_default();
    let platform = pkgsrc_env.platform().unwrap_or_default();
    let branch = report_cfg
        .branch
        .as_deref()
        .or(vcs_info.remote_branch.as_deref())
        .or(vcs_info.local_branch.as_deref())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Cannot determine branch for email subject. \
                 Set publish.report.branch in config."
            )
        })?;
    let date = chrono::NaiveDateTime::parse_from_str(build_id, "%Y%m%dT%H%M%SZ")
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .context("Failed to parse build ID as timestamp")?;
    let subject = format!("{} - {} - {}", branch, platform, date);

    let logdir = config.logdir();
    let body = std::fs::read_to_string(logdir.join("report.txt"))
        .context("Failed to read report.txt -- was the report generated?")?;

    use lettre::message::Mailbox;
    use lettre::{Message, SendmailTransport, Transport};

    let from: Mailbox = from_str
        .parse()
        .with_context(|| format!("Invalid from address: {}", from_str))?;

    let mut builder = Message::builder().from(from.clone()).subject(&subject);

    for addr in &report_cfg.to {
        let to: Mailbox = addr
            .parse()
            .with_context(|| format!("Invalid to address: {}", addr))?;
        builder = builder.to(to);
    }

    let message = builder
        .body(body)
        .context("Failed to build email message")?;

    if dry_run {
        info!("Dry run: would send email");
        println!("  From:    {}", from);
        println!("  To:      {}", report_cfg.to.join(", "));
        println!("  Subject: {}", subject);
        return Ok(());
    }

    let recipients = report_cfg.to.join(", ");
    println!("Sending report email to {}...", recipients);
    info!(from = %from, to = %recipients, subject = %subject, "Sending email");

    let mailer = SendmailTransport::new();
    mailer
        .send(&message)
        .context("Failed to send email via sendmail")?;
    Ok(())
}

fn validate_pre_publish(packages: &PublishPackages, successful: &[String]) -> Result<()> {
    if let Some(minimum) = packages.minimum {
        if successful.len() < minimum {
            bail!(
                "Only {} successful packages, minimum required is {}",
                successful.len(),
                minimum
            );
        }
    }

    for pattern_str in &packages.required {
        let pattern = Pattern::new(pattern_str).with_context(|| {
            format!(
                "Invalid glob pattern in publish.packages.required: {}",
                pattern_str
            )
        })?;
        let matched = successful.iter().any(|p| pattern.matches(p));
        if !matched {
            bail!(
                "Required pattern '{}' did not match any successful package",
                pattern_str
            );
        }
    }

    Ok(())
}

// ========================================================================
// RSYNC AND SSH
// ========================================================================

fn write_rsync_filter(packages: &[&String], path: &Path) -> Result<()> {
    let mut file = std::fs::File::create(path)
        .with_context(|| format!("Failed to create {}", path.display()))?;

    let mut lines: Vec<String> = vec![
        "+ All/".to_string(),
        "+ All/pkg_summary.bz2".to_string(),
        "+ All/pkg_summary.gz".to_string(),
        "+ All/pkg_summary.xz".to_string(),
        "+ All/pkg_summary.zst".to_string(),
    ];

    for pkgname in packages {
        lines.push(format!("+ All/{}.tgz", pkgname));
    }

    lines.sort();
    lines.push("- *".to_string());

    for line in &lines {
        writeln!(file, "{}", line)?;
    }
    file.flush()?;

    debug!(
        path = %path.display(),
        entries = lines.len(),
        "Wrote rsync filter"
    );

    Ok(())
}

fn run_rsync(
    publish: &Publish,
    packages: &PublishPackages,
    filter_path: &Path,
    packages_dir: &Path,
    dry_run: bool,
) -> Result<()> {
    let rsync_args = packages
        .rsync_args
        .as_deref()
        .unwrap_or(&publish.rsync_args);

    let mut cmd = Command::new(&publish.rsync);
    cmd.arg("--exclude-from").arg(filter_path);
    for arg in rsync_args.split_whitespace() {
        cmd.arg(arg);
    }
    cmd.arg("--partial-dir=.rsync-partial");
    cmd.arg(format!("--link-dest={}", packages.linkdest));
    if dry_run {
        cmd.arg("--dry-run");
    }
    cmd.arg(".");
    cmd.arg(format!(
        "{}:{}",
        format_remote(&packages.host, packages.user.as_deref()),
        packages.tmpdest
    ));
    cmd.current_dir(packages_dir);

    info!(
        remote = %format_remote(&packages.host, packages.user.as_deref()),
        tmpdest = %packages.tmpdest,
        linkdest = %packages.linkdest,
        "Running rsync"
    );
    debug!(cmd = ?cmd, "rsync command");

    let status = cmd.status().context("Failed to execute rsync")?;
    if !status.success() {
        bail!(
            "rsync failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }

    Ok(())
}

fn run_ssh_swap(publish: &Publish, packages: &PublishPackages, dry_run: bool) -> Result<()> {
    let script = format!(
        "if [ -f {tmpdest}/All/pkg_summary.gz ]; then \
             if [ -d {linkdest} ]; then \
                 mv {linkdest} {tmpdest}-old; \
             else \
                 mkdir -p $(dirname {linkdest}); \
             fi; \
             mv {tmpdest} {linkdest}; \
             rm -rf {tmpdest}-old; \
         fi",
        tmpdest = packages.tmpdest,
        linkdest = packages.linkdest,
    );

    if dry_run {
        info!("Dry run: would execute via ssh:");
        println!(
            "  ssh {} '{}'",
            format_remote(&packages.host, packages.user.as_deref()),
            script
        );
        return Ok(());
    }

    info!(remote = %format_remote(&packages.host, packages.user.as_deref()), "Performing atomic directory swap");

    let ssh = publish
        .rsync_args
        .split_whitespace()
        .skip_while(|a| *a != "-e")
        .nth(1)
        .unwrap_or("ssh");

    let status = Command::new(ssh)
        .arg(format_remote(&packages.host, packages.user.as_deref()))
        .arg(&script)
        .status()
        .context("Failed to execute ssh")?;

    if !status.success() {
        bail!(
            "ssh directory swap failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }

    Ok(())
}

fn format_remote(host: &str, user: Option<&str>) -> String {
    match user {
        Some(user) => format!("{}@{}", user, host),
        None => host.to_string(),
    }
}

// ========================================================================
// HTML REPORT GENERATION
// ========================================================================

const BUILD_PHASES: &[(&str, &str)] = &[
    ("pre-clean", "pre-clean.log"),
    ("depends", "depends.log"),
    ("checksum", "checksum.log"),
    ("configure", "configure.log"),
    ("build", "build.log"),
    ("install", "install.log"),
    ("package", "package.log"),
    ("deinstall", "deinstall.log"),
    ("clean", "clean.log"),
];

struct FailedPackageInfo<'a> {
    result: &'a BuildResult,
    breaks_count: usize,
    failed_phase: Option<String>,
    failed_log: Option<String>,
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn read_failed_phase(log_dir: &Path) -> Option<String> {
    let stage_file = log_dir.join(".stage");
    std::fs::read_to_string(stage_file)
        .ok()
        .map(|s| s.trim().to_string())
}

struct ReportMeta<'a> {
    build_id: &'a str,
    pkgsrc_env: &'a bob::config::PkgsrcEnv,
    vcs_info: &'a bob::vcs::VcsInfo,
}

fn write_text_report(
    db: &Database,
    logdir: &Path,
    meta: &ReportMeta,
    report_url: Option<&str>,
) -> Result<()> {
    let path = logdir.join("report.txt");
    let mut file = std::fs::File::create(&path)
        .with_context(|| format!("Failed to create {}", path.display()))?;

    let m = &meta.pkgsrc_env.metadata;
    let platform = meta
        .pkgsrc_env
        .platform()
        .unwrap_or_else(|| "unknown".to_string());

    let mut header_fields: Vec<(&str, String)> = vec![("Platform", platform)];
    if let Some(cc) = m.get("CC_VERSION") {
        header_fields.push(("Compiler", cc.clone()));
    }
    if let Some(url) = meta
        .vcs_info
        .web_url()
        .or_else(|| meta.vcs_info.remote_url.clone())
    {
        let mut parts = Vec::new();
        if let Some(branch) = &meta.vcs_info.remote_branch {
            parts.push(format!("branch: {}", branch));
        }
        if let Some(rev) = &meta.vcs_info.revision {
            parts.push(format!("rev: {}", rev));
        }
        if parts.is_empty() {
            header_fields.push(("Repository", url));
        } else {
            header_fields.push(("Repository", format!("{} ({})", url, parts.join(", "))));
        }
    }
    if let Some(url) = report_url {
        header_fields.push(("Report", format!("{}/report.html", url)));
    }

    let max_key = header_fields
        .iter()
        .map(|(k, _)| k.len())
        .max()
        .unwrap_or(0);
    for (key, value) in &header_fields {
        writeln!(
            file,
            "{:<width$} {}",
            format!("{}:", key),
            value,
            width = max_key + 1
        )?;
    }
    writeln!(file)?;

    let mut results = db.get_all_build_results()?;
    let duration = db.get_build_duration()?;

    let sched = bob::Scheduler::new(db)?;
    let breaks_counts: HashMap<String, usize> = sched
        .iter()
        .map(|sp| (sp.pkg.to_string(), sp.dep_count))
        .collect();

    for (pkgname, pkgpath, reason) in db.get_prefailed_packages()? {
        results.push(BuildResult {
            pkgname: pkgsrc::PkgName::new(&pkgname),
            pkgpath: pkgpath.and_then(|p| pkgsrc::PkgPath::new(&p).ok()),
            state: PackageState::PreFailed(reason),
            log_dir: None,
            build_stats: PkgBuildStats::default(),
        });
    }

    let summary = BuildSummary {
        duration,
        results,
        scanfail: db
            .get_scan_failures()?
            .into_iter()
            .filter_map(|(p, e)| pkgsrc::PkgPath::new(&p).ok().map(|pp| (pp, e)))
            .collect(),
    };

    use PackageStateKind::*;
    let c = summary.counts();
    let s = &c.states;
    let skipped = s[UpToDate]
        + s[PreSkipped]
        + s[PreFailed]
        + s[Unresolved]
        + s[IndirectPreSkipped]
        + s[IndirectPreFailed]
        + s[IndirectUnresolved]
        + s[IndirectFailed];
    let total = s[Success] + s[Failed] + skipped + c.scanfail;

    let dur_secs = duration.as_secs();
    let hours = dur_secs / 3600;
    let minutes = (dur_secs % 3600) / 60;
    let seconds = dur_secs % 60;
    let duration_str = if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    };

    writeln!(file, "Total:      {:>12}", total)?;
    writeln!(file, "Succeeded:  {:>12}", s[Success])?;
    writeln!(file, "Failed:     {:>12}", s[Failed])?;
    writeln!(file, "Skipped:    {:>12}", skipped)?;
    if c.scanfail > 0 {
        writeln!(file, "Scan fail:  {:>12}", c.scanfail)?;
    }
    writeln!(file, "Duration:   {:>12}", duration_str)?;

    if c.scanfail > 0 {
        writeln!(file)?;
        writeln!(file, "{:<40} Error", "Scan Failures")?;
        writeln!(file, "{}", "-".repeat(78))?;
        for (pkgpath, error_msg) in &summary.scanfail {
            writeln!(file, "{:<40} {}", pkgpath.as_path().display(), error_msg)?;
        }
    }

    let mut maintainers: HashMap<String, String> = HashMap::new();
    for (pkgname, _, scan_data, _, _) in db.get_report_data()? {
        if let Some(json_str) = scan_data {
            if let Ok(idx) = serde_json::from_str::<pkgsrc::ScanIndex>(&json_str) {
                if let Some(m) = idx.maintainer {
                    maintainers.insert(pkgname, m);
                }
            }
        }
    }

    let mut failed: Vec<_> = summary
        .failed()
        .into_iter()
        .filter(|r| matches!(r.state, PackageState::Failed(_)))
        .map(|r| {
            let breaks = breaks_counts.get(r.pkgname.pkgname()).copied().unwrap_or(0);
            (r, breaks)
        })
        .collect();

    failed.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.pkgname.pkgname().cmp(b.0.pkgname.pkgname()))
    });

    if !failed.is_empty() {
        writeln!(file)?;
        writeln!(
            file,
            "{:<30} {:>6}  {:<12} Maintainer",
            "Build Failures", "Breaks", "Phase"
        )?;
        writeln!(file, "{}", "-".repeat(78))?;
        for (result, breaks) in &failed {
            let phase =
                read_failed_phase(&logdir.join(result.pkgname.pkgname())).unwrap_or_default();
            let maintainer = maintainers
                .get(result.pkgname.pkgname())
                .map(|s| s.as_str())
                .unwrap_or_default();
            writeln!(
                file,
                "{:<30} {:>6}  {:<12} {}",
                result.pkgname.pkgname(),
                breaks,
                phase,
                maintainer
            )?;
        }
    }

    debug!(path = %path.display(), "Wrote text report");
    Ok(())
}

fn write_machine_report(db: &Database, logdir: &Path) -> Result<()> {
    let path = logdir.join("report.zst");
    let file = std::fs::File::create(&path)
        .with_context(|| format!("Failed to create {}", path.display()))?;
    let mut encoder = zstd::Encoder::new(file, 19)?;

    let sched = bob::Scheduler::new(db)?;
    let dep_counts: HashMap<String, usize> = sched
        .iter()
        .map(|sp| (sp.pkg.to_string(), sp.dep_count))
        .collect();

    for (pkgname, _, scan_data, outcome_id, detail) in db.get_report_data()? {
        if let Some(ref json_str) = scan_data {
            if let Ok(idx) = serde_json::from_str::<pkgsrc::ScanIndex>(json_str) {
                write!(encoder, "{}", idx)?;
            }
        }

        // TODO: packages not in the scheduler (e.g. skipped at scan time)
        // won't have a dep_count entry.  These default to 1 (just themselves).
        let pkg_depth = dep_counts.get(&pkgname).copied().unwrap_or(0) + 1;
        writeln!(encoder, "PKG_DEPTH={}", pkg_depth)?;

        let status = match outcome_id {
            Some(id) => match PackageState::from_db(id, detail) {
                Some(state) => state.pbulk_status(),
                None => "open",
            },
            None => "open",
        };
        writeln!(encoder, "BUILD_STATUS={}", status)?;
    }

    encoder.finish()?;
    debug!(path = %path.display(), "Wrote machine-readable report");
    Ok(())
}

fn write_variables_json(
    pkgsrc_env: &bob::config::PkgsrcEnv,
    vcs_info: &bob::vcs::VcsInfo,
    logdir: &Path,
) -> Result<()> {
    let mut pkgsrc = serde_json::Map::new();
    pkgsrc.insert(
        "PREFIX".to_string(),
        serde_json::Value::String(pkgsrc_env.prefix.display().to_string()),
    );
    let mut sorted: Vec<_> = pkgsrc_env.metadata.iter().collect();
    sorted.sort_by_key(|(k, _)| k.as_str());
    for (key, value) in sorted {
        pkgsrc.insert(key.clone(), serde_json::Value::String(value.clone()));
    }

    let mut root = serde_json::Map::new();
    root.insert("pkgsrc".to_string(), serde_json::Value::Object(pkgsrc));

    if vcs_info.is_detected() {
        let vcs = serde_json::to_value(vcs_info)?;
        root.insert("vcs".to_string(), vcs);
    }

    let path = logdir.join("variables.json");
    let file = std::fs::File::create(&path)
        .with_context(|| format!("Failed to create {}", path.display()))?;
    serde_json::to_writer_pretty(file, &root)?;
    debug!(path = %path.display(), "Wrote variables.json");
    Ok(())
}

const GITHUB_SVG: &str = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' width='20' height='20'%3E%3Cpath fill='%23caa080' d='M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z'/%3E%3C/svg%3E";
const REPORT_SVG: &str = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' width='20' height='20'%3E%3Cpath fill='%23caa080' d='M2 14V2h12v12H2zm2-1h2V7H4v6zm3 0h2V4H7v9zm3 0h2V9h-2v4z'/%3E%3C/svg%3E";
const VARS_SVG: &str = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' width='20' height='20'%3E%3Cpath fill='%23caa080' d='M4 1h8a1 1 0 011 1v12a1 1 0 01-1 1H4a1 1 0 01-1-1V2a1 1 0 011-1zm1 3v1h6V4H5zm0 2.5v1h6v-1H5zm0 2.5v1h4V9H5z'/%3E%3C/svg%3E";

const REPORT_CSS: &str = "\
body { font-family: \"Trebuchet MS\", verdana, sans-serif; font-size: 14px; color: #444; margin: 1em 4%; background: #fefefe; line-height: 1.45; }\n\
a { color: #8a4500; text-decoration: none; }\n\
a:hover { color: #f37021; text-decoration: underline; }\n\
h1 { font-size: 24px; margin: 0; color: #333; text-align: center; }\n\
table { border-collapse: collapse; margin-bottom: 14px; }\n\
th, td { padding: 4px 10px; border-bottom: 1px solid #e8e0d8; text-align: left; font-size: 14px; }\n\
th, .col-logs { white-space: nowrap; }\n\
th { color: #d35400; font-size: 13px; background: none; border-bottom: 1px solid #f37021; cursor: pointer; }\n\
.data tbody tr:nth-child(even) td { background: #fdfaf7; }\n\
.r { text-align: right; }\n\
.header { margin-bottom: 14px; padding-bottom: 10px; border-bottom: 1px solid #e8ddd4; position: relative; }\n\
.header-icons { position: absolute; top: 0; }\n\
.header-left { left: 0; }\n\
.header-right { right: 0; }\n\
.header-right a { margin-left: 10px; color: #caa080; }\n\
.header-right a:hover { color: #f37021; }\n\
.var-columns { margin-bottom: 14px; text-align: center; }\n\
.var-columns table { display: inline-table; vertical-align: top; margin-right: 24px; text-align: left; }\n\
.data { width: 100%; }\n\
.vars th, .vars td, .vars .vk { font-family: \"Consolas\", \"Monaco\", \"Courier New\", monospace; }\n\
.vars th { text-align: left; color: #d35400; font-size: 13px; background: none; border-bottom: 1px solid #f37021; padding: 3px 10px 5px 10px; font-family: \"Trebuchet MS\", verdana, sans-serif; }\n\
.vars .vk { color: #8a4500; font-weight: bold; font-size: 13px; }\n\
.vars td { font-size: 13px; border-bottom: 1px solid #f0ebe6; }\n\
.phase { font-size: 13px; margin-right: 6px; color: #c05500; }\n\
.phase.f { color: #8a4500; }\n\
.indirect { color: #aaa; }\n\
.reason { color: #888; font-size: 13px; }\n\
.col-pkg { width: 18%; }\n\
.col-path { width: 14%; }\n\
.col-maint { width: 14%; }\n\
.col-dur { width: 8%; }\n\
@media (max-width: 1200px) { .col-maint { display: none; } }\n\
@media (max-width: 1000px) { .col-dur { display: none; } }\n\
@media (max-width: 900px) { .col-status { display: none; } }\n\
@media (max-width: 700px) { .col-path { display: none; } body { margin: 1em 1%; } }\n";

fn write_html_report(db: &Database, logdir: &Path, path: &Path, meta: &ReportMeta) -> Result<()> {
    let mut results = db.get_all_build_results()?;
    let duration = db.get_build_duration()?;

    let sched = bob::Scheduler::new(db)?;
    let breaks_counts: HashMap<String, usize> = sched
        .iter()
        .map(|sp| (sp.pkg.to_string(), sp.dep_count))
        .collect();

    for (pkgname, pkgpath, reason) in db.get_prefailed_packages()? {
        results.push(BuildResult {
            pkgname: pkgsrc::PkgName::new(&pkgname),
            pkgpath: pkgpath.and_then(|p| pkgsrc::PkgPath::new(&p).ok()),
            state: PackageState::PreFailed(reason),
            log_dir: None,
            build_stats: PkgBuildStats::default(),
        });
    }

    for (pkgname, pkgpath, failed_dep) in db.get_indirect_failures()? {
        results.push(BuildResult {
            pkgname: pkgsrc::PkgName::new(&pkgname),
            pkgpath: pkgpath.and_then(|p| pkgsrc::PkgPath::new(&p).ok()),
            state: PackageState::IndirectFailed(failed_dep),
            log_dir: None,
            build_stats: PkgBuildStats::default(),
        });
    }

    let summary = BuildSummary {
        duration,
        results,
        scanfail: db
            .get_scan_failures()?
            .into_iter()
            .filter_map(|(p, e)| pkgsrc::PkgPath::new(&p).ok().map(|pp| (pp, e)))
            .collect(),
    };

    let mut file = std::fs::File::create(path)?;
    let m = &meta.pkgsrc_env.metadata;

    let mut failed_info: Vec<FailedPackageInfo> = summary
        .results
        .iter()
        .filter(|r| {
            matches!(
                r.state,
                PackageState::Failed(_) | PackageState::IndirectFailed(_)
            )
        })
        .map(|result| {
            let breaks_count = breaks_counts
                .get(result.pkgname.pkgname())
                .copied()
                .unwrap_or(0);
            let pkg_log_dir = logdir.join(result.pkgname.pkgname());
            let failed_phase = read_failed_phase(&pkg_log_dir);
            let failed_log = failed_phase.as_ref().and_then(|phase| {
                BUILD_PHASES
                    .iter()
                    .find(|(name, _)| *name == phase)
                    .map(|(_, log)| (*log).to_string())
            });
            FailedPackageInfo {
                result,
                breaks_count,
                failed_phase,
                failed_log,
            }
        })
        .collect();

    failed_info.sort_by(|a, b| {
        let a_indirect = matches!(a.result.state, PackageState::IndirectFailed(_));
        let b_indirect = matches!(b.result.state, PackageState::IndirectFailed(_));
        a_indirect
            .cmp(&b_indirect)
            .then_with(|| b.breaks_count.cmp(&a.breaks_count))
            .then_with(|| a.result.pkgname.pkgname().cmp(b.result.pkgname.pkgname()))
    });

    let title = format!("Build Report {}", meta.build_id);

    writeln!(file, "<!DOCTYPE html>")?;
    writeln!(file, "<html lang=\"en\">")?;
    writeln!(file, "<head>")?;
    writeln!(file, "<meta charset=\"UTF-8\">")?;
    writeln!(file, "<title>{}</title>", escape_html(&title))?;
    writeln!(file, "<style>")?;
    write!(file, "{}", REPORT_CSS)?;
    writeln!(file, "</style>")?;
    write_sort_script(&mut file)?;
    writeln!(file, "</head>")?;
    writeln!(file, "<body>")?;

    write_header(&mut file, &title)?;

    writeln!(file, "<div class=\"var-columns\">")?;
    write_statistics_table(&mut file, &summary)?;
    write_platform_table(&mut file, m)?;
    write_paths_table(&mut file, m, &meta.pkgsrc_env.prefix)?;
    if meta.vcs_info.is_detected() {
        write_vcs_table(&mut file, meta.vcs_info)?;
    }
    writeln!(file, "</div>")?;

    if !summary.scanfail.is_empty() {
        write_scanfail_table(&mut file, &summary.scanfail)?;
    }

    let mut maintainers: HashMap<String, String> = HashMap::new();
    for (pkgname, _, scan_data, _, _) in db.get_report_data()? {
        if let Some(json_str) = scan_data {
            if let Ok(idx) = serde_json::from_str::<pkgsrc::ScanIndex>(&json_str) {
                if let Some(m) = idx.maintainer {
                    maintainers.insert(pkgname, m);
                }
            }
        }
    }

    write_failed_table(&mut file, &failed_info, &maintainers, logdir)?;

    writeln!(file, "</body>")?;
    writeln!(file, "</html>")?;

    Ok(())
}

fn write_sort_script(file: &mut std::fs::File) -> Result<()> {
    writeln!(file, "<script>")?;
    writeln!(file, "function cmpVal(cells, col, type) {{")?;
    writeln!(
        file,
        "  var v = cells[col].getAttribute('data-sort') || cells[col].textContent;"
    )?;
    writeln!(file, "  return type === 'num' ? (parseFloat(v) || 0) : v;")?;
    writeln!(file, "}}")?;
    writeln!(file, "function sortTable(id, col, type, col2, type2) {{")?;
    writeln!(file, "  var t = document.getElementById(id);")?;
    writeln!(file, "  var b = t.tBodies[0];")?;
    writeln!(file, "  var rows = Array.prototype.slice.call(b.rows);")?;
    writeln!(file, "  var same = t.getAttribute('data-sort-col') == col;")?;
    writeln!(
        file,
        "  var desc = same ? t.getAttribute('data-sort-desc') != '1' : type === 'num';"
    )?;
    writeln!(file, "  rows.sort(function(a, b) {{")?;
    writeln!(file, "    var av = cmpVal(a.cells, col, type);")?;
    writeln!(file, "    var bv = cmpVal(b.cells, col, type);")?;
    writeln!(
        file,
        "    var r = type === 'num' ? av - bv : av.localeCompare(bv);"
    )?;
    writeln!(file, "    if (r === 0 && col2 !== undefined) {{")?;
    writeln!(file, "      var av2 = cmpVal(a.cells, col2, type2);")?;
    writeln!(file, "      var bv2 = cmpVal(b.cells, col2, type2);")?;
    writeln!(
        file,
        "      r = type2 === 'num' ? bv2 - av2 : av2.localeCompare(bv2);"
    )?;
    writeln!(file, "    }}")?;
    writeln!(file, "    return desc ? -r : r;")?;
    writeln!(file, "  }});")?;
    writeln!(
        file,
        "  for (var i = 0; i < rows.length; i++) b.appendChild(rows[i]);"
    )?;
    writeln!(file, "  t.setAttribute('data-sort-col', col);")?;
    writeln!(
        file,
        "  t.setAttribute('data-sort-desc', desc ? '1' : '0');"
    )?;
    writeln!(file, "}}")?;
    writeln!(file, "</script>")?;
    Ok(())
}

fn write_header(file: &mut std::fs::File, title: &str) -> Result<()> {
    writeln!(file, "<div class=\"header\">")?;
    writeln!(
        file,
        "<div class=\"header-icons header-left\"><a href=\"https://pkgsrc.org/\"><img src=\"https://www.pkgsrc.org/img/pkgsrc-square.png\" alt=\"pkgsrc\" height=\"36\"></a></div>"
    )?;
    write!(file, "<div class=\"header-icons header-right\">")?;
    write!(
        file,
        "<a href=\"report.zst\" title=\"Machine-readable report\"><img src=\"{}\" alt=\"Report\"></a>",
        REPORT_SVG
    )?;
    write!(
        file,
        "<a href=\"variables.json\" title=\"Build variables\"><img src=\"{}\" alt=\"Variables\"></a>",
        VARS_SVG
    )?;
    write!(
        file,
        "<a href=\"https://github.com/jperkin/bob\" title=\"bob on GitHub\"><img src=\"{}\" alt=\"GitHub\"></a>",
        GITHUB_SVG
    )?;
    writeln!(file, "</div>")?;
    writeln!(file, "<h1>{}</h1>", escape_html(title))?;
    writeln!(file, "</div>")?;
    Ok(())
}

fn write_var_row(file: &mut std::fs::File, key: &str, value: &str) -> Result<()> {
    writeln!(
        file,
        "<tr><td class=\"vk\">{}</td><td>{}</td></tr>",
        escape_html(key),
        escape_html(value)
    )?;
    Ok(())
}

fn write_statistics_table(file: &mut std::fs::File, summary: &BuildSummary) -> Result<()> {
    use PackageStateKind::*;

    let duration_secs = summary.duration.as_secs();
    let hours = duration_secs / 3600;
    let minutes = (duration_secs % 3600) / 60;
    let seconds = duration_secs % 60;
    let duration_str = if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    };

    let c = summary.counts();
    let s = &c.states;
    let skipped_count = s[UpToDate]
        + s[PreSkipped]
        + s[PreFailed]
        + s[Unresolved]
        + s[IndirectPreSkipped]
        + s[IndirectPreFailed]
        + s[IndirectUnresolved]
        + s[IndirectFailed];
    let total = s[Success] + s[Failed] + skipped_count + c.scanfail;

    writeln!(file, "<table class=\"vars\">")?;
    writeln!(file, "<tr><th colspan=\"2\">Statistics</th></tr>")?;
    write_var_row(file, "Total", &total.to_string())?;
    write_var_row(file, "Succeeded", &s[Success].to_string())?;
    write_var_row(file, "Failed", &s[Failed].to_string())?;
    write_var_row(file, "Skipped", &skipped_count.to_string())?;
    if c.scanfail > 0 {
        write_var_row(file, "Scan failed", &c.scanfail.to_string())?;
    }
    write_var_row(file, "Duration", &duration_str)?;
    writeln!(file, "</table>")?;
    Ok(())
}

fn write_platform_table(file: &mut std::fs::File, m: &HashMap<String, String>) -> Result<()> {
    writeln!(file, "<table class=\"vars\">")?;
    writeln!(file, "<tr><th colspan=\"2\">Platform</th></tr>")?;

    let has_variant = m.contains_key("OS_VARIANT");
    let has_variant_version = m.contains_key("LOWER_VARIANT_VERSION");

    if has_variant {
        write_var_row(file, "OS_VARIANT", &m["OS_VARIANT"])?;
    } else if let Some(val) = m.get("OPSYS") {
        write_var_row(file, "OPSYS", val)?;
    }

    if has_variant_version {
        write_var_row(file, "LOWER_VARIANT_VERSION", &m["LOWER_VARIANT_VERSION"])?;
    } else if let Some(val) = m.get("OS_VERSION") {
        write_var_row(file, "OS_VERSION", val)?;
    }

    for key in &["MACHINE_ARCH", "CC_VERSION"] {
        if let Some(val) = m.get(*key) {
            write_var_row(file, key, val)?;
        }
    }

    writeln!(file, "</table>")?;
    Ok(())
}

fn write_paths_table(
    file: &mut std::fs::File,
    m: &HashMap<String, String>,
    prefix: &Path,
) -> Result<()> {
    writeln!(file, "<table class=\"vars\">")?;
    writeln!(file, "<tr><th colspan=\"2\">Paths</th></tr>")?;
    write_var_row(file, "PREFIX", &prefix.display().to_string())?;
    for key in &["SYSCONFBASE", "VARBASE", "PKGMANDIR", "PKGINFODIR"] {
        if let Some(val) = m.get(*key) {
            write_var_row(file, key, val)?;
        }
    }
    writeln!(file, "</table>")?;
    Ok(())
}

fn write_vcs_table(file: &mut std::fs::File, vcs: &bob::vcs::VcsInfo) -> Result<()> {
    writeln!(file, "<table class=\"vars\">")?;
    writeln!(file, "<tr><th colspan=\"2\">Version Control</th></tr>")?;

    let web_url = vcs.web_url();
    let web_base = web_url.as_deref();

    if let Some(base) = web_base {
        writeln!(
            file,
            "<tr><td class=\"vk\">Repository</td><td><a href=\"{}\">{}</a></td></tr>",
            escape_html(base),
            escape_html(base)
        )?;
    } else if let Some(url) = &vcs.remote_url {
        write_var_row(file, "Repository", url)?;
    }
    if let Some(branch) = &vcs.remote_branch {
        if let Some(base) = web_base {
            writeln!(
                file,
                "<tr><td class=\"vk\">Branch</td><td><a href=\"{}/tree/{}\">{}</a></td></tr>",
                escape_html(base),
                escape_html(branch),
                escape_html(branch)
            )?;
        } else {
            write_var_row(file, "Branch", branch)?;
        }
    }
    if let Some(rev) = &vcs.revision {
        if let (Some(base), Some(full)) = (web_base, &vcs.revision_full) {
            writeln!(
                file,
                "<tr><td class=\"vk\">Revision</td><td><a href=\"{}/tree/{}\">{}</a></td></tr>",
                escape_html(base),
                escape_html(full),
                escape_html(rev)
            )?;
        } else {
            write_var_row(file, "Revision", rev)?;
        }
    }
    writeln!(file, "</table>")?;
    Ok(())
}

fn generate_phase_links(pkg_name: &str, log_dir: &Path, failed_phase: Option<&str>) -> String {
    if !log_dir.exists() {
        return String::new();
    }
    let mut links = Vec::new();
    for (phase_name, log_file) in BUILD_PHASES {
        let log_path = log_dir.join(log_file);
        if log_path.exists() {
            if failed_phase == Some(*phase_name) {
                links.push(format!(
                    "<a href=\"{}/{}\" class=\"phase f\">{}</a>",
                    pkg_name, log_file, phase_name
                ));
            } else {
                links.push(format!(
                    "<a href=\"{}/{}\" class=\"phase\">{}</a>",
                    pkg_name, log_file, phase_name
                ));
            }
        }
    }
    links.join(" ")
}

fn write_failed_table(
    file: &mut std::fs::File,
    failed_info: &[FailedPackageInfo],
    maintainers: &HashMap<String, String>,
    logdir: &Path,
) -> Result<()> {
    writeln!(file, "<table id=\"failed-table\" class=\"data\">")?;
    writeln!(file, "<thead><tr>")?;
    writeln!(
        file,
        "<th class=\"col-pkg\" onclick=\"sortTable('failed-table', 0, 'str')\">Package</th>"
    )?;
    writeln!(
        file,
        "<th class=\"col-path\" onclick=\"sortTable('failed-table', 1, 'str')\">Path</th>"
    )?;
    writeln!(
        file,
        "<th onclick=\"sortTable('failed-table', 2, 'num')\">Breaks</th>"
    )?;
    writeln!(
        file,
        "<th class=\"col-dur\" onclick=\"sortTable('failed-table', 3, 'num')\">Duration</th>"
    )?;
    writeln!(
        file,
        "<th class=\"col-maint\" onclick=\"sortTable('failed-table', 4, 'str')\">Maintainer</th>"
    )?;
    writeln!(
        file,
        "<th class=\"col-status\" onclick=\"sortTable('failed-table', 5, 'str')\">Status</th>"
    )?;
    writeln!(
        file,
        "<th class=\"col-logs\" onclick=\"sortTable('failed-table', 6, 'num', 2, 'num')\">Build Logs</th>"
    )?;
    writeln!(file, "</tr></thead>")?;
    writeln!(file, "<tbody>")?;

    for info in failed_info {
        let pkg_name = info.result.pkgname.pkgname();
        let pkgpath = info
            .result
            .pkgpath
            .as_ref()
            .map(|p| p.as_path().display().to_string())
            .unwrap_or_default();
        let maintainer = maintainers
            .get(pkg_name)
            .map(|s| s.as_str())
            .unwrap_or_default();

        if info.result.state.is_skip() {
            let reason = info.result.state.to_string();
            writeln!(
                file,
                "<tr><td class=\"indirect\">{}</td><td class=\"col-path indirect\">{}</td><td class=\"r indirect\" data-sort=\"{}\">{}</td><td class=\"col-dur r indirect\" data-sort=\"0\"></td><td class=\"col-maint indirect\">{}</td><td class=\"col-status indirect\">{}</td><td class=\"col-logs reason\" data-sort=\"1\">{}</td></tr>",
                escape_html(pkg_name),
                pkgpath,
                info.breaks_count,
                info.breaks_count,
                escape_html(maintainer),
                info.result.state.status(),
                escape_html(&reason)
            )?;
            continue;
        }

        let dur_secs = info.result.build_stats.duration.as_secs();
        let duration = if dur_secs >= 60 {
            format!("{}m {}s", dur_secs / 60, dur_secs % 60)
        } else {
            format!("{}s", dur_secs)
        };

        let pkg_link = match &info.failed_log {
            Some(log) => format!("<a href=\"{}/{}\">{}</a>", pkg_name, log, pkg_name),
            None => escape_html(pkg_name),
        };

        let log_dir = logdir.join(pkg_name);
        let phase_links = generate_phase_links(pkg_name, &log_dir, info.failed_phase.as_deref());

        writeln!(
            file,
            "<tr><td>{}</td><td class=\"col-path\">{}</td><td class=\"r\" data-sort=\"{}\">{}</td><td class=\"col-dur r\" data-sort=\"{}\">{}</td><td class=\"col-maint\">{}</td><td class=\"col-status\">{}</td><td class=\"col-logs\" data-sort=\"0\">{}</td></tr>",
            pkg_link,
            pkgpath,
            info.breaks_count,
            info.breaks_count,
            dur_secs,
            duration,
            escape_html(maintainer),
            info.result.state.status(),
            phase_links
        )?;
    }

    writeln!(file, "</tbody>")?;
    writeln!(file, "</table>")?;
    Ok(())
}

fn write_scanfail_table(
    file: &mut std::fs::File,
    scanfail: &[(pkgsrc::PkgPath, String)],
) -> Result<()> {
    writeln!(file, "<table id=\"scanfail-table\" class=\"data\">")?;
    writeln!(file, "<thead><tr>")?;
    writeln!(
        file,
        "<th onclick=\"sortTable('scanfail-table', 0, 'str')\">Path</th>"
    )?;
    writeln!(
        file,
        "<th onclick=\"sortTable('scanfail-table', 1, 'str')\">Error</th>"
    )?;
    writeln!(file, "</tr></thead>")?;
    writeln!(file, "<tbody>")?;

    for (pkgpath, error_msg) in scanfail {
        writeln!(
            file,
            "<tr><td>{}</td><td>{}</td></tr>",
            escape_html(&pkgpath.as_path().display().to_string()),
            escape_html(error_msg)
        )?;
    }

    writeln!(file, "</tbody>")?;
    writeln!(file, "</table>")?;
    Ok(())
}
