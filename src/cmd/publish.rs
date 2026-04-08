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
 * Package publishing has two knobs in `publish.packages`:
 *
 * - `tmppath` (optional): if unset, rsync writes straight to `path`.
 *   If set, rsync writes to `tmppath` with `--link-dest=path` so that
 *   unchanged files become hardlinks against the live tree.
 * - `swapcmd` (optional, requires `tmppath`): a shell script run on
 *   the remote host after rsync completes.  Either a literal string,
 *   or a Lua function returning a `scriptenv(run, env)` bundle so the
 *   env values can reference other config sections.  The script is
 *   piped to `ssh host sh -eu` on stdin; `set -eu` is mandatory so
 *   failures and unset variable references abort immediately rather
 *   than silently proceeding.  No default -- if `swapcmd` is unset,
 *   the staged data is left in `tmppath` and the caller is
 *   responsible for whatever happens next.
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
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use glob::Pattern;
use strum::IntoEnumIterator;
use tracing::{debug, info};

use bob::build::{BuildResult, BuildSummary, PkgBuildStats};
use bob::config::{Config, Publish, PublishPackages, ScriptValue};
use bob::db::Database;
use bob::{PackageCounts, PackageState, PackageStateKind};

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

    if dry_run {
        println!("Publishing packages (dry-run)...");
    } else {
        println!("Publishing packages...");
    }

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

    if let Some(swapcmd) = &packages.swapcmd {
        let remote = format_remote(&packages.host, packages.user.as_deref());
        let script = build_remote_script(swapcmd)?;

        if dry_run {
            info!("Dry run: would pipe to ssh {} sh -eu:", remote);
            for line in script.lines() {
                println!("  {}", line);
            }
        } else {
            info!(remote = %remote, "Running swapcmd via ssh");
            run_remote_script(&remote, &script)?;
        }
    }

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

    let mut states = PackageCounts::default();
    for r in &db.get_all_build_results()? {
        states.add(&r.state);
    }
    for (_, _, state) in &db.get_prefailskip_packages()? {
        states.add(state);
    }
    for (_, _, failed_dep) in &db.get_indirect_failures()? {
        states.add(&PackageState::IndirectFailed(failed_dep.clone()));
    }

    let duration = db.get_build_duration()?;
    let report_url = report_cfg
        .url
        .as_ref()
        .map(|u| format!("{}/{}", u, build_id));

    let diff = match db.list_history_builds() {
        Ok(builds) if builds.len() >= 2 => db
            .compute_build_diff(&builds[1].build_id, &builds[0].build_id)
            .ok(),
        _ => None,
    };

    std::fs::create_dir_all(logdir)
        .with_context(|| format!("Failed to create {}", logdir.display()))?;

    write_variables_json(
        &pkgsrc_env,
        &vcs_info,
        &states,
        build_id,
        report_url.as_deref(),
        duration,
        logdir,
        diff.as_ref(),
    )?;

    let report_path = logdir.join("report.html");
    let report_meta = ReportMeta {
        build_id,
        pkgsrc_env: &pkgsrc_env,
        vcs_info: &vcs_info,
    };

    println!("Generating report...");
    write_html_report(db, logdir, &report_path, &report_meta, diff.as_ref())?;
    write_machine_report(db, logdir)?;
    write_text_report(
        db,
        logdir,
        &report_meta,
        report_url.as_deref(),
        diff.as_ref(),
    )?;

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
    let rsync_args = &report_cfg.rsync_args;

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
    use lettre::message::header::{HeaderName, HeaderValue};
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

    if let Some(url) = &report_cfg.url {
        let base = format!("{}/{}", url, build_id);
        builder = builder.raw_header(HeaderValue::new(
            HeaderName::new_from_ascii_str("X-Bob-Report-URL"),
            format!("{}/report.html", base),
        ));
        builder = builder.raw_header(HeaderValue::new(
            HeaderName::new_from_ascii_str("X-Bob-Report-Raw"),
            format!("{}/report.zst", base),
        ));
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
    let rsync_args = &packages.rsync_args;
    let remote = format_remote(&packages.host, packages.user.as_deref());
    let dest = packages.tmppath.as_ref().unwrap_or(&packages.path);

    let mut cmd = Command::new(&publish.rsync);
    cmd.arg("--exclude-from").arg(filter_path);
    for arg in rsync_args.split_whitespace() {
        cmd.arg(arg);
    }
    cmd.arg("--partial-dir=.rsync-partial");
    if packages.tmppath.is_some() {
        cmd.arg(format!("--link-dest={}", packages.path));
    }
    if dry_run {
        cmd.arg("--dry-run");
    }
    cmd.arg(".");
    cmd.arg(format!("{}:{}", remote, dest));
    cmd.current_dir(packages_dir);

    info!(
        remote = %remote,
        dest = %dest,
        path = %packages.path,
        mode = if packages.tmppath.is_some() { "staged" } else { "direct" },
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

/*
 * Build a shell script to pipe over ssh.  Each env var becomes a
 * `name=value` assignment on its own line (shell-quoted by shlex if
 * the value needs it), followed by the user's script body.
 */
fn build_remote_script(sv: &ScriptValue) -> Result<String> {
    let mut out = String::new();
    for (k, v) in &sv.env {
        let quoted = shlex::try_quote(v)
            .with_context(|| format!("env value for '{}' cannot be shell-quoted", k))?;
        out.push_str(k);
        out.push('=');
        out.push_str(&quoted);
        out.push('\n');
    }
    out.push_str(&sv.run);
    Ok(out)
}

/*
 * Run a script on a remote host via ssh.  The script body is sent on
 * stdin and executed by `sh -eu`, so the script never appears as a
 * shell-quoted argument.  `set -eu` is mandatory: any failed command
 * or unset variable reference aborts immediately rather than silently
 * proceeding.
 */
fn run_remote_script(remote: &str, script: &str) -> Result<()> {
    let mut child = Command::new("ssh")
        .arg(remote)
        .arg("sh")
        .arg("-eu")
        .stdin(Stdio::piped())
        .spawn()
        .context("Failed to spawn ssh")?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Failed to open ssh stdin"))?;
        stdin
            .write_all(script.as_bytes())
            .context("Failed to write script to ssh stdin")?;
    }
    let status = child.wait().context("Failed to wait for ssh")?;
    if !status.success() {
        bail!(
            "swapcmd failed with exit code {}",
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
    failed_log: Option<String>,
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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
    diff: Option<&bob::db::BuildDiff>,
) -> Result<()> {
    let path = logdir.join("report.txt");
    let mut file = std::fs::File::create(&path)
        .with_context(|| format!("Failed to create {}", path.display()))?;

    let m = &meta.pkgsrc_env.metadata;
    let platform = meta
        .pkgsrc_env
        .platform()
        .unwrap_or_else(|| "unknown".to_string());

    let mut results = db.get_all_build_results()?;
    let duration = db.get_build_duration()?;

    let sched = bob::Scheduler::new(db)?;
    let breaks_counts: HashMap<String, usize> = sched
        .iter()
        .map(|sp| (sp.pkg.to_string(), sp.dep_count))
        .collect();

    for (pkgname, pkgpath, state) in db.get_prefailskip_packages()? {
        results.push(BuildResult {
            pkgname: pkgsrc::PkgName::new(&pkgname),
            pkgpath: pkgpath.and_then(|p| pkgsrc::PkgPath::new(&p).ok()),
            state,
            log_dir: None,
            build_stats: PkgBuildStats::default(),
        });
    }

    let mut scanfail: Vec<(pkgsrc::PkgPath, String)> = db
        .get_scan_failures()?
        .into_iter()
        .filter_map(|(p, e)| pkgsrc::PkgPath::new(&p).ok().map(|pp| (pp, e)))
        .collect();
    for r in &results {
        if let PackageState::Unresolved(reason) = &r.state {
            if let Some(pp) = &r.pkgpath {
                scanfail.push((pp.clone(), reason.clone()));
            }
        }
    }

    let summary = BuildSummary {
        duration,
        results,
        scanfail,
    };

    let c = summary.counts();

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

    if let Some(url) = report_url {
        writeln!(file, "URL: {}/report.html", url)?;
        writeln!(file)?;
    }

    let mut right: Vec<(&str, String)> = vec![("Platform", platform)];
    if let Some(cc) = m.get("CC_VERSION") {
        right.push(("Compiler", cc.clone()));
    }
    if let Some(url) = meta
        .vcs_info
        .web_url()
        .or_else(|| meta.vcs_info.remote_url.clone())
    {
        right.push(("Repository", url));
    }
    if let Some(branch) = &meta.vcs_info.remote_branch {
        match &meta.vcs_info.revision {
            Some(rev) => right.push(("Branch", format!("{} (revision: {})", branch, rev))),
            None => right.push(("Branch", branch.clone())),
        }
    }
    right.push(("Duration", duration_str));

    let left = [
        ("Total", c.states.total()),
        ("Succeeded", c.states.succeeded()),
        ("Failed", c.states.failed()),
        ("UpToDate", c.states.up_to_date()),
        ("Masked", c.states.masked()),
    ];

    for (i, (lk, lv)) in left.iter().enumerate() {
        let right_part = if i < right.len() {
            format!("  {:<13}{}", format!("{}:", right[i].0), right[i].1)
        } else {
            String::new()
        };
        writeln!(file, "{:<12}{:>5}{}", format!("{}:", lk), lv, right_part)?;
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

    if let Some(d) = diff {
        if !d.new_failures.is_empty() {
            let mut sorted: Vec<_> = d.new_failures.iter().collect();
            let get_breaks = |e: &bob::db::DiffEntry| -> usize {
                e.build2_pkgname
                    .as_deref()
                    .and_then(|n| breaks_counts.get(n))
                    .copied()
                    .unwrap_or(0)
            };
            let was_previously_ok = |e: &bob::db::DiffEntry| -> bool {
                matches!(
                    e.build1_outcome,
                    None | Some(PackageStateKind::Success) | Some(PackageStateKind::UpToDate)
                )
            };
            sorted.sort_by(|a, b| {
                was_previously_ok(b)
                    .cmp(&was_previously_ok(a))
                    .then_with(|| get_breaks(b).cmp(&get_breaks(a)))
            });
            writeln!(file)?;
            writeln!(
                file,
                "{:<44} {:>6}  Previously",
                format!("New Failures Since {}", d.build1_id),
                "Breaks"
            )?;
            writeln!(file, "{}", "-".repeat(76))?;
            for e in &sorted {
                let pkgname = e.build2_pkgname.as_deref().unwrap_or("-");
                let breaks = breaks_counts.get(pkgname).copied().unwrap_or(0);
                let previously: &str = e.build1_outcome.map(|o| o.into()).unwrap_or("");
                let breaks_str = if breaks > 0 {
                    breaks.to_string()
                } else {
                    String::new()
                };
                writeln!(file, "{:<44} {:>6}  {}", pkgname, breaks_str, previously)?;
            }
        }
    }

    if c.scanfail > 0 {
        let max_path = summary
            .scanfail
            .iter()
            .map(|(p, _)| p.as_path().display().to_string().len())
            .max()
            .unwrap_or(0);
        writeln!(file)?;
        writeln!(file, "Scan Failures")?;
        writeln!(file, "{}", "-".repeat(76))?;
        for (pkgpath, error_msg) in &summary.scanfail {
            writeln!(
                file,
                "{:<width$}  {}",
                pkgpath.as_path().display(),
                error_msg,
                width = max_path
            )?;
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
        writeln!(file, "{:<44} {:>6}  Maintainer", "Build Failures", "Breaks")?;
        writeln!(file, "{}", "-".repeat(76))?;
        for (result, breaks) in &failed {
            let maintainer = maintainers
                .get(result.pkgname.pkgname())
                .map(|s| s.as_str())
                .unwrap_or_default();
            let breaks_str = if *breaks > 0 {
                breaks.to_string()
            } else {
                String::new()
            };
            writeln!(
                file,
                "{:<44} {:>6}  {}",
                result.pkgname.pkgname(),
                breaks_str,
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

#[allow(clippy::too_many_arguments)]
fn write_variables_json(
    pkgsrc_env: &bob::config::PkgsrcEnv,
    vcs_info: &bob::vcs::VcsInfo,
    states: &PackageCounts,
    build_id: &str,
    report_url: Option<&str>,
    duration: Duration,
    logdir: &Path,
    diff: Option<&bob::db::BuildDiff>,
) -> Result<()> {
    let mut pkgsrc = serde_json::Map::new();
    pkgsrc.insert(
        "PREFIX".to_string(),
        pkgsrc_env.prefix.display().to_string().into(),
    );
    let mut sorted: Vec<_> = pkgsrc_env.metadata.iter().collect();
    sorted.sort_by_key(|(k, _)| k.as_str());
    for (key, value) in sorted {
        pkgsrc.insert(key.clone(), value.clone().into());
    }

    let counts: serde_json::Map<_, _> = PackageStateKind::iter()
        .map(|kind| (kind.as_ref().to_string(), states[kind].into()))
        .collect();

    let mut report = serde_json::Map::new();
    report.insert("date".to_string(), build_id.into());
    report.insert("duration".to_string(), duration.as_secs().into());
    if let Some(base) = report_url {
        report.insert("url".to_string(), format!("{}/report.html", base).into());
        report.insert("raw".to_string(), format!("{}/report.zst", base).into());
    }

    let mut root = serde_json::Map::new();
    root.insert("pkgsrc".to_string(), pkgsrc.into());
    root.insert("counts".to_string(), counts.into());
    root.insert("report".to_string(), report.into());

    if vcs_info.is_detected() {
        let vcs = serde_json::to_value(vcs_info)?;
        root.insert("vcs".to_string(), vcs);
    }

    if let Some(d) = diff {
        root.insert(
            "diff".to_string(),
            serde_json::json!({
                "compared_build_id": d.build1_id,
                "new_failures": d.new_failures.len(),
                "fixes": d.fixes.len(),
                "version_changes": d.version_changes.len(),
                "other_changes": d.other_changes.len(),
            }),
        );
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
body { font-family: \"Trebuchet MS\", Verdana, sans-serif; font-size: 0.875rem; color: #444; margin: 1em 4%; background: #fefefe; line-height: 1.45; }\n\
a { color: #8a4500; text-decoration: none; }\n\
a:hover { color: #f37021; text-decoration: underline; }\n\
a:visited { color: #8a4500; }\n\
table { border-collapse: collapse; margin-bottom: 1em; }\n\
th, td { padding: 0.25em 0.625em; text-align: left; }\n\
th { white-space: nowrap; color: #d35400; background: none; border-bottom: 1px solid #f37021; cursor: pointer; user-select: none; }\n\
th:focus-visible { outline: 2px solid #f37021; outline-offset: -2px; }\n\
th[aria-sort=\"ascending\"]::after { content: \" \\25B2\"; font-size: 0.75em; }\n\
th[aria-sort=\"descending\"]::after { content: \" \\25BC\"; font-size: 0.75em; }\n\
.data { font-size: 0.8125rem; white-space: nowrap; margin: 0 auto; }\n\
.data tbody tr:nth-child(even) td { background: #fdfaf7; }\n\
.r { text-align: right; }\n\
.header { margin-bottom: 1em; padding-bottom: 0.625em; border-bottom: 1px solid #e8ddd4; }\n\
.header-table { width: 100%; white-space: nowrap; border: none; margin: 0; }\n\
.header-table td { border: none; padding: 0 0.5em; vertical-align: middle; }\n\
.header-icons { width: 1%; }\n\
.header-icons a { color: #caa080; margin-left: 0.375em; }\n\
.header-icons a:hover { color: #f37021; }\n\
.hdr-label { font-size: 1.5rem; color: #333; }\n\
.hdr-platform { font-size: 1.5rem; color: #333; text-align: center; }\n\
.hdr-date { font-size: 1.5rem; color: #333; text-align: right; }\n\
.var-columns { margin-bottom: 1em; text-align: center; }\n\
.var-columns table { display: inline-table; vertical-align: top; margin-right: 1.5em; text-align: left; }\n\
.vars th, .vars td, .vars .vk { font-family: Consolas, Monaco, \"Courier New\", monospace; }\n\
.vars th { text-align: left; color: #d35400; font-size: 0.75rem; background: none; border-bottom: 1px solid #f37021; padding: 0.1875em 0.625em 0.3125em; font-family: \"Trebuchet MS\", Verdana, sans-serif; cursor: default; }\n\
.vars .vk { color: #8a4500; font-weight: bold; font-size: 0.75rem; }\n\
.vars td { font-size: 0.75rem; }\n\
.stats td:not(.vk) { text-align: right; }\n\
.phase { margin-right: 0.375em; }\n\
.indirect { color: #aaa; }\n\
.reason { color: #888; }\n\
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); border: 0; }\n\
.col-err { width: 75%; }\n\
.col-pkg span, .col-path span { display: inline-block; max-width: 18em; overflow: hidden; text-overflow: ellipsis; vertical-align: bottom; }\n\
.col-breaks, .col-dur { text-align: right; }\n\
@media (max-width: 100em) { .col-status { display: none; } }\n\
@media (max-width: 93em) { .col-maint { display: none; } }\n\
@media (max-width: 80em) { .col-dur { display: none; } }\n\
@media (max-width: 75em) { .col-path { display: none; } }\n\
@media (max-width: 58em) { .col-breaks { display: none; } }\n";

fn write_html_report(
    db: &Database,
    logdir: &Path,
    path: &Path,
    meta: &ReportMeta,
    diff: Option<&bob::db::BuildDiff>,
) -> Result<()> {
    let mut results = db.get_all_build_results()?;
    let duration = db.get_build_duration()?;

    let sched = bob::Scheduler::new(db)?;
    let breaks_counts: HashMap<String, usize> = sched
        .iter()
        .map(|sp| (sp.pkg.to_string(), sp.dep_count))
        .collect();

    for (pkgname, pkgpath, state) in db.get_prefailskip_packages()? {
        results.push(BuildResult {
            pkgname: pkgsrc::PkgName::new(&pkgname),
            pkgpath: pkgpath.and_then(|p| pkgsrc::PkgPath::new(&p).ok()),
            state,
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

    let mut scanfail: Vec<(pkgsrc::PkgPath, String)> = db
        .get_scan_failures()?
        .into_iter()
        .filter_map(|(p, e)| pkgsrc::PkgPath::new(&p).ok().map(|pp| (pp, e)))
        .collect();
    for r in &results {
        if let PackageState::Unresolved(reason) = &r.state {
            if let Some(pp) = &r.pkgpath {
                scanfail.push((pp.clone(), reason.clone()));
            }
        }
    }

    let summary = BuildSummary {
        duration,
        results,
        scanfail,
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
            let failed_log = result.build_stats.stage.and_then(|stage| {
                BUILD_PHASES
                    .iter()
                    .find(|(name, _)| *name == stage.into_str())
                    .map(|(_, log)| (*log).to_string())
            });
            FailedPackageInfo {
                result,
                breaks_count,
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

    let display_date = match chrono::NaiveDateTime::parse_from_str(meta.build_id, "%Y%m%dT%H%M%SZ")
    {
        Ok(dt) => dt.format("%Y-%m-%d %H:%M").to_string(),
        Err(_) => meta.build_id.to_string(),
    };
    let os = m
        .get("OS_VARIANT")
        .or_else(|| m.get("OPSYS"))
        .context("neither OS_VARIANT nor OPSYS found in metadata")?;
    let ver = m
        .get("LOWER_VARIANT_VERSION")
        .or_else(|| m.get("OS_VERSION"))
        .context("neither LOWER_VARIANT_VERSION nor OS_VERSION found in metadata")?;
    let arch = m
        .get("MACHINE_ARCH")
        .context("MACHINE_ARCH not found in metadata")?;
    let platform = format!("{} {}/{}", os, ver, arch);
    let title = format!("Build Report - {} - {}", platform, display_date);

    writeln!(file, "<!DOCTYPE html>")?;
    writeln!(file, "<html lang=\"en\">")?;
    writeln!(file, "<head>")?;
    writeln!(file, "<meta charset=\"UTF-8\">")?;
    writeln!(
        file,
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    )?;
    writeln!(file, "<title>{}</title>", escape_html(&title))?;
    writeln!(file, "<style>")?;
    write!(file, "{}", REPORT_CSS)?;
    writeln!(file, "</style>")?;
    write_sort_script(&mut file)?;
    writeln!(file, "</head>")?;
    writeln!(file, "<body>")?;

    write_header(&mut file, &platform, &display_date)?;

    writeln!(file, "<div class=\"var-columns\">")?;
    write_statistics_table(&mut file, &summary)?;
    write_platform_table(&mut file, m)?;
    write_paths_table(&mut file, m, &meta.pkgsrc_env.prefix)?;
    write_misc_table(&mut file, meta.vcs_info, summary.duration, db, diff)?;
    writeln!(file, "</div>")?;

    let pkgpath_base = meta.vcs_info.web_url().and_then(|base| {
        meta.vcs_info
            .revision_full
            .as_ref()
            .map(|rev| format!("{}/tree/{}", base, rev))
    });

    if let Some(d) = diff {
        write_diff_section(&mut file, d, &failed_info, pkgpath_base.as_deref())?;
    }

    if !summary.scanfail.is_empty() {
        write_scanfail_table(&mut file, &summary.scanfail, pkgpath_base.as_deref())?;
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
    write_failed_table(
        &mut file,
        "All Failures",
        &failed_info,
        &maintainers,
        logdir,
        pkgpath_base.as_deref(),
    )?;

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
    writeln!(file, "  var h = t.tHead.rows[0].cells;")?;
    writeln!(
        file,
        "  for (var i = 0; i < h.length; i++) h[i].setAttribute('aria-sort', i == col ? (desc ? 'descending' : 'ascending') : 'none');"
    )?;
    writeln!(file, "}}")?;
    writeln!(file, "</script>")?;
    Ok(())
}

fn write_header(file: &mut std::fs::File, platform: &str, date: &str) -> Result<()> {
    writeln!(file, "<div class=\"header\">")?;
    writeln!(file, "<table class=\"header-table\"><tr>")?;
    writeln!(
        file,
        "<td class=\"header-icons\"><a href=\"https://pkgsrc.org/\"><img src=\"https://www.pkgsrc.org/img/pkgsrc-square.png\" alt=\"pkgsrc\" height=\"36\"></a></td>"
    )?;
    writeln!(file, "<td class=\"hdr-label\">Build Report</td>")?;
    writeln!(
        file,
        "<td class=\"hdr-platform\">{}</td>",
        escape_html(platform)
    )?;
    writeln!(file, "<td class=\"hdr-date\">{}</td>", escape_html(date))?;
    write!(
        file,
        "<td class=\"header-icons\" style=\"text-align:right\">"
    )?;
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
    writeln!(file, "</td>")?;
    writeln!(file, "</tr></table>")?;
    writeln!(file, "</div>")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_sortable_th(
    file: &mut std::fs::File,
    table_id: &str,
    col: usize,
    sort_type: &str,
    label: &str,
    class: &str,
    extra_sort: &str,
    aria_sort: &str,
) -> Result<()> {
    let cls = if class.is_empty() {
        String::new()
    } else {
        format!(" class=\"{}\"", class)
    };
    writeln!(
        file,
        "<th{cls} scope=\"col\" role=\"columnheader\" tabindex=\"0\" aria-sort=\"{aria_sort}\" \
         onclick=\"sortTable('{table_id}', {col}, '{sort_type}'{extra_sort})\" \
         onkeydown=\"if(event.key==='Enter')this.click()\">{label}</th>",
    )?;
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
    let c = summary.counts();

    writeln!(file, "<table class=\"vars stats\">")?;
    writeln!(file, "<tr><th colspan=\"2\">Statistics</th></tr>")?;
    write_var_row(file, "Total", &c.states.total().to_string())?;
    write_var_row(file, "Succeeded", &c.states.succeeded().to_string())?;
    write_var_row(file, "Failed", &c.states.failed().to_string())?;
    write_var_row(file, "UpToDate", &c.states.up_to_date().to_string())?;
    write_var_row(file, "Masked", &c.states.masked().to_string())?;
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

fn write_misc_table(
    file: &mut std::fs::File,
    vcs: &bob::vcs::VcsInfo,
    duration: Duration,
    db: &Database,
    diff: Option<&bob::db::BuildDiff>,
) -> Result<()> {
    writeln!(file, "<table class=\"vars\">")?;
    writeln!(file, "<tr><th colspan=\"2\">Miscellaneous</th></tr>")?;

    let web_url = if vcs.is_detected() {
        vcs.web_url()
    } else {
        None
    };
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
    if let Some(d) = diff {
        if let Some((url, old_rev, new_rev)) = build_compare_url(db, vcs, &d.build1_id) {
            writeln!(
                file,
                "<tr><td class=\"vk\">Compare</td>\
                 <td><a href=\"{}\">{}..{}</a></td></tr>",
                escape_html(&url),
                escape_html(&old_rev),
                escape_html(&new_rev),
            )?;
        }
    }
    let dur_secs = duration.as_secs();
    let duration_str = if dur_secs >= 3600 {
        format!(
            "{}h {}m {}s",
            dur_secs / 3600,
            (dur_secs % 3600) / 60,
            dur_secs % 60
        )
    } else if dur_secs >= 60 {
        format!("{}m {}s", dur_secs / 60, dur_secs % 60)
    } else {
        format!("{}s", dur_secs)
    };
    write_var_row(file, "Duration", &duration_str)?;
    writeln!(file, "</table>")?;
    Ok(())
}

fn generate_phase_links(pkg_name: &str, log_dir: &Path) -> String {
    if !log_dir.exists() {
        return String::new();
    }
    let mut links = Vec::new();
    for (phase_name, log_file) in BUILD_PHASES {
        let log_path = log_dir.join(log_file);
        if log_path.exists() {
            links.push(format!(
                "<a href=\"{}/{}\" class=\"phase\">{}</a>",
                pkg_name, log_file, phase_name
            ));
        }
    }
    links.join(" ")
}

fn write_failed_table(
    file: &mut std::fs::File,
    title: &str,
    failed_info: &[FailedPackageInfo],
    maintainers: &HashMap<String, String>,
    logdir: &Path,
    pkgpath_base: Option<&str>,
) -> Result<()> {
    let t = "failed-table";
    writeln!(
        file,
        "<table id=\"{t}\" class=\"data\" data-sort-col=\"6\" data-sort-desc=\"0\">"
    )?;
    writeln!(file, "<caption class=\"sr-only\">Failed packages</caption>")?;
    writeln!(file, "<thead><tr>")?;
    write_sortable_th(file, t, 0, "str", title, "col-pkg", "", "none")?;
    write_sortable_th(file, t, 1, "str", "PkgPath", "col-path", "", "none")?;
    write_sortable_th(file, t, 2, "num", "Breaks", "col-breaks", "", "none")?;
    write_sortable_th(file, t, 3, "num", "Duration", "col-dur", "", "none")?;
    write_sortable_th(file, t, 4, "str", "Maintainer", "col-maint", "", "none")?;
    write_sortable_th(file, t, 5, "str", "Status", "col-status", "", "none")?;
    write_sortable_th(
        file,
        t,
        6,
        "num",
        "Build Logs",
        "col-logs",
        ", 2, 'num'",
        "ascending",
    )?;
    writeln!(file, "</tr></thead>")?;
    writeln!(file, "<tbody>")?;

    for info in failed_info {
        let pkg_name = info.result.pkgname.pkgname();
        let pkgpath_str = info
            .result
            .pkgpath
            .as_ref()
            .map(|p| p.as_path().display().to_string())
            .unwrap_or_default();
        let escaped_path = escape_html(&pkgpath_str);
        let pkgpath = match pkgpath_base {
            Some(base) if !pkgpath_str.is_empty() => format!(
                "<span title=\"{0}\"><a href=\"{1}/{0}\">{0}</a></span>",
                escaped_path,
                escape_html(base),
            ),
            _ => format!("<span title=\"{0}\">{0}</span>", escaped_path),
        };
        let maintainer = maintainers
            .get(pkg_name)
            .map(|s| s.as_str())
            .unwrap_or_default();

        let breaks_display = if info.breaks_count > 0 {
            info.breaks_count.to_string()
        } else {
            String::new()
        };

        if info.result.state.is_skip() {
            let reason = info.result.state.to_string();
            writeln!(
                file,
                "<tr><td class=\"col-pkg indirect\"><span title=\"{0}\">{0}</span></td><td class=\"col-path indirect\">{1}</td><td class=\"col-breaks r indirect\" data-sort=\"{2}\">{3}</td><td class=\"col-dur r indirect\" data-sort=\"0\"></td><td class=\"col-maint indirect\">{4}</td><td class=\"col-status indirect\">{5}</td><td class=\"col-logs reason\" data-sort=\"1\">{6}</td></tr>",
                escape_html(pkg_name),
                pkgpath,
                info.breaks_count,
                breaks_display,
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

        let escaped = escape_html(pkg_name);
        let pkg_link = match &info.failed_log {
            Some(log) => format!(
                "<span title=\"{0}\"><a href=\"{0}/{1}\">{0}</a></span>",
                escaped, log
            ),
            None => format!("<span title=\"{0}\">{0}</span>", escaped),
        };

        let log_dir = logdir.join(pkg_name);
        let phase_links = generate_phase_links(pkg_name, &log_dir);

        writeln!(
            file,
            "<tr><td class=\"col-pkg\">{}</td><td class=\"col-path\">{}</td><td class=\"col-breaks r\" data-sort=\"{}\">{}</td><td class=\"col-dur r\" data-sort=\"{}\">{}</td><td class=\"col-maint\">{}</td><td class=\"col-status\">{}</td><td class=\"col-logs\" data-sort=\"0\">{}</td></tr>",
            pkg_link,
            pkgpath,
            info.breaks_count,
            breaks_display,
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

fn write_diff_section(
    file: &mut std::fs::File,
    diff: &bob::db::BuildDiff,
    failed_info: &[FailedPackageInfo],
    pkgpath_base: Option<&str>,
) -> Result<()> {
    if diff.new_failures.is_empty() {
        return Ok(());
    }

    let info_by_name: HashMap<&str, &FailedPackageInfo> = failed_info
        .iter()
        .map(|i| (i.result.pkgname.pkgname(), i))
        .collect();

    let was_ok = |e: &bob::db::DiffEntry| -> bool {
        matches!(
            e.build1_outcome,
            None | Some(PackageStateKind::Success) | Some(PackageStateKind::UpToDate)
        )
    };

    let mut sorted: Vec<_> = diff.new_failures.iter().collect();
    sorted.sort_by(|a, b| {
        let ai = a
            .build2_pkgname
            .as_deref()
            .and_then(|n| info_by_name.get(n));
        let bi = b
            .build2_pkgname
            .as_deref()
            .and_then(|n| info_by_name.get(n));
        let ab = ai.map(|i| i.breaks_count).unwrap_or(0);
        let bb = bi.map(|i| i.breaks_count).unwrap_or(0);
        was_ok(b).cmp(&was_ok(a)).then_with(|| bb.cmp(&ab))
    });

    let t = "diff-new-failures";
    let title = format!("New Failures Since {}", escape_html(&diff.build1_id));
    writeln!(
        file,
        "<table id=\"{t}\" class=\"data\" data-sort-col=\"2\" data-sort-desc=\"1\">"
    )?;
    writeln!(
        file,
        "<caption class=\"sr-only\">New failures since previous build</caption>"
    )?;
    writeln!(file, "<thead><tr>")?;
    write_sortable_th(file, t, 0, "str", &title, "col-pkg", "", "none")?;
    write_sortable_th(file, t, 1, "str", "PkgPath", "col-path", "", "none")?;
    write_sortable_th(file, t, 2, "num", "Breaks", "col-breaks", "", "none")?;
    write_sortable_th(file, t, 3, "num", "Duration", "col-dur", "", "none")?;
    write_sortable_th(file, t, 4, "str", "Previously", "col-prev", "", "none")?;
    writeln!(file, "</tr></thead>")?;
    writeln!(file, "<tbody>")?;

    for e in &sorted {
        let pkgname = e
            .build2_pkgname
            .as_deref()
            .or(e.build1_pkgname.as_deref())
            .unwrap_or("-");
        let info = info_by_name.get(pkgname);

        let escaped_path = escape_html(&e.pkgpath);
        let pkgpath_cell = match pkgpath_base {
            Some(base) => format!(
                "<span title=\"{0}\"><a href=\"{1}/{0}\">{0}</a></span>",
                escaped_path,
                escape_html(base),
            ),
            None => format!("<span title=\"{0}\">{0}</span>", escaped_path),
        };

        let breaks = info.map(|i| i.breaks_count).unwrap_or(0);
        let breaks_display = if breaks > 0 {
            breaks.to_string()
        } else {
            String::new()
        };

        let (dur_secs, duration) = match info {
            Some(i) => {
                let s = i.result.build_stats.duration.as_secs();
                let d = if s >= 60 {
                    format!("{}m {}s", s / 60, s % 60)
                } else {
                    format!("{}s", s)
                };
                (s, d)
            }
            None => (0, String::new()),
        };

        let previously: &str = e.build1_outcome.map(|o| o.into()).unwrap_or("");

        let escaped = escape_html(pkgname);
        let pkg_link = match info.and_then(|i| i.failed_log.as_deref()) {
            Some(log) => format!(
                "<span title=\"{0}\"><a href=\"{0}/{1}\">{0}</a></span>",
                escaped, log
            ),
            None => format!("<span title=\"{0}\">{0}</span>", escaped),
        };

        writeln!(
            file,
            "<tr><td class=\"col-pkg\">{}</td>\
             <td class=\"col-path\">{}</td>\
             <td class=\"col-breaks r\" data-sort=\"{}\">{}</td>\
             <td class=\"col-dur r\" data-sort=\"{}\">{}</td>\
             <td class=\"col-prev\">{}</td></tr>",
            pkg_link, pkgpath_cell, breaks, breaks_display, dur_secs, duration, previously,
        )?;
    }

    writeln!(file, "</tbody>")?;
    writeln!(file, "</table>")?;
    Ok(())
}

/**
 * Build a compare URL and revision pair for two builds.
 *
 * If both builds have revisions and a web URL is available, returns
 * a GitHub-style compare URL and the two revision strings.
 */
fn build_compare_url(
    db: &Database,
    vcs_info: &bob::vcs::VcsInfo,
    build1_id: &str,
) -> Option<(String, String, String)> {
    let web_url = vcs_info.web_url()?;
    let old_rev = db.get_build_revision(build1_id).ok()??;
    let new_rev = vcs_info.revision.as_deref()?;
    let url = format!("{}/compare/{}..{}", web_url, old_rev, new_rev);
    Some((url, old_rev, new_rev.to_string()))
}

fn write_scanfail_table(
    file: &mut std::fs::File,
    scanfail: &[(pkgsrc::PkgPath, String)],
    pkgpath_base: Option<&str>,
) -> Result<()> {
    let t = "scanfail-table";
    writeln!(
        file,
        "<table id=\"{t}\" class=\"data\" style=\"white-space:normal\">"
    )?;
    writeln!(file, "<caption class=\"sr-only\">Scan failures</caption>")?;
    writeln!(file, "<thead><tr>")?;
    write_sortable_th(file, t, 0, "str", "PKGPATH", "", "", "none")?;
    write_sortable_th(file, t, 1, "str", "Scan Error", "col-err", "", "none")?;
    writeln!(file, "</tr></thead>")?;
    writeln!(file, "<tbody>")?;

    for (pkgpath, error_msg) in scanfail {
        let path_str = pkgpath.as_path().display().to_string();
        let path_html = match pkgpath_base {
            Some(base) => format!(
                "<a href=\"{}/{}\">{}</a>",
                escape_html(base),
                escape_html(&path_str),
                escape_html(&path_str)
            ),
            None => escape_html(&path_str),
        };
        writeln!(
            file,
            "<tr><td>{}</td><td>{}</td></tr>",
            path_html,
            escape_html(error_msg)
        )?;
    }

    writeln!(file, "</tbody>")?;
    writeln!(file, "</table>")?;
    Ok(())
}
