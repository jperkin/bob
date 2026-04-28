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

/*
 * Logging infrastructure, outputs bunyan-style JSON to a logs directory.
 */

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Subscriber};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{Builder, Rotation};
use tracing_subscriber::layer::{Context as LayerContext, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, fmt, util::SubscriberInitExt};

static LOG_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

/**
 * Per-package log: a [`Layer`] that routes any tracing event whose enclosing
 * span chain carries a `pkgname` field to `<logdir>/<pkgname>/setup.log`.
 *
 * Indirect failures and unresolved packages never get a build span (they're
 * filtered out at scheduler load time), so they naturally produce no log.
 */
struct PerPackageLayer {
    logdir: PathBuf,
    files: Mutex<HashMap<String, BufWriter<File>>>,
}

impl PerPackageLayer {
    fn new(logdir: PathBuf) -> Self {
        Self {
            logdir,
            files: Mutex::new(HashMap::new()),
        }
    }
}

#[derive(Clone)]
struct SpanPkgname(String);

#[derive(Default)]
struct PkgnameVisitor(Option<String>);

impl Visit for PkgnameVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "pkgname" {
            self.0 = Some(value.to_string());
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "pkgname" && self.0.is_none() {
            self.0 = Some(format!("{value:?}").trim_matches('"').to_string());
        }
    }
}

struct EventFormatter<'a> {
    buf: &'a mut String,
}

impl Visit for EventFormatter<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        use std::fmt::Write;
        if field.name() == "message" {
            self.buf.push_str(value);
        } else {
            let _ = write!(self.buf, " {}={value}", field.name());
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        if field.name() == "message" {
            let _ = write!(self.buf, "{value:?}");
        } else {
            let _ = write!(self.buf, " {}={value:?}", field.name());
        }
    }
}

impl<S> Layer<S> for PerPackageLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: LayerContext<'_, S>) {
        let mut visitor = PkgnameVisitor::default();
        attrs.record(&mut visitor);
        if let Some(name) = visitor.0
            && let Some(span) = ctx.span(id)
        {
            span.extensions_mut().insert(SpanPkgname(name));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: LayerContext<'_, S>) {
        let Some(scope) = ctx.event_scope(event) else {
            return;
        };
        let Some(pkgname) = scope
            .from_root()
            .find_map(|span| span.extensions().get::<SpanPkgname>().map(|p| p.0.clone()))
        else {
            return;
        };

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let level = event.metadata().level();
        let mut msg = String::new();
        let mut formatter = EventFormatter { buf: &mut msg };
        event.record(&mut formatter);

        let mut files = self.files.lock().expect("per-package log mutex poisoned");
        let writer = match files.entry(pkgname.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => {
                let dir = self.logdir.join(&pkgname);
                if fs::create_dir_all(&dir).is_err() {
                    return;
                }
                let Ok(f) = OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(dir.join("setup.log"))
                else {
                    return;
                };
                v.insert(BufWriter::new(f))
            }
        };
        let _ = writeln!(writer, "{now} [{level:>5}] {msg}");
        let _ = writer.flush();
    }
}

/**
 * Initialize stderr logging if RUST_LOG is set.
 *
 * For utility commands that don't need file logging but should support
 * debug output when explicitly requested.
 */
pub fn init_stderr_if_enabled() {
    if std::env::var("RUST_LOG").is_err() {
        return;
    }

    let filter = EnvFilter::from_default_env();

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time();

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .try_init();
}

/**
 * Initialize the logging system.
 *
 * Creates the dbdir and writes bob.log there, plus a per-package
 * setup.log under logdir for packages that hit a build span.
 */
pub fn init(dbdir: &PathBuf, logdir: &Path, log_level: &str) -> Result<()> {
    fs::create_dir_all(dbdir)
        .with_context(|| format!("Failed to create dbdir {}", dbdir.display()))?;

    let file_appender = Builder::new()
        .rotation(Rotation::NEVER)
        .filename_prefix("bob.log")
        .build(dbdir)
        .with_context(|| format!("Failed to open log file {}/bob.log", dbdir.display()))?;
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Store the guard to keep the writer alive
    LOG_GUARD
        .set(guard)
        .map_err(|_| anyhow::anyhow!("Logging already initialized"))?;

    // Build the subscriber with JSON formatting for files
    let file_layer = fmt::layer()
        .json()
        .with_writer(non_blocking)
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .with_line_number(false)
        .with_span_list(false);

    // Set up env filter - allow RUST_LOG to override
    let default_filter = format!("bob={}", log_level);
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&default_filter));

    let per_pkg_layer = PerPackageLayer::new(logdir.to_path_buf());

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(per_pkg_layer)
        .init();

    tracing::info!(dbdir = %dbdir.display(),
        log_level = log_level,
        "Logging initialized"
    );

    Ok(())
}
