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
 * Logging infrastructure, outputs bunyan-style JSON to a logs directory.
 */

use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
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
 * span chain carries `pkgname` and `logdir` fields to
 * `<logdir>/<pkgname>/setup.log`.
 *
 * Indirect failures and unresolved packages never get a build span (they're
 * filtered out at scheduler load time), so they naturally produce no log.
 */
struct PerPackageLayer;

struct SetupLog {
    path: PathBuf,
    writer: Mutex<Option<File>>,
}

#[derive(Default)]
struct BuildSpanVisitor {
    pkgname: Option<String>,
    logdir: Option<String>,
}

impl Visit for BuildSpanVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "pkgname" => self.pkgname = Some(value.to_string()),
            "logdir" => self.logdir = Some(value.to_string()),
            _ => {}
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let target = match field.name() {
            "pkgname" if self.pkgname.is_none() => &mut self.pkgname,
            "logdir" if self.logdir.is_none() => &mut self.logdir,
            _ => return,
        };
        *target = Some(format!("{value:?}").trim_matches('"').to_string());
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
        let mut visitor = BuildSpanVisitor::default();
        attrs.record(&mut visitor);
        let (Some(pkgname), Some(logdir)) = (visitor.pkgname, visitor.logdir) else {
            return;
        };
        let Some(span) = ctx.span(id) else {
            return;
        };
        span.extensions_mut().insert(SetupLog {
            path: PathBuf::from(logdir).join(&pkgname).join("setup.log"),
            writer: Mutex::new(None),
        });
    }

    fn on_event(&self, event: &Event<'_>, ctx: LayerContext<'_, S>) {
        let Some(scope) = ctx.event_scope(event) else {
            return;
        };
        for span in scope.from_root() {
            let exts = span.extensions();
            let Some(log) = exts.get::<SetupLog>() else {
                continue;
            };
            let mut guard = log.writer.lock().expect("setup.log mutex poisoned");
            let writer = match guard.as_mut() {
                Some(w) => w,
                None => {
                    let f = File::create(&log.path).unwrap_or_else(|e| {
                        panic!("Failed to create {}: {}", log.path.display(), e)
                    });
                    guard.insert(f)
                }
            };
            let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
            let level = event.metadata().level();
            let mut msg = String::new();
            let mut formatter = EventFormatter { buf: &mut msg };
            event.record(&mut formatter);
            let _ = writeln!(writer, "{now} [{level:>5}] {msg}");
            return;
        }
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
 * setup.log driven by `pkgname` and `logdir` fields on build spans.
 */
pub fn init(dbdir: &PathBuf, log_level: &str) -> Result<()> {
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

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(PerPackageLayer)
        .init();

    tracing::info!(dbdir = %dbdir.display(),
        log_level = log_level,
        "Logging initialized"
    );

    Ok(())
}
