/*
 * Copyright (c) 2025 Jonathan Perkin <jonathan@perkin.org.uk>
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
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

static LOG_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

/// Initialize the logging system.
/// Creates a logs directory and writes JSON-formatted logs there.
/// Also logs to stderr if verbose mode is enabled.
pub fn init(logs_dir: &PathBuf, verbose: bool) -> Result<()> {
    // Create logs directory
    fs::create_dir_all(logs_dir).with_context(|| {
        format!("Failed to create logs directory {:?}", logs_dir)
    })?;

    // Create a rolling file appender that writes to logs/bob.log
    let file_appender = tracing_appender::rolling::never(logs_dir, "bob.log");
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
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true);

    // Set up env filter - allow RUST_LOG to override
    // verbose mode uses debug level, otherwise info level
    let default_filter = if verbose { "bob=debug" } else { "bob=info" };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_filter));

    tracing_subscriber::registry().with(filter).with(file_layer).init();

    tracing::info!(
        logs_dir = %logs_dir.display(),
        verbose = verbose,
        "Logging initialized"
    );

    Ok(())
}
