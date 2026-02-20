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

use anyhow::{Context, Result};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/**
 * Thread-safe run state, shared across threads via internal `Arc`.
 *
 * Signal handlers store values via the inner `AtomicUsize`.
 * Use [`load`], [`interrupted`], and [`is_shutdown`] to query state.
 *
 * [`load`]: RunState::load
 * [`interrupted`]: RunState::interrupted
 * [`is_shutdown`]: RunState::is_shutdown
 */
#[derive(Clone, Debug, Default)]
pub struct RunState(Arc<AtomicUsize>);

impl RunState {
    const RUNNING: usize = 0;
    const STOPPING: usize = 1;
    const SHUTDOWN: usize = 2;

    /** Create a new run state initialized to running. */
    pub fn new() -> Self {
        Self(Arc::new(AtomicUsize::new(Self::RUNNING)))
    }

    fn load(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    /** Advance state by one step (RUNNING -> STOPPING -> SHUTDOWN). */
    pub fn advance(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    /** Set state to immediate shutdown. */
    pub fn shutdown(&self) {
        self.0.store(Self::SHUTDOWN, Ordering::SeqCst);
    }

    /** Returns true if the run was interrupted (stop or shutdown). */
    pub fn interrupted(&self) -> bool {
        self.load() != Self::RUNNING
    }

    /** Returns true if stopping (finishing current work, no new dispatches). */
    pub fn is_stopping(&self) -> bool {
        self.load() == Self::STOPPING
    }

    /** Returns true if immediate shutdown has been requested. */
    pub fn is_shutdown(&self) -> bool {
        self.load() >= Self::SHUTDOWN
    }

    /**
     * Register signal handlers for graceful interruption.
     *
     * SIGINT advances state: RUNNING -> STOPPING -> SHUTDOWN.
     * SIGTERM goes straight to SHUTDOWN.
     */
    pub fn register_signals(&self) -> Result<()> {
        let mut signals =
            Signals::new([SIGINT, SIGTERM]).context("Failed to register signal handlers")?;
        let state = self.clone();
        std::thread::spawn(move || {
            for sig in signals.forever() {
                match sig {
                    SIGINT => state.advance(),
                    SIGTERM => state.shutdown(),
                    _ => {}
                }
            }
        });
        Ok(())
    }
}
