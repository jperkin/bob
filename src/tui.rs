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

//! Line-based progress display using ratatui's inline viewport.

use crossterm::cursor::Show;
use crossterm::ExecutableCommand;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    text::Line,
    Terminal, TerminalOptions, Viewport,
};
use std::io::{self, stdout, Stdout};
use std::time::{Duration, Instant};

/// State for a single worker thread.
#[derive(Clone, Debug)]
pub struct WorkerState {
    pub package: Option<String>,
    pub stage: Option<String>,
    pub started: Option<Instant>,
}

impl WorkerState {
    pub fn new() -> Self {
        Self {
            package: None,
            stage: None,
            started: None,
        }
    }

    pub fn set_active(&mut self, package: &str) {
        self.package = Some(package.to_string());
        self.stage = None;
        self.started = Some(Instant::now());
    }

    pub fn set_idle(&mut self) {
        self.package = None;
        self.stage = None;
        self.started = None;
    }

    pub fn set_stage(&mut self, stage: Option<&str>) {
        self.stage = stage.map(|s| s.to_string());
    }

    pub fn elapsed(&self) -> Option<Duration> {
        self.started.map(|s| s.elapsed())
    }
}

/// Progress state shared between threads.
#[derive(Clone, Debug)]
pub struct ProgressState {
    pub title: String,
    pub finished_title: String,
    pub total: usize,
    pub completed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub show_skipped: bool,
    pub workers: Vec<WorkerState>,
    pub started: Instant,
    /// Current timer width tier (6, 10, or 13)
    pub timer_width: usize,
    /// Whether output is suppressed (e.g., during shutdown)
    pub suppressed: bool,
}

impl ProgressState {
    pub fn new(title: &str, finished_title: &str, total: usize, num_workers: usize, show_skipped: bool) -> Self {
        let workers = (0..num_workers).map(|_| WorkerState::new()).collect();
        Self {
            title: title.to_string(),
            finished_title: finished_title.to_string(),
            total,
            completed: 0,
            failed: 0,
            skipped: 0,
            show_skipped,
            workers,
            started: Instant::now(),
            timer_width: 6,
            suppressed: false,
        }
    }

    pub fn suppress(&mut self) {
        self.suppressed = true;
    }

    /// Update timer width tier based on elapsed durations.
    /// Returns true if width changed.
    pub fn update_timer_width(&mut self) -> bool {
        let old_width = self.timer_width;

        // Check main elapsed time
        let main_secs = self.started.elapsed().as_secs();
        let mut max_secs = main_secs;

        // Check all worker elapsed times
        for worker in &self.workers {
            if let Some(elapsed) = worker.elapsed() {
                max_secs = max_secs.max(elapsed.as_secs());
            }
        }

        // Expand width based on max seconds seen
        // Width tiers: 6 (for "XX.Xs"), 8 (for "Xm XXs"), 9 (for "XXm XXs"), 13 (for "XXh XXm XXs")
        if max_secs >= 3600 && self.timer_width < 13 {
            // 1 hour or more needs 13 chars (e.g., "99h 59m 59s")
            self.timer_width = 13;
        } else if max_secs >= 600 && self.timer_width < 9 {
            // 10 minutes or more needs 9 chars (e.g., "10m 59s" = 7 chars + padding)
            self.timer_width = 9;
        } else if max_secs >= 60 && self.timer_width < 8 {
            // 1 minute or more needs 8 chars (e.g., "9m 59s" = 6 chars + padding)
            self.timer_width = 8;
        }

        self.timer_width != old_width
    }

    pub fn set_worker_active(&mut self, id: usize, package: &str) {
        if let Some(worker) = self.workers.get_mut(id) {
            worker.set_active(package);
        }
    }

    pub fn set_worker_idle(&mut self, id: usize) {
        if let Some(worker) = self.workers.get_mut(id) {
            worker.set_idle();
        }
    }

    pub fn set_worker_stage(&mut self, id: usize, stage: Option<&str>) {
        if let Some(worker) = self.workers.get_mut(id) {
            worker.set_stage(stage);
        }
    }

    pub fn increment_completed(&mut self) {
        self.completed += 1;
    }

    pub fn increment_failed(&mut self) {
        self.failed += 1;
    }

    pub fn increment_skipped(&mut self) {
        self.skipped += 1;
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub fn progress_ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.completed + self.failed + self.skipped) as f64 / self.total as f64
        }
    }
}

/// Format a duration in human-readable form.
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m {}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

/// Format a duration with decimal seconds for short durations.
fn format_duration_short(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 60.0 {
        format!("{:.1}s", secs)
    } else {
        format_duration(d)
    }
}

/// Line-based progress display using ratatui inline viewport.
pub struct MultiProgress {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    state: ProgressState,
}

impl MultiProgress {
    pub fn new(title: &str, finished_title: &str, total: usize, num_workers: usize, show_skipped: bool) -> io::Result<Self> {
        // Calculate height: workers + progress bar
        let height = (num_workers + 1) as u16;

        let backend = CrosstermBackend::new(stdout());
        let options = TerminalOptions {
            viewport: Viewport::Inline(height),
        };
        let terminal = Terminal::with_options(backend, options)?;

        Ok(Self {
            terminal,
            state: ProgressState::new(title, finished_title, total, num_workers, show_skipped),
        })
    }

    pub fn state_mut(&mut self) -> &mut ProgressState {
        &mut self.state
    }

    /// Print a status message above the progress display.
    pub fn print_status(&mut self, msg: &str) -> io::Result<()> {
        // Don't print if suppressed
        if self.state.suppressed {
            return Ok(());
        }
        // Insert blank lines to scroll up the viewport, then print message
        self.terminal.insert_before(1, |buf| {
            let line = Line::raw(msg);
            let area = buf.area;
            buf.set_line(0, 0, &line, area.width);
        })?;
        Ok(())
    }

    pub fn render(&mut self) -> io::Result<()> {
        // Don't render if suppressed
        if self.state.suppressed {
            return Ok(());
        }
        self.state.update_timer_width();
        let state = &self.state;

        self.terminal.draw(|frame| {
            let area = frame.area();

            // Create constraints for each line
            let mut constraints: Vec<Constraint> = state.workers
                .iter()
                .map(|_| Constraint::Length(1))
                .collect();
            constraints.push(Constraint::Length(1)); // Progress bar

            let chunks = Layout::vertical(constraints).split(area);

            // Render worker lines
            let tw = state.timer_width;
            for (i, worker) in state.workers.iter().enumerate() {
                let text = if let (Some(pkg), Some(elapsed)) = (&worker.package, worker.elapsed()) {
                    if let Some(stage) = &worker.stage {
                        format!("  [{:>2}:{:>tw$} ] {} ({})", i, format_duration_short(elapsed), pkg, stage, tw = tw)
                    } else {
                        format!("  [{:>2}:{:>tw$} ] {}", i, format_duration_short(elapsed), pkg, tw = tw)
                    }
                } else {
                    format!("  [{:>2}:{:>tw$} ]", i, "idle", tw = tw)
                };
                frame.render_widget(Line::raw(text), chunks[i]);
            }

            // Render cargo-style progress bar: Scanning [====>        ] 5/20 1.2s
            let ratio = state.progress_ratio();
            let elapsed_str = format_duration_short(state.elapsed());

            // Fixed width progress bar
            let bar_width: usize = 30;
            let filled = (ratio * bar_width as f64) as usize;
            let empty = bar_width.saturating_sub(filled).saturating_sub(1);
            let bar = if filled >= bar_width {
                "=".repeat(bar_width)
            } else if filled == 0 {
                format!(">{}", " ".repeat(bar_width.saturating_sub(1)))
            } else {
                format!("{}>{}", "=".repeat(filled), " ".repeat(empty))
            };

            let line = format!(
                "{:>12} [{}] {}/{} {}",
                state.title,
                bar,
                state.completed + state.failed + state.skipped,
                state.total,
                elapsed_str
            );
            frame.render_widget(Line::raw(line), chunks[state.workers.len()]);
        })?;

        Ok(())
    }

    pub fn render_throttled(&mut self) -> io::Result<()> {
        self.render()
    }

    pub fn finish(&mut self) -> io::Result<()> {
        // Clear the inline viewport area
        self.terminal.clear()?;

        // Restore cursor
        stdout().execute(Show)?;

        // Print final summary to stdout (outside ratatui)
        let elapsed = format_duration(self.state.elapsed());
        if self.state.show_skipped {
            println!(
                "{} {} packages in {} ({} succeeded, {} failed, {} skipped)",
                self.state.finished_title,
                self.state.completed + self.state.failed + self.state.skipped,
                elapsed,
                self.state.completed,
                self.state.failed,
                self.state.skipped
            );
        } else {
            println!(
                "{} {} packages in {} ({} succeeded, {} failed)",
                self.state.finished_title,
                self.state.completed + self.state.failed,
                elapsed,
                self.state.completed,
                self.state.failed
            );
        }

        Ok(())
    }

    /// Finish display with an interrupted message (for Ctrl+C handling).
    pub fn finish_interrupted(&mut self) -> io::Result<()> {
        // Suppress any further output
        self.state.suppressed = true;

        // Clear the inline viewport area
        self.terminal.clear()?;

        // Restore cursor
        stdout().execute(Show)?;

        // Print interrupted message
        println!("Interrupted, shutting down...");

        Ok(())
    }
}

impl Drop for MultiProgress {
    fn drop(&mut self) {
        // Ensure cursor is visible when dropped
        let _ = stdout().execute(Show);
    }
}
