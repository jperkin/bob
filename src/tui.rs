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

use crossterm::ExecutableCommand;
use crossterm::cursor::Show;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
    enable_raw_mode,
};
use ratatui::{
    Terminal, TerminalOptions, Viewport,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    text::Line,
    widgets::{Block, Borders, Clear, Paragraph},
};
use std::collections::VecDeque;
use std::io::{self, Stdout, stdout};
use std::time::{Duration, Instant};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Strip ANSI escape sequences and sanitize control characters.
fn sanitize_output(s: &str) -> String {
    let stripped = strip_ansi_escapes::strip(s);
    let s = String::from_utf8_lossy(&stripped);
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\t' => out.push_str("        "),
            '\x00'..='\x1f' | '\x7f' => {}
            _ => out.push(ch),
        }
    }
    out
}

/// Ring buffer for build output with fixed line capacity.
#[derive(Clone, Debug)]
pub struct OutputBuffer {
    lines: VecDeque<String>,
    capacity: usize,
}

impl OutputBuffer {
    pub fn new(capacity: usize) -> Self {
        Self { lines: VecDeque::with_capacity(capacity), capacity }
    }

    pub fn push(&mut self, line: String) {
        // Strip ANSI escapes and sanitize control characters before storing.
        let clean_line = sanitize_output(&line);
        // If carriage returns are present, keep only the final segment.
        let clean_line = clean_line.rsplit('\r').next().unwrap_or("");
        if self.lines.len() >= self.capacity {
            self.lines.pop_front();
        }
        self.lines.push_back(clean_line.to_string());
    }

    pub fn last_n(&self, n: usize) -> impl Iterator<Item = &String> {
        let skip = self.lines.len().saturating_sub(n);
        self.lines.iter().skip(skip)
    }

    pub fn clear(&mut self) {
        self.lines.clear();
    }
}

/// Display mode for the TUI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewMode {
    /// Inline progress display (default).
    Inline,
    /// Fullscreen multi-panel view showing build output.
    MultiPanel,
}

/// State for a single worker thread.
#[derive(Clone, Debug)]
pub struct WorkerState {
    pub package: Option<String>,
    pub stage: Option<String>,
    pub started: Option<Instant>,
}

impl WorkerState {
    pub fn new() -> Self {
        Self { package: None, stage: None, started: None }
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
    pub fn new(
        title: &str,
        finished_title: &str,
        total: usize,
        num_workers: usize,
        show_skipped: bool,
    ) -> Self {
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
            (self.completed + self.failed + self.skipped) as f64
                / self.total as f64
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
    if secs < 60.0 { format!("{:.1}s", secs) } else { format_duration(d) }
}

/// Calculate grid layout for N panels.
/// If terminal width < 160, use vertical stack (full width panels).
/// Otherwise use a roughly square grid.
fn calculate_grid(area: Rect, num_panels: usize) -> Vec<Rect> {
    if num_panels == 0 {
        return vec![];
    }

    // For narrow terminals, stack panels vertically (full width each)
    if area.width < 160 {
        let constraints: Vec<Constraint> = (0..num_panels)
            .map(|_| Constraint::Ratio(1, num_panels as u32))
            .collect();

        return Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(area)
            .to_vec();
    }

    // For wide terminals, use a roughly square grid
    let cols = (num_panels as f64).sqrt().ceil() as usize;
    let rows = num_panels.div_ceil(cols);

    let row_constraints: Vec<Constraint> =
        (0..rows).map(|_| Constraint::Ratio(1, rows as u32)).collect();
    let col_constraints: Vec<Constraint> =
        (0..cols).map(|_| Constraint::Ratio(1, cols as u32)).collect();

    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(row_constraints)
        .split(area);

    let mut panels = Vec::with_capacity(num_panels);
    for (row_idx, row_area) in row_chunks.iter().enumerate() {
        let col_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(col_constraints.clone())
            .split(*row_area);

        for (col_idx, col_area) in col_chunks.iter().enumerate() {
            let panel_idx = row_idx * cols + col_idx;
            if panel_idx < num_panels {
                panels.push(*col_area);
            }
        }
    }
    panels
}

/// Line-based progress display using ratatui inline viewport.
pub struct MultiProgress {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    state: ProgressState,
    view_mode: ViewMode,
    output_buffers: Vec<OutputBuffer>,
    num_workers: usize,
    /// Messages buffered while in fullscreen mode, printed when returning to inline.
    pending_messages: Vec<String>,
}

impl MultiProgress {
    pub fn new(
        title: &str,
        finished_title: &str,
        total: usize,
        num_workers: usize,
        show_skipped: bool,
    ) -> io::Result<Self> {
        // Calculate height: workers + progress bar
        let height = (num_workers + 1) as u16;

        // Enable raw mode to capture keyboard events
        enable_raw_mode()?;

        let backend = CrosstermBackend::new(stdout());
        let options = TerminalOptions { viewport: Viewport::Inline(height) };
        let terminal = Terminal::with_options(backend, options)?;

        // Create output buffer for each worker (100 lines each)
        let output_buffers =
            (0..num_workers).map(|_| OutputBuffer::new(100)).collect();

        Ok(Self {
            terminal,
            state: ProgressState::new(
                title,
                finished_title,
                total,
                num_workers,
                show_skipped,
            ),
            view_mode: ViewMode::Inline,
            output_buffers,
            num_workers,
            pending_messages: Vec::new(),
        })
    }

    pub fn state_mut(&mut self) -> &mut ProgressState {
        &mut self.state
    }

    #[allow(dead_code)]
    pub fn view_mode(&self) -> ViewMode {
        self.view_mode
    }

    pub fn output_buffer_mut(
        &mut self,
        id: usize,
    ) -> Option<&mut OutputBuffer> {
        self.output_buffers.get_mut(id)
    }

    pub fn clear_output_buffer(&mut self, id: usize) {
        if let Some(buf) = self.output_buffers.get_mut(id) {
            buf.clear();
        }
    }

    /// Print a status message above the progress display.
    pub fn print_status(&mut self, msg: &str) -> io::Result<()> {
        // Don't print if suppressed
        if self.state.suppressed {
            return Ok(());
        }
        // Buffer messages while in fullscreen mode
        if self.view_mode == ViewMode::MultiPanel {
            self.pending_messages.push(msg.to_string());
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
            let mut constraints: Vec<Constraint> =
                state.workers.iter().map(|_| Constraint::Length(1)).collect();
            constraints.push(Constraint::Length(1)); // Progress bar

            let chunks = Layout::vertical(constraints).split(area);

            // Render worker lines
            let tw = state.timer_width;
            for (i, worker) in state.workers.iter().enumerate() {
                let text = if let (Some(pkg), Some(elapsed)) =
                    (&worker.package, worker.elapsed())
                {
                    if let Some(stage) = &worker.stage {
                        format!(
                            "  [{:>2}:{:>tw$} ] {} ({})",
                            i,
                            format_duration_short(elapsed),
                            pkg,
                            stage,
                            tw = tw
                        )
                    } else {
                        format!(
                            "  [{:>2}:{:>tw$} ] {}",
                            i,
                            format_duration_short(elapsed),
                            pkg,
                            tw = tw
                        )
                    }
                } else {
                    format!("  [{:>2}:{:>tw$} ]", i, "idle", tw = tw)
                };
                frame.render_widget(Line::raw(text), chunks[i]);
            }

            // Render cargo-style progress bar: Scanning [====>        ] 5/20 1.2s
            let ratio = state.progress_ratio();
            let elapsed_str = format_duration_short(state.elapsed());
            let counts = format!(
                "{}/{}",
                state.completed + state.failed + state.skipped,
                state.total
            );

            // Calculate bar width: shrink if needed to fit hint, max 30
            let hint = if state.title == "Building" {
                "(press 'v' to toggle full-screen)"
            } else {
                ""
            };
            let width = area.width as usize;
            // Fixed parts: "{:>12} [" (14) + "] " (2) + counts + " " + elapsed + " " + hint
            let fixed = 14 + 2 + counts.len() + 1 + elapsed_str.len()
                + if hint.is_empty() { 0 } else { 1 + hint.len() };
            let bar_width = width.saturating_sub(fixed).clamp(1, 30);
            let padding = width.saturating_sub(fixed + bar_width);

            let filled = (ratio * bar_width as f64) as usize;
            let empty = bar_width.saturating_sub(filled).saturating_sub(1);
            let bar = if filled >= bar_width {
                "=".repeat(bar_width)
            } else if filled == 0 {
                format!(">{}", " ".repeat(bar_width.saturating_sub(1)))
            } else {
                format!("{}>{}", "=".repeat(filled), " ".repeat(empty))
            };

            let line = if hint.is_empty() {
                format!(
                    "{:>12} [{}] {} {}",
                    state.title, bar, counts, elapsed_str
                )
            } else {
                format!(
                    "{:>12} [{}] {} {}{:pad$} {}",
                    state.title, bar, counts, elapsed_str, "", hint, pad = padding
                )
            };
            frame.render_widget(Line::raw(line), chunks[state.workers.len()]);
        })?;

        Ok(())
    }

    pub fn render_throttled(&mut self) -> io::Result<()> {
        match self.view_mode {
            ViewMode::Inline => self.render(),
            ViewMode::MultiPanel => self.render_multipanel(),
        }
    }

    /// Poll for keyboard events (non-blocking).
    /// Returns Ok(true) if view mode was toggled, Err if Ctrl+C pressed.
    pub fn poll_events(&mut self) -> io::Result<bool> {
        if self.state.suppressed {
            return Ok(false);
        }

        // Non-blocking poll
        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                // Toggle view mode on 'v' key
                if key.code == KeyCode::Char('v') && key.modifiers.is_empty() {
                    self.toggle_view_mode()?;
                    return Ok(true);
                }
                // Handle Ctrl+C - raise SIGINT to trigger the ctrlc handler
                if key.code == KeyCode::Char('c')
                    && key.modifiers.contains(KeyModifiers::CONTROL)
                {
                    unsafe {
                        libc::raise(libc::SIGINT);
                    }
                }
            }
        }
        Ok(false)
    }

    /// Toggle between inline and multi-panel view modes.
    pub fn toggle_view_mode(&mut self) -> io::Result<()> {
        match self.view_mode {
            ViewMode::Inline => self.switch_to_multipanel()?,
            ViewMode::MultiPanel => self.switch_to_inline()?,
        }
        Ok(())
    }

    /// Switch to fullscreen multi-panel mode.
    fn switch_to_multipanel(&mut self) -> io::Result<()> {
        // Clear the inline viewport first
        self.terminal.clear()?;

        // Enter alternate screen for fullscreen (raw mode already enabled)
        stdout().execute(EnterAlternateScreen)?;

        // Recreate terminal with fullscreen viewport
        let backend = CrosstermBackend::new(stdout());
        self.terminal = Terminal::new(backend)?;
        self.view_mode = ViewMode::MultiPanel;

        Ok(())
    }

    /// Switch back to inline progress mode.
    fn switch_to_inline(&mut self) -> io::Result<()> {
        // Leave alternate screen (stay in raw mode for keyboard input)
        stdout().execute(LeaveAlternateScreen)?;

        // Recreate terminal with inline viewport
        let height = (self.num_workers + 1) as u16;
        let backend = CrosstermBackend::new(stdout());
        let options = TerminalOptions { viewport: Viewport::Inline(height) };
        self.terminal = Terminal::with_options(backend, options)?;
        self.view_mode = ViewMode::Inline;

        // Print any messages that were buffered while in fullscreen mode
        for msg in self.pending_messages.drain(..) {
            self.terminal.insert_before(1, |buf| {
                let line = Line::raw(&msg);
                let area = buf.area;
                buf.set_line(0, 0, &line, area.width);
            })?;
        }

        Ok(())
    }

    /// Render multi-panel fullscreen view.
    fn render_multipanel(&mut self) -> io::Result<()> {
        if self.state.suppressed {
            return Ok(());
        }

        self.state.update_timer_width();

        // Pre-compute panel data to avoid borrowing issues with draw closure
        let num_workers = self.num_workers;
        let panel_data: Vec<_> = (0..num_workers)
            .map(|i| {
                let title = if let Some(w) = self.state.workers.get(i) {
                    if let Some(pkg) = &w.package {
                        let stage = w.stage.as_deref().unwrap_or("");
                        let elapsed = w
                            .elapsed()
                            .map(format_duration_short)
                            .unwrap_or_default();
                        if stage.is_empty() {
                            format!("[{}] {} {}", i, pkg, elapsed)
                        } else {
                            format!("[{}] {} ({}) {}", i, pkg, stage, elapsed)
                        }
                    } else {
                        format!("[{}] idle", i)
                    }
                } else {
                    format!("[{}]", i)
                };

                // Capture last 100 logical lines; draw will trim to fit panel.
                let lines = self
                    .output_buffers
                    .get(i)
                    .map(|buf| buf.last_n(100).cloned().collect::<Vec<_>>())
                    .unwrap_or_default();

                (title, lines)
            })
            .collect();

        self.terminal.draw(|frame| {
            let area = frame.area();
            let panels = calculate_grid(area, num_workers);

            for (i, panel_area) in panels.iter().enumerate() {
                if let Some((title, lines)) = panel_data.get(i) {
                    // Clear the panel area first to remove old content
                    frame.render_widget(Clear, *panel_area);

                    let block = Block::default()
                        .title(title.as_str())
                        .borders(Borders::ALL);

                    let inner_width =
                        panel_area.width.saturating_sub(2) as usize;
                    let inner_height =
                        panel_area.height.saturating_sub(2) as usize;

                    let visible =
                        build_visible_lines(lines, inner_width, inner_height);

                    let paragraph = Paragraph::new(visible).block(block);

                    frame.render_widget(paragraph, *panel_area);
                }
            }
        })?;

        Ok(())
    }

    pub fn finish(&mut self) -> io::Result<()> {
        // If in multi-panel mode, leave alternate screen first
        if self.view_mode == ViewMode::MultiPanel {
            let _ = stdout().execute(LeaveAlternateScreen);
        }

        // Disable raw mode (always enabled during TUI)
        let _ = disable_raw_mode();

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

        // If in multi-panel mode, leave alternate screen first
        if self.view_mode == ViewMode::MultiPanel {
            let _ = stdout().execute(LeaveAlternateScreen);
        }

        // Disable raw mode (always enabled during TUI)
        let _ = disable_raw_mode();

        // Clear the inline viewport area
        self.terminal.clear()?;

        // Restore cursor
        stdout().execute(Show)?;

        // Print interrupted message
        println!("Interrupted, shutting down...");

        Ok(())
    }
}

fn build_visible_lines(
    lines: &[String],
    width: usize,
    height: usize,
) -> Vec<Line<'static>> {
    if width == 0 || height == 0 {
        return Vec::new();
    }

    let mut rows_rev: Vec<String> = Vec::new();
    let mut remaining = height;
    let mut is_last = true;

    for line in lines.iter().rev() {
        if remaining == 0 {
            break;
        }

        let mut wrapped = if is_last {
            let max_cols = width.saturating_mul(height);
            let total_cols = UnicodeWidthStr::width(line.as_str());
            if total_cols > max_cols {
                let truncated = truncate_left_cols(line, max_cols);
                wrap_line(&truncated, width)
            } else {
                wrap_line(line, width)
            }
        } else {
            wrap_line(line, width)
        };

        if wrapped.len() > remaining {
            if is_last {
                let start = wrapped.len() - remaining;
                wrapped = wrapped[start..].to_vec();
            } else {
                continue;
            }
        }

        for row in wrapped.iter().rev() {
            rows_rev.push(row.clone());
        }

        remaining = height.saturating_sub(rows_rev.len());
        is_last = false;
    }

    rows_rev.into_iter().rev().map(Line::raw).collect()
}

fn wrap_line(s: &str, width: usize) -> Vec<String> {
    let mut rows = Vec::new();
    if width == 0 {
        return rows;
    }
    let mut current = String::new();
    let mut count = 0usize;
    for ch in s.chars() {
        let w = UnicodeWidthChar::width(ch).unwrap_or(0);
        if w == 0 {
            current.push(ch);
            continue;
        }
        if count + w > width && count > 0 {
            rows.push(current);
            current = String::new();
            count = 0;
        }
        current.push(ch);
        count += w;
        if count >= width {
            rows.push(current);
            current = String::new();
            count = 0;
        }
    }
    if !current.is_empty() {
        rows.push(current);
    }
    if rows.is_empty() {
        rows.push(String::new());
    }
    rows
}

fn tail_by_width(s: &str, max_cols: usize) -> String {
    if max_cols == 0 {
        return String::new();
    }
    let mut cols = 0usize;
    let mut rev: Vec<char> = Vec::new();
    for ch in s.chars().rev() {
        let w = UnicodeWidthChar::width(ch).unwrap_or(0);
        if w > 0 && cols + w > max_cols {
            break;
        }
        rev.push(ch);
        cols = cols.saturating_add(w);
    }
    rev.into_iter().rev().collect()
}

fn truncate_left_cols(s: &str, max_cols: usize) -> String {
    if max_cols == 0 {
        return String::new();
    }
    let width = UnicodeWidthStr::width(s);
    if width <= max_cols {
        return s.to_string();
    }
    if max_cols <= 3 {
        return tail_by_width(s, max_cols);
    }
    let keep = max_cols - 3;
    let tail = tail_by_width(s, keep);
    format!("...{}", tail)
}

impl Drop for MultiProgress {
    fn drop(&mut self) {
        // If in multi-panel mode, leave alternate screen
        if self.view_mode == ViewMode::MultiPanel {
            let _ = stdout().execute(LeaveAlternateScreen);
        }
        // Always disable raw mode (was enabled in new())
        let _ = disable_raw_mode();
        // Ensure cursor is visible when dropped
        let _ = stdout().execute(Show);
    }
}
