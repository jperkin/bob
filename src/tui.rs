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

//! Line-based progress display using ratatui's inline viewport.

use crossterm::ExecutableCommand;
use crossterm::cursor::Show;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::{
    Terminal, TerminalOptions, Viewport,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};
use std::collections::VecDeque;
use std::io::{self, IsTerminal, Stdout, stdout};
use std::time::{Duration, Instant};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Default refresh interval for UI updates (10fps).
/// Used for both event polling timeout and render throttling.
pub const REFRESH_INTERVAL: Duration = Duration::from_millis(100);

/// Fixed-width column for status verbs and progress titles,
/// matching cargo's 12-character status column.
const STATUS_WIDTH: usize = 12;

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
        Self {
            lines: VecDeque::with_capacity(capacity),
            capacity,
        }
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
    pub dispatched: usize,
    pub completed: usize,
    pub cached: usize,
    pub failed: usize,
    pub skipped: usize,
    pub workers: Vec<WorkerState>,
    pub started: Instant,
    /// Current timer width tier (6, 10, or 13)
    pub timer_width: usize,
    /// Whether output is suppressed (e.g., during shutdown)
    pub suppressed: bool,
}

impl ProgressState {
    pub fn new(title: &str, finished_title: &str, total: usize, num_workers: usize) -> Self {
        let workers = (0..num_workers).map(|_| WorkerState::new()).collect();
        Self {
            title: title.to_string(),
            finished_title: finished_title.to_string(),
            total,
            dispatched: 0,
            completed: 0,
            cached: 0,
            failed: 0,
            skipped: 0,
            workers,
            started: Instant::now(),
            timer_width: 6,
            suppressed: false,
        }
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

    pub fn increment_dispatched(&mut self) {
        self.dispatched += 1;
    }

    pub fn increment_completed(&mut self) {
        self.completed += 1;
    }

    pub fn increment_failed(&mut self) {
        self.failed += 1;
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub fn progress_ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.dispatched + self.cached + self.skipped) as f64 / self.total as f64
        }
    }
}

/// Format a duration in human-readable form.
/**
 * Format duration with fixed-width columns for aligned plain text output.
 * Minutes and seconds each occupy 2 characters so columns line up.
 */
fn format_duration_fixed(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{:>5}s", secs)
    } else if secs < 3600 {
        format!("{:>2}m {:>2}s", secs / 60, secs % 60)
    } else {
        format!(
            "{}h {:>2}m {:>2}s",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        )
    }
}

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

/// Format the progress/status bar line for a given width.
fn format_status_line(state: &ProgressState, msg: (&str, &str), width: usize) -> Line<'static> {
    let ratio = state.progress_ratio();
    let elapsed_str = format_duration_short(state.elapsed());
    let done = (state.dispatched + state.cached + state.skipped).to_string();
    let total = state.total.to_string();

    let (msg_bold, msg_rest) = msg;
    let has_msg = !msg_bold.is_empty() || !msg_rest.is_empty();
    let msg_total_len = if has_msg {
        " (".len() + msg_bold.len() + msg_rest.len() + ") ".len()
    } else {
        0
    };
    let bar_chrome = " [".len() + "] ".len();
    let counts_len = done.len() + 1 + total.len();
    let fixed = STATUS_WIDTH + bar_chrome + counts_len + 1 + elapsed_str.len() + msg_total_len;
    let bar_width = width.saturating_sub(fixed).clamp(1, 30);
    let padding = width.saturating_sub(fixed + bar_width);

    let filled = (ratio * bar_width as f64) as usize;
    let empty = bar_width.saturating_sub(filled).saturating_sub(1);
    let bar = if filled >= bar_width {
        format!("{}>", "=".repeat(bar_width - 1))
    } else if filled == 0 {
        format!(">{}", " ".repeat(bar_width.saturating_sub(1)))
    } else {
        format!("{}>{}", "=".repeat(filled), " ".repeat(empty))
    };

    let bold = Style::new().add_modifier(Modifier::BOLD);
    let title = Span::styled(format!("{:>tw$}", state.title, tw = STATUS_WIDTH), bold);
    if !has_msg {
        Line::from(vec![
            title,
            Span::raw(format!(" [{}] ", bar)),
            Span::styled(done, bold),
            Span::raw("/"),
            Span::styled(total, bold),
            Span::raw(format!(" {}", elapsed_str)),
        ])
    } else {
        let mut spans = vec![
            title,
            Span::raw(format!(" [{}] ", bar)),
            Span::styled(done, bold),
            Span::raw("/"),
            Span::styled(total, bold),
            Span::raw(format!(" {}{:pad$} (", elapsed_str, "", pad = padding)),
        ];
        if !msg_bold.is_empty() {
            spans.push(Span::styled(msg_bold.to_string(), bold));
        }
        spans.push(Span::raw(format!("{}) ", msg_rest)));
        Line::from(spans)
    }
}

fn status_msg(interrupt_announced: bool, title: &str) -> (&'static str, &'static str) {
    if interrupt_announced {
        ("stopping", ", ^C to force quit")
    } else if title == "Building" {
        ("", "press 'v' to toggle full-screen")
    } else {
        ("", "")
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

/**
 * Represents a group of workers for display purposes.
 * Active workers get their own panel; consecutive idle workers are collapsed.
 */
#[derive(Clone, Debug)]
enum PanelGroup {
    Active(usize),
    Idle(Vec<usize>),
}

impl PanelGroup {
    fn is_active(&self) -> bool {
        matches!(self, PanelGroup::Active(_))
    }

    fn format_title(&self) -> String {
        match self {
            PanelGroup::Active(i) => format!("[{}] ", i),
            PanelGroup::Idle(ids) => {
                let id_strs: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
                format!("[{}] idle ", id_strs.join(","))
            }
        }
    }
}

/**
 * Group a sequence of worker IDs by their active state, collapsing consecutive
 * idle workers into single groups.
 */
fn group_worker_sequence(workers: &[usize], is_active: &[bool]) -> Vec<PanelGroup> {
    let mut groups = Vec::new();
    let mut i = 0;

    while i < workers.len() {
        let w = workers[i];
        if is_active[w] {
            groups.push(PanelGroup::Active(w));
            i += 1;
        } else {
            let mut idle_ids = vec![w];
            i += 1;
            while i < workers.len() && !is_active[workers[i]] {
                idle_ids.push(workers[i]);
                i += 1;
            }
            groups.push(PanelGroup::Idle(idle_ids));
        }
    }

    groups
}

/**
 * Group consecutive idle workers together for collapsed display (linear layout).
 */
fn group_workers_linear(is_active: &[bool]) -> Vec<PanelGroup> {
    let workers: Vec<usize> = (0..is_active.len()).collect();
    group_worker_sequence(&workers, is_active)
}

/**
 * Group workers by column for grid layout, collapsing consecutive idle workers
 * within each column. Returns (groups, rows) for rendering.
 */
fn group_workers_grid(is_active: &[bool], cols: usize) -> (Vec<Vec<PanelGroup>>, usize) {
    let num_workers = is_active.len();
    let rows = num_workers.div_ceil(cols);

    let column_groups = (0..cols)
        .map(|col| {
            let workers_in_col: Vec<usize> = (0..rows)
                .map(|r| r * cols + col)
                .filter(|&w| w < num_workers)
                .collect();
            group_worker_sequence(&workers_in_col, is_active)
        })
        .collect();

    (column_groups, rows)
}

/**
 * Calculate linear layout for narrow terminals with height optimization.
 * Idle groups get minimal height, active panels share remaining space
 * equally.
 */
fn calculate_linear_layout(area: Rect, groups: &[PanelGroup]) -> Vec<Rect> {
    let num_groups = groups.len();
    if num_groups == 0 {
        return vec![];
    }

    let active_count = groups.iter().filter(|g| g.is_active()).count();
    let idle_height = 2u16;
    let idle_count = num_groups - active_count;
    let total_idle_height = idle_count as u16 * idle_height;
    let active_space = area.height.saturating_sub(total_idle_height);

    let base_height = if active_count > 0 {
        active_space / active_count as u16
    } else {
        0
    };
    let remainder = if active_count > 0 {
        (active_space % active_count as u16) as usize
    } else {
        0
    };

    /*
     * Distribute extra lines from the bottom up so that columns
     * line up correctly when using multi-column layouts.
     */
    let mut extra_line = vec![false; num_groups];
    let mut extra_given = 0;
    for (i, group) in groups.iter().enumerate().rev() {
        if group.is_active() && extra_given < remainder {
            extra_line[i] = true;
            extra_given += 1;
        }
    }

    // Build rects maintaining order
    let mut rects = Vec::with_capacity(num_groups);
    let mut y = area.y;

    for (i, group) in groups.iter().enumerate() {
        let h = if group.is_active() && active_count > 0 {
            base_height + if extra_line[i] { 1 } else { 0 }
        } else {
            idle_height
        };
        rects.push(Rect {
            x: area.x,
            y,
            width: area.width,
            height: h,
        });
        y += h;
    }

    rects
}

/**
 * Calculate grid layout for column-grouped panels.
 * Each column has its own set of groups, with idle groups getting minimal height.
 */
fn calculate_grid_layout(area: Rect, column_groups: &[Vec<PanelGroup>]) -> Vec<Vec<Rect>> {
    let cols = column_groups.len();
    if cols == 0 {
        return vec![];
    }

    // Split area into columns
    let col_constraints: Vec<Constraint> = (0..cols)
        .map(|_| Constraint::Ratio(1, cols as u32))
        .collect();
    let col_areas = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(col_constraints)
        .split(area);

    // Calculate layout for each column independently
    column_groups
        .iter()
        .enumerate()
        .map(|(col_idx, groups)| calculate_linear_layout(col_areas[col_idx], groups))
        .collect()
}

/**
 * Simple progress display for non-terminal output.
 *
 * Prints progress dots and status lines to stdout without any terminal
 * escape sequences.  Used when stdout is not a terminal (e.g. Jenkins,
 * piped output) or when TUI mode is disabled.
 */
pub struct PlainProgress {
    state: ProgressState,
    plain_dots: usize,
    interrupt_announced: bool,
}

impl PlainProgress {
    pub fn new(title: &str, finished_title: &str, total: usize, num_workers: usize) -> Self {
        Self {
            state: ProgressState::new(title, finished_title, total, num_workers),
            plain_dots: 0,
            interrupt_announced: false,
        }
    }
}

/**
 * Progress display that works in both terminal and non-terminal contexts.
 *
 * In non-terminal contexts (Jenkins, piped output), uses `PlainProgress`
 * which prints dots and status lines without escape sequences.  In
 * terminals with TUI enabled, uses `MultiProgress` with a ratatui inline
 * viewport for real-time worker status.
 */
pub enum Progress {
    Plain(PlainProgress),
    Tui(MultiProgress),
}

impl Progress {
    pub fn new(
        title: &str,
        finished_title: &str,
        total: usize,
        num_workers: usize,
        tui: bool,
    ) -> io::Result<Self> {
        if tui && io::stdout().is_terminal() && enable_raw_mode().is_ok() {
            match MultiProgress::new(title, finished_title, total, num_workers) {
                Ok(mp) => return Ok(Self::Tui(mp)),
                Err(_) => {
                    let _ = disable_raw_mode();
                }
            }
        }
        Ok(Self::Plain(PlainProgress::new(
            title,
            finished_title,
            total,
            num_workers,
        )))
    }

    pub fn is_plain(&self) -> bool {
        matches!(self, Self::Plain(_))
    }

    pub fn state_mut(&mut self) -> &mut ProgressState {
        match self {
            Self::Plain(p) => &mut p.state,
            Self::Tui(p) => p.state_mut(),
        }
    }

    pub fn output_buffer_mut(&mut self, id: usize) -> Option<&mut OutputBuffer> {
        match self {
            Self::Plain(_) => None,
            Self::Tui(p) => p.output_buffer_mut(id),
        }
    }

    pub fn clear_output_buffer(&mut self, id: usize) {
        if let Self::Tui(p) = self {
            p.clear_output_buffer(id);
        }
    }

    pub fn print_status(
        &mut self,
        verb: &str,
        pkg: &str,
        duration: Option<Duration>,
        breaks: Option<usize>,
    ) -> io::Result<()> {
        match self {
            Self::Plain(p) => {
                let done = p.state.dispatched + p.state.cached + p.state.skipped;
                let tw = p.state.total.to_string().len();
                let prefix = format!("[{:>tw$}/{}] {:>10} ", done, p.state.total, verb, tw = tw);
                let brk = match breaks {
                    Some(n) if n > 0 => format!(" ({})", n),
                    _ => String::new(),
                };
                match duration {
                    Some(d) => {
                        let dur = format_duration_fixed(d);
                        let left = format!("{}{}", pkg, brk);
                        let pad = 80usize.saturating_sub(prefix.len() + left.len() + dur.len());
                        println!("{}{}{:>pad$}{}", prefix, left, "", dur, pad = pad);
                    }
                    None => println!("{}{}", prefix, pkg),
                }
                Ok(())
            }
            Self::Tui(p) => p.print_status(verb, pkg, duration, breaks),
        }
    }

    pub fn print_progress_dot(&mut self, done: usize, total: usize) -> io::Result<()> {
        if let Self::Plain(p) = self {
            p.plain_dots += 1;
            if p.plain_dots >= 50 {
                let counter = format!("{}/{}", done, total);
                println!("    {:<50}  {:>11}", ".".repeat(50), counter);
                p.plain_dots = 0;
            }
        }
        Ok(())
    }

    pub fn flush_progress_dots(&mut self, done: usize, total: usize) -> io::Result<()> {
        if let Self::Plain(p) = self {
            if p.plain_dots > 0 {
                let dots = ".".repeat(p.plain_dots);
                let counter = format!("{}/{}", done, total);
                println!("    {:<50}  {:>11}", dots, counter);
                p.plain_dots = 0;
            }
        }
        Ok(())
    }

    pub fn announce_interrupt(&mut self) {
        match self {
            Self::Plain(p) => {
                if !p.interrupt_announced {
                    p.interrupt_announced = true;
                    eprintln!("Interrupted, stopping...");
                }
            }
            Self::Tui(p) => p.announce_interrupt(),
        }
    }

    pub fn render(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(_) => Ok(()),
            Self::Tui(p) => p.render(),
        }
    }

    pub fn handle_event(&mut self) -> io::Result<bool> {
        match self {
            Self::Plain(_) => Ok(false),
            Self::Tui(p) => p.handle_event(),
        }
    }

    pub fn finish(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(p) => {
                let elapsed_str = format_duration(p.state.elapsed());
                let total = p.state.completed + p.state.cached + p.state.failed + p.state.skipped;
                println!(
                    "{} {} in {} ({} succeeded, {} cached, {} failed, {} skipped)",
                    p.state.finished_title,
                    total,
                    elapsed_str,
                    p.state.completed,
                    p.state.cached,
                    p.state.failed,
                    p.state.skipped,
                );
                Ok(())
            }
            Self::Tui(p) => p.finish(),
        }
    }

    pub fn finish_silent(&mut self) -> io::Result<Duration> {
        match self {
            Self::Plain(p) => Ok(p.state.elapsed()),
            Self::Tui(p) => p.finish_silent(),
        }
    }

    pub fn finish_interrupted(&mut self) -> io::Result<bool> {
        match self {
            Self::Plain(_) => Ok(false),
            Self::Tui(p) => p.finish_interrupted(),
        }
    }
}

/// Line-based progress display using ratatui inline viewport.
pub(crate) struct MultiProgress {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    state: ProgressState,
    view_mode: ViewMode,
    output_buffers: Vec<OutputBuffer>,
    num_workers: usize,
    /// Messages buffered while in fullscreen mode, printed when returning to inline.
    pending_messages: Vec<Line<'static>>,
    interrupt_announced: bool,
}

impl MultiProgress {
    /** Create a new TUI progress display. Raw mode must already be enabled. */
    fn new(
        title: &str,
        finished_title: &str,
        total: usize,
        num_workers: usize,
    ) -> io::Result<Self> {
        let height = (num_workers + 1) as u16;
        let backend = CrosstermBackend::new(stdout());
        let viewport = Viewport::Inline(height);
        let terminal = Terminal::with_options(backend, TerminalOptions { viewport })?;
        let output_buffers = (0..num_workers).map(|_| OutputBuffer::new(100)).collect();

        Ok(Self {
            terminal,
            state: ProgressState::new(title, finished_title, total, num_workers),
            view_mode: ViewMode::Inline,
            output_buffers,
            num_workers,
            pending_messages: Vec::new(),
            interrupt_announced: false,
        })
    }

    fn state_mut(&mut self) -> &mut ProgressState {
        &mut self.state
    }

    fn output_buffer_mut(&mut self, id: usize) -> Option<&mut OutputBuffer> {
        self.output_buffers.get_mut(id)
    }

    fn clear_output_buffer(&mut self, id: usize) {
        if let Some(buf) = self.output_buffers.get_mut(id) {
            buf.clear();
        }
    }

    fn print_status(
        &mut self,
        verb: &str,
        pkg: &str,
        duration: Option<Duration>,
        breaks: Option<usize>,
    ) -> io::Result<()> {
        if self.state.suppressed {
            return Ok(());
        }
        let detail = match (duration, breaks) {
            (Some(d), Some(n)) if n > 0 => {
                format!("{} ({}, breaks {})", pkg, format_duration(d), n)
            }
            (Some(d), _) => format!("{} ({})", pkg, format_duration(d)),
            _ => pkg.to_string(),
        };
        let bold = Style::new().add_modifier(Modifier::BOLD);
        let line = Line::from(vec![
            Span::styled(format!("{:>tw$}", verb, tw = STATUS_WIDTH), bold),
            Span::raw(format!(" {}", detail)),
        ]);
        if self.view_mode == ViewMode::MultiPanel {
            self.pending_messages.push(line);
            return Ok(());
        }
        self.terminal.insert_before(1, |buf| {
            buf.set_line(0, 0, &line, line.width() as u16);
        })?;
        Ok(())
    }

    /**
     * Announce an interrupt to the user via the progress display.
     *
     * In TUI mode, sets a flag so the next render shows a stopping
     * indicator in the status bar.  In plain mode, prints a message
     * immediately.  Only the first call has any effect; subsequent
     * calls are no-ops so that both `handle_event` and the
     * manager/scan loop can call this without duplicating output.
     */
    fn announce_interrupt(&mut self) {
        if self.interrupt_announced {
            return;
        }
        self.interrupt_announced = true;
    }

    fn render(&mut self) -> io::Result<()> {
        match self.view_mode {
            ViewMode::Inline => self.render_inline(),
            ViewMode::MultiPanel => self.render_multipanel(),
        }
    }

    fn render_inline(&mut self) -> io::Result<()> {
        // Don't render if suppressed
        if self.state.suppressed {
            return Ok(());
        }
        self.state.update_timer_width();
        let interrupt_announced = self.interrupt_announced;
        let state = &self.state;

        self.terminal.draw(|frame| {
            let area = frame.area();

            // Create constraints for each line
            let mut constraints: Vec<Constraint> = state
                .workers
                .iter()
                .map(|_| Constraint::Length(1))
                .collect();
            constraints.push(Constraint::Length(1)); // Progress bar

            let chunks = Layout::vertical(constraints).split(area);

            // Render worker lines
            let bold = Style::new().add_modifier(Modifier::BOLD);
            let tw = state.timer_width;
            for (i, worker) in state.workers.iter().enumerate() {
                let line = if let (Some(pkg), Some(elapsed)) = (&worker.package, worker.elapsed()) {
                    let prefix = format!(
                        "  [{:>2}:{:>tw$} ] ",
                        i,
                        format_duration_short(elapsed),
                        tw = tw
                    );
                    if let Some(stage) = &worker.stage {
                        Line::from(vec![
                            Span::raw(prefix),
                            Span::styled(pkg.clone(), bold),
                            Span::raw(format!(" ({})", stage)),
                        ])
                    } else {
                        Line::from(vec![Span::raw(prefix), Span::styled(pkg.clone(), bold)])
                    }
                } else {
                    Line::raw(format!("  [{:>2}:{:>tw$} ]", i, "idle", tw = tw))
                };
                frame.render_widget(line, chunks[i]);
            }

            let msg = status_msg(interrupt_announced, &state.title);
            let status = format_status_line(state, msg, area.width as usize);
            frame.render_widget(status, chunks[state.workers.len()]);
        })?;

        Ok(())
    }

    fn handle_event(&mut self) -> io::Result<bool> {
        if self.state.suppressed {
            return Ok(false);
        }

        if let Event::Key(key) = event::read()? {
            // Toggle view mode on 'v' key
            if key.code == KeyCode::Char('v') && key.modifiers.is_empty() {
                self.toggle_view_mode()?;
                return Ok(true);
            }
            /*
             * Handle Ctrl+C.  First press: show a stopping indicator
             * in the status bar and keep the TUI active so the user
             * can watch in-progress work finish.  Second press: tear
             * down the TUI and print the shutdown message.
             */
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                if self.interrupt_announced {
                    if self.finish_interrupted().unwrap_or(false) {
                        eprintln!("Interrupted, shutting down...");
                    }
                } else {
                    self.announce_interrupt();
                }
                unsafe {
                    libc::raise(libc::SIGINT);
                }
            }
        }
        Ok(false)
    }

    fn toggle_view_mode(&mut self) -> io::Result<()> {
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
        let options = TerminalOptions {
            viewport: Viewport::Inline(height),
        };
        self.terminal = Terminal::with_options(backend, options)?;
        self.view_mode = ViewMode::Inline;

        // Print any messages that were buffered while in fullscreen mode
        for line in self.pending_messages.drain(..) {
            self.terminal.insert_before(1, |buf| {
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

        let num_workers = self.num_workers;

        // Extract active flags and elapsed times for layout calculation
        let is_active: Vec<bool> = (0..num_workers)
            .map(|i| {
                self.state
                    .workers
                    .get(i)
                    .is_some_and(|w| w.package.is_some())
            })
            .collect();
        let size = self.terminal.size()?;
        let area = Rect::new(0, 0, size.width, size.height);

        let msg = status_msg(self.interrupt_announced, &self.state.title);
        let status_line = format_status_line(&self.state, msg, size.width as usize);

        if area.width < 160 {
            self.render_multipanel_linear(&is_active, area, status_line)
        } else {
            self.render_multipanel_grid(&is_active, area, status_line)
        }
    }

    fn render_multipanel_linear(
        &mut self,
        is_active: &[bool],
        area: Rect,
        status_line: Line<'static>,
    ) -> io::Result<()> {
        let panel_area = Rect::new(area.x, area.y, area.width, area.height.saturating_sub(1));
        let status_area = Rect::new(area.x, area.y + panel_area.height, area.width, 1);

        let groups = group_workers_linear(is_active);
        let panels = calculate_linear_layout(panel_area, &groups);

        // Pre-compute titles
        let titles: Vec<Line<'static>> = groups
            .iter()
            .map(|group| self.format_group_title(group))
            .collect();

        // Collect output lines for each panel
        let panel_lines: Vec<Vec<String>> = panels
            .iter()
            .enumerate()
            .map(|(gi, panel_area)| {
                let inner_height = panel_area.height.saturating_sub(2) as usize;
                let lines_needed = (inner_height * 2).max(10);
                match &groups[gi] {
                    PanelGroup::Active(i) => self
                        .output_buffers
                        .get(*i)
                        .map(|buf| buf.last_n(lines_needed).cloned().collect())
                        .unwrap_or_default(),
                    PanelGroup::Idle(..) => Vec::new(),
                }
            })
            .collect();

        self.terminal.draw(|frame| {
            for (i, panel_rect) in panels.iter().enumerate() {
                frame.render_widget(Clear, *panel_rect);

                let block = Block::default()
                    .title(titles[i].clone())
                    .borders(Borders::ALL);

                let inner_width = panel_rect.width.saturating_sub(2) as usize;
                let inner_height = panel_rect.height.saturating_sub(2) as usize;

                let visible = build_visible_lines(&panel_lines[i], inner_width, inner_height);

                let paragraph = Paragraph::new(visible).block(block);
                frame.render_widget(paragraph, *panel_rect);
            }
            frame.render_widget(status_line, status_area);
        })?;

        Ok(())
    }

    fn render_multipanel_grid(
        &mut self,
        is_active: &[bool],
        area: Rect,
        status_line: Line<'static>,
    ) -> io::Result<()> {
        let panel_area = Rect::new(area.x, area.y, area.width, area.height.saturating_sub(1));
        let status_area = Rect::new(area.x, area.y + panel_area.height, area.width, 1);

        let num_workers = is_active.len();

        // Calculate grid dimensions based on worker count and width
        let max_cols_by_count = (num_workers as f64).sqrt().ceil() as usize;
        let max_cols_by_width = (panel_area.width as usize) / 80;
        let cols = max_cols_by_count.min(max_cols_by_width).max(1);

        let (column_groups, _rows) = group_workers_grid(is_active, cols);
        let column_rects = calculate_grid_layout(panel_area, &column_groups);

        // Pre-compute titles for each group in each column
        let column_titles: Vec<Vec<Line<'static>>> = column_groups
            .iter()
            .map(|groups| groups.iter().map(|g| self.format_group_title(g)).collect())
            .collect();

        // Collect output lines for each panel in each column
        let column_lines: Vec<Vec<Vec<String>>> = column_groups
            .iter()
            .zip(column_rects.iter())
            .map(|(groups, rects)| {
                groups
                    .iter()
                    .zip(rects.iter())
                    .map(|(group, rect)| {
                        let inner_height = rect.height.saturating_sub(2) as usize;
                        let lines_needed = (inner_height * 2).max(10);
                        match group {
                            PanelGroup::Active(i) => self
                                .output_buffers
                                .get(*i)
                                .map(|buf| buf.last_n(lines_needed).cloned().collect())
                                .unwrap_or_default(),
                            PanelGroup::Idle(..) => Vec::new(),
                        }
                    })
                    .collect()
            })
            .collect();

        self.terminal.draw(|frame| {
            for (col_idx, rects) in column_rects.iter().enumerate() {
                for (row_idx, panel_rect) in rects.iter().enumerate() {
                    frame.render_widget(Clear, *panel_rect);

                    let title = column_titles[col_idx][row_idx].clone();
                    let block = Block::default().title(title).borders(Borders::ALL);

                    let inner_width = panel_rect.width.saturating_sub(2) as usize;
                    let inner_height = panel_rect.height.saturating_sub(2) as usize;

                    let lines = &column_lines[col_idx][row_idx];
                    let visible = build_visible_lines(lines, inner_width, inner_height);

                    let paragraph = Paragraph::new(visible).block(block);
                    frame.render_widget(paragraph, *panel_rect);
                }
            }
            frame.render_widget(status_line, status_area);
        })?;

        Ok(())
    }

    fn format_group_title(&self, group: &PanelGroup) -> Line<'static> {
        match group {
            PanelGroup::Active(i) => {
                if let Some(w) = self.state.workers.get(*i) {
                    if let Some(pkg) = &w.package {
                        let bold = Style::new().add_modifier(Modifier::BOLD);
                        let stage = w.stage.as_deref().unwrap_or("");
                        let elapsed = w.elapsed().map(format_duration_short).unwrap_or_default();
                        if stage.is_empty() {
                            Line::from(vec![
                                Span::raw(format!("[{}] ", i)),
                                Span::styled(pkg.clone(), bold),
                                Span::raw(format!(" {} ", elapsed)),
                            ])
                        } else {
                            Line::from(vec![
                                Span::raw(format!("[{}] ", i)),
                                Span::styled(pkg.clone(), bold),
                                Span::raw(format!(" ({}) {} ", stage, elapsed)),
                            ])
                        }
                    } else {
                        Line::raw(format!("[{}] idle ", i))
                    }
                } else {
                    Line::raw(format!("[{}] ", i))
                }
            }
            PanelGroup::Idle(_) => Line::raw(group.format_title()),
        }
    }

    fn finish(&mut self) -> io::Result<()> {
        let elapsed = self.finish_silent()?;
        let elapsed_str = format_duration(elapsed);
        let total =
            self.state.completed + self.state.cached + self.state.failed + self.state.skipped;
        println!(
            "{} {} in {} ({} succeeded, {} cached, {} failed, {} skipped)",
            self.state.finished_title,
            total,
            elapsed_str,
            self.state.completed,
            self.state.cached,
            self.state.failed,
            self.state.skipped,
        );
        Ok(())
    }

    fn finish_silent(&mut self) -> io::Result<Duration> {
        if self.view_mode == ViewMode::MultiPanel {
            self.switch_to_inline()?;
        }
        let _ = disable_raw_mode();
        self.terminal.clear()?;
        stdout().execute(Show)?;
        Ok(self.state.elapsed())
    }

    fn finish_interrupted(&mut self) -> io::Result<bool> {
        if self.state.suppressed {
            return Ok(false);
        }
        self.state.suppressed = true;
        if self.view_mode == ViewMode::MultiPanel {
            let _ = self.switch_to_inline();
        }
        let _ = disable_raw_mode();
        self.terminal.clear()?;
        stdout().execute(Show)?;
        Ok(true)
    }
}

fn build_visible_lines(lines: &[String], width: usize, height: usize) -> Vec<Line<'static>> {
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
        if self.view_mode == ViewMode::MultiPanel {
            let _ = stdout().execute(LeaveAlternateScreen);
        }
        let _ = disable_raw_mode();
        let _ = stdout().execute(Show);
    }
}
