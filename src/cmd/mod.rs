pub mod build;
pub mod db;
pub mod diff;
pub mod history;
pub mod list;
pub mod log;
pub mod prune;
pub mod publish;
pub mod rebuild;
pub mod sandbox;
pub mod simulate;
pub mod status;
pub mod util;

use bob::PackageState;
use strum::VariantArray;

/**
 * Sort key for one column of one row.  `Num`/`OptStr` order missing
 * values last regardless of direction, since "no data" is rarely the
 * first thing the reader wants to see.  `Idx` carries a precomputed
 * ordinal for enum-like columns where domain ordering beats
 * alphabetical (e.g. status outcome).
 *
 * Each variant carries a natural direction: `Num` defaults to
 * descending (biggest first), everything else to ascending.  The
 * user's `-` prefix inverts that default rather than meaning
 * "descending" outright -- so `-S disk_usage` puts the largest
 * package on top and `-S pkgname` is A-Z, with `-` flipping either.
 */
pub enum SortKey {
    Str(String),
    OptStr(Option<String>),
    Num(Option<u64>),
    Idx(usize),
}

impl SortKey {
    fn natural_desc(&self) -> bool {
        matches!(self, SortKey::Num(_))
    }
}

fn cmp_keys(a: &SortKey, b: &SortKey, invert: bool) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    let ord = match (a, b) {
        (SortKey::Str(x), SortKey::Str(y)) => x.cmp(y),
        (SortKey::OptStr(Some(x)), SortKey::OptStr(Some(y))) => x.cmp(y),
        (SortKey::OptStr(Some(_)), SortKey::OptStr(None)) => return Less,
        (SortKey::OptStr(None), SortKey::OptStr(Some(_))) => return Greater,
        (SortKey::OptStr(None), SortKey::OptStr(None)) => Equal,
        (SortKey::Num(Some(x)), SortKey::Num(Some(y))) => x.cmp(y),
        (SortKey::Num(Some(_)), SortKey::Num(None)) => return Less,
        (SortKey::Num(None), SortKey::Num(Some(_))) => return Greater,
        (SortKey::Num(None), SortKey::Num(None)) => Equal,
        (SortKey::Idx(x), SortKey::Idx(y)) => x.cmp(y),
        _ => Equal,
    };
    let desc = a.natural_desc() ^ invert;
    if desc { ord.reverse() } else { ord }
}

/**
 * Parse comma-separated sort specs of the form `col` or `-col`,
 * mapping each name through `lookup`.  The boolean is the user's
 * `-` prefix flag, interpreted as "invert this column's natural
 * direction" by [`sort_indexed_rows`].
 */
pub fn parse_sort_specs<C>(
    values: &[String],
    lookup: impl Fn(&str) -> Option<C>,
    valid_names: &[&str],
) -> anyhow::Result<Vec<(C, bool)>> {
    values
        .iter()
        .map(|s| {
            let (invert, name) = match s.strip_prefix('-') {
                Some(rest) => (true, rest),
                None => (false, s.as_str()),
            };
            lookup(name).map(|c| (c, invert)).ok_or_else(|| {
                anyhow::anyhow!(
                    "Unknown sort column '{}'. Valid columns: {}",
                    name,
                    valid_names.join(", ")
                )
            })
        })
        .collect()
}

/**
 * Stable in-place multi-key sort of `(keys, payload)` pairs.  Each
 * `inverts[i]` flag flips the natural direction of the corresponding
 * key position.  Its length must match each row's keys vec.
 */
pub fn sort_indexed_rows<T>(rows: &mut [(Vec<SortKey>, T)], inverts: &[bool]) {
    rows.sort_by(|(a, _), (b, _)| {
        for (i, &invert) in inverts.iter().enumerate() {
            let ord = cmp_keys(&a[i], &b[i], invert);
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }
        std::cmp::Ordering::Equal
    });
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Padded columns
    #[default]
    Table,
    /// Comma-separated values
    Csv,
    /// JSON array of objects
    Json,
}

/**
 * Render-time column metadata used by the writer.  Independent of any
 * particular command's column repository (see [`Column`]).
 */
pub struct Col {
    pub key: std::borrow::Cow<'static, str>,
    pub title: std::borrow::Cow<'static, str>,
    pub align: bob::Align,
    pub max_width: Option<usize>,
}

impl Col {
    pub fn new(key: impl Into<std::borrow::Cow<'static, str>>, align: bob::Align) -> Self {
        let key = key.into();
        Self {
            title: key.clone(),
            key,
            align,
            max_width: None,
        }
    }

    pub fn max(mut self, w: usize) -> Self {
        self.max_width = Some(w);
        self
    }
}

/**
 * Repository of every column the CLI can emit, with its display
 * metadata.  Each command picks the subset it supports and provides a
 * source-specific extraction; nothing else varies across commands.
 */
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Column {
    // Package identity
    Pkgname,
    Pkgpath,
    Pkgbase,
    // diff baselines
    PkgnamePrev,
    OutcomePrev,
    StagePrev,
    // Diff/scheduler
    Breaks,
    // Build outcome
    Outcome,
    Stage,
    // Build sizing/timing
    Duration,
    DiskUsage,
    MakeJobs,
    Wrkobjdir,
    Timestamp,
    BuildId,
    // bob list builds counters
    Packages,
    Succeeded,
    Uptodate,
    Failed,
    Masked,
    // bob status fields
    Status,
    Reason,
    MultiVersion,
    Deps,
    Priority,
    Cpu,
    // bob history per-stage durations / cpu time
    StageDuration(crate::build::Stage),
    StageCpu(crate::build::Stage),
}

impl Column {
    /// Machine identifier used for CSV/JSON field names and -o lookups.
    pub fn key(self) -> std::borrow::Cow<'static, str> {
        match self {
            Self::Pkgname => "pkgname".into(),
            Self::Pkgpath => "pkgpath".into(),
            Self::Pkgbase => "pkgbase".into(),
            Self::PkgnamePrev => "pkgname_prev".into(),
            Self::OutcomePrev => "outcome_prev".into(),
            Self::StagePrev => "stage_prev".into(),
            Self::Breaks => "breaks".into(),
            Self::Outcome => "outcome".into(),
            Self::Stage => "stage".into(),
            Self::Duration => "duration".into(),
            Self::DiskUsage => "disk_usage".into(),
            Self::MakeJobs => "make_jobs".into(),
            Self::Wrkobjdir => "wrkobjdir".into(),
            Self::Timestamp => "timestamp".into(),
            Self::BuildId => "build_id".into(),
            Self::Packages => "packages".into(),
            Self::Succeeded => "succeeded".into(),
            Self::Uptodate => "uptodate".into(),
            Self::Failed => "failed".into(),
            Self::Masked => "masked".into(),
            Self::Status => "status".into(),
            Self::Reason => "reason".into(),
            Self::MultiVersion => "multi_version".into(),
            Self::Deps => "deps".into(),
            Self::Priority => "priority".into(),
            Self::Cpu => "cpu".into(),
            Self::StageDuration(s) => <&str>::from(s).into(),
            Self::StageCpu(s) => format!("cpu:{}", <&str>::from(s)).into(),
        }
    }

    pub fn align(self) -> bob::Align {
        use bob::Align::*;
        match self {
            Self::Breaks
            | Self::Duration
            | Self::DiskUsage
            | Self::MakeJobs
            | Self::Packages
            | Self::Succeeded
            | Self::Uptodate
            | Self::Failed
            | Self::Masked
            | Self::Deps
            | Self::Priority
            | Self::Cpu
            | Self::StageDuration(_)
            | Self::StageCpu(_) => Right,
            _ => Left,
        }
    }

    pub fn desc(self) -> std::borrow::Cow<'static, str> {
        match self {
            Self::Pkgname => "Package name".into(),
            Self::Pkgpath => "Package path in pkgsrc".into(),
            Self::Pkgbase => "Package name without version".into(),
            Self::PkgnamePrev => "Package name from the previous build".into(),
            Self::OutcomePrev => "Outcome from the previous build".into(),
            Self::StagePrev => "Build stage that failed in the previous build".into(),
            Self::Breaks => "Number of packages broken by this failure".into(),
            Self::Outcome => "Build outcome".into(),
            Self::Stage => "Build stage that failed".into(),
            Self::Duration => "Wall-clock duration".into(),
            Self::DiskUsage => "WRKDIR size at end of build".into(),
            Self::MakeJobs => "MAKE_JOBS used".into(),
            Self::Wrkobjdir => "WRKOBJDIR type".into(),
            Self::Timestamp => "Build start time".into(),
            Self::BuildId => "Build session identifier".into(),
            Self::Packages => "Total packages in the build".into(),
            Self::Succeeded => "Packages built successfully".into(),
            Self::Uptodate => "Packages already up-to-date".into(),
            Self::Failed => "Packages that failed".into(),
            Self::Masked => "Packages skipped or masked".into(),
            Self::Status => "Current build status".into(),
            Self::Reason => "Status detail or reason".into(),
            Self::MultiVersion => "MULTI_VERSION variables".into(),
            Self::Deps => "Number of dependent packages".into(),
            Self::Priority => "Scheduler priority order".into(),
            Self::Cpu => "Previous build CPU time".into(),
            Self::StageDuration(s) => format!("Wall time for {} stage", <&str>::from(s)).into(),
            Self::StageCpu(s) => format!("CPU time for {} stage", <&str>::from(s)).into(),
        }
    }

    /// Build the render-time `Col` for this column.
    pub fn col(self) -> Col {
        Col::new(self.key(), self.align())
    }

    /// Parse a column name (e.g. from `-o`).
    pub fn parse(s: &str) -> Option<Self> {
        if let Some(stage) = s.strip_prefix("cpu:") {
            return stage.parse().ok().map(Self::StageCpu);
        }
        Some(match s {
            "pkgname" => Self::Pkgname,
            "pkgpath" => Self::Pkgpath,
            "pkgbase" => Self::Pkgbase,
            "pkgname_prev" => Self::PkgnamePrev,
            "outcome_prev" => Self::OutcomePrev,
            "stage_prev" => Self::StagePrev,
            "breaks" => Self::Breaks,
            "outcome" => Self::Outcome,
            "stage" => Self::Stage,
            "duration" => Self::Duration,
            "disk_usage" => Self::DiskUsage,
            "make_jobs" => Self::MakeJobs,
            "wrkobjdir" => Self::Wrkobjdir,
            "timestamp" => Self::Timestamp,
            "build_id" => Self::BuildId,
            "packages" => Self::Packages,
            "succeeded" => Self::Succeeded,
            "uptodate" => Self::Uptodate,
            "failed" => Self::Failed,
            "masked" => Self::Masked,
            "status" => Self::Status,
            "reason" => Self::Reason,
            "multi_version" => Self::MultiVersion,
            "deps" => Self::Deps,
            "priority" => Self::Priority,
            "cpu" => Self::Cpu,
            _ => return s.parse().ok().map(Self::StageDuration),
        })
    }
}

/**
 * Resolve user-supplied column names against a command's supported set.
 * `long` selects the full `supported` list; otherwise `requested` is
 * validated against `supported`, or `defaults` is used when no
 * selection is given.
 */
pub fn select_columns(
    requested: Option<&[String]>,
    all: bool,
    defaults: &[Column],
    supported: &[Column],
) -> anyhow::Result<Vec<Column>> {
    if let Some(names) = requested {
        return names
            .iter()
            .map(|n| {
                Column::parse(n)
                    .filter(|c| supported.contains(c))
                    .ok_or_else(|| {
                        let valid: Vec<String> =
                            supported.iter().map(|c| c.key().into_owned()).collect();
                        anyhow::anyhow!(
                            "Unknown column '{}'. Valid columns: {}",
                            n,
                            valid.join(", ")
                        )
                    })
            })
            .collect();
    }
    if all {
        return Ok(supported.to_vec());
    }
    Ok(defaults.to_vec())
}

/**
 * Instantiate the render-time `Col` metadata for the chosen columns.
 */
pub fn col_defs(chosen: &[Column]) -> Vec<Col> {
    chosen.iter().map(|c| c.col()).collect()
}

/**
 * `Columns:` help block listing each supported column with its
 * description, and the default selection.  Suitable as a clap
 * `long_help` value.
 */
pub fn cols_help(supported: &[Column], defaults: &[Column]) -> String {
    use std::fmt::Write as _;
    let entries: Vec<(String, std::borrow::Cow<'static, str>)> = supported
        .iter()
        .map(|c| (c.key().into_owned(), c.desc()))
        .collect();
    let width = entries.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::from("Columns:\n");
    for (k, d) in &entries {
        let _ = writeln!(out, "  {:<width$}  {}", k, d);
    }
    let default_names: Vec<String> = defaults.iter().map(|c| c.key().into_owned()).collect();
    let _ = write!(out, "\nDefault columns: {}", default_names.join(","));
    out
}

/**
 * Project a per-command data type into typed `Cell`s, one column at a
 * time.  Each command implements this for its row type so that the
 * shared [`Writer`] can build rows without per-command boilerplate.
 */
pub trait ColumnSource {
    type Ctx;
    fn cell(&self, col: Column, ctx: &Self::Ctx) -> Cell;
}

/**
 * Output options threaded through the formatter.  `raw` disables
 * human-friendly cell rendering.
 */
#[derive(Clone, Copy, Debug, Default)]
pub struct OutputOptions {
    pub format: OutputFormat,
    pub no_header: bool,
    pub raw: bool,
}

pub use bob::fmt::Cell;

enum OutputEvent {
    Row {
        prefix: Option<char>,
        cells: Vec<Cell>,
    },
    Message(String),
}

/**
 * Buffered output writer with optional row prefixes and free-form
 * messages.  Generic over the underlying writer.
 */
pub struct Formatter<W: std::io::Write> {
    writer: W,
    cols: Vec<Col>,
    opts: OutputOptions,
    events: Vec<OutputEvent>,
}

impl<W: std::io::Write> Formatter<W> {
    pub fn new(writer: W, cols: Vec<Col>, opts: OutputOptions) -> Self {
        Self {
            writer,
            cols,
            opts,
            events: Vec::new(),
        }
    }

    pub fn row<I: IntoIterator<Item = Cell>>(&mut self, cells: I) {
        self.row_with_prefix(None, cells)
    }

    pub fn row_with_prefix<I: IntoIterator<Item = Cell>>(
        &mut self,
        prefix: Option<char>,
        cells: I,
    ) {
        self.events.push(OutputEvent::Row {
            prefix,
            cells: cells.into_iter().collect(),
        });
    }

    pub fn message(&mut self, msg: &str) {
        self.events.push(OutputEvent::Message(msg.to_string()));
    }

    pub fn finish(self) -> anyhow::Result<()> {
        use std::io::Write;
        let Self {
            writer,
            cols,
            opts,
            events,
        } = self;
        let mut w = std::io::BufWriter::new(writer);
        match opts.format {
            OutputFormat::Table => write_table(&cols, &opts, &events, &mut w)?,
            OutputFormat::Csv => write_csv(&cols, &opts, &events, &mut w)?,
            OutputFormat::Json => write_json(&cols, &events, &mut w)?,
        }
        w.flush()?;
        Ok(())
    }
}

/**
 * Column-aware wrapper around `Formatter`.  Holds the chosen column
 * list and projects [`ColumnSource`] values into rows.
 */
pub struct Writer<W: std::io::Write> {
    formatter: Formatter<W>,
    chosen: Vec<Column>,
}

impl<W: std::io::Write> Writer<W> {
    pub fn new(writer: W, chosen: Vec<Column>, opts: OutputOptions) -> Self {
        let cols = col_defs(&chosen);
        Self {
            formatter: Formatter::new(writer, cols, opts),
            chosen,
        }
    }

    pub fn message(&mut self, msg: &str) {
        self.formatter.message(msg)
    }

    pub fn write<S: ColumnSource>(&mut self, prefix: Option<char>, source: &S, ctx: &S::Ctx) {
        let cells: Vec<Cell> = self.chosen.iter().map(|&c| source.cell(c, ctx)).collect();
        self.formatter.row_with_prefix(prefix, cells)
    }

    pub fn finish(self) -> anyhow::Result<()> {
        self.formatter.finish()
    }
}

impl Writer<std::io::StdoutLock<'static>> {
    pub fn stdout(chosen: Vec<Column>, opts: OutputOptions) -> Self {
        Writer::new(std::io::stdout().lock(), chosen, opts)
    }
}

/**
 * True if any cause in the error chain is a `BrokenPipe`.
 */
pub fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        if let Some(io) = c.downcast_ref::<std::io::Error>() {
            io.kind() == std::io::ErrorKind::BrokenPipe
        } else if let Some(ce) = c.downcast_ref::<csv::Error>() {
            matches!(
                ce.kind(),
                csv::ErrorKind::Io(io) if io.kind() == std::io::ErrorKind::BrokenPipe
            )
        } else {
            false
        }
    })
}

fn write_table<W: std::io::Write>(
    cols: &[Col],
    opts: &OutputOptions,
    events: &[OutputEvent],
    w: &mut W,
) -> anyhow::Result<()> {
    let raw = opts.raw;
    let mut rendered: Vec<RenderedEvent> = Vec::with_capacity(events.len());
    for ev in events {
        match ev {
            OutputEvent::Row { prefix, cells } => {
                let mut strs = Vec::with_capacity(cells.len());
                for c in cells {
                    strs.push(c.render_table(raw)?);
                }
                rendered.push(RenderedEvent::Row {
                    prefix: *prefix,
                    cells: strs,
                });
            }
            OutputEvent::Message(m) => rendered.push(RenderedEvent::Message(m.clone())),
        }
    }

    let widths: Vec<usize> = cols
        .iter()
        .enumerate()
        .map(|(i, col)| {
            let header_len = col.title.len();
            let max_data = rendered
                .iter()
                .filter_map(|e| match e {
                    RenderedEvent::Row { cells, .. } => cells.get(i).map(String::len),
                    _ => None,
                })
                .max()
                .unwrap_or(0);
            header_len
                .max(max_data)
                .min(col.max_width.unwrap_or(usize::MAX))
        })
        .collect();

    let any_prefix = rendered.iter().any(|e| {
        matches!(
            e,
            RenderedEvent::Row {
                prefix: Some(_),
                ..
            }
        )
    });
    let pad_prefix = if any_prefix { " " } else { "" };

    let mut header_emitted = false;
    for ev in &rendered {
        match ev {
            RenderedEvent::Row { prefix, cells } => {
                if !header_emitted {
                    if !opts.no_header {
                        let header: Vec<String> = cols
                            .iter()
                            .zip(&widths)
                            .map(|(col, &width)| pad(&col.title.to_uppercase(), col.align, width))
                            .collect();
                        writeln!(w, "{}{}", pad_prefix, header.join("  ").trim_end())?;
                    }
                    header_emitted = true;
                }
                let values: Vec<String> = cols
                    .iter()
                    .zip(&widths)
                    .enumerate()
                    .map(|(i, (col, &width))| {
                        let s = cells.get(i).map(String::as_str).unwrap_or("");
                        pad(s, col.align, width)
                    })
                    .collect();
                let line = values.join("  ");
                let line = line.trim_end();
                match prefix {
                    Some(c) => writeln!(w, "{}{}", c, line)?,
                    None => writeln!(w, "{}{}", pad_prefix, line)?,
                }
            }
            RenderedEvent::Message(m) => writeln!(w, "{}", m)?,
        }
    }
    Ok(())
}

fn write_csv<W: std::io::Write>(
    cols: &[Col],
    opts: &OutputOptions,
    events: &[OutputEvent],
    w: &mut W,
) -> anyhow::Result<()> {
    let mut wtr = csv::Writer::from_writer(w);
    if !opts.no_header {
        let header: Vec<&str> = cols.iter().map(|c| c.key.as_ref()).collect();
        wtr.write_record(&header)?;
    }
    for ev in events {
        if let OutputEvent::Row { cells, .. } = ev {
            let mut record = Vec::with_capacity(cols.len());
            for i in 0..cols.len() {
                record.push(cells.get(i).map(Cell::render_csv).unwrap_or_default());
            }
            wtr.write_record(&record)?;
        }
    }
    wtr.flush()?;
    Ok(())
}

fn write_json<W: std::io::Write>(
    cols: &[Col],
    events: &[OutputEvent],
    w: &mut W,
) -> anyhow::Result<()> {
    let mut array: Vec<serde_json::Map<String, serde_json::Value>> = Vec::new();
    for ev in events {
        if let OutputEvent::Row { cells, .. } = ev {
            let mut obj = serde_json::Map::new();
            for (i, col) in cols.iter().enumerate() {
                let v = match cells.get(i) {
                    Some(c) => c.render_json()?,
                    None => serde_json::Value::Null,
                };
                obj.insert(col.key.to_string(), v);
            }
            array.push(obj);
        }
    }
    let s = serde_json::to_string_pretty(&array)?;
    writeln!(w, "{}", s)?;
    Ok(())
}

enum RenderedEvent {
    Row {
        prefix: Option<char>,
        cells: Vec<String>,
    },
    Message(String),
}

fn pad(s: &str, align: bob::Align, width: usize) -> String {
    match align {
        bob::Align::Right => format!("{:>width$}", s, width = width),
        bob::Align::Left => format!("{:<width$}", s, width = width),
    }
}

struct FilterAlias {
    name: &'static str,
    desc: &'static str,
    matches: fn(PackageState) -> bool,
}

const FILTER_ALIASES: &[FilterAlias] = &[
    FilterAlias {
        name: "ok",
        desc: "Any successful outcome (freshly built or up-to-date)",
        matches: PackageState::is_success,
    },
    FilterAlias {
        name: "skipped",
        desc: "Any pre-skipped or pre-failed package",
        matches: PackageState::is_skipped,
    },
    FilterAlias {
        name: "blocked",
        desc: "Any package blocked by another",
        matches: PackageState::is_blocked,
    },
    FilterAlias {
        name: "masked",
        desc: "Any skipped or indirectly blocked package",
        matches: PackageState::is_masked,
    },
];

/**
 * Iterate over `(alias_name, description)` for every status filter alias
 * recognised by [`parse_status_filter`].
 */
pub fn status_filter_aliases() -> impl Iterator<Item = (&'static str, &'static str)> {
    FILTER_ALIASES.iter().map(|a| (a.name, a.desc))
}

/**
 * Parse a status filter string into the states it matches.
 *
 * A filter string is either the name of a single state, for example
 * `failed` or `indirect-failed`, which matches just that state (see
 * [`PackageState::as_str`](bob::PackageState::as_str) for the full set of
 * names); or an alias for a group of states, listed by
 * [`status_filter_aliases`].
 */
pub fn parse_status_filter(s: &str) -> Result<Vec<PackageState>, String> {
    if let Ok(k) = s.parse::<PackageState>() {
        return Ok(vec![k]);
    }
    for alias in FILTER_ALIASES {
        if alias.name == s {
            return Ok(PackageState::VARIANTS
                .iter()
                .copied()
                .filter(|k| (alias.matches)(*k))
                .collect());
        }
    }
    Err(format!("unknown status '{s}'"))
}
