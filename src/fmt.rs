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
 * Display formatting primitives shared across CLI output paths.
 */

/**
 * Local "YYYY-MM-DD HH:MM:SS" for an epoch second.  `Err` if `epoch`
 * is outside chrono's representable range.
 */
pub fn timestamp(epoch: i64) -> anyhow::Result<String> {
    let dt = chrono::DateTime::from_timestamp(epoch, 0)
        .ok_or_else(|| anyhow::anyhow!("Epoch second {epoch} out of range"))?;
    Ok(dt
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string())
}

/**
 * Duration with auto-selected unit: `Nms`, `N.Ns`, `NmSSs`, `NhMMm`.
 */
pub fn duration_ms(ms: u64) -> String {
    if ms == 0 {
        "-".to_string()
    } else if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        let mins = ms / 60_000;
        let secs = (ms % 60_000) / 1000;
        format!("{}m{:02}s", mins, secs)
    } else {
        let hours = ms / 3_600_000;
        let mins = (ms % 3_600_000) / 60_000;
        format!("{}h{:02}m", hours, mins)
    }
}

/**
 * Byte count with auto-selected unit: `NB`, `N.NK`, `N.NM`, `N.NG`.
 */
pub fn size_bytes(bytes: u64) -> String {
    const K: u64 = 1024;
    const M: u64 = 1024 * 1024;
    const G: u64 = 1024 * 1024 * 1024;
    if bytes >= G {
        format!("{:.1}G", bytes as f64 / G as f64)
    } else if bytes >= M {
        format!("{:.1}M", bytes as f64 / M as f64)
    } else if bytes >= K {
        format!("{:.1}K", bytes as f64 / K as f64)
    } else {
        format!("{}B", bytes)
    }
}

/**
 * Typed output cell.
 *
 * The unit of data exchanged between query and display layers: a
 * value plus enough type information to render it as a table cell,
 * CSV scalar, or JSON value.
 */
pub enum Cell {
    /// Absent value, rendered as `-` in tables and empty in CSV.
    Null,
    /// Literal text.
    Text(String),
    /// Plain number.
    UInt(u64),
    /// Duration in milliseconds.
    DurationMs(u64),
    /// Size in bytes.
    Bytes(u64),
    /// Epoch seconds.
    Timestamp(i64),
}

impl From<String> for Cell {
    fn from(s: String) -> Self {
        Cell::Text(s)
    }
}

impl From<&str> for Cell {
    fn from(s: &str) -> Self {
        Cell::Text(s.to_string())
    }
}

impl From<u64> for Cell {
    fn from(u: u64) -> Self {
        Cell::UInt(u)
    }
}

impl From<usize> for Cell {
    fn from(u: usize) -> Self {
        Cell::UInt(u as u64)
    }
}

impl Cell {
    /**
     * Human-friendly string.  `raw` keeps numeric values as scalars.
     */
    pub fn render_table(&self, raw: bool) -> anyhow::Result<String> {
        Ok(match self {
            Cell::Null => "-".to_string(),
            Cell::Text(s) => s.clone(),
            Cell::UInt(u) => u.to_string(),
            Cell::DurationMs(ms) => {
                if raw {
                    ms.to_string()
                } else {
                    duration_ms(*ms)
                }
            }
            Cell::Bytes(b) => {
                if raw {
                    b.to_string()
                } else {
                    size_bytes(*b)
                }
            }
            Cell::Timestamp(t) => {
                if raw {
                    t.to_string()
                } else {
                    timestamp(*t)?
                }
            }
        })
    }

    /**
     * Scalar string for CSV.
     */
    pub fn render_csv(&self) -> String {
        match self {
            Cell::Null => String::new(),
            Cell::Text(s) => s.clone(),
            Cell::UInt(u) => u.to_string(),
            Cell::DurationMs(ms) => ms.to_string(),
            Cell::Bytes(b) => b.to_string(),
            Cell::Timestamp(t) => t.to_string(),
        }
    }

    /**
     * Typed JSON value.  `Timestamp` renders as ISO-8601 UTC.
     */
    pub fn render_json(&self) -> anyhow::Result<serde_json::Value> {
        Ok(match self {
            Cell::Null => serde_json::Value::Null,
            Cell::Text(s) => serde_json::Value::String(s.clone()),
            Cell::UInt(u) => serde_json::Value::from(*u),
            Cell::DurationMs(ms) => serde_json::Value::from(*ms),
            Cell::Bytes(b) => serde_json::Value::from(*b),
            Cell::Timestamp(t) => {
                let dt = chrono::DateTime::from_timestamp(*t, 0)
                    .ok_or_else(|| anyhow::anyhow!("Epoch second {t} out of range"))?;
                serde_json::Value::String(dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            }
        })
    }
}
