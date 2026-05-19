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
