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
 * System-wide CPU usage sampling.
 *
 * A background thread periodically measures system CPU utilisation and
 * collects timestamped samples.  The caller retrieves them via
 * [`CpuSamplerHandle::stop`] and decides where to persist them.
 */

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tracing::debug;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

/**
 * A single CPU usage measurement.
 */
pub(crate) struct CpuSample {
    pub timestamp: i64,
    pub user_pct: u8,
    pub sys_pct: u8,
}

/**
 * Platform CPU load reader, created once per sampler thread.
 */
#[cfg(not(target_os = "illumos"))]
struct CpuLoad;

#[cfg(not(target_os = "illumos"))]
impl CpuLoad {
    fn new() -> Self {
        CpuLoad
    }

    /**
     * Measure system CPU load over `interval`.
     *
     * Sleeps for `interval`, then returns `(user_pct, sys_pct)` as values
     * 0--100.  Returns `None` if the platform does not support measurement
     * or if the measurement fails.
     */
    fn sample(&mut self, interval: Duration) -> Option<(u8, u8)> {
        use systemstat::{Platform, System};
        let sys = System::new();
        let measurement = sys.cpu_load_aggregate().ok()?;
        std::thread::sleep(interval);
        let cpu = measurement.done().ok()?;
        let user = ((cpu.user + cpu.nice) * 100.0).round().min(100.0) as u8;
        let system = ((cpu.system + cpu.interrupt) * 100.0).round().min(100.0) as u8;
        Some((user, system))
    }
}

/**
 * Platform CPU load reader, created once per sampler thread.
 *
 * kstat_open() copies every kstat header on the system, so the chain is
 * held open across samples and refreshed with kstat_chain_update().
 */
#[cfg(target_os = "illumos")]
struct CpuLoad {
    /// Open kstat chain.  `None` until the first sample or after a
    /// failed one; the next sample opens a fresh chain.
    ctl: Option<kstat_rs::Ctl>,
    /// Ticks read at the end of the previous sample, the baseline for
    /// the next interval.
    prev: Option<(u64, u64, u64)>,
}

#[cfg(target_os = "illumos")]
impl CpuLoad {
    fn new() -> Self {
        CpuLoad {
            ctl: None,
            prev: None,
        }
    }

    /**
     * Measure system CPU load over `interval`.
     *
     * Sleeps for `interval`, then returns `(user_pct, sys_pct)` as values
     * 0--100.  Returns `None` if the measurement fails.
     */
    fn sample(&mut self, interval: Duration) -> Option<(u8, u8)> {
        use kstat_rs::{Ctl, Data, NamedData};

        fn read_ticks(ctl: &mut Ctl) -> Option<(u64, u64, u64)> {
            let mut user: u64 = 0;
            let mut kernel: u64 = 0;
            let mut idle: u64 = 0;
            for mut ks in ctl.filter(Some("cpu"), None, Some("sys")) {
                if let Ok(Data::Named(named)) = ctl.read(&mut ks) {
                    for n in &named {
                        match n.name {
                            "cpu_ticks_user" => {
                                if let NamedData::UInt64(v) = n.value {
                                    user += v;
                                }
                            }
                            "cpu_ticks_kernel" => {
                                if let NamedData::UInt64(v) = n.value {
                                    kernel += v;
                                }
                            }
                            "cpu_ticks_idle" => {
                                if let NamedData::UInt64(v) = n.value {
                                    idle += v;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            Some((user, kernel, idle))
        }

        let mut ctl = match self.ctl.take() {
            Some(ctl) => ctl,
            None => Ctl::new().ok()?,
        };
        let (u1, k1, i1) = match self.prev.take() {
            Some(prev) => prev,
            None => read_ticks(&mut ctl)?,
        };
        std::thread::sleep(interval);
        let mut ctl = ctl.update().ok()?;
        let (u2, k2, i2) = read_ticks(&mut ctl)?;
        self.ctl = Some(ctl);
        self.prev = Some((u2, k2, i2));

        let du = u2.saturating_sub(u1);
        let dk = k2.saturating_sub(k1);
        let di = i2.saturating_sub(i1);
        let total = du + dk + di;
        if total == 0 {
            return None;
        }
        let user = ((du * 100) / total).min(100) as u8;
        let system = ((dk * 100) / total).min(100) as u8;
        Some((user, system))
    }
}

/**
 * Handle to a running CPU sampler thread.
 *
 * Stopping the handle signals the thread to exit and retrieves the
 * collected samples; dropping it discards them.
 */
pub struct CpuSamplerHandle {
    stop: Arc<AtomicBool>,
    samples: Arc<Mutex<Vec<CpuSample>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CpuSamplerHandle {
    pub(crate) fn stop(mut self) -> Vec<CpuSample> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        self.samples
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
    }
}

impl Drop for CpuSamplerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/**
 * Start a background thread that samples system CPU usage.
 *
 * Returns `None` if the initial CPU measurement fails (unsupported
 * platform or permissions issue).
 */
pub fn start_cpu_sampler() -> Option<CpuSamplerHandle> {
    /*
     * Single probe measurement over a short window to verify CPU
     * sampling works on this platform.
     */
    CpuLoad::new().sample(Duration::from_millis(100))?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let samples: Arc<Mutex<Vec<CpuSample>>> = Arc::new(Mutex::new(Vec::new()));
    let samples_ref = Arc::clone(&samples);

    let thread = crate::spawn_named("cpu-sampler", move || {
        debug!("CPU sampler started");
        let mut load = CpuLoad::new();
        while !stop_flag.load(Ordering::Relaxed) {
            if let Some((user, sys)) = load.sample(SAMPLE_INTERVAL) {
                let ts = crate::epoch_secs().unwrap_or(0);
                if let Ok(mut v) = samples_ref.lock() {
                    v.push(CpuSample {
                        timestamp: ts,
                        user_pct: user,
                        sys_pct: sys,
                    });
                }
            }
        }
        debug!("CPU sampler stopped");
    });

    Some(CpuSamplerHandle {
        stop,
        samples,
        thread: Some(thread),
    })
}
