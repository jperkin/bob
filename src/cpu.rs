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
 * A background thread periodically measures CPU utilisation and load
 * average, handing batches of samples to a sink supplied by the caller,
 * which decides where to persist them.
 */

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tracing::debug;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

/**
 * Samples buffered before the sink is called.
 */
const FLUSH_SAMPLES: usize = 12;

/**
 * A single CPU usage measurement.
 */
pub struct CpuSample {
    /// Seconds since the Unix epoch at the end of the sample interval.
    pub timestamp: i64,
    /// User CPU across all cores, 0 to 100.
    pub user_pct: u8,
    /// System CPU across all cores, 0 to 100.
    pub sys_pct: u8,
    /// One, five, and fifteen minute load averages.
    pub load: Option<(f64, f64, f64)>,
}

/**
 * Read the one, five, and fifteen minute load averages.
 */
fn load_average() -> Option<(f64, f64, f64)> {
    let mut avg = [0f64; 3];
    match unsafe { libc::getloadavg(avg.as_mut_ptr(), avg.len() as libc::c_int) } {
        3 => Some((avg[0], avg[1], avg[2])),
        _ => None,
    }
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
 * Dropping the handle signals the thread to exit and waits for it, so
 * whatever it has buffered reaches the sink.
 */
pub struct CpuSamplerHandle {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
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
 * Start a background thread that samples CPU usage and load average,
 * passing each batch of [`FLUSH_SAMPLES`] to `sink`, and whatever
 * remains when the sampler stops.
 *
 * Returns `None` if the initial CPU measurement fails (unsupported
 * platform or permissions issue).
 */
pub fn start_cpu_sampler<F>(mut sink: F) -> Option<CpuSamplerHandle>
where
    F: FnMut(&[CpuSample]) + Send + 'static,
{
    /*
     * Single probe measurement over a short window to verify CPU
     * sampling works on this platform.
     */
    CpuLoad::new().sample(Duration::from_millis(100))?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);

    let thread = crate::spawn_named("cpu-sampler", move || {
        debug!("CPU sampler started");
        let mut load = CpuLoad::new();
        let mut batch: Vec<CpuSample> = Vec::with_capacity(FLUSH_SAMPLES);
        while !stop_flag.load(Ordering::Relaxed) {
            if let Some((user, sys)) = load.sample(SAMPLE_INTERVAL) {
                batch.push(CpuSample {
                    timestamp: crate::epoch_secs().unwrap_or(0),
                    user_pct: user,
                    sys_pct: sys,
                    load: load_average(),
                });
                if batch.len() >= FLUSH_SAMPLES {
                    sink(&batch);
                    batch.clear();
                }
            }
        }
        if !batch.is_empty() {
            sink(&batch);
        }
        debug!("CPU sampler stopped");
    });

    Some(CpuSamplerHandle {
        stop,
        thread: Some(thread),
    })
}
