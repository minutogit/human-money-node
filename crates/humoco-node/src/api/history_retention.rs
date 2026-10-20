//! Private, bounded hourly diagnostic retention. Never used for consensus decisions.
use super::history::HistoryPoint;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// A rolling year of hourly records, with an independent eight MiB file ceiling.
pub const HOURLY_CAPACITY: usize = 24 * 365;
const MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Observed counter deltas and last sampled gauges; missing time is never interpolated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HourSummary {
    pub hour: u64,
    pub observed_write_delta: u64,
    pub observed_read_delta: u64,
    pub observed_free_delta: u64,
    pub observed_f2f_delta: u64,
    pub observed_vip_delta: u64,
    pub last_sample: HistoryPoint,
    /// True after restart, counter reset, backwards time, or a gap greater than two minutes.
    pub incomplete: bool,
}

#[derive(Debug, Default)]
struct Retained {
    hours: VecDeque<HourSummary>,
    previous: Option<HistoryPoint>,
}

/// Diagnostic state independent of the 24 hour minute-resolution ring.
#[derive(Debug, Default)]
pub struct HourlyHistory {
    inner: Mutex<Retained>,
    path: Mutex<Option<PathBuf>>,
}

impl HourlyHistory {
    /// Loads bounded, ordered summaries. Failure leaves the caller free to start fresh.
    pub fn load(&self, path: &Path) -> std::io::Result<()> {
        *self.path.lock() = Some(path.to_path_buf());
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(std::io::Error::other("hourly history exceeds fixed budget"));
        }
        let hours: VecDeque<HourSummary> = serde_json::from_slice(&bytes)?;
        if hours.len() > HOURLY_CAPACITY
            || hours
                .iter()
                .zip(hours.iter().skip(1))
                .any(|(a, b)| a.hour >= b.hour)
            || hours
                .iter()
                .any(|h| h.last_sample.timestamp_sec / 3600 != h.hour)
        {
            return Err(std::io::Error::other(
                "invalid hourly history ordering or capacity",
            ));
        }
        self.inner.lock().hours = hours;
        Ok(())
    }

    /// Returns true on an hour transition, when a background snapshot should be written.
    pub fn record(&self, point: HistoryPoint) -> bool {
        let mut state = self.inner.lock();
        let hour = point.timestamp_sec / 3600;
        let previous = state.previous.take();
        let gap = previous.as_ref().is_none_or(|p| {
            point.timestamp_sec < p.timestamp_sec
                || point.timestamp_sec.saturating_sub(p.timestamp_sec) > 120
        });
        let reset = previous.as_ref().is_some_and(|p| {
            point.write_count < p.write_count
                || point.read_count < p.read_count
                || point.free_writes < p.free_writes
                || point.f2f_writes < p.f2f_writes
                || point.vip_writes < p.vip_writes
        });
        let transition = state.hours.back().is_none_or(|h| h.hour != hour);
        if state.hours.back().is_some_and(|h| hour < h.hour) {
            state.previous = Some(point);
            return false;
        }
        if transition {
            state.hours.push_back(HourSummary {
                hour,
                observed_write_delta: 0,
                observed_read_delta: 0,
                observed_free_delta: 0,
                observed_f2f_delta: 0,
                observed_vip_delta: 0,
                last_sample: point.clone(),
                incomplete: gap || reset,
            });
        }
        if let Some(summary) = state.hours.back_mut() {
            summary.incomplete |= gap || reset;
            if let Some(old) = previous.filter(|_| !gap && !reset) {
                summary.observed_write_delta = summary
                    .observed_write_delta
                    .saturating_add(point.write_count.saturating_sub(old.write_count));
                summary.observed_read_delta = summary
                    .observed_read_delta
                    .saturating_add(point.read_count.saturating_sub(old.read_count));
                summary.observed_free_delta = summary
                    .observed_free_delta
                    .saturating_add(point.free_writes.saturating_sub(old.free_writes));
                summary.observed_f2f_delta = summary
                    .observed_f2f_delta
                    .saturating_add(point.f2f_writes.saturating_sub(old.f2f_writes));
                summary.observed_vip_delta = summary
                    .observed_vip_delta
                    .saturating_add(point.vip_writes.saturating_sub(old.vip_writes));
            }
            summary.last_sample = point.clone();
        }
        while state.hours.len() > HOURLY_CAPACITY
            || state
                .hours
                .front()
                .is_some_and(|h| h.hour.saturating_add(HOURLY_CAPACITY as u64) <= hour)
        {
            state.hours.pop_front();
        }
        state.previous = Some(point);
        transition
    }

    pub fn query(&self) -> Vec<HourSummary> {
        self.inner.lock().hours.iter().cloned().collect()
    }

    /// Called only by the sampler's blocking background worker, never a request handler.
    pub fn persist(&self) -> std::io::Result<()> {
        let Some(path) = self.path.lock().clone() else {
            return Ok(());
        };
        let bytes = serde_json::to_vec(&self.query())?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(std::io::Error::other("hourly history exceeds fixed budget"));
        }
        let temporary = path.with_extension("json.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    }
}
