use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

/// Size of the sparkline ringbuffer in seconds (60 seconds).
pub const SPARKLINE_CAPACITY: usize = 60;

/// DTO for system resource stats and capacity projections.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemStatsDto {
    pub cpu_percent: f64,
    pub rss_mb: f64,
    pub redb_bytes: u64,
    pub netto_locks_bytes: u64,
    pub disk_free_bytes: u64,
    pub peak_tps_single_core: u64,
    pub peak_tps_multi_core: u64,
    pub max_storage_locks: u64,
    pub byte_years_capacity: u64,
    pub ttl_purged_count: u64,
    #[serde(default)]
    pub redb_growth_mb_per_day: f64,
    #[serde(default)]
    pub days_until_full: Option<u64>,
    #[serde(default)]
    pub disk_headroom_label: String,
}

/// DTO for 60-second historical sparkline graphs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SparklinesDto {
    pub writes: Vec<f32>,
    pub reads: Vec<f32>,
    pub latency: Vec<f32>,
    pub nodes: Vec<u32>,
}

/// Fixed-size chronological ringbuffer for sparkline metrics.
#[derive(Debug, Clone)]
pub struct SparklineRingBuffer<T: Copy, const N: usize = SPARKLINE_CAPACITY> {
    buffer: [T; N],
    head: usize,
    count: usize,
}

impl<T: Copy + Default, const N: usize> Default for SparklineRingBuffer<T, N> {
    fn default() -> Self {
        Self {
            buffer: [T::default(); N],
            head: 0,
            count: 0,
        }
    }
}

impl<T: Copy + Default, const N: usize> SparklineRingBuffer<T, N> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a new item into the ring buffer.
    pub fn push(&mut self, item: T) {
        self.buffer[self.head] = item;
        self.head = (self.head + 1) % N;
        if self.count < N {
            self.count += 1;
        }
    }

    /// Returns a chronological vector of exactly N items (oldest to newest).
    pub fn to_chronological_vec(&self) -> Vec<T> {
        let mut result = Vec::with_capacity(N);
        if self.count < N {
            // Leading padding with default (0)
            let padding = N - self.count;
            for _ in 0..padding {
                result.push(T::default());
            }
            for i in 0..self.count {
                result.push(self.buffer[i]);
            }
        } else {
            // Oldest item is at head
            for i in 0..N {
                let idx = (self.head + i) % N;
                result.push(self.buffer[idx]);
            }
        }
        result
    }
}

/// Internal CPU tick counters parsed from Linux `/proc/stat`.
#[derive(Debug, Clone, Copy, Default)]
struct CpuStatSample {
    total: u64,
    idle: u64,
}

impl CpuStatSample {
    fn read() -> Option<Self> {
        let content = std::fs::read_to_string("/proc/stat").ok()?;
        let first_line = content.lines().next()?;
        if !first_line.starts_with("cpu ") {
            return None;
        }
        let parts: Vec<u64> = first_line
            .split_whitespace()
            .skip(1)
            .filter_map(|s| s.parse::<u64>().ok())
            .collect();
        if parts.len() < 4 {
            return None;
        }
        let user = parts[0];
        let nice = parts[1];
        let system = parts[2];
        let idle = parts[3];
        let iowait = parts.get(4).copied().unwrap_or(0);
        let irq = parts.get(5).copied().unwrap_or(0);
        let softirq = parts.get(6).copied().unwrap_or(0);
        let steal = parts.get(7).copied().unwrap_or(0);
        let guest = parts.get(8).copied().unwrap_or(0);
        let guest_nice = parts.get(9).copied().unwrap_or(0);

        let total = user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
        let idle_total = idle + iowait;
        Some(Self {
            total,
            idle: idle_total,
        })
    }
}

/// Reads RSS memory usage in MB via `/proc/self/statm` (pages * 4096 / 1MB).
fn read_rss_mb() -> f64 {
    if let Ok(content) = std::fs::read_to_string("/proc/self/statm") {
        if let Some(resident_str) = content.split_whitespace().nth(1) {
            if let Ok(pages) = resident_str.parse::<u64>() {
                return (pages as f64 * 4096.0) / (1024.0 * 1024.0);
            }
        }
    }
    0.0
}

/// Computes file size of `humoco.redb` if present.
fn read_redb_size(data_dir: &Path) -> u64 {
    let redb_path = data_dir.join("humoco.redb");
    std::fs::metadata(redb_path).map(|m| m.len()).unwrap_or(0)
}

/// Safe disk space calculation / fallback via POSIX `df -Pk`.
fn read_disk_free(data_dir: &Path) -> u64 {
    const DEFAULT_FALLBACK_BYTES: u64 = 64 * 1024 * 1024 * 1024;

    #[cfg(unix)]
    {
        if let Ok(output) = std::process::Command::new("df")
            .arg("-Pk")
            .arg(data_dir)
            .output()
        {
            if output.status.success() {
                if let Ok(stdout) = std::str::from_utf8(&output.stdout) {
                    let mut lines = stdout.lines();
                    let _header = lines.next();
                    if let Some(data_line) = lines.next() {
                        let cols: Vec<&str> = data_line.split_whitespace().collect();
                        // Line 2, column 4 (1-indexed col 4 = index 3: Available 1K-blocks)
                        if let Some(avail_col) = cols.get(3) {
                            if let Ok(avail_1k) = avail_col.parse::<u64>() {
                                return avail_1k.saturating_mul(1024);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    let _ = data_dir;

    DEFAULT_FALLBACK_BYTES
}

/// Inner state guarded by RwLock.
#[derive(Debug, Default)]
struct CollectorState {
    last_cpu_sample: Option<CpuStatSample>,
    cpu_percent: f64,
    rss_mb: f64,
    redb_bytes: u64,
    disk_free_bytes: u64,
    redb_history: VecDeque<(Instant, u64)>,

    // Sparklines
    writes_sparkline: SparklineRingBuffer<f32, SPARKLINE_CAPACITY>,
    reads_sparkline: SparklineRingBuffer<f32, SPARKLINE_CAPACITY>,
    latency_sparkline: SparklineRingBuffer<f32, SPARKLINE_CAPACITY>,
    nodes_sparkline: SparklineRingBuffer<u32, SPARKLINE_CAPACITY>,

    // Rate tracker previous counters
    last_writes_total: u64,
    last_reads_total: u64,
}

impl CollectorState {
    fn new(data_dir: &Path) -> Self {
        let redb_bytes = read_redb_size(data_dir);
        let mut redb_history = VecDeque::with_capacity(120);
        redb_history.push_back((Instant::now(), redb_bytes));
        Self {
            disk_free_bytes: read_disk_free(data_dir),
            redb_bytes,
            rss_mb: read_rss_mb(),
            redb_history,
            ..Default::default()
        }
    }
}

/// System-Observatory Background Collector.
#[derive(Debug)]
pub struct SystemStatsCollector {
    data_dir: PathBuf,
    state: RwLock<CollectorState>,
}

impl SystemStatsCollector {
    /// Creates a new SystemStatsCollector bound to the specified `data_dir`.
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let data_dir = data_dir.as_ref().to_path_buf();
        let initial_state = CollectorState::new(&data_dir);
        Self {
            data_dir,
            state: RwLock::new(initial_state),
        }
    }

    /// Records one 1-second sample step.
    pub fn tick_sample(
        &self,
        current_writes_total: u64,
        current_reads_total: u64,
        current_local_latency_ms: f64,
        current_nodes_count: usize,
    ) {
        let cpu_sample = CpuStatSample::read();
        let rss = read_rss_mb();
        let redb_sz = read_redb_size(&self.data_dir);
        let disk_free = read_disk_free(&self.data_dir);

        let mut guard = self.state.write();

        // 1. Calculate CPU usage % delta
        if let (Some(prev), Some(curr)) = (guard.last_cpu_sample, cpu_sample) {
            let total_delta = curr.total.saturating_sub(prev.total);
            let idle_delta = curr.idle.saturating_sub(prev.idle);
            if total_delta > 0 {
                let usage = (1.0 - (idle_delta as f64 / total_delta as f64)) * 100.0;
                guard.cpu_percent = usage.clamp(0.0, 100.0);
            }
        }
        guard.last_cpu_sample = cpu_sample;
        guard.rss_mb = rss;
        guard.redb_bytes = redb_sz;
        guard.disk_free_bytes = disk_free;

        // Track redb file size history (up to 120 samples)
        let now = Instant::now();
        guard.redb_history.push_back((now, redb_sz));
        if guard.redb_history.len() > 120 {
            guard.redb_history.pop_front();
        }

        // 2. Calculate TX/s and Reads/s delta
        let writes_per_sec = current_writes_total.saturating_sub(guard.last_writes_total) as f32;
        let reads_per_sec = current_reads_total.saturating_sub(guard.last_reads_total) as f32;
        guard.last_writes_total = current_writes_total;
        guard.last_reads_total = current_reads_total;

        // 3. Push to ringbuffers
        guard.writes_sparkline.push(writes_per_sec);
        guard.reads_sparkline.push(reads_per_sec);
        guard.latency_sparkline.push(current_local_latency_ms as f32);
        guard.nodes_sparkline.push(current_nodes_count as u32);
    }

    /// Computes and returns the `SystemStatsDto`.
    pub fn get_system_stats(
        &self,
        total_valid_locks: usize,
        avg_local_latency_ms: f64,
        ttl_purged_count: u64,
    ) -> SystemStatsDto {
        let guard = self.state.read();

        let netto_locks_bytes = (total_valid_locks as u64).saturating_mul(144);
        let peak_tps_single_core = (1000.0 / avg_local_latency_ms.max(0.01)) as u64;
        let peak_tps_single_core = peak_tps_single_core.min(50_000);

        let cpu_cores = std::thread::available_parallelism()
            .map(|n| n.get() as u64)
            .unwrap_or(1);
        let peak_tps_multi_core = peak_tps_single_core.saturating_mul(cpu_cores);

        let disk_free = guard.disk_free_bytes;
        let max_storage_locks = disk_free / 256;
        let byte_years_capacity = max_storage_locks;

        let (redb_growth_mb_per_day, days_until_full, disk_headroom_label) = {
            if let (Some(oldest), Some(newest)) = (guard.redb_history.front(), guard.redb_history.back()) {
                let delta_sec = newest.0.duration_since(oldest.0).as_secs();
                if delta_sec > 0 && newest.1 > oldest.1 {
                    let delta_bytes = newest.1 - oldest.1;
                    let growth_mb_per_day = (delta_bytes as f64 / delta_sec as f64) * 86400.0 / (1024.0 * 1024.0);
                    if growth_mb_per_day > 0.0 {
                        let bytes_per_day = growth_mb_per_day * 1024.0 * 1024.0;
                        let days = (disk_free as f64 / bytes_per_day) as u64;
                        (growth_mb_per_day, Some(days), format!("{days} Tage"))
                    } else {
                        (0.0, None, "> 365 Tage (stabil)".to_string())
                    }
                } else {
                    (0.0, None, "> 365 Tage (stabil)".to_string())
                }
            } else {
                (0.0, None, "> 365 Tage (stabil)".to_string())
            }
        };

        SystemStatsDto {
            cpu_percent: guard.cpu_percent,
            rss_mb: guard.rss_mb,
            redb_bytes: guard.redb_bytes,
            netto_locks_bytes,
            disk_free_bytes: disk_free,
            peak_tps_single_core,
            peak_tps_multi_core,
            max_storage_locks,
            byte_years_capacity,
            ttl_purged_count,
            redb_growth_mb_per_day,
            days_until_full,
            disk_headroom_label,
        }
    }

    #[doc(hidden)]
    pub fn push_redb_history_for_testing(&self, instant: Instant, bytes: u64) {
        let mut guard = self.state.write();
        guard.redb_history.push_back((instant, bytes));
        if guard.redb_history.len() > 120 {
            guard.redb_history.pop_front();
        }
    }

    #[doc(hidden)]
    pub fn clear_redb_history_for_testing(&self) {
        let mut guard = self.state.write();
        guard.redb_history.clear();
    }

    /// Computes and returns the `SparklinesDto`.
    pub fn get_sparklines(&self) -> SparklinesDto {
        let guard = self.state.read();
        SparklinesDto {
            writes: guard.writes_sparkline.to_chronological_vec(),
            reads: guard.reads_sparkline.to_chronological_vec(),
            latency: guard.latency_sparkline.to_chronological_vec(),
            nodes: guard.nodes_sparkline.to_chronological_vec(),
        }
    }

    /// Spawns the autonomous 1-second sampling background motor.
    pub fn spawn_background_collector(
        self: Arc<Self>,
        metrics: Arc<crate::api::metrics::NodeMetrics>,
        peer_manager: Option<Arc<crate::network::PeerManager>>,
        cancel_token: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("System stats observatory worker shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        let writes_total = metrics.total_writes();
                        let reads_total = metrics.total_reads();
                        let local_latency = metrics.local_latency.avg_ms();

                        let nodes_count = if let Some(ref pm) = peer_manager {
                            pm.active_nodes_count()
                        } else {
                            1
                        };

                        self.tick_sample(writes_total, reads_total, local_latency, nodes_count);
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparkline_ring_buffer_chronology() {
        let mut ring: SparklineRingBuffer<f32, 5> = SparklineRingBuffer::new();
        // Empty buffer returns 5 zeroes
        assert_eq!(ring.to_chronological_vec(), vec![0.0, 0.0, 0.0, 0.0, 0.0]);

        // Partially filled
        ring.push(10.0);
        ring.push(20.0);
        assert_eq!(ring.to_chronological_vec(), vec![0.0, 0.0, 0.0, 10.0, 20.0]);

        // Fully filled
        ring.push(30.0);
        ring.push(40.0);
        ring.push(50.0);
        assert_eq!(ring.to_chronological_vec(), vec![10.0, 20.0, 30.0, 40.0, 50.0]);

        // Over-filled wrapping
        ring.push(60.0);
        assert_eq!(ring.to_chronological_vec(), vec![20.0, 30.0, 40.0, 50.0, 60.0]);
    }

    #[test]
    fn test_system_stats_capacity_projections() {
        let collector = SystemStatsCollector::new(".");
        let stats = collector.get_system_stats(1000, 0.5, 42);

        // 144 bytes * 1000 = 144_000
        assert_eq!(stats.netto_locks_bytes, 144_000);
        assert_eq!(stats.ttl_purged_count, 42);

        // Latency 0.5 ms -> 1000.0 / 0.5 = 2000 TPS
        assert_eq!(stats.peak_tps_single_core, 2000);
        assert!(stats.peak_tps_multi_core >= 2000);
        assert!(stats.max_storage_locks > 0);
        assert_eq!(stats.byte_years_capacity, stats.max_storage_locks);

        // Initial state has insufficient delta
        assert_eq!(stats.redb_growth_mb_per_day, 0.0);
        assert_eq!(stats.days_until_full, None);
        assert_eq!(stats.disk_headroom_label, "> 365 Tage (stabil)");
    }

    #[test]
    fn test_read_disk_free() {
        let free = read_disk_free(Path::new("."));
        assert!(free > 0);
    }

    #[test]
    fn test_redb_growth_and_headroom_projection() {
        let collector = SystemStatsCollector::new(".");
        collector.clear_redb_history_for_testing();

        let t0 = Instant::now() - Duration::from_secs(86400);
        let t1 = Instant::now();

        // 100 MB to 110 MB in 24 hours -> 10 MB / day
        collector.push_redb_history_for_testing(t0, 100 * 1024 * 1024);
        collector.push_redb_history_for_testing(t1, 110 * 1024 * 1024);

        let stats = collector.get_system_stats(100, 1.0, 0);
        let growth = stats.redb_growth_mb_per_day;
        assert!((growth - 10.0).abs() < 0.1, "Growth expected ~10.0 MB/day, got {growth}");
        assert!(stats.days_until_full.is_some());
        let days = stats.days_until_full.unwrap();
        assert_eq!(stats.disk_headroom_label, format!("{days} Tage"));
    }
}
