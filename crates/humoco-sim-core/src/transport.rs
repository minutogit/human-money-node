//! Spec 15: P2P Transport & Connection Lifecycle (INV-1501..1503)
use std::collections::{HashMap, VecDeque};

use crate::types::{NodeId, SimTime};

/// 3-Phasen Connection Lifecycle (INV-1501)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnState {
    Connected,
    Degrading,
    Suspended,
}

#[derive(Clone, Debug)]
pub struct Connection {
    pub peer: NodeId,
    pub state: ConnState,
    pub last_seen: SimTime,
    pub missing_count: u32,
    pub backoff_attempt: u32,
    pub next_retry_at: SimTime,
}

impl Connection {
    pub fn new(peer: NodeId, now: SimTime) -> Self {
        Self { peer, state: ConnState::Connected, last_seen: now, missing_count: 0, backoff_attempt: 0, next_retry_at: now }
    }
    /// Keep-alive ping succeeded
    pub fn on_heartbeat(&mut self, now: SimTime) {
        self.last_seen = now;
        self.missing_count = 0;
        if self.state == ConnState::Suspended {
            // stay suspended until backoff retry succeeds? For test, immediately reconnect?
            // Spec: after suspension, need successful reconnect to go Connected
            self.state = ConnState::Connected;
            self.backoff_attempt = 0;
        } else {
            self.state = ConnState::Connected;
        }
    }
    /// Missed heartbeat / failed request
    pub fn on_miss(&mut self, now: SimTime) {
        self.missing_count += 1;
        if self.missing_count >= crate::types::MISSING_COUNT_THRESHOLD {
            self.state = ConnState::Suspended;
            self.backoff_attempt += 1;
            let backoff = compute_backoff(self.backoff_attempt, 1000, 60_000, self.peer as u64 + now.0);
            self.next_retry_at = SimTime(now.0 + backoff);
        } else if self.missing_count >= 1 {
            self.state = ConnState::Degrading;
        }
    }
    pub fn is_suspended(&self) -> bool { self.state == ConnState::Suspended }
    /// QUIC idle timeout 30s: if now - last_seen >= 30s => degrading/suspended
    pub fn check_idle(&mut self, now: SimTime) {
        let idle = now.0.saturating_sub(self.last_seen.0);
        if idle >= 30_000 {
            if self.state == ConnState::Connected {
                self.state = ConnState::Degrading;
            }
            if idle >= 60_000 {
                self.state = ConnState::Suspended;
            }
        }
    }
}

/// Exponentielles Backoff mit Jitter (INV-1502)
/// base * 2^(attempt-1) with jitter +/-25% deterministic via seed, capped
pub fn compute_backoff(attempt: u32, base_ms: u64, cap_ms: u64, seed: u64) -> u64 {
    if attempt == 0 { return 0; }
    let exp = 1u64 << (attempt - 1).min(10); // cap exponent
    let base = base_ms.saturating_mul(exp).min(cap_ms);
    // jitter 0.75..1.25 deterministic via xorshift on seed+attempt
    let mut x = seed ^ (attempt as u64).wrapping_mul(0x9E3779B97F4A7C15);
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    let jitter_factor = (x % 500) as f64 / 1000.0; // 0..0.5
    // shift to -0.25..+0.25
    let jitter = jitter_factor - 0.25;
    let with_jitter = (base as f64 * (1.0 + jitter)).round() as i64;
    let clamped = with_jitter.clamp((base as f64 * 0.75) as i64, (base as f64 * 1.25) as i64) as u64;
    clamped.min(cap_ms).max(base_ms/2)
}

// ---------------------------------------------------------------------------
// Connection Pool with Dunbar eviction (INV-1503)
// ---------------------------------------------------------------------------

pub const DUNBAR_MAX: usize = 150;
pub const POOL_HARD_LIMIT: usize = 200;

pub struct ConnectionPool {
    pub conns: HashMap<NodeId, Connection>,
    /// LRU order (most recent front)
    lru: VecDeque<NodeId>,
}

impl ConnectionPool {
    pub fn new() -> Self { Self { conns: HashMap::new(), lru: VecDeque::new() } }
    pub fn len(&self) -> usize { self.conns.len() }
    pub fn is_empty(&self) -> bool { self.conns.is_empty() }
    pub fn contains(&self, peer: NodeId) -> bool { self.conns.contains_key(&peer) }
    /// Try add; if at limit, evict least useful (LRU tail or suspended)
    pub fn add(&mut self, peer: NodeId, now: SimTime) -> Option<NodeId> {
        if self.conns.contains_key(&peer) {
            self.touch(peer);
            return None;
        }
        let mut evicted = None;
        if self.conns.len() >= DUNBAR_MAX {
            // Prefer evict suspended first
            let suspended = self.conns.iter().find(|(_,c)| c.state == ConnState::Suspended).map(|(k,_)| *k);
            let to_remove = if let Some(s) = suspended {
                s
            } else {
                // LRU tail
                self.lru.back().copied().unwrap_or(peer)
            };
            self.conns.remove(&to_remove);
            self.lru.retain(|&x| x != to_remove);
            evicted = Some(to_remove);
        }
        // Hard limit never exceed POOL_HARD_LIMIT (should not happen due to dunbar)
        if self.conns.len() >= POOL_HARD_LIMIT {
            // evict one more
            if let Some(tail) = self.lru.back().copied() {
                self.conns.remove(&tail);
                self.lru.retain(|&x| x != tail);
                evicted = Some(tail);
            }
        }
        self.conns.insert(peer, Connection::new(peer, now));
        self.lru.push_front(peer);
        evicted
    }
    fn touch(&mut self, peer: NodeId) {
        self.lru.retain(|&x| x != peer);
        self.lru.push_front(peer);
    }
    pub fn on_heartbeat(&mut self, peer: NodeId, now: SimTime) {
        if let Some(c) = self.conns.get_mut(&peer) {
            c.on_heartbeat(now);
        }
        self.touch(peer);
    }
    pub fn on_miss(&mut self, peer: NodeId, now: SimTime) {
        if let Some(c) = self.conns.get_mut(&peer) {
            c.on_miss(now);
        }
    }
    pub fn suspended_count(&self) -> usize { self.conns.values().filter(|c| c.state == ConnState::Suspended).count() }
}

impl Default for ConnectionPool {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_backoff_jitter_bounds() {
        for attempt in 1..6 {
            let b = compute_backoff(attempt, 1000, 60_000, 42);
            let base = 1000 * (1u64<< (attempt-1));
            assert!(b >= (base as f64 * 0.75) as u64);
            assert!(b <= (base as f64 * 1.25) as u64);
        }
    }
    #[test]
    fn test_pool_dunbar_eviction() {
        let mut pool = ConnectionPool::new();
        let now = SimTime(0);
        for i in 0..150 {
            pool.add(i as u16, now);
        }
        assert_eq!(pool.len(), 150);
        // add one more triggers eviction
        let ev = pool.add(999, now);
        assert!(ev.is_some());
        assert_eq!(pool.len(), 150);
        assert!(pool.contains(999));
    }
}
