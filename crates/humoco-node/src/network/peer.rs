use std::net::SocketAddr;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Spec 15 / Spec 19: 3-phase lifecycle (Connected -> Degrading -> Suspended).
/// From 2 failures (debounced): Degrading (early warning).
/// From 3 failures (INV-1501 / AGENTS.md): Suspended (rank-21 replacement jumps in 0ms).
pub const FAILURE_THRESHOLD_DEGRADING: u32 = 2;
pub const FAILURE_THRESHOLD_SUSPENDED: u32 = 3;
pub const FAILURE_DEBOUNCE_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerStatus {
    Connected,
    Degrading,
    Suspended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerConnectionType {
    /// Direct trusted friend: full gossip, heartbeats, and Shard-RPC
    FriendToFriend,
    /// Known network node (learned from F2F gossip): authorized for Shard-RPC, but NO gossip
    ShardDirect,
    /// Unknown / untrusted connection
    Untrusted,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub node_id: Option<[u8; 32]>,
    pub status: PeerStatus,
    pub missing_count: u32,
    pub last_seen: Option<Instant>,
    pub last_failure: Option<Instant>,
    pub connection: Option<quinn::Connection>,
    pub conn_type: PeerConnectionType,
}

impl PeerInfo {
    pub fn new(addr: SocketAddr) -> Self {
        Self::with_type(addr, PeerConnectionType::FriendToFriend)
    }

    pub fn with_type(addr: SocketAddr, conn_type: PeerConnectionType) -> Self {
        Self {
            addr,
            node_id: None,
            status: PeerStatus::Degrading, // Initial state until first successful connection
            missing_count: 0,
            last_seen: None,
            last_failure: None,
            connection: None,
            conn_type,
        }
    }

    pub fn can_accept_gossip(&self) -> bool {
        self.conn_type == PeerConnectionType::FriendToFriend
    }

    pub fn mark_success(&mut self, node_id: Option<[u8; 32]>, conn: Option<quinn::Connection>) {
        self.missing_count = 0;
        self.status = PeerStatus::Connected;
        self.last_seen = Some(Instant::now());
        self.last_failure = None;
        if node_id.is_some() {
            self.node_id = node_id;
        }
        if conn.is_some() {
            self.connection = conn;
        }
    }

    /// Debounced mark_failure: Multiple failures within 10 seconds increment missing_count by at most 1 (Cascading Death Spiral protection, Spec 15 & 19).
    pub fn mark_failure(&mut self) {
        self.mark_failure_at(Instant::now());
    }

    /// Debounced mark_failure with explicit timestamp (for tests and simulation).
    pub fn mark_failure_at(&mut self, now: Instant) {
        let should_increment = match self.last_failure {
            Some(last) => now.duration_since(last) >= Duration::from_secs(FAILURE_DEBOUNCE_SECS),
            None => true,
        };

        if should_increment {
            self.last_failure = Some(now);
            self.missing_count = self.missing_count.saturating_add(1);
            if self.missing_count >= FAILURE_THRESHOLD_SUSPENDED {
                self.status = PeerStatus::Suspended;
                self.connection = None;
            } else if self.missing_count >= FAILURE_THRESHOLD_DEGRADING {
                self.status = PeerStatus::Degrading;
            }
        }
    }

    /// Autonomous healing: hourly penalty decay (-1)
    pub fn decay_malus(&mut self) {
        self.missing_count = self.missing_count.saturating_sub(1);
        if self.missing_count < FAILURE_THRESHOLD_DEGRADING {
            if self.connection.is_some() {
                self.status = PeerStatus::Connected;
            } else {
                self.status = PeerStatus::Degrading;
            }
        } else if self.missing_count < FAILURE_THRESHOLD_SUSPENDED {
            self.status = PeerStatus::Degrading;
        }
    }

    pub fn is_suspended(&self) -> bool {
        self.status == PeerStatus::Suspended
    }

    pub fn is_connected(&self) -> bool {
        self.status == PeerStatus::Connected
            && self
                .connection
                .as_ref()
                .is_none_or(|c| c.close_reason().is_none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_lifecycle_transitions() {
        let addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let mut peer = PeerInfo::new(addr);
        assert_eq!(peer.status, PeerStatus::Degrading);

        // Mark success
        peer.mark_success(Some([1u8; 32]), None);
        assert_eq!(peer.status, PeerStatus::Connected);
        assert_eq!(peer.missing_count, 0);
        assert!(peer.last_seen.is_some());

        // Failures up to Degrading (resetting last_failure to simulate >10s intervals)
        for _ in 0..FAILURE_THRESHOLD_DEGRADING {
            peer.last_failure = None;
            peer.mark_failure();
        }
        assert_eq!(peer.status, PeerStatus::Degrading);

        // Failures up to Suspended
        for _ in FAILURE_THRESHOLD_DEGRADING..FAILURE_THRESHOLD_SUSPENDED {
            peer.last_failure = None;
            peer.mark_failure();
        }
        assert_eq!(peer.status, PeerStatus::Suspended);
        assert!(peer.is_suspended());

        // Recovery upon success
        peer.mark_success(None, None);
        assert_eq!(peer.status, PeerStatus::Connected);
        assert!(!peer.is_suspended());
    }

    #[test]
    fn test_peer_failure_debounce() {
        let addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let mut peer = PeerInfo::new(addr);
        let t0 = Instant::now();

        // 1st failure at t0 -> increments missing_count to 1
        peer.mark_failure_at(t0);
        assert_eq!(peer.missing_count, 1);

        // Multiple rapid failures within 60s window (e.g., at +1s, +15s, +59s) MUST NOT increment missing_count
        peer.mark_failure_at(t0 + Duration::from_secs(1));
        assert_eq!(peer.missing_count, 1);

        peer.mark_failure_at(t0 + Duration::from_secs(15));
        assert_eq!(peer.missing_count, 1);

        peer.mark_failure_at(t0 + Duration::from_secs(59));
        assert_eq!(peer.missing_count, 1);

        // Failure at >= 60s MUST increment missing_count to 2
        let t1 = t0 + Duration::from_secs(60);
        peer.mark_failure_at(t1);
        assert_eq!(peer.missing_count, 2);

        // Another failure at t1 + 10s MUST NOT increment
        peer.mark_failure_at(t1 + Duration::from_secs(10));
        assert_eq!(peer.missing_count, 2);

        // Failure at t1 + 60s MUST increment to 3 (reaching Suspended per AGENTS.md / Spec 15)
        let t2 = t1 + Duration::from_secs(60);
        peer.mark_failure_at(t2);
        assert_eq!(peer.missing_count, 3);
        assert_eq!(peer.status, PeerStatus::Suspended);
    }
}
