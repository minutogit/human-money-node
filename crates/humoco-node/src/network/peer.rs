use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Spec 15 / Spec 19: 3-phase lifecycle (Connected -> Degrading -> Suspended).
/// From 2 failures (debounced): Degrading (early warning).
/// From 3 failures: local diagnostic suspension; never committee replacement.
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
    pub last_rpc_tested_at: Option<Instant>,
    pub last_connected_at: Option<Instant>,
    pub active_connected_failure_since: Option<Instant>,
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
            last_rpc_tested_at: None,
            last_connected_at: None,
            active_connected_failure_since: None,
        }
    }

    pub fn can_accept_gossip(&self) -> bool {
        self.conn_type == PeerConnectionType::FriendToFriend
    }

    pub fn mark_success(&mut self, node_id: Option<[u8; 32]>, conn: Option<quinn::Connection>) {
        // Phase 8 (Spec 15/19): a pure QUIC/TLS handshake MUST NOT reset the
        // Tit-for-Tat error malus. Only actually performed shard work
        // (`mark_shard_work_success`) decays the malus. The handshake merely
        // refreshes identity, connection handle and last-seen timestamp while
        // preserving `missing_count` / `last_failure` and the suspension state.
        self.last_seen = Some(Instant::now());
        self.last_connected_at = Some(Instant::now());
        if node_id.is_some() {
            self.node_id = node_id;
        }
        if conn.is_some() {
            self.connection = conn;
        }
        if self.missing_count >= FAILURE_THRESHOLD_SUSPENDED {
            self.status = PeerStatus::Suspended;
        } else if self.missing_count >= FAILURE_THRESHOLD_DEGRADING {
            self.status = PeerStatus::Degrading;
        } else if self.missing_count == 0 {
            self.status = PeerStatus::Connected;
        } else {
            self.status = PeerStatus::Degrading;
        }
    }

    /// Records genuinely performed shard work (valid attestation / sync payload).
    /// This is the ONLY path (besides hourly `decay_malus`) that reduces the
    /// Tit-for-Tat malus: each proven shard contribution decays `missing_count`
    /// by exactly 1 (activity-locked healing, Spec 19).
    pub fn mark_shard_work_success(&mut self) {
        self.missing_count = self.missing_count.saturating_sub(1);
        let now = Instant::now();
        self.last_seen = Some(now);
        self.last_rpc_tested_at = Some(now);
        self.active_connected_failure_since = None;
        if self.missing_count == 0 {
            self.last_failure = None;
            if self.connection.is_some() {
                self.status = PeerStatus::Connected;
            } else {
                self.status = PeerStatus::Degrading;
            }
        } else if self.missing_count < FAILURE_THRESHOLD_SUSPENDED {
            self.status = PeerStatus::Degrading;
        } else {
            self.status = PeerStatus::Suspended;
        }
    }

    /// Clears a dead QUIC connection handle (e.g. Tier-2 15s idle timeout,
    /// graceful `CONNECTION_CLOSE`) WITHOUT touching the Tit-for-Tat malus.
    /// An idle timeout is the normal state of the ephemeral Tier-2 LRU pool
    /// (TODO-ARCH-02) and must NEVER be counted as a peer failure.
    pub fn clear_connection_preserve_malus(&mut self) {
        self.connection = None;
        if self.missing_count >= FAILURE_THRESHOLD_SUSPENDED {
            self.status = PeerStatus::Suspended;
        } else if self.missing_count >= FAILURE_THRESHOLD_DEGRADING {
            self.status = PeerStatus::Degrading;
        }
        // `missing_count == 0` without a connection handle keeps the last
        // status (Connected peers become Degrading only on next failure).
    }

    /// Debounced mark_failure: Multiple failures within 10 seconds increment missing_count by at most 1 (Cascading Death Spiral protection, Spec 15 & 19).
    pub fn mark_failure(&mut self) {
        self.mark_failure_at(Instant::now());
    }

    /// Debounced mark_failure with explicit timestamp (for tests and simulation).
    pub fn mark_failure_at(&mut self, now: Instant) {
        self.last_rpc_tested_at = Some(now);
        if self.connection.is_some() {
            self.active_connected_failure_since.get_or_insert(now);
        } else {
            self.active_connected_failure_since = None;
        }

        let should_increment = match self.last_failure {
            Some(last) => now.duration_since(last) >= Duration::from_secs(FAILURE_DEBOUNCE_SECS),
            None => true,
        };

        if should_increment {
            self.last_failure = Some(now);
            self.missing_count = self.missing_count.saturating_add(1);
            if self.missing_count >= FAILURE_THRESHOLD_SUSPENDED {
                self.status = PeerStatus::Suspended;
                if self.conn_type != PeerConnectionType::FriendToFriend {
                    self.connection = None;
                }
            } else if self.missing_count >= FAILURE_THRESHOLD_DEGRADING {
                self.status = PeerStatus::Degrading;
            }
        }
    }

    /// Returns true iff peer has reached suspension (missing_count >= 3), maintains an open QUIC connection,
    /// and has persistently failed active RPC tests while connected for at least `min_duration`.
    /// Protects against reboot false alarms during quiet periods (INV-1701).
    pub fn is_active_non_responder(&self, now: Instant, min_duration: Duration) -> bool {
        self.missing_count >= FAILURE_THRESHOLD_SUSPENDED
            && self.connection.is_some()
            && self
                .connection
                .as_ref()
                .is_none_or(|c| c.close_reason().is_none())
            && self
                .active_connected_failure_since
                .is_some_and(|s| now.duration_since(s) >= min_duration)
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

        // Mark success (fresh peer, malus 0 -> Connected)
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

        // A pure handshake must NOT reset the malus (Phase 8 / Spec 15/19)
        peer.mark_success(None, None);
        assert_eq!(peer.missing_count, FAILURE_THRESHOLD_DEGRADING);
        assert_eq!(peer.status, PeerStatus::Degrading);

        // Genuine shard work decays the malus by exactly 1 per contribution
        peer.mark_shard_work_success();
        assert_eq!(peer.missing_count, FAILURE_THRESHOLD_DEGRADING - 1);

        // Failures up to Suspended (malus is 1 after the decay above, need 2 more)
        for _ in 0..FAILURE_THRESHOLD_DEGRADING {
            peer.last_failure = None;
            peer.mark_failure();
        }
        assert_eq!(peer.missing_count, FAILURE_THRESHOLD_SUSPENDED);
        assert_eq!(peer.status, PeerStatus::Suspended);
        assert!(peer.is_suspended());

        // A pure handshake must NOT lift a suspension (Phase 8)
        peer.mark_success(None, None);
        assert!(peer.is_suspended());
        assert_eq!(peer.missing_count, FAILURE_THRESHOLD_SUSPENDED);

        // Idle-timeout close preserves the malus without penalizing
        peer.clear_connection_preserve_malus();
        assert_eq!(peer.missing_count, FAILURE_THRESHOLD_SUSPENDED);

        // Recovery only via genuine shard work (decays step by step)
        peer.mark_shard_work_success();
        assert_eq!(peer.status, PeerStatus::Degrading);
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

    #[test]
    fn test_active_non_responder_and_reboot_quiet_period_immunity() {
        let addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let mut peer = PeerInfo::new(addr);
        let t0 = Instant::now();

        // Initially no failures and not connected
        assert!(!peer.is_active_non_responder(t0, Duration::from_secs(1800)));

        // Peer is suspended (e.g. from previous failures)
        peer.missing_count = 3;
        peer.status = PeerStatus::Suspended;

        // Even though missing_count >= 3, if connection is None, it is NOT an active non-responder
        assert!(!peer.is_active_non_responder(t0, Duration::from_secs(1800)));

        // Simulate connection established, but quiet period (no RPC failures tested yet)
        peer.last_connected_at = Some(t0);
        // We simulate a mock connection state (or active_connected_failure_since)
        // Note: active_connected_failure_since is None until an actual RPC failure occurs while connected
        assert_eq!(peer.active_connected_failure_since, None);
        assert!(!peer.is_active_non_responder(t0, Duration::from_secs(1800)));

        // RPC failure occurs while connected
        peer.active_connected_failure_since = Some(t0);
        // Before 30 min has elapsed: false
        assert!(!peer.is_active_non_responder(t0 + Duration::from_secs(600), Duration::from_secs(1800)));

        // After 30 min (1800s) has elapsed: if connection is None, still false!
        assert!(!peer.is_active_non_responder(t0 + Duration::from_secs(1801), Duration::from_secs(1800)));

        // Shard work success heals and resets active_connected_failure_since
        peer.mark_shard_work_success();
        assert_eq!(peer.active_connected_failure_since, None);
        assert_eq!(peer.missing_count, 2);
    }
}
