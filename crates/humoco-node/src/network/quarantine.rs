use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Configuration policy for Hop-invariant KISS F2F Quarantine (Algo 3v2) and ShadowEdgeWindow.
///
/// Default values adhere to the verified production parameters:
/// - `hop_wait_per_hop`: 3 hours ($T(h) = 3\text{h} \cdot h$)
/// - `shadow_clean_window`: 3 hours
/// - `min_step_interval`: 1 hour (calm cadence: at most 1 quarantine / preemption action per hour)
/// - `min_remaining_active_friends`: 2 (minimum degree of active friends that must never be severed)
/// - `max_exclusive_strictly_healthy`: 2 (bridge protection: edges carrying > 2 strictly healthy nodes are immune at $h \ge 1$)
#[derive(Debug, Clone)]
pub struct QuarantinePolicy {
    /// Wait time multiplier per hop: T(h) = h * hop_wait_per_hop.
    pub hop_wait_per_hop: Duration,
    /// Duration of clean shadow window required for autonomous self-healing.
    pub shadow_clean_window: Duration,
    /// Minimum interval between quarantine / preemption steps (Rule 3: calm cadence).
    pub min_step_interval: Duration,
    /// Minimum remaining active F2F friend edges that must never be severed (Rule 1).
    pub min_remaining_active_friends: usize,
    /// Maximum exclusive strictly healthy nodes tolerated behind an edge before bridge protection triggers (Rule 2).
    pub max_exclusive_strictly_healthy: usize,
}

impl Default for QuarantinePolicy {
    fn default() -> Self {
        Self {
            hop_wait_per_hop: Duration::from_secs(3 * 3600),
            shadow_clean_window: Duration::from_secs(3 * 3600),
            min_step_interval: Duration::from_secs(3600),
            min_remaining_active_friends: 2,
            max_exclusive_strictly_healthy: 2,
        }
    }
}

impl QuarantinePolicy {
    /// Computes the required maturation delay for a zombie at hop `h`.
    #[inline]
    pub fn hop_wait_duration(&self, h: u8) -> Duration {
        self.hop_wait_per_hop.saturating_mul(h as u32)
    }
}

/// State tracking for a quarantined direct F2F edge during its `ShadowEdgeWindow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedEdgeState {
    /// Local timestamp when the edge was quarantined.
    pub quarantined_at: Instant,
    /// The hop distance of the defect / zombie that triggered this quarantine.
    pub trigger_hops: u8,
    /// Timestamp when a zombie heartbeat (missing_count >= 3) was last observed over this quarantined edge.
    /// Initialized to `quarantined_at`.
    pub last_zombie_shadow_seen: Instant,
    /// Total count of non-zombie heartbeats observed over this quarantined edge in the shadow window.
    pub clean_heartbeats_seen: u64,
    /// Timestamp of any heartbeat received over this quarantined edge.
    pub shadow_last_seen: Option<Instant>,
}

impl QuarantinedEdgeState {
    pub fn new(now: Instant, trigger_hops: u8) -> Self {
        Self {
            quarantined_at: now,
            trigger_hops,
            last_zombie_shadow_seen: now,
            clean_heartbeats_seen: 0,
            shadow_last_seen: None,
        }
    }

    /// Records an incoming heartbeat over this quarantined edge in the shadow window.
    ///
    /// If the origin node has `missing_count >= 3` (zombie), `last_zombie_shadow_seen` is refreshed to `now`.
    /// Otherwise, `clean_heartbeats_seen` is incremented.
    pub fn record_shadow_heartbeat(&mut self, is_zombie: bool, now: Instant) {
        self.shadow_last_seen = Some(now);
        if is_zombie {
            self.last_zombie_shadow_seen = now;
        } else {
            self.clean_heartbeats_seen = self.clean_heartbeats_seen.saturating_add(1);
        }
    }

    /// Checks if this quarantined edge has healed autonomously.
    ///
    /// An edge heals back to Active when no zombie heartbeats were observed for at least `shadow_clean_window`.
    pub fn is_healed(&self, now: Instant, policy: &QuarantinePolicy) -> bool {
        now.saturating_duration_since(self.last_zombie_shadow_seen) >= policy.shadow_clean_window
    }
}

/// A candidate active F2F friend edge evaluated for potential quarantine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateEdge {
    /// Direct F2F friend public key.
    pub friend_pk: [u8; 32],
    /// Trigger hop distance: 0 for direct peer failure, or minimum hops to a mature zombie.
    pub h: u8,
    /// Number of nodes exclusively observed via this friend that are strictly healthy (missing_count == 0).
    pub n_exclusive_strictly_healthy: usize,
    /// Number of nodes exclusively observed via this friend that are healthy (missing_count < 3).
    pub n_exclusive_healthy: usize,
    /// Total number of healthy nodes (missing_count < 3) observed via this friend.
    pub n_healthy: usize,
}

/// Decision output from `decide_algo3v2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineDecision {
    /// Quarantine an active friend edge directly (active_friends_count >= min + 1).
    Quarantine {
        friend_pk: [u8; 32],
        trigger_hops: u8,
    },
    /// At the active limit (active_friends_count == min): release an existing quarantined edge with
    /// higher trigger_hops to quarantine a closer defect.
    Preempt {
        release_friend_pk: [u8; 32],
        target_friend_pk: [u8; 32],
        trigger_hops: u8,
    },
}

/// Discrete event produced by quarantine evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineEvent {
    /// An edge healed autonomously after a clean shadow window.
    Healed { friend_pk: [u8; 32] },
    /// An active edge was quarantined.
    Quarantined { friend_pk: [u8; 32], trigger_hops: u8 },
    /// An existing quarantined edge was released to quarantine a closer defect edge.
    Preempted {
        released_friend_pk: [u8; 32],
        quarantined_friend_pk: [u8; 32],
        trigger_hops: u8,
    },
}

/// Pure, deterministic decision function for Hop-invariant KISS Quarantine (Algo 3v2).
///
/// Steps:
/// 1. Rule 2 (Bridge Protection): Filter `mature_candidates` to
///    `c.h == 0 || c.n_exclusive_strictly_healthy <= policy.max_exclusive_strictly_healthy`.
/// 2. Select `best` candidate minimizing `(c.h, c.n_exclusive_healthy, c.n_healthy, c.friend_pk)`.
/// 3. Rule 1 (Minimum Active Edges & Preemption):
///    - If `active_friends_count >= policy.min_remaining_active_friends + 1`:
///      `Some(Quarantine { friend_pk: best.friend_pk, trigger_hops: best.h })`.
///    - Else if `active_friends_count == policy.min_remaining_active_friends`:
///      Find currently quarantined edge with maximal `(trigger_hops, friend_pk)` where `trigger_hops > best.h`.
///      If found: `Some(Preempt { release_friend_pk, target_friend_pk: best.friend_pk, trigger_hops: best.h })`.
///      Else: `None`.
///    - Else: `None`.
pub fn decide_algo3v2(
    mature_candidates: &[CandidateEdge],
    active_friends_count: usize,
    currently_quarantined: &HashMap<[u8; 32], QuarantinedEdgeState>,
    policy: &QuarantinePolicy,
) -> Option<QuarantineDecision> {
    // 1. Rule 2 (Hop-invariant bridge protection)
    let mut allowed: Vec<&CandidateEdge> = mature_candidates
        .iter()
        .filter(|c| c.h == 0 || c.n_exclusive_strictly_healthy <= policy.max_exclusive_strictly_healthy)
        .collect();

    if allowed.is_empty() {
        return None;
    }

    // 2. Select best candidate minimizing (c.h, c.n_exclusive_healthy, c.n_healthy, c.friend_pk)
    allowed.sort_by(|a, b| {
        (a.h, a.n_exclusive_healthy, a.n_healthy, a.friend_pk)
            .cmp(&(b.h, b.n_exclusive_healthy, b.n_healthy, b.friend_pk))
    });
    let best = allowed[0];

    // 3. Rule 1 (Minimum active edges & preemption)
    let min_active = policy.min_remaining_active_friends;
    if active_friends_count >= min_active.saturating_add(1) {
        Some(QuarantineDecision::Quarantine {
            friend_pk: best.friend_pk,
            trigger_hops: best.h,
        })
    } else if active_friends_count == min_active {
        let victim = currently_quarantined
            .iter()
            .filter(|(_, state)| state.trigger_hops > best.h)
            .max_by_key(|(&pk, state)| (state.trigger_hops, pk));

        if let Some((&release_friend_pk, _)) = victim {
            Some(QuarantineDecision::Preempt {
                release_friend_pk,
                target_friend_pk: best.friend_pk,
                trigger_hops: best.h,
            })
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_protection_filters_multi_hop_candidates() {
        let policy = QuarantinePolicy::default(); // max_exclusive_strictly_healthy = 2
        let pk_bridge = [1u8; 32];
        let pk_direct_fail = [2u8; 32];
        let pk_vulnerable = [3u8; 32];

        let candidates = vec![
            CandidateEdge {
                friend_pk: pk_bridge,
                h: 1,
                n_exclusive_strictly_healthy: 3, // > 2 -> MUST be protected!
                n_exclusive_healthy: 3,
                n_healthy: 10,
            },
            CandidateEdge {
                friend_pk: pk_vulnerable,
                h: 2,
                n_exclusive_strictly_healthy: 2, // <= 2 -> allowed
                n_exclusive_healthy: 2,
                n_healthy: 5,
            },
        ];

        let quarantined = HashMap::new();
        // active = 3 -> can quarantine
        let decision = decide_algo3v2(&candidates, 3, &quarantined, &policy);
        assert_eq!(
            decision,
            Some(QuarantineDecision::Quarantine {
                friend_pk: pk_vulnerable,
                trigger_hops: 2,
            })
        );

        // However, h = 0 ignores bridge protection (a direct failing peer is always eligible)
        let candidates_with_direct = vec![
            CandidateEdge {
                friend_pk: pk_direct_fail,
                h: 0,
                n_exclusive_strictly_healthy: 5,
                n_exclusive_healthy: 5,
                n_healthy: 5,
            },
        ];
        let decision_direct = decide_algo3v2(&candidates_with_direct, 3, &quarantined, &policy);
        assert_eq!(
            decision_direct,
            Some(QuarantineDecision::Quarantine {
                friend_pk: pk_direct_fail,
                trigger_hops: 0,
            })
        );
    }

    #[test]
    fn test_tie_breaking_order() {
        let policy = QuarantinePolicy::default();
        let pk1 = [10u8; 32];
        let pk2 = [20u8; 32];

        // Same h = 1, pk1 has fewer exclusive healthy
        let candidates = vec![
            CandidateEdge {
                friend_pk: pk2,
                h: 1,
                n_exclusive_strictly_healthy: 1,
                n_exclusive_healthy: 2,
                n_healthy: 5,
            },
            CandidateEdge {
                friend_pk: pk1,
                h: 1,
                n_exclusive_strictly_healthy: 1,
                n_exclusive_healthy: 0,
                n_healthy: 5,
            },
        ];

        let decision = decide_algo3v2(&candidates, 3, &HashMap::new(), &policy);
        assert_eq!(
            decision,
            Some(QuarantineDecision::Quarantine {
                friend_pk: pk1,
                trigger_hops: 1,
            })
        );
    }

    #[test]
    fn test_preemption_at_active_limit() {
        let policy = QuarantinePolicy::default(); // min_remaining = 2
        let pk_quarantined = [99u8; 32];
        let mut quarantined = HashMap::new();
        quarantined.insert(
            pk_quarantined,
            QuarantinedEdgeState::new(Instant::now(), 3), // distant h = 3
        );

        let pk_attacker_h1 = [1u8; 32];
        let candidates = vec![CandidateEdge {
            friend_pk: pk_attacker_h1,
            h: 1,
            n_exclusive_strictly_healthy: 0,
            n_exclusive_healthy: 0,
            n_healthy: 0,
        }];

        // active = 2 (at limit) -> cannot do normal quarantine, must preempt higher hop
        let decision = decide_algo3v2(&candidates, 2, &quarantined, &policy);
        assert_eq!(
            decision,
            Some(QuarantineDecision::Preempt {
                release_friend_pk: pk_quarantined,
                target_friend_pk: pk_attacker_h1,
                trigger_hops: 1,
            })
        );

        // If candidate hop was >= quarantined trigger_hops (e.g. h = 4 vs h = 3), no preemption
        let pk_far = [2u8; 32];
        let far_candidates = vec![CandidateEdge {
            friend_pk: pk_far,
            h: 4,
            n_exclusive_strictly_healthy: 0,
            n_exclusive_healthy: 0,
            n_healthy: 0,
        }];
        let decision_far = decide_algo3v2(&far_candidates, 2, &quarantined, &policy);
        assert_eq!(decision_far, None);
    }

    #[test]
    fn test_shadow_edge_window_autonomous_healing() {
        let policy = QuarantinePolicy {
            shadow_clean_window: Duration::from_secs(10),
            ..Default::default()
        };
        let t0 = Instant::now();
        let mut state = QuarantinedEdgeState::new(t0, 1);

        assert!(!state.is_healed(t0, &policy));
        assert!(!state.is_healed(t0 + Duration::from_secs(5), &policy));

        // Clean heartbeat received at +6s: does NOT reset last_zombie_shadow_seen
        state.record_shadow_heartbeat(false, t0 + Duration::from_secs(6));
        assert_eq!(state.clean_heartbeats_seen, 1);
        assert_eq!(state.last_zombie_shadow_seen, t0);

        // At +10s: exactly 10s of clean window -> healed!
        assert!(state.is_healed(t0 + Duration::from_secs(10), &policy));

        // But if a zombie heartbeat was received at +8s:
        state.record_shadow_heartbeat(true, t0 + Duration::from_secs(8));
        assert_eq!(state.last_zombie_shadow_seen, t0 + Duration::from_secs(8));
        // At +10s, only 2s elapsed since zombie heartbeat -> NOT healed
        assert!(!state.is_healed(t0 + Duration::from_secs(10), &policy));
        // At +18s (8s + 10s): healed!
        assert!(state.is_healed(t0 + Duration::from_secs(18), &policy));
    }
}
